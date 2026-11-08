"""Duplicate File Monitor authenticated HTTP UI and API."""
import json
import datetime
import os
# SQLite initializes its scratch path at import time; set it beforehand.
_sqlite_dir = os.path.join(os.path.dirname(os.getenv('DB_PATH', '/data/inventory.sqlite3')), '.sqlite-tmp')
os.environ.setdefault('SQLITE_TMPDIR', _sqlite_dir)
os.environ.setdefault('TMPDIR', _sqlite_dir)
import sqlite3
import shutil
import threading
import traceback
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import auth
from version import VERSION
from directory_report_cache import get_directory_report
from directory_analysis import AutomaticDirectoryAnalysis
from observability import monitoring_snapshot, prometheus, get_config, validate_config, mqtt_worker
from configuration import (volume_config, add_volume, remove_volume,
                           relocate_volume, save_volume_mode)
from schedule_engine import (get_schedules, save_schedules, update_run,
                             next_occurrence)
from scanner import (ScanControl, archive_volume, connect, current_metrics,
                     effective_roots, read_meta, report, restore_volume, scan,
                     write_meta, initialize_database, FINGERPRINT_PROFILE,
                     quick_baseline_available, read_scan_report, configured_mount_types, reconstruct_legacy_scan_report,
                     list_scan_duplicate_groups)

DB = os.getenv('DB_PATH', '/data/inventory.sqlite3')
ROOTS = [r for r in os.getenv('SCAN_ROOTS', '/scan').split(':') if r]
# Legacy interval timer is superseded by explicitly configured, disabled-by-default schedules.
DEFAULT_BANDWIDTH = float(os.getenv('SCAN_BANDWIDTH_MBPS', '250'))
DEFAULT_FILE_WORKERS = int(os.getenv('SCAN_FILE_WORKERS', '4'))
lock = threading.Lock()
active_control = None
startup_ready = threading.Event()
startup_phase = 'Preparing database'
startup_error = None
UI = Path(__file__).with_name('index.html')
FAVICON = Path(__file__).with_name('favicon.svg')
LOGIN = Path(__file__).with_name('login.html')
_volume_stats_cache = {'key':None,'metrics':{}}
directory_analysis = AutomaticDirectoryAnalysis(DB)


def bandwidth_setting():
    c = connect(DB, readonly=True)
    try:
        return float(read_meta(c, 'bandwidth_mbps', str(DEFAULT_BANDWIDTH)))
    finally:
        c.close()



def scan_workers_setting():
    c = connect(DB, readonly=True)
    try:
        return int(read_meta(c, 'scan_file_workers', str(DEFAULT_FILE_WORKERS)))
    finally:
        c.close()



def run_locked(roots, control, mode='full', preserved=()):
    global active_control
    published = False
    try:
        print('Scan starting with roots: ' + json.dumps(roots), flush=True)
        opts = {'mode':mode} if mode != 'full' else {}
        if preserved:
            opts['preserved_roots'] = preserved
        result = scan(DB, roots, control, **opts)
        print(json.dumps(result), flush=True)
        published = result.get('status') == 'success'
    except Exception as exc:
        print('Scan ended without publication: ' + repr(exc), flush=True)
        if isinstance(exc, sqlite3.Error):
            print('SQLite error code:', getattr(exc, 'sqlite_errorcode', None),
                  'name:', getattr(exc, 'sqlite_errorname', None), flush=True)
        traceback.print_exc()
    finally:
        # Scanner finalization, report publication and connection closure
        # finish before a separate directory-analysis operation is queued.
        active_control = None
        lock.release()
        if published:
            directory_analysis.request()


def configured():
    return volume_config(DB, ROOTS)


def trigger_scan(mode='full', root='all', selected_roots=None):
    global active_control
    if mode not in ('full', 'quick'):
        raise ValueError('Unknown scan mode')
    if not lock.acquire(blocking=False):
        return False
    try:
        conf = configured()
        active = effective_roots(DB, conf['roots'])
        # Both the legacy single-volume API and the new checked-volume API
        # use one coordinated scan job. Multiple volumes are enumerated by
        # existing workers; there are no competing SQLite publishers.
        if selected_roots is not None:
            if not conf['per_volume_enabled']:
                raise ValueError('Enable per-volume scanning before selecting volumes')
            if (not isinstance(selected_roots, list) or not selected_roots
                    or any(not isinstance(r, str) for r in selected_roots)
                    or len(set(selected_roots)) != len(selected_roots)):
                raise ValueError('Select one or more unique volumes')
            if any(r not in active for r in selected_roots):
                raise ValueError('A selected volume is unavailable, archived or unknown')
            roots = [r for r in active if r in selected_roots]
        else:
            if root != 'all' and not conf['per_volume_enabled']:
                raise ValueError('Enable per-volume scanning before selecting an individual volume')
            if root != 'all' and root not in active:
                raise ValueError('Selected volume is unavailable or archived')
            roots = active if root == 'all' else [root]
        preserved = [r for r in active if r not in roots]
        if not roots:
            raise ValueError('All configured volumes are excluded')
        if mode == 'quick':
            c = connect(DB, readonly=True)
            try:
                if not quick_baseline_available(c, [os.path.realpath(r) for r in roots]):
                    raise ValueError('Run a full scan first. Quick Scan needs a completed Full Scan baseline.')
            finally:
                c.close()
        control = ScanControl(bandwidth_setting(), scan_workers_setting())
        active_control = control
        threading.Thread(target=run_locked, args=(roots, control, mode, preserved), daemon=True).start()
        return True
    except Exception:
        active_control = None
        lock.release()
        raise


def run_due_schedules(now=None):
    """Execute at most one scheduled job per tick; respect global scan lock."""
    now=time.time() if now is None else now
    conf=configured()
    entries=get_schedules(DB)
    active=effective_roots(DB,conf['roots'])
    for entry in entries:
        if not entry.get('enabled') or entry.get('next_run') is None:
            continue
        due=float(entry['next_run'])
        if due>now:
            continue
        schedule_id=entry['id']
        if now-due>60 and entry.get('on_missed','skip')=='skip':
            update_run(DB,schedule_id,next_run=next_occurrence(entry,now),
                       last_outcome='Missed while offline (skipped)')
            continue
        root=entry.get('root','all')
        if root!='all' and (not conf['per_volume_enabled'] or root not in active):
            update_run(DB,schedule_id,next_run=next_occurrence(entry,now),
                       last_outcome='Skipped: volume unavailable')
            continue
        if lock.locked():
            if entry.get('on_conflict')=='defer':
                update_run(DB,schedule_id,next_run=now+15,
                           last_outcome='Waiting: another scan is active')
            else:
                update_run(DB,schedule_id,next_run=next_occurrence(entry,now),
                           last_outcome='Skipped: another scan is active')
            continue
        accepted=False
        try:
            accepted=trigger_scan(entry['mode'],root)
            outcome='Started' if accepted else 'Skipped: busy'
        except Exception as exc:
            outcome='Rejected: '+str(exc)[:300]
        update_run(DB,schedule_id,last_run=now,last_outcome=outcome,
                   next_run=next_occurrence(entry,now))
        # Global scanner permits exactly one active job. Any other due
        # schedules are handled by the next tick using their conflict policy.
        if accepted:
            break


def scheduler():
    """Persisted, explicitly enabled schedules; no silent legacy interval jobs."""
    while True:
        time.sleep(10)
        try:
            run_due_schedules()
        except Exception as exc:
            print('Scheduler error:', repr(exc), flush=True)


def database_storage():
    usage = shutil.disk_usage(os.path.dirname(DB))
    db_main = os.path.getsize(DB) if os.path.isfile(DB) else 0
    wal = os.path.getsize(DB + '-wal') if os.path.isfile(DB + '-wal') else 0
    shm = os.path.getsize(DB + '-shm') if os.path.isfile(DB + '-shm') else 0
    return {'filesystem_total_bytes':usage.total, 'filesystem_free_bytes':usage.free,
            'database_bytes':db_main + wal + shm,
            'main_database_bytes':db_main, 'wal_bytes':wal, 'shm_bytes':shm}


def latest_status():
    c = connect(DB, readonly=True)
    try:
        r = c.execute('SELECT * FROM scans ORDER BY id DESC LIMIT 1').fetchone()
        data = dict(r) if r else {'status': 'not_scanned'}
        # A previously killed worker cannot still be running in this process.
        # Surface it as interrupted, without writing to SQLite at startup.
        if not lock.locked() and data.get('status') == 'running':
            data['status'] = 'interrupted'
            data['error'] = data.get('error') or 'Scanner process exited before completion'
        data['scanning'] = lock.locked()
        conf = configured()
        data['configured_roots'] = conf['roots']
        data['per_volume_enabled'] = conf['per_volume_enabled']
        data['active_roots'] = effective_roots(DB, conf['roots'])
        data['quick_available'] = quick_baseline_available(c,
            [os.path.realpath(r) for r in data['active_roots']])
        data['quick_baseline_roots'] = [r for r in data['active_roots']
            if quick_baseline_available(c,[os.path.realpath(r)])]
        last = c.execute("SELECT id,ended FROM scans WHERE status='success' ORDER BY id DESC LIMIT 1").fetchone()
        data['published_scan_id'] = last['id'] if last else None
        data['published_scan_ended'] = last['ended'] if last else None
        if last:
            duplicates, wasted = current_metrics(c)
            data['duplicates'] = duplicates
            data['wasted'] = wasted
            data['files'] = c.execute('SELECT COUNT(*) n FROM files').fetchone()['n']
            data['total_file_size_bytes'] = c.execute('SELECT COALESCE(SUM(size),0) FROM files').fetchone()[0]
            data['lifetime'] = int(read_meta(c, 'lifetime'))
        data['progress'] = active_control.snapshot() if active_control else None
        try:
            data['changes'] = json.loads(r['changes_json']) if r and r['changes_json'] else None
        except (TypeError,ValueError):
            data['changes'] = None
        # Persistent, immutable last-scan outcome for the idle dashboard.
        # v0.3.7 scan records lack this field; UI falls back to final totals.
        try:
            data['last_scan_progress'] = (json.loads(r['progress_json'])
                                          if r and r['progress_json'] else None)
        except (ValueError, TypeError):
            data['last_scan_progress'] = None
        data['bandwidth_mbps'] = bandwidth_setting()
        data['file_workers'] = scan_workers_setting()
        data['storage'] = database_storage()
        data['version'] = VERSION
        return data
    finally:
        c.close()


def _per_volume_duplicate_metrics(c, key):
    # Count all redundant copies globally, attributing each extra copy to its
    # actual root. Retain one deterministic reference path per hash group.
    global _volume_stats_cache
    if _volume_stats_cache['key'] == key:
        return _volume_stats_cache['metrics']
    counters={}
    last_group=None
    first=True
    rows=c.execute("""SELECT size,full,root,COUNT(*) n,MIN(path) first_path
          FROM files WHERE size>0 AND full IS NOT NULL
          GROUP BY size,full,root ORDER BY size,full,first_path""")
    for row in rows:
        group=(row['size'],row['full'])
        if group!=last_group:
            first=True
            last_group=group
        copies=row['n']-(1 if first else 0)
        first=False
        if copies>0:
            entry=counters.setdefault(row['root'],{'duplicate_copies':0,'wasted_bytes':0})
            entry['duplicate_copies']+=copies
            entry['wasted_bytes']+=copies*row['size']
    _volume_stats_cache={'key':key,'metrics':counters}
    return counters


def volumes():
    conf = configured()
    c = connect(DB, readonly=True)
    try:
        archived = {r['root']: r['archived_at'] for r in c.execute('SELECT * FROM excluded_roots')}
        history = {r['root']: dict(r) for r in c.execute('''
            SELECT v.root,v.file_count,v.added,v.removed,v.modified,v.possible_moves,
                   v.scan_id,s.ended
            FROM volume_scans v JOIN scans s ON s.id=v.scan_id
            WHERE s.status='success' AND NOT EXISTS(
              SELECT 1 FROM volume_scans newer JOIN scans ns ON ns.id=newer.scan_id
              WHERE newer.root=v.root AND newer.scan_id>v.scan_id AND ns.status='success')''')}
        current = {r['root']: (r['n'],r['bytes']) for r in c.execute('SELECT root, COUNT(*) n, COALESCE(SUM(size),0) bytes FROM files GROUP BY root')}
        last_scan=c.execute("SELECT MAX(id) FROM scans WHERE status='success'").fetchone()[0]
        stat_key=(last_scan,tuple(conf['roots']),tuple(sorted(archived)))
        extras=_per_volume_duplicate_metrics(c,stat_key)
        aliases=json.loads(read_meta(c,'baseline_aliases_json','{}'))
        results = []
        invalid = {r['root']:r['reason'] for r in c.execute('SELECT * FROM invalid_baselines')}
        for root in conf['roots']:
            excluded = root in archived
            h = history.get(root) or history.get(aliases.get(root))
            # An archived volume has no active inventory and is not a removal event.
            n = 0 if excluded else current.get(root, (0,0))[0]
            logical_bytes = 0 if excluded else current.get(root, (0,0))[1]
            added = None if excluded or h is None else h.get('added')
            removed = None if excluded or h is None else h.get('removed')
            status = 'Archived' if excluded else 'Needs Full Scan' if root in invalid else 'Active' if h else 'New'
            results.append({'root': root, 'volume_id':conf['volume_ids'].get(root),
                            'status':status,'baseline_reason':invalid.get(root),
                            'last_scanned_at':h['ended'] if h else None,
                            'duplicate_copies':0 if excluded else extras.get(root,{}).get('duplicate_copies',0),
                            'wasted_bytes':0 if excluded else extras.get(root,{}).get('wasted_bytes',0),
                            'archived': excluded,
                            'archived_at': archived.get(root), 'file_count': n, 'total_file_size_bytes': logical_bytes,
                            'added': added, 'removed': removed,
                            'modified': None if excluded or h is None else h.get('modified'),
                            'possible_moves': None if excluded or h is None else h.get('possible_moves'),
                            'net_change': added-removed if added is not None and removed is not None else None})
        return results
    finally:
        c.close()


def monitoring():
    # Read-only snapshot; never touches scan staging or its source mounts.
    c=connect(DB,readonly=True)
    try:
        return monitoring_snapshot(c,latest_status(),volumes())
    finally:
        c.close()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        # High-frequency in-memory progress updates must not flood Docker logs.
        if self.path.split('?', 1)[0] == '/api/progress':
            return
        super().log_message(fmt, *args)

    def respond(self, data, code=200, extra_headers=None):
        body = json.dumps(data).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Length', str(len(body)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def body_json(self):
        length = int(self.headers.get('Content-Length','0'))
        if length > 131072 or length < 0:
            raise ValueError('Invalid JSON body size')
        data = json.loads(self.rfile.read(length) or b'{}')
        if not isinstance(data, dict):
            raise ValueError('Expected JSON object')
        return data

    def render_html(self, path):
        body = path.read_bytes()
        if path == UI:
            # Use the running application's version, not a handwritten HTML
            # constant, for release comparisons and deployment refreshes.
            body = body.replace(b'__DFM_UI_VERSION__', VERSION.encode('ascii'))
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Content-Security-Policy', "frame-ancestors 'none'")
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def session(self):
        return auth.get_session(DB, self.headers.get('Cookie', ''))

    def check_origin(self):
        if self.headers.get('Sec-Fetch-Site','').lower() == 'cross-site':
            self.respond({'error':'Cross-origin request denied'},403)
            return False
        origin = self.headers.get('Origin')
        if origin:
            from urllib.parse import urlsplit
            parsed = urlsplit(origin)
            # Host must reflect the publicly requested host, including the
            # port. Reject malformed and cross-origin requests.
            if parsed.scheme not in ('http','https') or parsed.netloc.lower() != self.headers.get('Host','').lower() or parsed.username is not None:
                self.respond({'error':'Cross-origin request denied'},403)
                return False
        return True

    def csrf_valid(self, session):
        return bool(session and self.headers.get('X-DFM-CSRF','') and
                    __import__('hmac').compare_digest(self.headers.get('X-DFM-CSRF',''),session['csrf']))

    def do_GET(self):
        parsed = urlsplit(self.path)
        path = parsed.path
        try:
            if path in ('/favicon.svg', '/favicon.ico'):
                if path == '/favicon.ico':
                    self.send_response(302)
                    self.send_header('Location', '/favicon.svg')
                    self.send_header('Cache-Control', 'public, max-age=86400')
                    self.end_headers()
                    return
                body = FAVICON.read_bytes()
                self.send_response(200)
                self.send_header('Content-Type', 'image/svg+xml; charset=utf-8')
                self.send_header('Cache-Control', 'public, max-age=86400')
                self.send_header('X-Content-Type-Options', 'nosniff')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if path == '/health':
                self.respond({'ok': startup_ready.is_set() and startup_error is None,
                              'phase': startup_phase, 'error': startup_error,
                              'version': VERSION}, 200 if startup_ready.is_set() else 503)
                return
            if path == '/api/startup':
                self.respond({'ready': startup_ready.is_set(), 'phase': startup_phase,
                              'error': startup_error, 'version': VERSION})
                return
            if path in ('/','/index.html','/login') and not startup_ready.is_set():
                self.render_html(LOGIN)
                return
            if path == '/api/auth/status':
                if not startup_ready.is_set():
                    self.respond({'authenticated':False,'setup_required':False,'setup_configured':False,'starting':True},503)
                    return
                session = self.session() if auth.has_admin(DB) else None
                self.respond({'authenticated':bool(session),
                              'setup_required':not auth.has_admin(DB),
                              'setup_configured':len(os.getenv('DFM_SETUP_TOKEN',''))>=24,
                              'username':session['username'] if session else None,
                              'csrf':session['csrf'] if session else None})
                return
            if path not in ('/', '/index.html') and not startup_ready.is_set():
                self.respond({'error': ('Database startup failed: '+startup_error) if startup_error else ('Database initialization: ' + startup_phase),
                              'phase': startup_phase, 'version': VERSION}, 503)
                return
            session = self.session()
            if path == '/metrics':
                if not (session or auth.metrics_authorized(self.headers.get('Authorization',''))):
                    self.respond({'error':'Authentication required'},401)
                    return
            elif not session:
                if path in ('/','/index.html','/login'):
                    self.render_html(LOGIN)
                    return
                self.respond({'error':'Authentication required'},401)
                return
            if path in ('/', '/index.html'):
                self.render_html(UI)
            elif path == '/login':
                self.render_html(LOGIN)
            elif path == '/api/auth/session':
                self.respond({'username':session['username'],'csrf':session['csrf']})
            elif path.startswith('/api/reports/'):
                parts = path.split('/')
                if len(parts) not in (4, 5) or (len(parts) == 5 and parts[4] != 'duplicates'):
                    raise ValueError('Invalid scan report URL')
                try:
                    scan_id = int(parts[3])
                    if scan_id < 1:
                        raise ValueError()
                except ValueError:
                    raise ValueError('Invalid scan ID')
                c = connect(DB, readonly=True)
                try:
                    data = read_scan_report(c, scan_id)
                finally:
                    c.close()
                if data is None:
                    data = reconstruct_legacy_scan_report(DB, scan_id)
                if data is None:
                    self.respond({'error':'Scan does not exist'}, 404)
                elif len(parts) == 5:
                    q = parse_qs(parsed.query)
                    limit = min(max(int(q.get('limit',['25'])[0]),1),100)
                    offset = max(int(q.get('offset',['0'])[0]),0)
                    search = q.get('search',[''])[0][:200]
                    root = q.get('root',[''])[0]
                    sort = q.get('sort',['wasted'])[0]
                    order = q.get('order',['desc'])[0]
                    c = connect(DB, readonly=True)
                    try:
                        self.respond(list_scan_duplicate_groups(c, scan_id, data, limit,
                                                               offset, search, root, sort, order))
                    finally:
                        c.close()
                else:
                    self.respond(data)
            elif path == '/api/monitoring':
                self.respond(monitoring())
            elif path == '/api/mqtt-settings':
                c=connect(DB,readonly=True)
                try: self.respond(get_config(c))
                finally: c.close()
            elif path == '/metrics':
                body=prometheus(monitoring()).encode('utf-8')
                self.send_response(200)
                self.send_header('Content-Type','text/plain; version=0.0.4; charset=utf-8')
                self.send_header('Cache-Control','no-store')
                self.send_header('Content-Length',str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif path == '/api/duplicate-directories':
                q = parse_qs(parsed.query)
                limit = min(max(int(q.get('limit',['100'])[0]),1),500)
                c=connect(DB,readonly=True)
                try:
                    data = get_directory_report(c,limit=limit)
                    status = directory_analysis.status()
                    # Never expose an old tree list as actionable cleanup data.
                    if data['stale'] and status not in ('pending','running','failed'):
                        status = 'pending'
                    if status in ('pending','running','failed') or data['stale']:
                        data['items'] = []
                        data['returned'] = 0
                        data['total_directory_roots'] = None
                    data['analysis_status'] = status
                    self.respond(data)
                finally: c.close()
            elif path == '/api/duplicates':
                q = parse_qs(parsed.query)
                search = q.get('search',[''])[0][:200]
                limit = min(max(int(q.get('limit',['50'])[0]),1),100)
                offset = max(int(q.get('offset',['0'])[0]),0)
                # During a scan, the published inventory remains unchanged.
                # Show only committed, FULL-hash-confirmed groups from the
                # work table once enumeration has finished. Never expose
                # leftovers of a failed scan or a partial enumeration.
                control = active_control
                progress = control.snapshot() if control is not None else None
                stage = progress.get('stage') if progress else None
                # Scoped scans use connection-local TEMP staging. The HTTP
                # reader cannot see it, so report the published snapshot.
                live = bool(lock.locked() and progress and progress.get('scan_id')
                            and not progress.get('staging_in_memory')
                            and stage in ('partial_hashing','full_hashing'))
                sort=q.get('sort',['wasted'])[0]
                order=q.get('order',['desc'])[0]
                if sort not in ('wasted','size','copies','filename'):
                    raise ValueError('Unsupported sort')
                if order not in ('asc','desc'):
                    raise ValueError('Unsupported sort order')
                items,total=report(DB,search=search,limit=limit,
                                   offset=offset,live=live,sort=sort,
                                   order=order,return_total=True)
                self.respond({'items':items,'total_groups':total,
                              'total_pages':max(1,(total+limit-1)//limit),
                              'has_more':offset+len(items)<total,
                              'offset':offset,'limit':limit,'sort':sort,'order':order,
                              'source':'live' if live else 'published',
                              'scan_id':progress.get('scan_id') if live else None})
            elif path == '/api/progress':
                # No SQLite access: this endpoint samples the live per-file counter
                # cheaply and independently of the 1,000-row commit cadence.
                control = active_control
                self.respond({'scanning': lock.locked(),
                              'progress': control.snapshot() if control else None})
            elif path == '/api/status':
                self.respond(latest_status())
            elif path == '/api/volumes':
                self.respond(volumes())
            elif path == '/api/settings':
                self.respond({'bandwidth_mbps': bandwidth_setting(),
                              'file_workers': scan_workers_setting(),
                              **configured()})
            elif path == '/api/schedules':
                self.respond({'schedules':get_schedules(DB),
                              'per_volume_enabled':configured()['per_volume_enabled']})
            elif path == '/api/diagnostics':
                c = connect(DB, readonly=True)
                try:
                    last = c.execute('SELECT id,mode,status,started,ended,progress_json,changes_json '
                                     'FROM scans ORDER BY id DESC LIMIT 1').fetchone()
                    history = dict(last) if last else None
                    if history:
                        for key in ('progress_json','changes_json'):
                            raw = history.pop(key)
                            history['progress' if key=='progress_json' else 'changes'] = json.loads(raw) if raw else None
                finally:
                    c.close()
                self.respond({'version':VERSION,'active':active_control.snapshot() if active_control else None,
                              'last_scan':history})
            elif path == '/api/history':
                q = parse_qs(parsed.query)
                root_filter = q.get('root',['all'])[0]
                if root_filter != 'all' and root_filter not in configured()['roots']:
                    raise ValueError('Unknown history volume')
                paged = 'page' in q or 'limit' in q
                limit = min(max(int(q.get('limit',['25' if paged else '50'])[0]),1),100)
                page = max(int(q.get('page',['1'])[0]),1)
                c = connect(DB, readonly=True)
                try:
                    # Filter before paginating so every historical page remains
                    # reachable. Scope includes All-Volumes scans, even when
                    # viewing the history of one selected volume.
                    where = ''
                    args = []
                    if root_filter != 'all':
                        where = """
                            WHERE EXISTS (
                                SELECT 1 FROM volume_scans v
                                WHERE v.scan_id = scans.id AND v.root = ?
                            ) OR EXISTS (
                                SELECT 1 FROM json_each(
                                    CASE WHEN json_valid(scans.progress_json)
                                         THEN json_extract(scans.progress_json,'$.scan_scope')
                                         ELSE '[]' END
                                ) AS scope WHERE scope.value = ?
                            )"""
                        args = [root_filter, root_filter]
                    c.execute('BEGIN')
                    total = c.execute('SELECT COUNT(*) FROM scans ' + where,args).fetchone()[0]
                    total_pages = max(1,(total+limit-1)//limit)
                    page = min(page,total_pages)
                    offset = (page-1)*limit
                    rows = [dict(r) for r in c.execute(
                        'SELECT * FROM scans ' + where + ' ORDER BY id DESC LIMIT ? OFFSET ?',
                        (*args,limit,offset))]
                    # Fetch immutable volume snapshots for ONLY the current
                    # page; no present-day totals enter historical records.
                    ids = [row['id'] for row in rows]
                    members = {}
                    report_ids = set()
                    if ids:
                        placeholders = ','.join('?' for _ in ids)
                        for member in c.execute(
                                'SELECT scan_id,root,file_count,duplicate_copies,wasted_bytes '
                                'FROM volume_scans WHERE scan_id IN ('+placeholders+')',ids):
                            members.setdefault(member['scan_id'],[]).append(dict(member))
                        for record in c.execute(
                                'SELECT scan_id FROM scan_reports WHERE scan_id IN ('+placeholders+')',ids):
                            report_ids.add(record['scan_id'])
                    for row in rows:
                        row['has_report'] = row['id'] in report_ids
                        row['volumes'] = members.get(row['id'],[])
                        try:
                            raw = json.loads(row.get('progress_json') or '{}')
                            row['scope'] = raw.get('scan_scope')
                        except (ValueError,TypeError,AttributeError):
                            row['scope'] = None
                    if not lock.locked():
                        for row in rows:
                            if row['status'] == 'running':
                                row['status'] = 'interrupted'
                                row['error'] = row.get('error') or 'Scanner process exited before completion'
                    c.commit()
                finally:
                    c.close()
                if paged:
                    self.respond({'items':rows,'total_records':total,'total_pages':total_pages,
                                  'page':page,'limit':limit})
                else:
                    # Preserve the previous array response for API clients
                    # not requesting pagination explicitly.
                    self.respond(rows)
            else:
                self.send_error(404)
        except ValueError as exc:
            self.respond({'error':str(exc)}, 400)
        except (BrokenPipeError,ConnectionResetError):
            pass
        except Exception as exc:
            print('API error:', repr(exc), flush=True)
            traceback.print_exc()
            self.respond({'error':'Internal server error'}, 500)

    def do_POST(self):
        parsed = urlsplit(self.path)
        path = parsed.path
        try:
            if not self.check_origin():
                return
            ctype = self.headers.get('Content-Type','').split(';',1)[0].strip().lower()
            if ctype != 'application/json':
                self.respond({'error':'Content-Type must be application/json'},415)
                return
            if path == '/api/auth/setup':
                if not startup_ready.is_set():
                    self.respond({'error':'Database not ready'},503)
                    return
                data = self.body_json()
                # The random setup token is a one-time secret, not a default credential.
                auth.setup(DB, data.get('setup_token'), data.get('username'), data.get('password'))
                token, csrf = auth.create_session(DB,data['username'])
                self.respond({'ok':True,'csrf':csrf},200,
                             {'Set-Cookie':auth.cookie_header(token)})
                return
            if path == '/api/auth/login':
                if not startup_ready.is_set():
                    self.respond({'error':'Database not ready'},503)
                    return
                data = self.body_json()
                token, csrf = auth.login(DB,data.get('username'),data.get('password'),self.client_address[0])
                self.respond({'ok':True,'csrf':csrf},200,
                             {'Set-Cookie':auth.cookie_header(token)})
                return
            session = self.session()
            if not session:
                self.respond({'error':'Authentication required'},401)
                return
            if not self.csrf_valid(session):
                self.respond({'error':'Invalid CSRF token'},403)
                return
            if path == '/api/auth/logout':
                auth.revoke(DB,self.headers.get('Cookie',''))
                self.respond({'ok':True},200,{'Set-Cookie':auth.clear_cookie_header()})
                return
            if path == '/api/auth/change':
                data = self.body_json()
                auth.change_credentials(DB,session['username'],
                    data.get('current_password'),data.get('username'),data.get('password'))
                self.respond({'ok':True},200,{'Set-Cookie':auth.clear_cookie_header()})
                return
            if not startup_ready.is_set():
                self.respond({'error': ('Database startup failed: '+startup_error) if startup_error else ('Database initialization: ' + startup_phase)}, 503)
                return
            if path in ('/api/scan', '/api/scan/quick'):
                mode = 'quick' if path.endswith('/quick') else 'full'
                data = self.body_json()
                root = data.get('root','all')
                if not isinstance(root,str):
                    raise ValueError('Invalid scan volume')
                selected = data.get('roots') if 'roots' in data else None
                if not trigger_scan(mode, root, selected):
                    self.respond({'error':'Previous scan is still running, stopping, or cleaning up'}, 409)
                else:
                    self.respond({'accepted':True,'mode':mode,'message':mode.title()+' Scan started'}, 202)
                return
            if path in ('/api/scan/pause','/api/scan/resume','/api/scan/stop'):
                ctrl = active_control
                if not ctrl or not lock.locked():
                    self.respond({'error':'No scan in progress'}, 409)
                    return
                if ctrl.stop_requested():
                    if path == '/api/scan/stop':
                        self.respond({'ok':True,'message':'Stop already requested'})
                    else:
                        self.respond({'error':'Scan is stopping or cleaning up'},409)
                    return
                if path == '/api/scan/stop':
                    if not ctrl.stop():
                        self.respond({'error':ctrl.snapshot()['stop_disabled_reason'] or
                                      'Stop is unavailable during finalization'}, 409)
                        return
                else:
                    state = ctrl.snapshot()
                    if state.get('stage') in ('starting','preparing'):
                        self.respond({'error':'Pause and Resume are unavailable during scan preparation'}, 409)
                        return
                    if not state['can_stop']:
                        self.respond({'error':'Scan is finalizing; controls unavailable'}, 409)
                        return
                    {'/api/scan/pause':ctrl.pause,
                     '/api/scan/resume':ctrl.resume}[path]()
                self.respond({'ok':True})
                return
            data = self.body_json()
            if path == '/api/mqtt-settings':
                if lock.locked():
                    self.respond({'error':'Wait for the active scan to finish before changing MQTT configuration'},409)
                    return
                c=connect(DB)
                try:
                    previous=get_config(c,True)
                    raw=data.get('settings',{})
                    # Blank password leaves the previous secret unchanged.
                    if raw.get('password','')=='': raw.pop('password',None)
                    updated=validate_config(raw,previous)
                    with c: write_meta(c,'mqtt_settings_json',json.dumps(updated))
                    self.respond({'ok':True,'settings':get_config(c)})
                finally: c.close()
                return
            if path == '/api/settings':
                mbps = float(data.get('bandwidth_mbps', bandwidth_setting()))
                workers = int(data.get('file_workers', scan_workers_setting()))
                if not 0 <= mbps <= 10000:
                    raise ValueError('Bandwidth must be between 0 and 10000 Mbps')
                if not 1 <= workers <= 16:
                    raise ValueError('File workers must be between 1 and 16')
                c = connect(DB)
                try:
                    with c:
                        write_meta(c,'bandwidth_mbps',mbps)
                        write_meta(c,'scan_file_workers',workers)
                finally:
                    c.close()
                if active_control:
                    active_control.set_bandwidth(mbps)
                self.respond({'ok':True,'bandwidth_mbps':mbps,
                              'file_workers':workers,
                              'workers_apply_next_scan':bool(active_control),
                              'fingerprint_profile':FINGERPRINT_PROFILE})
                return
            if path in ('/api/volumes/archive','/api/volumes/restore'):
                if not lock.acquire(blocking=False):
                    self.respond({'error':'Stop the active scan before modifying volumes'}, 409)
                    return
                try:
                    root = data.get('root')
                    if not isinstance(root,str) or root not in configured()['roots']:
                        raise ValueError('Unknown configured volume')
                    if path.endswith('/archive'):
                        archive_volume(DB,root,configured()['roots'])
                    else:
                        restore_volume(DB,root,configured()['roots'])
                finally:
                    lock.release()
                directory_analysis.request()
                self.respond({'ok':True,'root':root})
                return
            if path == '/api/volume-mode':
                if not lock.acquire(blocking=False):
                    self.respond({'error':'Wait for the active scan to finish'},409)
                    return
                try:
                    result=save_volume_mode(DB,ROOTS,data.get('enabled'))
                finally:
                    lock.release()
                self.respond({'ok':True,**result})
                return
            if path in ('/api/volumes/add','/api/volumes/remove','/api/volumes/relocate'):
                if not lock.acquire(blocking=False):
                    self.respond({'error':'Wait for the active scan to finish'},409)
                    return
                try:
                    required=bool(configured_mount_types())
                    if path.endswith('/add'):
                        result=add_volume(DB,ROOTS,data.get('root'),required)
                    elif path.endswith('/remove'):
                        result=remove_volume(DB,ROOTS,data.get('root'))
                    else:
                        result=relocate_volume(DB,ROOTS,data.get('old_root'),
                                               data.get('new_root'),required)
                finally:
                    lock.release()
                directory_analysis.request()
                self.respond({'ok':True,**result})
                return
            if path == '/api/schedules':
                conf=configured()
                saved=save_schedules(DB,data.get('schedules'),conf['roots'],
                                     conf['per_volume_enabled'])
                self.respond({'ok':True,'schedules':saved})
                return
            self.send_error(404)
        except (ValueError,KeyError,TypeError,auth.AuthError) as exc:
            self.respond({'error':str(exc)}, 400)
        except Exception as exc:
            print('API error:', repr(exc), flush=True)
            traceback.print_exc()
            self.respond({'error':'Internal server error'},500)


def bootstrap_database():
    """Expose the existing inventory without initiating a startup fsync.

    A previous 'running' history record can safely be presented as interrupted
    in memory. Its durable status is fixed in the next scan's first transaction.
    Avoiding automatic repair writes protects startup on slow virtual disks.
    """
    global startup_phase, startup_error
    try:
        startup_phase = 'Opening saved inventory (read-only)'
        print('Database startup: ' + startup_phase, flush=True)
        begin = time.monotonic()
        initialize_database(DB)
        auth.initialize(DB)
        startup_phase = 'Checking existing scan history (read-only)'
        c = connect(DB, readonly=True)
        try:
            orphaned = c.execute("SELECT COUNT(*) FROM scans WHERE status='running'").fetchone()[0]
            c.execute('SELECT COUNT(*) FROM files').fetchone()
        finally:
            c.close()
        if orphaned:
            print('Previous interrupted scan detected; will reconcile its history on the next scan',flush=True)
        startup_phase = 'Ready'
        startup_ready.set()
        print('Database startup completed in %.2fs (no startup writes)' %
              (time.monotonic()-begin),flush=True)
        directory_analysis.start()
        threading.Thread(target=scheduler, daemon=True).start()
        threading.Thread(target=mqtt_worker, args=(DB,monitoring), daemon=True,name='mqtt-publisher').start()
    except Exception as exc:
        startup_error = repr(exc)
        startup_phase = 'Failed'
        print('Database startup FAILED: ' + startup_error, flush=True)
        traceback.print_exc()


if __name__ == '__main__':
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    for obsolete in ('SCAN_INTERVAL_SECONDS','SCAN_ON_START'):
        if obsolete in os.environ:
            print('WARNING: '+obsolete+' is ignored; configure scan schedules in the dashboard',flush=True)
    sqlite_tmp = os.path.join(os.path.dirname(DB), '.sqlite-tmp')
    os.makedirs(sqlite_tmp, mode=0o700, exist_ok=True)
    if not os.access(sqlite_tmp, os.W_OK):
        raise RuntimeError('SQLite temporary directory is not writable: ' + sqlite_tmp)
    # These variables were configured before sqlite3 was imported.
    print('SQLite scratch directory: ' + sqlite_tmp, flush=True)
    # HTTP must be ready BEFORE expensive recovery, checkpoints, or migrations.
    httpd = ThreadingHTTPServer(('0.0.0.0', int(os.getenv('HTTP_PORT','8080'))), Handler)
    print('HTTP listener started; database may still be initializing', flush=True)
    threading.Thread(target=bootstrap_database, name='database-bootstrap', daemon=True).start()
    httpd.serve_forever()
