"""Read-only, multi-volume duplicate scanner with durable checkpoints.

Source files are never modified. The completed inventory is kept separately from
an in-progress scan; only a fully validated scan can replace it or accrue savings.
"""
import hashlib
from collections import deque
from queue import Queue, Empty
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
import sqlite3
import stat
import threading
import time
from pathlib import Path

# Files <=3 MiB receive their full SHA-256 in the first content pass.
# Larger files get six distributed 512 KiB windows; matching samples need
# complete-file verification. The immutable profile protects previous caches.
READ_CHUNK = 256 * 1024
MIB = 1024 ** 2
GIB = 1024 ** 3
FINGERPRINT_PROFILE = 'fixed-six-v1-512k-3m'
FINGERPRINT_PREFIX = 'pf4-' + FINGERPRINT_PROFILE + ':'
SAMPLE_COUNT = 6
SAMPLE_WINDOW = 512 * 1024
FULL_FIRST_PASS_LIMIT = 3 * MIB

BATCH = 1000
CANDIDATE_PAGE = 256
CHECKPOINT_EVERY_PAGES = 16

SCHEMA = '''
CREATE TABLE IF NOT EXISTS files(
  path TEXT PRIMARY KEY, root TEXT NOT NULL, size INTEGER NOT NULL,
  mtime_ns INTEGER NOT NULL, dev INTEGER NOT NULL, inode INTEGER NOT NULL,
  partial TEXT, full TEXT);
CREATE INDEX IF NOT EXISTS files_full_idx ON files(size,full);
CREATE INDEX IF NOT EXISTS files_root_idx ON files(root);
CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY, started REAL, ended REAL,
  status TEXT, mode TEXT NOT NULL DEFAULT 'full', error TEXT, files INTEGER, duplicates INTEGER,
  wasted INTEGER, lifetime INTEGER, progress_json TEXT, changes_json TEXT);
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS volume_scans(scan_id INTEGER NOT NULL, root TEXT NOT NULL,
  file_count INTEGER NOT NULL, duplicate_copies INTEGER, wasted_bytes INTEGER, PRIMARY KEY(scan_id,root));
CREATE TABLE IF NOT EXISTS excluded_roots(root TEXT PRIMARY KEY, archived_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS invalid_baselines(root TEXT PRIMARY KEY, reason TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS hash_cache(
  path TEXT PRIMARY KEY, root TEXT NOT NULL, size INTEGER NOT NULL,
  mtime_ns INTEGER NOT NULL, dev INTEGER NOT NULL, inode INTEGER NOT NULL,
  partial TEXT, samples TEXT, full TEXT);
CREATE INDEX IF NOT EXISTS hash_cache_root_idx ON hash_cache(root);
-- Retain every historical partial fingerprint profile for an unchanged file.
-- Never overwrite another profile when sample sizes/algorithms change.
CREATE TABLE IF NOT EXISTS partial_cache(
  path TEXT NOT NULL, profile TEXT NOT NULL, root TEXT NOT NULL,
  size INTEGER NOT NULL, mtime_ns INTEGER NOT NULL,
  dev INTEGER NOT NULL, inode INTEGER NOT NULL, partial TEXT NOT NULL,
  PRIMARY KEY(path, profile));
CREATE INDEX IF NOT EXISTS partial_cache_root_idx ON partial_cache(root);
CREATE TABLE IF NOT EXISTS work_files(
  path TEXT PRIMARY KEY, root TEXT NOT NULL, size INTEGER NOT NULL,
  mtime_ns INTEGER NOT NULL, dev INTEGER NOT NULL, inode INTEGER NOT NULL,
  partial TEXT, samples TEXT, full TEXT);
CREATE INDEX IF NOT EXISTS work_size_idx ON work_files(size);
CREATE INDEX IF NOT EXISTS work_partial_idx ON work_files(size,partial);
CREATE INDEX IF NOT EXISTS work_samples_idx ON work_files(size,samples);
-- Efficient live lookups for exact, fully fingerprinted duplicate copies.
CREATE INDEX IF NOT EXISTS work_full_idx ON work_files(size,full) WHERE full IS NOT NULL;
CREATE TABLE IF NOT EXISTS scan_progress(
  id INTEGER PRIMARY KEY CHECK(id=1), scan_id INTEGER, stage TEXT,
  file_count INTEGER DEFAULT 0, candidates INTEGER DEFAULT 0,
  fully_hashed INTEGER DEFAULT 0, read_bytes INTEGER DEFAULT 0, updated REAL);
'''


# Schema creation and migrations are one-time startup operations, NOT work
# that every UI request should repeat while a scan is writing to SQLite.
_init_lock = threading.Lock()
_initialized_dbs = set()


def _open_database(db, readonly=False):
    if readonly:
        from urllib.parse import quote
        path = os.path.abspath(os.fspath(db))
        c = sqlite3.connect('file:' + quote(path, safe='/') + '?mode=ro',
                            uri=True, timeout=5)
    else:
        c = sqlite3.connect(str(db), timeout=30)
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA busy_timeout=30000')
    return c


def _current_schema_readonly(db):
    """Read-only startup fast path for an already-migrated database.

    Most application restarts MUST NOT create a transaction or force a WAL fsync.
    SQLite handles WAL recovery when opening a connection; no explicit
    checkpoint or metadata UPDATE is necessary for read-only access.
    """
    from urllib.parse import quote
    path = os.path.abspath(os.fspath(db))
    if not os.path.isfile(path):
        return False
    uri = 'file:' + quote(path, safe='/') + '?mode=ro'
    c = sqlite3.connect(uri, uri=True, timeout=5)
    try:
        required = {'files','scans','meta','volume_scans','excluded_roots',
                    'invalid_baselines','hash_cache','partial_cache',
                    'work_files','scan_progress'}
        present = {row[0] for row in c.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        if not required.issubset(present):
            return False
        scans = {row[1] for row in c.execute('PRAGMA table_info(scans)')}
        vols = {row[1] for row in c.execute('PRAGMA table_info(volume_scans)')}
        if not {'mode','progress_json','changes_json'}.issubset(scans):
            return False
        if not {'modified','possible_moves','added','removed','duplicate_copies','wasted_bytes'}.issubset(vols):
            return False
        # A missing legacy partial-cache flag is handled on the NEXT scan,
        # never as a surprise expensive startup write.
        return True
    finally:
        c.close()


def initialize_database(db):
    key = os.path.abspath(os.fspath(db))
    with _init_lock:
        if key in _initialized_dbs:
            return
        # Common path: verify a complete schema without writing a single byte
        # to the main DB/WAL. Large SQLite writes must never delay startup.
        if _current_schema_readonly(db):
            _initialized_dbs.add(key)
            return
        c = _open_database(db)
        try:
            # First install / legacy schema migration only.
            c.execute('PRAGMA journal_mode=WAL')
            c.executescript(SCHEMA)
            cols = {r[1] for r in c.execute('PRAGMA table_info(volume_scans)')}
            scan_cols = {r[1] for r in c.execute('PRAGMA table_info(scans)')}
            with c:
                if 'mode' not in scan_cols:
                    c.execute("ALTER TABLE scans ADD COLUMN mode TEXT NOT NULL DEFAULT 'full'")
                if 'progress_json' not in scan_cols:
                    c.execute('ALTER TABLE scans ADD COLUMN progress_json TEXT')
                if 'changes_json' not in scan_cols:
                    c.execute('ALTER TABLE scans ADD COLUMN changes_json TEXT')
                if 'modified' not in cols:
                    c.execute('ALTER TABLE volume_scans ADD COLUMN modified INTEGER')
                if 'possible_moves' not in cols:
                    c.execute('ALTER TABLE volume_scans ADD COLUMN possible_moves INTEGER')
                if 'added' not in cols:
                    c.execute('ALTER TABLE volume_scans ADD COLUMN added INTEGER')
                if 'removed' not in cols:
                    c.execute('ALTER TABLE volume_scans ADD COLUMN removed INTEGER')
                if 'duplicate_copies' not in cols:
                    c.execute('ALTER TABLE volume_scans ADD COLUMN duplicate_copies INTEGER')
                if 'wasted_bytes' not in cols:
                    c.execute('ALTER TABLE volume_scans ADD COLUMN wasted_bytes INTEGER')
                # One-time, idempotent migration of existing v0.3.5/0.3.6
                # fingerprints into a multi-profile cache. Unknown older
                # formats are ignored, never mistaken for the new algorithm.
                # Interrupted scans are reconciled atomically when another
                # scan begins; opening an existing DB must remain read-only.
                # The legacy profile migration must be performed once only.
                # Replaying INSERT OR IGNORE over hundreds of thousands of
                # hashes on every container restart is expensive.
                profile_migrated = c.execute("SELECT value FROM meta WHERE key='partial_profile_migrated'").fetchone()
                if not profile_migrated:
                    for table in ('hash_cache', 'files'):
                        c.execute(f"""INSERT OR IGNORE INTO partial_cache
                          (path,profile,root,size,mtime_ns,dev,inode,partial)
                          SELECT path,substr(partial,1,instr(partial,':')-1),root,
                                 size,mtime_ns,dev,inode,partial FROM {table}
                          WHERE partial LIKE 'pf2-%:%' OR partial LIKE 'pf3-%:%' OR partial LIKE 'pf4-%:%'""")
                    c.execute("INSERT INTO meta(key,value) VALUES('partial_profile_migrated','1')")
            _initialized_dbs.add(key)
        finally:
            c.close()


def connect(db, readonly=False):
    initialize_database(db)
    return _open_database(db, readonly=readonly)


def read_meta(c, key, default='0'):
    r = c.execute('SELECT value FROM meta WHERE key=?', (key,)).fetchone()
    return r['value'] if r else default


def write_meta(c, key, value):
    c.execute('INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) '
              'DO UPDATE SET value=excluded.value', (key, str(value)))


def quick_baseline_available(c, roots):
    if not roots:
        return False
    # A successful Full Scan is a baseline only for roots it covered. Archived
    # roots and changed configuration must never silently qualify for Quick.
    covered = {r['root'] for r in c.execute('''SELECT DISTINCT v.root FROM volume_scans v
        JOIN scans s ON s.id=v.scan_id
        WHERE s.status='success' AND COALESCE(s.mode,'full')='full' ''')}
    invalid = {r['root'] for r in c.execute('SELECT root FROM invalid_baselines')}
    aliases=json.loads(read_meta(c,'baseline_aliases_json','{}'))
    return all((root in covered or aliases.get(root) in covered)
               and root not in invalid for root in roots)


def excluded_roots(c):
    return {r['root'] for r in c.execute('SELECT root FROM excluded_roots')}


def effective_roots(db, configured_roots):
    c = connect(db, readonly=True)
    try:
        excluded = excluded_roots(c)
        return [r for r in configured_roots if r not in excluded]
    finally:
        c.close()


def archive_volume(db, root, configured_roots):
    """Administrative exclusion: no deletion event, no lifetime-savings credit."""
    if root not in configured_roots:
        raise ValueError('Unknown configured root')
    c = connect(db)
    try:
        with c:
            c.execute('INSERT OR REPLACE INTO excluded_roots(root,archived_at) VALUES(?,?)',
                      (root, time.time()))
            c.execute("INSERT OR REPLACE INTO invalid_baselines(root,reason) VALUES(?,'archived')",(root,))
            c.execute('DELETE FROM files WHERE root=?', (root,))
            c.execute('DELETE FROM work_files WHERE root=?', (root,))
            c.execute('DELETE FROM hash_cache WHERE root=?', (root,))
            c.execute('DELETE FROM partial_cache WHERE root=?', (root,))
    finally:
        c.close()


def restore_volume(db, root, configured_roots):
    if root not in configured_roots:
        raise ValueError('Unknown configured root')
    c = connect(db)
    try:
        with c:
            c.execute('DELETE FROM excluded_roots WHERE root=?', (root,))
            c.execute("INSERT OR REPLACE INTO invalid_baselines(root,reason) VALUES(?,'restored')",(root,))
    finally:
        c.close()


def current_metrics(c):
    rows = c.execute('''SELECT size,COUNT(*) n FROM files WHERE full IS NOT NULL AND size>0
        GROUP BY size,full HAVING COUNT(*)>1''')
    duplicates = wasted = 0
    for r in rows:
        duplicates += r['n'] - 1
        wasted += (r['n'] - 1) * r['size']
    return duplicates, wasted



def _scope_group_contribution(c, size, full, roots, scoped):
    """Redundant *paths owned by this scan's roots* in one exact SHA group.

    Choose the same deterministic global reference (lexicographically first
    path) as the volume-management table. Each redundant path is attributed to
    one root, so the per-root counts sum to the global duplicate count.
    """
    if not scoped:
        n=c.execute('SELECT COUNT(*) FROM work_files WHERE size=? AND full=?',
                    (size,full)).fetchone()[0]
        return (max(0,n-1),size*max(0,n-1))
    places=','.join('?' for _ in roots)
    row=c.execute(f"""SELECT COUNT(*) AS total,
        SUM(CASE WHEN root IN ({places}) THEN 1 ELSE 0 END) AS owned,
        MIN(path) AS first_path,
        MIN(CASE WHEN root IN ({places}) THEN path END) AS first_owned
        FROM work_files WHERE size=? AND full=?""",
        (*roots,*roots,size,full)).fetchone()
    if row['total']<2 or not row['owned']:
        return (0,0)
    copies=int(row['owned'])-int(row['first_path']==row['first_owned'])
    return (copies,copies*size)


def scan_scope_metrics(c, roots, scoped=False):
    """Confirmed redundant copies located in the current scan scope.

    Per-volume attribution is consistent with the volume-management table:
    each (size, full SHA-256) group retains the alphabetically first path as
    its reference; every other path belongs to exactly one volume's duplicate
    count. These are not *new duplicates found on this scan*, nor is this the
    all-volumes count when only one root was scanned.
    """
    if not scoped:
        row=c.execute("""SELECT COALESCE(SUM(n-1),0) copies,
            COALESCE(SUM(size*(n-1)),0) wasted FROM
            (SELECT size,COUNT(*) n FROM work_files
             WHERE full IS NOT NULL AND size>0
             GROUP BY size,full HAVING COUNT(*)>1)""").fetchone()
    else:
        places=','.join('?' for _ in roots)
        row=c.execute(f"""SELECT
            COALESCE(SUM(owned - CASE WHEN first_path=first_owned THEN 1 ELSE 0 END),0) copies,
            COALESCE(SUM(size * (owned - CASE WHEN first_path=first_owned THEN 1 ELSE 0 END)),0) wasted
            FROM (SELECT size,full, COUNT(*) n,
                SUM(CASE WHEN root IN ({places}) THEN 1 ELSE 0 END) owned,
                MIN(path) first_path,
                MIN(CASE WHEN root IN ({places}) THEN path END) first_owned
                FROM work_files WHERE full IS NOT NULL AND size>0
                GROUP BY size,full HAVING COUNT(*)>1) WHERE owned>0""",
            (*roots,*roots)).fetchone()
    return (int(row['copies'] or 0),int(row['wasted'] or 0))


def snapshot(c):
    """Compatibility helper for smaller inventories/tests, not used by scanning."""
    rows = c.execute('SELECT path,size,full FROM files WHERE full IS NOT NULL')
    groups = {}
    for r in rows:
        groups.setdefault((r['size'], r['full']), []).append(r['path'])
    return {k: sorted(v) for k, v in groups.items() if len(v) > 1}


def metrics(groups):
    return (sum(len(v)-1 for v in groups.values()),
            sum(k[0]*(len(v)-1) for k, v in groups.items()))


def validate_cifs_mounts(roots):
    mounts = {}
    with open('/proc/self/mountinfo', encoding='utf-8') as f:
        for line in f:
            left, sep, right = line.rstrip('\n').partition(' - ')
            if sep:
                fields, info = left.split(), right.split()
                if len(fields) > 4 and info:
                    mountpoint = fields[4].replace('\\040', ' ').replace('\\011', '\t')
                    mounts[os.path.realpath(mountpoint)] = info[0]
    for root in roots:
        if mounts.get(os.path.realpath(root)) != 'cifs':
            raise RuntimeError(f'Scan root is not an active CIFS mount: {root}')
        try:
            with os.scandir(root) as entries:
                next(entries, None)
        except OSError as exc:
            raise RuntimeError(f'Scan root is inaccessible: {root}: {exc}') from exc


class ScanCancelled(Exception):
    pass


class ScanControl:
    """Thread-safe pause/stop/progress and adjustable global content-read cap."""
    def __init__(self, bandwidth_mbps=250, file_workers=4):
        self._lock = threading.Lock()
        self._paused = threading.Event()
        self._stopped = threading.Event()
        self._can_stop = True
        self._stop_reason = ''
        self._rate_bps = 0.0
        self._tokens = 0.0
        self._tick = time.monotonic()
        self.file_workers = int(file_workers)
        if not 1 <= self.file_workers <= 16:
            raise ValueError('File workers must be between 1 and 16')
        self.fingerprint_profile = FINGERPRINT_PROFILE
        self.fingerprint_prefix = FINGERPRINT_PREFIX
        self.progress = {
            'stage': 'starting', 'volume': None, 'files_indexed': 0,
            'files_discovered': 0, 'per_volume_discovered': {}, 'candidate_files': 0,
            'candidate_bytes': 0,
            'partial_files_total': 0, 'partial_files_checked': 0,
            'partial_hashes_calculated': 0,
            'potential_hash_matches': 0,
            'partial_eliminated_files': 0,
            'partial_eliminated_bytes': 0,
            'full_files_total': 0, 'full_files_checked': 0,
            'full_hash_bytes_total': 0, 'full_hash_bytes_done': 0,
            'files_hashed': 0, 'bytes_read': 0, 'scan_id': None,
            'full_hashes_available': 0, 'full_hashes_calculated': 0,
            'confirmed_duplicate_copies': 0, 'confirmed_wasted_bytes': 0,
            'metrics_ready': False, 'metric_scope': 'scan',
            'started_at': None, 'file_workers': self.file_workers,
            'lifecycle': 'preparing', 'scan_mode': 'full',
            'finalizing_step': None, 'cache_partial_reused': 0,
            'cache_full_reused': 0, 'cache_remounted_roots': 0,
            'cache_full_metadata_misses': 0, 'cache_full_identity_misses': 0,
            'cache_full_unavailable': 0, 'publication_changed': 0, 'publication_removed': 0,
            'fingerprint_profile': self.fingerprint_profile,
            'io_files': 0, 'io_open_seconds': 0.0, 'io_seek_seconds': 0.0,
            'io_read_seconds': 0.0, 'io_hash_seconds': 0.0,
            'io_throttle_seconds': 0.0, 'io_stat_seconds': 0.0,
        }
        self.set_bandwidth(bandwidth_mbps)

    def set_bandwidth(self, mbps):
        mbps = float(mbps)
        if not 0 <= mbps <= 10000:
            raise ValueError('Bandwidth must be between 0 and 10000 Mbps')
        with self._lock:
            self._rate_bps = mbps * 1_000_000 / 8
            self._tokens = 0.0
            self._tick = time.monotonic()

    def bandwidth(self):
        with self._lock:
            return self._rate_bps * 8 / 1_000_000

    def pause(self):
        self._paused.set()

    def resume(self):
        self._paused.clear()

    def stop(self):
        # Server-side enforcement: the browser's disabled state is advisory.
        # Use one mutex for publication transition and stop requests to avoid
        # a race where a late request aborts a committed publication.
        with self._lock:
            if not self._can_stop:
                return False
            self._stopped.set()
            self._paused.clear()
            return True

    def begin_finalizing(self):
        self.check()
        with self._lock:
            if self._stopped.is_set():
                raise ScanCancelled('Scan cancelled before finalization')
            self._can_stop = False
            self._stop_reason = 'Inventory finalization cannot be interrupted safely'
            # Finalizing starts when file-content work finishes, not when
            # the noninterruptible publication transaction begins. Preserve
            # that timestamp as the frozen scan-duration cutoff.
            cutoff = self.progress.get('duration_cutoff_at') or time.time()
            self.progress.update(stage='finalizing', lifecycle='finalizing',
                                 duration_cutoff_at=cutoff,
                                 finalizing_step='Verifying scan results')

    def finalizing(self, step):
        with self._lock:
            # The first Finalizing operation stops the scan clock. All later
            # finalization, including the SQLite commit, is timed separately.
            self.progress.setdefault('duration_cutoff_at', time.time())
            self.progress.update(stage='finalizing', lifecycle='finalizing', finalizing_step=step)

    def stop_requested(self):
        return self._stopped.is_set()

    def set_progress(self, **kw):
        with self._lock:
            self.progress.update(kw)

    def add_progress(self, **kw):
        with self._lock:
            for key, value in kw.items():
                self.progress[key] += value

    def add_volume_discovered(self, root):
        with self._lock:
            self.progress['files_discovered'] += 1
            totals = self.progress['per_volume_discovered']
            totals[root] = totals.get(root, 0) + 1

    def snapshot(self):
        with self._lock:
            return {**self.progress, 'paused': self._paused.is_set(),
                    'stop_requested': self._stopped.is_set(),
                    'bandwidth_mbps': self._rate_bps * 8 / 1_000_000,
                    'can_stop': self._can_stop and not self._stopped.is_set(),
                    'stop_disabled_reason': self._stop_reason}

    def check(self):
        if self._stopped.is_set():
            raise ScanCancelled('Scan cancelled by user; completed hashes were retained')
        while self._paused.is_set():
            if self._stopped.is_set():
                raise ScanCancelled('Scan cancelled by user; completed hashes were retained')
            time.sleep(0.1)

    def before_read(self, requested):
        self.check()
        with self._lock:
            rate = self._rate_bps
        if rate == 0:
            return
        while True:
            self.check()
            with self._lock:
                now = time.monotonic()
                rate = self._rate_bps
                if rate == 0:
                    return
                # Smooth token bucket with a small maximum burst to protect other traffic.
                cap = max(READ_CHUNK, rate * 0.10)
                self._tokens = min(cap, self._tokens + (now - self._tick) * rate)
                self._tick = now
                if self._tokens >= requested:
                    self._tokens -= requested
                    return
                remaining = (requested - self._tokens) / rate
            time.sleep(min(max(remaining, 0.005), 0.10))


def sample_window_for_size(size):
    """Return a fixed 512 KiB window, or None for files fully checked in pass 1."""
    return None if size <= FULL_FIRST_PASS_LIMIT else SAMPLE_WINDOW


def sample_offsets(size, window=None):
    """Six distributed, nonoverlapping windows; small files are fully checked."""
    if window is None:
        window = sample_window_for_size(size)
        if window is None:
            return None
    if size <= SAMPLE_COUNT * window:
        return None
    last = size - window
    return tuple(last * i // (SAMPLE_COUNT - 1) for i in range(SAMPLE_COUNT))


def _record_path(path, size, expected, control, partial=False):
    """One open per file. Returns (fingerprint, complete_sha_or_None, timings).

    Files <=3 MiB are fully verified in the first pass; larger files are
    sampled in six windows. Historical sample profiles remain independent.
    """
    timing = {'io_files': 1, 'io_open_seconds': 0., 'io_seek_seconds': 0.,
              'io_read_seconds': 0., 'io_hash_seconds': 0.,
              'io_throttle_seconds': 0., 'io_stat_seconds': 0.}
    control.check()
    window = sample_window_for_size(size) if partial else None
    offsets = sample_offsets(size, window) if partial and window is not None else None
    whole_file = offsets is None
    h = hashlib.sha256()
    if partial and not whole_file:
        # Delimit the sampled ranges, so byte-boundary ambiguities cannot
        # produce accidental equality between different sample layouts.
        h.update(b'DFM-PARTIAL-4\0')
        h.update(struct.pack('>QII', size, window, SAMPLE_COUNT))
    tick = time.perf_counter()
    f = open(path, 'rb', buffering=0)
    timing['io_open_seconds'] += time.perf_counter() - tick
    with f:
        tick = time.perf_counter()
        before = os.fstat(f.fileno())
        timing['io_stat_seconds'] += time.perf_counter() - tick
        actual = (before.st_size, before.st_mtime_ns, before.st_dev, before.st_ino)
        if actual != expected:
            raise RuntimeError('File changed since enumeration: ' + path)
        sections = ((0, size),) if whole_file else ((offset, window) for offset in offsets)
        for offset, length in sections:
            control.check()
            if not whole_file:
                tick = time.perf_counter()
                f.seek(offset)
                timing['io_seek_seconds'] += time.perf_counter() - tick
                h.update(struct.pack('>QI', offset, length))
            remaining = length
            while remaining:
                n = min(READ_CHUNK, remaining)
                tick = time.perf_counter()
                control.before_read(n)
                timing['io_throttle_seconds'] += time.perf_counter() - tick
                tick = time.perf_counter()
                chunk = f.read(n)
                timing['io_read_seconds'] += time.perf_counter() - tick
                if not chunk:
                    raise RuntimeError('Unexpected EOF: ' + path)
                tick = time.perf_counter()
                h.update(chunk)
                timing['io_hash_seconds'] += time.perf_counter() - tick
                remaining -= len(chunk)
                if not partial:
                    control.add_progress(bytes_read=len(chunk), full_hash_bytes_done=len(chunk))
                else:
                    control.add_progress(bytes_read=len(chunk))
        tick = time.perf_counter()
        after = os.fstat(f.fileno())
        timing['io_stat_seconds'] += time.perf_counter() - tick
        if (after.st_size, after.st_mtime_ns, after.st_dev, after.st_ino) != expected:
            raise RuntimeError('File changed during hashing: ' + path)
    digest = h.hexdigest()
    if partial:
        # For fully read small files, h is precisely the real full SHA-256.
        return control.fingerprint_prefix + digest, digest if whole_file else None, timing
    return digest, digest, timing


def _compute_candidate(row, control, stage):
    expected = (row['size'], row['mtime_ns'], row['dev'], row['inode'])
    digest, full, timing = _record_path(row['path'], row['size'], expected,
                                        control, partial=(stage == 'partial_hashing'))
    return row, digest, full, timing


def _save_hash_batch(c, outputs, stage, control):
    """Only the coordinator writes SQLite. Results are committed per bounded page.

    Worker threads never share an SQLite connection, and no read cursor stays
    open during SMB reads or while writing checkpoints.
    """
    if not outputs:
        return
    updated_full = dupes = wasted = 0
    meta=control.snapshot()
    roots=tuple(meta.get('scan_scope') or ())
    # TEMP staging is also used by All Volumes Quick Scan. Scope attribution
    # must depend on the scan's selected roots, not its storage mechanism.
    scoped=bool(meta.get('scoped_scan'))
    timings = {'io_files': 0, 'io_open_seconds': 0., 'io_seek_seconds': 0.,
               'io_read_seconds': 0., 'io_hash_seconds': 0.,
               'io_throttle_seconds': 0., 'io_stat_seconds': 0.}
    with c:
        for row, digest, full, timing in outputs:
            for field in timings:
                timings[field] += timing[field]
            before=(0,0)
            if scoped and full is not None and row['full'] is None:
                before=_scope_group_contribution(c,row['size'],full,roots,scoped)
            if stage == 'partial_hashing':
                partial = digest
                if full is not None:
                    # No second read needed: content already fully hashed.
                    c.execute('UPDATE work_files SET partial=?,full=? WHERE path=?',
                              (partial, full, row['path']))
                else:
                    c.execute('UPDATE work_files SET partial=? WHERE path=?',
                              (partial, row['path']))
            else:
                full = digest
                c.execute('UPDATE work_files SET full=? WHERE path=?',
                          (full, row['path']))
            if full is not None and row['full'] is None:
                updated_full += 1
                # Count matches committed from previous pages AND from this page.
                # This query runs *after* the current UPDATE, so n>1 implies
                # at least one distinct existing fully hashed copy.
                if scoped:
                    after=_scope_group_contribution(c,row['size'],full,roots,scoped)
                    dupes += after[0]-before[0]
                    wasted += after[1]-before[1]
                else:
                    n = c.execute('SELECT COUNT(*) n FROM work_files WHERE size=? AND full=?',
                                  (row['size'], full)).fetchone()['n']
                    if n > 1:
                        dupes += 1
                        wasted += row['size']
            if stage == 'partial_hashing':
                c.execute('''INSERT INTO partial_cache
                        (path,profile,root,size,mtime_ns,dev,inode,partial)
                        VALUES(?,?,?,?,?,?,?,?)
                        ON CONFLICT(path,profile) DO UPDATE SET
                        root=excluded.root,size=excluded.size,
                        mtime_ns=excluded.mtime_ns,dev=excluded.dev,
                        inode=excluded.inode,partial=excluded.partial''',
                        (row['path'], control.fingerprint_profile,
                         row['root'],row['size'],row['mtime_ns'],
                         row['dev'],row['inode'],digest))
            c.execute('''INSERT INTO hash_cache(path,root,size,mtime_ns,dev,inode,partial,samples,full)
                         SELECT path,root,size,mtime_ns,dev,inode,partial,NULL,full
                         FROM work_files WHERE path=?
                         ON CONFLICT(path) DO UPDATE SET
                         root=excluded.root,size=excluded.size,mtime_ns=excluded.mtime_ns,
                         dev=excluded.dev,inode=excluded.inode,
                         partial=excluded.partial,samples=NULL,full=excluded.full''',
                      (row['path'],))
    changes = dict(timings)
    if updated_full:
        changes.update(full_hashes_available=updated_full,
                       full_hashes_calculated=updated_full,
                       confirmed_duplicate_copies=dupes,
                       confirmed_wasted_bytes=wasted)
    if stage == 'partial_hashing':
        changes['partial_hashes_calculated'] = len(outputs)
    else:
        changes['files_hashed'] = len(outputs)
    control.add_progress(**changes)


def _hash_candidate_pages(c, predicate, params, stage, control, scan_id):
    """Bounded worker parallelism with a single coordinated SQLite writer."""
    with ThreadPoolExecutor(max_workers=control.file_workers,
                            thread_name_prefix='dfm-smb') as executor:
        for page_number, rows in enumerate(_work_pages(c, predicate, params)):
            control.check()
            if rows:
                control.set_progress(volume=rows[-1]['root'])
            field = 'partial' if stage == 'partial_hashing' else 'full'
            needed = [row for row in rows if row[field] is None]
            futures = [executor.submit(_compute_candidate, row, control, stage)
                       for row in needed]
            outputs = []
            first_error = None
            for future in as_completed(futures):
                try:
                    outputs.append(future.result())
                except Exception as exc:
                    if first_error is None:
                        first_error = exc
            # Preserve successful work even if a different worker failed.
            _save_hash_batch(c, outputs, stage, control)
            if stage == 'partial_hashing':
                control.add_progress(partial_files_checked=len(rows))
            else:
                control.add_progress(full_files_checked=len(rows))
            if first_error is not None:
                raise first_error
            if (page_number+1) % CHECKPOINT_EVERY_PAGES == 0:
                _wal_checkpoint(c)
                _set_stage(c, scan_id, stage, control)


def _work_pages(c, predicate, params=(), page_size=CANDIDATE_PAGE):
    """Fetch candidate rows in bounded pages and CLOSE the read cursor before
    returning any rows for hashing/writing. Never pin a WAL snapshot for an
    entire hashing stage.

    Rowid pagination is safe: hashing changes only fingerprint columns, not
    work_files row IDs or file membership. Candidate group tables must be
    finalized before the first page is read.
    """
    after = 0
    sql = ('SELECT w.rowid AS scan_rowid, w.* FROM work_files AS w '
           'WHERE w.rowid > ? AND (' + predicate + ') '
           'ORDER BY w.rowid LIMIT ?')
    while True:
        cursor = c.execute(sql, (after, *params, page_size))
        try:
            rows = cursor.fetchall()
        finally:
            cursor.close()
        if not rows:
            return
        after = rows[-1]['scan_rowid']
        yield rows


def _wal_checkpoint(c, mode='PASSIVE'):
    """Checkpoint between bounded read batches, never under a read cursor.
    PASSIVE does not wait for transient API readers. The SQLite auto-checkpoint
    also remains enabled; TRUNCATE is used only at stage boundaries.
    """
    result = c.execute('PRAGMA wal_checkpoint(' + mode + ')').fetchone()
    # SQLite returns (busy, log_pages, checkpointed_pages). A busy reader can
    # postpone a truncate, so we log it and retry on a later stage.
    if result and result[0]:
        print('WAL checkpoint deferred ('+mode+'): '+str(tuple(result)),flush=True)
    return result


def _set_stage(c, scan_id, stage, control):
    if control:
        control.set_progress(stage=stage)
        p = control.snapshot()
        with c:
            c.execute('''INSERT INTO scan_progress(id,scan_id,stage,file_count,candidates,
                         fully_hashed,read_bytes,updated) VALUES(1,?,?,?,?,?,?,?)
                         ON CONFLICT(id) DO UPDATE SET
                         scan_id=excluded.scan_id,stage=excluded.stage,
                         file_count=excluded.file_count,candidates=excluded.candidates,
                         fully_hashed=excluded.fully_hashed,read_bytes=excluded.read_bytes,
                         updated=excluded.updated''',
                      (scan_id, stage, p['files_indexed'], p['candidate_files'],
                       p['files_hashed'], p['bytes_read'], time.time()))


def _check_roots(rootlist, require_mounts):
    if not rootlist:
        raise ValueError('No active scan roots')
    if len(set(rootlist)) != len(rootlist):
        raise ValueError('Duplicate scan root')
    for i, root in enumerate(rootlist):
        if not os.path.isdir(root):
            raise ValueError('Scan root missing: ' + root)
        if any(root.startswith(other + os.sep) for j, other in enumerate(rootlist) if j != i):
            raise ValueError('Overlapping scan roots')
    if require_mounts:
        validate_cifs_mounts(rootlist)



class _ScopedDiscoveryMetrics:
    """Live counts for cached SHA-256 files as a scoped scan discovers them.

    Old hashes are only reused with *matching file metadata and identity*.
    Counts are therefore confirmed for files seen so far, not a guess based on
    the old per-volume totals. Unhashed/changed files are counted later during
    content verification. All work is in-memory, with indexed READS only.
    """
    def __init__(self, c, roots, control, has_outside=True):
        self.control=control
        self.has_outside=has_outside
        self.baseline={}
        places=','.join('?' for _ in roots)
        for r in c.execute(f"""SELECT path,size,mtime_ns,dev,inode,full FROM files
                WHERE root IN ({places}) AND size>0 AND full IS NOT NULL""", roots):
            self.baseline[r['path']]=(r['size'],r['mtime_ns'],r['dev'],r['inode'],r['full'])
        self.groups={}
        self.outside_first={}
        self.duplicates=0
        self.wasted=0

    def _contribution(self, selected_count, selected_first, outside_first):
        if not selected_count:
            return 0
        if outside_first is None and selected_count<2:
            return 0
        return selected_count-int(outside_first is None or selected_first<outside_first)

    def observe(self, c, batch):
        # This runs only in the SQLite coordinator, after the batch has been
        # enumerated. No worker-thread SQLite calls or writes to the DB cache.
        for path,root,size,mtime_ns,dev,inode in batch:
            cached=self.baseline.get(path)
            if cached is None or cached[:4]!=(size,mtime_ns,dev,inode):
                continue
            full=cached[4]
            group=(size,full)
            if group not in self.outside_first and self.has_outside:
                # The selected new files still have NULL full in work_files;
                # only the preserved/unscanned volumes can match here.
                row=c.execute('SELECT MIN(path) FROM work_files WHERE size=? AND full=?',group).fetchone()
                self.outside_first[group]=row[0]
            outside=self.outside_first.get(group)
            previous_n,previous_first=self.groups.get(group,(0,None))
            previous=self._contribution(previous_n,previous_first,outside)
            current_n=previous_n+1
            current_first=min(previous_first,path) if previous_first is not None else path
            current=self._contribution(current_n,current_first,outside)
            self.groups[group]=(current_n,current_first)
            increase=current-previous
            self.duplicates+=increase
            self.wasted+=increase*size
        self.control.set_progress(metrics_ready=True,
                                  confirmed_duplicate_copies=self.duplicates,
                                  confirmed_wasted_bytes=self.wasted)


def _enumerate_parallel(c, rootlist, control, scan_id, discovery_metrics=None):
    """Traverse SMB trees using the same file-worker setting as comparisons.

    Prefer one active directory per volume until all volumes have been started.
    As workers become available, assist remaining volumes with discovered
    subdirectories. Directory tasks exist only in memory; the main thread is
    the sole SQLite writer. Result batches are bounded to protect memory.
    """
    pending = {root: deque([root]) for root in rootlist}
    active = {root: 0 for root in rootlist}
    started = set()
    condition = threading.Condition()
    written = Queue(maxsize=max(4,control.file_workers*2))
    errors = []
    task_failures = []
    worker_count = control.file_workers
    last_root = -1

    def take_directory():
        nonlocal last_root
        while True:
            # Pause/cancel checks must never hold the directory-queue lock.
            control.check()
            with condition:
                # Allocate one worker to each not-yet-started root first.
                for root in rootlist:
                    if root not in started and pending[root]:
                        started.add(root)
                        active[root] += 1
                        return root, pending[root].popleft()
                # Then balance workers over the remaining directory trees.
                available = [(active[root], (i-last_root-1)%len(rootlist),i,root)
                             for i,root in enumerate(rootlist) if pending[root]]
                if available:
                    _,_,i,root = min(available)
                    last_root = i
                    active[root] += 1
                    return root,pending[root].popleft()
                if not any(active.values()):
                    return None
                condition.wait(timeout=0.15)

    def walk_worker():
        try:
            while True:
                task = take_directory()
                if task is None:
                    break
                root, directory = task
                batch = []
                discovered_dirs = []
                try:
                    control.set_progress(volume=root)
                    with os.scandir(directory) as entries:
                        for entry in entries:
                            control.check()
                            try:
                                if entry.is_dir(follow_symlinks=False):
                                    discovered_dirs.append(entry.path)
                                    # Let idle workers take subdirectories early.
                                    if len(discovered_dirs)>=32:
                                        with condition:
                                            pending[root].extend(discovered_dirs)
                                            condition.notify_all()
                                        discovered_dirs.clear()
                                elif entry.is_file(follow_symlinks=False):
                                    st = entry.stat(follow_symlinks=False)
                                    if stat.S_ISREG(st.st_mode):
                                        batch.append((entry.path,root,st.st_size,
                                                      st.st_mtime_ns,st.st_dev,st.st_ino))
                                        control.add_volume_discovered(root)
                                        if len(batch)>=BATCH:
                                            written.put(batch)
                                            batch=[]
                            except OSError as exc:
                                errors.append(f'{entry.path}: {exc}')
                    if batch:
                        written.put(batch)
                except OSError as exc:
                    errors.append(f'{directory}: {exc}')
                finally:
                    with condition:
                        if discovered_dirs:
                            pending[root].extend(discovered_dirs)
                        active[root] -= 1
                        condition.notify_all()
        except Exception as exc:
            task_failures.append(exc)
            control.stop()
            with condition:
                condition.notify_all()
        finally:
            written.put(None)

    count, finished, buffered = 0, 0, []
    def commit_batch():
        nonlocal count, buffered
        if not buffered:
            return
        with c:
            c.executemany("""INSERT INTO work_files(path,root,size,mtime_ns,dev,inode)
                             VALUES(?,?,?,?,?,?)""", buffered)
        previous = count
        count += len(buffered)
        control.add_progress(files_indexed=len(buffered))
        if discovery_metrics is not None:
            discovery_metrics.observe(c,buffered)
        buffered = []
        if count//10000 != previous//10000:
            _set_stage(c,scan_id,'enumerating',control)

    write_error = None
    with ThreadPoolExecutor(max_workers=worker_count,
                            thread_name_prefix='dfm-discover') as executor:
        futures = [executor.submit(walk_worker) for _ in range(worker_count)]
        while finished < worker_count:
            entry = written.get()
            if entry is None:
                finished += 1
                continue
            if write_error is None:
                try:
                    buffered.extend(entry)
                    if len(buffered)>=BATCH:
                        commit_batch()
                except Exception as exc:
                    # Keep draining the bounded queue, or blocked producers
                    # could prevent executor shutdown after a SQLite failure.
                    write_error = exc
                    control.stop()
                    with condition:
                        condition.notify_all()
        if write_error is None:
            try:
                commit_batch()
            except Exception as exc:
                write_error = exc
        for future in futures:
            future.result()
    if write_error is not None:
        raise write_error
    if task_failures:
        raise task_failures[0]
    return count,errors


def _changes_since_published(c, root):
    """Path-based changes plus *possible* content-matched moves within root.

    Renames are inherently ambiguous when multiple identical files exist:
    a new path plus a removed path with the same complete SHA-256 is only a
    possible rename/move, not proof of an actual filesystem rename.
    """
    added = c.execute('''SELECT COUNT(*) FROM work_files w WHERE w.root=? AND
        NOT EXISTS(SELECT 1 FROM files f WHERE f.path=w.path)''',(root,)).fetchone()[0]
    removed = c.execute('''SELECT COUNT(*) FROM files f WHERE f.root=? AND
        NOT EXISTS(SELECT 1 FROM work_files w WHERE w.path=f.path)''',(root,)).fetchone()[0]
    modified = c.execute('''SELECT COUNT(*) FROM work_files w
        JOIN files f ON f.path=w.path WHERE w.root=? AND
        (w.size!=f.size OR w.mtime_ns!=f.mtime_ns)''',(root,)).fetchone()[0]
    potential = c.execute('''SELECT COALESCE(SUM(MIN(l.n,r.n)),0) FROM
      (SELECT f.size,f.full,COUNT(*) n FROM files f WHERE f.root=? AND
        f.full IS NOT NULL AND NOT EXISTS(SELECT 1 FROM work_files w WHERE w.path=f.path)
        GROUP BY f.size,f.full) l JOIN
      (SELECT w.size,w.full,COUNT(*) n FROM work_files w WHERE w.root=? AND
        w.full IS NOT NULL AND NOT EXISTS(SELECT 1 FROM files f WHERE f.path=w.path)
        GROUP BY w.size,w.full) r ON l.size=r.size AND l.full=r.full''',
        (root,root)).fetchone()[0]
    return {'added':int(added),'removed':int(removed),
            'modified':int(modified),'possible_moves':int(potential)}


def _remounted_cifs_roots(c, roots, require_mounts):
    """Detect wholesale CIFS inode/device remapping, not isolated replacements.

    Reuse hashes based on path/size/mtime only when an entire CIFS mount
    demonstrably changed its host-local identity. An isolated inode change on
    a stable mount is treated as a new file and rehashed. Never use the
    relaxed rule on ordinary local filesystems.
    """
    if not require_mounts:
        return set()
    allowed = set()
    for root in roots:
        row = c.execute('''SELECT COUNT(*) total,
            SUM(CASE WHEN (h.dev != w.dev OR h.inode != w.inode) THEN 1 ELSE 0 END) changed,
            SUM(CASE WHEN h.dev != w.dev THEN 1 ELSE 0 END) device_changed
            FROM work_files w JOIN hash_cache h ON h.path=w.path
            WHERE w.root=? AND h.root=w.root AND h.size=w.size
              AND h.mtime_ns=w.mtime_ns''', (root,)).fetchone()
        total = int(row['total'] or 0)
        changed = int(row['changed'] or 0)
        # A significant majority of at least five otherwise-identical files
        # must have been remapped. Avoid trusting lone replaced files.
        if total >= 5 and changed >= 5 and changed / total >= 0.90:
            allowed.add(root)
            print(f'CIFS mount identity remapped: {root}; {changed}/{total} files', flush=True)
    return allowed


def _prepare_publication_delta(c, control):
    """Compute only path-level changes against authoritative inventory.

    SQLite compares indexed paths once. A Quick Scan with a handful of changed
    paths must not rewrite all 373k published file rows.
    """
    control.finalizing('Identifying changed inventory records')
    c.execute('DROP TABLE IF EXISTS temp.publish_changed')
    c.execute('DROP TABLE IF EXISTS temp.publish_removed')
    c.execute('CREATE TEMP TABLE publish_changed(path TEXT PRIMARY KEY) WITHOUT ROWID')
    c.execute('CREATE TEMP TABLE publish_removed(path TEXT PRIMARY KEY) WITHOUT ROWID')
    c.execute('''INSERT INTO publish_changed(path)
        SELECT w.path FROM work_files w LEFT JOIN files f ON f.path=w.path
        WHERE f.path IS NULL OR f.root IS NOT w.root OR f.size IS NOT w.size
          OR f.mtime_ns IS NOT w.mtime_ns OR f.dev IS NOT w.dev
          OR f.inode IS NOT w.inode OR f.partial IS NOT w.partial
          OR f.full IS NOT w.full''')
    control.check()
    c.execute('''INSERT INTO publish_removed(path)
        SELECT f.path FROM files f
        WHERE NOT EXISTS (SELECT 1 FROM work_files w WHERE w.path=f.path)''')
    control.check()
    changed=c.execute('SELECT COUNT(*) FROM publish_changed').fetchone()[0]
    removed=c.execute('SELECT COUNT(*) FROM publish_removed').fetchone()[0]
    control.set_progress(publication_changed=changed, publication_removed=removed)
    print('Publication delta: '+json.dumps({'upsert':changed,'removed':removed}),flush=True)
    return changed, removed


def _verified_savings_credit(c):
    """One SQL statement over *removed* paths, never every duplicate group.

    Preserve the historical rule: credit only disappearing redundant copies,
    and only when an old member survived at the same path with identical full
    content. Replacements at a path do not count as deletions.
    """
    return int(c.execute('''
        WITH missing AS (
          SELECT f.size, f.full, COUNT(*) AS gone
          FROM files f JOIN temp.publish_removed d ON d.path=f.path
          WHERE f.full IS NOT NULL AND f.size>0
          GROUP BY f.size,f.full
        )
        SELECT COALESCE(SUM(CASE
          WHEN (SELECT COUNT(*) FROM files f
                WHERE f.size=m.size AND f.full=m.full)>1
           AND EXISTS(SELECT 1 FROM files f JOIN work_files w ON w.path=f.path
                WHERE f.size=m.size AND f.full=m.full
                  AND w.size=f.size AND w.full=f.full)
          THEN m.size * MIN(m.gone, MAX(0,
               (SELECT COUNT(*) FROM files f WHERE f.size=m.size AND f.full=m.full)
             - (SELECT COUNT(*) FROM work_files w WHERE w.size=m.size AND w.full=m.full)))
          ELSE 0 END),0) AS credit
        FROM missing m
        ''').fetchone()['credit'])


def _apply_publication_delta(c):
    """Atomically change published rows corresponding to actual differences."""
    c.execute('DELETE FROM files WHERE path IN (SELECT path FROM temp.publish_removed)')
    c.execute('''INSERT INTO files(path,root,size,mtime_ns,dev,inode,partial,full)
        SELECT w.path,w.root,w.size,w.mtime_ns,w.dev,w.inode,w.partial,w.full
        FROM work_files w JOIN temp.publish_changed d ON d.path=w.path
        WHERE 1 ON CONFLICT(path) DO UPDATE SET
        root=excluded.root,size=excluded.size,mtime_ns=excluded.mtime_ns,
        dev=excluded.dev,inode=excluded.inode,partial=excluded.partial,
        full=excluded.full''')


def _prune_changed_cache(c):
    """Clean cache entries for changed/removed paths only.

    All unchanged historical sampling profiles remain available. The complete
    staging inventory is deliberately retained as a resumable checkpoint and
    cleared at the beginning of the next scan, never in the success transaction.
    """
    c.execute('''DELETE FROM hash_cache
        WHERE path IN (SELECT path FROM temp.publish_removed)''')
    c.execute('''DELETE FROM partial_cache
        WHERE path IN (SELECT path FROM temp.publish_removed)''')
    # A changed file must not retain another profile from its previous
    # contents. Keep all current profiles whose size/mtime/identity matches.
    c.execute('''DELETE FROM partial_cache WHERE path IN
        (SELECT path FROM temp.publish_changed)
        AND NOT EXISTS (SELECT 1 FROM files f WHERE f.path=partial_cache.path
           AND f.size=partial_cache.size AND f.mtime_ns=partial_cache.mtime_ns
           AND f.dev=partial_cache.dev AND f.inode=partial_cache.inode)''')
    c.execute('''DELETE FROM hash_cache WHERE path IN
        (SELECT path FROM temp.publish_changed)
        AND NOT EXISTS (SELECT 1 FROM files f WHERE f.path=hash_cache.path
           AND f.size=hash_cache.size AND f.mtime_ns=hash_cache.mtime_ns
           AND f.dev=hash_cache.dev AND f.inode=hash_cache.inode)''')



def _snapshot_volume_duplicate_metrics(c, roots):
    #Attribute confirmed duplicates from the final staged inventory.

    # The staging table is complete before publication. Calculating this BEFORE
    # the write transaction avoids a full-inventory GROUP BY / ORDER BY while
    # SQLite holds the publication write lock. The result is identical to
    # running the query against `files` immediately after the delta is applied.
    totals = {root: [0, 0] for root in roots}
    previous = None
    for row in c.execute('''SELECT size,full,root,COUNT(*) n,MIN(path) first_path
            FROM work_files WHERE size>0 AND full IS NOT NULL
            GROUP BY size,full,root ORDER BY size,full,first_path'''):
        group = row['size'], row['full']
        copies = row['n'] - (1 if group != previous else 0)
        previous = group
        if copies and row['root'] in totals:
            totals[row['root']][0] += copies
            totals[row['root']][1] += copies * row['size']
    return totals

def _create_scoped_work_table(c):
    """Stage scoped scans in memory instead of rewriting the NAS-backed WAL.

    A TEMP table shadows work_files in this SQLite connection only. Other
    connections continue to see the durable working table. The published
    inventory is untouched until the final atomic publication transaction.
    """
    c.execute('PRAGMA temp_store=MEMORY')
    c.execute('''CREATE TEMP TABLE work_files(
        path TEXT PRIMARY KEY, root TEXT NOT NULL, size INTEGER NOT NULL,
        mtime_ns INTEGER NOT NULL, dev INTEGER NOT NULL, inode INTEGER NOT NULL,
        partial TEXT, samples TEXT, full TEXT)''')


def _index_scoped_work_table(c):
    """Create the temporary indexes after copying preserved rows."""
    c.execute('CREATE INDEX temp.work_size_idx ON work_files(size)')
    c.execute('CREATE INDEX temp.work_partial_idx ON work_files(size,partial)')
    c.execute('CREATE INDEX temp.work_samples_idx ON work_files(size,samples)')
    c.execute('CREATE INDEX temp.work_full_idx ON work_files(size,full) WHERE full IS NOT NULL')


def scan(db, roots, control=None, mode='full', preserved_roots=()):
    """Scan selected roots while preserving all other active published inventory.

    Existing files on unselected volumes are copied into staging from SQLite
    (no SMB enumeration/content reads), so global duplicate groups remain
    correct. Only selected root metadata and the scan outcome are recorded.
    """
    if mode not in ('full', 'quick'):
        raise ValueError('Unknown scan mode')
    start = time.time()
    c = connect(db)
    scan_id = None
    require_mounts = os.getenv('REQUIRE_CIFS_MOUNTS', 'false').lower() == 'true'
    rootlist = [os.path.realpath(root) for root in roots]
    preserved_roots = [os.path.realpath(root) for root in preserved_roots]
    # Quick Scan is incremental and must never clear the large persistent
    # work_files checkpoint just to enumerate existing source metadata. The
    # previously established TEMP staging path works for ALL volumes too.
    # Full all-volumes scans retain the original durable working checkpoint.
    staging_in_memory = bool(preserved_roots) or mode == 'quick'
    if len(rootlist) != len(set(rootlist)) or (set(rootlist) & set(preserved_roots)):
        raise ValueError('Scan roots and preserved roots must be disjoint')
    if control is None:
        control = ScanControl(0)
    try:
        # Record a run before checking the source mounts, so even a missing
        # share produces a visible, specific Failed result in Scan Progress.
        with c:
            # An interrupted scan from a killed container is not actually
            # running. Reconcile its history in the SAME transaction as the
            # next scan registration. Never fsync solely for startup recovery.
            c.execute("""UPDATE scans SET status='interrupted', ended=COALESCE(ended,?),
                error=CASE WHEN error IS NULL OR error='' THEN
                'Scanner process exited before completion' ELSE error END
                WHERE status='running'""", (start,))
            cur = c.execute('INSERT INTO scans(started,status,mode) VALUES(?,?,?)',
                            (start,'running',mode))
            scan_id = cur.lastrowid
        control.set_progress(scan_id=scan_id, started_at=start, scan_mode=mode,
                             scan_scope=list(rootlist), scanned_roots=list(rootlist),
                             staging_in_memory=staging_in_memory,
                             scoped_scan=bool(preserved_roots),
                             metrics_ready=False, metric_scope='scan',
                             per_volume_discovered={})
        if mode == 'quick':
            # No Quick Scan without a completed Full Scan covering each active
            # root. Historical successful scans are migrated as 'full'.
            if not quick_baseline_available(c, rootlist):
                raise ValueError('Run a full scan first. Quick Scan needs a valid baseline for every active volume.')
        _check_roots(rootlist, require_mounts)
        # Never silently count a removed/renamed configured volume as deleted files.
        allowed_roots = set(rootlist) | set(preserved_roots)
        absent = [r['root'] for r in c.execute('SELECT DISTINCT root FROM files')
                  if r['root'] not in allowed_roots]
        if absent:
            raise RuntimeError('Previously monitored volume missing from configuration; '
                               'archive or relocate it first: ' + ', '.join(absent))
        # Preparation can touch hundreds of thousands of rows. The progress
        # callback permits Stop to interrupt a long SQLite statement and roll
        # back its transaction rather than leaving the UI stuck at zero files.
        # It is removed BEFORE recording a cancelled run in the scans table.
        control.set_progress(stage='preparing', lifecycle='preparing',
                             preparing_step='Preparing scan inventory')
        control.check()
        preparing_since = time.monotonic()
        # Every Quick Scan, including All Volumes, must avoid deleting the
        # entire durable working table and generating an enormous SQLite WAL.
        # The TEMP shadow is connection-local and discarded automatically.
        # Preserve unselected roots from published inventory on scoped scans.
        if staging_in_memory:
            control.set_progress(preparing_step='Preparing in-memory workspace')
            _create_scoped_work_table(c)
        c.set_progress_handler(lambda: 1 if control.stop_requested() else 0, 2000)
        try:
            with c:
                if not staging_in_memory:
                    c.execute('DELETE FROM work_files')
                control.check()
                if preserved_roots:
                    control.set_progress(preparing_step='Loading cached inventory for other volumes')
                    c.executemany('''INSERT INTO work_files
                        (path,root,size,mtime_ns,dev,inode,partial,samples,full)
                        SELECT path,root,size,mtime_ns,dev,inode,partial,NULL,full
                        FROM files WHERE root=?''', [(root,) for root in preserved_roots])
                    control.check()
                    control.set_progress(preparing_step='Indexing in-memory inventory')
                if staging_in_memory:
                    # Empty all-volume workspaces get their indexes instantly;
                    # scoped scans index after copying preserved rows.
                    _index_scoped_work_table(c)
                control.check()
                # A legacy backfill is necessary only once per database. On
                # every subsequent scan the hash_cache is maintained by the
                # comparison workers; repeating this indexed SELECT/INSERT
                # was an expensive, unnecessary start-up operation.
                if read_meta(c, 'legacy_hash_cache_backfilled', '0') != '1':
                    c.execute('''INSERT OR IGNORE INTO hash_cache(
                         path,root,size,mtime_ns,dev,inode,partial,samples,full)
                         SELECT path,root,size,mtime_ns,dev,inode,partial,NULL,full
                         FROM files WHERE partial IS NOT NULL OR full IS NOT NULL''')
                    write_meta(c, 'legacy_hash_cache_backfilled', '1')
                # Legacy profile migration is intentionally scan-scoped.
                # Previously it could trigger hundreds of thousands of DB
                # writes before the web UI became available at all.
                if read_meta(c,'partial_profile_migrated','0') != '1':
                    for table in ('hash_cache','files'):
                        c.execute(f"""INSERT OR IGNORE INTO partial_cache
                          (path,profile,root,size,mtime_ns,dev,inode,partial)
                          SELECT path,substr(partial,1,instr(partial,':')-1),root,
                                 size,mtime_ns,dev,inode,partial FROM {table}
                          WHERE partial LIKE 'pf2-%:%' OR partial LIKE 'pf3-%:%' OR partial LIKE 'pf4-%:%'""")
                    write_meta(c,'partial_profile_migrated','1')
                control.check()
        except sqlite3.OperationalError as exc:
            if control.stop_requested() and 'interrupted' in str(exc).lower():
                raise ScanCancelled('Scan cancelled during database preparation') from exc
            raise
        finally:
            c.set_progress_handler(None, 0)
            print('Scan preparation elapsed seconds:',
                  round(time.monotonic()-preparing_since, 2), flush=True)
        control.check()
        checkpoint_mode = 'PASSIVE' if mode == 'quick' or preserved_roots else 'TRUNCATE'
        control.set_progress(lifecycle='running', preparing_step=None)
        _set_stage(c, scan_id, 'enumerating', control)
        discovery_metrics = (_ScopedDiscoveryMetrics(c,rootlist,control, bool(preserved_roots))
                             if mode == 'quick' else None)
        count, errors = _enumerate_parallel(c, rootlist, control, scan_id, discovery_metrics)
        # Drop cached baseline dictionaries and group ledgers before expensive
        # comparison work; the authoritative staged SQL rows remain in memory.
        del discovery_metrics
        if errors:
            raise RuntimeError('Enumeration failed; completed inventory unchanged: '
                               + '; '.join(errors[:5]))
        if require_mounts:
            validate_cifs_mounts(rootlist)
        # Do not reject legitimate deletions based on the magnitude of an
        # inventory reduction. Mount validation and enumeration errors are
        # independently checked above; file-count thresholds are not evidence
        # of a failed scan.
        # Cached full-file hashes are algorithm-independent. Reuse a previous
        # identity or an established *whole-mount* CIFS remap, never a lone
        # changed inode within the same mount. Metadata mismatch always misses.
        remounted = _remounted_cifs_roots(c, rootlist, require_mounts)
        control.set_progress(cache_remounted_roots=len(remounted))
        # Keep remount identity checks as one SQL expression (no 373k Python
        # callbacks), with a temporary list indexed by root.
        c.execute('CREATE TEMP TABLE IF NOT EXISTS remounted_roots(root TEXT PRIMARY KEY)')
        c.execute('DELETE FROM temp.remounted_roots')
        if remounted:
            c.executemany('INSERT INTO temp.remounted_roots VALUES(?)', [(r,) for r in remounted])
        cache_match = '''(h.dev=work_files.dev AND h.inode=work_files.inode
           OR EXISTS(SELECT 1 FROM temp.remounted_roots rr WHERE rr.root=work_files.root))'''
        partial_match = cache_match.replace('h.', 'p.')
        with c:
            c.execute(f'''UPDATE work_files SET
               partial=(SELECT p.partial FROM partial_cache p
                        WHERE p.path=work_files.path AND p.root=work_files.root
                        AND p.profile=? AND p.size=work_files.size
                        AND p.mtime_ns=work_files.mtime_ns AND {partial_match}),
               samples=NULL,
               full=(SELECT h.full FROM hash_cache h WHERE h.path=work_files.path
                        AND h.root=work_files.root AND h.size=work_files.size
                        AND h.mtime_ns=work_files.mtime_ns AND {cache_match})
               WHERE work_files.root IN ({','.join('?' for _ in rootlist)})''',
                (control.fingerprint_profile, *rootlist))
        reused = c.execute('''SELECT
            SUM(CASE WHEN partial IS NOT NULL THEN 1 ELSE 0 END) p,
            SUM(CASE WHEN full IS NOT NULL THEN 1 ELSE 0 END) f
            FROM work_files''').fetchone()
        cache_reasons = c.execute('''SELECT
          SUM(CASE WHEN h.full IS NULL THEN 1 ELSE 0 END) unavailable,
          SUM(CASE WHEN h.full IS NOT NULL AND
            (h.size<>w.size OR h.mtime_ns<>w.mtime_ns OR h.root<>w.root)
            THEN 1 ELSE 0 END) metadata_misses,
          SUM(CASE WHEN h.full IS NOT NULL AND h.size=w.size
            AND h.mtime_ns=w.mtime_ns AND h.root=w.root
            AND (h.dev<>w.dev OR h.inode<>w.inode)
            AND NOT EXISTS(SELECT 1 FROM remounted_roots rr WHERE rr.root=w.root)
            THEN 1 ELSE 0 END) identity_misses
          FROM work_files w LEFT JOIN hash_cache h ON h.path=w.path''').fetchone()
        cache_metrics = dict(cache_partial_reused=int(reused['p'] or 0),
                             cache_full_reused=int(reused['f'] or 0),
                             cache_full_unavailable=int(cache_reasons['unavailable'] or 0),
                             cache_full_metadata_misses=int(cache_reasons['metadata_misses'] or 0),
                             cache_full_identity_misses=int(cache_reasons['identity_misses'] or 0))
        control.set_progress(**cache_metrics)
        print('Cache reuse: '+json.dumps({**cache_metrics,
             'cifs_remapped_roots':sorted(remounted)}),flush=True)
        # An existing complete SHA-256 is already proof for a <=3 MiB file.
        # Derive this profile's first-pass fingerprint without rereading it.
        # For larger files, actually sample: mixing old and new profiles would
        # otherwise miss candidates with one newly discovered copy.
        with c:
            c.execute('''UPDATE work_files SET partial=? || full
                         WHERE size<=? AND full IS NOT NULL AND partial IS NULL''',
                      (control.fingerprint_prefix, FULL_FIRST_PASS_LIMIT))
        # Seed the live confirmed-duplicate count from reusable full hashes.
        # Partial fingerprints NEVER qualify as confirmed duplicates.
        scoped_count, scoped_wasted = scan_scope_metrics(c,rootlist,bool(preserved_roots))
        available = c.execute('SELECT COUNT(*) FROM work_files WHERE full IS NOT NULL').fetchone()[0]
        control.set_progress(full_hashes_available=available, metrics_ready=True,
                             confirmed_duplicate_copies=scoped_count,
                             confirmed_wasted_bytes=scoped_wasted)
        # Metadata/size grouping is a prefilter, not an extra hash pass.
        with c:
            c.execute('DROP TABLE IF EXISTS temp.size_candidates')
            c.execute('''CREATE TEMP TABLE size_candidates AS
                SELECT size FROM work_files WHERE size>0 GROUP BY size HAVING COUNT(*)>1''')
            c.execute('CREATE UNIQUE INDEX temp.sc_idx ON size_candidates(size)')
        candidate_totals = c.execute('''SELECT COUNT(*) n,COALESCE(SUM(w.size),0) bytes
                 FROM work_files w JOIN size_candidates sc ON sc.size=w.size''').fetchone()
        candidates = candidate_totals['n']
        # Other roots retain their authoritative hashes. Only compare their
        # previously unique/unhashed files when their size intersects files
        # actually enumerated on this selected volume.
        c.execute('DROP TABLE IF EXISTS temp.selected_sizes')
        c.execute('CREATE TEMP TABLE selected_sizes(size INTEGER PRIMARY KEY)')
        c.execute('INSERT INTO selected_sizes SELECT DISTINCT size FROM work_files WHERE root IN (' +
                  ','.join('?' for _ in rootlist) + ')',rootlist)
        selected_sql='w.root IN (' + ','.join('?' for _ in rootlist) + ')'
        scope_expr=(selected_sql + ''' OR (EXISTS (SELECT 1 FROM temp.selected_sizes ss
            WHERE ss.size=w.size) AND (w.partial IS NULL OR
            w.partial NOT LIKE ?))''')
        scope_params=tuple(rootlist)+(control.fingerprint_prefix+'%',)
        partial_predicate='EXISTS (SELECT 1 FROM temp.size_candidates sc WHERE sc.size=w.size)'
        partial_params=()
        if mode=='quick':
            partial_predicate+=' AND w.partial IS NULL'
        if preserved_roots:
            partial_predicate+=' AND (' + scope_expr + ')'
            partial_params=scope_params
        if mode=='quick' or preserved_roots:
            partial_total=c.execute('SELECT COUNT(*) FROM work_files w WHERE '+partial_predicate,
                                    partial_params).fetchone()[0]
        else:
            partial_total=candidates
        control.set_progress(candidate_files=candidates,
                             candidate_bytes=candidate_totals['bytes'],
                             partial_files_total=partial_total)
        _set_stage(c, scan_id, 'partial_hashing', control)
        _wal_checkpoint(c, checkpoint_mode)
        _hash_candidate_pages(c, partial_predicate, partial_params, 'partial_hashing', control, scan_id)
        _wal_checkpoint(c, checkpoint_mode)

        # ONLY full-file SHA-256 can confirm duplicates. A different-size or
        # different-partial file is not sent to the second content pass.
        with c:
            c.execute('DROP TABLE IF EXISTS temp.full_candidates')
            c.execute('''CREATE TEMP TABLE full_candidates AS
                SELECT size,partial FROM work_files WHERE partial IS NOT NULL
                GROUP BY size,partial HAVING COUNT(*)>1''')
            c.execute('CREATE UNIQUE INDEX temp.fc_idx ON full_candidates(size,partial)')
        surviving = c.execute('''SELECT COUNT(*) n,COALESCE(SUM(w.size),0) bytes
            FROM work_files w JOIN full_candidates fc
                 ON w.size=fc.size AND w.partial=fc.partial''').fetchone()
        totals = c.execute('''SELECT COUNT(*) n,COALESCE(SUM(w.size),0) bytes
            FROM work_files w JOIN full_candidates fc
                 ON w.size=fc.size AND w.partial=fc.partial
            WHERE w.full IS NULL''').fetchone()
        control.set_progress(
            potential_hash_matches=surviving['n'],
            partial_eliminated_files=candidates-surviving['n'],
            partial_eliminated_bytes=candidate_totals['bytes']-surviving['bytes'],
            full_files_total=totals['n'],
            full_hash_bytes_total=totals['bytes'])
        print('Partial filtering: '+json.dumps({
            'size_candidates':candidates,
            'size_candidate_bytes':candidate_totals['bytes'],
            'surviving_candidates':surviving['n'],
            'full_hash_files_needed':totals['n'],
            'full_hash_bytes_needed':totals['bytes'],
            'file_workers':control.file_workers,
            'fingerprint_profile':control.fingerprint_profile,
            'io_totals':{k:v for k,v in control.snapshot().items() if k.startswith('io_')}
        }),flush=True)
        _set_stage(c, scan_id, 'full_hashing', control)
        _wal_checkpoint(c, checkpoint_mode)
        full_predicate='''w.full IS NULL AND EXISTS (SELECT 1 FROM temp.full_candidates fc
                  WHERE fc.size=w.size AND fc.partial=w.partial)'''
        if preserved_roots:
            full_predicate+=' AND EXISTS (SELECT 1 FROM temp.selected_sizes ss WHERE ss.size=w.size)'
        _hash_candidate_pages(c, full_predicate, (), 'full_hashing', control, scan_id)
        finalization_started = time.monotonic()
        control.finalizing('Saving hash checkpoints')
        # PASSIVE never waits for an open dashboard reader to release a WAL
        # snapshot. TRUNCATE may block for the busy timeout and is needless here.
        _wal_checkpoint(c, 'PASSIVE')
        if require_mounts:
            control.finalizing('Verifying all source mounts')
            validate_cifs_mounts(rootlist)
        control.finalizing('Calculating confirmed duplicate statistics')
        # Count exact matches using final SHA-256, not sample fingerprints.
        dupes, wasted = scan_scope_metrics(c,rootlist,bool(preserved_roots))
        global_dupes, global_wasted = scan_scope_metrics(c,rootlist,False)
        control.set_progress(metrics_ready=True,
                             confirmed_duplicate_copies=dupes,
                             confirmed_wasted_bytes=wasted)
        # Only credit verified loss of redundant copies when at least one
        # unchanged-content copy remains in the newly validated active inventory.
        # One indexed delta pass and one set-based savings statement. No
        # per-group SQL loops, and no expensive full-inventory rewrite.
        _prepare_publication_delta(c, control)
        control.finalizing('Calculating verified lifetime space savings')
        credit = _verified_savings_credit(c)
        lifetime = int(read_meta(c,'lifetime')) + credit
        control.check()
        control.finalizing('Preparing per-volume scan history')
        per_root = {r['root']: r['n'] for r in c.execute('''SELECT root,COUNT(*) n
                                                             FROM work_files GROUP BY root''')}
        per_changes = {}
        for root in rootlist:
            per_root.setdefault(root, 0)
            has_baseline = bool(c.execute('SELECT 1 FROM files WHERE root=? LIMIT 1',
                                          (root,)).fetchone())
            if has_baseline:
                per_changes[root] = _changes_since_published(c,root)
            else:
                per_changes[root] = {'added':None,'removed':None,
                                     'modified':None,'possible_moves':None}
        change_totals = {name:sum(item[name] or 0 for item in per_changes.values())
                         for name in ('added','removed','modified','possible_moves')}
        control.check()
        control.finalizing('Preparing duplicate statistics for per-volume history')
        volume_metrics_started = time.monotonic()
        root_dupes = _snapshot_volume_duplicate_metrics(c, rootlist)
        volume_metrics_seconds = round(time.monotonic() - volume_metrics_started, 3)
        control.check()
        control.begin_finalizing()  # cancellation closes only at atomic publish
        control.finalizing('Committing changed inventory records and scan history')
        print('Finalizing: publishing inventory delta and committing scan history',flush=True)
        # This is the ONLY publication point. Cancellation/failure before here
        # cannot corrupt the previously committed inventory or accrue savings.
        publication_started = time.monotonic()
        publication_timings = {}
        with c:
            phase = time.monotonic()
            _apply_publication_delta(c)
            publication_timings['inventory_delta_seconds'] = round(time.monotonic() - phase, 3)
            write_meta(c,'lifetime',lifetime)
            # Record final success only after all publication/cleanup writes
            # have completed. The UPDATE is performed after the other SQL
            # statements below to keep the finished time consistent.
            # Per-volume duplicate snapshots were computed from the complete
            # staged inventory before the write transaction; do not sort all
            # published files while holding SQLite's publication write lock.
            c.executemany('''INSERT INTO volume_scans
                    (scan_id,root,file_count,added,removed,modified,possible_moves,duplicate_copies,wasted_bytes)
                    VALUES(?,?,?,?,?,?,?,?,?)''',
                          [(scan_id,root,n,*[per_changes[root][key]
                          for key in ('added','removed','modified','possible_moves')],
                          *root_dupes[root])
                          for root,n in per_root.items() if root in rootlist])
            if mode == 'full':
                c.executemany('DELETE FROM invalid_baselines WHERE root=?',
                              [(root,) for root in rootlist])
            if remounted:
                # Normalize verified cache identities to this host's CIFS mount.
                # Without this step, the stale dev/inode in partial_cache would
                # be pruned below, forcing another large sample pass next time.
                # Do not change cache identities for files whose size/mtime
                # differs from the now-published inventory.
                c.execute('''UPDATE hash_cache SET
                    dev=(SELECT f.dev FROM files f WHERE f.path=hash_cache.path),
                    inode=(SELECT f.inode FROM files f WHERE f.path=hash_cache.path)
                    WHERE root IN (SELECT root FROM remounted_roots) AND
                    EXISTS(SELECT 1 FROM files f WHERE f.path=hash_cache.path
                    AND f.root=hash_cache.root AND f.size=hash_cache.size
                    AND f.mtime_ns=hash_cache.mtime_ns)''')
                c.execute('''UPDATE partial_cache SET
                    dev=(SELECT f.dev FROM files f WHERE f.path=partial_cache.path),
                    inode=(SELECT f.inode FROM files f WHERE f.path=partial_cache.path)
                    WHERE root IN (SELECT root FROM remounted_roots) AND
                    EXISTS(SELECT 1 FROM files f WHERE f.path=partial_cache.path
                    AND f.root=partial_cache.root AND f.size=partial_cache.size
                    AND f.mtime_ns=partial_cache.mtime_ns)''')
            phase = time.monotonic()
            _prune_changed_cache(c)
            publication_timings['cache_pruning_seconds'] = round(time.monotonic() - phase, 3)
            # Success status, end timestamp and last UI snapshot are written
            # in the same atomic transaction as the published inventory.
            # The scan-duration clock was stopped when Finalizing began. The remaining commit time is
            # explicitly excluded; avoid pretending it was included later.
            ended = control.snapshot()['duration_cutoff_at']
            final_progress = control.snapshot()
            final_progress.update(stage='complete', lifecycle='complete',
                                  finalizing_step=None, ended_at=ended,
                                  files_indexed=count, files_discovered=count,
                                  confirmed_duplicate_copies=dupes,
                                  confirmed_wasted_bytes=wasted)
            c.execute('''UPDATE scans SET ended=?,status='success',error='',files=?,
                         duplicates=?,wasted=?,lifetime=?,progress_json=?,changes_json=?
                         WHERE id=?''',
                      (ended,count,dupes,wasted,lifetime,
                       json.dumps(final_progress),json.dumps(change_totals),scan_id))
        # The success row and published data are in the same committed
        # transaction. There is no second transaction that can leave the UI
        # showing an earlier completed duration while the run is still active.
        # The transaction's commit is expected to be short after delta writes.
        # All critical database work is committed. Do not perform a large
        # synchronous checkpoint after declaring success; WAL maintenance is
        # handled between stages/at next startup.
        publication_timings['transaction_total_seconds'] = round(time.monotonic() - publication_started, 3)
        publication_timings['volume_metrics_seconds'] = volume_metrics_seconds
        publication_timings['finalization_total_seconds'] = round(time.monotonic() - finalization_started, 3)
        print('Finalization timings: ' + json.dumps(publication_timings), flush=True)
        control.set_progress(**final_progress)
        result = {'status':'success','files_scanned':count,'scan_scope':rootlist,
                  'scan_duplicates_count':dupes,'scan_wasted_space':wasted,
                  'current_duplicates_count':global_dupes,'current_wasted_space':global_wasted,
                  'lifetime_space_saved':lifetime,
                  'scan_duration_seconds':round(ended-start,2),
                  'per_volume_file_counts':per_root,
                  'changes':change_totals}
        result['finalization_timings'] = publication_timings
        result['wall_clock_seconds'] = round(time.time() - start, 2)
        result['io_totals'] = {k:v for k,v in control.snapshot().items() if k.startswith('io_')}
        result['partial_eliminated_files'] = control.snapshot()['partial_eliminated_files']
        result['partial_eliminated_bytes'] = control.snapshot()['partial_eliminated_bytes']
        print('Scan completed: '+json.dumps(result), flush=True)
        return result
    except Exception as exc:
        status = 'cancelled' if isinstance(exc,ScanCancelled) else 'failed'
        if scan_id is not None:
            try:
                # If an INSERT/COMMIT failed, first discard any open transaction
                # so diagnostic recording cannot accidentally commit partial work.
                c.rollback()
                with c:
                    c.execute('''UPDATE scans SET ended=?,status=?,error=?,progress_json=?
                                 WHERE id=?''',
                              (time.time(),status,str(exc)[:2000],
                               json.dumps(control.snapshot()),scan_id))
            except Exception as status_exc:
                # Never hide the original failure with a secondary SQLite error.
                print('Could not record scan failure: ' + repr(status_exc), flush=True)
        raise
    finally:
        # Keep the scan lock held through connection closure. On failure,
        # report cleanup explicitly; do not overwrite a successful final state.
        if control.snapshot().get('stage') != 'complete':
            control.set_progress(lifecycle='cleaning')
        try:
            c.set_progress_handler(None, 0)
            if c.in_transaction:
                c.rollback()
        finally:
            c.close()


def report(db, search='', limit=100, offset=0, live=False, sort='wasted',
           order='desc', return_total=False):
    """Fully confirmed groups with deterministic server-side sort and paging.

    A single WAL snapshot binds total count, group rows, and paths together.
    Group identity is (size, complete SHA-256); first discovered filename is a
    display label only and never affects the duplicate comparison.
    """
    if sort not in ('wasted','size','copies','filename'):
        raise ValueError('Unknown duplicate report sort')
    if order not in ('asc','desc'):
        raise ValueError('Unknown duplicate report order')
    c=connect(db,readonly=True)
    try:
        table='work_files' if live else 'files'
        c.create_function('dfm_basename',1,lambda p:os.path.basename(p or ''),deterministic=True)
        c.execute('BEGIN')
        arguments=[]
        filt=''
        if search:
            escaped=search.replace('\\','\\\\').replace('%','\\%').replace('_','\\_')
            filt=f""" AND (g.full LIKE ? ESCAPE '\\' OR EXISTS
                (SELECT 1 FROM {table} a WHERE a.size=g.size AND a.full=g.full
                 AND a.path LIKE ? ESCAPE '\\'))"""
            arguments=['%'+escaped+'%','%'+escaped+'%']
        groups=f"""(SELECT size,full,COUNT(*) n,MIN(rowid) first_rowid
                    FROM {table} WHERE full IS NOT NULL AND size>0
                    GROUP BY size,full HAVING COUNT(*)>1) g"""
        where='WHERE 1=1'+filt
        total=c.execute('SELECT COUNT(*) FROM '+groups+' '+where,arguments).fetchone()[0]
        keys={'wasted':'g.size*(g.n-1)', 'size':'g.size',
              'copies':'g.n', 'filename':'LOWER(dfm_basename(first.path))'}
        direction='ASC' if order=='asc' else 'DESC'
        sql=f"""SELECT g.size,g.full,g.n,first.path first_path FROM {groups}
                 JOIN {table} first ON first.rowid=g.first_rowid
                 {where} ORDER BY {keys[sort]} {direction},g.size DESC,g.full ASC"""
        page_args=list(arguments)
        if limit is not None:
            sql+=' LIMIT ? OFFSET ?'
            page_args += [max(1,min(int(limit),500)),max(0,int(offset))]
        results=[]
        groups_rows=c.execute(sql,page_args).fetchall()
        for g in groups_rows:
            paths=[r['path'] for r in c.execute(
                f'SELECT path FROM {table} WHERE size=? AND full=? ORDER BY rowid',
                (g['size'],g['full']))]
            results.append({'size_bytes':g['size'],'sha256':g['full'],
                            'representative_filename':os.path.basename(g['first_path']),
                            'copies':g['n'],'redundant_copies':g['n']-1,
                            'wasted_bytes':g['size']*(g['n']-1),'paths':paths})
        return (results,total) if return_total else results
    finally:
        c.close()
