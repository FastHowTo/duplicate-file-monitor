"""Persisted volume and scheduling configuration in the existing SQLite meta table.

No schema migration, writes or checkpoints are required to display an existing
v0.3.9.3 inventory. Configuration changes are explicit atomic user actions.
"""
from contextlib import closing
import json
import os
import stat
import time
import uuid

from scanner import connect, read_meta, write_meta, archive_volume, restore_volume, validate_mount_types, configured_mount_types


def volume_config(db, defaults):
    c = connect(db, readonly=True)
    try:
        raw = read_meta(c, 'managed_roots_json', '')
        roots = json.loads(raw) if raw else list(defaults)
        if not isinstance(roots, list) or any(not isinstance(p, str) for p in roots):
            raise ValueError('Invalid saved volume configuration')
        ids = json.loads(read_meta(c, 'volume_ids_json', '{}'))
        enabled = read_meta(c, 'per_volume_scanning', '0') == '1'
        return {'roots': roots, 'volume_ids': ids, 'per_volume_enabled': enabled}
    finally:
        c.close()


def normalize_root(root):
    if not isinstance(root, str) or not root.strip():
        raise ValueError('Provide a volume mount path')
    normalized = os.path.normpath(root.strip())
    if normalized == '/scan' or not normalized.startswith('/scan/'):
        raise ValueError('Volume paths must be within /scan')
    if os.path.islink(normalized) or os.path.realpath(normalized) != normalized:
        raise ValueError('Volume paths must not be symlinks')
    if not os.path.isdir(normalized):
        raise ValueError('Volume is not mounted in this Docker container. Provision its read-only bind mount first.')
    return normalized


def _ensure_nonoverlap(roots):
    for i, first in enumerate(roots):
        if any(first == other or first.startswith(other + '/') or other.startswith(first + '/')
               for other in roots[i+1:]):
            raise ValueError('Volumes must be unique, non-overlapping scan roots')


def save_volume_mode(db, defaults, enabled):
    if type(enabled) is not bool:
        raise ValueError('Expected true/false per-volume setting')
    conf=volume_config(db,defaults)
    ids=dict(conf['volume_ids'])
    for root in conf['roots']:
        ids.setdefault(root,str(uuid.uuid4()))
    with closing(connect(db)) as c, c:
        write_meta(c, 'per_volume_scanning', '1' if enabled else '0')
        write_meta(c, 'volume_ids_json', json.dumps(ids))
    return volume_config(db, defaults)


def add_volume(db, defaults, root, require_mounts=False):
    root = normalize_root(root)
    if require_mounts:
        validate_mount_types([root], configured_mount_types() or {'cifs'})
    config = volume_config(db, defaults)
    if root in config['roots']:
        raise ValueError('Volume is already configured')
    roots = config['roots'] + [root]
    _ensure_nonoverlap(roots)
    ids = config['volume_ids']
    ids[root] = str(uuid.uuid4())
    with closing(connect(db)) as c, c:
        write_meta(c, 'managed_roots_json', json.dumps(roots))
        write_meta(c, 'volume_ids_json', json.dumps(ids))
        # A re-added volume never inherits an obsolete Full Scan baseline.
        c.execute('DELETE FROM excluded_roots WHERE root=?', (root,))
        c.execute("INSERT OR REPLACE INTO invalid_baselines(root,reason) VALUES(?,'new volume')", (root,))
        aliases=json.loads(read_meta(c,'baseline_aliases_json','{}'))
        aliases.pop(root,None)
        write_meta(c,'baseline_aliases_json',json.dumps(aliases))
    return volume_config(db, defaults)


def remove_volume(db, defaults, root):
    config = volume_config(db, defaults)
    if root not in config['roots']:
        raise ValueError('Unknown configured volume')
    # Unregistering removes ACTIVE inventory, never immutable scan history or
    # lifetime-savings history. An explicit archive already does this.
    roots = [p for p in config['roots'] if p != root]
    if not roots:
        raise ValueError('Cannot remove the last configured volume')
    ids = config['volume_ids']
    ids.pop(root, None)
    with closing(connect(db)) as c, c:
        c.execute('DELETE FROM files WHERE root=?', (root,))
        c.execute('DELETE FROM work_files WHERE root=?', (root,))
        c.execute('DELETE FROM hash_cache WHERE root=?', (root,))
        c.execute('DELETE FROM partial_cache WHERE root=?', (root,))
        c.execute('DELETE FROM excluded_roots WHERE root=?', (root,))
        c.execute('DELETE FROM invalid_baselines WHERE root=?', (root,))
        aliases=json.loads(read_meta(c,'baseline_aliases_json','{}'))
        aliases.pop(root,None)
        write_meta(c,'baseline_aliases_json',json.dumps(aliases))
        write_meta(c, 'managed_roots_json', json.dumps(roots))
        write_meta(c, 'volume_ids_json', json.dumps(ids))
        schedules=json.loads(read_meta(c,'scan_schedules_json','[]'))
        write_meta(c,'scan_schedules_json',json.dumps([x for x in schedules if x.get('root')!=root]))
    return volume_config(db, defaults)


def relocate_volume(db, defaults, old, new, require_mounts=False):
    config = volume_config(db, defaults)
    if old not in config['roots']:
        raise ValueError('Unknown original volume')
    new = normalize_root(new)
    if new == old:
        raise ValueError('New path must differ from old path')
    if require_mounts:
        validate_mount_types([new], configured_mount_types() or {'cifs'})
    roots = [new if p == old else p for p in config['roots']]
    _ensure_nonoverlap(roots)
    c = connect(db, readonly=True)
    try:
        examples = [dict(r) for r in c.execute('''SELECT path,size,mtime_ns FROM files
            WHERE root=? ORDER BY path LIMIT 16''', (old,))]
    finally:
        c.close()
    # Do not silently transplant hashes into an unrelated mounted share.
    for item in examples:
        target = new + item['path'][len(old):]
        try:
            s = os.stat(target, follow_symlinks=False)
        except OSError as exc:
            raise ValueError('Relocation verification failed; missing representative file: ' + target) from exc
        if not stat.S_ISREG(s.st_mode) or s.st_size != item['size'] or s.st_mtime_ns != item['mtime_ns']:
            raise ValueError('Relocation verification failed; file metadata differs: ' + target)
    ids = config['volume_ids']
    volume_id = ids.pop(old, str(uuid.uuid4()))
    ids[new] = volume_id
    with closing(connect(db)) as c, c:
        # Original completed scans and volume_scans are intentionally immutable.
        for table in ('files', 'hash_cache', 'partial_cache', 'work_files'):
            c.execute(f'''UPDATE {table} SET root=?,path=? || substr(path,?) WHERE root=?''',
                      (new, new, len(old)+1, old))
        c.execute('UPDATE excluded_roots SET root=? WHERE root=?', (new,old))
        c.execute('UPDATE invalid_baselines SET root=? WHERE root=?', (new,old))
        aliases=json.loads(read_meta(c,'baseline_aliases_json','{}'))
        ancestor=aliases.pop(old,old)
        aliases[new]=ancestor
        write_meta(c,'baseline_aliases_json',json.dumps(aliases))
        if not examples:
            c.execute("INSERT OR REPLACE INTO invalid_baselines(root,reason) VALUES(?,'unverified relocation')", (new,))
        write_meta(c, 'managed_roots_json', json.dumps(roots))
        write_meta(c, 'volume_ids_json', json.dumps(ids))
        schedules=json.loads(read_meta(c,'scan_schedules_json','[]'))
        for item in schedules:
            if item.get('root')==old:
                item['root']=new
                item['id']=new+'|'+item['mode']
        write_meta(c,'scan_schedules_json',json.dumps(schedules))
    return volume_config(db, defaults)
