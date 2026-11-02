"""Conservative, read-only matching of exact inventoried directory trees.

Only complete full-content SHA256 fingerprints can qualify. Empty directory
entries are not inventoried, so results describe *inventoried file trees*, not
unobserved empty directories or filesystem metadata.
"""
import hashlib
import os
from collections import defaultdict


def duplicate_directories(connection, limit=100, min_files=2):
    limit = max(1, min(int(limit), 500))
    min_files = max(1, int(min_files))
    directories = {}
    # The published inventory is immutable during scans. All observations come
    # from one read-only SQLite snapshot, and no source files are opened.
    for path, root, size, digest in connection.execute('SELECT path,root,size,full FROM files ORDER BY root,path'):
        root = os.path.normpath(root)
        path = os.path.normpath(path)
        if not (path.startswith(root + os.sep) and path != root):
            continue
        relative = os.path.relpath(path, root)
        parts = relative.split(os.sep)
        for depth in range(len(parts)):
            directory = os.path.join(root, *parts[:depth]) if depth else root
            entry = directories.setdefault(directory, {'files': [], 'dirs': set(), 'root': root})
            if depth < len(parts) - 1:
                entry['dirs'].add(parts[depth])
            else:
                entry['files'].append((parts[-1], int(size), digest))
    digests = {}
    counts = {}
    sizes = {}
    complete = {}
    for path in sorted(directories, key=lambda p: (-p.count(os.sep), p)):
        node = directories[path]
        entries = []
        count = 0
        total_size = 0
        valid = True
        for name, size, digest in sorted(node['files']):
            count += 1
            total_size += size
            if not digest or len(digest) != 64:
                valid = False
            entries.append(('F', name, size, digest or ''))
        for name in sorted(node['dirs']):
            child = os.path.join(path, name)
            if child not in digests or not complete[child]:
                valid = False
            entries.append(('D', name, digests.get(child,'')))
            count += counts.get(child,0)
            total_size += sizes.get(child,0)
        complete[path] = valid
        counts[path] = count
        sizes[path] = total_size
        h = hashlib.sha256()
        for entry in sorted(entries):
            h.update(repr(entry).encode('utf-8', 'surrogateescape'))
            h.update(b'\0')
        digests[path] = h.hexdigest()
    groups = defaultdict(list)
    for path, digest in digests.items():
        if path != directories[path]['root'] and complete[path] and counts[path] >= min_files:
            groups[(digest, counts[path], sizes[path])].append(path)
    candidates = []
    for (digest, count, total_size), paths in groups.items():
        if len(paths) >= 2:
            candidates.append((count, total_size, digest, sorted(paths)))
    # Prefer the largest qualifying trees; suppress children already covered by
    # reported ancestor trees. Never report an overlapping removal candidate.
    candidates.sort(key=lambda item: (-item[0], -item[1], item[3]))
    covered = []
    result = []
    for count, total_size, digest, paths in candidates:
        remaining = [p for p in paths if not any(p == a or p.startswith(a + os.sep) for a in covered)]
        if len(remaining) < 2:
            continue
        result.append({'paths':remaining,'copies':len(remaining),'files_per_copy':count,
                       'size_bytes_per_copy':total_size,'potential_savings_bytes':total_size*(len(remaining)-1),
                       'fingerprint':digest})
        covered.extend(remaining)
        if len(result) >= limit:
            break
    return {'items':result,'returned':len(result),
            'note':'Exact inventoried file-tree matches using stored full SHA-256; unverified files and unobserved empty directories are excluded. Read-only.'}
