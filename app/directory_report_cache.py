"""Saved read-only duplicate directory analysis with explicit stale detection."""
import json
import time
from directory_matches import duplicate_directories

# Snapshot checks include count and bytes so archiving/removing a volume also
# invalidates the report even without creating a new successful scan.
# MAX(scan id) catches same-count and same-size content modifications on scans.
def inventory_stamp(c):
    scan_id = c.execute("SELECT COALESCE(MAX(id),0) FROM scans WHERE status='success'").fetchone()[0]
    count, size = c.execute('SELECT COUNT(*),COALESCE(SUM(size),0) FROM files').fetchone()
    return json.dumps([scan_id, count, size], separators=(',', ':'))


def _ensure_table(c):
    c.execute("""CREATE TABLE IF NOT EXISTS directory_analysis_cache (
        id INTEGER PRIMARY KEY CHECK(id=1), stamp TEXT NOT NULL,
        generated_at REAL NOT NULL, payload TEXT NOT NULL)""")


def get_directory_report(c, limit=100):
    # A missing cache on an existing database is normal and requires no write.
    has_table=c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='directory_analysis_cache'").fetchone()
    if not has_table:
        return {'items':[], 'returned':0,'saved':False,'stale':False}
    row=c.execute('SELECT stamp,generated_at,payload FROM directory_analysis_cache WHERE id=1').fetchone()
    if row is None:
        return {'items':[], 'returned':0,'saved':False,'stale':False}
    data=json.loads(row[2]); data['items']=data['items'][:max(1,min(int(limit),500))]
    data.update(saved=True,stale=row[0]!=inventory_stamp(c),generated_at=row[1],returned=len(data['items']))
    return data


def refresh_directory_report(c, limit=500):
    # Use the same stable inventory snapshot for both the stamp and analysis.
    # BEGIN before SELECT prevents interleaving a scan commit with matching.
    c.execute('BEGIN')
    try:
        stamp=inventory_stamp(c)
        result=duplicate_directories(c,limit=500)
        c.commit()
    except Exception:
        c.rollback()
        raise
    # Refresh writes a single row. If inventory changes during calculation or
    # before publication, GET reports the saved result as stale.
    _ensure_table(c)
    generated=time.time()
    c.execute('INSERT OR REPLACE INTO directory_analysis_cache(id,stamp,generated_at,payload) VALUES(1,?,?,?)',
              (stamp,generated,json.dumps(result)))
    c.commit()
    return get_directory_report(c,limit=limit)
