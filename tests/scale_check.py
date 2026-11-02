"""373k-row synthetic Quick Scan regression benchmark.

No source share is mounted/read; enumeration is simulated by replaying known
metadata into the new temp staging table to isolate SQL preparation,
cache re-use, delta publication and startup behavior at real inventory scale.
"""
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
import json
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
import scanner

COUNT=372756
with tempfile.TemporaryDirectory(prefix='dfm-scale-') as base:
    db=os.path.join(base,'db.sqlite3')
    root=os.path.join(base,'share')
    os.mkdir(root)
    scanner.initialize_database(db)
    c=scanner.connect(db)
    c.execute('PRAGMA journal_mode=WAL')
    t0=time.perf_counter()
    batch=[]
    prefix=scanner.FINGERPRINT_PREFIX
    for i in range(COUNT):
        size=i+1;full=f'{i+1:064x}';path=f'{root}/file{i:06d}'
        batch.append((path,root,size,777,1,i+1,prefix+full,full))
        if len(batch)==5000:
            with c:
                c.executemany('INSERT INTO files VALUES(?,?,?,?,?,?,?,?)',batch)
            batch.clear()
    if batch:
        with c:c.executemany('INSERT INTO files VALUES(?,?,?,?,?,?,?,?)',batch)
    with c:
        c.execute('''INSERT INTO hash_cache(path,root,size,mtime_ns,dev,inode,partial,samples,full)
          SELECT path,root,size,mtime_ns,dev,inode,partial,NULL,full FROM files''')
        c.execute('''INSERT INTO partial_cache(path,profile,root,size,mtime_ns,dev,inode,partial)
          SELECT path,?,root,size,mtime_ns,dev,inode,partial FROM files''',(scanner.FINGERPRINT_PROFILE,))
        scanner.write_meta(c,'legacy_hash_cache_backfilled','1')
        scanner.write_meta(c,'partial_profile_migrated','1')
        scanid=c.execute('INSERT INTO scans(started,ended,status,mode,files,duplicates,wasted) VALUES(?,?,?,?,?,?,?)',
                         (1,2,'success','full',COUNT,0,0)).lastrowid
        c.execute('INSERT INTO volume_scans(scan_id,root,file_count) VALUES(?,?,?)',(scanid,root,COUNT))
        c.execute('INSERT INTO work_files(path,root,size,mtime_ns,dev,inode) VALUES(?,?,?,?,?,?)',
                  ('SENTINEL','not-a-real-root',1,1,1,1))
    c.close()
    print('SYNTHETIC_DB_POPULATED_SEC',round(time.perf_counter()-t0,3),flush=True)
    startup=time.perf_counter()
    scanner._initialized_dbs.clear()
    scanner.initialize_database(db)
    print('READONLY_STARTUP_SEC',round(time.perf_counter()-startup,3),flush=True)
    original=scanner._enumerate_parallel
    def replay(c,rootlist,control,scan_id,discovery_metrics=None):
        c.execute('''INSERT INTO work_files(path,root,size,mtime_ns,dev,inode)
            SELECT path,root,size,mtime_ns,dev,inode FROM files''')
        control.set_progress(files_discovered=COUNT,files_indexed=COUNT)
        return COUNT, []
    scanner._enumerate_parallel=replay
    try:
        ctl=scanner.ScanControl(0,4)
        ts=time.perf_counter()
        result=scanner.scan(db,[root],ctl,mode='quick')
        duration=time.perf_counter()-ts
        assert result['status']=='success' and result['files_scanned']==COUNT
        assert result['changes']=={'added':0,'removed':0,'modified':0,'possible_moves':0}
        assert result['io_totals']['io_files']==0
        c=scanner.connect(db,readonly=True)
        assert c.execute("SELECT COUNT(*) FROM work_files WHERE path='SENTINEL'").fetchone()[0]==1
        assert c.execute('SELECT COUNT(*) FROM files').fetchone()[0]==COUNT
        assert c.execute("SELECT COUNT(*) FROM scans WHERE status='success'").fetchone()[0]==2
        c.close()
        print('SYNTHETIC_QUICK_ALL_COMPLETE_SEC',round(duration,3),flush=True)
        print('SYNTHETIC_RESULTS',json.dumps({'files':result['files_scanned'],'changes':result['changes'],
                                             'bytes_read':result['io_totals']['io_files'],
                                             'completed_history_preserved':True,
                                             'persistent_work_sentinel_preserved':True}),flush=True)
    finally:
        scanner._enumerate_parallel=original
