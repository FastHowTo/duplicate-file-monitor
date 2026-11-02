"""372,756-row, 3-volume duplicate attribution + two selected roots workload.
Database and source names are synthetic; no SMB I/O is performed.
"""
import os
from pathlib import Path
import json
import sys
import tempfile
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
import scanner

GROUPS=124252
N=GROUPS*3
with tempfile.TemporaryDirectory(prefix='dfm-scoped-scale-') as base:
    db=base+'/db.sqlite3'
    roots=[base+'/vol'+str(j) for j in range(3)]
    for r in roots:os.mkdir(r)
    scanner.initialize_database(db)
    c=scanner.connect(db)
    t0=time.perf_counter()
    for k in range(3):
        batch=[]
        for i in range(GROUPS):
            size=8192+(i%50);digest=f'{i+1:064x}'
            batch.append((f'{roots[k]}/{i:07d}',roots[k],size,11,1,i+1,scanner.FINGERPRINT_PREFIX+digest,digest))
            if len(batch)>=4000:
                with c:c.executemany('INSERT INTO files VALUES(?,?,?,?,?,?,?,?)',batch)
                batch=[]
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
                         (1,2,'success','full',N,2*GROUPS,0)).lastrowid
        for r in roots:c.execute('INSERT INTO volume_scans(scan_id,root,file_count) VALUES(?,?,?)',(scanid,r,GROUPS))
        c.execute('INSERT INTO work_files(path,root,size,mtime_ns,dev,inode) VALUES(?,?,?,?,?,?)',
                  ('SENTINEL','preserve-work',1,1,1,1))
    c.close()
    print('SYNTHETIC_3_VOLUME_DB_CREATED',round(time.perf_counter()-t0,3),flush=True)
    original=scanner._enumerate_parallel
    def replay(c,rootlist,control,scan_id,discovery_metrics=None):
        ph=','.join('?' for _ in rootlist)
        c.execute(f'''INSERT INTO work_files(path,root,size,mtime_ns,dev,inode)
            SELECT path,root,size,mtime_ns,dev,inode FROM files WHERE root IN ({ph})''',rootlist)
        control.set_progress(files_discovered=GROUPS*len(rootlist),files_indexed=GROUPS*len(rootlist))
        if discovery_metrics:
            batch=[tuple(row) for row in c.execute(f'''SELECT path,root,size,mtime_ns,dev,inode
                FROM work_files WHERE root IN ({ph}) LIMIT 1000''',rootlist)]
            discovery_metrics.observe(c,batch)
        return GROUPS*len(rootlist),[]
    scanner._enumerate_parallel=replay
    try:
        ts=time.perf_counter()
        selected=roots[1:];preserved=roots[:1]
        ctl=scanner.ScanControl(0,4)
        out=scanner.scan(db,selected,ctl,mode='quick',preserved_roots=preserved)
        duration=time.perf_counter()-ts
        assert out['status']=='success'
        assert out['files_scanned']==2*GROUPS
        assert out['scan_duplicates_count']==2*GROUPS, out['scan_duplicates_count']
        assert out['current_duplicates_count']==2*GROUPS
        assert out['changes']=={'added':0,'removed':0,'modified':0,'possible_moves':0}
        assert out['io_totals']['io_files']==0
        c=scanner.connect(db,readonly=True)
        assert c.execute("SELECT COUNT(*) FROM work_files WHERE path='SENTINEL'").fetchone()[0]==1
        assert c.execute('SELECT COUNT(*) FROM files').fetchone()[0]==N
        assert c.execute("SELECT COUNT(*) FROM scans WHERE status='success'").fetchone()[0]==2
        c.close()
        print('SYNTHETIC_SCOPED_QUICK_TOTAL_SEC',round(duration,3),flush=True)
        print('SYNTHETIC_SCOPED_COUNTS',json.dumps({'selected':2,'preserved':1,
            'files_discovered':out['files_scanned'],'duplicates_selected':out['scan_duplicates_count'],
            'duplicates_global':out['current_duplicates_count'],'history_preserved':True,
            'persistent_work_preserved':True}),flush=True)
    finally:
        scanner._enumerate_parallel=original
