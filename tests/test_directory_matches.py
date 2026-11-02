import hashlib
import os
import sqlite3
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from directory_matches import duplicate_directories
from scanner import connect


def test_matching_trees_roll_up_and_scattered_copies_do_not(tmp_path):
    db=connect(str(tmp_path/'db.sqlite'))
    a=tmp_path/'a'; b=tmp_path/'b'; scattered=tmp_path/'scattered';c=tmp_path/'c'
    entries=[]
    def add(root,rel,data,verified=True):
        path=str(root/rel)
        digest=hashlib.sha256(data).hexdigest() if verified else None
        entries.append((path,str(root),len(data),0,0,0,None,digest))
    for root in (a,b):
        for folder in ('c','d'):
            for i in range(3):add(root,'parent/'+folder+f'/file{i}.txt',f'{folder}-{i}'.encode())
    # Same exact files, but wrong directory layout must not match the tree.
    for folder in ('c','d'):
        for i in range(3):add(scattered,f'other{i}/{folder}_{i}',f'{folder}-{i}'.encode())
    # A matching-looking third tree with a single unverified entry cannot qualify.
    for folder in ('c','d'):
        for i in range(3):add(c,'parent/'+folder+f'/file{i}.txt',f'{folder}-{i}'.encode(),verified=(i!=2))
    db.executemany('INSERT INTO files(path,root,size,mtime_ns,dev,inode,partial,full) VALUES(?,?,?,?,?,?,?,?)',entries)
    db.commit()
    result=duplicate_directories(db)
    assert len(result['items'])==1
    group=result['items'][0]
    assert set(group['paths'])=={str(a/'parent'),str(b/'parent')}
    assert group['files_per_copy']==6
    assert group['potential_savings_bytes']==group['size_bytes_per_copy']
    assert not any('/c' in p or '/d' in p for p in group['paths'])
    db.close()


def test_unique_extra_file_disqualifies_parent(tmp_path):
    db=connect(str(tmp_path/'db.sqlite'))
    rows=[]
    for root in ('a','b'):
        for rel,content in [('parent/x/a',b'foo'),('parent/y/b',b'bar')]:
            rows.append((str(tmp_path/root/rel),str(tmp_path/root),len(content),0,0,0,None,hashlib.sha256(content).hexdigest()))
    content=b'unique'
    rows.append((str(tmp_path/'a/parent/extra'),str(tmp_path/'a'),len(content),0,0,0,None,hashlib.sha256(content).hexdigest()))
    db.executemany('INSERT INTO files(path,root,size,mtime_ns,dev,inode,partial,full) VALUES(?,?,?,?,?,?,?,?)',rows)
    db.commit()
    result=duplicate_directories(db,min_files=1)
    assert all(not any(p.endswith('/parent') for p in g['paths']) for g in result['items'])
    assert {tuple(p.rsplit('/',1)[-1] for p in g['paths']) for g in result['items']} # children match
    db.close()
