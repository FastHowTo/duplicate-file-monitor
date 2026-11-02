import hashlib
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from scanner import connect
from directory_report_cache import get_directory_report, refresh_directory_report


def test_saved_report_survives_restart_and_detects_inventory_changes(tmp_path):
    path=tmp_path/'db.sqlite3'
    c=connect(str(path))
    assert get_directory_report(c)['saved'] is False
    rows=[]
    for root in ('a','b'):
        for filename, value in [('x',b'abc'),('y',b'def')]:
            rows.append((str(tmp_path/root/'set'/filename),str(tmp_path/root),len(value),0,0,0,None,hashlib.sha256(value).hexdigest()))
    c.executemany('INSERT INTO files(path,root,size,mtime_ns,dev,inode,partial,full) VALUES(?,?,?,?,?,?,?,?)',rows)
    c.commit()
    result=refresh_directory_report(c)
    assert result['saved'] and not result['stale'] and result['items'][0]['copies']==2
    c.close()
    c=connect(str(path))
    saved=get_directory_report(c)
    assert saved['saved'] and not saved['stale'] and saved['items']==result['items']
    c.execute('DELETE FROM files WHERE path=?',(rows[0][0],))
    c.commit()
    assert get_directory_report(c)['stale']
    updated=refresh_directory_report(c)
    assert not updated['stale'] and not updated['items']
    c.close()


def test_scan_id_invalidates_same_count_same_size_changes(tmp_path):
    c=connect(str(tmp_path/'db.sqlite3'))
    refresh_directory_report(c)
    c.execute("INSERT INTO scans(started,ended,status) VALUES (1,2,'success')")
    c.commit()
    assert get_directory_report(c)['stale']
    c.close()
