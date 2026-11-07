"""Security, recovery and archived reporting checks for v0.6.4."""
import json
import os
import sys
from pathlib import Path
import sqlite3
import urllib.error
import urllib.request

import pytest

APP=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(APP/'app'))
import auth
import scanner

def test_auth_requires_one_time_setup_and_sessions(tmp_path,monkeypatch):
    db=str(tmp_path/'database.sqlite3')
    scanner.initialize_database(db)
    auth.initialize(db)
    monkeypatch.setenv('DFM_SETUP_TOKEN','secure-private-setup-token-for-testing')
    monkeypatch.setenv('DFM_COOKIE_SECURE','false')
    with pytest.raises(auth.AuthError):
        auth.setup(db,'incorrect','admin','a-long-private-password')
    auth.setup(db,'secure-private-setup-token-for-testing','admin','a-long-private-password')
    assert auth.has_admin(db)
    with pytest.raises(auth.AuthError):
        auth.setup(db,'secure-private-setup-token-for-testing','admin2','a-long-private-password')
    token,csrf=auth.login(db,'admin','a-long-private-password','127.0.0.1')
    session=auth.get_session(db,'dfm_session='+token)
    assert session['username']=='admin' and session['csrf']==csrf
    assert 'HttpOnly' in auth.cookie_header(token) and 'Secure' not in auth.cookie_header(token)
    auth.revoke(db,'dfm_session='+token)
    assert auth.get_session(db,'dfm_session='+token) is None

def test_password_change_revokes_all_sessions(tmp_path,monkeypatch):
    db=str(tmp_path/'database.sqlite3')
    scanner.initialize_database(db)
    auth.initialize(db)
    monkeypatch.setenv('DFM_SETUP_TOKEN','secure-private-setup-token-for-testing')
    auth.setup(db,'secure-private-setup-token-for-testing','admin','a-long-private-password')
    token,_=auth.login(db,'admin','a-long-private-password','127.0.0.1')
    auth.change_credentials(db,'admin','a-long-private-password','newadmin','an-even-longer-password')
    assert auth.get_session(db,'dfm_session='+token) is None
    with pytest.raises(auth.AuthError):
        auth.login(db,'admin','a-long-private-password','127.0.0.1')
    new_token,_=auth.login(db,'newadmin','an-even-longer-password','127.0.0.1')
    assert auth.get_session(db,'dfm_session='+new_token)

def test_recoverable_and_fatal_file_errors():
    assert scanner._recoverable(PermissionError(13,'Permission denied'))
    assert scanner._recoverable(FileNotFoundError(2,'Not found'))
    assert scanner._recoverable(RuntimeError('File changed during hashing: /tmp/log'))
    assert not scanner._recoverable(OSError(5,'Input/output error'))
    assert not scanner._recoverable(sqlite3.OperationalError('database is locked'))

def test_changed_file_warning_does_not_count_as_removed(tmp_path,monkeypatch):
    root=tmp_path/'source'
    root.mkdir()
    a=root/'first.bin'
    b=root/'second.bin'
    a.write_bytes(b'A'*4096)
    b.write_bytes(b'A'*4096)
    db=str(tmp_path/'inventory.sqlite3')
    first=scanner.scan(db,[str(root)],scanner.ScanControl(0,2))
    assert first['status']=='success' and first['scan_duplicates_count']==1
    previous_lifetime=first['lifetime_space_saved']
    # Refresh file metadata to force the hashing pass rather than cached reuse.
    a.write_bytes(b'B'*4096)
    old=scanner._record_path
    def unstable(path,*args,**kwargs):
        if path==str(a):
            raise RuntimeError('File changed during hashing: '+path)
        return old(path,*args,**kwargs)
    monkeypatch.setattr(scanner,'_record_path',unstable)
    second=scanner.scan(db,[str(root)],scanner.ScanControl(0,2))
    assert second['status']=='success'
    assert second['warning_count']>=1
    assert second['changes']['removed']==0
    assert second['lifetime_space_saved']==previous_lifetime
    c=scanner.connect(db,readonly=True)
    try:
        r=c.execute('SELECT id FROM scans ORDER BY id DESC LIMIT 1').fetchone()
        report=scanner.read_scan_report(c,r['id'])
        assert report['warnings']
        assert any(w['path']==str(a) for w in report['warnings'])
        assert report['totals']['file_count']==2
        assert report['volumes'][0]['previous_scan_at'] is not None
    finally:
        c.close()

def test_unscanned_volume_not_in_report(tmp_path):
    roots=[]
    for name in ('first','second','third'):
        p=tmp_path/name;p.mkdir();(p/'x.bin').write_bytes(b'contents'+name.encode())
        roots.append(str(p))
    db=str(tmp_path/'inventory.sqlite3')
    scanner.scan(db,roots,scanner.ScanControl(0,2))
    scanner.scan(db,roots[:2],scanner.ScanControl(0,2),mode='quick',preserved_roots=roots[2:])
    c=scanner.connect(db,readonly=True)
    try:
        sid=c.execute('SELECT MAX(id) FROM scans').fetchone()[0]
        report=scanner.read_scan_report(c,sid)
        assert set(report['roots'])==set(roots[:2])
        assert len(report['volumes'])==2
        assert report['totals']['file_count']==2
        assert report['totals']['file_delta']==0
    finally:
        c.close()

@pytest.mark.skipif(hasattr(os,'geteuid') and os.geteuid()==0,reason='root ignores Unix directory permissions')
def test_unreadable_subdirectory_preserves_previous_inventory(tmp_path):
    root=tmp_path/'source'
    secret=root/'private'
    secret.mkdir(parents=True)
    (secret/'secret.bin').write_bytes(b'duplicate'*1024)
    (root/'visible.bin').write_bytes(b'duplicate'*1024)
    db=str(tmp_path/'inventory.sqlite3')
    first=scanner.scan(db,[str(root)],scanner.ScanControl(0,2))
    assert first['status']=='success'
    lifetime=first['lifetime_space_saved']
    secret.chmod(0)
    try:
        second=scanner.scan(db,[str(root)],scanner.ScanControl(0,2))
    finally:
        secret.chmod(0o700)
    assert second['status']=='success'
    assert second['warning_count']>=1
    assert second['changes']['removed']==0
    assert second['lifetime_space_saved']==lifetime
    c=scanner.connect(db,readonly=True)
    try:
        assert c.execute('SELECT COUNT(*) FROM files').fetchone()[0]==2
        sid=c.execute('SELECT MAX(id) FROM scans').fetchone()[0]
        report=scanner.read_scan_report(c,sid)
        assert any(w['path']==str(secret) for w in report['warnings'])
    finally:
        c.close()

def test_historical_report_remains_unchanged(tmp_path):
    root=tmp_path/'source'
    root.mkdir()
    (root/'first').write_bytes(b'A'*4096)
    db=str(tmp_path/'data.sqlite3')
    scanner.scan(db,[str(root)],scanner.ScanControl(0,2))
    c=scanner.connect(db,readonly=True)
    try:
        first_report=scanner.read_scan_report(c,1)
    finally:
        c.close()
    (root/'second').write_bytes(b'A'*4096)
    scanner.scan(db,[str(root)],scanner.ScanControl(0,2),mode='quick')
    c=scanner.connect(db,readonly=True)
    try:
        assert scanner.read_scan_report(c,1)==first_report
        second_report=scanner.read_scan_report(c,2)
        assert second_report['totals']['file_count']==2
        assert second_report['totals']['file_delta']==1
    finally:
        c.close()
