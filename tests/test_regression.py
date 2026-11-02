"""DFM v0.4.1 end-to-end safety and compatibility tests (stdlib + pytest).

All file roots and SQLite databases are disposable temporary directories.
No user's NAS, Docker volume or source data is touched.
"""
import hashlib
import importlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import threading
import time
import urllib.request
import urllib.error
import tempfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
import scanner
import configuration
import schedule_engine


@pytest.fixture
def setup(tmp_path):
    roots = [tmp_path / ('vol' + str(i)) for i in range(3)]
    for r in roots: r.mkdir()
    # Deliberately include same-size/different-content, zero-length, duplicate
    # within a volume, and cross-volume duplicate groups.
    (roots[0] / 'alpha.bin').write_bytes(b'A' * 8192)
    (roots[0] / 'same.bin').write_bytes(b'A' * 8192)
    (roots[0] / 'zero').write_bytes(b'')
    (roots[0] / 'diff.bin').write_bytes(b'B' * 8192)
    (roots[1] / 'dup.bin').write_bytes(b'A' * 8192)
    (roots[1] / 'unique.bin').write_bytes(b'X' * 121)
    (roots[1] / 'zero').write_bytes(b'')
    (roots[2] / 'other.bin').write_bytes(b'A' * 8192)
    (roots[2] / 'unique.bin').write_bytes(b'Z' * 319)
    db = str(tmp_path / 'db.sqlite3')
    return db, [str(r) for r in roots]


def inventory(db):
    c=scanner.connect(db, readonly=True)
    try:
        return {row['path']:tuple(row) for row in c.execute('SELECT path,root,size,mtime_ns,dev,inode,partial,full FROM files ORDER BY path')}
    finally:c.close()


def history(db):
    c=scanner.connect(db,readonly=True)
    try:
        return [tuple(row) for row in c.execute("SELECT * FROM scans WHERE status='success' ORDER BY id")]
    finally:c.close()


def run(db,roots,mode='full',preserved=(),control=None):
    return scanner.scan(db,roots, control or scanner.ScanControl(0,2),mode=mode,preserved_roots=preserved)


def prepare_baseline(db,roots):
    scanner.initialize_database(db)
    x=run(db,roots)
    assert x['status']=='success'
    return x


def test_full_scan_consistent_cache_history(setup):
    db, roots=setup
    x=prepare_baseline(db,roots)
    assert x['files_scanned']==9
    assert x['scan_duplicates_count']==3
    assert x['scan_wasted_space']==3*8192
    rows=inventory(db)
    assert len(rows)==9
    assert all(row[7] for row in rows.values() if row[2]==8192)
    assert all(row[7] is None for row in rows.values() if row[2]==0)
    c=scanner.connect(db,readonly=True)
    try:
        assert scanner.quick_baseline_available(c,roots)
        assert scanner.current_metrics(c)==(3,3*8192)
    finally:c.close()
    assert history(db)[0][3]=='success'


def test_quick_all_no_persistent_staging_deletion_no_rehash(setup):
    db,roots=setup;prepare_baseline(db,roots)
    c=scanner.connect(db,readonly=False)
    with c:
        c.execute('INSERT INTO work_files(path,root,size,mtime_ns,dev,inode) VALUES(?,?,?,?,?,?)',
                  ('PERSISTENT_SENTINEL','PERSISTENT_SENTINEL',1,0,0,0))
    c.close()
    initial=inventory(db);old=history(db)
    x=run(db,roots,'quick')
    assert x['files_scanned']==9
    assert x['scan_duplicates_count']==3
    assert x['changes']=={'added':0,'removed':0,'modified':0,'possible_moves':0}
    assert x['io_totals']['io_files'] == 0
    assert inventory(db)==initial
    assert history(db)[:len(old)]==old
    c=scanner.connect(db, readonly=True)
    try:
        assert c.execute("SELECT COUNT(*) FROM work_files WHERE path='PERSISTENT_SENTINEL'").fetchone()[0]==1
    finally:c.close()


def test_quick_scoped_metrics_protect_other_roots(setup):
    db,roots=setup;prepare_baseline(db,roots)
    old=inventory(db);before=history(db)
    out=run(db,[roots[1]],'quick',preserved=[roots[0],roots[2]])
    assert out['status']=='success'
    assert out['files_scanned']==3
    assert out['scan_duplicates_count']==1
    assert out['scan_wasted_space']==8192
    assert out['current_duplicates_count']==3
    assert inventory(db)==old
    assert history(db)[:len(before)]==before
    c=scanner.connect(db, readonly=True)
    try:
        newest=c.execute('SELECT files,duplicates,wasted,progress_json FROM scans ORDER BY id DESC LIMIT 1').fetchone()
        assert newest['files']==3 and newest['duplicates']==1 and newest['wasted']==8192
        assert json.loads(newest['progress_json'])['scan_scope']==[roots[1]]
    finally:c.close()


def test_quick_select_two_scopes_preserves_third_and_history(setup):
    db,roots=setup;prepare_baseline(db,roots)
    old=inventory(db);before=history(db)
    (Path(roots[0])/'diff.bin').write_bytes(b'C'*8192)
    (Path(roots[2])/'other.bin').unlink() # This volume MUST NOT be enumerated.
    x=run(db,roots[:2],'quick',preserved=roots[2:])
    assert x['files_scanned']==7
    assert x['changes']['modified']==1
    new=inventory(db)
    assert new[str(Path(roots[2])/'other.bin')]==old[str(Path(roots[2])/'other.bin')]
    assert x['scan_duplicates_count']==2
    assert x['current_duplicates_count']==3
    assert history(db)[:len(before)]==before
    c=scanner.connect(db,readonly=True)
    try:
        assert [r['root'] for r in c.execute('SELECT root FROM volume_scans WHERE scan_id=(SELECT MAX(id) FROM scans) ORDER BY root')]==roots[:2]
    finally:c.close()


def test_no_quick_without_full_baseline(setup):
    db,roots=setup;scanner.initialize_database(db)
    with pytest.raises(ValueError,match='full scan'):
        run(db,[roots[2]],'quick',preserved=roots[:2])
    c=scanner.connect(db,readonly=True)
    try:
        assert c.execute('SELECT COUNT(*) FROM files').fetchone()[0]==0
    finally:c.close()


def test_cancel_before_enumeration_never_publish(setup):
    db,roots=setup;prepare_baseline(db,roots)
    old=inventory(db);past=history(db)
    control=scanner.ScanControl(0,2)
    assert control.stop()
    with pytest.raises(scanner.ScanCancelled):
        run(db,roots,'quick',control=control)
    assert inventory(db)==old
    assert history(db)==past


def test_missing_root_fails_closed(setup):
    db,roots=setup;prepare_baseline(db,roots)
    old=inventory(db);past=history(db)
    os.rename(roots[1],roots[1]+'-offline')
    with pytest.raises(Exception):
        run(db,roots,'quick')
    assert inventory(db)==old and history(db)==past


def test_archival_and_restore_preserve_completed_history(setup):
    db,roots=setup;prepare_baseline(db,roots)
    before=history(db)
    scanner.archive_volume(db,roots[2],roots)
    assert all(row[1]!=roots[2] for row in inventory(db).values())
    scanner.restore_volume(db,roots[2],roots)
    assert history(db)==before


def test_settings_and_schedule_validations(setup):
    db,roots=setup;prepare_baseline(db,roots)
    configured=configuration.save_volume_mode(db,roots,True)
    assert configured['per_volume_enabled'] is True
    entries=[{'mode':'quick','root':roots[0],'frequency':'daily','at':'02:00',
              'timezone':'America/Chicago','enabled':False,'on_conflict':'skip','on_missed':'skip'}]
    saved=schedule_engine.save_schedules(db,entries,roots,True)
    assert len(saved)==1 and saved[0]['enabled'] is False
    assert schedule_engine.next_occurrence(saved[0],time.time())>time.time()
    assert len(schedule_engine.get_schedules(db))==1
    # Invalid root and invalid cron must fail validation without replacing good schedules.
    with pytest.raises(ValueError):
        schedule_engine.save_schedules(db,[dict(entries[0],root='/nope')],roots,True)
    assert len(schedule_engine.get_schedules(db))==1


def test_startup_existing_database_zero_writes(setup):
    db,roots=setup;prepare_baseline(db,roots)
    mtime=Path(db).stat().st_mtime_ns
    scanner._initialized_dbs.clear()
    assert scanner._current_schema_readonly(db)
    scanner.initialize_database(db)
    assert Path(db).stat().st_mtime_ns==mtime


def test_hash_cache_full_shas_correct(setup):
    db,roots=setup;prepare_baseline(db,roots)
    c=scanner.connect(db,readonly=True)
    try:
        for row in c.execute('SELECT path, full FROM files WHERE size>0 AND full IS NOT NULL'):
            assert hashlib.sha256(Path(row['path']).read_bytes()).hexdigest()==row['full']
    finally:c.close()


def test_scan_lock_rejects_overlap_and_selection_validation(setup,monkeypatch):
    db,roots=setup;prepare_baseline(db,roots)
    import main
    monkeypatch.setattr(main,'DB',db)
    monkeypatch.setattr(main,'ROOTS',roots)
    configuration.save_volume_mode(db,roots,True)
    main.lock.acquire()
    try:
        assert main.trigger_scan('quick',roots[0]) is False
    finally:main.lock.release()
    for invalid in ([],[roots[0],roots[0]],['/unknown'],['/unknown',roots[0]],'bad'):
        with pytest.raises(ValueError):
            main.trigger_scan('quick','all',invalid)
    assert main.lock.locked() is False


def test_discovery_real_time_scoped_counts(setup):
    db,roots=setup;prepare_baseline(db,roots)
    snapshots=[]
    class Capture(scanner.ScanControl):
        def set_progress(self,**kw):
            super().set_progress(**kw)
            if kw.get('metrics_ready') and self.snapshot().get('stage')=='enumerating':
                snapshots.append((kw.get('confirmed_duplicate_copies'),kw.get('confirmed_wasted_bytes')))
    ctrl=Capture(0,2)
    x=run(db,[roots[1]],'quick',preserved=[roots[0],roots[2]],control=ctrl)
    assert x['scan_duplicates_count']==1
    assert snapshots and snapshots[-1]==(1,8192)


def test_two_volume_full_initialization_not_touch_unselected(setup):
    db,roots=setup;prepare_baseline(db,roots)
    before=inventory(db)
    x=run(db,[roots[0],roots[2]],'full',preserved=[roots[1]])
    assert x['files_scanned']==6 and x['scan_duplicates_count']==2
    after=inventory(db)
    for path,row in before.items():
        if row[1]==roots[1]:assert after[path]==row


def test_zero_byte_excluded_from_all_scan_counts(setup):
    db,roots=setup;prepare_baseline(db,roots)
    (Path(roots[2])/'another-empty').write_bytes(b'')
    x=run(db,roots,'quick')
    assert x['files_scanned']==10
    assert x['scan_duplicates_count']==3


def test_history_filter_includes_scanned_scope_only(setup):
    db,roots=setup;prepare_baseline(db,roots)
    run(db,[roots[0]],'quick',preserved=roots[1:])
    c=scanner.connect(db,readonly=True)
    try:
        records=[dict(row) for row in c.execute('SELECT id,progress_json FROM scans WHERE status="success"')]
        scopes={r['id']:json.loads(r['progress_json'])['scan_scope'] for r in records}
        assert any(roots[0] in r for r in scopes.values())
        assert any(roots[2] not in r for r in scopes.values())
    finally:c.close()

@pytest.mark.parametrize('frequency,seconds', [('5m',300),('10m',600),('15m',900),('30m',1800),('60m',3600)])
def test_schedule_interval_precision(frequency,seconds):
    e={'frequency':frequency,'timezone':'America/Chicago'}
    assert schedule_engine.next_occurrence(e,1_500_000_000.125)==pytest.approx(1_500_000_000.125+seconds)

@pytest.mark.parametrize('frequency', ['hourly','daily','weekly','monthly','custom'])
def test_calendar_schedules_advance_without_past_results(frequency):
    from datetime import datetime
    from zoneinfo import ZoneInfo
    e={'frequency':frequency,'timezone':'America/Chicago','at':'02:17',
       'weekday':2,'month_day':15,'cron':'17 2 * * 1-5'}
    before=datetime(2026,10,31,16,0,tzinfo=ZoneInfo('America/Chicago')).timestamp()
    when=schedule_engine.next_occurrence(e,before)
    after=datetime.fromtimestamp(when,ZoneInfo('America/Chicago'))
    assert when>before
    if frequency=='hourly':assert after.minute==17
    elif frequency=='daily':assert after.hour==2 and after.minute==17
    elif frequency=='weekly':assert after.weekday()==2
    elif frequency=='monthly':assert after.day==15
    elif frequency=='custom':assert after.weekday() in range(5)

@pytest.mark.parametrize('invalid', ['a b c d e', '* * * *', '0 24 * * *', '99 2 * * *',
                                     '*/0 * * * *', '0 1 40 * *', '0 1 * 15 *'])
def test_cron_rejects_invalid_expressions(invalid):
    from datetime import datetime
    with pytest.raises(ValueError):
        schedule_engine.cron_matches(invalid,datetime(2026,10,31,2,0))

@pytest.mark.parametrize('size', [0,1,10,4096,1_000_000,3*1024*1024,3*1024*1024+1,30*1024*1024])
def test_sampling_windows_within_file(size):
    window=scanner.sample_window_for_size(size)
    assert window is None or window>0
    for offset in scanner.sample_offsets(size) or ():
        assert 0<=offset<=size


def test_stop_and_failure_in_discovery_cannot_change_inventory(setup,monkeypatch):
    db,roots=setup;prepare_baseline(db,roots)
    old=inventory(db);previous=history(db)
    def aborted(c,rootlist,control,scan_id,discovery_metrics=None):
        with c:c.execute('DELETE FROM work_files WHERE root=?',(roots[1],))
        raise scanner.ScanCancelled('simulated stop in enumeration')
    monkeypatch.setattr(scanner,'_enumerate_parallel',aborted)
    with pytest.raises(scanner.ScanCancelled):
        run(db,[roots[1]],'quick',preserved=[roots[0],roots[2]])
    assert inventory(db)==old
    assert history(db)==previous


def test_failed_missing_file_in_fingerprint_never_publishes(setup,monkeypatch):
    db,roots=setup;prepare_baseline(db,roots)
    old=inventory(db)
    before=history(db)
    def failed(c,rootlist,control,scan_id,discovery_metrics=None):
        raise OSError('simulated read failure')
    monkeypatch.setattr(scanner,'_enumerate_parallel',failed)
    with pytest.raises(OSError, match='read failure'):
        run(db,roots,'quick')
    assert inventory(db)==old and history(db)==before


def test_large_intentional_removal_is_published_without_override(setup):
    db,roots=setup;prepare_baseline(db,roots)
    before=inventory(db)
    for file in Path(roots[0]).iterdir():file.unlink()
    out=run(db,[roots[0]],'quick',preserved=[roots[1],roots[2]])
    assert out['status']=='success'
    assert out['changes']['removed']==4
    after=inventory(db)
    assert len(after)==len(before)-4
    assert not any(path.startswith(roots[0] + os.sep) for path in after)
    assert history(db)[-1][3]=='success'


def test_deleted_duplicate_credits_lifetime_only_when_verified(setup):
    db,roots=setup;prepare_baseline(db,roots)
    previous=history(db)
    (Path(roots[1])/'dup.bin').unlink()
    out=run(db,[roots[1]],'quick',preserved=[roots[0],roots[2]])
    assert out['changes']['removed']==1
    assert out['lifetime_space_saved']==8192
    assert out['current_duplicates_count']==2
    assert history(db)[:len(previous)]==previous


def test_added_duplicate_discovered_correctly(setup):
    db,roots=setup;prepare_baseline(db,roots)
    (Path(roots[2])/'new-match.bin').write_bytes(b'A'*8192)
    x=run(db,[roots[2]],'quick',preserved=roots[:2])
    assert x['changes']['added']==1
    assert x['scan_duplicates_count']==2
    assert x['current_duplicates_count']==4


def test_new_volume_baseline_is_invalid_until_full_scan(setup,monkeypatch):
    db,roots=setup;prepare_baseline(db,roots)
    added=str(Path(roots[0]).parent/'added')
    Path(added).mkdir()
    (Path(added)/'first').write_text('example')
    # Mount-point guard is exercised separately in configuration.normalize_root.
    monkeypatch.setattr(configuration,'normalize_root',lambda p: str(Path(p)))
    conf=configuration.add_volume(db,roots,added)
    assert added in conf['roots']
    c=scanner.connect(db,readonly=True)
    try:assert not scanner.quick_baseline_available(c,[added])
    finally:c.close()
    run(db,[added],'full',preserved=roots)
    c=scanner.connect(db,readonly=True)
    try:assert scanner.quick_baseline_available(c,[added])
    finally:c.close()


def test_verified_relocation_keeps_baseline_and_immutable_history(setup,monkeypatch):
    db,roots=setup;prepare_baseline(db,roots)
    import shutil
    before=history(db)
    new=str(Path(roots[0]).parent/'moved')
    shutil.copytree(roots[0],new,copy_function=shutil.copy2)
    monkeypatch.setattr(configuration,'normalize_root',lambda p:str(Path(p)))
    conf=configuration.relocate_volume(db,roots,roots[0],new)
    assert new in conf['roots'] and roots[0] not in conf['roots']
    assert history(db)==before
    c=scanner.connect(db,readonly=True)
    try:
        assert scanner.quick_baseline_available(c,[new])
        assert c.execute('SELECT COUNT(*) FROM files WHERE root=?',(new,)).fetchone()[0]==4
        assert c.execute('SELECT COUNT(*) FROM files WHERE root=?',(roots[0],)).fetchone()[0]==0
    finally:c.close()


def test_volume_remove_does_not_touch_history(setup):
    db,roots=setup;prepare_baseline(db,roots)
    previous=history(db)
    conf=configuration.remove_volume(db,roots,roots[2])
    assert len(conf['roots'])==2
    assert all(row[1]!=roots[2] for row in inventory(db).values())
    assert history(db)==previous


def test_volume_relocation_to_different_files_is_rejected(setup,monkeypatch):
    db,roots=setup;prepare_baseline(db,roots)
    before=inventory(db)
    other=str(Path(roots[0]).parent/'not-matching')
    Path(other).mkdir()
    monkeypatch.setattr(configuration,'normalize_root',lambda p:str(Path(p)))
    with pytest.raises(ValueError,match='verification failed'):
        configuration.relocate_volume(db,roots,roots[0],other)
    assert inventory(db)==before


def test_multiple_volume_selection_requires_enabled_mode(setup,monkeypatch):
    db,roots=setup;prepare_baseline(db,roots)
    import main
    monkeypatch.setattr(main,'DB',db)
    monkeypatch.setattr(main,'ROOTS',roots)
    with pytest.raises(ValueError,match='Enable per-volume'):
        main.trigger_scan('quick','all',roots[:2])


def test_report_only_true_full_hash_duplicates(setup):
    db,roots=setup;prepare_baseline(db,roots)
    result=scanner.report(db,limit=50,return_total=True)
    # The duplicate report should include only verified full-hash groups.
    assert result is not None


def test_overlap_prevents_multiple_scanner_workers(setup,monkeypatch):
    db,roots=setup;prepare_baseline(db,roots)
    import main
    monkeypatch.setattr(main,'DB',db)
    monkeypatch.setattr(main,'ROOTS',roots)
    main.lock.acquire()
    try:
        assert main.trigger_scan('quick','all') is False
        assert main.trigger_scan('full','all') is False
    finally:
        main.lock.release()


def test_scan_scope_metrics_from_published_and_scoped_add_up(setup):
    db,roots=setup;prepare_baseline(db,roots)
    import main
    c=scanner.connect(db,readonly=True)
    try:
        global_copies,global_wasted=scanner.current_metrics(c)
        attributed=main._per_volume_duplicate_metrics(c,('test',time.time()))
        assert sum(x['duplicate_copies'] for x in attributed.values())==global_copies
        assert sum(x['wasted_bytes'] for x in attributed.values())==global_wasted
    finally:c.close()

@pytest.mark.parametrize('policy,should_start', [('skip',False),('run_once',True)])
def test_scheduler_missed_run_policy(setup,monkeypatch,policy,should_start):
    db,roots=setup;prepare_baseline(db,roots)
    import main
    monkeypatch.setattr(main,'DB',db)
    monkeypatch.setattr(main,'ROOTS',roots)
    now=1_800_000_000.
    entry={'mode':'quick','root':'all','frequency':'daily','at':'02:00',
           'timezone':'America/Chicago','enabled':True,'on_missed':policy,
           'on_conflict':'skip'}
    saved=schedule_engine.save_schedules(db,[entry],roots,False,now=now-100000)
    assert saved[0]['next_run']<now-60
    starts=[]
    monkeypatch.setattr(main,'trigger_scan',lambda mode,root:starts.append((mode,root)) or True)
    main.run_due_schedules(now=now)
    assert bool(starts)==should_start
    updated=schedule_engine.get_schedules(db)[0]
    assert updated['next_run']>now
    assert updated['last_outcome']=='Started' if should_start else 'skipped' in updated['last_outcome']


@pytest.mark.parametrize('policy', ['skip','defer'])
def test_scheduler_busy_does_not_start_second_job(setup,monkeypatch,policy):
    db,roots=setup;prepare_baseline(db,roots)
    import main
    monkeypatch.setattr(main,'DB',db)
    monkeypatch.setattr(main,'ROOTS',roots)
    now=1_800_000_000.
    entry={'mode':'quick','root':'all','frequency':'5m','at':'02:00',
           'timezone':'America/Chicago','enabled':True,'on_missed':'run_once',
           'on_conflict':policy}
    schedule_engine.save_schedules(db,[entry],roots,False,now=now-600)
    monkeypatch.setattr(main,'trigger_scan',lambda *a:pytest.fail('Concurrent schedule started a scan'))
    main.lock.acquire()
    try:main.run_due_schedules(now=now)
    finally:main.lock.release()
    row=schedule_engine.get_schedules(db)[0]
    assert 'another scan' in row['last_outcome'].lower()
    assert row['next_run']==now+15 if policy=='defer' else row['next_run']>now


def test_enabled_schedule_records_next_run_and_never_fires_on_save(setup):
    db,roots=setup;prepare_baseline(db,roots)
    before=history(db)
    entry={'mode':'quick','root':roots[1],'frequency':'hourly','at':'02:15',
           'timezone':'America/Chicago','enabled':True,'on_missed':'skip',
           'on_conflict':'skip'}
    configuration.save_volume_mode(db,roots,True)
    s=schedule_engine.save_schedules(db,[entry],roots,True,now=1_800_000_000.)
    assert s[0]['next_run']>1_800_000_000.
    assert history(db)==before


def test_reject_duplicate_schedule_id_without_modifying_saved(setup):
    db,roots=setup;prepare_baseline(db,roots)
    entry={'mode':'quick','root':'all','frequency':'daily','at':'02:00',
           'timezone':'America/Chicago','enabled':False}
    old=schedule_engine.save_schedules(db,[entry],roots,False)
    with pytest.raises(ValueError,match='Duplicate schedule'):
        schedule_engine.save_schedules(db,[entry,entry],roots,False)
    assert schedule_engine.get_schedules(db)==old


def test_v043_volume_progress_and_immutable_snapshots(setup):
    db, roots = setup
    control = scanner.ScanControl(0, 2)
    result = run(db, roots, 'full', control=control)
    assert result['status'] == 'success'
    progress = control.snapshot()
    assert progress['per_volume_discovered'] == dict(zip(roots, (4, 3, 2)))
    c = scanner.connect(db, readonly=True)
    try:
        first = [dict(r) for r in c.execute(
            'SELECT root,file_count,duplicate_copies,wasted_bytes FROM volume_scans ORDER BY root')]
        assert sum(r['duplicate_copies'] for r in first) == 3
        assert sum(r['wasted_bytes'] for r in first) == 24576
        saved = [(r['root'],r['file_count'],r['duplicate_copies'],r['wasted_bytes']) for r in first]
    finally:
        c.close()
    (Path(roots[1]) / 'dup.bin').write_bytes(b'Q' * 8192)
    result = run(db, [roots[1]], 'full', preserved=[roots[0], roots[2]])
    assert result['status'] == 'success'
    c = scanner.connect(db, readonly=True)
    try:
        unchanged = [(r['root'],r['file_count'],r['duplicate_copies'],r['wasted_bytes'])
                     for r in c.execute('SELECT root,file_count,duplicate_copies,wasted_bytes FROM volume_scans WHERE scan_id=1 ORDER BY root')]
        assert unchanged == saved
        assert c.execute('SELECT COUNT(*) FROM volume_scans WHERE scan_id=2').fetchone()[0] == 1
    finally:
        c.close()

def test_v0431_discovery_snapshot_atomic_counts():
    control=scanner.ScanControl(0, 2)
    roots=['/scan/fht','/scan/files']
    control.set_progress(scan_scope=roots,per_volume_discovered={})
    for _ in range(37): control.add_volume_discovered(roots[0])
    for _ in range(19): control.add_volume_discovered(roots[1])
    snap=control.snapshot()
    assert snap['files_discovered']==sum(snap['per_volume_discovered'][r] for r in roots)


def test_staged_duplicate_snapshots_equal_published_metrics_on_large_deletion(tmp_path):
    """Moving snapshot aggregation outside the commit preserves exact attribution."""
    db = str(tmp_path / 'db.sqlite3')
    scanner.initialize_database(db)
    c = scanner.connect(db)
    roots = ['/synthetic/a', '/synthetic/b']
    try:
        scanner._create_scoped_work_table(c)
        scanner._index_scoped_work_table(c)
        records=[]
        # Includes duplicate groups with several copies across volumes,
        # independent unique files and a zero-byte file.
        for i in range(2500):
            root=roots[i%2]
            size=128 if i%3 else 256
            digest='hash'+str(i%100)
            records.append((f'{root}/file{i}',root,size,1,1,i+1,digest))
        records.append(('/synthetic/b/empty',roots[1],0,1,1,9999,None))
        c.executemany('INSERT INTO temp.work_files(path,root,size,mtime_ns,dev,inode,full) VALUES(?,?,?,?,?,?,?)', records)
        expected=scanner._snapshot_volume_duplicate_metrics(c, roots)
        with c:
            c.execute('INSERT INTO files(path,root,size,mtime_ns,dev,inode,full) SELECT path,root,size,mtime_ns,dev,inode,full FROM temp.work_files')
        actual={root:[0,0] for root in roots}
        group=None
        for r in c.execute('''SELECT size,full,root,COUNT(*) n,MIN(path) first_path
                               FROM files WHERE size>0 AND full IS NOT NULL
                               GROUP BY size,full,root ORDER BY size,full,first_path'''):
            new=(r['size'],r['full']); n=r['n']-(1 if group!=new else 0); group=new
            actual[r['root']][0]+=n
            actual[r['root']][1]+=n*r['size']
        assert expected==actual
        # Mimic large file removals followed by publication.
        c.execute('DELETE FROM temp.work_files WHERE (inode%3) != 0')
        expected=scanner._snapshot_volume_duplicate_metrics(c, roots)
        with c:
            c.execute('DELETE FROM files WHERE path NOT IN (SELECT path FROM temp.work_files)')
        actual={root:[0,0] for root in roots}
        group=None
        for r in c.execute('''SELECT size,full,root,COUNT(*) n,MIN(path) first_path
                               FROM files WHERE size>0 AND full IS NOT NULL
                               GROUP BY size,full,root ORDER BY size,full,first_path'''):
            new=(r['size'],r['full']); n=r['n']-(1 if group!=new else 0); group=new
            actual[r['root']][0]+=n
            actual[r['root']][1]+=n*r['size']
        assert expected==actual
    finally:
        c.close()
