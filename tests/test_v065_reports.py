"""v0.6.5 immutable scan-specific duplicate archives and truthful legacy reconstruction."""
import json
import os
from pathlib import Path
import sys

import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
import scanner
from test_regression import setup, run


def test_archive_complete_paths_existing_and_cross_volume(setup):
    db, roots = setup
    run(db, roots)
    c = scanner.connect(db, readonly=True)
    try:
        r = scanner.read_scan_report(c, 1)
        assert r['duplicate_snapshot_available'] is True
        assert r['duplicate_group_count'] == 1
        a = scanner.list_scan_duplicate_groups(c, 1, r)
        assert a['available'] and a['total_groups'] == 1
        group = a['items'][0]
        assert group['copies'] == 4 and group['scoped_copies'] == 4
        assert {p['path'] for p in group['paths']} == {
            os.path.join(roots[0], 'alpha.bin'), os.path.join(roots[0], 'same.bin'),
            os.path.join(roots[1], 'dup.bin'), os.path.join(roots[2], 'other.bin')}
        assert all(p['in_scope'] for p in group['paths'])
    finally:
        c.close()

    # A later scoped Quick Scan retains every *previously known* duplicate,
    # including cross-volume paths without rescanning those other volumes.
    run(db, roots[:1], mode='quick', preserved=roots[1:])
    c = scanner.connect(db, readonly=True)
    try:
        report = scanner.read_scan_report(c, 2)
        assert report['roots'] == roots[:1]
        groups = scanner.list_scan_duplicate_groups(c, 2, report)
        group = groups['items'][0]
        assert group['copies'] == 4 and group['scoped_copies'] == 2
        assert sum(p['in_scope'] for p in group['paths']) == 2
        assert len(group['paths']) == 4
        assert scanner.list_scan_duplicate_groups(c, 2, report,
                   search='same.bin')['total_groups'] == 1
        assert scanner.list_scan_duplicate_groups(c, 2, report,
                   search='absent-file-name')['total_groups'] == 0
        assert scanner.list_scan_duplicate_groups(c, 2, report,
                   root=roots[0])['total_groups'] == 1
        with pytest.raises(ValueError):
            scanner.list_scan_duplicate_groups(c, 2, report, root=roots[2])
    finally:
        c.close()


def test_duplicate_archive_remains_immutable_when_inventory_changes(setup):
    db, roots = setup
    run(db, roots)
    c = scanner.connect(db, readonly=True)
    try:
        report_before = scanner.read_scan_report(c, 1)
        groups_before = scanner.list_scan_duplicate_groups(c, 1, report_before)
    finally:
        c.close()
    (Path(roots[0]) / 'same.bin').write_bytes(b'changed-data')
    run(db, roots, mode='quick')
    c = scanner.connect(db, readonly=True)
    try:
        assert scanner.read_scan_report(c, 1) == report_before
        assert scanner.list_scan_duplicate_groups(c, 1, report_before) == groups_before
        latest = scanner.read_scan_report(c, 2)
        now = scanner.list_scan_duplicate_groups(c, 2, latest)
        assert len(now['items'][0]['paths']) == 3
    finally:
        c.close()


def test_legacy_report_is_created_only_once_with_unknowns(tmp_path):
    db = str(tmp_path / 'dfm.db')
    scanner.initialize_database(db)
    c = scanner.connect(db)
    try:
        with c:
            c.execute("""INSERT INTO scans(id,started,ended,status,mode,error,files,duplicates,wasted)
                         VALUES(7,100,120,'success','quick','',8,3,12288)""")
            c.execute("""INSERT INTO volume_scans(scan_id,root,file_count,duplicate_copies,wasted_bytes)
                         VALUES(7,'/scan/old',8,3,12288)""")
    finally:
        c.close()
    first = scanner.reconstruct_legacy_scan_report(db, 7)
    assert first['reconstructed'] is True
    assert first['warning_details_available'] is False
    assert first['duplicate_snapshot_available'] is False
    assert first['totals']['total_size_bytes'] is None
    assert first['volumes'][0]['file_count'] == 8
    assert first['volumes'][0]['wasted_bytes'] == 12288
    assert first['warnings'] == []
    assert first['duration_seconds'] == 20
    assert scanner.reconstruct_legacy_scan_report(db, 7) == first
    c = scanner.connect(db)
    try:
        with c:
            c.execute('UPDATE scans SET files=900,duplicates=800,wasted=999999 WHERE id=7')
        assert scanner.read_scan_report(c, 7) == first
        result = scanner.list_scan_duplicate_groups(c, 7, first)
        assert result['available'] is False and result['total_groups'] is None
    finally:
        c.close()
    assert scanner.reconstruct_legacy_scan_report(db, 999) is None


def test_browser_status_styles_and_history_links(tmp_path, monkeypatch):
    # Other HTTP tests import main.py, which sets a container-only TMPDIR.
    # Playwright must use an actual runner-local writable temp directory.
    import tempfile
    monkeypatch.setenv('TMPDIR', str(tmp_path))
    monkeypatch.setattr(tempfile, 'tempdir', str(tmp_path))
    pytest.importorskip('playwright.sync_api')
    from playwright.sync_api import sync_playwright
    html = (Path(__file__).resolve().parents[1] / 'app/index.html').read_text()
    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path='/usr/bin/chromium', headless=True,
                                     args=['--no-sandbox', '--disable-dev-shm-usage'])
        page = browser.new_page()
        errors = []
        page.on('pageerror', lambda err: errors.append(str(err)))
        page.set_content(html, wait_until='domcontentloaded')
        for status, warnings, stage_class, meter_class in [
            ('success', 0, 'stage-complete', 'complete'),
            ('success', 3, 'stage-warning', 'warning'),
            ('failed', 0, 'stage-failed', 'failed'),
            ('cancelled', 0, 'stage-cancelled', 'cancelled')]:
            page.evaluate("""([status,warning_count]) => progressRender({
                scanning:false,status,warning_count,started:100,ended:103,files:2,
                lifetime:0, last_scan_progress:{stage:'full_hashing',full_hash_bytes_total:100,
                full_hash_bytes_done:50,scan_scope:['/scan/one']}})""",
                [status, warnings])
            assert stage_class in page.locator('#stage-name').get_attribute('class')
            assert meter_class in page.locator('#progress-meter').get_attribute('class')
        page.evaluate("""()=>{const row={id:8,status:'success',mode:'full',started:100,ended:103,
          files:2,duplicates:1,wasted:3,volumes:[],has_report:false};
          const table=document.getElementById('history');const tr=document.createElement('tr');
          const st=cell(tr,reportStatus(row.status,0));
          const link=makeReportLink(row.id,reportStatus(row.status,0));
          st.replaceChildren(link);table.replaceChildren(tr)}""")
        assert page.locator('#history a.scan-report-link').inner_text() == 'Completed'
        assert page.locator('#history button').count() == 0
        assert not errors, errors
        browser.close()
