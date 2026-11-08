"""v0.6.6 regression tests for modal usability and outstanding GitHub issues."""
from pathlib import Path
import os
import sys
import tempfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app'))
import scanner
from version import VERSION


def test_version_sources_and_release_notes_match():
    assert VERSION == '0.6.6'
    html = (ROOT / 'app/index.html').read_text()
    assert f"const LOADED_UI_VERSION = '{VERSION}'" in html
    assert f"**Version {VERSION}**" in (ROOT / 'README.md').read_text()
    assert f"ghcr.io/fasthowto/duplicate-file-monitor:{VERSION}" in (ROOT / 'docker-compose.example.yml').read_text()
    assert (ROOT / f'RELEASE_NOTES_{VERSION}.md').is_file()
    assert 'requirements-dev.txt' in (ROOT / 'README.md').read_text()


def test_mount_type_config_and_backcompat(monkeypatch):
    monkeypatch.delenv('REQUIRE_MOUNT_TYPES', raising=False)
    monkeypatch.delenv('REQUIRE_CIFS_MOUNTS', raising=False)
    assert scanner.configured_mount_types() == set()
    monkeypatch.setenv('REQUIRE_CIFS_MOUNTS', 'true')
    assert scanner.configured_mount_types() == {'cifs'}
    monkeypatch.setenv('REQUIRE_MOUNT_TYPES', 'cifs, nfs4, ZFS, xfs')
    assert scanner.configured_mount_types() == {'cifs','nfs4','zfs','xfs'}
    monkeypatch.setenv('REQUIRE_MOUNT_TYPES', '')
    assert scanner.configured_mount_types() == {'cifs'}
    monkeypatch.setenv('REQUIRE_MOUNT_TYPES', 'nfs,,zfs')
    with pytest.raises(ValueError, match='REQUIRE_MOUNT_TYPES'):
        scanner.configured_mount_types()


def test_mount_validation_accepts_nfs_zfs_xfs_and_rejects_other_types(tmp_path, monkeypatch):
    root = str(tmp_path / 'mounted')
    Path(root).mkdir()
    actual = {'type': 'nfs4'}
    monkeypatch.setattr(scanner, '_mount_filesystems', lambda: {root:actual['type']})
    assert scanner.validate_mount_types([root], {'nfs','nfs4','zfs','xfs'}) == {root:'nfs4'}
    actual['type'] = 'zfs'
    assert scanner.validate_mount_types([root], {'zfs'}) == {root:'zfs'}
    actual['type'] = 'xfs'
    assert scanner.validate_mount_types([root], {'xfs'}) == {root:'xfs'}
    assert scanner.validate_mount_types([root], {'any'}) == {root:'xfs'}
    with pytest.raises(RuntimeError, match='not allowed'):
        scanner.validate_mount_types([root], {'cifs'})
    monkeypatch.setattr(scanner, '_mount_filesystems', lambda: {})
    with pytest.raises(RuntimeError, match='not an active mountpoint'):
        scanner.validate_mount_types([root], {'any'})


def test_non_cifs_mounts_do_not_apply_cifs_remap(tmp_path, monkeypatch):
    root = str(tmp_path / 'scan')
    Path(root).mkdir()
    (Path(root) / 'one').write_bytes(b'A' * 4096)
    (Path(root) / 'two').write_bytes(b'A' * 4096)
    db = str(tmp_path / 'data.sqlite3')
    monkeypatch.setenv('REQUIRE_MOUNT_TYPES', 'nfs4,zfs')
    monkeypatch.setattr(scanner, '_mount_filesystems', lambda: {root:'nfs4'})
    remap_args = []
    original = scanner._remounted_cifs_roots
    def wrapped(c, roots, cifs_roots):
        remap_args.append(set(cifs_roots))
        return original(c, roots, cifs_roots)
    monkeypatch.setattr(scanner, '_remounted_cifs_roots', wrapped)
    result = scanner.scan(db, [root], scanner.ScanControl(0, 2))
    assert result['status'] == 'success'
    assert remap_args == [set()]
    monkeypatch.setattr(scanner, '_mount_filesystems', lambda: {root:'ext4'})
    with pytest.raises(RuntimeError, match='not allowed'):
        scanner.scan(db, [root], scanner.ScanControl(0, 2))
    c = scanner.connect(db, readonly=True)
    try:
        assert c.execute('SELECT COUNT(*) FROM files').fetchone()[0] == 2
    finally:
        c.close()


def test_ignored_paths_preserve_published_inventory_without_warning(tmp_path, monkeypatch):
    root = tmp_path / 'scan'
    hidden = root / '.cache'
    hidden.mkdir(parents=True)
    old = hidden / 'previously-indexed.dat'
    old.write_bytes(b'DUPLICATE' * 300)
    (root / 'retained.dat').write_bytes(b'DUPLICATE' * 300)
    db = str(tmp_path / 'inventory.sqlite3')
    first = scanner.scan(db, [str(root)], scanner.ScanControl(0, 2))
    assert first['status'] == 'success'
    (hidden / 'newly-ignored.dat').write_bytes(b'not indexed after ignore')
    monkeypatch.setenv('SCAN_IGNORE', '.cache:*.tmp')
    (root / 'skip.tmp').write_bytes(b'also ignored')
    second = scanner.scan(db, [str(root)], scanner.ScanControl(0, 2), mode='quick')
    assert second['status'] == 'success'
    assert second['warning_count'] == 0
    assert second['changes']['removed'] == 0
    c = scanner.connect(db, readonly=True)
    try:
        inventory = {item['path'] for item in c.execute('SELECT path FROM files')}
        assert str(old) in inventory
        assert str(root / 'retained.dat') in inventory
        assert str(hidden / 'newly-ignored.dat') not in inventory
        assert str(root / 'skip.tmp') not in inventory
    finally:
        c.close()


def test_mountinfo_escaped_paths_are_decoded(monkeypatch):
    import builtins
    import io
    normal_open = builtins.open
    text = '42 35 0:6 / /scan/a\\040b rw - nfs4 server:/export rw\n'
    def fake_open(path, *args, **kwargs):
        return io.StringIO(text) if path == '/proc/self/mountinfo' else normal_open(path, *args, **kwargs)
    monkeypatch.setattr(builtins, 'open', fake_open)
    assert scanner._mount_filesystems()['/scan/a b'] == 'nfs4'


def test_report_modal_backdrop_escape_and_focus(tmp_path, monkeypatch):
    pytest.importorskip('playwright.sync_api')
    from playwright.sync_api import sync_playwright
    monkeypatch.setenv('TMPDIR', str(tmp_path))
    monkeypatch.setattr(tempfile, 'tempdir', str(tmp_path))
    html = (ROOT / 'app/index.html').read_text()
    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path='/usr/bin/chromium', headless=True,
                                     args=['--no-sandbox', '--disable-dev-shm-usage'])
        page = browser.new_page(viewport={'width': 1280, 'height': 900})
        errors = []
        page.on('pageerror', lambda err: errors.append(str(err)))
        page.set_content(html, wait_until='domcontentloaded')
        page.evaluate("""() => {
          document.body.classList.remove('starting');
          api = async (path) => {
            if(path === '/api/reports/42') return {
              scan_id:42,status:'success',started:100,ended:110,duration_seconds:10,
              mode:'full',roots:[],volumes:[],totals:null,warnings:[],
              duplicate_snapshot_available:false
            };
            throw Error('Expected synthetic test endpoint only: '+path);
          };
          $('current-report-link').replaceChildren(makeReportLink(42,'Completed'));
        }""")
        link = page.locator('#current-report-link a.scan-report-link')
        link.click()
        overlay = page.locator('#report-overlay')
        overlay.wait_for(state='visible')
        page.locator('#report-content').click()
        assert overlay.is_visible()
        overlay.click(position={'x': 3, 'y': 3})
        assert overlay.is_hidden()
        assert link.evaluate('(e) => document.activeElement === e')
        link.click()
        overlay.wait_for(state='visible')
        page.keyboard.press('Escape')
        assert overlay.is_hidden()
        assert link.evaluate('(e) => document.activeElement === e')
        link.click()
        overlay.wait_for(state='visible')
        page.locator('#report-close').click()
        assert overlay.is_hidden()
        assert not errors, errors
        browser.close()
