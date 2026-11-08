"""Real HTTP + browser smoke tests against a disposable DFM server."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import urllib.parse

import pytest

from test_regression import prepare_baseline, setup

APP=Path(__file__).resolve().parents[1]
AUTH={}
METRICS_TOKEN='test-metrics-token-for-dfm-ci-9876543210'


def request(base, path, data=None):
    if path not in ('/api/startup','/health') and base not in AUTH:
        # CI uses a new disposable private database. No default app credentials.
        username='test-admin'
        password='a-very-long-test-password'
        setup_token='test-setup-token-for-dfm-ci-1234567890'
        req=urllib.request.Request(base+'/api/auth/setup',
            data=json.dumps({'setup_token':setup_token,'username':username,
                             'password':password}).encode(),
            headers={'Content-Type':'application/json'},method='POST')
        with urllib.request.urlopen(req,timeout=5) as res:
            cookie=res.headers['Set-Cookie'].split(';',1)[0]
            csrf=json.load(res)['csrf']
        AUTH[base]=(cookie,csrf)
    headers={'Content-Type':'application/json'}
    if base in AUTH:
        cookie,csrf=AUTH[base]
        headers.update({'Cookie':cookie,'X-DFM-CSRF':csrf})
    body=json.dumps(data).encode() if data is not None else None
    req=urllib.request.Request(base+path,data=body,headers=headers,
            method='POST' if data is not None else 'GET')
    try:
        with urllib.request.urlopen(req,timeout=5) as resp:
            return resp.status,json.load(resp)
    except urllib.error.HTTPError as exc:
        return exc.code,json.loads(exc.read())


@pytest.fixture
def running(setup):
    db,roots=setup
    prepare_baseline(db,roots)
    with socket.socket() as s:
        s.bind(('127.0.0.1',0));port=s.getsockname()[1]
    env=os.environ.copy()
    env.update(DB_PATH=db,SCAN_ROOTS=':'.join(roots),HTTP_PORT=str(port),SCAN_BANDWIDTH_MBPS='0',SCAN_FILE_WORKERS='2',REQUIRE_CIFS_MOUNTS='false',DFM_SETUP_TOKEN='test-setup-token-for-dfm-ci-1234567890',DFM_COOKIE_SECURE='false',DFM_METRICS_TOKEN=METRICS_TOKEN)
    proc=subprocess.Popen([sys.executable,'-u',str(APP/'app/main.py')],cwd=str(APP),env=env,
            stdout=subprocess.DEVNULL,stderr=subprocess.STDOUT)
    base='http://127.0.0.1:'+str(port)
    try:
        for _ in range(100):
            if proc.poll() is not None:raise RuntimeError('DFM exited unexpectedly')
            try:
                code,res=request(base,'/api/startup')
                if code==200 and res.get('ready'):break
            except Exception:pass
            time.sleep(0.05)
        else:raise AssertionError('HTTP startup failed')
        yield base,roots,db
    finally:
        proc.terminate()
        try:proc.wait(timeout=3)
        except subprocess.TimeoutExpired:proc.kill();proc.wait()


def wait_scan(base, n=1):
    for _ in range(250):
        _,s=request(base,'/api/status')
        if not s['scanning'] and s['status']!='running':return s
        time.sleep(0.03)
    raise AssertionError('Scan not done in 7.5 sec')


def test_authentication_and_csrf_block_unauthorized_api(running):
    base,roots,db=running
    def raw(path, method='GET', data=None, headers=None):
        req=urllib.request.Request(base+path,method=method,
            data=json.dumps(data or {}).encode() if method=='POST' else None,
            headers=headers or {})
        try:
            with urllib.request.urlopen(req,timeout=5) as response:
                return response.status,dict(response.headers)
        except urllib.error.HTTPError as exc:
            return exc.code,dict(exc.headers)
    assert raw('/api/status')[0]==401
    assert raw('/api/volumes')[0]==401
    assert raw('/api/history')[0]==401
    assert raw('/metrics')[0]==401
    assert raw('/api/scan',method='POST',headers={'Content-Type':'application/json'})[0]==401
    assert request(base,'/api/status')[0]==200
    cookie,csrf=AUTH[base]
    assert raw('/api/settings',method='POST',headers={
        'Cookie':cookie,'Content-Type':'application/json'})[0]==403
    assert raw('/api/settings',method='POST',headers={
        'Cookie':cookie,'Content-Type':'text/plain','X-DFM-CSRF':csrf})[0]==415
    assert raw('/api/settings',method='POST',headers={
        'Cookie':cookie,'Content-Type':'application/json',
        'X-DFM-CSRF':csrf,'Origin':'https://evil.example'})[0]==403
    assert request(base,'/api/settings')[0]==200
    assert raw('/metrics',headers={'Authorization':'Bearer '+METRICS_TOKEN})[0]==200
    assert raw('/metrics',headers={'Authorization':'Bearer incorrect'})[0]==401
    # Every new scan produced on the current version has an immutable report.
    c=request(base,'/api/history')[1][0]
    assert c['has_report']
    report=request(base,'/api/reports/'+str(c['id']))[1]
    assert report['scan_id']==c['id']
    assert report['totals']['file_count']==9

def test_public_svg_favicon_before_login(running):
    base, _, _ = running
    import urllib.request
    with urllib.request.urlopen(base + '/favicon.svg', timeout=5) as response:
        assert response.status == 200
        assert response.headers['Content-Type'].startswith('image/svg+xml')
        assert b'<svg' in response.read()
    with urllib.request.urlopen(base + '/favicon.ico', timeout=5) as response:
        assert response.status == 200
        assert response.geturl().endswith('/favicon.svg')


def test_http_startup_readonly_status_and_schedules(running):
    base,roots,db=running
    assert request(base,'/api/startup')[1]['version']=='0.6.6'
    status=request(base,'/api/status')[1]
    assert status['files']==9 and status['duplicates']==3
    assert status['quick_available']
    assert status['per_volume_enabled']==False
    assert request(base,'/api/schedules')[1]['schedules']==[]
    assert request(base,'/api/settings')[1]['per_volume_enabled']==False
    assert request(base,'/api/volumes')[1][0]['file_count']==4
    assert request(base,'/api/diagnostics')[0]==200


def test_http_volume_selection_backcompat_validation_and_history(running):
    base,roots,db=running
    code,b=request(base,'/api/scan/quick',{'roots':[roots[0],roots[1]]})
    assert code==400 and 'per-volume' in b['error']
    assert request(base,'/api/volume-mode',{'enabled':True})[0]==200
    for invalid in ([], [roots[0],roots[0]], ['/fake'],[roots[0],'/fake'],'bad'):
        assert request(base,'/api/scan/quick',{'roots':invalid})[0]==400
    assert request(base,'/api/scan/quick',{'roots':[roots[0],roots[1]]})[0]==202
    result=wait_scan(base)
    assert result['status']=='success' and result['files']==9 # published global inventory
    h=request(base,'/api/history')[1]
    assert h[0]['files']==7 and h[0]['duplicates']==2 and h[0]['scope']==roots[:2]
    assert h[1]['status']=='success' and h[1]['scope']==roots
    assert request(base,'/api/history?root='+urllib.parse.quote(roots[2],safe=''))[1][0]['id']==h[1]['id']
    assert len(request(base,'/api/history?root='+urllib.parse.quote(roots[2],safe=''))[1])==1
    assert request(base,'/api/history?root=not-real')[0]==400
    # Legacy single root behavior remains fully supported.
    assert request(base,'/api/scan/quick',{'root':roots[1]})[0]==202
    done=wait_scan(base)
    assert done['status']=='success'
    scoped=request(base,'/api/history')[1][0]
    assert scoped['files']==3 and scoped['duplicates']==1
    assert request(base,'/api/scan/quick',{'root':'all'})[0]==202
    assert wait_scan(base)['status']=='success'
    allscan=request(base,'/api/history')[1][0]
    assert allscan['files']==9 and allscan['duplicates']==3


def test_browser_scope_scheduler_history_clock():
    pytest.importorskip('playwright.sync_api')
    from playwright.sync_api import sync_playwright
    # Browser policy blocks localhost navigation, so test the real HTML file
    # using synthetic server snapshots. API itself is tested over real HTTP.
    with sync_playwright() as pw:
        browser=pw.chromium.launch(executable_path='/usr/bin/chromium',headless=True,
                                   args=['--no-sandbox','--disable-dev-shm-usage'])
        page=browser.new_page()
        errors=[]
        page.on('pageerror',lambda err:errors.append(str(err)))
        page.set_content((APP/'app/index.html').read_text(),wait_until='domcontentloaded')
        roots=['/scan/vol0','/scan/vol1','/scan/vol2']
        page.evaluate('''(roots)=>{
          document.body.classList.remove('starting');
          const s={scanning:false,quick_baseline_roots:roots,quick_available:true,
            status:'success',files:9,duplicates:3,wasted:24576,lifetime:0,
            last_scan_progress:{scan_scope:roots,metric_scope:'scan',metrics_ready:true,
              confirmed_duplicate_copies:3,confirmed_wasted_bytes:24576},
            published_scan_id:1,mode:'full',started:100,ended:101};
          redrawScope(roots.map(root=>({root,archived:false})),true);
          progressRender(s);
        }''', roots)
        assert page.locator('#scope-caption').inner_text()=='All volumes'
        page.locator('#scope-picker').evaluate('(e)=>e.open=true')
        boxes=page.locator('#scope-checks input[data-root]')
        assert boxes.count()==3
        boxes.nth(2).uncheck()
        assert page.locator('#scope-caption').inner_text()=='2 volumes selected'
        assert not page.locator('#scan-quick').is_disabled()
        boxes.nth(1).uncheck()
        assert page.locator('#scope-caption').inner_text()=='vol0'
        boxes.nth(0).uncheck()
        assert page.locator('#scan-quick').is_disabled()
        page.locator('#scope-checks input[data-all]').check()
        assert page.locator('#scope-caption').inner_text()=='All volumes'
        assert not page.locator('#scan-quick').is_disabled()
        # While open, selecting multiple checkboxes does not close the picker.
        picker=page.locator('#scope-picker')
        picker.evaluate('(e)=>e.open=true')
        boxes.nth(2).uncheck()
        assert picker.evaluate('(e)=>e.open')
        boxes.nth(2).check()
        assert picker.evaluate('(e)=>e.open')
        # Clicking elsewhere dismisses without affecting the selection.
        page.locator('#stage-name').click()
        assert not picker.evaluate('(e)=>e.open')
        assert page.locator('#scope-caption').inner_text()=='All volumes'
        # Clicking the summary still toggles the native details control.
        page.locator('#scope-caption').click()
        assert picker.evaluate('(e)=>e.open')
        page.locator('#scope-caption').click()
        assert not picker.evaluate('(e)=>e.open')
        # Escape dismisses and restores focus to the selector.
        page.locator('#scope-caption').click()
        assert picker.evaluate('(e)=>e.open')
        page.keyboard.press('Escape')
        assert not picker.evaluate('(e)=>e.open')
        assert page.locator('#scope-caption').evaluate('(e)=>e===document.activeElement')
        # When user presses a scan action, outside pointerdown dismisses first.
        page.locator('#scope-caption').click()
        assert picker.evaluate('(e)=>e.open')
        page.locator('#scan').dispatch_event('pointerdown')
        assert not picker.evaluate('(e)=>e.open')
        # The clock is hidden during Finalizing but restored on Finished.
        page.evaluate('''()=>progressRender({scanning:true,status:'running',
           progress:{scan_id:2,stage:'finalizing',lifecycle:'finalizing',
           finalizing_step:'Committing',can_stop:false,started_at:100,
           duration_cutoff_at:112,scan_scope:['/scan/vol0'],metrics_ready:true,
           metric_scope:'scan',confirmed_duplicate_copies:1,confirmed_wasted_bytes:8192}})''')
        assert page.locator('#scan-time').is_hidden()
        page.evaluate('''()=>progressRender({scanning:false,status:'success',started:100,ended:112,
           files:4,lifetime:0,progress:null,
           last_scan_progress:{scan_scope:['/scan/vol0'],metrics_ready:true,metric_scope:'scan',
           confirmed_duplicate_copies:1,confirmed_wasted_bytes:8192,files_discovered:4}})''')
        assert page.locator('#scan-time').is_visible()
        assert '00:00:12' in page.locator('#scan-time').inner_text()
        page.locator('#tab-settings').click()
        page.locator('#schedule-add').click()
        assert page.locator('.schedule-card').first.is_visible()
        assert not errors,errors
        browser.close()

@pytest.mark.parametrize('frequency,fields',[
    ('5m',['Timezone']),('10m',['Timezone']),('15m',['Timezone']),('30m',['Timezone']),('60m',['Timezone']),
    ('hourly',['Minute past the hour','Timezone']),
    ('daily',['Time','Timezone']),
    ('weekly',['Time','Timezone','Day of week']),
    ('monthly',['Time','Timezone','Day of month']),
    ('custom',['Cron expression','Timezone'])])
def test_browser_schedule_fields_conditional(frequency,fields):
    pytest.importorskip('playwright.sync_api')
    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        browser=pw.chromium.launch(executable_path='/usr/bin/chromium',headless=True,
                                   args=['--no-sandbox','--disable-dev-shm-usage'])
        page=browser.new_page()
        page.set_content((APP/'app/index.html').read_text())
        page.evaluate("""()=>{document.body.classList.remove('starting');
          showTab('settings');scheduleDrafts=[];schedulesLoaded=true;
          document.getElementById('schedule-add').click()}""")
        card=page.locator('.schedule-card').first
        card.get_by_label('Repeat').select_option(frequency)
        visibility=page.evaluate("""()=>Object.fromEntries(
          ['Time','Minute past the hour','Day of week','Day of month','Timezone','Cron expression'].map(name=>{
          const label=[...document.querySelectorAll('.schedule-card label.settings-field')]
             .find(e=>e.firstChild?.textContent===name);
          return [name,!!label&&!label.hidden&&!label.closest('.schedule-timing')?.hidden];
          }))""")
        assert [k for k,v in visibility.items() if v]==[k for k in visibility if k in fields]
        assert not card.get_by_text('If a run was missed while DFM was offline').is_visible()
        browser.close()


def test_v043_stable_header_and_shared_schedule_day_slot():
    pytest.importorskip('playwright.sync_api')
    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        browser=pw.chromium.launch(executable_path='/usr/bin/chromium',headless=True,
                                   args=['--no-sandbox','--disable-dev-shm-usage'])
        page=browser.new_page(viewport={'width':1440,'height':1000})
        page.set_content((APP/'app/index.html').read_text(),wait_until='domcontentloaded')
        page.evaluate('''()=>{
          document.body.classList.remove('starting');
          document.getElementById('settings-page').hidden=false;
          const roots=['/scan/one','/scan/two','/scan/three'];
          redrawScope(roots.map(root=>({root,archived:false})),true);
          scheduleItem({mode:'quick',root:'all',frequency:'weekly',at:'02:00',
            weekday:1,month_day:7,timezone:'America/Chicago',cron:'0 2 * * *',enabled:false,
            on_missed:'skip',on_conflict:'skip'});
        }''')
        weekly=page.locator('.schedule-card .timing-day-slot:not([hidden])').bounding_box()
        timezone=page.locator('.schedule-card .timing-zone-slot').bounding_box()
        assert weekly and timezone
        page.locator('.schedule-card select').filter(has=page.locator('option[value="monthly"]')) if False else None
        page.locator('.schedule-card select').evaluate_all('''items=>{
          const frequency=items.find(e=>Array.from(e.options).some(o=>o.value==='monthly'));
          frequency.value='monthly';frequency.dispatchEvent(new Event('change'));
        }''')
        monthly=page.locator('.schedule-card .timing-day-slot:not([hidden])').bounding_box()
        timezone2=page.locator('.schedule-card .timing-zone-slot').bounding_box()
        assert monthly and abs(weekly['x']-monthly['x']) < 1
        assert abs(timezone['x']-timezone2['x']) < 1
        buttons=page.locator('#scan').bounding_box()
        page.locator('#pause').evaluate('(e)=>e.hidden=false')
        page.locator('#resume').evaluate('(e)=>e.hidden=true')
        assert abs(buttons['x']-page.locator('#scan').bounding_box()['x']) < 1
        browser.close()

def test_v0431_dashboard_order_and_live_count_consistency():
    pytest.importorskip('playwright.sync_api')
    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        browser=pw.chromium.launch(executable_path='/usr/bin/chromium',headless=True,
                                   args=['--no-sandbox','--disable-dev-shm-usage'])
        page=browser.new_page()
        page.set_content((APP/'app/index.html').read_text(),wait_until='domcontentloaded')
        assert page.evaluate('''()=>{
          const a=document.querySelector('[aria-label="Scan progress"]');
          const b=document.getElementById('volume-summary-panel');
          const c=document.getElementById('history').closest('section.panel');
          return !!(a.compareDocumentPosition(b)&Node.DOCUMENT_POSITION_FOLLOWING)
            && !!(b.compareDocumentPosition(c)&Node.DOCUMENT_POSITION_FOLLOWING);
        }''')
        # Replicate the production mismatch. Never aggregate stale volume counts.
        total=page.evaluate('''()=>discoveredForSnapshot({scan_scope:['fht','files'],
           per_volume_discovered:{fht:15483,files:22831},files_discovered:68127})''')
        assert total==68127
        page.evaluate('''()=>showDiscovered({scan_scope:['fht','files'],
           per_volume_discovered:{fht:15483,files:22831},files_discovered:68127})''')
        assert page.locator('#live-files-discovered').inner_text()=='68,127'
        assert page.locator('#volume-progress').is_hidden()
        browser.close()


def test_monitoring_api_mqtt_settings_and_prometheus(running):
    base,roots,db=running
    status,mon=request(base,'/api/monitoring')
    assert status==200 and mon['files']==9 and mon['duplicates']==3
    assert mon['last_scan_changes']['removed']==0
    assert mon['last_scan_scope']==roots
    assert len(mon['volumes'])==3
    assert request(base,'/api/mqtt-settings')[1]['enabled'] is False
    assert request(base,'/api/mqtt-settings',{'settings':{'enabled':True,'host':''}})[0]==400
    assert request(base,'/api/mqtt-settings',{'settings':{'host':'mqtt.lan','username':'dfm','password':'test-private'}})[0]==200
    safe=request(base,'/api/mqtt-settings')[1]
    assert safe['password']=='' and safe['password_configured'] and safe['host']=='mqtt.lan'
    assert request(base,'/api/mqtt-settings',{'settings':{'port':1884,'password':''}})[0]==200
    assert request(base,'/api/mqtt-settings')[1]['port']==1884
    from scanner import connect,read_meta
    c=connect(db,readonly=True)
    try: assert json.loads(read_meta(c,'mqtt_settings_json'))['password']=='test-private'
    finally:c.close()
    with urllib.request.urlopen(urllib.request.Request(base+'/metrics',headers={'Authorization':'Bearer '+METRICS_TOKEN}),timeout=5) as response:
        payload=response.read().decode()
        assert 'dfm_duplicate_copies 3\n' in payload
        assert 'dfm_last_scan_removed 0\n' in payload


def test_historical_trends_removed_from_dashboard():
    source = (APP / 'app' / 'index.html').read_text()
    assert 'Historical trends' not in source
    assert 'loadTrends' not in source
    assert '/api/trends' not in source
    assert 'Scan history' in source
