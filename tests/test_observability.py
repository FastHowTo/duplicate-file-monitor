import os
import sys
import json
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from scanner import connect,scan
from observability import monitoring_snapshot,prometheus,validate_config,DEFAULTS,get_config,publish_mqtt


def test_monitoring_snapshot_and_metrics(tmp_path):
    root=tmp_path/'a';root.mkdir()
    (root/'copy1').write_bytes(b'A'*8192)
    (root/'copy2').write_bytes(b'A'*8192)
    db=tmp_path/'data.db'
    scan(str(db),[str(root)])
    c=connect(str(db),readonly=True)
    try:
        vols=[{'root':str(root),'volume_id':'vol-a','status':'Active','archived':False,'file_count':2,
               'duplicate_copies':1,'wasted_bytes':8192,'added':0,'removed':0,'last_scanned_at':123}]
        snap=monitoring_snapshot(c,{'scanning':False,'progress':None},vols)
        assert snap['files']==2 and snap['duplicates']==1 and snap['wasted_bytes']==8192
        assert snap['last_scan_mode']=='full' and snap['last_scan_scope']==[str(root)]
        assert snap['last_scan_changes']['added']==0
        metrics=prometheus(snap)
        assert 'dfm_duplicate_copies 1\n' in metrics
        assert 'dfm_last_scan_removed 0\n' in metrics
        assert 'dfm_lifetime_saved_bytes 0\n' in metrics
        assert 'dfm_volume_files{volume_id="vol-a"} 2' in metrics
    finally:c.close()


def test_mqtt_password_redaction_and_validation(tmp_path):
    db=tmp_path/'empty.db';c=connect(str(db))
    try:
        from scanner import write_meta
        with c: write_meta(c,'mqtt_settings_json',json.dumps({**DEFAULTS,'password':'my secret'}))
        safe=get_config(c)
        assert safe['password']=='' and safe['password_configured']
        assert get_config(c,True)['password']=='my secret'
    finally:c.close()
    assert validate_config({'enabled':False},DEFAULTS)['enabled'] is False
    import pytest
    with pytest.raises(ValueError):validate_config({'enabled':True,'host':''},DEFAULTS)
    with pytest.raises(ValueError):validate_config({'base_topic':'bad/#'},DEFAULTS)


class FakeClient:
    def __init__(self):self.messages=[]
    def publish(self,topic,payload,qos,retain):
        self.messages.append((topic,json.loads(payload) if payload.startswith('{') else payload,retain))
        return type('Info',(),{'rc':0})()


def test_mqtt_global_and_volume_discovery():
    cli=FakeClient()
    snap={'files':12,'duplicates':3,'wasted_bytes':44,'total_file_size_bytes':55,'lifetime_saved_bytes':66,
          'volume_count':1,'scan_active':False,'scan_status':'idle','last_scan_duration_seconds':20,
          'last_successful_scan':123,'last_scan_changes':{'added':2,'removed':1,'modified':0,'possible_moves':0},'last_scan_net_change':1,'last_scan_result':'success','last_scan_error':'',
          'volumes':[{'root':'/scan/fht','volume_id':'fht123','file_count':12,'duplicate_copies':3,'wasted_bytes':44,'added':2,'removed':1}]}
    cfg={**DEFAULTS,'discovery':True}
    publish_mqtt(cli,cfg,snap)
    topics=[item[0] for item in cli.messages]
    assert 'dfm/state' in topics
    assert 'homeassistant/sensor/dfm_last_scan_removed/config' in topics
    assert 'homeassistant/sensor/dfm_fht123_file_count/config' in topics
    assert all(retain for _,_,retain in cli.messages)


def test_mqtt_data_size_units_are_user_selectable():
    cli=FakeClient()
    snap={'files':2,'duplicates':1,'wasted_bytes':1024,'total_file_size_bytes':2048,
          'lifetime_saved_bytes':512,'volume_count':1,'scan_status':'idle',
          'last_scan_result':'success','last_scan_error':'','last_scan_net_change':0,
          'last_scan_duration_seconds':1,'last_successful_scan':1,
          'last_scan_changes':{'added':0,'removed':0,'modified':0,'possible_moves':0},
          'volumes':[{'root':'/scan/fht','volume_id':'v123','file_count':2,
                      'duplicate_copies':1,'wasted_bytes':1024,'added':0,
                      'removed':0,'modified':0,'possible_moves':0}]}
    publish_mqtt(cli,{**DEFAULTS,'discovery':True},snap)
    payloads={topic:body for topic,body,_ in cli.messages}
    for name in ('wasted_bytes','total_file_size_bytes','lifetime_saved_bytes'):
        cfg=payloads[f'homeassistant/sensor/dfm_{name}/config']
        assert cfg['unit_of_measurement']=='GiB'
        assert cfg['device_class']=='data_size'
        assert cfg['state_class']=='measurement'
        assert '/ 1073741824' in cfg['value_template']
    cfg=payloads['homeassistant/sensor/dfm_v123_wasted_bytes/config']
    assert cfg['unit_of_measurement']=='GiB'
    assert cfg['device_class']=='data_size'
    assert '/ 1073741824' in cfg['value_template']
    assert payloads['dfm/state']['wasted_bytes']==1024


def test_last_scan_result_persists_during_active_scan(tmp_path):
    from scanner import write_meta
    root=tmp_path/'volume';root.mkdir()
    (root/'a.txt').write_text('test')
    db=tmp_path/'db.sqlite'
    scan(str(db),[str(root)])
    c=connect(str(db))
    try:
        with c:
            c.execute("INSERT INTO scans(started,mode,status) VALUES(1234567,'quick','running')")
        vol=[{'root':str(root),'volume_id':'a','archived':False}]
        snap=monitoring_snapshot(c,{'scanning':True,'progress':{'stage':'enumerating'}},vol)
        assert snap['last_scan_result']=='success'
        assert snap['scan_status']=='scanning'
        assert snap['last_full_scan'] is not None
        assert snap['last_quick_scan'] is None
        assert vol[0]['last_full_scan']==snap['last_full_scan']
        assert vol[0]['last_quick_scan'] is None
        with c:
            c.execute("UPDATE scans SET status='failed',error='Network error',ended=1234568 WHERE started=1234567")
        snap=monitoring_snapshot(c,{'scanning':False,'progress':None},vol)
        assert snap['last_scan_result']=='failed'
        assert snap['last_scan_error']=='Network error'
        assert snap['scan_status']=='idle'
    finally:c.close()


def test_mqtt_timestamps_and_retain():
    cli=FakeClient()
    snap={'last_full_scan':'2026-11-01T12:00:00Z','last_quick_scan':'2026-11-01T13:00:00Z',
          'volumes':[{'root':'/scan/fht','volume_id':'v123','last_full_scan':'2026-11-01T12:00:00Z','last_quick_scan':None}]}
    publish_mqtt(cli,{**DEFAULTS,'discovery':True},snap)
    cfg={topic:payload for topic,payload,_ in cli.messages}
    assert cfg['homeassistant/sensor/dfm_last_full_scan/config']['device_class']=='timestamp'
    assert cfg['homeassistant/sensor/dfm_v123_last_full_scan/config']['device_class']=='timestamp'
    assert cfg['homeassistant/sensor/dfm_wasted_bytes/config']['suggested_display_precision']==1
    assert all(retained for _,_,retained in cli.messages)


def test_v052_volume_logical_bytes_and_precision():
    cli=FakeClient()
    snap={'files':4,'duplicates':2,'wasted_bytes':60,'total_file_size_bytes':100,
        'lifetime_saved_bytes':0,'volume_count':1,'scan_status':'idle',
        'last_scan_result':'success','last_scan_error':'',
        'last_scan_changes':{'added':0,'removed':0,'modified':0,'possible_moves':0},
        'last_scan_net_change':0,'last_scan_duplicate_change':None,
        'last_scan_wasted_change_bytes':None,
        'volumes':[{'root':'/scan/a','volume_id':'a','file_count':4,'total_file_size_bytes':100,
                    'duplicate_copies':2,'wasted_bytes':60}]}
    publish_mqtt(cli,{**DEFAULTS,'discovery':True},snap)
    configs={topic:body for topic,body,_ in cli.messages}
    cfg=configs['homeassistant/sensor/dfm_a_total_file_size_bytes/config']
    assert cfg['device_class']=='data_size'
    assert cfg['unit_of_measurement']=='GiB'
    assert '/ 1073741824' in cfg['value_template']
    assert cfg['suggested_display_precision']==1
    assert configs['dfm/state']['volumes'][0]['total_file_size_bytes']==100
    for topic,config in configs.items():
        if topic.endswith('/config') and config.get('name') not in ('Scan Status','Last Scan Result','Last Scan Error','Last Full Scan','Last Quick Scan'):
            if 'value_template' in config:
                assert config['suggested_display_precision']==1,topic
    assert all(r for _,_,r in cli.messages)


def test_v052_global_deltas_not_inferred_for_scoped_scan(tmp_path):
    root=tmp_path/'a';root.mkdir()
    (root/'one').write_text('same')
    (root/'two').write_text('same')
    db=tmp_path/'db.sqlite'
    scan(str(db),[str(root)])
    c=connect(str(db))
    try:
        vols=[{'root':str(root),'volume_id':'a','archived':False,'file_count':2,
               'total_file_size_bytes':8,'duplicate_copies':1,'wasted_bytes':4}]
        snap=monitoring_snapshot(c,{'scanning':False},vols)
        assert snap['last_scan_duplicate_change'] is None
        assert snap['last_scan_wasted_change_bytes'] is None
    finally:c.close()


def test_v0521_native_gib_templates_render_correctly():
    from jinja2 import Environment
    cli=FakeClient()
    snap={'wasted_bytes':2*1073741824,'total_file_size_bytes':3*1073741824,
          'lifetime_saved_bytes':1073741824,'last_scan_wasted_change_bytes':None,
          'volumes':[{'root':'/scan/a','volume_id':'v-one','wasted_bytes':1073741824,
                      'total_file_size_bytes':4*1073741824}]}
    publish_mqtt(cli,{**DEFAULTS,'discovery':True},snap)
    configs={topic:body for topic,body,_ in cli.messages}
    renderer=Environment()
    for entity,expected in [('dfm_wasted_bytes','2.0'),('dfm_total_file_size_bytes','3.0'),
                            ('dfm_lifetime_saved_bytes','1.0'),('dfm_v-one_wasted_bytes','1.0'),
                            ('dfm_v-one_total_file_size_bytes','4.0')]:
        cfg=configs[f'homeassistant/sensor/{entity}/config']
        assert cfg['unit_of_measurement']=='GiB'
        assert cfg['suggested_display_precision']==1
        assert renderer.from_string(cfg['value_template']).render(value_json=snap)==expected
    delta=configs['homeassistant/sensor/dfm_last_scan_wasted_change_bytes/config']
    assert renderer.from_string(delta['value_template']).render(value_json=snap)=='None'
    assert configs['dfm/state']['wasted_bytes']==2*1073741824


def test_scoped_scan_does_not_replace_global_last_change_counters(tmp_path):
    root_a=tmp_path/'a';root_b=tmp_path/'b'
    root_a.mkdir();root_b.mkdir()
    (root_a/'file').write_bytes(b'data')
    (root_b/'file').write_bytes(b'data')
    db=str(tmp_path/'inventory.db')
    scan(db,[str(root_a),str(root_b)])
    c=connect(db)
    try:
        with c:
            row=c.execute("SELECT id FROM scans WHERE status='success' ORDER BY id DESC LIMIT 1").fetchone()
            c.execute('UPDATE scans SET changes_json=? WHERE id=?', (json.dumps({'added':7,'removed':2,'modified':1,'possible_moves':3}),row[0]))
    finally:c.close()
    # A successful scoped Quick Scan must not replace the global counters.
    scan(db,[str(root_a)], mode='quick', preserved_roots=[str(root_b)])
    c=connect(db,readonly=True)
    try:
        vols=[{'root':str(root_a),'volume_id':'a','archived':False},
              {'root':str(root_b),'volume_id':'b','archived':False}]
        result=monitoring_snapshot(c,{'scanning':False},vols)
        assert result['last_scan_changes']=={'added':7,'removed':2,'modified':1,'possible_moves':3}
        assert result['last_scan_net_change']==5
    finally:c.close()
