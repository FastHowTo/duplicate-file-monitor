"""DFM monitoring: read-only snapshots and opt-in MQTT discovery.

No source mounts are opened here. Retained values describe the last committed
inventory; scan-change counts are scoped to the latest successful scan.
"""
import json
import os
import re
import threading
import time
from datetime import datetime, timezone
from urllib.parse import quote


def monitoring_snapshot(connection, current_status, volumes):
    from scanner import current_metrics, read_meta
    c = connection
    total = c.execute('SELECT COUNT(*),COALESCE(SUM(size),0) FROM files').fetchone()
    dupes, wasted = current_metrics(c)
    r = c.execute("SELECT id,started,ended,mode,status,changes_json,progress_json,duplicates,wasted FROM scans WHERE status='success' ORDER BY id DESC LIMIT 1").fetchone()
    latest = dict(r) if r else None
    changes = json.loads(latest['changes_json'] or '{}') if latest else {}
    progress = json.loads(latest['progress_json'] or '{}') if latest else {}
    scan_roots = progress.get('scan_scope', [])
    if not isinstance(scan_roots,list): scan_roots=[]
    last = c.execute("SELECT status,error,mode,started,ended FROM scans WHERE status NOT IN ('running') ORDER BY id DESC LIMIT 1").fetchone()
    last = dict(last) if last else {}
    def iso(epoch):
        return datetime.fromtimestamp(epoch, timezone.utc).isoformat().replace('+00:00', 'Z') if epoch is not None else None
    scan_times = {}
    for mode in ('full','quick'):
        completed = c.execute("SELECT MAX(ended) FROM scans WHERE mode=? AND status='success'",(mode,)).fetchone()[0]
        scan_times[mode] = iso(completed)
    # Only completed all-volume scans may update global change counters.
    # Scoped scans still refresh aggregate inventory, live status and only the
    # selected volumes' last-scan values.
    active_roots = {v['root'] for v in volumes if not v.get('archived')}
    def global_scope(row):
        try:
            roots = json.loads(row['progress_json'] or '{}').get('scan_scope') or []
            return bool(active_roots) and set(roots) == active_roots
        except (ValueError, TypeError, KeyError):
            return False
    global_scans = []
    for row in c.execute("SELECT id,duplicates,wasted,changes_json,progress_json FROM scans WHERE status='success' ORDER BY id DESC"):
        if global_scope(row):
            global_scans.append(row)
            if len(global_scans) == 2: break
    global_latest = global_scans[0] if global_scans else None
    global_previous = global_scans[1] if len(global_scans) > 1 else None
    global_changes = json.loads(global_latest['changes_json'] or '{}') if global_latest else {}
    # A different active volume roster is not a comparable population.
    comparable = bool(global_previous and global_latest and
        set(json.loads(global_previous['progress_json'] or '{}').get('scan_scope') or []) ==
        set(json.loads(global_latest['progress_json'] or '{}').get('scan_scope') or []))
    changes_in_duplicates = (int(global_latest['duplicates'] - global_previous['duplicates'])
        if comparable and global_latest['duplicates'] is not None and global_previous['duplicates'] is not None else None)
    changes_in_wasted = (int(global_latest['wasted'] - global_previous['wasted'])
        if comparable and global_latest['wasted'] is not None and global_previous['wasted'] is not None else None)
    last_per_volume = {}
    for row in c.execute("SELECT vs.root,s.mode,MAX(s.ended) ended FROM volume_scans vs JOIN scans s ON s.id=vs.scan_id WHERE s.status='success' GROUP BY vs.root,s.mode"):
        last_per_volume.setdefault(row['root'],{})[row['mode']] = iso(row['ended'])
    for volume in volumes:
        stamps=last_per_volume.get(volume['root'],{})
        volume['last_full_scan']=stamps.get('full')
        volume['last_quick_scan']=stamps.get('quick')
    return {
        'last_full_scan':scan_times['full'], 'last_quick_scan':scan_times['quick'],
        'last_scan_result': last.get('status') or 'not_scanned',
        'last_scan_duplicate_change': changes_in_duplicates,
        'last_scan_wasted_change_bytes': changes_in_wasted,
        'last_scan_error': last.get('error') or '',
        'timestamp': time.time(), 'files':int(total[0]), 'total_file_size_bytes':int(total[1]),
        'duplicates':int(dupes), 'wasted_bytes':int(wasted),
        'lifetime_saved_bytes':int(read_meta(c,'lifetime','0')),
        'volume_count':sum(not v['archived'] for v in volumes),
        'scan_active':bool(current_status.get('scanning')),
        'scan_status': ('paused' if (current_status.get('progress') or {}).get('paused') else 'scanning') if current_status.get('scanning') else 'idle',
        'scan_stage': (current_status.get('progress') or {}).get('stage'),
        'files_discovered': (current_status.get('progress') or {}).get('files_discovered') if current_status.get('scanning') else None,
        'last_successful_scan':latest['ended'] if latest else None,
        'last_scan_mode':latest['mode'] if latest else None,
        'last_scan_scope':scan_roots,
        'last_scan_duration_seconds': max(0,latest['ended']-latest['started']) if latest and latest['ended'] else None,
        'last_scan_changes':{k:int(global_changes.get(k) or 0) for k in ('added','removed','modified','possible_moves')},
        'last_scan_net_change':int(global_changes.get('added') or 0)-int(global_changes.get('removed') or 0),
        'volumes':[{k:v.get(k) for k in ('root','volume_id','status','archived','file_count','duplicate_copies','wasted_bytes','total_file_size_bytes','added','removed','modified','possible_moves','last_scanned_at','last_full_scan','last_quick_scan')} for v in volumes]
    }


def prometheus(snapshot):
    """Minimal Prometheus text exporter; paths deliberately not included as labels."""
    metrics = {'dfm_files':snapshot['files'], 'dfm_file_size_bytes':snapshot['total_file_size_bytes'],
               'dfm_duplicate_copies':snapshot['duplicates'], 'dfm_wasted_bytes':snapshot['wasted_bytes'],
               'dfm_lifetime_saved_bytes':snapshot['lifetime_saved_bytes'],
               'dfm_volumes':snapshot['volume_count'],
               'dfm_scan_active':int(snapshot['scan_active']), 'dfm_last_scan_net_change':snapshot['last_scan_net_change']}
    for field, metric in (('last_scan_duplicate_change','dfm_last_scan_duplicate_change'),('last_scan_wasted_change_bytes','dfm_last_scan_wasted_change_bytes')):
        if snapshot.get(field) is not None: metrics[metric]=snapshot[field]
    for key, val in snapshot['last_scan_changes'].items(): metrics['dfm_last_scan_'+key]=val
    if snapshot['last_successful_scan'] is not None:
        metrics['dfm_last_success_timestamp_seconds']=snapshot['last_successful_scan']
    if snapshot['last_scan_duration_seconds'] is not None:
        metrics['dfm_last_scan_duration_seconds']=snapshot['last_scan_duration_seconds']
    output=''.join('# TYPE '+k+' gauge\n'+k+' '+str(v)+'\n' for k,v in metrics.items())
    # Stable volume IDs, not root paths: avoid exposing NAS paths in Prometheus labels.
    for v in snapshot['volumes']:
        identifier=re.sub(r'[^A-Za-z0-9_-]','_',str(v.get('volume_id') or 'unidentified'))
        for field,metric in (('file_count','files'),('duplicate_copies','duplicate_copies'),
                             ('wasted_bytes','wasted_bytes'),('total_file_size_bytes','file_size_bytes'),('added','last_scan_added'),
                             ('removed','last_scan_removed'),('modified','last_scan_modified')):
            value=v.get(field)
            if value is not None:
                output+=f'dfm_volume_{metric}{{volume_id="{identifier}"}} {int(value)}\n'
    return output


CONFIG_KEYS=('host','port','username','password','tls','discovery','enabled','base_topic','discovery_prefix')
DEFAULTS={'host':'','port':1883,'username':'','password':'','tls':False,'discovery':True,
          'enabled':False,'base_topic':'dfm','discovery_prefix':'homeassistant'}


def get_config(c, include_password=False):
    from scanner import read_meta
    try: result={**DEFAULTS,**json.loads(read_meta(c,'mqtt_settings_json','{}'))}
    except (ValueError,TypeError): result=dict(DEFAULTS)
    result={k:result.get(k,v) for k,v in DEFAULTS.items()}
    if not include_password: result['password']=''; result['password_configured']=bool(get_config(c,True).get('password'))
    return result


def validate_config(raw, old):
    if not isinstance(raw,dict): raise ValueError('Expected MQTT settings object')
    out={**old}
    for k in CONFIG_KEYS:
        if k in raw: out[k]=raw[k]
    for k in ('enabled','tls','discovery'):
        if not isinstance(out[k],bool): raise ValueError(k+' must be boolean')
    if not isinstance(out['port'],int) or not 1<=out['port']<=65535: raise ValueError('Invalid MQTT port')
    for k in ('host','username','password','base_topic','discovery_prefix'):
        if not isinstance(out[k],str) or len(out[k])>255: raise ValueError('Invalid '+k)
    if out['enabled'] and not out['host'].strip(): raise ValueError('MQTT host required when enabled')
    if not re.fullmatch(r'[A-Za-z0-9_/-]+',out['base_topic']) or not re.fullmatch(r'[A-Za-z0-9_/-]+',out['discovery_prefix']):
        raise ValueError('MQTT topics contain invalid characters')
    return out


def _publish(client, topic, payload, retain=True):
    info=client.publish(topic, payload if isinstance(payload,str) else json.dumps(payload,separators=(',',':')),qos=1,retain=retain)
    if info.rc != 0: raise RuntimeError('MQTT publish failed: '+str(info.rc))


def publish_mqtt(client, settings, snapshot):
    base=settings['base_topic'].strip('/')
    _publish(client,base+'/state',snapshot)
    if not settings['discovery']: return
    prefix=settings['discovery_prefix'].strip('/')
    device={'identifiers':['dfm_global'],'name':'Duplicate File Monitor','manufacturer':'DFM','model':'Duplicate File Monitor'}
    fields={
        'files':('Total Files',None,None), 'duplicates':('Duplicate Files',None,None),
        'wasted_bytes':('Wasted Space','B','data_size'),
        'total_file_size_bytes':('Total File Size','B','data_size'),
        'lifetime_saved_bytes':('Estimated Lifetime Space Saved','B','data_size'),
        'volume_count':('Monitored Volumes',None,None),
        'last_scan_duplicate_change':('Last Scan Duplicate Change',None,None),
        'last_scan_wasted_change_bytes':('Last Scan Wasted Space Change','B','data_size'),
        'scan_status':('Scan Status',None,None),
        'last_scan_result':('Last Scan Result',None,None),
        'last_scan_error':('Last Scan Error',None,None),
        'last_scan_net_change':('Last Scan Net File Change',None,None),
        'last_scan_duration_seconds':('Last Scan Duration','s','duration'),
        'last_successful_scan':('Last Successful Scan',None,None),
        'last_full_scan':('Last Full Scan',None,'timestamp'),
        'last_quick_scan':('Last Quick Scan',None,'timestamp'),
    }
    for key,(name,unit,device_class) in fields.items():
        config={'name':name,'unique_id':'dfm_'+key,'state_topic':base+'/state',
                'value_template':'{{ value_json.'+key+' }}','device':device,
                'availability_topic':base+'/availability','payload_available':'online','payload_not_available':'offline'}
        if unit: config['unit_of_measurement']=unit
        if key in ('files','duplicates','volume_count','last_scan_net_change','last_scan_duplicate_change','last_scan_duration_seconds'): config['suggested_display_precision']=1
        if device_class: config['device_class']=device_class
        if device_class=='data_size':
            config['state_class']='measurement'
            config['suggested_display_precision']=1
            config['unit_of_measurement']='GiB'
            config['value_template']='{{ ((value_json.'+key+' | float) / 1073741824) | round(6) if value_json.'+key+' is not none else none }}'
        if key=='last_scan_duplicate_change':
            config['value_template']='{{ value_json.'+key+' if value_json.'+key+' is not none else none }}'
        if device_class=='timestamp':
            config['value_template']='{{ value_json.'+key+' if value_json.'+key+' else none }}'
        if key=='last_successful_scan':
            # Timestamp sensors require ISO8601, publish a separate normalized topic.
            continue
        _publish(client,f'{prefix}/sensor/dfm_{key}/config',config)
    for key in ('added','removed','modified','possible_moves'):
        config={'name':'Last Scan '+key.replace('_',' ').title(),
                'unique_id':'dfm_last_scan_'+key,'state_topic':base+'/state',
                'value_template':'{{ value_json.last_scan_changes.'+key+' }}','device':device,
                'availability_topic':base+'/availability'}
        config['suggested_display_precision']=1
        _publish(client,f'{prefix}/sensor/dfm_last_scan_{key}/config',config)
    for vol in snapshot['volumes']:
        identity=str(vol.get('volume_id') or vol['root'])
        # Stable ID should come from persisted volume_id, not changeable path.
        uid=re.sub(r'[^A-Za-z0-9_-]','_',identity)
        dev={'identifiers':['dfm_volume_'+uid],'name':'DFM — '+os.path.basename(vol['root'].rstrip('/')),'manufacturer':'DFM','via_device':'dfm_global'}
        for field,name,unit in [('last_full_scan','Last Full Scan',None),('last_quick_scan','Last Quick Scan',None),('file_count','Files',None),('duplicate_copies','Duplicate Copies',None),('wasted_bytes','Wasted Space','B'),('total_file_size_bytes','Total Data Consumed','B'),('added','Last Files Added',None),('removed','Last Files Removed',None),('modified','Last Files Modified',None),('possible_moves','Last Possible Moves',None)]:
            config={'name':name,'unique_id':f'dfm_{uid}_{field}','device':dev,'state_topic':base+'/state',
                    'value_template':"{{ (value_json.volumes | selectattr('volume_id','equalto', '"+str(vol.get('volume_id'))+"') | list | first)."+field+" }}",
                    'availability_topic':base+'/availability'}
            if unit: config['unit_of_measurement']=unit
            if field not in ('last_full_scan','last_quick_scan'): config['suggested_display_precision']=1
            if field in ('last_full_scan','last_quick_scan'):
                config['device_class']='timestamp'
            if field in ('wasted_bytes','total_file_size_bytes'):
                config['device_class']='data_size'
                config['state_class']='measurement'
                config['suggested_display_precision']=1
                config['unit_of_measurement']='GiB'
                config['value_template'] = ("{{ (((value_json.volumes | selectattr('volume_id','equalto', '"
                    + str(vol.get('volume_id')) + "') | list | first)." + field
                    + " | float) / 1073741824) | round(6) }}")
            _publish(client,f'{prefix}/sensor/dfm_{uid}_{field}/config',config)


def mqtt_worker(db, snapshot_fn, stop_event=None):
    """Opt-in background sender. MQTT failures never affect the scanner."""
    stop_event=stop_event or threading.Event()
    previous=None
    client=None
    while not stop_event.wait(30):
        try:
            from scanner import connect
            c=connect(db,readonly=True)
            try: cfg=get_config(c,True)
            finally: c.close()
            if not cfg['enabled']:
                if client: client.disconnect(); client.loop_stop(); client=None
                previous=None
                continue
            fingerprint=tuple(cfg[k] for k in CONFIG_KEYS)
            if previous!=fingerprint:
                if client: client.disconnect(); client.loop_stop()
                import paho.mqtt.client as mqtt
                client=mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,client_id='dfm-monitor',clean_session=True)
                if cfg['username']: client.username_pw_set(cfg['username'],cfg['password'])
                if cfg['tls']: client.tls_set()
                client.will_set(cfg['base_topic'].strip('/')+'/availability','offline',qos=1,retain=True)
                client.connect(cfg['host'],cfg['port'],keepalive=60)
                client.loop_start()
                previous=fingerprint
            snapshot=snapshot_fn()
            _publish(client,cfg['base_topic'].strip('/')+'/availability','online')
            if cfg['discovery']:
                from scanner import read_meta, write_meta
                c=connect(db)
                try:
                    known=set(json.loads(read_meta(c,'mqtt_known_volume_ids','[]')))
                    current={str(v['volume_id']) for v in snapshot['volumes'] if v.get('volume_id')}
                    removed=known-current
                    fields=('last_full_scan','last_quick_scan','file_count','duplicate_copies','wasted_bytes','total_file_size_bytes','added','removed','modified','possible_moves')
                    for ident in removed:
                        uid=re.sub(r'[^A-Za-z0-9_-]','_',ident)
                        for field in fields:
                            _publish(client,f"{cfg['discovery_prefix'].strip('/')}/sensor/dfm_{uid}_{field}/config",'',retain=True)
                    # Persist known set only after messages have been handed off successfully.
                    with c: write_meta(c,'mqtt_known_volume_ids',json.dumps(sorted(current)))
                finally:c.close()
            publish_mqtt(client,cfg,snapshot)
        except Exception as exc:
            print('MQTT monitoring error:',repr(exc),flush=True)
            previous=None
            if client:
                try: client.disconnect();client.loop_stop()
                except Exception: pass
                client=None
