"""Safe, persistent, timezone-aware Quick/Full scan schedules.

Scheduler never starts an implicit legacy interval job. All schedules are
explicitly disabled until configured through the UI.
"""
from datetime import datetime, timedelta, timezone
from contextlib import closing
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
import json
import re
import time
from scanner import connect, read_meta, write_meta

FREQUENCIES = {'5m':300,'10m':600,'15m':900,'30m':1800,'60m':3600,
               'hourly':3600,'daily':None,'weekly':None,'monthly':None,'custom':None}


def _cron_values(part, bottom, top):
    values=set()
    for token in part.split(','):
        m = re.fullmatch(r'(\*|\d+)(?:-(\d+))?(?:/(\d+))?', token)
        if not m:
            raise ValueError('Invalid cron field: '+part)
        first = bottom if m[1]=='*' else int(m[1])
        end = top if m[1]=='*' else int(m[2]) if m[2] else first
        step=int(m[3] or 1)
        if first < bottom or end > top or first>end or step < 1:
            raise ValueError('Cron field out of range: '+part)
        values.update(range(first,end+1,step))
    return values


def cron_matches(expr, dt):
    fields=expr.split()
    if len(fields)!=5:
        raise ValueError('Custom schedule requires five cron fields')
    minute,hour,day,month,dow=fields
    values=[_cron_values(f,lo,hi) for f,lo,hi in zip(fields,(0,0,1,1,0),(59,23,31,12,7))]
    # Unix cron treats both 0 and 7 as Sunday, Python weekday Monday=0.
    day_of_week=(dt.weekday()+1)%7
    dom_ok=dt.day in values[2]
    dow_ok=day_of_week in values[4] or (day_of_week==0 and 7 in values[4])
    day_ok=(dom_ok or dow_ok) if day!='*' and dow!='*' else (dom_ok if dow=='*' else dow_ok)
    return dt.minute in values[0] and dt.hour in values[1] and day_ok and dt.month in values[3]


def validate(entry, per_volume_enabled, roots):
    if not isinstance(entry, dict):
        raise ValueError('Invalid schedule')
    mode=entry.get('mode')
    if mode not in ('quick','full'):
        raise ValueError('Schedule type must be Quick or Full')
    scope=entry.get('root') or 'all'
    if scope != 'all' and (not per_volume_enabled or scope not in roots):
        raise ValueError('Per-volume scheduling must be enabled and volume configured')
    frequency=entry.get('frequency','daily')
    if frequency not in FREQUENCIES:
        raise ValueError('Unsupported schedule frequency')
    tz_name=entry.get('timezone','America/Chicago')
    try: ZoneInfo(tz_name)
    except (ZoneInfoNotFoundError,KeyError): raise ValueError('Unknown time zone')
    at=entry.get('at','02:00')
    if not re.fullmatch(r'(?:[01]\d|2[0-3]):[0-5]\d',at):
        raise ValueError('Time must use 24-hour HH:MM format')
    weekday=int(entry.get('weekday',0))
    month_day=int(entry.get('month_day',1))
    if not 0<=weekday<=6 or not 1<=month_day<=28:
        raise ValueError('Weekday (0–6) or monthly date (1–28) invalid')
    cron=entry.get('cron','0 2 * * *')
    if frequency=='custom':
        cron_matches(cron,datetime.now())
    enabled=entry.get('enabled',False)
    if type(enabled) is not bool:
        raise ValueError('Schedule enabled must be true or false')
    conflict=entry.get('on_conflict','skip')
    missed=entry.get('on_missed','skip')
    if conflict not in ('skip','defer') or missed not in ('skip','run_once'):
        raise ValueError('Invalid schedule conflict or missed-run policy')
    return {'id':scope+'|'+mode,'mode':mode,'root':scope,
            'enabled':enabled,'frequency':frequency,'timezone':tz_name,'at':at,
            'weekday':weekday,'month_day':month_day,'cron':cron,
            'on_conflict':conflict,'on_missed':missed,
            'last_run':entry.get('last_run'), 'last_outcome':entry.get('last_outcome'),
            'next_run':entry.get('next_run')}


def next_occurrence(entry, after):
    """Earliest execution strictly later than after. Calendar times use zoneinfo."""
    frequency=entry['frequency']
    if frequency in ('5m','10m','15m','30m','60m'):
        return after + FREQUENCIES[frequency]
    zone=ZoneInfo(entry['timezone'])
    local=datetime.fromtimestamp(after,zone)
    if frequency=='hourly':
        # Schedule hourly at the saved minute rather than at creation time.
        minute=int(entry['at'][3:])
        for h in range(0,27):
            candidate=(local+timedelta(hours=h)).replace(minute=minute,second=0,microsecond=0)
            if candidate.timestamp()>after and datetime.fromtimestamp(candidate.timestamp(),zone).minute==minute:
                return candidate.timestamp()
    else:
        hour,minute=map(int,entry['at'].split(':'))
        for offset in range(0,400):
            day=(local+timedelta(days=offset)).date()
            if frequency=='weekly' and day.weekday()!=entry['weekday']:
                continue
            if frequency=='monthly' and day.day!=entry['month_day']:
                continue
            if frequency=='custom':
                # Cron can execute every minute, not only once daily.
                break
            candidate=datetime(day.year,day.month,day.day,hour,minute,tzinfo=zone)
            stamp=candidate.timestamp()
            if stamp>after and datetime.fromtimestamp(stamp,zone).hour==hour and datetime.fromtimestamp(stamp,zone).minute==minute:
                return stamp
        if frequency=='custom':
            stamp=int(after//60)*60+60
            for _ in range(366*24*60):
                candidate=datetime.fromtimestamp(stamp,zone)
                if cron_matches(entry['cron'], candidate):
                    return float(stamp)
                stamp+=60
    raise ValueError('Could not determine next schedule execution')


def get_schedules(db):
    with closing(connect(db,readonly=True)) as c:
        data=read_meta(c,'scan_schedules_json','[]')
    return json.loads(data)


def save_schedules(db, items, roots, per_volume_enabled, now=None):
    if not isinstance(items,list) or len(items)>100:
        raise ValueError('Provide at most 100 schedules')
    now=time.time() if now is None else now
    prior={x['id']:x for x in get_schedules(db)}
    output=[]
    for source in items:
        item=validate(source,per_volume_enabled,roots)
        if item['id'] in {x['id'] for x in output}:
            raise ValueError('Duplicate schedule for the same scan type and scope')
        before=prior.get(item['id'])
        # Never accept client-supplied timestamps or outcome history.
        for field in ('last_run','last_outcome'):
            item[field]=before.get(field) if before else None
        item['next_run']=next_occurrence(item,now) if item['enabled'] else None
        output.append(item)
    with closing(connect(db)) as c, c:
        write_meta(c,'scan_schedules_json',json.dumps(output))
    return output


def update_run(db, schedule_id, **fields):
    with closing(connect(db)) as c, c:
        rows=json.loads(read_meta(c,'scan_schedules_json','[]'))
        for row in rows:
            if row['id']==schedule_id:
                row.update(fields)
                break
        write_meta(c,'scan_schedules_json',json.dumps(rows))
