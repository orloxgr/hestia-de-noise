"""Explicit preview/apply/restore of existing native Hestia WordPress cron jobs."""
import copy
import math
import re
import secrets
from urllib.parse import urlsplit

FIELDS = ('MIN', 'HOUR', 'DAY', 'MONTH', 'WDAY', 'CMD')


def minutes(minimum=5, maximum=15, rng=None):
    if type(minimum) is not int or type(maximum) is not int or not 1 <= minimum <= maximum <= 30:
        raise ValueError('Cron intervals must be integers between 1 and 30 minutes')
    lo, hi = math.ceil(60/maximum), math.floor(60/minimum)
    if lo > hi:
        raise ValueError('This interval range cannot repeat hourly; use a wider range such as 5–15')
    rng = rng or secrets.SystemRandom()
    count, offset = rng.randint(lo, hi), rng.randrange(60)
    values = sorted((offset + index*60//count) % 60 for index in range(count))
    return ','.join(map(str, values))


def preview(hestia, minimum=5, maximum=15):
    minutes(minimum, maximum)  # Validate before calling native commands.
    rows = []
    for owner, user in hestia('v-list-users').items():
        if user.get('SUSPENDED') == 'yes':
            continue
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', owner):
            raise ValueError('Invalid Hestia cron owner')
        for ident, job in hestia('v-list-cron-jobs', owner).items():
            if job.get('SUSPENDED') != 'no' or any(job.get(key) != '*' for key in ('HOUR', 'DAY', 'MONTH', 'WDAY')):
                continue
            match = re.search(r'(?:https?://[A-Za-z0-9.-]+|/home/[A-Za-z0-9_./-]+)/wp-cron\.php\b', job.get('CMD', ''))
            if not match:
                continue
            if not re.fullmatch(r'[0-9]+', ident) or not all(isinstance(job.get(key), str) for key in FIELDS):
                raise ValueError('Malformed native WordPress cron job')
            before = {key: job[key] for key in FIELDS}
            after = {**before, 'MIN': minutes(minimum, maximum)}
            rows.append({'key': owner+'/'+ident, 'owner': owner, 'job': ident,
                         'label': match[0], 'before': before, 'after': after, 'state': 'preview'})
    return {'id': secrets.token_hex(16), 'minimum': minimum, 'maximum': maximum, 'rows': rows}


def public(plan):
    if not plan:
        return None
    if (not isinstance(plan, dict) or not isinstance(plan.get('id'), str)
            or not re.fullmatch('[0-9a-f]{32}', plan['id']) or not isinstance(plan.get('rows'), list)):
        return {'error': 'Saved cron preview is invalid. Generate a new preview.'}
    return {'id': plan['id'], 'minimum': plan['minimum'], 'maximum': plan['maximum'],
            'rows': [{**{key: row[key] for key in ('key', 'owner', 'job', 'label', 'state')},
                      'site': site_label(row['label']),
                      'before': row['before']['MIN'], 'after': row['after']['MIN'],
                      'before_label': interval_label(row['before']['MIN']),
                      'after_label': interval_label(row['after']['MIN'])}
                     for row in plan['rows']]}


def site_label(label):
    if label.startswith(('http://', 'https://')):
        return urlsplit(label).hostname or label
    parts = label.split('/')
    if len(parts) > 4 and parts[1] == 'home':
        return parts[4] if parts[3] == 'web' and len(parts) > 5 else parts[3]
    return label


def interval_label(value):
    if value == '*':
        return 'Every minute'
    match = re.fullmatch(r'\*/([1-9][0-9]?)', value)
    if match:
        step = int(match[1])
        values = list(range(0, 60, step))
    elif re.fullmatch(r'[0-9]+(?:,[0-9]+)*', value):
        values = sorted(set(map(int, value.split(','))))
    else:
        return 'Custom schedule'
    if not values or any(not 0 <= minute < 60 for minute in values):
        return 'Custom schedule'
    gaps = [right-left for left, right in zip(values, values[1:]+[values[0]+60])]
    low, high = min(gaps), max(gaps)
    return 'Every ' + (str(low) if low == high else str(low)+'–'+str(high)) + ' minutes'


def apply(plan, selection, hestia, change, save, restore=False):
    if (not isinstance(selection, list) or not selection or len(selection) > 10000
            or any(not isinstance(key, str) for key in selection)):
        raise ValueError('Select existing WordPress cron jobs')
    known = {row['key']: row for row in plan['rows']}
    if any(key not in known for key in selection):
        raise ValueError('The selected cron job is not in this preview')
    jobs = {}
    # Check the whole selection before any change; a stale preview cannot
    # overwrite a command or schedule edited in the native Hestia interface.
    for key in dict.fromkeys(selection):
        row = known[key]
        if row['owner'] not in jobs:
            jobs[row['owner']] = hestia('v-list-cron-jobs', row['owner'])
        current = jobs[row['owner']].get(row['job'], {})
        source, destination = (row['after'], row['before']) if restore else (row['before'], row['after'])
        if current.get('SUSPENDED') != 'no' or {field: current.get(field) for field in FIELDS} not in (source, destination):
            raise ValueError('Cron job changed after preview: ' + key + '. Create a fresh preview.')
        if restore and row['state'] == 'preview':
            raise ValueError('This cron job has not been changed by this preview: ' + key)
    for key in dict.fromkeys(selection):
        row = known[key]
        destination = row['before'] if restore else row['after']
        source = row['after'] if restore else row['before']
        current = hestia('v-list-cron-jobs', row['owner']).get(row['job'], {})
        if current.get('SUSPENDED') != 'no' or {field: current.get(field) for field in FIELDS} not in (source, destination):
            raise ValueError('Cron job changed after preview: ' + key + '. Create a fresh preview.')
        row['state'] = 'restoring' if restore else 'applying'; save(plan)
        if {field: current.get(field) for field in FIELDS} != destination:
            try:
                change(row['owner'], row['job'], *[destination[field] for field in FIELDS])
            except Exception as error:
                # Keep actual native error details, without echoing a private
                # existing cron command into the panel's error banner.
                raise RuntimeError(str(error).replace(destination['CMD'], '[existing cron command]')) from error
        confirmed = hestia('v-list-cron-jobs', row['owner']).get(row['job'], {})
        if confirmed.get('SUSPENDED') != 'no' or {field: confirmed.get(field) for field in FIELDS} != destination:
            raise RuntimeError('Hestia did not confirm the requested schedule: ' + key)
        row['state'] = 'restored' if restore else 'applied'; save(plan)
    return copy.deepcopy(plan)
