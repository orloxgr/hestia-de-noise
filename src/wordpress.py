"""Administrator controls for one native Fail2ban jail; no WordPress discovery."""
import base64
import configparser
import copy
import ipaddress
import json
from pathlib import Path
import re

import storage
import ban_history
from policy import MARKER

JAIL = 'wordpress-login'
CLIENT = '/usr/bin/fail2ban-client'
ETC = Path('/etc/fail2ban')
ROOT = Path(__file__).resolve().parents[1]
SETTINGS = 'wordpress.json'
JOURNAL = 'wordpress-transaction.json'
RECEIPT = 'wordpress-install.json'
DEFAULT = {'enabled': False, 'maxretry': 3, 'findtime': 300,
           'durations': [300, 259200, -1]}
LEGACY_HEADER = b'# WordPress failed logins across hosted sites.\n'
HISTORY_HEADER = b'# Preserve repeat-offender history beyond the three-day second ban.\n'


def validate(value):
    if not isinstance(value, dict) or set(value) != set(DEFAULT):
        raise ValueError('Expected WordPress login protection settings')
    if type(value['enabled']) is not bool:
        raise ValueError('Enabled must be a switch')
    for key in ('maxretry', 'findtime'):
        if type(value[key]) is not int or value[key] < 1:
            raise ValueError(key + ' must be a positive integer')
    times = value['durations']
    if (not isinstance(times, list) or len(times) != 3 or
            any(type(t) is not int for t in times) or
            times[0] < 1 or times[1] < times[0] or
            (times[2] != -1 and times[2] < times[1])):
        raise ValueError('Use three increasing ban durations; the last can be permanent')
    return copy.deepcopy(value)


def read_json(state, name, default=None):
    raw = storage.read(Path(state) / name)
    return json.loads(raw) if raw is not None else copy.deepcopy(default)


def paths(state):
    return [ETC / 'filter.d/hdn-wordpress-login.conf',
            ETC / 'action.d/hdn-wordpress.conf',
            ETC / 'jail.d/wordpress-login.local',
            ETC / 'fail2ban.d/wordpress-history.local', Path(state) / SETTINGS]


def legacy_settings(raw):
    """Adopt only the known standalone setup, never an unrelated administrator jail."""
    if raw is None or not raw.startswith(LEGACY_HEADER):
        return None
    parser = configparser.ConfigParser(interpolation=None)
    parser.read_string(raw.decode())
    allowed = {'enabled', 'filter', 'backend', 'logpath', 'usedns', 'port', 'protocol',
               'findtime', 'maxretry', 'bantime', 'bantime.increment', 'bantime.factor',
               'bantime.multipliers', 'bantime.overalljails', 'action'}
    if parser.sections() != [JAIL] or set(parser[JAIL]) != allowed:
        raise ValueError('The standalone WordPress jail has additional settings; kept unchanged')
    row = parser[JAIL]
    if (row['filter'] != 'wordpress-login' or row['action'] !=
            'hestia-wordpress[name=WORDPRESS,port="80,443",protocol=tcp,blocktype=DROP]' or
            row['logpath'] != '/var/log/auth.log tail' or row['port'] != '80,443' or
            row['backend'] != 'auto' or row['usedns'] != 'no' or row['protocol'] != 'tcp' or
            row.getboolean('bantime.increment') is not True or row.getboolean('bantime.overalljails') or
            row['bantime.factor'] != '1/300' or row['bantime.multipliers'] != '300 259200 -1' or
            row['bantime'] != '5m'):
        raise ValueError('The standalone WordPress jail differs from the supported setup')
    seconds = row['findtime']
    seconds = int(seconds[:-1]) * 60 if seconds.endswith('m') else int(seconds)
    return validate({'enabled': row.getboolean('enabled'), 'maxretry': row.getint('maxretry'),
                     'findtime': seconds, 'durations': [300, 259200, -1]})


def settings(state):
    saved = read_json(state, SETTINGS)
    if saved is not None:
        return validate(saved)
    adopted = legacy_settings(storage.read(ETC / 'jail.d/wordpress-login.local'))
    return adopted if adopted is not None else copy.deepcopy(DEFAULT)


def render(value, state):
    value = validate(value)
    first, second, third = value['durations']
    header = MARKER + '\n# WordPress failed authentication\n'
    jail = (header + '[' + JAIL + ']\n' +
            'enabled = ' + str(value['enabled']).lower() + '\n' +
            'filter = hdn-wordpress-login\nbackend = auto\nlogpath = /var/log/auth.log tail\n' +
            'usedns = no\nport = 80,443\nprotocol = tcp\n' +
            'findtime = ' + str(value['findtime']) + '\nmaxretry = ' + str(value['maxretry']) + '\n' +
            'bantime = ' + str(first) + '\nbantime.increment = true\n' +
            # Native formulas clamp -1; reciprocal floats lose its exact value
            # for some first durations. Native multiplier evaluation permits a
            # factor expression: normalize the base to integer 1, then multiply
            # by the exact, validated integer durations. No imports or hooks.
            'bantime.factor = type("ExactBanUnit", (), {"__rmul__": lambda self, base: 1})()\n' +
            'bantime.multipliers = ' + ' '.join(map(str, (first, second, third))) +
            '\nbantime.overalljails = false\n' +
            'action = hdn-wordpress[actname=hestia-wordpress-WORDPRESS,name=WORDPRESS]\n')
    filter_text = (header + '[INCLUDES]\nbefore = common.conf\n[Definition]\n' +
                   '_daemon = (?:wordpress|wp)\n' +
                   'failregex = ^%(__prefix_line)s(?:Authentication|(?:REST|XML-RPC) authentication) ' +
                   '(?:failure for|attempt for unknown user) .* from <HOST>$\nignoreregex =\n')
    destinations = paths(state)
    return dict(zip(destinations, [filter_text.encode(),
        (ROOT / 'config/wordpress-action.conf').read_text(encoding='utf-8').encode(), jail.encode(),
        (header + '[Definition]\ndbpurgeage = 30d\n').encode(), storage.json_bytes(value)]))


def capture(destinations):
    return {str(p): None if (raw := storage.read(p)) is None else
            base64.b64encode(raw).decode('ascii') for p in destinations}


def restore(record, state):
    allowed = {str(p) for p in paths(state)}
    if not isinstance(record, dict) or set(record) != allowed:
        raise ValueError('Invalid WordPress recovery paths')
    for name, raw in record.items():
        storage.replace(Path(name), None if raw is None else base64.b64decode(raw, validate=True),
                        0o600 if name == str(Path(state) / SETTINGS) else 0o644)


def recover(state, run):
    record = read_json(state, JOURNAL)
    if record is None:
        return
    if (set(record) != {'before', 'reload_started', 'receipt_created'} or
            type(record['reload_started']) is not bool or type(record['receipt_created']) is not bool):
        raise ValueError('Invalid WordPress recovery journal')
    restore(record['before'], state)
    if record['reload_started']:
        run(CLIENT, '-t')
        run(CLIENT, 'reload')
    if record['receipt_created']:
        storage.replace(Path(state) / RECEIPT, None)
    storage.replace(Path(state) / JOURNAL, None)


def apply(state, value, run):
    value = validate(value)
    desired = render(value, state)
    before = capture(desired)
    jail = str(ETC / 'jail.d/wordpress-login.local')
    for p in desired:
        raw = storage.read(p)
        if raw is None or p == Path(state) / SETTINGS or raw.startswith((MARKER + '\n').encode()):
            continue
        if str(p) == jail and legacy_settings(raw) is not None:
            continue
        if p == ETC / 'fail2ban.d/wordpress-history.local' and raw.startswith(HISTORY_HEADER):
            continue
        raise ValueError('Existing file is not owned by De-Noise: ' + str(p))
    if all(storage.read(p) == data for p, data in desired.items()):
        return {'changed': False}
    for p in desired:
        if not p.parent.is_dir():
            raise ValueError('An installed Fail2ban configuration directory is required: ' + str(p.parent))
    receipt = Path(state) / RECEIPT
    receipt_created = storage.read(receipt) is None
    record = {'before': before, 'reload_started': False, 'receipt_created': receipt_created}
    storage.replace(Path(state) / JOURNAL, storage.json_bytes(record), 0o600)
    try:
        if receipt_created:
            storage.replace(receipt, storage.json_bytes(before), 0o600)
        for p, data in desired.items():
            storage.replace(p, data, 0o600 if p == Path(state) / SETTINGS else 0o644)
        run(CLIENT, '-t')
        record['reload_started'] = True
        storage.replace(Path(state) / JOURNAL, storage.json_bytes(record), 0o600)
        run(CLIENT, 'reload')
    except Exception as error:
        try:
            recover(state, run)
        except Exception as recovery:
            raise RuntimeError(str(error) + '\nWordPress protection recovery failed: ' + str(recovery)) from error
        raise
    storage.replace(Path(state) / JOURNAL, None)
    return {'changed': True}


def install(state, run):
    """An empty installation stays off; a known existing jail is adopted unchanged."""
    saved = read_json(state, SETTINGS)
    legacy = storage.read(ETC / 'jail.d/wordpress-login.local')
    if saved is None and (legacy is None or not legacy.startswith(LEGACY_HEADER)):
        return {'managed': False}
    result = apply(state, settings(state), run)
    return {'managed': True, **result}


def uninstall(state, run):
    before = read_json(state, RECEIPT)
    if before is None:
        return
    current = capture(paths(state))
    for p in paths(state)[:-1]:
        raw = storage.read(p)
        if raw is not None and not raw.startswith((MARKER + '\n').encode()):
            raise ValueError('A managed WordPress configuration was replaced: ' + str(p))
    record = {'before': current, 'reload_started': True, 'receipt_created': False}
    storage.replace(Path(state) / JOURNAL, storage.json_bytes(record), 0o600)
    try:
        restore(before, state)
        run(CLIENT, '-t')
        run(CLIENT, 'reload')
    except Exception:
        recover(state, run)
        raise
    storage.replace(Path(state) / JOURNAL, None)
    storage.replace(Path(state) / RECEIPT, None)


def addresses(output):
    result = set()
    for token in output.split():
        try:
            result.add(str(ipaddress.ip_address(token.strip("[],'\""))))
        except ValueError:
            continue
    return sorted(result, key=lambda s: (':' in s, s))


def snapshot(state, run, live=False, page=1):
    ban_history.selection(page)
    result = {'settings': settings(state), 'managed': read_json(state, RECEIPT) is not None,
              'loaded': live, 'ips': [], 'pagination': ban_history.pagination(0, page)}
    if not live:
        return result
    try:
        status = run(CLIENT, 'status')
        match = re.search(r'Jail list:\s*([^\n]+)', status)
        active = JAIL in [s.strip() for s in match[1].split(',')] if match else False
        result['active'] = active
        if active:
            all_ips = addresses(run(CLIENT, 'get', JAIL, 'banip'))
            meta = ban_history.pagination(len(all_ips), page)
            offset = (meta['page'] - 1) * ban_history.PAGE_SIZE
            result.update(ips=all_ips[offset:offset + ban_history.PAGE_SIZE], pagination=meta)
        result['available'] = True
    except (OSError, RuntimeError) as error:
        result.update(available=False, error=str(error))
    return result


def unban(state, selection, run):
    if read_json(state, RECEIPT) is None:
        raise ValueError('Apply WordPress protection settings before managing its bans')
    active = addresses(run(CLIENT, 'get', JAIL, 'banip'))
    if selection == 'all':
        selection = active
    if (not isinstance(selection, list) or
            any(not isinstance(s, str) or s not in active for s in selection)):
        raise ValueError('Select existing WordPress bans')
    for address in dict.fromkeys(selection):
        run(CLIENT, 'set', JAIL, 'unbanip', address)
