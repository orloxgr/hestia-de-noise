"""Validated policy and a deterministic native Nginx compiler."""
import copy
import re

MARKER = '# Managed by hestia-de-noise'
MODES = ('off', 'observe', 'enforce')
PRESET_AGENTS = ['meta-externalagent', 'GoogleOther', 'MJ12bot']
DEFAULT = {'schema': 1, 'mode': 'observe', 'agents': [], 'scanners': False,
           'login': {'enabled': False, 'rate': 5, 'burst': 3},
           'xmlrpc': {'enabled': False, 'rate': 10, 'burst': 3}, 'overrides': {}}


def account(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', value):
        raise ValueError('Invalid account name')
    return value


def domain(value):
    if (not isinstance(value, str) or len(value) > 253 or
            not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', value) or
            any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', s) for s in value.split('.'))):
        raise ValueError('Invalid ASCII domain name')
    return value


def target(value):
    if not isinstance(value, str) or value.count('/') != 1:
        raise ValueError('Invalid site selection')
    owner, name = value.split('/')
    account(owner); domain(name)
    return value


def validate(raw):
    if not isinstance(raw, dict) or raw.get('schema') != 1 or set(raw) != set(DEFAULT):
        raise ValueError('Unsupported policy format')
    data = copy.deepcopy(raw)
    if data['mode'] not in MODES or type(data['scanners']) is not bool:
        raise ValueError('Invalid mode or private-file setting')
    if not isinstance(data['agents'], list) or len(data['agents']) > 200:
        raise ValueError('Use at most 200 User-Agent entries')
    agents = []
    for entry in data['agents']:
        # Printable ASCII keeps the literal substring behavior explicit across
        # Nginx/PCRE builds. Quotes, regex and config punctuation are escaped.
        if (not isinstance(entry, str) or not 2 <= len(entry.strip()) <= 160 or
                any(ord(c) < 32 or ord(c) > 126 for c in entry)):
            raise ValueError('User-Agents must be printable text, 2–160 characters per line')
        entry = entry.strip()
        if entry.lower() not in [x.lower() for x in agents]:
            agents.append(entry)
    data['agents'] = agents
    for key in ('login', 'xmlrpc'):
        rule = data[key]
        if (not isinstance(rule, dict) or set(rule) != {'enabled', 'rate', 'burst'} or
                type(rule['enabled']) is not bool or type(rule['rate']) is not int or
                not 1 <= rule['rate'] <= 600 or type(rule['burst']) is not int or
                not 0 <= rule['burst'] <= 100):
            raise ValueError('Rates must be 1–600 per minute; burst must be 0–100')
    if not isinstance(data['overrides'], dict) or len(data['overrides']) > 10000:
        raise ValueError('Invalid domain overrides')
    for key, mode in data['overrides'].items():
        target(key)
        if mode not in MODES:
            raise ValueError('Invalid domain mode')
    return data


def literal_regex(value):
    """A PCRE literal inside one Nginx double-quoted config token."""
    # Hex every byte: neither Nginx config interpolation nor PCRE metacharacters
    # can reinterpret an administrator's literal text. Nginx consumes one of
    # the two backslashes before PCRE receives each \xHH escape.
    return '"~*' + ''.join(r'\\x' + format(ord(c), '02x') for c in value) + '"'


def site_mode(policy, site):
    return policy['overrides'].get(site['key'], policy['mode']) if not site.get('suspended') else 'off'


def global_config(policy, sites):
    policy = validate(policy)
    # Declare a safe mode even on a new server with no domains yet. Supported
    # virtual hosts set this changeable variable during their rewrite phase.
    lines = [MARKER, 'map $server_name $hdn_mode { default off; }',
             'map $http_user_agent $hdn_agent {', '    default 0;']
    lines += ['    ' + literal_regex(entry) + ' 1;' for entry in policy['agents']]
    lines += ['}', 'map $uri $hdn_private {', '    default 0;']
    if policy['scanners']:
        lines += [r'    ~*^/\.env(?:[./]|$) 1;', r'    ~*^/\.git(?:/|$) 1;',
                  r'    ~*^/wp-config\.php\.(?:bak|backup|old)$ 1;']
    lines += ['}', 'map "$hdn_agent:$hdn_private" $hdn_match {', '    default "";',
              '    "1:0" agent;', '    "0:1" private-file;', '    "1:1" agent;', '}',
              # Separate observation log: no IP, URI, query, header or agent.
              'log_format hdn "$time_iso8601 $server_name $hdn_match $limit_req_status $status";',
              'map "$hdn_mode:$hdn_match:$limit_req_status" $hdn_log {',
              '    default 0;', '    ~^(observe|enforce):[^:]+: 1;',
              '    ~^(observe|enforce):.*:(REJECTED|REJECTED_DRY_RUN|DELAYED_DRY_RUN)$ 1;', '}',
              'map "$hdn_mode:$request_method:$uri" $hdn_login_key {', '    default "";']
    if policy['login']['enabled']:
        lines.append('    ~^(observe|enforce):POST:/wp-login\\.php/?$ "$server_name:$binary_remote_addr";')
    lines += ['}', 'map "$hdn_mode:$request_method:$uri" $hdn_xmlrpc_key {', '    default "";']
    if policy['xmlrpc']['enabled']:
        lines.append('    ~^(observe|enforce):POST:/xmlrpc\\.php/?$ "$server_name:$binary_remote_addr";')
    lines += ['}']
    for key in ('login', 'xmlrpc'):
        if policy[key]['enabled']:
            lines.append('limit_req_zone $hdn_' + key + '_key zone=hdn_' + key + ':10m rate=' + str(policy[key]['rate']) + 'r/m;')
    return '\n'.join(lines) + '\n'


def site_config(policy, site):
    mode = site_mode(policy, site)
    lines = [MARKER, 'set $hdn_mode ' + mode + ';']
    if mode == 'enforce':
        lines.append('if ($hdn_match != "") { return 403; }')
    for key in ('login', 'xmlrpc'):
        if policy[key]['enabled']:
            burst = policy[key]['burst']
            lines.append('limit_req zone=hdn_' + key + ((' burst=' + str(burst) + ' nodelay') if burst else '') + ';')
    if any(policy[key]['enabled'] for key in ('login', 'xmlrpc')):
        lines += ['limit_req_status 429;', 'limit_req_dry_run ' + ('off' if mode == 'enforce' else 'on') + ';']
    lines += ['access_log /var/log/hestia-de-noise/matches.log hdn if=$hdn_log;']
    return '\n'.join(lines) + '\n'
