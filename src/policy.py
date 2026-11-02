"""Validated policy and a deterministic native Nginx compiler."""
import copy
import hashlib
import ipaddress
import re
from urllib.parse import quote, unquote
import probe_rules

MARKER = '# Managed by hestia-de-noise'
VERSION = '0.5.0'
MODES = ('off', 'observe', 'enforce')
SCANNER_AGENTS = ['TLM-Audit-Scanner', 'sqlmap', 'Nikto', 'Nuclei', 'zgrab',
                  'masscan', 'ZmEu', 'DirBuster', 'gobuster', 'ffuf', 'WPScan']
CRAWLER_AGENTS = ['meta-externalagent', 'GoogleOther', 'MJ12bot', 'Bytespider',
                  'ClaudeBot', 'Amazonbot', 'Reflectionbot', 'GPTBot',
                  'AhrefsBot', 'SemrushBot', 'DotBot', 'BLEXBot', 'YisouSpider']
PRESET_AGENTS = SCANNER_AGENTS + CRAWLER_AGENTS[:3]
FILTER_AGENTS = ['Applebot', 'Amazonbot', 'Reflectionbot', 'Googlebot', 'bingbot']
DEFAULT = {'schema': 6, 'mode': 'observe', 'agents': [], 'scanners': False,
           'login': {'enabled': False, 'rate': 5, 'burst': 3},
           'xmlrpc': {'enabled': False, 'rate': 10, 'burst': 3}, 'overrides': {},
           'filters': [], 'static': [], 'static_exceptions': {},
           'tool_agents': [], 'tool_agents_enabled': True, 'agents_enabled': True,
           'bans': {'enabled': False, 'private_files': True, 'repositories': True,
                    'maxretry': 1, 'findtime': 300, 'duration_days': 0,
                    'ignore_ips': [], 'targets': [],
                    'missing_files': {'enabled': False, 'maxretry': 2, 'findtime': 60,
                                      'duration_days': 3, 'paths': list(probe_rules.FILES)},
                    'suspicious_queries': {'enabled': False, 'maxretry': 2, 'findtime': 60,
                                           'duration_days': 3, 'targets': list(probe_rules.QUERY_TARGETS),
                                           'parameters': list(probe_rules.QUERY_PARAMETERS)}},
           'probe_exceptions': {'files': {}, 'queries': {}},
           'domain_bans': {'allow_users': True, 'sites': {}}}
LEGACY_KEYS = {'schema', 'mode', 'agents', 'scanners', 'login', 'xmlrpc', 'overrides'}
PRIVATE_PATTERNS = [
    ('private-file', r'(?:^|/)\.env(?:[./]|$)'),
    ('repository', r'(?:^|/)\.(?:git|svn|hg)(?:/|$)'),
    ('private-file', r'(?:^|/)wp-config\.php\.(?:bak|backup|old|orig|save|swp|zip|sql)$'),
    ('private-file', r'(?:^|/)\.htpasswd(?:/|$)'),
    ('metadata', r'(?:^|/)\.DS_Store(?:/|$)'),
    ('private-file', r'(?:^|/)\.aws/(?:credentials|config)(?:/|$)'),
    ('private-file', r'(?:^|/)\.docker/(?:config|secrets)\.json(?:/|$)'),
    ('private-file', r'(?:^|/)\.kube/config(?:/|$)'),
    ('private-file', r'(?:^|/)\.terraform/(?:credentials\.tfrc\.json|terraform\.tfstate)(?:/|$)'),
    ('private-file', r'(?:^|/)proc/(?:self|[0-9]+)/(?:environ|cmdline)(?:/|$)'),
    ('private-file', r'(?:^|/)etc/(?:passwd|shadow|gshadow)(?:/|$)'),
    ('private-file', r'(?:^|/)var/run/secrets/kubernetes\.io/serviceaccount(?:/|$)')]


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
    if not isinstance(raw, dict):
        raise ValueError('Unsupported policy format')
    data = copy.deepcopy(raw)
    if data.get('schema') == 1 and set(data) == LEGACY_KEYS:
        data.update(schema=2, filters=[], static=[])
    if data.get('schema') == 2 and set(data) == LEGACY_KEYS | {'filters', 'static'}:
        data.update(schema=3, static_exceptions={})
    if data.get('schema') == 3 and set(data) == LEGACY_KEYS | {'filters', 'static', 'static_exceptions'}:
        tools = {name.lower() for name in SCANNER_AGENTS}
        previous = data['agents']
        if not isinstance(previous, list) or any(not isinstance(entry, str) for entry in previous):
            raise ValueError('Invalid saved User-Agent list')
        data.update(schema=4, tool_agents=[entry for entry in previous if entry.strip().lower() in tools],
                    agents=[entry for entry in previous if entry.strip().lower() not in tools],
                    tool_agents_enabled=True, agents_enabled=True, bans={key: copy.deepcopy(value) for key, value in DEFAULT['bans'].items() if key not in ('missing_files', 'suspicious_queries')})
    if data.get('schema') == 4 and set(data) == set(DEFAULT) - {'probe_exceptions', 'domain_bans'}:
        if not isinstance(data.get('bans'), dict):
            raise ValueError('Invalid saved automatic-ban settings')
        data['bans'].update({key: copy.deepcopy(DEFAULT['bans'][key]) for key in ('missing_files', 'suspicious_queries')})
        data.update(schema=5, probe_exceptions={'files': {}, 'queries': {}})
    if data.get('schema') == 5 and set(data) == set(DEFAULT) - {'domain_bans'}:
        data.update(schema=6, domain_bans=copy.deepcopy(DEFAULT['domain_bans']))
    if data.get('schema') != 6 or set(data) != set(DEFAULT):
        raise ValueError('Unsupported policy format')
    if data['mode'] not in MODES or type(data['scanners']) is not bool:
        raise ValueError('Invalid mode or private-file setting')
    if any(type(data[key]) is not bool for key in ('tool_agents_enabled', 'agents_enabled')):
        raise ValueError('Invalid User-Agent list switch')
    for field in ('agents', 'tool_agents'):
        data[field] = validate_agents(data[field])
    ban = data['bans']
    if (not isinstance(ban, dict) or set(ban) != set(DEFAULT['bans']) or
            any(type(ban[key]) is not bool for key in ('enabled', 'private_files', 'repositories')) or
            type(ban['maxretry']) is not int or not 1 <= ban['maxretry'] <= 1000 or
            type(ban['findtime']) is not int or not 30 <= ban['findtime'] <= 86400 or
            type(ban['duration_days']) is not int or not 0 <= ban['duration_days'] <= 3650):
        raise ValueError('Invalid automatic-ban settings: attempts 1–1000, window 30–86400 seconds, duration 0–3650 days')
    if not isinstance(ban['targets'], list) or len(ban['targets']) > 10000:
        raise ValueError('Invalid automatic-ban domain selection')
    ban['targets'] = list(dict.fromkeys(target(name) for name in ban['targets']))
    if not isinstance(ban['ignore_ips'], list) or len(ban['ignore_ips']) > 1000:
        raise ValueError('Invalid never-ban IP list')
    if any(not isinstance(value, str) for value in ban['ignore_ips']):
        raise ValueError('Never-ban entries must be IP addresses or CIDR networks')
    try:
        ban['ignore_ips'] = list(dict.fromkeys(str(ipaddress.ip_network(value, strict=False)) for value in ban['ignore_ips']))
    except ValueError as error:
        raise ValueError('Never-ban entries must be IP addresses or CIDR networks') from error
    probe_rules.validate_settings(data, exception_path, target)
    delegation = data['domain_bans']
    if (not isinstance(delegation, dict) or set(delegation) != {'allow_users', 'sites'}
            or type(delegation['allow_users']) is not bool or not isinstance(delegation['sites'], dict)
            or len(delegation['sites']) > 10000):
        raise ValueError('Invalid domain automatic-ban settings')
    for key, rules in delegation['sites'].items():
        target(key)
        if (not isinstance(rules, dict) or set(rules) != {'missing_files', 'suspicious_queries'}
                or any(type(value) is not bool for value in rules.values())):
            raise ValueError('Domain owners may select trigger categories only')
    return validate_rules(data)


def validate_agents(entries):
    if not isinstance(entries, list) or len(entries) > 200:
        raise ValueError('Use at most 200 entries per User-Agent list')
    agents = []
    for entry in entries:
        # Printable ASCII keeps the literal substring behavior explicit across
        # Nginx/PCRE builds. Quotes, regex and config punctuation are escaped.
        if (not isinstance(entry, str) or not 2 <= len(entry.strip()) <= 160 or
                any(ord(c) < 32 or ord(c) > 126 for c in entry)):
            raise ValueError('User-Agents must be printable text, 2–160 characters per line')
        entry = entry.strip()
        if entry.lower() not in [x.lower() for x in agents]:
            agents.append(entry)
    return agents


def validate_rules(data):
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
    ids = set()
    for module in ('filters', 'static'):
        if not isinstance(data[module], list) or len(data[module]) > 20:
            raise ValueError('Use at most 20 rules per module')
        for rule in data[module]:
            fields = {'id', 'enabled', 'path', 'targets'} | (
                {'parameters', 'agents', 'action', 'rate', 'burst'} if module == 'filters' else {'extensions'})
            if not isinstance(rule, dict) or set(rule) != fields:
                raise ValueError('Invalid ' + module + ' rule fields')
            ident = rule['id']
            if not isinstance(ident, str) or not re.fullmatch(r'[a-z][a-z0-9_]{0,31}', ident) or ident in ids:
                raise ValueError('Rule IDs must be unique lowercase names, up to 32 characters')
            ids.add(ident)
            if type(rule['enabled']) is not bool:
                raise ValueError('Invalid rule switch')
            path = rule['path']
            if (not isinstance(path, str) or not re.fullmatch(r'/[A-Za-z0-9_./~-]*', path) or
                    '..' in path.split('/') or '//' in path or len(path) > 250):
                raise ValueError('Enter a literal URL path, without query, wildcard or traversal')
            if module == 'static' and (path == '/' or not path.endswith('/')):
                raise ValueError('Static directories must end in / and cannot be the site root')
            if not isinstance(rule['targets'], list) or len(rule['targets']) > 10000:
                raise ValueError('Invalid rule domain selection')
            rule['targets'] = list(dict.fromkeys(target(x) for x in rule['targets']))
            if module == 'filters':
                if rule['action'] not in ('limit', 'block'):
                    raise ValueError('Choose limit or block for filtered URLs')
                if (type(rule['rate']) is not int or not 1 <= rule['rate'] <= 600 or
                        type(rule['burst']) is not int or not 0 <= rule['burst'] <= 100):
                    raise ValueError('Rates must be 1–600 per minute; burst must be 0–100')
                if not isinstance(rule['parameters'], list) or not 1 <= len(rule['parameters']) <= 20:
                    raise ValueError('Enter 1–20 filter parameter names')
                if any(not isinstance(x, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,63}', x)
                       for x in rule['parameters']):
                    raise ValueError('Invalid filter parameter name')
                rule['parameters'] = list(dict.fromkeys(x.lower() for x in rule['parameters']))
                if (not isinstance(rule['agents'], list) or not 1 <= len(rule['agents']) <= 40 or
                        any(not isinstance(x, str) or not 2 <= len(x) <= 100 or
                            any(ord(c) < 32 or ord(c) > 126 for c in x) for x in rule['agents'])):
                    raise ValueError('Enter 1–40 literal crawler names for a filter rule')
                rule['agents'] = list(dict.fromkeys(x.lower() for x in rule['agents']))
            else:
                if (not isinstance(rule['extensions'], list) or not 1 <= len(rule['extensions']) <= 20 or
                        any(not isinstance(x, str) or not re.fullmatch(r'[a-z0-9]{1,10}', x)
                            for x in rule['extensions'])):
                    raise ValueError('Enter 1–20 lowercase static file extensions, without dots')
                rule['extensions'] = list(dict.fromkeys(rule['extensions']))
    exceptions = data['static_exceptions']
    if not isinstance(exceptions, dict) or len(exceptions) > 10000:
        raise ValueError('Invalid static-file exceptions')
    normalized, count, size = {}, 0, 0
    for site, paths in exceptions.items():
        target(site)
        if not isinstance(paths, list) or len(paths) > 500:
            raise ValueError('Use at most 500 file exceptions per domain')
        paths = list(dict.fromkeys(exception_path(path) for path in paths))
        if paths:
            normalized[site] = paths
            count += len(paths)
            size += sum(len((site.split('/', 1)[1] + ':' + unquote(path)).encode('utf-8')) for path in paths)
    if count > 2000 or size > 65536:
        raise ValueError('Use at most 2000 file exceptions and 64 KiB of exception entries in total')
    data['static_exceptions'] = normalized
    return data


def exception_path(value):
    """Canonical URL-encoded representation; decode exactly once when compiling."""
    if not isinstance(value, str) or not value.startswith('/') or re.search(r'%(?![0-9A-Fa-f]{2})', value):
        raise ValueError('File exceptions must be URL paths starting with /, one per line')
    try:
        decoded = unquote(value, encoding='utf-8', errors='strict')
    except UnicodeError as error:
        raise ValueError('File exceptions must contain valid UTF-8 URL paths') from error
    if (len(decoded.encode('utf-8')) > 2048 or decoded.endswith('/') or '//' in decoded or
            any(part in ('.', '..') for part in decoded.split('/')) or
            any(char in decoded for char in '?#*\\') or not decoded.isprintable()):
        raise ValueError('Enter exact file paths without query strings, wildcards or traversal')
    return quote(decoded, safe='/-._~$&()+,;=:@')


def exact_uri_pattern(value):
    return '"~^' + ''.join(r'\\x' + format(byte, '02x') for byte in value.encode('utf-8')) + '$"'


def literal_regex(value):
    """A PCRE literal inside one Nginx double-quoted config token."""
    # Hex every byte: neither Nginx config interpolation nor PCRE metacharacters
    # can reinterpret an administrator's literal text. Nginx consumes one of
    # the two backslashes before PCRE receives each \xHH escape.
    return '"~*' + ''.join(r'\\x' + format(ord(c), '02x') for c in value) + '"'


def pattern(value):
    """Quote only compiler-created PCRE expressions, never administrator regex."""
    return '"~*' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


def applies(rule, site):
    return rule['enabled'] and (not rule['targets'] or site['key'] in rule['targets'])


def path_pattern(value):
    return '^' if value == '/' else '^' + re.escape(value.rstrip('/')) + '(?:/|$)'


def parameter_pattern(value):
    # Also recognize percent-encoded ASCII parameter names, not just literal ones.
    return ''.join('(?:' + re.escape(c) + '|%' + format(ord(c), '02x') + ')' for c in value)


def scope_map(variable, rule, sites):
    names = sorted({s.get('domain', s['key'].split('/', 1)[1]) for s in sites
                    if applies(rule, s) and s.get('supported', True) and not s.get('suspended')})
    return ['map $server_name $' + variable + ' {', '    default 0;'] + [
        '    ' + domain(name) + ' 1;' for name in names] + ['}']


def site_mode(policy, site):
    return policy['overrides'].get(site['key'], policy['mode']) if not site.get('suspended') else 'off'


def global_config(policy, sites, domain_blocks=None):
    policy = validate(policy)
    # Declare a safe mode even on a new server with no domains yet. Supported
    # virtual hosts set this changeable variable during their rewrite phase.
    lines = [MARKER]
    block_variables = []
    known = {site['key']: site for site in sites if site.get('supported', True) and not site.get('suspended')}
    for key, addresses in sorted((domain_blocks or {}).items()):
        if key not in known or site_mode(policy, known[key]) != 'enforce' or not addresses:
            continue
        name = 'hdn_domain_' + hashlib.sha256(key.encode()).hexdigest()[:16]
        lines += ['geo $remote_addr $' + name + ' {', '    default 0;']
        for address in sorted(addresses):
            ip = ipaddress.ip_address(address)
            lines += ['    ' + str(ip) + ('/32' if ip.version == 4 else '/128') + ' 1;']
        lines += ['}']
        block_variables.append((domain(known[key].get('domain', key.split('/', 1)[1])), name))
    lines += ['map $server_name $hdn_domain_blocked {', '    default 0;']
    lines += ['    ' + host + ' $' + name + ';' for host, name in block_variables]
    lines += ['}', 'map $server_name $hdn_mode { default off; }',
             'map $http_user_agent $hdn_agent {', '    default 0;']
    entries = (policy['agents'] if policy['agents_enabled'] else []) + (policy['tool_agents'] if policy['tool_agents_enabled'] else [])
    lines += ['    ' + literal_regex(entry) + ' 1;' for entry in dict.fromkeys(entries)]
    lines += ['}', 'map $uri $hdn_private {', '    default 0;']
    if policy['scanners']:
        lines += ['    ' + pattern(p) + ' 1;' for _, p in PRIVATE_PATTERNS]
    lines += ['}']
    lines += ['map $uri $hdn_ban_signal {', '    default "";']
    for signal, regex in PRIVATE_PATTERNS:
        if policy['bans']['enabled'] and ((signal == 'private-file' and policy['bans']['private_files']) or
                                          (signal == 'repository' and policy['bans']['repositories'])):
            lines += ['    ' + pattern(regex) + ' ' + signal + ';']
    lines += ['}']
    lines += scope_map('hdn_ban_site', policy['bans'], sites)
    lines += ['map "$hdn_mode:$hdn_ban_site:$hdn_ban_signal" $hdn_direct_reject {',
              '    default 0;', '    ~^enforce:1:(private-file|repository)$ 1;', '}']
    lines += probe_rules.compile_maps(policy, sites, pattern, exact_uri_pattern)
    lines += ['map "$server_name:$uri" $hdn_static_exempt {', '    default 0;']
    for site in sites:
        if site.get('supported', True) and not site.get('suspended'):
            name = domain(site.get('domain', site['key'].split('/', 1)[1]))
            lines += ['    ' + exact_uri_pattern(name + ':' + unquote(path)) + ' 1;'
                      for path in policy['static_exceptions'].get(site['key'], [])]
    lines += ['}']
    block_variables = []
    for index, rule in enumerate(policy['filters']):
        tag = 'hdn_f' + str(index)
        lines += scope_map(tag + '_site', rule, sites)
        lines += ['map $uri $' + tag + '_path {', '    default 0;',
                  '    ' + pattern(path_pattern(rule['path'])) + ' 1;', '}']
        args = '(?:^|&)(?:' + '|'.join(parameter_pattern(x) for x in rule['parameters']) + ')(?:=|&|$)'
        lines += ['map $args $' + tag + '_arg {', '    default 0;', '    ' + pattern(args) + ' 1;', '}']
        lines += ['map $http_user_agent $' + tag + '_agent {', '    default "";']
        lines += ['    ' + literal_regex(agent) + ' a' + hashlib.sha256(agent.encode()).hexdigest()[:12] + ';' for agent in rule['agents']]
        lines += ['}', 'map "$hdn_mode:$' + tag + '_site:$' + tag + '_path:$' + tag + '_arg:$' + tag + '_agent" $' + tag + '_key {',
                  '    default "";', '    ' + pattern('^(observe|enforce):1:1:1:a[0-9a-f]+$') + ' "$server_name:' + rule['id'] + ':$' + tag + '_agent";', '}']
        if rule['action'] == 'limit':
            lines += ['limit_req_zone $' + tag + '_key zone=' + tag + ':10m rate=' + str(rule['rate']) + 'r/m;']
        block_variables.append((tag + '_key', 'filter-' + rule['action'] + '-' + rule['id']))
    for index, (variable, label) in enumerate(block_variables):
        lines += ['map $' + variable + ' $hdn_b' + str(index) + ' {', '    default ' + label + ';', '    "" "";', '}']
    static = []
    for index, rule in enumerate(policy['static']):
        tag = 'hdn_s' + str(index)
        lines += scope_map(tag + '_site', rule, sites)
        regex = '^' + re.escape(rule['path']) + '.*\\.(?:' + '|'.join(rule['extensions']) + ')$'
        lines += ['map "$hdn_mode:$' + tag + '_site:$hdn_static_exempt:$request_method:$uri" $' + tag + '_candidate {', '    default "";',
                  '    ' + pattern('^(observe|enforce):1:0:(GET|HEAD):' + regex[1:]) + ' static-' + rule['id'] + ';', '}']
        static.append('$' + tag + '_candidate')
    lines += ['map "' + ':'.join(static) + '" $hdn_static_candidate {', '    default "";']
    for rule in policy['static']:
        label = 'static-' + rule['id']
        lines += ['    ' + pattern('(?:^|:)' + label + '(?:$|:)') + ' ' + label + ';']
    lines += ['}', 'map "$hdn_direct_reject:$hdn_private:$hdn_agent:' + ':'.join('$hdn_b' + str(i) for i in range(len(block_variables))) + ':$hdn_static_candidate:$hdn_login_label:$hdn_xmlrpc_label:$hdn_probe_query:$hdn_probe_file" $hdn_match_base {',
              '    default "";', '    ' + pattern('^1:') + ' private-file;',
              '    ' + pattern('^[01]:1:') + ' private-file;',
              '    ' + pattern('^[01]:[01]:1:') + ' agent;']
    lines += ['    ' + pattern(':q[0-9a-f]{16}:') + ' suspicious-query;', '    ' + pattern(':f[0-9a-f]{16}$') + ' missing-file;']
    for _, label in block_variables:
        lines += ['    ' + pattern('(?:^|:)' + label + '(?:$|:)') + ' ' + label + ';']
    for rule in policy['static']:
        label = 'static-' + rule['id']
        lines += ['    ' + pattern('(?:^|:)' + label + '(?:$|:)') + ' ' + label + ';']
    lines += ['    ' + pattern('(?:^|:)login(?:$|:)') + ' login;',
              '    ' + pattern('(?:^|:)xmlrpc(?:$|:)') + ' xmlrpc;']
    lines += ['}', 'map "$hdn_domain_blocked:$hdn_match_base" $hdn_match {',
              '    default $hdn_match_base;', '    ~^1: domain-ban;', '}',
              'map $hdn_match $hdn_block {', '    default 0;', '    private-file 1;',
              '    agent 1;', '    ~^filter-block- 1;', '}',
              'map "$hdn_mode:$hdn_static_candidate" $hdn_static_reject {', '    default 0;', '    ~^enforce:static- 1;', '}',
              # Separate observation log: no IP, URI, query, header or agent.
              'log_format hdn "$time_iso8601 $server_name $hdn_match $limit_req_status $status $hdn_mode";',
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
        lines += ['map $hdn_' + key + '_key $hdn_' + key + '_label {',
                  '    default ' + key + ';', '    "" "";', '}']
        if policy[key]['enabled']:
            lines.append('limit_req_zone $hdn_' + key + '_key zone=hdn_' + key + ':10m rate=' + str(policy[key]['rate']) + 'r/m;')
    return '\n'.join(lines) + '\n'


def site_config(policy, site, document_root=None):
    mode = site_mode(policy, site)
    lines = [MARKER, 'set $hdn_mode ' + mode + ';']
    if mode == 'enforce':
        lines += ['if ($hdn_domain_blocked) { return 403; }']
    local = policy['domain_bans']['sites'].get(site['key'], {})
    if mode != 'off' and ((policy['bans']['enabled'] and policy['bans']['missing_files']['enabled']) or local.get('missing_files')):
        if not document_root or not re.fullmatch(r'/[A-Za-z0-9_./-]+', document_root) or '..' in document_root.split('/'):
            raise ValueError('PHP probe protection needs one literal document root: ' + site['key'])
        lines += ['set $hdn_probe_filename "";',
                  'if ($hdn_probe_file != "") { set $hdn_probe_filename "' + document_root.rstrip('/') + '$uri"; }',
                  'if (-f $hdn_probe_filename) { set $hdn_probe_file ""; }']
    if mode != 'off' and any(applies(rule, site) for rule in policy['static']):
        if not document_root or not re.fullmatch(r'/[A-Za-z0-9_./-]+', document_root) or '..' in document_root.split('/'):
            raise ValueError('Static-file rules need one literal document root in the existing template: ' + site['key'])
        lines += ['set $hdn_static_file "";',
                  'if ($hdn_static_candidate != "") { set $hdn_static_file "' + document_root.rstrip('/') + '$uri"; }',
                  'if (-f $hdn_static_file) { set $hdn_static_candidate ""; }']
    if mode == 'enforce':
        lines += ['if ($hdn_direct_reject) { return 403; }', 'if ($hdn_block) { return 403; }',
                  'if ($hdn_probe_query != "") { return 404; }', 'if ($hdn_probe_file != "") { return 404; }',
                  'if ($hdn_static_reject) { return 404; }']
    for key in ('login', 'xmlrpc'):
        if policy[key]['enabled']:
            burst = policy[key]['burst']
            lines.append('limit_req zone=hdn_' + key + ((' burst=' + str(burst) + ' nodelay') if burst else '') + ';')
    rate_rules = [rule for rule in policy['filters'] if rule['action'] == 'limit' and applies(rule, site)]
    for index, rule in enumerate(policy['filters']):
        if rule['action'] == 'limit' and applies(rule, site):
            lines.append('limit_req zone=hdn_f' + str(index) + ((' burst=' + str(rule['burst']) + ' nodelay') if rule['burst'] else '') + ';')
    if any(policy[key]['enabled'] for key in ('login', 'xmlrpc')) or rate_rules:
        lines += ['limit_req_status 429;', 'limit_req_dry_run ' + ('off' if mode == 'enforce' else 'on') + ';']
    lines += ['access_log /var/log/hestia-de-noise/matches.log hdn if=$hdn_log;']
    if policy['bans']['enabled']:
        lines += ['access_log /var/log/hestia-de-noise/ban-events.log hdn_bans if=$hdn_autoban_log;']
    if any(local.values()):
        lines += ['access_log /var/log/hestia-de-noise/ban-events.log hdn_domain_bans if=$hdn_domain_autoban_log;']
    return '\n'.join(lines) + '\n'
