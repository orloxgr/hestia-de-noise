"""Per-domain native Nginx administration gates. No WordPress request worker."""
import copy
import hashlib
import re
import subprocess
from pathlib import Path

SETTINGS = 'access.json'
DIRECTORY = Path('/etc/nginx/hestia-de-noise-access')
DEFAULT = {'enabled': False, 'bypass_internal': True, 'username': 'wp', 'password_hash': '',
           'country': {'enabled': False, 'scope': 'admin', 'mode': 'deny',
                       'countries': [], 'allow_unknown': True}}
# Match complete path segments, including installations below a URL prefix.
ADMIN = r'^/(?:[^/]+/)*(?:wp-login\.php(?:/.*)?|wp-admin(?:/.*)?)$'
EXEMPT = r'^/(?:[^/]+/)*wp-admin/(?:admin-ajax\.php|admin-post\.php|js/password-strength-meter(?:\.min)?\.js)$'


def identifier(key):
    return hashlib.sha256(key.encode()).hexdigest()[:24]


def validate(value, target):
    if not isinstance(value, dict) or set(value) != {'sites'} or not isinstance(value['sites'], dict):
        raise ValueError('Invalid domain access settings')
    result = copy.deepcopy(value)
    for key, entry in result['sites'].items():
        target(key)
        if not isinstance(entry, dict) or set(entry) != set(DEFAULT):
            raise ValueError('Invalid domain access controls')
        if any(type(entry[k]) is not bool for k in ('enabled', 'bypass_internal')):
            raise ValueError('Access switches must be booleans')
        if not isinstance(entry['username'], str) or not re.fullmatch(r'[A-Za-z0-9_.@-]+', entry['username']):
            raise ValueError('Use a nonempty HTTP username containing letters, numbers, _, ., @ or -')
        hashed = entry['password_hash']
        if not isinstance(hashed, str) or hashed and not re.fullmatch(r'\$6\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{86}', hashed):
            raise ValueError('Invalid saved HTTP password hash')
        if entry['enabled'] and not hashed:
            raise ValueError('Set an HTTP password before enabling administration protection')
        country = entry['country']
        if not isinstance(country, dict) or set(country) != set(DEFAULT['country']):
            raise ValueError('Invalid country controls')
        if any(type(country[k]) is not bool for k in ('enabled', 'allow_unknown')):
            raise ValueError('Country switches must be booleans')
        if country['scope'] not in ('admin', 'site') or country['mode'] not in ('allow', 'deny'):
            raise ValueError('Select a country scope and allow/deny policy')
        if not isinstance(country['countries'], list) or any(
                not isinstance(c, str) or not re.fullmatch(r'[A-Z]{2}', c) or c == 'ZZ'
                for c in country['countries']):
            raise ValueError('Use two-letter country codes, for example GR and CY')
        country['countries'] = sorted(set(country['countries']))
        if country['enabled'] and not country['countries']:
            raise ValueError('Select at least one country before enabling the country filter')
    return result


def password_hash(password):
    if not isinstance(password, str) or not password or any(c in password for c in '\x00\r\n'):
        raise ValueError('Enter a nonempty HTTP password without line breaks')
    # The plaintext travels only over stdin, never in process arguments or logs.
    result = subprocess.run(['/usr/bin/openssl', 'passwd', '-6', '-stdin'],
                            input=password + '\n', text=True, capture_output=True)
    if result.returncode or not result.stdout.startswith('$6$'):
        raise ValueError('Could not hash the HTTP password with OpenSSL')
    return result.stdout.strip()


def public(settings, visible):
    return {key: {**{k: copy.deepcopy(v) for k, v in entry.items() if k != 'password_hash'},
                  'password_set': bool(entry['password_hash'])}
            for key, entry in settings['sites'].items() if key in visible}


def compile_maps(settings, sites, pattern, geo_path=None):
    entries = [(s, settings['sites'][s['key']]) for s in sites
               if s.get('supported', True) and not s.get('suspended') and s.get('kind') != 'mail'
               and s['key'] in settings['sites'] and (settings['sites'][s['key']]['enabled']
                    or settings['sites'][s['key']]['country']['enabled'])]
    if not entries:
        return []
    lines = ['map $uri $hdn_admin_path {', '    default 0;',
             '    ' + pattern(EXEMPT) + ' 0;', '    ' + pattern(ADMIN) + ' 1;', '}']
    lines += ['map $uri $hdn_acme_path { default 0; ~^/\\.well-known/acme-challenge/ 1; }']
    if any(e['country']['enabled'] for _, e in entries):
        if not geo_path:
            raise ValueError('Download the country database before enabling a country filter')
        lines += ['geo $remote_addr $hdn_country {', '    default ZZ;',
                  '    include ' + str(geo_path) + ';', '}']
    else:
        lines += ['map $remote_addr $hdn_country { default ZZ; }']
    basic, countries = [], []
    for site, entry in entries:
        tag = 'ha' + identifier(site['key'])
        # Origin includes scheme, exact hostname and port; same-site is not same-origin.
        hosts = [site.get('domain', site['key'].split('/', 1)[1])]
        hosts += site.get('aliases', '').split(',')
        hosts = [h.strip() for h in hosts if h.strip()]
        origin_checks = []
        for host in hosts:
            origin_checks.append(re.escape(host) + r':https:https://' + re.escape(host) + r'(?::443)?(?:/|$)')
            origin_checks.append(re.escape(host) + r':http:http://' + re.escape(host) + r'(?::80)?(?:/|$)')
        lines += ['map "$host:$scheme:$http_referer" $' + tag + '_r {', '    default 0;']
        lines += ['    ' + pattern('^' + check) + ' 1;' for check in origin_checks]
        lines += ['}',
                  'map "$http_sec_fetch_site:$' + tag + '_r" $' + tag + '_i {',
                  '    default 0;', '    ~^same-origin:[01]$ 1;', '    ":1" 1;', '}']
        enabled = '1' if entry['enabled'] else '0'
        bypass = '1' if entry['bypass_internal'] else '0'
        lines += ['map "' + enabled + ':$hdn_admin_path:' + bypass + ':$' + tag + '_i" $' + tag + '_b {',
                  '    default 0;', '    ~^1:1:(0:[01]|1:0)$ 1;', '}',
                  'map "$hdn_mode:$' + tag + '_b" $' + tag + '_a {',
                  '    default off;', '    "enforce:1" "WordPress administration";', '}']
        country = entry['country']
        lines += ['map $hdn_country $' + tag + '_cm {', '    default ' + ('1' if country['mode'] == 'allow' else '0') + ';']
        lines += ['    ' + c + ' ' + ('0' if country['mode'] == 'allow' else '1') + ';' for c in country['countries']]
        lines += ['    ZZ ' + ('0' if country['allow_unknown'] else '1') + ';', '}']
        scope = '$hdn_admin_path' if country['scope'] == 'admin' else '1'
        lines += ['map "' + ('1' if country['enabled'] else '0') + ':' + scope + ':$' + tag + '_cm:$hdn_acme_path" $' + tag + '_c {',
                  '    default 0;', '    "1:1:1:0" 1;', '}']
        host = site.get('domain', site['key'].split('/', 1)[1])
        basic.append('    ' + host + ' $' + tag + '_b;')
        countries.append('    ' + host + ' $' + tag + '_c;')
    lines += ['map $server_name $hdn_access_basic {', '    default 0;', *basic, '}',
              'map $server_name $hdn_access_country {', '    default 0;', *countries, '}',
              'map "$hdn_mode:$hdn_access_country:$hdn_access_basic:$status:$upstream_status" $hdn_access_event {',
              '    default "";', '    ~^observe:1: country-filter;', '    ~^enforce:1:[01]:403:(-|)$ country-filter;',
              '    ~^observe:0:1: wordpress-access;', '    ~^enforce:0:1:401:(-|)$ wordpress-access;', '}',
              'map $hdn_access_event $hdn_access_log { default 1; "" 0; }',
              'log_format hdn_access escape=json \'$time_iso8601 $server_name $hdn_access_event - $status $hdn_mode\\t"$http_user_agent"\';']
    return lines


def site_lines(settings, site, mode):
    entry = settings['sites'].get(site['key'])
    if not entry or mode == 'off' or site.get('kind') == 'mail':
        return []
    tag = 'ha' + identifier(site['key'])
    lines = []
    if entry['enabled']:
        lines += ['auth_basic $' + tag + '_a;',
                  'auth_basic_user_file ' + str(DIRECTORY / (identifier(site['key']) + '.htpasswd')) + ';']
    if entry['country']['enabled'] and mode == 'enforce':
        lines += ['if ($' + tag + '_c) { return 403; }']
    if entry['enabled'] or entry['country']['enabled']:
        lines += ['access_log /var/log/hestia-de-noise/matches.log hdn_access if=$hdn_access_log;']
    return lines
