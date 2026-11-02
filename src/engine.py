"""Hestia discovery and journaled Nginx configuration transactions."""
from contextlib import contextmanager
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

from policy import (DEFAULT, VERSION, SCANNER_AGENTS, CRAWLER_AGENTS, FILTER_AGENTS,
                    account, domain, validate, site_mode, global_config, site_config)
import activity
import auto_bans
from presets import RULES
import storage
import probe_rules
import cron_spread
import domain_bans
import wordpress

HESTIA = Path('/usr/local/hestia')
STATE = Path('/var/lib/hestia-de-noise')
GLOBAL = Path('/etc/nginx/conf.d/00-hestia-de-noise.conf')
COMMAND_ENV = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
               'LANG': 'C.UTF-8', 'HESTIA': str(HESTIA)}


def run(*args, timeout=90):
    result = subprocess.run(args, env=COMMAND_ENV, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError('Command failed (' + str(result.returncode) + '): ' + ' '.join(args) +
                           '\n' + (result.stderr or result.stdout)[-6000:].strip())
    return result.stdout


def hestia(command, *args):
    return json.loads(run(str(HESTIA / 'bin' / command), *args, 'json'))


def config_paths(owner, name):
    account(owner); domain(name)
    directory = Path('/home') / owner / 'conf/web' / name
    return [directory / 'nginx.conf_hdn', directory / 'nginx.ssl.conf_hdn']


def managed_path(value):
    path = Path(value)
    if path == GLOBAL:
        return path
    match = re.fullmatch(r'/home/([^/]+)/conf/web/([^/]+)/nginx\.(?:ssl\.)?conf_hdn', str(path))
    if not match:
        raise ValueError('Invalid managed path in transaction')
    account(match[1]); domain(match[2])
    return path


def inspect_site(site):
    site = copy.deepcopy(site)
    site['paths'] = []
    site['roots'] = {}
    site['supported'] = False
    site['reason'] = ''
    if not site['template']:
        site['reason'] = 'No Nginx proxy template'
        return site
    for destination in config_paths(site['owner'], site['domain']):
        base = destination.with_name(destination.name.removesuffix('_hdn'))
        try:
            raw = storage.read(base)
            if raw is None:
                if base.name == 'nginx.conf':
                    site['reason'] = 'HTTP proxy configuration is missing'
                    return site
                continue
            text = raw.decode('utf-8')
            roots = set(re.findall(r'^\s*root\s+(/[A-Za-z0-9_./-]+)\s*;', text, re.M))
            if len(roots) == 1:
                site['roots'][str(destination)] = roots.pop()
            include = 'include ' + str(base) + '_*;'
            quoted = 'include "' + str(base) + '_*";'
            if include not in text and quoted not in text:
                site['reason'] = 'Template has no native per-domain include point'
                return site
            if re.search(r'^\s*limit_req(?:_dry_run|_status)?\s', text, re.M):
                site['reason'] = 'Template already sets request limits; kept unchanged'
                return site
            # Independently managed snippets may define these directives too.
            # Refuse rather than silently override their protection/inheritance.
            for sibling in base.parent.glob(base.name + '_*'):
                if sibling.name == destination.name:
                    continue
                fragment = storage.read_hestia_include(sibling)
                if fragment and re.search(rb'^\s*limit_req(?:_dry_run|_status)?\s', fragment, re.M):
                    site['reason'] = 'Another domain include defines request limits; kept unchanged'
                    return site
            storage.owned(destination)
            site['paths'].append(str(destination))
        except (OSError, ValueError, UnicodeError) as error:
            site['reason'] = str(error)
            return site
    site['supported'] = bool(site['paths'])
    return site


def collect():
    sites = []
    users = hestia('v-list-users')
    for owner, user in sorted(users.items()):
        account(owner)
        for name, row in sorted(hestia('v-list-web-domains', owner).items()):
            domain(name)
            sites.append(inspect_site({'key': owner + '/' + name, 'owner': owner, 'domain': name,
                                      'template': row.get('PROXY', ''),
                                      'aliases': row.get('ALIAS', ''),
                                      'suspended': user.get('SUSPENDED') == 'yes' or row.get('SUSPENDED') == 'yes'}))
    return sites


def load(name, default):
    raw = storage.read(STATE / name)
    return json.loads(raw) if raw is not None else copy.deepcopy(default)


@contextmanager
def locked():
    import fcntl
    storage.private_directory(STATE)
    fd = os.open(STATE / 'operation.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        if os.fstat(fd).st_uid != 0:
            raise ValueError('Operation lock must belong to root')
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def verify(paths):
    # -T both syntax-checks and proves that the installed snippets are actually
    # included by the running distribution's Nginx configuration structure.
    dump = run('/usr/sbin/nginx', '-T')
    for path in paths:
        if '# configuration file ' + str(path) + ':' not in dump:
            raise RuntimeError('Nginx does not load the expected include: ' + str(path))


def reload_nginx():
    master = run('/usr/bin/systemctl', 'show', 'nginx', '-p', 'MainPID', '--value').strip()
    if not re.fullmatch(r'[1-9][0-9]*', master):
        raise RuntimeError('The native Nginx service has no running master process')

    def workers():
        try:
            children = Path('/proc/' + master + '/task/' + master + '/children').read_text().split()
        except FileNotFoundError:
            return set()
        active = set()
        for child in children:
            try:
                command = Path('/proc/' + child + '/cmdline').read_bytes()
            except FileNotFoundError:
                continue
            if b'nginx: worker process' in command and b'shutting down' not in command:
                active.add(child)
        return active

    previous = workers()
    run('/usr/bin/systemctl', 'reload', 'nginx')
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        current = workers()
        if current and not current.intersection(previous):
            return
        time.sleep(.1)
    raise RuntimeError('Nginx did not start its new worker generation after reload')


def restore(record):
    for name, text in record['before'].items():
        path = managed_path(name)
        if not path.parent.exists() and text is None:
            continue
        storage.owned(path)
        storage.replace(path, None if text is None else text.encode())


def recover():
    record = load('transaction.json', None)
    if record is None:
        return
    if record.get('schema') != 1 or not isinstance(record.get('before'), dict):
        raise ValueError('Invalid pending transaction; refusing unsafe recovery')
    restore(record)
    run('/usr/sbin/nginx', '-t')
    reload_nginx()
    for name in ('policy.json', 'manifest.json', domain_bans.APPLIED):
        if name not in record:
            continue  # Recovery journals from an older installed generation.
        old = record[name]
        storage.replace(STATE / name, None if old is None else storage.json_bytes(old), 0o600)
    storage.replace(STATE / 'transaction.json', None)


def apply(policy, sites, remove=False):
    policy = validate(policy)
    if not remove:
        known = {site['key'] for site in sites}
        policy['overrides'] = {key: mode for key, mode in policy['overrides'].items() if key in known}
        policy['static_exceptions'] = {key: paths for key, paths in policy['static_exceptions'].items() if key in known}
        policy['domain_bans']['sites'] = {key: value for key, value in policy['domain_bans']['sites'].items() if key in known}
        for kind in ('files', 'queries'):
            policy['probe_exceptions'][kind] = {key: paths for key, paths in policy['probe_exceptions'][kind].items() if key in known}
    desired = {}
    domain_blocks = domain_bans.desired(policy, sites, STATE) if not remove else {}
    if not remove:
        desired[str(GLOBAL)] = global_config(policy, sites, domain_blocks)
        for site in sites:
            if site['supported']:
                for path in site['paths']:
                    desired[path] = site_config(policy, site, site.get('roots', {}).get(path))
    manifest = load('manifest.json', [])
    old_paths = {str(managed_path(name)) for name in manifest}
    before, changes = {}, {}
    for name in sorted(old_paths | set(desired)):
        path = managed_path(name)
        if not path.parent.exists() and name not in desired:
            continue  # A domain deleted through Hestia is authoritative.
        current = storage.owned(path)
        text = None if current is None else current.decode()
        next_text = desired.get(name)
        if text != next_text:
            before[name] = text
            changes[name] = next_text
    # Preserve policy + ownership manifest in the same recovery journal. A
    # crash after reload but before state commit restores the old policy too.
    record = {'schema': 1, 'before': before,
              'policy.json': load('policy.json', None), 'manifest.json': load('manifest.json', None),
              domain_bans.APPLIED: load(domain_bans.APPLIED, None)}
    storage.replace(STATE / 'transaction.json', storage.json_bytes(record), 0o600)
    try:
        for name, text in changes.items():
            storage.replace(name, None if text is None else text.encode())
        verify(desired)
        if changes:
            reload_nginx()
        storage.replace(STATE / 'manifest.json', storage.json_bytes(sorted(desired)), 0o600)
        storage.replace(STATE / 'policy.json', storage.json_bytes(policy), 0o600)
        storage.replace(STATE / domain_bans.APPLIED, storage.json_bytes(domain_blocks), 0o600)
        storage.replace(STATE / 'transaction.json', None)
    except Exception as error:
        try:
            recover()
        except Exception as rollback:
            raise RuntimeError(str(error) + '\nRecovery also failed: ' + str(rollback) +
                               '\nThe recovery journal has been retained.') from error
        raise
    return {'changed_files': len(changes), 'sites': len(sites),
            'supported_sites': sum(s['supported'] for s in sites)}


def snapshot(policy, sites, owner=None, wordpress_live=False):
    rows = []
    for site in sites:
        if owner is not None and site['owner'] != owner:
            continue
        rows.append({**{key: site[key] for key in ('key', 'owner', 'domain', 'template', 'aliases',
                                                   'suspended', 'supported', 'reason')},
                     'mode': site_mode(policy, site),
                     'override': policy['overrides'].get(site['key'], 'inherit')})
    try:
        metrics = activity.summary({row['domain'] for row in rows})
    except (OSError, ValueError) as error:
        metrics = {'available': False, 'error': str(error)}
    ban_status = {}
    if owner is None:
        try:
            ban_status = auto_bans.report(STATE, policy['bans']['enabled'])
        except (OSError, ValueError) as error:
            ban_status = {'error': str(error)}
    try:
        scoped = domain_bans.report(policy, sites, STATE, owner)
    except (OSError, ValueError) as error:
        scoped = {'active': 0, 'pending': 0, 'rows': [], 'error': str(error)}
    visible_keys = {row['key'] for row in rows}
    scoped['preferences'] = {key: value for key, value in policy['domain_bans']['sites'].items() if key in visible_keys}
    scoped['can_edit'] = owner is None or policy['domain_bans']['allow_users']
    scoped['limits'] = {key: {name: policy['bans'][key][name] for name in ('maxretry', 'findtime', 'duration_days')}
                       for key in ('missing_files', 'suspicious_queries', 'any_404')}
    wordpress_status = None
    if owner is None:
        try:
            wordpress_status = wordpress.snapshot(STATE, run, live=wordpress_live)
        except (OSError, ValueError) as error:
            wordpress_status = {'settings': wordpress.DEFAULT, 'loaded': wordpress_live, 'error': str(error)}
    return {'ok': True, 'version': VERSION, 'policy': policy if owner is None else {'mode': policy['mode']},
            'sites': rows, 'activity': metrics,
            'bans': ban_status,
            'domain_bans': scoped,
            'wordpress': wordpress_status,
            'cron': cron_spread.public(load('cron-spread.json', None)) if owner is None else None,
            'presets': {'scanners': SCANNER_AGENTS, 'crawlers': CRAWLER_AGENTS,
                        'filter_agents': FILTER_AGENTS, 'rules': RULES,
                        'probe_files': probe_rules.FILES, 'probe_queries': probe_rules.QUERY_TARGETS,
                        'probe_parameters': probe_rules.QUERY_PARAMETERS} if owner is None else {}}


def authorize(request):
    actor = account(request.get('actor'))
    user = hestia('v-list-user', actor).get(actor, {})
    if user.get('SUSPENDED') != 'no':
        raise PermissionError('Account is suspended or unavailable')
    admin = user.get('ROLE') == 'admin'
    owner = account(request.get('owner', actor))
    if not admin and owner != actor:
        raise PermissionError('Another account cannot be selected')
    if request.get('action') not in ('status', 'domain_bans_save') and not admin:
        raise PermissionError('Only an administrator can change De-Noise settings')
    return admin, owner


def dispatch(request):
    if not isinstance(request, dict):
        raise ValueError('Expected a JSON object')
    admin, owner = authorize(request)
    action = request.get('action')
    policy = validate(load('policy.json', DEFAULT))
    sites = collect()
    if action == 'wordpress_save':
        if set(request) - {'actor', 'owner', 'action', 'settings'}:
            raise ValueError('Only WordPress protection settings can be submitted')
        wordpress.apply(STATE, request.get('settings'), run)
    elif action == 'wordpress_unban':
        wordpress.unban(STATE, request.get('ips'), run)
    elif action == 'wordpress_status':
        pass
    elif action == 'domain_bans_save':
        if set(request) - {'actor', 'owner', 'action', 'preferences'}:
            raise ValueError('Only domain trigger selections can be submitted')
        if not admin and not policy['domain_bans']['allow_users']:
            raise PermissionError('Domain automatic-ban editing is disabled by the administrator')
        preferences = request.get('preferences')
        if not isinstance(preferences, dict) or not preferences or len(preferences) > 10000:
            raise ValueError('Select existing domain automatic-ban settings')
        known = {site['key']: site for site in sites}
        for key, flags in preferences.items():
            if (key not in known or (not (admin and owner == request['actor']) and known[key]['owner'] != owner)):
                raise PermissionError('This domain does not belong to the selected account')
            if not known[key]['supported'] or known[key]['suspended']:
                raise ValueError('This domain is suspended or unsupported')
            if isinstance(flags, dict) and set(flags) == {'missing_files', 'suspicious_queries'}:
                # An already-open 0.5 panel cannot clear a newer switch.
                flags['any_404'] = policy['domain_bans']['sites'].get(key, {}).get('any_404', False)
            if (not isinstance(flags, dict) or set(flags) != {'missing_files', 'suspicious_queries', 'any_404'}
                    or any(type(value) is not bool for value in flags.values())):
                raise ValueError('Only domain trigger switches can be changed')
        for key, flags in preferences.items():
            if any(flags.values()):
                policy['domain_bans']['sites'][key] = flags
            else:
                policy['domain_bans']['sites'].pop(key, None)
        apply(policy, sites)
    elif action == 'cron_preview':
        plan = cron_spread.preview(hestia, request.get('minimum', 5), request.get('maximum', 15))
        storage.replace(STATE / 'cron-spread.json', storage.json_bytes(plan), 0o600)
    elif action == 'cron_apply':
        plan = load('cron-spread.json', None)
        if not plan or request.get('plan_id') != plan['id']:
            raise ValueError('Cron preview is missing or changed. Generate a new preview.')
        cron_spread.apply(plan, request.get('jobs'), hestia,
            lambda *args: run(str(HESTIA / 'bin/v-change-cron-job'), *args),
            lambda value: storage.replace(STATE / 'cron-spread.json', storage.json_bytes(value), 0o600),
            restore=request.get('restore') is True)
    elif action == 'save':
        # Keep overrides server-side; the global form cannot overwrite them.
        incoming = request.get('policy')
        if not isinstance(incoming, dict):
            raise ValueError('Expected policy settings')
        previous = policy
        if incoming.get('schema') in (6, 7):
            if not isinstance(incoming.get('domain_bans'), dict):
                raise ValueError('Invalid domain automatic-ban policy')
            incoming = {**incoming, 'domain_bans': {**incoming.get('domain_bans', {}),
                'sites': previous['domain_bans']['sites'] if incoming.get('schema') == 7 else {}}}
        policy = validate({**incoming, 'overrides': previous['overrides']})
        if incoming.get('schema') in (1, 2, 3, 4, 5, 6):
            policy['bans']['any_404'] = previous['bans']['any_404']
        if incoming.get('schema') == 6:
            policy['domain_bans']['sites'] = previous['domain_bans']['sites']
        if incoming.get('schema') in (1, 2, 3, 4, 5):
            policy['domain_bans'] = previous['domain_bans']
        if incoming.get('schema') in (1, 2):
            policy['static_exceptions'] = previous['static_exceptions']
        if incoming.get('schema') in (1, 2, 3):
            policy['bans'] = previous['bans']
            policy['tool_agents_enabled'] = previous['tool_agents_enabled']
            policy['agents_enabled'] = previous['agents_enabled']
        if incoming.get('schema') in (1, 2, 3, 4):
            for key in ('missing_files', 'suspicious_queries'):
                policy['bans'][key] = previous['bans'][key]
            policy['probe_exceptions'] = previous['probe_exceptions']
        if policy['bans']['enabled']:
            for command in ('v-add-firewall-chain', 'v-list-firewall-ban', 'v-add-firewall-ban', 'v-delete-firewall-ban'):
                if not (HESTIA / 'bin' / command).is_file():
                    raise ValueError('Automatic bans require native Hestia firewall commands: ' + command)
        apply(policy, sites)
    elif action == 'bulk':
        selection = request.get('targets')
        mode = request.get('mode')
        known = {s['key'] for s in sites}
        if (not isinstance(selection, list) or not selection or len(selection) > 10000 or
                any(not isinstance(x, str) or x not in known for x in selection) or
                mode not in ('inherit', 'off', 'observe', 'enforce')):
            raise ValueError('Select existing domains and a valid mode')
        for key in selection:
            if mode == 'inherit':
                policy['overrides'].pop(key, None)
            else:
                policy['overrides'][key] = mode
        apply(policy, sites)
    elif action == 'disable':
        policy['mode'] = 'off'; policy['overrides'] = {}
        apply(policy, sites)
        if wordpress.read_json(STATE, wordpress.RECEIPT) is not None:
            wordpress.apply(STATE, {**wordpress.settings(STATE), 'enabled': False}, run)
    elif action == 'sync':
        domain_bans.synchronize(policy, sites, STATE, auto_bans.Native(HESTIA, run))
        apply(policy, sites)
        result = auto_bans.synchronize(policy, sites, STATE, auto_bans.Native(HESTIA, run))
        if result.get('error'):
            raise RuntimeError('HTTP rules synchronized; automatic firewall bans failed: ' + result['error'])
    elif action == 'unban':
        auto_bans.unban(STATE, auto_bans.Native(HESTIA, run), request.get('ips'))
        result = auto_bans.synchronize(policy, sites, STATE, auto_bans.Native(HESTIA, run), read_events=False)
        if result.get('error'):
            raise RuntimeError('Unban is pending; native firewall operation failed: ' + result['error'])
    elif action != 'status':
        raise ValueError('Unsupported operation')
    return snapshot(policy, sites, None if admin and owner == request['actor'] else owner,
                    wordpress_live=action in ('wordpress_status', 'wordpress_save', 'wordpress_unban'))


def main():
    if os.geteuid() != 0:
        raise PermissionError('Invoke this command as root or through the Hestia panel')
    with locked():
        recover()
        wordpress.recover(STATE, run)
        if sys.argv[1:]:
            action = sys.argv[1:]
            if action not in (['sync'], ['disable'], ['status'], ['remove-rules']):
                raise ValueError('Commands: status, sync, disable, remove-rules')
            policy = validate(load('policy.json', DEFAULT))
            sites = collect()
            if action == ['disable']:
                policy['mode'] = 'off'; policy['overrides'] = {}
            if action != ['status']:
                if action == ['remove-rules']:
                    auto_bans.cleanup(policy, sites, STATE, auto_bans.Native(HESTIA, run))
                else:
                    domain_bans.synchronize(policy, sites, STATE, auto_bans.Native(HESTIA, run))
                result = apply(policy, sites, remove=action == ['remove-rules'])
                if action == ['disable'] and wordpress.read_json(STATE, wordpress.RECEIPT) is not None:
                    wordpress.apply(STATE, {**wordpress.settings(STATE), 'enabled': False}, run)
                if action != ['remove-rules']:
                    bans = auto_bans.synchronize(policy, sites, STATE, auto_bans.Native(HESTIA, run))
                    if bans.get('error'):
                        raise RuntimeError('HTTP rules synchronized; automatic firewall bans failed: ' + bans['error'])
                    result['bans'] = {key: value for key, value in bans.items() if key != 'rows'}
            else:
                result = snapshot(policy, sites)
        else:
            raw = sys.stdin.buffer.read(1048577)
            if len(raw) > 1048576:
                raise ValueError('Request too large')
            result = dispatch(json.loads(raw))
    return {'ok': True, **result}
