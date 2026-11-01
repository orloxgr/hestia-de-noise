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

from policy import DEFAULT, account, domain, validate, site_mode, global_config, site_config
import storage

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
    for name in ('policy.json', 'manifest.json'):
        old = record[name]
        storage.replace(STATE / name, None if old is None else storage.json_bytes(old), 0o600)
    storage.replace(STATE / 'transaction.json', None)


def apply(policy, sites, remove=False):
    policy = validate(policy)
    if not remove:
        known = {site['key'] for site in sites}
        policy['overrides'] = {key: mode for key, mode in policy['overrides'].items() if key in known}
    desired = {}
    if not remove:
        desired[str(GLOBAL)] = global_config(policy, sites)
        for site in sites:
            if site['supported']:
                for path in site['paths']:
                    desired[path] = site_config(policy, site)
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
              'policy.json': load('policy.json', None), 'manifest.json': load('manifest.json', None)}
    storage.replace(STATE / 'transaction.json', storage.json_bytes(record), 0o600)
    try:
        for name, text in changes.items():
            storage.replace(name, None if text is None else text.encode())
        verify(desired)
        if changes:
            reload_nginx()
        storage.replace(STATE / 'manifest.json', storage.json_bytes(sorted(desired)), 0o600)
        storage.replace(STATE / 'policy.json', storage.json_bytes(policy), 0o600)
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


def snapshot(policy, sites, owner=None):
    rows = []
    for site in sites:
        if owner is not None and site['owner'] != owner:
            continue
        rows.append({**{key: site[key] for key in ('key', 'owner', 'domain', 'template', 'aliases',
                                                   'suspended', 'supported', 'reason')},
                     'mode': site_mode(policy, site),
                     'override': policy['overrides'].get(site['key'], 'inherit')})
    return {'ok': True, 'version': '0.1.1', 'policy': policy if owner is None else {'mode': policy['mode']},
            'sites': rows}


def authorize(request):
    actor = account(request.get('actor'))
    user = hestia('v-list-user', actor).get(actor, {})
    if user.get('SUSPENDED') != 'no':
        raise PermissionError('Account is suspended or unavailable')
    admin = user.get('ROLE') == 'admin'
    owner = account(request.get('owner', actor))
    if not admin and owner != actor:
        raise PermissionError('Another account cannot be selected')
    if request.get('action') != 'status' and not admin:
        raise PermissionError('Only an administrator can change De-Noise settings')
    return admin, owner


def dispatch(request):
    if not isinstance(request, dict):
        raise ValueError('Expected a JSON object')
    admin, owner = authorize(request)
    action = request.get('action')
    policy = validate(load('policy.json', DEFAULT))
    sites = collect()
    if action == 'save':
        # Keep overrides server-side; the global form cannot overwrite them.
        incoming = request.get('policy')
        if not isinstance(incoming, dict):
            raise ValueError('Expected policy settings')
        policy = validate({**incoming, 'overrides': policy['overrides']})
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
    elif action == 'sync':
        apply(policy, sites)
    elif action != 'status':
        raise ValueError('Unsupported operation')
    return snapshot(policy, sites, None if admin else owner)


def main():
    if os.geteuid() != 0:
        raise PermissionError('Invoke this command as root or through the Hestia panel')
    with locked():
        recover()
        if sys.argv[1:]:
            action = sys.argv[1:]
            if action not in (['sync'], ['disable'], ['status'], ['remove-rules']):
                raise ValueError('Commands: status, sync, disable, remove-rules')
            policy = validate(load('policy.json', DEFAULT))
            sites = collect()
            if action == ['disable']:
                policy['mode'] = 'off'; policy['overrides'] = {}
            if action != ['status']:
                result = apply(policy, sites, remove=action == ['remove-rules'])
            else:
                result = snapshot(policy, sites)
        else:
            raw = sys.stdin.buffer.read(131073)
            if len(raw) > 131072:
                raise ValueError('Request too large')
            result = dispatch(json.loads(raw))
    return {'ok': True, **result}
