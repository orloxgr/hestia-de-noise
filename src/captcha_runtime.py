"""Managed socket service and private native Nginx cookie-verification keys."""
import json
from pathlib import Path
import re
import secrets

import captcha

NAME = 'hestia-de-noise-captcha'
SOCKET = Path('/run') / NAME / 'service.sock'
UNITS = Path('/etc/systemd/system')
CONFIG_NAME = 'captcha-sites.conf'
MARKER = '# Managed by hestia-de-noise'


def unit_files(group):
    if not re.fullmatch(r'[A-Za-z0-9_-]+', group): raise ValueError('Invalid native Nginx group')
    return {
        UNITS / (NAME + '.socket'): MARKER + '\n[Unit]\nDescription=Local De-Noise CAPTCHA socket\n[Socket]\nListenStream=' + str(SOCKET) + '\nSocketUser=root\nSocketGroup=' + group + '\nSocketMode=0660\nDirectoryMode=0755\n[Install]\nWantedBy=sockets.target\n',
        UNITS / (NAME + '.service'): MARKER + '''
[Unit]
Description=Local De-Noise math CAPTCHA
Requires=hestia-de-noise-captcha.socket
After=hestia-de-noise-captcha.socket
[Service]
Type=simple
DynamicUser=yes
ExecStart=/usr/bin/python3 -I /opt/hestia-de-noise/current/src/captcha_server.py
LoadCredential=signing-key:/var/lib/hestia-de-noise/captcha.key
StateDirectory=hestia-de-noise-captcha
StateDirectoryMode=0700
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
RestrictAddressFamilies=AF_UNIX
UMask=0077
'''}


def worker_group():
    import pwd
    import grp
    import storage
    raw = storage.read('/etc/nginx/nginx.conf') or b''
    match = re.search(rb'^\s*user\s+[\'\"]?([A-Za-z0-9_-]+)[\'\"]?(?:\s+[\'\"]?([A-Za-z0-9_-]+)[\'\"]?)?\s*;', raw, re.M)
    return match[2].decode() if match and match[2] else grp.getgrgid(pwd.getpwnam(match[1].decode()).pw_gid).gr_name if match else 'root'


def prepare(state_directory, directory, settings, sites, site_mode):
    import access_protection as access
    import storage
    active = [(site, access.effective(settings, site['key'])) for site in sites
              if site.get('supported') and not site.get('suspended') and site.get('kind') != 'mail'
              and site_mode(site) != 'off' and access.effective(settings, site['key'])['enabled']
              and access.effective(settings, site['key'])['method'] == 'captcha']
    if not active: return {}, False
    key_path = state_directory / 'captcha.key'
    secret = storage.read(key_path)
    if secret is None:
        secret = secrets.token_bytes(32); storage.replace(key_path, secret, 0o600)
    if len(secret) != 32: raise ValueError('Invalid retained CAPTCHA key')
    directory.mkdir(mode=0o755, exist_ok=True)
    with storage.parent(directory / '.check'):
        pass
    desired, entries = {}, {}
    for site, profile in active:
        scope = access.identifier(site['key']); rev = captcha.revision(profile)
        entries[scope] = dict(hosts=[site['domain'], *(s.strip() for s in site.get('aliases', '').split(',') if s.strip())],
                              revision=rev, seconds=profile['captcha_seconds'])
        key = captcha.scope_key(secret, scope, rev)
        desired[str(directory / (scope + '.captcha.conf'))] = (MARKER + '\nsecure_link $ha' + scope + '_token;\n' +
                'secure_link_md5 "$secure_link_expires|$host|$scheme|' + key + '";\n')
    desired[str(directory / CONFIG_NAME)] = MARKER + '\n' + json.dumps({'sites': entries}, sort_keys=True) + '\n'
    return desired, True


def enable(run):
    run('/usr/bin/systemctl', 'enable', '--now', NAME + '.socket')


def disable(run):
    run('/usr/bin/systemctl', 'disable', '--now', NAME + '.socket')
    run('/usr/bin/systemctl', 'stop', NAME + '.service')
