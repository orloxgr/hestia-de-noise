#!/usr/bin/python3
"""Install/update only this addon's files; start with an empty Observe policy."""
import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import stat
import sys

SOURCE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE / 'src'))
import engine
from policy import DEFAULT, MARKER, validate
import storage

BASE = Path('/opt/hestia-de-noise')
ROUTE = engine.HESTIA / 'web/plugins/de-noise'
MENU = engine.HESTIA / 'web/js/custom_scripts/hestia-de-noise.js'
BRIDGE = engine.HESTIA / 'bin/v-denoise-hestia'
CRON = Path('/etc/cron.d/hestia-de-noise')
ROTATE = Path('/etc/logrotate.d/hestia-de-noise')
LOGS = Path('/var/log/hestia-de-noise')
OWNER = b'hestia-de-noise\n'


def directory(path, private=False, shared=False):
    if not path.exists():
        path.mkdir(mode=0o700 if private else 0o755)
    with storage.parent(path / '.check'):
        if private and path.stat().st_mode & 0o077:
            raise ValueError('Directory must be root-private: ' + str(path))
    if not shared:
        marker = path / '.addon-owner'
        previous = storage.read(marker)
        if previous is not None and previous != OWNER:
            raise ValueError('Directory belongs to another application: ' + str(path))
        if previous is None:
            if any(path.iterdir()):
                raise ValueError('Refusing an existing unmanaged directory: ' + str(path))
            storage.replace(marker, OWNER)


def managed_file(path, data, mode=0o644):
    old = storage.read(path)
    if old is not None and b'Managed by hestia-de-noise' not in old[:150]:
        raise ValueError('Refusing an unmanaged integration file: ' + str(path))
    storage.replace(path, data, mode)
    return old


def pointer(destination):
    path = BASE / 'current'
    temporary = BASE / ('.current-' + secrets.token_hex(8))
    try:
        temporary.symlink_to(destination, target_is_directory=True)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def check_pointer():
    current = BASE / 'current'
    if current.is_symlink():
        resolved = current.resolve(strict=True)
        if resolved.parent != BASE / 'releases' or not resolved.is_dir():
            raise ValueError('Unexpected installed release pointer')
        return resolved
    if current.exists():
        raise ValueError('Expected an addon-owned release pointer')
    return None


def preflight():
    if os.name != 'posix' or os.geteuid() != 0:
        raise ValueError('Run this installer as root on the Ubuntu Hestia server')
    os_release = Path('/etc/os-release').read_text()
    if not any(line in os_release.splitlines() for line in ('ID=ubuntu', 'ID="ubuntu"')):
        raise ValueError('This release targets Ubuntu with HestiaCP')
    if not (engine.HESTIA / 'web/inc/main.php').is_file():
        raise ValueError('An existing HestiaCP installation is required')
    for file in (SOURCE / 'panel').glob('*.php'):
        engine.run(str(engine.HESTIA / 'php/bin/php'), '-l', str(file))
    engine.run('/usr/sbin/nginx', '-t')
    # Nginx rejects unsupported directives during the candidate validation.
    # Nothing is downloaded, no package/service/firewall setting is replaced.


def prepare_logs():
    directory(LOGS)
    for filename in ('matches.log', 'maintenance.log'):
        with storage.parent(LOGS / filename) as descriptor:
            log = os.open(filename, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW,
                          0o640, dir_fd=descriptor)
            try:
                info = os.fstat(log)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                    raise ValueError('Unexpected addon log file')
            finally:
                os.close(log)


def install():
    preflight()
    with engine.locked():
        engine.recover()
        directory(BASE)
        directory(BASE / 'releases')
        previous = check_pointer()
        directory(ROUTE.parent, shared=True)
        directory(ROUTE)
        directory(MENU.parent, shared=True)
        prepare_logs()
        # Stage an immutable release. Running panel requests continue to use a
        # complete code generation when the current pointer changes.
        stage = BASE / 'releases' / ('release-' + secrets.token_hex(10))
        stage.mkdir(mode=0o755)
        for name in ('src', 'panel'):
            for item in (SOURCE / name).rglob('*'):
                if item.is_symlink():
                    raise ValueError('Source symlinks are not supported')
            shutil.copytree(SOURCE / name, stage / name,
                            ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        shutil.copyfile(SOURCE / 'addon.json', stage / 'addon.json')
        for folder, _, files in os.walk(stage):
            os.chmod(folder, 0o755)
            for filename in files:
                path = Path(folder) / filename
                path.chmod(0o644)
                with path.open('rb') as stream:
                    os.fsync(stream.fileno())
        # Each published route pins one immutable release, including its view.
        page = (stage / 'panel/index.php').read_bytes().replace(b'__INSTALL_ROOT__', str(stage).encode())
        integration = {
            ROUTE / 'index.php': (page, 0o644),
            MENU: ((stage / 'panel/menu.js').read_bytes(), 0o644),
            BRIDGE: (("#!/bin/sh\n" + MARKER + "\nexec /usr/bin/python3 -I " +
                      str(BASE / 'current/src/addon.py') + ' "$@"\n').encode(), 0o755),
            CRON: ((MARKER + '\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n' +
                    '* * * * * root ' + str(BRIDGE) +
                    ' sync >> /var/log/hestia-de-noise/maintenance.log 2>&1\n').encode(), 0o644),
            ROTATE: ((MARKER + '\n/var/log/hestia-de-noise/*.log {\n' +
                      '    daily\n    rotate 7\n    maxsize 10M\n    missingok\n    notifempty\n' +
                      '    compress\n    delaycompress\n    create 0640 root root\n    sharedscripts\n' +
                      '    postrotate\n        /usr/sbin/nginx -s reopen\n    endscript\n}\n').encode(), 0o644)}
        before = {}
        try:
            for path, (data, mode) in integration.items():
                before[path] = managed_file(path, data, mode)
            pointer(stage)
            policy = validate(engine.load('policy.json', DEFAULT))
            sites = engine.collect()
            if sites and not any(site['supported'] for site in sites):
                raise RuntimeError('None of the existing proxy configurations has a supported native include point')
            result = engine.apply(policy, sites)
        except Exception:
            for path, old in before.items():
                storage.replace(path, old, integration[path][1])
            if previous:
                pointer(previous)
            else:
                (BASE / 'current').unlink(missing_ok=True)
            raise
        print(json.dumps({'ok': True, 'version': '0.1.1', 'mode': policy['mode'],
                          'panel': '/plugins/de-noise/', **result,
                          'unsupported': [{'owner': s['owner'], 'domain': s['domain'], 'reason': s['reason']}
                                          for s in sites if not s['supported']]}))


def uninstall():
    preflight()
    with engine.locked():
        engine.recover()
        directory(BASE)
        check_pointer()
        cron_before = storage.owned(CRON)
        storage.replace(CRON, None)
        try:
            engine.apply(validate(engine.load('policy.json', DEFAULT)), engine.collect(), remove=True)
        except Exception:
            storage.replace(CRON, cron_before)
            raise
        for path in (MENU, BRIDGE, ROUTE / 'index.php', ROTATE):
            managed_file(path, None)
        # Retain root-private policy, logs and immutable releases. No recursive
        # deletion of server data, shared plugin directories or other addons.
        print(json.dumps({'ok': True, 'uninstalled': True,
                          'retained': [str(engine.STATE), str(BASE), str(LOGS)]}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--uninstall', action='store_true')
    args = parser.parse_args()
    try:
        uninstall() if args.uninstall else install()
    except Exception as error:
        print(str(error), file=sys.stderr)
        print(json.dumps({'ok': False, 'error_type': type(error).__name__, 'error': str(error)}))
        raise SystemExit(1)
