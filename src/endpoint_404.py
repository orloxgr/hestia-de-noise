"""Exact administrator-selected paths: ban only after a real final HTTP 404."""
import hashlib
import json
from urllib.parse import unquote

DEFAULT = dict(enabled=False, paths=[], targets=[], duration_seconds=86400)
REASON = 'endpoint-404-list'


def validate(settings, target):
    if not isinstance(settings, dict) or set(settings) != set(DEFAULT):
        raise ValueError('Invalid selected endpoint 404 settings')
    if type(settings['enabled']) is not bool or type(settings['duration_seconds']) is not int or settings['duration_seconds'] < 0:
        raise ValueError('Selected 404 ban duration must be nonnegative; 0 = permanent')
    if not isinstance(settings['paths'], list) or not isinstance(settings['targets'], list):
        raise ValueError('Use an exact path list and domain selections')
    for path in settings['paths']:
        if (not isinstance(path, str) or not path.startswith('/') or '?' in path or '#' in path
                or any(ord(c) < 32 or ord(c) == 127 for c in unquote(path))):
            raise ValueError('404 selections must be exact paths without query strings or control characters')
    settings['paths'] = list(dict.fromkeys(settings['paths']))
    settings['targets'] = list(dict.fromkeys(target(value) for value in settings['targets']))


def fingerprint(settings, domains):
    return hashlib.sha256(json.dumps([settings['enabled'], settings['paths'], sorted(domains)]).encode()).hexdigest() if domains else ''


def expand(records, settings, domains, start):
    selected = {unquote(path) for path in settings['paths']}
    for row in records:
        stamp, address, domain, reason, token, path, method = row
        try: recent = float(stamp) >= start
        except (ValueError, TypeError): recent = False
        matches = domain in domains and unquote(path) in selected and recent
        if reason == REASON:
            if matches: yield row
            continue
        if reason == 'not-found' and matches:
            yield stamp, address, domain, REASON, 'selected-404', path, method
        yield row


def compile_maps(settings, sites, scope_map, exact_uri_pattern, event_format):
    lines = scope_map('hdn_endpoint404_site', settings, sites)
    lines += ['map $uri $hdn_endpoint404_path {', '    default 0;']
    for path in settings['paths']:
        lines += ['    ' + exact_uri_pattern(unquote(path)) + ' 1;']
    lines += ['}', 'map "$hdn_mode:$hdn_endpoint404_site:$hdn_endpoint404_path:$status" $hdn_endpoint404_log {',
              '    default 0;', '    enforce:1:1:404 1;', '}',
              event_format('hdn_endpoint404_bans', REASON, 'selected-404')]
    return lines
