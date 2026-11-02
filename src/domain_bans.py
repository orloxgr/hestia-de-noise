"""Domain-only automatic bans. No native firewall mutation or user exceptions."""
import ipaddress
import json
from pathlib import Path
import time
from itertools import chain
import not_found

import auto_bans
from policy import site_mode
from probe_rules import token
import storage

APPLIED = 'domain-ban-applied.json'
CATEGORIES = {'domain-file': 'missing_files', 'domain-query': 'suspicious_queries', 'domain-404': 'any_404'}


def eligible(policy, sites):
    preferences = policy['domain_bans']['sites']
    return {site['key']: site for site in sites if site.get('supported') and not site.get('suspended')
            and site_mode(policy, site) == 'enforce' and any(preferences.get(site['key'], {}).values())}


def tables(db):
    db.executescript('''
        CREATE TABLE IF NOT EXISTS domain_cursors (device INTEGER, inode INTEGER, offset INTEGER NOT NULL, PRIMARY KEY(device,inode));
        CREATE TABLE IF NOT EXISTS domain_strikes (site TEXT, ip TEXT, reason TEXT, token TEXT, stamp REAL);
        CREATE INDEX IF NOT EXISTS domain_strikes_lookup ON domain_strikes(site,ip,reason,stamp);
        CREATE TABLE IF NOT EXISTS domain_bans (site TEXT, ip TEXT, reason TEXT, created REAL, expires REAL,
            PRIMARY KEY(site,ip));
    ''')


def rows(state):
    with auto_bans.database(state, create=False) as db:
        if db is None or not db.execute("SELECT name FROM sqlite_master WHERE name='domain_bans'").fetchone():
            return []
        return [dict(row) for row in db.execute('SELECT * FROM domain_bans')]


def desired(policy, sites, state, now=None):
    now = time.time() if now is None else now
    known = eligible(policy, sites); result = {}
    for row in rows(state):
        key = row['site']; category = CATEGORIES.get(row['reason'])
        if (key not in known or not category or not policy['domain_bans']['sites'][key].get(category)
                or (row['expires'] and row['expires'] <= now)):
            continue
        address = str(ipaddress.ip_address(row['ip']))
        result.setdefault(key, {})[address] = {name: row[name] for name in ('reason', 'created', 'expires')}
    return result


def applied(state):
    raw = storage.read(Path(state) / APPLIED)
    return json.loads(raw) if raw is not None else {}


def report(policy, sites, state, owner=None, now=None):
    known = {site['key'] for site in sites if owner is None or site['owner'] == owner}
    pending = desired(policy, sites, state, now); actual = applied(state); result = []
    for key in sorted(known):
        before, after = actual.get(key, {}), pending.get(key, {})
        for address in sorted(set(before) | set(after)):
            data = after.get(address, before.get(address))
            result.append({'site': key, 'domain': key.split('/', 1)[1], 'ip': address, **data,
                           'status': 'active' if address in before and address in after else
                                     'pending' if address in after else 'removing'})
    return {'active': sum(row['status'] == 'active' for row in result),
            'pending': sum(row['status'] != 'active' for row in result),
            'rows': sorted(result, key=lambda row: row['created'], reverse=True)[:100]}


def synchronize(policy, sites, state, native, now=None):
    """Consume its own cursor; native global bans consume the same log separately."""
    now = time.time() if now is None else now
    known = eligible(policy, sites)
    if not known and not (Path(state) / 'bans.sqlite').exists():
        return
    by_domain = {site['domain']: key for key, site in known.items()}
    settings = policy['bans']; preferences = policy['domain_bans']['sites']
    with auto_bans.database(state) as db:
        tables(db)
        shared_rules = {name: settings[name] for name in CATEGORIES.values()}
        for key in known:
            signature = json.dumps([preferences[key], shared_rules], sort_keys=True)
            if auto_bans.get(db, 'domain-rules:'+key) != signature:
                db.execute('DELETE FROM domain_strikes WHERE site=?', (key,))
                auto_bans.put(db, 'domain-rules:'+key, signature)
        if known:
            db.execute('DELETE FROM domain_strikes WHERE site NOT IN ('+','.join('?' for _ in known)+')', tuple(known))
        else:
            db.execute('DELETE FROM domain_strikes')
        cutoff = now - max(settings[name]['findtime'] for name in CATEGORIES.values())
        db.execute('DELETE FROM domain_strikes WHERE stamp<?', (cutoff,))
        for row in db.execute('SELECT * FROM domain_bans').fetchall():
            category = CATEGORIES[row['reason']]
            if (row['site'] not in known or not preferences.get(row['site'], {}).get(category)
                    or (row['expires'] and row['expires'] <= now)):
                db.execute('DELETE FROM domain_bans WHERE site=? AND ip=?', (row['site'], row['ip']))
        ignored = [ipaddress.ip_network(value) for value in settings['ignore_ips']]
        ignored.extend(native.exclusions() if known else [])
        own = native.own_ips() if known else set()

        def exempt(ip):
            return (ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local
                    or str(ip) in own or any(ip in network for network in ignored))

        for row in db.execute('SELECT site,ip FROM domain_bans').fetchall():
            if exempt(ipaddress.ip_address(row['ip'])):
                db.execute('DELETE FROM domain_bans WHERE site=? AND ip=?', (row['site'], row['ip']))
        valid = {'domain-file': {token('f', value) for value in settings['missing_files']['paths']},
                 'domain-query': {token('q', value) for value in settings['suspicious_queries']['targets']},
                 'domain-404': {'-'}}
        sources = chain(auto_bans.events(db, 'domain_cursors'), not_found.events(db,
            [site for key, site in known.items() if preferences[key].get('any_404')], 'domain'))
        for stamp, address, host, reason, event_token in sources:
            if reason == 'not-found':
                reason = 'domain-404'
            key = by_domain.get(host); category = CATEGORIES.get(reason)
            if not key or not category or not preferences[key][category] or event_token not in valid[reason]:
                continue
            try:
                ip = ipaddress.ip_address(address); stamp = float(stamp)
            except ValueError:
                continue
            rule = settings[category]
            if not now-rule['findtime'] <= stamp <= now+5 or exempt(ip):
                continue
            address = str(ip)
            if db.execute('SELECT ip FROM domain_bans WHERE site=? AND ip=?', (key, address)).fetchone():
                continue
            db.execute('INSERT INTO domain_strikes VALUES (?,?,?,?,?)', (key, address, reason, event_token, stamp))
            expression = 'COUNT(DISTINCT token)' if reason == 'domain-file' else 'COUNT(*)'
            count = db.execute('SELECT '+expression+' FROM domain_strikes WHERE site=? AND ip=? AND reason=? AND stamp>=?',
                               (key, address, reason, now-rule['findtime'])).fetchone()[0]
            if count >= rule['maxretry']:
                duration = rule['duration_days']
                db.execute('INSERT OR REPLACE INTO domain_bans VALUES (?,?,?,?,?)',
                           (key, address, reason, now, now+duration*86400 if duration else 0))
                db.execute('DELETE FROM domain_strikes WHERE site=? AND ip=?', (key, address))
        # Store independent lifetimes for this scope, preserving creation time.
        for reason, category in CATEGORIES.items():
            duration = settings[category]['duration_days']
            if auto_bans.get(db, 'domain-duration:'+reason) != str(duration):
                db.execute('UPDATE domain_bans SET expires=CASE WHEN ?=0 THEN 0 ELSE created+? END WHERE reason=?',
                           (duration, duration*86400, reason))
                auto_bans.put(db, 'domain-duration:'+reason, duration)
        db.commit()
