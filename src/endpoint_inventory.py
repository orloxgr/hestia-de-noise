"""Read-only, disk-backed evidence for endpoint suggestions, including successes."""
import hashlib
import json
import re
import secrets
import sqlite3
import tempfile
from pathlib import Path
from urllib.parse import unquote

import agent_catalog

# Candidate discovery only. These expressions never become active protection.
BACKUP = re.compile(r'\.(?:sql|sqlite3?)(?:\.(?:gz|zip|zst|bz2|xz))?$|'
                    r'(?:^|/)(?:bak|backup|dump|database|db|site|www|web|public_html|wp-content|wp-config)'
                    r'(?:[-_.][^/]*)?\.(?:zip|tar(?:\.(?:gz|bz2|xz|zst))?|tgz|gz|zst|7z|rar|bak|old)$', re.I)
SECRET = re.compile(r'(?:^|/)\.(?:env(?:[./]|$)|git(?:/|$)|svn(?:/|$)|hg(?:/|$))', re.I)


def family(path):
    if SECRET.search(path):
        return 'Secret / repository path'
    if BACKUP.search(path):
        return 'Backup / database filename'
    return None


class Inventory:
    def __init__(self, kind='endpoints', path=None):
        self.salt = secrets.token_bytes(16)
        self.directory = tempfile.TemporaryDirectory(prefix='hdn-endpoints-') if path is None else None
        if path is None:
            path = Path(self.directory.name) / 'report.sqlite'
        else:
            import storage
            storage.replace(path, b'', 0o600)
        self.db = sqlite3.connect(path)
        self.db.executescript('''
            CREATE TABLE counts (site TEXT, domain TEXT, path TEXT, category TEXT,
                count INTEGER, first REAL, last REAL, PRIMARY KEY(site,path));
            CREATE TABLE evidence (site TEXT, path TEXT, kind TEXT, value BLOB, count INTEGER,
                PRIMARY KEY(site,path,kind,value));
            CREATE TABLE findings (rank INTEGER, count INTEGER, site TEXT, path TEXT, payload TEXT);
            CREATE INDEX finding_order ON findings(rank,count DESC,site,path);
        ''')

    def observe(self, site, path, status, agent, stamp, address=None, method=''):
        normalized = unquote(path)
        category = family(normalized)
        if not category:
            return
        self.db.execute('''INSERT INTO counts VALUES (?,?,?,?,1,?,?) ON CONFLICT(site,path)
            DO UPDATE SET count=count+1,first=min(first,excluded.first),last=max(last,excluded.last)''',
            (site['key'], site['domain'], path, category, stamp, stamp))
        values = [('status', status), ('method', method), ('agent', agent_catalog.observed(agent)[0])]
        if address is not None:
            values.append(('client', hashlib.blake2s(address.encode(), key=self.salt, digest_size=16).digest()))
        for kind, value in values:
            self.db.execute('''INSERT INTO evidence VALUES (?,?,?,?,1) ON CONFLICT(site,path,kind,value)
                DO UPDATE SET count=count+1''', (site['key'], path, kind, value))

    def finish(self, persist):
        self.paths_total = self.db.execute('SELECT COUNT(*) FROM counts').fetchone()[0]
        for site, domain, path, category, count, first, last in self.db.execute('SELECT * FROM counts'):
            evidence = lambda kind: dict(self.db.execute('''SELECT value,count FROM evidence
                WHERE site=? AND path=? AND kind=? ORDER BY count DESC,value''', (site, path, kind)))
            statuses = evidence('status')
            success = sum(n for code, n in statuses.items() if code.startswith(('2', '3')))
            candidate = path if '[redacted-' not in path else None
            row = dict(site=site, domain=domain, path=path, candidate=candidate, category=category,
                       count=count, first=first, last=last, statuses=statuses, methods=evidence('method'),
                       agents=evidence('agent'), clients=len(evidence('client')), successful=success,
                       advice=('Successful / redirected responses exist. Check downloads, redirects and application routes before considering a block.' if success else
                               'Filename resembles a probe target. Verify that this domain does not publish it intentionally. A 404 or agent name alone does not establish abuse.'))
            self.db.execute('INSERT INTO findings VALUES (?,?,?,?,?)',
                            (0 if success else 1, count, site, path, json.dumps(row, separators=(',', ':'))))
        self.db.commit()
        rows = [] if persist else [json.loads(r[0]) for r in self.db.execute('SELECT payload FROM findings ORDER BY rank,count DESC,site,path')]
        return rows, self.paths_total

    def close(self):
        self.db.close()
        if self.directory:
            self.directory.cleanup()
