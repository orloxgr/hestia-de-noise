"""Incremental final-404 counters from existing native Hestia access logs.

Nginx serves static files and Apache serves origin responses into the same native
combined log. Local Nginx rejections that inherit server logging have a separate
metadata-only event, because they never reach either native logging location.
"""
import datetime
import os
from pathlib import Path
import re
import stat
import storage
import ban_evidence

LOG_ROOT = Path('/var/log/apache2/domains')
READ_LIMIT = 2 * 1024 * 1024
FILE_LIMIT = 256 * 1024
LINE = re.compile(rb'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) ((?:[^"\\\s]|\\.)+) [^"\r\n]+" 404 (?:[0-9]+|-) ')


def events(db, sites, namespace):
    import pwd
    if namespace not in ('native', 'domain'):
        raise ValueError('Invalid native access-log cursor namespace')
    trusted_uids = {0, pwd.getpwnam('www-data').pw_uid}
    db.execute('CREATE TABLE IF NOT EXISTS access_cursors (namespace TEXT, domain TEXT, device INTEGER, inode INTEGER, offset INTEGER, PRIMARY KEY(namespace,domain,device,inode))')
    names = sorted({site['domain'] for site in sites})
    if not names:
        return
    row = db.execute('SELECT value FROM meta WHERE key=?', ('404-next:'+namespace,)).fetchone()
    first = int(row[0]) % len(names) if row else 0
    names = names[first:] + names[:first]; remaining = READ_LIMIT
    for index, domain in enumerate(names):
        if not re.fullmatch(r'[a-z0-9][a-z0-9.-]*', domain):
            raise ValueError('Invalid native access-log domain')
        for suffix in ('.log.1', '.log'):
            if remaining <= 0:
                break
            path = LOG_ROOT / (domain+suffix)
            try:
                # All ancestors and the log itself must be root-controlled.
                with storage.parent(path) as parent:
                    fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            except FileNotFoundError:
                continue
            with os.fdopen(fd, 'rb') as stream:
                info = os.fstat(stream.fileno())
                if info.st_uid not in trusted_uids or info.st_mode & 0o022 or not stat.S_ISREG(info.st_mode):
                    raise ValueError('Untrusted native access log: '+str(path))
                cursor = db.execute('SELECT offset FROM access_cursors WHERE namespace=? AND domain=? AND device=? AND inode=?',
                                    (namespace, domain, info.st_dev, info.st_ino)).fetchone()
                offset = cursor[0] if cursor and cursor[0] <= info.st_size else max(0, info.st_size-FILE_LIMIT)
                stream.seek(offset)
                if not cursor and offset:
                    stream.readline(); offset = stream.tell()
                body = stream.read(min(FILE_LIMIT, remaining)); remaining -= len(body)
                end = body.rfind(b'\n')+1
                if not end:
                    if len(body) == FILE_LIMIT:
                        raise ValueError('Native access-log line exceeds the read bound')
                    continue
                for raw in body[:end].splitlines():
                    match = LINE.match(raw)
                    if not match:
                        continue
                    ip, date, method, target = match.groups()
                    try:
                        stamp = datetime.datetime.strptime(date.decode('ascii'), '%d/%b/%Y:%H:%M:%S %z').timestamp()
                        yield (str(stamp), ip.decode('ascii'), domain, 'not-found', '-',
                               ban_evidence.path_only(target.decode('utf-8', errors='replace')),
                               ban_evidence.method_only(method.decode('ascii')))
                    except (ValueError, UnicodeError):
                        continue
                db.execute('INSERT OR REPLACE INTO access_cursors VALUES (?,?,?,?,?)',
                           (namespace,domain,info.st_dev,info.st_ino,offset+end))
        db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)', ('404-next:'+namespace,str((first+index+1) % len(names))))
        if remaining <= 0:
            break
