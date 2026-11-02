"""Bounded reads of addon match logs, performed only when viewing the panel."""
from collections import Counter
from datetime import datetime
import os
from pathlib import Path
import stat
import time

LOG = Path('/var/log/hestia-de-noise/matches.log')
MAX_BYTES = 2 * 1024 * 1024


def summary(domains, now=None):
    if os.name != 'posix':
        raise ValueError('Activity logs are available on the Linux server')
    cutoff = (time.time() if now is None else now) - 900
    counts, recent = Counter(), []
    scanned = 0
    truncated = False
    for path in (LOG.with_name(LOG.name + '.1'), LOG):
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            continue
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('Refusing an untrusted activity log')
            offset = max(0, info.st_size - MAX_BYTES)
            stream.seek(offset)
            if offset:
                stream.readline()
                truncated = True
            body = stream.read(MAX_BYTES)
            scanned += len(body)
        for line in body.decode(errors='replace').splitlines():
            fields = line.split()
            if len(fields) == 4:  # Older endpoint-only rate-limit record.
                timestamp, domain, limit, status = fields
                rule, mode = 'endpoint-limit', 'unknown'
            elif len(fields) in (5, 6):
                timestamp, domain, rule, limit, status = fields[:5]
                mode = fields[5] if len(fields) == 6 else 'unknown'
            else:
                continue
            try:
                stamp = datetime.fromisoformat(timestamp).timestamp()
            except ValueError:
                continue
            if stamp < cutoff or domain not in domains or not status.isdigit():
                continue
            outcome = 'matched'
            if limit == 'REJECTED' or (mode == 'enforce' and (
                    status == '403' and (rule in ('agent', 'private-file', 'domain-ban') or rule.startswith('filter-block-'))
                    or status == '404' and (rule.startswith('static-') or rule in ('missing-file', 'suspicious-query')))):
                outcome = 'blocked'
            elif mode == 'observe' or limit.endswith('_DRY_RUN'):
                outcome = 'observed'
            counts[(domain, rule, outcome)] += 1
            recent.append({'time': timestamp, 'domain': domain, 'rule': rule,
                           'outcome': outcome, 'status': int(status), 'stamp': stamp})
    recent.sort(key=lambda row: row['stamp'], reverse=True)
    return {'available': True, 'window_minutes': 15, 'sample_truncated': truncated,
            'bytes_read': scanned, 'total': sum(counts.values()),
            'rows': [{'domain': d, 'rule': r, 'outcome': o, 'count': n}
                     for (d, r, o), n in counts.most_common(50)],
            'recent': [{k: v for k, v in row.items() if k != 'stamp'} for row in recent[:25]]}
