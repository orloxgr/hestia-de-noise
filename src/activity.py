"""Complete streamed reads of addon match logs, performed only when viewing the panel."""
from datetime import datetime
import os
from pathlib import Path
import sqlite3
import json
import time
import storage
import log_files

LOG = Path('/var/log/hestia-de-noise/matches.log')


def summary(domains, now=None, minutes=15, progress=None, cancelled=None, report_path=None):
    if os.name != 'posix':
        raise ValueError('Activity logs are available on the Linux server')
    if type(minutes) is not int or minutes < 1:
        raise ValueError('Activity window must be positive minutes')
    cutoff = (time.time() if now is None else now) - minutes * 60
    if report_path is not None:
        storage.replace(report_path, b'', 0o600)
    connection = sqlite3.connect(str(report_path) if report_path is not None else ':memory:')
    connection.execute('CREATE TABLE events(stamp REAL, payload TEXT, domain TEXT, rule TEXT, outcome TEXT)')
    connection.execute('CREATE INDEX event_order ON events(stamp DESC)')
    scanned = 0
    truncated = False
    paths = log_files.rotations(LOG)
    for number, path in enumerate(paths):
        try:
            context = log_files.opened(path)
            stream, raw = context.__enter__()
        except FileNotFoundError:
            continue
        try:
            snapshot_size = os.fstat(raw.fileno()).st_size
            position = 0
            for value in stream:
                if not log_files.compressed(path) and position + len(value) > snapshot_size:
                    break
                position += len(value)
                if not value.endswith(b'\n'):
                    continue
                if cancelled and cancelled():
                    connection.close()
                    raise InterruptedError('Activity review cancelled')
                scanned += len(value)
                if progress:
                    progress(dict(stage='Reading activity', bytes=scanned, files_done=number, files_total=len(paths)))
                line = value.decode(errors='replace')
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
                        status == '403' and (rule in ('agent', 'private-file', 'domain-ban', 'user-enumeration') or rule.startswith('filter-block-'))
                        or status == '404' and (rule.startswith('static-') or rule in ('missing-file', 'suspicious-query')))):
                    outcome = 'blocked'
                elif mode == 'observe' or limit.endswith('_DRY_RUN'):
                    outcome = 'observed'
                payload = dict(time=timestamp, domain=domain, rule=rule, outcome=outcome, status=int(status))
                connection.execute('INSERT INTO events VALUES(?,?,?,?,?)', (stamp, json.dumps(payload), domain, rule, outcome))
        finally:
            context.__exit__(None, None, None)
    connection.commit()
    total = connection.execute('SELECT COUNT(*) FROM events').fetchone()[0]
    rows = [dict(domain=d, rule=r, outcome=o, count=n) for d,r,o,n in connection.execute(
        'SELECT domain,rule,outcome,COUNT(*) AS n FROM events GROUP BY domain,rule,outcome ORDER BY n DESC,domain,rule,outcome')]
    recent = [] if report_path is not None else [json.loads(row[0]) for row in connection.execute('SELECT payload FROM events ORDER BY stamp DESC')]
    connection.close()
    return dict(available=True, window_minutes=minutes, sample_truncated=False, bytes_read=scanned,
                total=total, rows=rows, recent=recent, findings_total=total, findings_database=report_path is not None)
