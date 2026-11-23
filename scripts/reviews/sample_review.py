#!/usr/bin/env python3
"""Render the sample observed server review a prospect can read before buying.

The report is produced by the real renderer (`jarvis.response.review`) over a
throwaway store filled with a fictional server's week. Nothing is read from this
machine's store, and no finding below was observed anywhere: the host, findings
and dates are invented to show the format, including the honest states
(partial, stale, not observed) a real week usually has.

    python3 scripts/reviews/sample_review.py > docs/commercial/SAMPLE-SERVER-REVIEW.txt

Deterministic: a fixed clock and fixed run ids, so the file only changes when the
renderer, the register or this fixture changes.
"""

import json
import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from jarvis.core.store import Store  # noqa: E402
from jarvis.response import review  # noqa: E402

NOW = 1_793_577_600.0           # 2026-11-02 00:00 UTC
DAY = 86400
HOST = 'sample-web-01 (fictional)'
BANNER = ('SAMPLE REPORT. The server, findings and dates below are invented to show the format '
          'of a real review; none of them was observed on any machine.')

# job -> (complete runs, partial runs, unavailable runs, stored result, findings).
# stored result: 'last' = written by the last run in the window, a number = that many days
# before the window ends (older than the window), None = never stored.
WEEK = {
    'sshwatch': (2016, 0, 0, 'last', [
        {'severity': 'high', 'title': 'new ssh key for deploy',
         'detail': 'a key was added to /home/deploy/.ssh/authorized_keys on 2026-10-29; '
                   'confirm who added it'},
        {'severity': 'medium', 'title': 'PasswordAuthentication is enabled',
         'detail': 'sshd accepts passwords; keys only is the usual choice for a web server'},
        {'severity': 'low', 'title': 'PermitRootLogin prohibit-password',
         'detail': 'root may log in with a key'}]),
    'logins': (2016, 0, 0, 'last', [
        {'severity': 'medium', 'title': 'login for deploy from a network not seen before',
         'detail': 'first login from this network in the window, using the key added on '
                   '2026-10-29'}]),
    'firewall': (168, 0, 0, 'last', [
        {'severity': 'high', 'title': 'MySQL (3306) listens on all addresses',
         'detail': 'mysqld is bound to 0.0.0.0 and no firewall rule limits it'},
        {'severity': 'low', 'title': 'no host firewall rules are loaded'}]),
    'netflow': (0, 0, 0, None, []),          # optional packet sensor not enabled
    'opshealth': (2016, 0, 0, 'last', [
        {'severity': 'high', 'title': 'certificate for shop.example expires in 9 days',
         'detail': 'certbot.timer is inactive, so it will not renew on its own'},
        {'severity': 'medium', 'title': 'php8.3-fpm was killed by the OOM killer 3 times',
         'detail': 'last at 2026-10-31 02:14 UTC, during the backup window'},
        {'severity': 'low', 'title': 'failed unit: logrotate.service'}]),
    'bootchain': (0, 0, 0, 12, []),          # last result predates the window
    'keyreaders': (2016, 0, 0, 'last', []),
    'pkgverify': (7, 0, 0, 'last', []),
    'patches': (7, 0, 0, 'last', [
        {'severity': 'high', 'title': '14 security updates pending, 1 on the CISA KEV list',
         'detail': 'oldest pending for 23 days; a reboot is also pending for a new kernel'}]),
    'distrovuln': (7, 0, 0, 'last', [
        {'severity': 'medium', 'title': '3 known CVEs in installed packages have a fix available'}]),
    'appcode': (7, 0, 0, 'last', [
        {'severity': 'high', 'title': 'lodash 4.17.15 in /srv/shop (prototype pollution)',
         'detail': 'fixed in 4.17.21'},
        {'severity': 'high', 'title': 'credential in /srv/shop/.env',
         'detail': 'DB_PASSWORD=not-a-real-value'},
        {'severity': 'medium', 'title': '/srv/shop/.env is world-readable'}]),
    'osv': (7, 0, 0, 'last', []),
    'containers': (2016, 0, 0, 'last', []),
    'selfguard': (2016, 0, 0, 'last', []),
    'heartbeat': (0, 1840, 176, 'last', [
        {'severity': 'low',
         'title': 'no off-box heartbeat: nothing outside this machine notices if it goes silent',
         'detail': 'set a heartbeat URL to a dead-man service to be told when this server stops'}]),
}


def fill(db):
    with sqlite3.connect(db) as c:
        n = 0
        for job, (complete, partial, unavailable, age, findings) in WEEK.items():
            last = 0.0
            for coverage, count in (('complete', complete), ('partial', partial),
                                    ('unavailable', unavailable)):
                # Receipts spread over the window; one row per run keeps the counts real.
                for i in range(count):
                    n += 1
                    at = NOW - 7 * DAY + (i + 0.5) * (7 * DAY / count)
                    last = max(last, at)
                    c.execute('INSERT INTO defender_runs(run_id,job,observed_at,coverage,error,'
                              'digest,finding_count) VALUES(?,?,?,?,?,?,?)',
                              (f'sample-{n:06d}', job, at, coverage, '', 'sample', len(findings)))
            if age is not None:
                ts = last if age == 'last' else NOW - age * DAY
                c.execute('INSERT OR REPLACE INTO snapshots(kind,ts,duration,error,payload) '
                          'VALUES(?,?,?,?,?)', (job, int(ts), 1.0, '', json.dumps(findings)))


def main():
    with tempfile.TemporaryDirectory() as tmp:
        db = os.path.join(tmp, 'sample.db')
        Store(db).close()
        fill(db)
        text = review.render(review.build(db, days=7, now=NOW, host=HOST))
    sys.stdout.write(BANNER + '\n\n' + text)


if __name__ == '__main__':
    main()
