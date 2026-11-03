"""Read-only diagnosis, resource bounds, privacy and authenticated scope."""
import copy
import datetime
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import engine
import log_analysis as review
from policy import DEFAULT, validate
from presets import RULES


class ScopeTests(unittest.TestCase):
    sites = [dict(key='alice/one.test', domain='one.test', kind='web'),
             dict(key='bob/two.test', domain='two.test', kind='web'),
             dict(key='bob/webmail.two.test', domain='webmail.two.test', kind='mail')]

    def test_only_known_web_domains_and_fixed_windows_are_accepted(self):
        self.assertEqual(len(review.selection(self.sites, 'all', 30)), 2)
        self.assertEqual(review.selection(self.sites, 'alice/one.test', 1440), self.sites[:1])
        for key, minutes in [('bob/webmail.two.test', 30), ('../../etc/passwd', 30),
                             ('all', True), ('all', 15), (None, 30)]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                review.selection(self.sites, key, minutes)

    def test_analysis_dispatch_has_no_policy_or_firewall_side_effect(self):
        with patch.object(engine, 'authorize', return_value=(True, 'admin')), \
             patch.object(engine, 'collect', return_value=self.sites), \
             patch.object(engine.log_analysis, 'review', return_value={'findings': []}) as scan, \
             patch.object(engine, 'apply') as apply, patch.object(engine, 'synchronize') as sync, \
             patch.object(engine, 'load') as load:
            result = engine.dispatch(dict(action='log_scan', actor='admin', target='all', minutes=30))
            self.assertTrue(result['ok']);scan.assert_called_once()
            apply.assert_not_called();sync.assert_not_called();load.assert_not_called()

    def test_owner_and_impersonated_context_cannot_read_other_logs(self):
        for role, owner in [(False, 'alice'), (True, 'alice')]:
            with patch.object(engine, 'authorize', return_value=(role, owner)), \
                 patch.object(engine, 'collect') as collect, self.assertRaises(PermissionError):
                engine.dispatch(dict(action='log_scan', actor='admin', target='all', minutes=30))
            collect.assert_not_called()

    def test_main_analysis_skips_protection_lock_and_recovery(self):
        request = dict(action='log_scan', actor='admin', target='all', minutes=30)
        stdin = io.TextIOWrapper(io.BytesIO(json.dumps(request).encode()))
        with patch.object(engine.os, 'geteuid', return_value=0, create=True), \
             patch.object(engine.sys, 'argv', ['addon.py']), patch.object(engine.sys, 'stdin', stdin), \
             patch.object(engine, 'dispatch', return_value={'ok': True}) as dispatch, \
             patch.object(engine, 'locked') as lock, patch.object(engine, 'recover') as recover, \
             patch.object(engine.wordpress, 'recover') as wp_recover:
            self.assertTrue(engine.main()['ok'])
            dispatch.assert_called_once_with(request)
            lock.assert_not_called();recover.assert_not_called();wp_recover.assert_not_called()

    def test_application_presets_removed_without_changing_saved_rules(self):
        self.assertEqual(RULES['filters'], [])
        saved = copy.deepcopy(DEFAULT)
        saved['filters'] = [dict(id='existing_listing', enabled=True, path='/',
            parameters=['app_listing_tag'], agents=['Googlebot'], action='limit', rate=7,
            burst=2, targets=['alice/one.test'])]
        normalized = validate(saved)
        self.assertEqual(normalized['filters'][0]['rate'], 7)
        self.assertEqual(normalized['filters'][0]['targets'], ['alice/one.test'])
        self.assertTrue(normalized['filters'][0]['enabled'])


@unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0, 'Trusted Linux logs')
class ScanTests(unittest.TestCase):
    def setUp(self):
        import time
        self.temp = tempfile.TemporaryDirectory(prefix='hdn-review-')
        self.root = Path(self.temp.name)
        self.state = self.root / 'state';self.state.mkdir(mode=0o700)
        self.logs = self.root / 'logs';self.logs.mkdir()
        self.path = self.logs / 'one.test.log';self.path.write_text('')
        self.now = int(time.time())
        self.sites = ScopeTests.sites[:2]
        self.enterContext(patch.object(review, 'LOG_ROOTS', (self.logs,)))

    def tearDown(self):
        self.temp.cleanup()

    def record(self, target, status=200, agent='Googlebot', ip='198.51.100.1', at=None, extra=''):
        at = self.now - 10 if at is None else at
        stamp = datetime.datetime.fromtimestamp(at, datetime.timezone.utc).strftime('%d/%b/%Y:%H:%M:%S %z')
        with self.path.open('a') as out:
            out.write(f'{ip} - - [{stamp}] "GET {target} HTTP/1.1" {status} 123 "-" "{agent}"{extra}\n')

    def scan(self, target='alice/one.test', **kwargs):
        return review.scan(self.sites, target, 30, self.state, now=self.now, **kwargs)

    def test_filter_diversity_suggests_site_review_not_a_ban_or_a_rate(self):
        for i in range(35):self.record('/catalog/?season='+str(i))
        result = self.scan()
        self.assertEqual(result['totals']['requests'], 35)
        row = result['findings'][0]
        self.assertEqual(row['kind'], 'crawl')
        self.assertEqual(row['site'], 'alice/one.test')
        self.assertEqual(row['combinations'], 35)
        self.assertEqual(row['verified_google'], 0)
        self.assertIsNone(row['mean_request_ms'])
        self.assertEqual(row['cache'], {})
        self.assertFalse({'rate', 'maxretry', 'ban', 'rule'} & set(row))
        self.assertIn('valid pages', row['advice'])
        self.assertEqual(list(self.state.iterdir()), [])

    def test_tracking_values_do_not_create_filter_diversity_or_expose_private_data(self):
        for i in range(35):self.record('/catalog/?season=summer&utm_source=private-'+str(i)+'&token=SECRET_VALUE', agent='MyPrivateAgentXYZ')
        result = self.scan()
        self.assertEqual(result['findings'], [])
        text = json.dumps(result)
        for private in ('SECRET_VALUE', 'private-1', '198.51.100.1', 'MyPrivateAgentXYZ'):
            self.assertNotIn(private, text)

    def test_missing_assets_and_php_404s_are_not_labeled_malicious(self):
        for _ in range(7):
            self.record('/uploads/logo.jpg', 404)
            self.record('/virtual.php', 404)
        rows = {row['path']: row for row in self.scan()['findings']}
        self.assertEqual(rows['/uploads/logo.jpg']['kind'], 'site')
        self.assertIn('virtual PHP route', rows['/virtual.php']['advice'])
        self.assertEqual(rows['/virtual.php']['kind'], 'investigate')

    def test_explicit_security_signature_is_separate_from_generic_high_volume(self):
        self.record('/.git/config', 403)
        self.record('/?file=../../etc/passwd', 404)
        rows = self.scan()['findings']
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row['kind'] == 'security' for row in rows))
        self.assertTrue(all('never bans' in row['advice'] for row in rows))

    def test_actual_time_window_and_explicit_timing_cache_fields(self):
        self.record('/.env', 403, at=self.now-1900)
        self.record('/.git/config', 403, extra=' rt=0.120 urt=0.100 cache=MISS')
        self.record('/.git/config', 403, extra=' rt=0.080 urt=0.080 cache=HIT')
        row = self.scan()['findings'][0]
        self.assertEqual(row['path'], '/.git/config')
        self.assertEqual(row['mean_request_ms'], 100)
        self.assertEqual(row['request_time_samples'], 2)
        self.assertEqual(row['mean_upstream_ms'], 90)
        self.assertEqual(row['cache'], {'MISS': 1, 'HIT': 1})

    def test_all_domain_results_remain_separate_and_shared_inodes_are_not_double_counted(self):
        self.record('/.env', 403)
        os.link(self.path, self.logs / 'two.test.log')
        result = self.scan('all')
        self.assertEqual(result['totals']['requests'], 1)
        self.assertEqual(result['findings'][0]['site'], 'alice/one.test')

    def test_server_errors_and_recorded_slow_routes_are_diagnostic_only(self):
        for _ in range(5):
            self.record('/slow', extra=' rt=2.000 urt=1.500')
            self.record('/broken', 503)
        rows = {row['path']: row for row in self.scan()['findings']}
        self.assertEqual(rows['/slow']['kind'], 'investigate')
        self.assertEqual(rows['/broken']['kind'], 'site')
        self.assertEqual(rows['/slow']['mean_upstream_ms'], 1500)

    def test_partial_budget_and_group_limit_are_explicit(self):
        for i in range(50):self.record('/probe'+str(i)+'.php', 404)
        with patch.object(review, 'READ_LIMIT', 1000), patch.object(review, 'FILE_LIMIT', 1000):
            result = self.scan()
        self.assertLessEqual(result['bytes_read'], 1000)
        self.assertTrue(result['partial'])
        with patch.object(review, 'GROUP_LIMIT', 1):
            result = self.scan()
        self.assertTrue(result['group_limit_reached'])
        self.assertTrue(result['partial'])

    def test_time_limit_and_malformed_lines_report_incomplete_coverage(self):
        self.record('/.env', 403)
        with patch.object(review.time, 'monotonic', side_effect=iter([0] + [10] * 20)):
            result = self.scan()
        self.assertTrue(result['partial'])
        self.assertEqual(result['findings'], [])
        with self.path.open('a') as out:out.write('bad log line\n' + 'unfinished')
        result = self.scan()
        self.assertEqual(result['totals']['unparsed'], 1)
        self.assertEqual(result['totals']['incomplete_lines'], 1)
        self.assertTrue(result['partial'])

    def test_distinct_counts_cap_and_report_lower_bounds(self):
        for i in range(35):self.record('/catalog/?season='+str(i))
        with patch.object(review, 'DISTINCT_LIMIT', 20):
            row = self.scan()['findings'][0]
        self.assertEqual(row['combinations'], 20)
        self.assertTrue(row['distinct_capped'])

    def test_symlink_and_writable_logs_refused_and_no_recent_data_is_not_a_clean_bill(self):
        self.path.unlink();self.path.symlink_to('/etc/passwd')
        result = self.scan()
        self.assertTrue(result['errors']);self.assertTrue(result['partial'])
        self.assertEqual(result['findings'], [])
        self.path.unlink();self.path.write_text('x');self.path.chmod(0o666)
        self.assertTrue(self.scan()['errors'])

    def test_two_reviews_cannot_overlap_but_protection_lock_is_independent(self):
        with review.scan_lock(self.state):
            with self.assertRaisesRegex(ValueError, 'already running'):
                with review.scan_lock(self.state):pass
        self.assertFalse((self.state/'operation.lock').exists())

    def test_google_verification_downloads_no_visitor_data_and_uses_private_cache(self):
        data = dict(prefixes=[dict(ipv4Prefix='198.51.100.0/24')])
        with patch.object(review.subprocess, 'run', return_value=type('Reply', (), {'returncode': 0, 'stdout': json.dumps(data).encode()})()) as fetch:
            self.record('/.env', 403)
            self.record('/.env', 403, ip='203.0.113.7')
            result = self.scan(verify_google=True)
        row = result['findings'][0]
        self.assertEqual(row['verified_google'], 1)
        self.assertEqual(row['unconfirmed_google'], 1)
        self.assertNotIn('198.51.100.1', repr(fetch.call_args))
        self.assertEqual(fetch.call_args.kwargs['timeout'], 2)
        cache = self.state / review.GOOGLE_CACHE
        self.assertEqual(cache.stat().st_mode & 0o777, 0o600)
        with patch.object(review.subprocess, 'run') as fetch:
            self.assertEqual(self.scan(verify_google=True)['findings'][0]['verified_google'], 1)
        fetch.assert_not_called()

    def test_unavailable_google_ranges_leave_scan_useful_and_unverified(self):
        self.record('/.env', 403)
        with patch.object(review.subprocess, 'run', side_effect=review.subprocess.TimeoutExpired('ranges', 2)):
            result = self.scan(verify_google=True)
        self.assertEqual(result['findings'][0]['verified_google'], 0)
        self.assertIn('unavailable', result['verification'])
