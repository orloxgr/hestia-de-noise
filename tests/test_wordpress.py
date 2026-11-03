"""Native-jail settings, adoption, recovery and scope; never inspect WordPress."""
import base64
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import wordpress
import engine
from test_engine import fixture_read, fixture_replace


class WordPressTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.state = self.root / 'state'; self.state.mkdir()
        self.etc = self.root / 'etc'
        for folder in ['filter.d', 'action.d', 'jail.d', 'fail2ban.d']:
            (self.etc / folder).mkdir(parents=True)
        self.patches = [patch.object(wordpress, 'ETC', self.etc),
                        patch.object(wordpress.storage, 'read', side_effect=fixture_read),
                        patch.object(wordpress.storage, 'replace', side_effect=fixture_replace)]
        for p in self.patches: p.start()
        self.run = Mock(return_value='OK')

    def tearDown(self):
        for p in reversed(self.patches): p.stop()
        self.temp.cleanup()

    def test_fresh_install_stays_off_and_calls_no_external_commands(self):
        self.assertEqual(wordpress.install(self.state, self.run), {'managed': False})
        status = wordpress.snapshot(self.state, self.run)
        self.assertFalse(status['settings']['enabled'])
        self.assertFalse(status['loaded'])
        self.run.assert_not_called()

    def test_apply_validate_reload_and_namespace_with_exact_duration_seconds(self):
        value = {**copy.deepcopy(wordpress.DEFAULT), 'enabled': True}
        wordpress.apply(self.state, value, self.run)
        jail = (self.etc / 'jail.d/wordpress-login.local').read_text()
        self.assertIn('ExactBanUnit', jail)
        self.assertIn('bantime.multipliers = 300 259200 -1', jail)
        self.assertIn('filter = hdn-wordpress-login', jail)
        self.assertIn('actname=hestia-wordpress-WORDPRESS', jail)
        self.assertEqual([c.args for c in self.run.call_args_list],
                         [(wordpress.CLIENT, '-t'), (wordpress.CLIENT, 'reload')])
        self.run.reset_mock()
        wordpress.apply(self.state, value, self.run)
        self.run.assert_not_called()

    def test_candidate_failure_restores_previous_jail_settings_and_other_files(self):
        initial = {**copy.deepcopy(wordpress.DEFAULT), 'enabled': True}
        wordpress.apply(self.state, initial, self.run)
        before = wordpress.capture(wordpress.paths(self.state))
        unrelated = self.etc / 'jail.d/other-service.local'
        unrelated.write_text('[other]\nenabled = true\n')
        failing = Mock(side_effect=RuntimeError('configuration rejected'))
        with self.assertRaisesRegex(RuntimeError, 'configuration rejected'):
            wordpress.apply(self.state, {**initial, 'maxretry': 4}, failing)
        self.assertEqual(before, wordpress.capture(wordpress.paths(self.state)))
        self.assertEqual(unrelated.read_text(), '[other]\nenabled = true\n')
        self.assertFalse((self.state / wordpress.JOURNAL).exists())

    def test_reload_failure_restores_and_reloads_previous_configuration(self):
        initial = copy.deepcopy(wordpress.DEFAULT)
        wordpress.apply(self.state, initial, self.run)
        before = wordpress.capture(wordpress.paths(self.state))
        command = Mock(side_effect=['OK', RuntimeError('reload failed'), 'OK', 'OK'])
        with self.assertRaisesRegex(RuntimeError, 'reload failed'):
            wordpress.apply(self.state, {**initial, 'enabled': True}, command)
        self.assertEqual(before, wordpress.capture(wordpress.paths(self.state)))
        self.assertEqual(command.call_count, 4)

    def test_journal_cannot_restore_an_arbitrary_path(self):
        journal = {'before': {str(self.root / 'unrelated'): base64.b64encode(b'bad').decode()},
                   'reload_started': False, 'receipt_created': False}
        (self.state / wordpress.JOURNAL).write_text(json.dumps(journal))
        with self.assertRaisesRegex(ValueError, 'recovery paths'):
            wordpress.recover(self.state, self.run)
        self.assertFalse((self.root / 'unrelated').exists())

    def test_existing_unowned_file_is_not_replaced(self):
        path = self.etc / 'jail.d/wordpress-login.local'
        path.write_text('[wordpress-login]\nenabled = true\n')
        with self.assertRaisesRegex(ValueError, 'not owned'):
            wordpress.apply(self.state, wordpress.DEFAULT, self.run)
        self.assertEqual(path.read_text(), '[wordpress-login]\nenabled = true\n')
        self.run.assert_not_called()

    def test_adopt_and_uninstall_restores_original_standalone_jail(self):
        # Exact supported standalone format, including stable jail/action names.
        raw = (wordpress.LEGACY_HEADER.decode() + '''[wordpress-login]
enabled = true
filter = wordpress-login
backend = auto
logpath = /var/log/auth.log tail
usedns = no
port = 80,443
protocol = tcp
findtime = 5m
maxretry = 3
bantime = 5m
bantime.increment = true
bantime.factor = 1/300
bantime.multipliers = 300 259200 -1
bantime.overalljails = false
action = hestia-wordpress[name=WORDPRESS,port="80,443",protocol=tcp,blocktype=DROP]
''').encode()
        path = self.etc / 'jail.d/wordpress-login.local'; path.write_bytes(raw)
        history = self.etc / 'fail2ban.d/wordpress-history.local'
        old_history = wordpress.HISTORY_HEADER + b'[Definition]\ndbpurgeage = 30d\n'
        history.write_bytes(old_history)
        wordpress.install(self.state, self.run)
        self.assertTrue(wordpress.settings(self.state)['enabled'])
        self.assertNotEqual(path.read_bytes(), raw)
        wordpress.uninstall(self.state, self.run)
        self.assertEqual(path.read_bytes(), raw)
        self.assertEqual(history.read_bytes(), old_history)
        self.assertFalse((self.etc / 'filter.d/hdn-wordpress-login.conf').exists())
        self.assertFalse((self.state / wordpress.RECEIPT).exists())

    def test_status_reads_only_fail2ban_when_explicitly_requested(self):
        self.run.side_effect = ['Status\n`- Jail list: ssh-iptables, wordpress-login',
                                '192.0.2.5 2001:db8::5']
        data = wordpress.snapshot(self.state, self.run, live=True)
        self.assertTrue(data['active'])
        self.assertEqual(data['ips'], ['192.0.2.5', '2001:db8::5'])
        self.assertTrue(all(c.args[0] == wordpress.CLIENT for c in self.run.call_args_list))

    def test_ip_pagination_keeps_total_and_does_not_poll_when_not_requested(self):
        self.run.side_effect = ['Jail list: wordpress-login', ' '.join(f'198.51.100.{i}' for i in range(123))]
        data = wordpress.snapshot(self.state,self.run,live=True,page=3)
        self.assertEqual(len(data['ips']),23)
        self.assertEqual(data['pagination'],dict(page=3,pages=3,total=123,per_page=50,view='active'))
        self.assertEqual(self.run.call_count,2)
        self.run.reset_mock()
        self.assertEqual(wordpress.snapshot(self.state,self.run,page=3)['ips'],[])
        self.run.assert_not_called()

    def test_unban_only_accepts_ips_belonging_to_wordpress_jail(self):
        wordpress.apply(self.state, wordpress.DEFAULT, self.run)
        self.run.reset_mock(); self.run.return_value = '192.0.2.5'
        with self.assertRaisesRegex(ValueError, 'existing WordPress bans'):
            wordpress.unban(self.state, ['192.0.2.7'], self.run)
        self.assertEqual(self.run.call_count, 1)
        self.run.reset_mock()
        wordpress.unban(self.state, ['192.0.2.5'], self.run)
        self.assertEqual(self.run.call_args.args,
                         (wordpress.CLIENT, 'set', wordpress.JAIL, 'unbanip', '192.0.2.5'))

    def test_unban_all_completes_every_ip_beyond_old_five_hundred_limit(self):
        import ipaddress
        wordpress.apply(self.state,wordpress.DEFAULT,self.run)
        self.run.reset_mock()
        values=[str(ipaddress.ip_address('198.18.0.1')+number) for number in range(650)]
        self.run.return_value=' '.join(values)
        wordpress.unban(self.state,'all',self.run)
        self.assertEqual(self.run.call_count,651)
        self.assertEqual({call.args[-1] for call in self.run.call_args_list[1:]}, set(values))

    def test_users_cannot_invoke_wordpress_actions(self):
        for action in ['wordpress_status', 'wordpress_save', 'wordpress_unban']:
            with patch.object(engine, 'hestia', return_value={'alice': {'SUSPENDED': 'no', 'ROLE': 'user'}}):
                with self.assertRaises(PermissionError):
                    engine.authorize({'actor': 'alice', 'owner': 'alice', 'action': action})

    def test_http_disable_runs_even_if_optional_fail2ban_change_fails(self):
        from policy import DEFAULT
        with patch.object(engine, 'authorize', return_value=(True, 'admin')), \
                patch.object(engine, 'load', return_value=copy.deepcopy(DEFAULT)), \
                patch.object(engine, 'collect', return_value=[]), \
                patch.object(engine, 'apply') as http_apply, \
                patch.object(wordpress, 'read_json', return_value={}), \
                patch.object(wordpress, 'settings', return_value=wordpress.DEFAULT), \
                patch.object(wordpress, 'apply', side_effect=RuntimeError('Fail2ban unavailable')):
            with self.assertRaisesRegex(RuntimeError, 'Fail2ban unavailable'):
                engine.dispatch({'actor': 'admin', 'owner': 'admin', 'action': 'disable'})
        self.assertEqual(http_apply.call_args.args[0]['mode'], 'off')

    def test_invalid_policy_cannot_reach_fail2ban(self):
        for update in [{'maxretry': True}, {'findtime': 0}, {'enabled': 'true'},
                       {'durations': [300, 60, -1]}, {'durations': [300, 259200, 0]}]:
            with self.assertRaises(ValueError):
                wordpress.apply(self.state, {**wordpress.DEFAULT, **update}, self.run)
        self.run.assert_not_called()

    def test_arbitrary_durations_preserve_exact_permanent_sentinel_without_float_scaling(self):
        value={**wordpress.DEFAULT, 'durations':[4020,259200,-1]}
        wordpress.validate(value)
        text=next(body.decode() for path,body in wordpress.render(value,self.state).items() if path.name=='wordpress-login.local')
        self.assertIn('ExactBanUnit',text)
        self.assertIn('bantime.multipliers = 4020 259200 -1',text)
        self.assertNotIn('bantime.factor = 1/',text)



if __name__ == '__main__':
    unittest.main()
