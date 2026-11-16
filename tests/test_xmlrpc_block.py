"""XML-RPC disabling is an explicit selected-site choice, independent of limits."""
import copy
import io
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import engine
import xmlrpc_block
from policy import DEFAULT, global_config, validate


class XmlrpcBlockTests(unittest.TestCase):
    def test_jetpack_lookup_loads_complete_official_list_without_mutations(self):
        with patch.object(xmlrpc_block.urllib.request, 'urlopen', return_value=io.BytesIO(
                b'192.0.2.1\n192.0.2.1/32\n198.51.100.0/24\n')) as fetch, \
                patch.object(engine, 'authorize', return_value=(True, 'admin')), \
                patch.object(engine, 'collect') as collect, patch.object(engine, 'apply') as apply:
            result = engine.dispatch(dict(actor='admin', action='xmlrpc_jetpack_ips'))
        self.assertEqual(result, dict(ok=True,ips=['192.0.2.1/32','198.51.100.0/24'],source=xmlrpc_block.JETPACK_URL))
        self.assertEqual(fetch.call_args.args, (xmlrpc_block.JETPACK_URL,))
        collect.assert_not_called(); apply.assert_not_called()

    def test_jetpack_lookup_rejects_partial_invalid_empty_and_failed_downloads(self):
        for value in (b'', b'<html>Server unavailable</html>', b'192.0.2.1\nnot-an-IP', b'\xff', b'2001:db8::/32'):
            with self.subTest(value=value), patch.object(xmlrpc_block.urllib.request, 'urlopen', return_value=io.BytesIO(value)):
                with self.assertRaisesRegex(ValueError, 'Could not load the official Jetpack IP list'):
                    xmlrpc_block.jetpack_ips()
        with patch.object(xmlrpc_block.urllib.request, 'urlopen', side_effect=OSError('connection unavailable')):
            with self.assertRaisesRegex(ValueError, 'connection unavailable'):
                xmlrpc_block.jetpack_ips()

    def test_jetpack_lookup_needs_admin_context_and_cannot_fetch_arbitrary_urls(self):
        for identity, extra in (((False,'alice'),{}), ((True,'alice'),{}), ((True,'admin'),{'url':'http://internal.test'})):
            with self.subTest(identity=identity,extra=extra), patch.object(engine,'authorize',return_value=identity), \
                    patch.object(xmlrpc_block, 'jetpack_ips') as fetch:
                with self.assertRaises((PermissionError, ValueError)):
                    engine.dispatch(dict(actor='admin',action='xmlrpc_jetpack_ips',**extra))
                fetch.assert_not_called()

    def test_previous_policy_upgrades_without_enabling_or_selecting_sites(self):
        old = copy.deepcopy(DEFAULT); old.pop('xmlrpc_block'); old['schema'] = 13
        old['mode'] = 'enforce'; old['xmlrpc'].update(enabled=True, rate=7, burst=2)
        new = validate(old)
        self.assertEqual(new['schema'], 15)
        self.assertEqual(new['xmlrpc_block'], dict(exceptions={}, enabled=False, targets=[]))
        self.assertEqual(new['xmlrpc'], old['xmlrpc'])

    def test_empty_selection_never_means_all_sites_and_disabled_switch_is_inert(self):
        sites = [dict(key='alice/one.test'), dict(key='bob/two.test')]
        for settings in (dict(exceptions={}, enabled=True, targets=[]), dict(exceptions={}, enabled=False, targets=['alice/one.test'])):
            policy = copy.deepcopy(DEFAULT); policy['xmlrpc_block'] = settings
            section = global_config(policy, sites).split('map $server_name $hdn_xmlrpc_disabled_site {')[1].split('}')[0]
            self.assertNotIn('one.test 1;', section)
            self.assertNotIn('two.test 1;', section)

    def test_scope_excludes_unselected_suspended_unsupported_and_mail_sites(self):
        sites = [dict(key='alice/one.test'), dict(key='bob/two.test'),
                 dict(key='alice/suspended.test', suspended=True), dict(key='alice/bad.test', supported=False),
                 dict(key='alice/mail.test', kind='mail')]
        policy = copy.deepcopy(DEFAULT)
        policy['xmlrpc_block'] = dict(exceptions={}, enabled=True, targets=[s['key'] for s in sites if s['key'] != 'bob/two.test'])
        section = global_config(policy, sites).split('map $server_name $hdn_xmlrpc_disabled_site {')[1].split('}')[0]
        self.assertIn('one.test 1;', section)
        for name in ('two', 'suspended', 'bad', 'mail'):
            self.assertNotIn(name + '.test 1;', section)

    def test_invalid_settings_are_rejected_and_targets_deduplicated(self):
        policy = copy.deepcopy(DEFAULT)
        policy['xmlrpc_block'] = dict(exceptions={}, enabled=True, targets=['alice/one.test', 'alice/one.test'])
        self.assertEqual(validate(policy)['xmlrpc_block']['targets'], ['alice/one.test'])
        for settings in (dict(exceptions={}, enabled=1, targets=[]), dict(exceptions={}, enabled=True, targets='all'),
                         dict(exceptions={}, enabled=True, targets=['../one.test']), dict(exceptions={}, enabled=True, targets=[None]),
                         dict(exceptions={}, enabled=True, targets=[], all=True)):
            with self.subTest(settings=settings), self.assertRaises(ValueError):
                validate({**policy, 'xmlrpc_block': settings})

    def test_older_panel_preserves_saved_choices_and_current_panel_can_clear_them(self):
        saved = copy.deepcopy(DEFAULT)
        saved['xmlrpc_block'] = dict(exceptions={}, enabled=True, targets=['alice/one.test'])
        old = copy.deepcopy(DEFAULT); old.pop('xmlrpc_block'); old['schema'] = 13
        saved['xmlrpc_block']['exceptions'] = {'alice/one.test': ['192.0.2.1/32']}
        previous_form = copy.deepcopy(DEFAULT); previous_form['schema'] = 14
        previous_form['xmlrpc_block'] = dict(enabled=False, targets=[])
        retained = dict(enabled=False, targets=[], exceptions=saved['xmlrpc_block']['exceptions'])
        for incoming, expected in ((old, saved['xmlrpc_block']), (previous_form, retained),
                                   (copy.deepcopy(DEFAULT), xmlrpc_block.DEFAULT)):
            with patch.object(engine, 'authorize', return_value=(True, 'admin')), \
                    patch.object(engine, 'load', return_value=saved), patch.object(engine, 'collect', return_value=[]), \
                    patch.object(engine, 'snapshot', return_value={}), patch.object(engine, 'apply') as apply:
                engine.dispatch(dict(action='save', actor='admin', policy=incoming))
            self.assertEqual(apply.call_args.args[0]['xmlrpc_block'], expected)

    def test_schema14_keeps_selections_and_adds_empty_exceptions(self):
        old = copy.deepcopy(DEFAULT); old['schema'] = 14
        old['xmlrpc_block'] = dict(enabled=True, targets=['alice/one.test'])
        block = validate(old)['xmlrpc_block']
        self.assertEqual(block, dict(enabled=True, targets=['alice/one.test'], exceptions={}))

    def test_ip_validation_normalizes_ipv4_ipv6_and_cidr_without_arbitrary_limits(self):
        policy = copy.deepcopy(DEFAULT)
        policy['xmlrpc_block']['exceptions'] = {'alice/one.test': [
            '192.0.2.10', '192.0.2.10/32', '192.0.2.123/24', '2001:db8::1', '::/0', '0.0.0.0/0']}
        self.assertEqual(validate(policy)['xmlrpc_block']['exceptions']['alice/one.test'],
                         ['192.0.2.10/32', '192.0.2.0/24', '2001:db8::1/128', '::/0', '0.0.0.0/0'])
        for invalid in ([], {'../one.test': []}, {'alice/one.test': '192.0.2.1'},
                        {'alice/one.test': [123]}, {'alice/one.test': ['192.0.2.1; return 200;']},
                        {'alice/one.test': ['2001:db8::1%eth0']}, {'alice/one.test': ['example.test']},
                        {'alice/one.test': ['192.0.2.1/33']}):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                validate({**policy, 'xmlrpc_block': {**policy['xmlrpc_block'], 'exceptions': invalid}})

    def test_exceptions_emit_only_for_active_selected_supported_web_sites(self):
        policy = copy.deepcopy(DEFAULT)
        keys = ['alice/one.test', 'bob/two.test', 'alice/suspended.test', 'alice/unsupported.test', 'alice/mail.test']
        policy['xmlrpc_block'] = dict(enabled=True, targets=[key for key in keys if key != 'bob/two.test'],
                                     exceptions={key: ['192.0.2.1'] for key in keys})
        sites = [dict(key=key, suspended='suspended' in key, supported='unsupported' not in key,
                      kind='mail' if 'mail' in key else 'web') for key in keys]
        text = global_config(policy, sites)
        section = text.split('map $server_name $hdn_xmlrpc_exempt {')[1].split('}')[0]
        self.assertIn('one.test $hdn_xmlrpc_allow_', section)
        self.assertEqual(text.count('geo $remote_addr $hdn_xmlrpc_allow_'), 1)
        for name in ('two', 'suspended', 'unsupported', 'mail'):
            self.assertNotIn(name+'.test', section)
        policy['xmlrpc_block']['enabled'] = False
        self.assertNotIn('geo $remote_addr $hdn_xmlrpc_allow_', global_config(policy, sites))


if __name__ == '__main__':
    unittest.main()
