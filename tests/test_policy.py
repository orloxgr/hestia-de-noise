import copy
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from policy import DEFAULT, validate, domain, target, site_mode, global_config, site_config


class PolicyTests(unittest.TestCase):
    def test_install_defaults_do_not_deny_anything(self):
        policy = validate(DEFAULT)
        self.assertEqual(policy['mode'], 'observe')
        self.assertFalse(policy['agents'])
        self.assertFalse(policy['login']['enabled'])
        self.assertFalse(policy['xmlrpc']['enabled'])
        self.assertFalse(policy['scanners'])

    def test_normalization_and_invalid_inputs(self):
        policy = copy.deepcopy(DEFAULT)
        policy['agents'] = ['Crawler', ' crawler ', 'Other']
        self.assertEqual(validate(policy)['agents'], ['Crawler', 'Other'])
        for text in ['a\nreturn 403;', 'a\rfoo', 'agent\x00x', 'a', 'x' * 161]:
            with self.subTest(text=text):
                policy['agents'] = [text]
                with self.assertRaises(ValueError):
                    validate(policy)
        for name in ['../test', '*.test', 'x;return403', 'x..test', 'x.-test', 'TEST.example']:
            with self.assertRaises(ValueError):
                domain(name)
        with self.assertRaises(ValueError):
            target('owner/../../etc')

    def test_different_site_and_alias_scope(self):
        policy = copy.deepcopy(DEFAULT)
        policy['mode'] = 'enforce'
        policy['overrides'] = {'alice/one.test': 'off'}
        site = {'key': 'alice/one.test', 'suspended': False}
        self.assertEqual(site_mode(policy, site), 'off')
        self.assertEqual(site_mode(policy, {'key': 'alice/two.test'}), 'enforce')
        self.assertEqual(site_mode(policy, {'key': 'bob/one.test'}), 'enforce')
        self.assertEqual(site_mode(policy, {'key': 'bob/one.test', 'suspended': True}), 'off')

    def test_rates_never_intercept_general_rest_or_ajax(self):
        policy = copy.deepcopy(DEFAULT)
        policy['login']['enabled'] = True
        policy['xmlrpc']['enabled'] = True
        text = global_config(policy, [])
        self.assertIn(':POST:/wp-login', text)
        self.assertIn(':POST:/xmlrpc', text)
        self.assertNotIn('wp-admin', text)
        self.assertNotIn('wp-json', text)
        self.assertNotIn('$args', text)
        self.assertNotIn('$http_x_forwarded_for', text)
        self.assertIn('$server_name:$binary_remote_addr', text)

    def test_off_cannot_deny_requests(self):
        policy = copy.deepcopy(DEFAULT)
        policy['mode'] = 'off'
        policy['agents'] = ['Crawler']
        text = site_config(policy, {'key': 'alice/one.test'})
        self.assertNotIn('return 403', text)
        self.assertIn('set $hdn_mode off;', text)

    def test_upgrade_keeps_old_policy_without_adding_restrictions(self):
        old = copy.deepcopy(DEFAULT)
        del old['filters'], old['static']
        old.update(schema=1, mode='enforce', agents=['ExistingBot'])
        old['overrides'] = {'alice/one.test': 'off'}
        upgraded = validate(old)
        self.assertEqual(upgraded['agents'], old['agents'])
        self.assertEqual(upgraded['overrides'], old['overrides'])
        self.assertEqual(upgraded['mode'], 'enforce')
        self.assertEqual(upgraded['filters'], [])
        self.assertEqual(upgraded['static'], [])

    def test_rule_config_injection_and_unsafe_static_root_are_rejected(self):
        policy = copy.deepcopy(DEFAULT)
        policy['filters'] = [{'id': 'facets', 'enabled': True, 'path': '/shop/',
                              'parameters': ['orderby'], 'agents': ['Applebot'],
                              'action': 'limit', 'rate': 30, 'burst': 5, 'targets': []}]
        self.assertEqual(validate(policy)['filters'][0]['agents'], ['applebot'])
        for key, value in [('id', 'x;return'), ('path', '/x/../y/'),
                           ('parameters', ['a;return']), ('targets', ['alice/../x']), ('rate', True)]:
            invalid = copy.deepcopy(policy)
            invalid['filters'][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate(invalid)
        policy['static'] = [{'id': 'maps', 'enabled': True, 'path': '/wp-content/', 'extensions': ['map'], 'targets': []}]
        with self.assertRaisesRegex(ValueError, 'document root'):
            site_config(policy, {'key': 'alice/one.test'})


if __name__ == '__main__':
    unittest.main()
