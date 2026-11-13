"""Hestia-specific boundaries when importing shared Webuzo analysis features."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import activity
import captcha_runtime
import engine
import policy
import review_findings

class PortSettings(unittest.TestCase):
    def test_new_panel_save_keeps_delegated_domain_bans_and_independent_agent_switches(self):
        saved = copy.deepcopy(policy.DEFAULT)
        saved['domain_bans']['sites'] = {'alice/one.test':dict(missing_files=True, suspicious_queries=False, any_404=True)}
        incoming = copy.deepcopy(policy.DEFAULT)
        incoming['ai_agents'] = ['GPTBot']; incoming['ai_agents_enabled'] = False
        incoming['search_agents'] = ['Googlebot-Image']; incoming['search_agents_enabled'] = True
        with patch.object(engine,'authorize',return_value=(True,'admin')), patch.object(engine,'load',return_value=saved), \
             patch.object(engine,'collect',return_value=[]),patch.object(engine,'snapshot',return_value={}),patch.object(engine,'apply') as apply:
            engine.dispatch(dict(action='save',actor='admin',policy=incoming))
        result = apply.call_args.args[0]
        self.assertEqual(result['domain_bans'],saved['domain_bans'])
        self.assertEqual(result['ai_agents'],['GPTBot']); self.assertFalse(result['ai_agents_enabled'])
        self.assertIn(policy.literal_regex('Googlebot-Image'),policy.global_config(result,[]))
        self.assertNotIn(policy.literal_regex('GPTBot'),policy.global_config(result,[]))

    def test_full_legacy_literal_policy_keeps_domain_preferences_and_compiled_agents(self):
        for enabled in (False,True):
            old = {key:copy.deepcopy(policy.DEFAULT[key]) for key in policy.V9_KEYS}
            old.update(schema=9,agents=['GPTBot','AhrefsBot','Googlebot-Image','Custom UA'],agents_enabled=enabled)
            old['domain_bans']['sites']={'alice/one.test':dict(missing_files=True,suspicious_queries=True,any_404=False)}
            new=policy.validate(old)
            self.assertEqual(new['domain_bans'],old['domain_bans'])
            for literal in old['agents']:
                self.assertEqual(policy.literal_regex(literal) in policy.global_config(new,[]),enabled)

    @unittest.skipUnless(os.name == 'posix', 'Native Unix Nginx groups')
    def test_native_nginx_omitted_group_uses_same_named_group_not_passwd_primary(self):
        with patch('storage.read',return_value=b'user nginx;\n'),patch('grp.getgrnam') as lookup:
            self.assertEqual(captcha_runtime.worker_group(),'nginx')
            lookup.assert_called_once_with('nginx')
        with patch('storage.read',return_value=b'user nginx www-data;\n'),patch('grp.getgrnam') as lookup:
            self.assertEqual(captcha_runtime.worker_group(),'www-data')
            lookup.assert_called_once_with('www-data')

    def test_path_search_has_no_arbitrary_length_cap_but_rejects_control_characters(self):
        text='/'+('long-path/'*600)
        self.assertEqual(review_findings.filters({'query':text})['query'],text)
        with self.assertRaises(ValueError):review_findings.filters({'query':'/valid\ninvalid'})

@unittest.skipUnless(os.name=='posix' and os.geteuid()==0,'Native trusted log fixture')
class ActivityEmptyLimit(unittest.TestCase):
    def test_empty_nginx_limit_does_not_drop_real_agent_or_probe_matches(self):
        with tempfile.TemporaryDirectory() as temp:
            log=Path(temp)/'matches.log';stamp='2026-01-01T00:00:00+00:00'
            log.write_text(f'{stamp} own.test agent  403 enforce\t"GPTBot"\n'
                           f'{stamp} own.test missing-file  404 enforce\t"Scanner"\n'
                           f'{stamp} foreign.test agent  403 enforce\t"Private"\n')
            with patch.object(activity,'LOG',log):result=activity.summary({'own.test'},1767225601)
            self.assertEqual(result['total'],2)
            self.assertEqual({row['agent'] for row in result['rows']},{'GPTBot','Scanner'})
            self.assertTrue(all(row['outcome']=='blocked' for row in result['rows']))
            self.assertNotIn('Private',json.dumps(result))
