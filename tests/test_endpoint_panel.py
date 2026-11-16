"""Exercise the actual native save parser, including an already open older form."""
import json
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which('php'), 'PHP CLI for native save parsing')
class SaveParser(unittest.TestCase):
    def parse(self, post):
        program = r'''
            $source = file_get_contents($argv[1]);
            $begin = strpos($source, '$agents = is_string(');
            $end = strpos($source, '} elseif ($request[\'action\'] === \'review_mark\')', $begin);
            if ($begin === false || $end === false) throw new RuntimeException('Missing save parser');
            $_POST = json_decode($argv[2], true, 512, JSON_THROW_ON_ERROR);
            $request = []; $submitted = null;
            eval(substr($source, $begin, $end - $begin));
            echo json_encode($request['policy'], JSON_THROW_ON_ERROR);
        '''
        return subprocess.run(['php', '-r', program, str(ROOT/'panel/index.php'), json.dumps(post)],
                              capture_output=True, text=True)

    def base(self):
        return dict(mode='enforce',endpoint404_duration='1',endpoint404_unit='days',
                    endpoint404_maxretry='3',endpoint404_findtime='600')

    def test_prior_open_hestia_forms_do_not_submit_or_clear_the_new_switch(self):
        for schema in (12,13):
            post=self.base()
            if schema==12:
                post.pop('endpoint404_maxretry');post.pop('endpoint404_findtime')
            result=self.parse(post)
            self.assertEqual(result.returncode,0,result.stderr)
            policy=json.loads(result.stdout)
            self.assertEqual(policy['schema'],schema)
            self.assertNotIn('xmlrpc_block',policy)

    def test_current_checked_empty_and_disabled_selections_parse_exactly(self):
        for enabled,targets in ((True,['alice/one.test']),(True,[]),(False,[])):
            post=dict(self.base(),xmlrpc_block_present='1',xmlrpc_block_targets=targets)
            if enabled:post['xmlrpc_block_enabled']='on'
            result=self.parse(post)
            self.assertEqual(result.returncode,0,result.stderr)
            policy=json.loads(result.stdout)
            self.assertEqual(policy['schema'],14)
            self.assertEqual(policy['xmlrpc_block'],dict(enabled=enabled,targets=targets))
            self.assertEqual(policy['endpoint_404']['maxretry'],3)
            self.assertEqual(policy['endpoint_404']['findtime'],600)

    def test_new_form_parses_per_site_networks_and_can_clear_all_exceptions(self):
        for posted, expected in (({'alice/one.test':'192.0.2.1\n2001:db8::/32', 'bob/two.test':''},
                                  {'alice/one.test':['192.0.2.1','2001:db8::/32']}), ({}, {})):
            result=self.parse(dict(self.base(),xmlrpc_block_present='1',xmlrpc_exceptions_present='1',
                                   xmlrpc_block_exceptions=posted))
            self.assertEqual(result.returncode,0,result.stderr)
            policy=json.loads(result.stdout)
            self.assertEqual(policy['schema'],15)
            self.assertEqual(policy['xmlrpc_block'],dict(enabled=False,targets=[],exceptions=expected))
        for invalid in ('192.0.2.1', {'alice/one.test':['192.0.2.1']}):
            result=self.parse(dict(self.base(),xmlrpc_block_present='1',xmlrpc_exceptions_present='1',
                                   xmlrpc_block_exceptions=invalid))
            self.assertNotEqual(result.returncode,0)


if __name__=='__main__':unittest.main()
