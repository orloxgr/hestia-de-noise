"""Publication lifecycle checks using temporary paths, not a Hestia install."""
import contextlib
import copy
import importlib.util
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from policy import DEFAULT, MARKER
from test_engine import fixture_read, fixture_replace

spec = importlib.util.spec_from_file_location('denoise_installer', ROOT / 'tools/install.py')
installer = importlib.util.module_from_spec(spec); spec.loader.exec_module(installer)


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name)
        self.locations = {'BASE': self.path / 'code', 'ROUTE': self.path / 'web/plugins/de-noise',
                          'MENU': self.path / 'web/js/custom_scripts/hestia-de-noise.js',
                          'BRIDGE': self.path / 'bin/v-denoise-hestia',
                          'CRON': self.path / 'cron/hestia-de-noise',
                          'ROTATE': self.path / 'logrotate/hestia-de-noise'}
        for path in self.locations.values(): path.parent.mkdir(parents=True, exist_ok=True)
        self.original_cron = (MARKER + '\n# Previous job\n').encode()
        self.locations['CRON'].write_bytes(self.original_cron)
        self.stack = contextlib.ExitStack()
        for key, value in self.locations.items():
            self.stack.enter_context(patch.object(installer, key, value))
        self.stack.enter_context(patch.object(installer, 'preflight'))
        self.stack.enter_context(patch.object(installer, 'directory',
                                             side_effect=lambda p, **kw: p.mkdir(parents=True, exist_ok=True)))
        self.stack.enter_context(patch.object(installer, 'prepare_logs'))
        # Windows cannot fsync a read-only descriptor; production is Linux.
        self.stack.enter_context(patch.object(installer.os, 'fsync'))
        self.stack.enter_context(patch.object(installer, 'check_pointer', return_value=self.path / 'previous-release'))
        self.pointer = self.stack.enter_context(patch.object(installer, 'pointer'))
        self.stack.enter_context(patch.object(installer.engine, 'locked', side_effect=contextlib.nullcontext))
        self.stack.enter_context(patch.object(installer.engine, 'recover'))
        self.stack.enter_context(patch.object(installer.storage, 'read', side_effect=fixture_read))
        self.stack.enter_context(patch.object(installer.storage, 'replace', side_effect=fixture_replace))
        self.stack.enter_context(patch.object(installer.engine, 'collect', return_value=[]))
        self.policy = copy.deepcopy(DEFAULT)
        self.policy['mode'] = 'enforce'; self.policy['agents'] = ['ExampleCrawler']
        self.stack.enter_context(patch.object(installer.engine, 'load', return_value=self.policy))

    def tearDown(self):
        self.stack.close(); self.temp.cleanup()

    def test_failed_install_restores_integration_and_previous_code_pointer(self):
        with patch.object(installer.engine, 'apply', side_effect=RuntimeError('nginx: configuration rejected')):
            with self.assertRaisesRegex(RuntimeError, 'configuration rejected'):
                installer.install()
        self.assertEqual(self.locations['CRON'].read_bytes(), self.original_cron)
        self.assertFalse(self.locations['BRIDGE'].exists())
        self.assertFalse(self.locations['MENU'].exists())
        self.assertFalse((self.locations['ROUTE'] / 'index.php').exists())
        self.assertEqual(self.pointer.call_args.args[0], self.path / 'previous-release')

    def test_update_uses_saved_policy_and_publishes_real_panel_route(self):
        with patch.object(installer.engine, 'apply', return_value={'changed_files': 0}) as apply, \
                contextlib.redirect_stdout(io.StringIO()):
            installer.install()
        self.assertEqual(apply.call_args.args[0], self.policy)
        self.assertIn(b'exec /usr/bin/python3 -I ', self.locations['BRIDGE'].read_bytes())
        self.assertIn(b'current', self.locations['BRIDGE'].read_bytes())
        page = (self.locations['ROUTE'] / 'index.php').read_bytes()
        self.assertNotIn(b'__INSTALL_ROOT__', page)
        self.assertIn(b'/releases/release-', page.replace(b'\\', b'/'))
        self.assertIn(b' sync >> ', self.locations['CRON'].read_bytes())


if __name__ == '__main__':
    unittest.main()
