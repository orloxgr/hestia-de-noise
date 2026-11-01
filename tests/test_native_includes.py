"""Regression coverage for Hestia's native SSL ACME include convention."""
from contextlib import nullcontext
import errno
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import engine
import storage


class NativeIncludeTests(unittest.TestCase):
    def setUp(self):
        self.path = Path('/home/alice/conf/web/example.test/nginx.ssl.conf_letsencrypt')
        self.target = self.path.with_name('nginx.conf_letsencrypt')
        self.content = b'location ~ "^/\\.well-known/acme-challenge/(.*)$" { return 200 "$1.test"; }\n'

    def linked_read(self, value=None, uid=0, content=b'native ACME snippet', mode=stat.S_IFLNK):
        self.read = self.enterContext(patch.object(storage, 'read', side_effect=[OSError(errno.ELOOP, 'symlink'), content]))
        self.enterContext(patch.object(storage, 'parent', return_value=nullcontext(17)))
        self.enterContext(patch.object(storage.os, 'stat', return_value=SimpleNamespace(st_uid=uid, st_mode=mode)))
        self.enterContext(patch.object(storage.os, 'readlink', return_value=value if value is not None else str(self.target)))
        return storage.read_hestia_include(self.path)

    def test_absolute_native_target_is_read_without_following_the_ssl_link(self):
        self.assertEqual(self.linked_read(content=self.content), self.content)
        self.assertEqual(self.read.call_args.args, (self.target,))

    def test_relative_native_target_is_accepted(self):
        self.assertEqual(self.linked_read(value=self.target.name), b'native ACME snippet')

    def test_other_target_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'Unexpected target'):
            self.linked_read(value='/etc/shadow')
        self.assertEqual(self.read.call_count, 1)

    def test_user_owned_link_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'must belong to root'):
            self.linked_read(uid=1000)
        self.assertEqual(self.read.call_count, 1)

    def test_missing_target_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'target is missing'):
            self.linked_read(content=None)

    def test_other_symlink_names_are_refused(self):
        with patch.object(storage, 'read', side_effect=OSError(errno.ELOOP, 'symlink')):
            with self.assertRaisesRegex(ValueError, 'Unsupported symbolic include'):
                storage.read_hestia_include(self.path.with_name('nginx.ssl.conf_other'))

    def test_regular_snippet_uses_existing_reader(self):
        with patch.object(storage, 'read', return_value=self.content):
            self.assertEqual(storage.read_hestia_include(self.target), self.content)

    def test_native_include_is_inspected_for_conflicting_limits(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            destinations = [root / 'nginx.conf_hdn', root / 'nginx.ssl.conf_hdn']
            for destination in destinations:
                base = destination.with_name(destination.name.removesuffix('_hdn'))
                base.write_text('server {\n include ' + str(base) + '_*;\n}\n')
            (root / 'nginx.ssl.conf_letsencrypt').write_bytes(self.content)
            def fixture_read(path):
                path = Path(path)
                return path.read_bytes() if path.exists() else None
            site = {'owner': 'alice', 'domain': 'example.test', 'template': 'example-varnish',
                    'key': 'alice/example.test', 'suspended': False}
            with patch.object(engine, 'config_paths', return_value=destinations), \
                    patch.object(storage, 'read', side_effect=fixture_read), \
                    patch.object(storage, 'read_hestia_include', return_value=self.content) as include:
                result = engine.inspect_site(site)
                self.assertTrue(result['supported'], result['reason'])
                self.assertEqual(result['template'], 'example-varnish')
                include.assert_called_once_with(root / 'nginx.ssl.conf_letsencrypt')
            with patch.object(engine, 'config_paths', return_value=destinations), \
                    patch.object(storage, 'read', side_effect=fixture_read), \
                    patch.object(storage, 'read_hestia_include', return_value=b'limit_req zone=other;\n'):
                result = engine.inspect_site(site)
                self.assertFalse(result['supported'])
                self.assertIn('Another domain include defines request limits', result['reason'])


if __name__ == '__main__':
    unittest.main()
