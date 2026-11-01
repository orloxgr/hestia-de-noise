import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import activity


@unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0, 'Requires Linux root-owned log fixture')
class ActivityTests(unittest.TestCase):
    def test_owner_scope_rotation_old_formats_and_observation_are_not_block_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'matches.log'
            stamp = '2026-01-01T00:00:00+00:00'
            now = 1767225601
            log.write_text('\n'.join([
                f'{stamp} own.test private-file - 403 enforce',
                f'{stamp} own.test agent - 403 observe',
                f'{stamp} own.test private-file - 403',
                f'{stamp} own.test REJECTED 429',
                f'{stamp} other.test agent - 403 enforce',
                f'2025-01-01T00:00:00+00:00 own.test agent - 403 enforce',
                'invalid record']) + '\n')
            log.with_suffix('.log.1').write_text(f'{stamp} own.test static-maps - 404 enforce\n')
            with patch.object(activity, 'LOG', log):
                report = activity.summary({'own.test'}, now)
                self.assertEqual(report['total'], 5)
                self.assertEqual(sum(r['count'] for r in report['rows'] if r['outcome'] == 'blocked'), 3)
                self.assertEqual({r['domain'] for r in report['rows']}, {'own.test'})
                self.assertEqual({r['outcome'] for r in report['rows']}, {'blocked', 'observed', 'matched'})
                self.assertNotIn('stamp', report['recent'][0])
                with patch.object(activity, 'MAX_BYTES', 100):
                    bounded = activity.summary({'own.test'}, now)
                    self.assertTrue(bounded['sample_truncated'])
                    self.assertLessEqual(bounded['bytes_read'], 200)
                alias = Path(directory) / 'alias.log'
                alias.symlink_to(log)
                with patch.object(activity, 'LOG', alias), self.assertRaises(OSError):
                    activity.summary({'own.test'}, now)
