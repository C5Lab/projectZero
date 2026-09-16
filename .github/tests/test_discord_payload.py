"""Run locally: python -m unittest discover -s .github/tests -v (no network)."""
import json
import os
from pathlib import Path
import subprocess
import sys
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github/workflows/esp32c5-build-master.yml'
RELEASE = 'https://github.com/C5Lab/projectZero/releases/tag/v1.7.2'
FLASHER = 'https://C5Lab.github.io/projectZero/'


class DiscordPayloadTests(unittest.TestCase):
    def payload(self, body):
        workflow = WORKFLOW.read_text(encoding='utf-8').split('  discord:\n')[1]
        self.assertIn("python - <<'PY'", workflow)
        code = textwrap.dedent(workflow.split("python - <<'PY'\n", 1)[1].split('\n          PY', 1)[0])
        env = dict(os.environ, RELEASE_BODY=body, TAG='v1.7.2',
                   RELEASE_PAGE=RELEASE, PAGES_LINK=FLASHER, REPO='C5Lab/projectZero')
        result = subprocess.run([sys.executable, '-c', code], env=env,
                                capture_output=True, check=True, encoding='utf-8')
        payload = json.loads(result.stdout)
        content = payload['content']
        self.assertEqual(payload['allowed_mentions'], {'parse': []})
        self.assertTrue(content.startswith('projectZero v1.7.2\n'))
        self.assertEqual(content.count(RELEASE), 1)
        self.assertEqual(content.count(FLASHER), 1)
        self.assertNotIn('/releases/download/', content)
        self.assertLessEqual(len(content.encode('utf-16-le')) // 2, 2000)
        return content

    def test_real_release(self):
        body = (ROOT / '.github/tests/fixtures/release-v1.7.2.md').read_text(encoding='utf-8')
        content = self.payload(body)
        self.assertIn('Summary\nJanOS 1.7.2 release with a new capture gateway', content)
        self.assertIn('Key changes', content)
        self.assertNotIn('Release v1.7.2 published.', content)
        self.assertNotIn('Full package:', content)
        self.assertTrue(content.endswith('... More in the release.'))

    def test_empty(self):
        self.assertEqual(self.payload(' \r\n'),
                         f'projectZero v1.7.2\nRelease page: {RELEASE}\nWeb flasher: {FLASHER}')

    def test_long_unicode(self):
        body = 'Summary\n' + 'Zażółć gęślą jaźń 🚀 漢字 ' * 300
        content = self.payload(body)
        self.assertIn('Summary\nZażółć gęślą jaźń 🚀 漢字', content)
        self.assertTrue(content.endswith('... More in the release.'))
        self.assertNotIn('\ufffd', content)

    def test_duplicate_links_preserve_prose(self):
        body = (f'Release v1.7.2 published.\nRelease page: {RELEASE}\n'
                f'Web flasher: {FLASHER}\nSummary\nFix downloads using '
                f'[release]({RELEASE}) and [flasher]({FLASHER}).\n'
                'BIN: https://github.com/C5Lab/projectZero/releases/download/v1.7.2/projectZero.bin\n'
                'Keep the changelog and https://example.com/issue/123')
        content = self.payload(body)
        self.assertIn('Fix downloads using release and flasher.', content)
        self.assertIn('Keep the changelog and https://example.com/issue/123', content)
        self.assertNotIn('BIN:', content)


if __name__ == '__main__':
    unittest.main()
