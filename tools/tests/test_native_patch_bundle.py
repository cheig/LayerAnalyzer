import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

spec = importlib.util.spec_from_file_location('native_bundle', Path(__file__).resolve().parents[1] / 'fetch_native_deps.py')
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)


class NativePatchBundleTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.library = self.root / 'app/src/main/cpp/libs/arm64-v8a/libwireshark.so'
        self.library.parent.mkdir(parents=True)
        self.base, self.fixed = b'base-library', b'fixed-library'
        self.archive = self.root / 'base.zip'
        with zipfile.ZipFile(self.archive, 'w') as archive:
            archive.writestr('arm64-v8a/libwireshark.so', self.base)
        sha = lambda data: hashlib.sha256(data).hexdigest()
        manifest = {'sha256': sha(self.archive.read_bytes()), 'files': {
            'arm64-v8a/libwireshark.so': sha(self.base)}, 'requiredLocalRebuild': {
            'instructions': 'rebuild.md', 'files': {'arm64-v8a/libwireshark.so': sha(self.fixed)}}}
        (self.root / 'native_build').mkdir()
        (self.root / 'native_build/native-deps.json').write_text(json.dumps(manifest))

    def run_command(self, *args):
        with patch.object(bundle, 'ROOT', self.root), patch('sys.argv', ['fetch_native_deps.py', *args]), contextlib.redirect_stdout(io.StringIO()):
            bundle.main()

    def test_original_bundle_does_not_satisfy_current_check(self):
        self.library.write_bytes(self.base)
        with self.assertRaisesRegex(SystemExit, 'required local rebuilds'):
            self.run_command('--check')

    def test_fixed_bundle_passes_without_download(self):
        self.library.write_bytes(self.fixed)
        self.run_command('--check')
        self.run_command()

    def test_explicit_original_archive_does_not_undo_verified_patch(self):
        self.library.write_bytes(self.fixed)
        self.run_command('--archive', str(self.archive))
        self.assertEqual(self.fixed, self.library.read_bytes())

    def test_first_base_install_requires_rebuild_and_wrong_hash_is_rejected(self):
        with self.assertRaisesRegex(SystemExit, 'required local rebuild'):
            self.run_command('--archive', str(self.archive))
        self.assertEqual(self.base, self.library.read_bytes())
        self.library.write_bytes(b'unknown-library')
        with self.assertRaises(SystemExit):
            self.run_command('--check')


if __name__ == '__main__':
    unittest.main()
