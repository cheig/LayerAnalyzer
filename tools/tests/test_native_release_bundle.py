"""Native bundle acquisition must be atomic with respect to validation failures."""
import hashlib
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import fetch_native_deps as fetch


def digest(data):
    return hashlib.sha256(data).hexdigest()


class FixedNativeBundleTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.dest = self.root / 'clean-libs'
        self.archive = self.root / 'r3.zip'
        self.files = {'arm64-v8a/libwireshark.so': b'fixed-arm64', 'x86_64/libwireshark.so': b'fixed-x86'}
        self.manifest = {'sha256': '', 'url': 'https://example.invalid/r3.zip',
                         'files': {n: digest(d) for n, d in self.files.items()}}
        self.write_bundle(self.files.items())

    def write_bundle(self, entries):
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            with zipfile.ZipFile(self.archive, 'w') as archive:
                for name, data in entries:
                    archive.writestr(name, data)
        self.manifest['sha256'] = fetch.sha256(self.archive)

    def install(self):
        fetch.fetch(self.manifest, self.dest, self.archive)

    def test_clean_install_and_check_need_no_manual_rebuild_or_network(self):
        with patch.object(fetch.urllib.request, 'urlopen', side_effect=AssertionError('unexpected network')):
            self.install()
            fetch.fetch(self.manifest, self.dest, check=True)
            fetch.fetch(self.manifest, self.dest)

    def test_anonymous_download_installs_and_verifies_complete_fixed_bundle(self):
        with self.archive.open('rb') as stream, patch.object(fetch.urllib.request, 'urlopen', return_value=stream) as request:
            fetch.fetch(self.manifest, self.dest)
            self.assertNotIn('Authorization', request.call_args.args[0].headers)
        fetch.fetch(self.manifest, self.dest, check=True)

    def test_check_failure_without_local_rebuild_omits_rebuild_hint(self):
        # The promoted r3 pin ships the resolver fix inside the archive, so there is
        # no local rebuild step to prepare and the failure hint must not mention one.
        with self.assertRaises(ValueError) as caught:
            fetch.fetch(self.manifest, self.dest, check=True)
        message = str(caught.exception)
        self.assertIn('missing or modified', message)
        self.assertNotIn('local rebuild', message)
        self.assertFalse(self.dest.exists())

    def test_old_libraries_fail_check(self):
        self.install()
        (self.dest / next(iter(self.files))).write_bytes(b'old-r1')
        with self.assertRaisesRegex(ValueError, 'missing or modified'):
            fetch.fetch(self.manifest, self.dest, check=True)

    def test_wrong_archive_hash_does_not_create_destination(self):
        self.manifest['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'bundle SHA-256 mismatch'):
            self.install()
        self.assertFalse(self.dest.exists())

    def test_old_archive_is_rejected_without_overwriting_existing_fix(self):
        self.install()
        before = {n: (self.dest / n).read_bytes() for n in self.files}
        self.write_bundle((n, b'old-r1') for n in self.files)
        self.manifest['sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            self.install()
        self.assertEqual(before, {n: (self.dest / n).read_bytes() for n in self.files})

    def test_late_bad_file_hash_does_not_install_earlier_valid_file(self):
        self.write_bundle([(next(iter(self.files)), b'fixed-arm64'), ('x86_64/libwireshark.so', b'bad')])
        with self.assertRaisesRegex(ValueError, 'library SHA-256 mismatch'):
            self.install()
        self.assertFalse(self.dest.exists())

    def test_missing_extra_and_duplicate_files_are_rejected(self):
        for entries in ([list(self.files.items())[0]], [*self.files.items(), ('extra', b'x')],
                        [*self.files.items(), list(self.files.items())[0]]):
            with self.subTest(entries=entries):
                self.write_bundle(entries)
                with self.assertRaisesRegex(ValueError, 'file list'):
                    self.install()
                self.assertFalse(self.dest.exists())

    def test_manifest_paths_and_hashes_fail_closed(self):
        for name in ('../libwireshark.so', '/arm64-v8a/libwireshark.so', 'arm64-v8a/../libwireshark.so',
                     'arm64-v8a\\libwireshark.so', 'arm64-v8a/libwireshark.so:stream', 'mips/libwireshark.so'):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'Unsafe'):
                fetch.validate_manifest({'sha256': 'a' * 64, 'files': {name: 'b' * 64}})
        with self.assertRaisesRegex(ValueError, 'Invalid native SHA'):
            fetch.validate_manifest({'sha256': 'a' * 64, 'files': {'arm64-v8a/libz.a': 'unreviewed'}})
        with self.assertRaisesRegex(ValueError, 'unknown library'):
            fetch.validate_manifest({**self.manifest, 'requiredLocalRebuild': {'files': {'x86_64/libextra.so': 'c' * 64}}})

    def test_zip_symlink_is_rejected(self):
        name = next(iter(self.files))
        info = zipfile.ZipInfo(name)
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        self.write_bundle([(info, self.files[name]), ('x86_64/libwireshark.so', self.files['x86_64/libwireshark.so'])])
        with self.assertRaisesRegex(ValueError, 'Unsafe native bundle path'):
            self.install()
        self.assertFalse(self.dest.exists())

    def test_unsafe_directory_entry_is_rejected(self):
        self.write_bundle([*self.files.items(), ('../../escape/', b'')])
        with self.assertRaisesRegex(ValueError, 'Unsafe'):
            self.install()
        self.assertFalse(self.dest.exists())

    def test_cli_candidate_does_not_modify_default_destination(self):
        manifest = self.root / 'manifest.json'
        manifest.write_text(json.dumps(self.manifest))
        with patch.object(fetch, 'ROOT', self.root / 'untouched-repo'), patch.object(sys, 'argv',
                ['fetch_native_deps.py', '--manifest', str(manifest), '--destination', str(self.dest), '--archive', str(self.archive)]):
            fetch.main()
        self.assertFalse((self.root / 'untouched-repo').exists())
