"""Reject wrong signing identities and unsafe or inconsistent release uploads."""
import copy
from pathlib import Path
import sys
import struct
import tempfile
import unittest
import zipfile
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import create_release_draft as draft
import stage_release as staging
from verify_release_apk import check_alignment, check_identity


class SigningTest(unittest.TestCase):
    def setUp(self):
        self.certificate = 'a' * 64
        self.signing = ('Verified using v2 scheme (APK Signature Scheme v2): true\n'
                        f'Signer #1 certificate SHA-256 digest: {self.certificate}\n')
        self.badging = ("package: name='com.layeranalyzer.android' versionCode='2' versionName='1.0.0-rc.1'\n"
                        "native-code: 'arm64-v8a'\n")
        self.build = {'applicationId': 'com.layeranalyzer.android', 'versionCode': 2,
                      'versionName': '1.0.0-rc.1', 'abis': ['arm64-v8a']}

    def check(self, signing=None, badging=None, tag='v1.0.0-rc.1'):
        check_identity(signing or self.signing, badging or self.badging,
                       self.build, self.certificate, tag)

    def test_correct_release(self):
        self.check()

    def test_wrong_key(self):
        with self.assertRaises(ValueError):
            self.check(signing=self.signing.replace('a' * 64, 'b' * 64))

    def test_missing_v2(self):
        with self.assertRaises(ValueError):
            self.check(signing=self.signing.replace(': true', ': false'))

    def test_additional_signer(self):
        with self.assertRaises(ValueError):
            self.check(signing=self.signing + 'Signer #2 certificate SHA-256 digest: ' + 'b' * 64 + '\n')

    def test_wrong_tag(self):
        with self.assertRaises(ValueError):
            self.check(tag='v1.0.0')

    def test_wrong_package_version_abi_or_debuggable(self):
        for badging in [self.badging.replace('com.layeranalyzer.android', 'com.example.debug'),
                        self.badging.replace("versionCode='2'", "versionCode='1'"),
                        self.badging.replace('1.0.0-rc.1', '1.0'),
                        self.badging.replace('arm64-v8a', 'x86_64'),
                        self.badging + 'application-debuggable\n']:
            with self.subTest(badging=badging), self.assertRaises(ValueError):
                self.check(badging=badging)


class AlignmentTest(unittest.TestCase):
    def make_apk(self, path, padding=True, compressed=False, elf_alignment=16384):
        data = bytearray(120)
        data[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<Q', data, 32, 64)
        struct.pack_into('<HH', data, 54, 56, 1)
        struct.pack_into('<IIQQQQQQ', data, 64, 1, 5, 0, 0, 0, 120, 120, elf_alignment)
        entry = zipfile.ZipInfo('lib/arm64-v8a/example.so')
        if padding:
            size = 16384 - 30 - len(entry.filename)
            entry.extra = struct.pack('<HH', 0xffff, size - 4) + bytes(size - 4)
        entry.compress_type = zipfile.ZIP_DEFLATED if compressed else zipfile.ZIP_STORED
        with zipfile.ZipFile(path, 'w') as archive:
            archive.writestr(entry, data)

    def test_zip_and_elf_alignment(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.apk'
            self.make_apk(path)
            check_alignment(path)
            for options in [{'padding': False}, {'compressed': True}, {'elf_alignment': 4096}]:
                self.make_apk(path, **options)
                with self.subTest(options=options), self.assertRaises(ValueError):
                    check_alignment(path)


class DraftTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.stage = Path(self.temp.name)
        path = self.stage / 'app.apk'
        path.write_bytes(b'candidate')
        self.assets = [{'name': path.name, 'size': path.stat().st_size,
                        'state': 'uploaded', 'digest': 'sha256:' + draft.digest(path)}]

    def test_complete_upload(self):
        self.assertEqual({'app.apk'}, draft.check_assets(self.assets, self.stage, complete=True))

    def test_incomplete_upload_can_resume(self):
        self.assertEqual(set(), draft.check_assets([], self.stage))
        with self.assertRaises(ValueError):
            draft.check_assets([], self.stage, complete=True)

    def test_mismatched_or_injected_assets_fail(self):
        for key, value in [('name', 'extra.apk'), ('size', 0), ('digest', 'sha256:' + '0' * 64),
                           ('state', 'starter')]:
            assets = copy.deepcopy(self.assets)
            assets[0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                draft.check_assets(assets, self.stage)
        with self.assertRaises(ValueError):
            draft.check_assets(self.assets * 2, self.stage)

    def test_published_or_wrong_commit_release_is_immutable(self):
        release = {'draft': True, 'tag_name': 'v1.0', 'target_commitish': 'a' * 40}
        draft.check_draft(release, 'v1.0', 'a' * 40)
        for key, value in [('draft', False), ('tag_name', 'v2.0'), ('target_commitish', 'b' * 40)]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                draft.check_draft(release | {key: value}, 'v1.0', 'a' * 40)

    def test_tag_mismatch_rejected_before_network(self):
        (self.stage / 'app.apk').rename(self.stage / 'LayerAnalyzer-arm64-v8a-1.0.apk')
        staging.write_checksums(self.stage)
        with patch.object(draft, 'api') as api:
            with self.assertRaises(ValueError):
                draft.create(self.stage, 'owner/repo', 'v2.0', 'a' * 40)
            api.assert_not_called()


class ApkAttachmentsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.stage = Path(self.temp.name)
        self.apk = self.stage / 'LayerAnalyzer-arm64-v8a-1.0.0-rc.1.apk'
        self.apk.write_bytes(b'signed candidate fixture')
        staging.write_checksums(self.stage)

    def test_only_apk_and_checksum(self):
        self.assertEqual(self.apk, staging.verify_apk(self.stage, 'v1.0.0-rc.1'))
        self.assertEqual({self.apk.name, 'SHA256SUMS'}, {p.name for p in self.stage.iterdir()})
        self.assertEqual(1, len((self.stage / 'SHA256SUMS').read_text().splitlines()))

    def test_tampering_or_missing_apk(self):
        self.apk.write_bytes(b'changed')
        with self.assertRaises(ValueError):
            staging.verify_apk(self.stage)
        self.apk.unlink()
        with self.assertRaises(ValueError):
            staging.verify_apk(self.stage)

    def test_metadata_cannot_be_added_even_with_updated_checksums(self):
        (self.stage / 'delivery-manifest.json').write_text('{}')
        staging.write_checksums(self.stage)
        with self.assertRaises(ValueError):
            staging.verify_apk(self.stage)

    def test_wrong_name_or_version(self):
        with self.assertRaises(ValueError):
            staging.verify_apk(self.stage, 'v1.0.0')
        self.apk.rename(self.stage / 'LayerAnalyzer-012345abcdef.apk')
        staging.write_checksums(self.stage)
        with self.assertRaises(ValueError):
            staging.verify_apk(self.stage)


if __name__ == '__main__':
    unittest.main()
