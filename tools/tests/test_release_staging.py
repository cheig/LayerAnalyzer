"""Release failures must stop before uploading a misleading attachment set."""
import copy
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import stage_release as release


class ChecksumsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.stage = Path(self.temp.name)
        (self.stage / 'app.apk').write_bytes(b'fixture APK')
        (self.stage / 'source.zip').write_bytes(b'fixture source')
        release.write_json(self.stage / 'delivery-manifest.json', {
            'attachments': release.payloads(self.stage)})
        release.write_checksums(self.stage)

    def test_portable_flat_round_trip(self):
        self.assertEqual(3, release.verify(self.stage))
        raw = (self.stage / 'SHA256SUMS').read_bytes()
        self.assertNotIn(b'\r', raw)
        self.assertNotIn(b'./', raw)
        self.assertTrue(raw.endswith(b'\n'))

    def test_missing_attachment(self):
        (self.stage / 'source.zip').unlink()
        with self.assertRaises(ValueError):
            release.verify(self.stage)

    def test_extra_output_metadata(self):
        (self.stage / 'output-metadata.json').write_text('{}')
        with self.assertRaises(ValueError):
            release.verify(self.stage)

    def test_tampered_attachment(self):
        (self.stage / 'app.apk').write_bytes(b'changed')
        with self.assertRaises(ValueError):
            release.verify(self.stage)

    def test_duplicate_entry(self):
        path = self.stage / 'SHA256SUMS'
        path.write_bytes(path.read_bytes() + path.read_bytes().splitlines(keepends=True)[0])
        with self.assertRaises(ValueError):
            release.verify(self.stage)

    def test_crlf_rejected(self):
        path = self.stage / 'SHA256SUMS'
        path.write_bytes(path.read_bytes().replace(b'\n', b'\r\n'))
        with self.assertRaises(ValueError):
            release.verify(self.stage)

    def test_directory_rejected(self):
        (self.stage / 'nested').mkdir()
        with self.assertRaises(ValueError):
            release.verify(self.stage)

    def test_hidden_attachment_rejected(self):
        (self.stage / '.hidden').write_text('not uploaded by Actions')
        with self.assertRaises(ValueError):
            release.write_checksums(self.stage)

    def test_rewritten_checksums_cannot_hide_injection(self):
        (self.stage / 'extra.json').write_text('{}')
        release.write_checksums(self.stage)
        with self.assertRaisesRegex(ValueError, 'delivery-manifest'):
            release.verify(self.stage)

    def test_nonempty_stage_not_overwritten(self):
        before = (self.stage / 'app.apk').read_bytes()
        with self.assertRaisesRegex(ValueError, 'new or empty'):
            release.create(self.stage, Path('unused.json'))
        self.assertEqual(before, (self.stage / 'app.apk').read_bytes())

    def test_aab_requires_apk(self):
        with self.assertRaisesRegex(ValueError, 'matching APK'):
            release.create(self.stage, Path('unused.json'), aab=Path('unused.aab'))


class SbomTest(unittest.TestCase):
    def setUp(self):
        self.review = release.read_json(release.ROOT / 'docs/dependency-licenses.json')
        self.inventory = copy.deepcopy(self.review)
        self.inventory['build'] = {'versionName': '1.0', 'ndkVersion': '27.0.12077973',
                                   'abis': ['arm64-v8a'], 'g729': True, 'ilbc': False}
        self.deps = release.read_json(release.ROOT / 'native_build/native-deps.json')
        self.sources = release.read_json(release.ROOT / 'native_build/native-sources.json')
        self.provenance = release.read_json(release.ROOT / self.sources['verificationRecord'])
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.stage = Path(self.temp.name)
        (self.stage / 'source.zip').write_bytes(b'fixture source archive')

    def build_sbom(self):
        return release.make_sbom(self.inventory, 'a' * 40, 'source.zip', self.stage,
                                 self.deps, self.sources, self.provenance)

    def fixture_binary(self, kind='apk', omit=None, extra=None):
        prefix = 'lib/' if kind == 'apk' else 'base/lib/'
        names = {n for n in self.deps['files'] if n.startswith('arm64-v8a/') and n.endswith('.so')}
        names |= {'arm64-v8a/' + n for n in ['liblayanalyzer.so', 'liblayanalyzer_tunnel.so', 'libc++_shared.so']}
        if omit:
            names.remove('arm64-v8a/' + omit)
        if extra:
            names.add('arm64-v8a/' + extra)
        with zipfile.ZipFile(self.stage / ('app.' + kind), 'w') as archive:
            for name in names:
                archive.writestr(prefix + name, b'fixture library')

    def test_complete_input_coverage(self):
        sbom = self.build_sbom()
        self.assertEqual(len(self.review['components']), sum(
            p['SPDXID'].startswith('SPDXRef-Maven-') for p in sbom['packages']))
        self.assertEqual(len(self.sources['components']), sum(
            p['SPDXID'].startswith('SPDXRef-Native-') for p in sbom['packages']))
        self.assertEqual(len(self.deps['files']), sum(
            f['SPDXID'].startswith('SPDXRef-NativeInput-') for f in sbom['files']))
        self.assertEqual(sum(len(c['artifacts']) for c in self.review['components']), sum(
            '-Artifact-' in f['SPDXID'] for f in sbom['files']))
        ids = {p['SPDXID'] for p in sbom['packages']} | {f['SPDXID'] for f in sbom['files']}
        ids.add('SPDXRef-DOCUMENT')
        for relationship in sbom['relationships']:
            self.assertIn(relationship['spdxElementId'], ids)
            self.assertIn(relationship['relatedSpdxElement'], ids)

    def test_inventory_drift_rejected(self):
        for mutation in ['missing', 'extra', 'hash', 'duplicate']:
            with self.subTest(mutation=mutation):
                inventory = copy.deepcopy(self.inventory)
                components = inventory['components']
                if mutation == 'missing':
                    components.pop()
                elif mutation == 'extra':
                    components.append({'coordinate': 'new:library:1', 'artifacts': []})
                elif mutation == 'duplicate':
                    components.append(components[0])
                else:
                    next(c for c in components if c['artifacts'])['artifacts'][0]['sha256'] = '0' * 64
                with self.assertRaises(ValueError):
                    release.checked_inventory(inventory, self.review)

    def test_unknown_native_input_rejected(self):
        self.deps['files']['arm64-v8a/libunknown.so'] = '0' * 64
        with self.assertRaises((ValueError, KeyError)):
            self.build_sbom()

    def test_missing_native_input_rejected(self):
        self.deps['files'].pop(next(iter(self.deps['files'])))
        with self.assertRaises(ValueError):
            self.build_sbom()

    def test_codec_flags(self):
        self.inventory['build'].update(g729=False, ilbc=True)
        names = {p['name'] for p in self.build_sbom()['packages']}
        self.assertNotIn('bcg729', names)
        self.assertIn('libilbc', names)

    def test_actual_apk_and_aab_libraries(self):
        self.fixture_binary()
        self.fixture_binary('aab')
        sbom = self.build_sbom()
        for kind in ['apk', 'aab']:
            self.assertEqual(13, sum(f['SPDXID'].startswith(f'SPDXRef-{kind}-Library-') for f in sbom['files']))

    def test_missing_packaged_library_rejected(self):
        self.fixture_binary(omit='libwireshark.so')
        with self.assertRaisesRegex(ValueError, 'Packaged native library set'):
            self.build_sbom()

    def test_unknown_packaged_library_rejected(self):
        self.fixture_binary(extra='libunknown.so')
        with self.assertRaisesRegex(ValueError, 'Packaged native library set'):
            self.build_sbom()


if __name__ == '__main__':
    unittest.main()
