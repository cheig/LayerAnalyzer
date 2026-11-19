import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('check_tls_privacy', ROOT / 'tools/check_tls_privacy.py')
privacy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(privacy)


class TlsPrivacyConfigurationTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for name in ('AndroidManifest.xml', 'res/xml/file_paths.xml',
                     'res/xml/backup_rules.xml', 'res/xml/data_extraction_rules.xml'):
            target = self.root / 'app/src/main' / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / 'app/src/main' / name, target)

    def mutate(self, name, change):
        target = self.root / 'app/src/main' / name
        tree = ET.parse(target)
        change(tree.getroot())
        tree.write(target, encoding='utf-8')

    def rejected(self):
        with self.assertRaises(ValueError):
            privacy.check_configuration(self.root)

    def test_actual_source_configuration_passes_without_claiming_device_validation(self):
        result = privacy.check_configuration(ROOT)
        self.assertEqual('PASS', result['status'])
        self.assertEqual('NOT_RUN', result['deviceBackupAndFileProvider'])

    def test_broad_private_or_capture_share_roots_are_rejected(self):
        for tag, path in [('root-path', '.'), ('files-path', 'captures/'),
                          ('files-path', '../no_backup/'), ('cache-path', '.')]:
            with self.subTest(tag=tag, path=path):
                self.mutate('res/xml/file_paths.xml', lambda root: ET.SubElement(root, tag, path=path))
                self.rejected()
                shutil.copyfile(ROOT / 'app/src/main/res/xml/file_paths.xml',
                                self.root / 'app/src/main/res/xml/file_paths.xml')

    def test_missing_credential_or_device_protected_backup_exclusion_fails(self):
        for domain in privacy.BACKUP_DOMAINS:
            with self.subTest(domain=domain):
                self.mutate('res/xml/backup_rules.xml', lambda root: root.remove(
                    next(e for e in root if e.get('domain') == domain)))
                self.rejected()
                shutil.copyfile(ROOT / 'app/src/main/res/xml/backup_rules.xml',
                                self.root / 'app/src/main/res/xml/backup_rules.xml')

    def test_device_transfer_cannot_be_enabled_while_cloud_backup_is_disabled(self):
        self.mutate('res/xml/data_extraction_rules.xml', lambda root: root.find('device-transfer').clear())
        self.rejected()

    def test_provider_requires_explicit_grants(self):
        self.mutate('AndroidManifest.xml', lambda root: root.find('application/provider').set(
            privacy.ANDROID + 'exported', 'true'))
        self.rejected()

    def test_referencing_different_path_rules_fails(self):
        self.mutate('AndroidManifest.xml', lambda root: root.find('application/provider/meta-data').set(
            privacy.ANDROID + 'resource', '@xml/other_paths'))
        self.rejected()

    def test_application_cannot_enable_backup(self):
        self.mutate('AndroidManifest.xml', lambda root: root.find('application').set(
            privacy.ANDROID + 'allowBackup', 'true'))
        self.rejected()

    def test_include_cannot_override_exclusions(self):
        self.mutate('res/xml/backup_rules.xml', lambda root: ET.SubElement(root, 'include', domain='file', path='.'))
        self.rejected()

    def test_backup_rules_must_be_referenced_by_manifest(self):
        self.mutate('AndroidManifest.xml', lambda root: root.find('application').set(
            privacy.ANDROID + 'dataExtractionRules', '@xml/other_rules'))
        self.rejected()
