#!/usr/bin/env python3
"""Check R07's declarative storage/share boundaries; this is not a device gate."""
import argparse
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
ANDROID = '{http://schemas.android.com/apk/res/android}'
BACKUP_DOMAINS = {
    'root', 'file', 'database', 'sharedpref', 'external',
    'device_root', 'device_file', 'device_database', 'device_sharedpref',
}
SHARE_ROOTS = {('files-path', 'exports/'), ('cache-path', 'rtp/')}


def check_configuration(root):
    main = root / 'app/src/main'
    app = ET.parse(main / 'AndroidManifest.xml').getroot().find('application')
    if app is None or app.get(ANDROID + 'allowBackup') != 'false':
        raise ValueError('Application backup must be disabled')
    for name, reference in [('fullBackupContent', '@xml/backup_rules'),
                            ('dataExtractionRules', '@xml/data_extraction_rules')]:
        if app.get(ANDROID + name) != reference:
            raise ValueError('Backup rules are not wired to the application')
    providers = [p for p in app.findall('provider')
                 if p.get(ANDROID + 'name') == 'androidx.core.content.FileProvider']
    if len(providers) != 1:
        raise ValueError('Expected exactly one FileProvider')
    provider = providers[0]
    if provider.get(ANDROID + 'exported') != 'false' or provider.get(ANDROID + 'grantUriPermissions') != 'true':
        raise ValueError('FileProvider must require explicit URI grants')
    metadata = provider.findall('meta-data')
    if len(metadata) != 1 or metadata[0].get(ANDROID + 'resource') != '@xml/file_paths' or \
            metadata[0].get(ANDROID + 'name') != 'android.support.FILE_PROVIDER_PATHS':
        raise ValueError('FileProvider paths are not wired to the audited XML')
    paths = ET.parse(main / 'res/xml/file_paths.xml').getroot()
    roots = [(p.tag, p.get('path')) for p in paths]
    if paths.tag != 'paths' or len(roots) != len(SHARE_ROOTS) or set(roots) != SHARE_ROOTS:
        raise ValueError('FileProvider exposes an unaudited storage root')
    backup = ET.parse(main / 'res/xml/backup_rules.xml').getroot()
    extraction = ET.parse(main / 'res/xml/data_extraction_rules.xml').getroot()
    if backup.tag != 'full-backup-content' or extraction.tag != 'data-extraction-rules':
        raise ValueError('Unexpected backup XML root')
    if {e.tag for e in extraction} != {'cloud-backup', 'device-transfer'} or len(extraction) != 2:
        raise ValueError('Both cloud backup and device transfer must be excluded')
    for section in [backup, *extraction]:
        exclusions = {(e.get('domain'), e.get('path')) for e in section if e.tag == 'exclude'}
        if any(e.tag != 'exclude' for e in section) or exclusions != {(d, '.') for d in BACKUP_DOMAINS}:
            raise ValueError('Every backup storage domain must be explicitly excluded')
    return {'status': 'PASS', 'scope': 'source-XML-only',
            'backupDomains': sorted(BACKUP_DOMAINS), 'shareRoots': sorted(SHARE_ROOTS),
            'deviceBackupAndFileProvider': 'NOT_RUN'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    report = {'schemaVersion': 1}
    try:
        report.update(check_configuration(args.root))
    except (ValueError, OSError, ET.ParseError) as error:
        report.update(status='FAIL', error=str(error))
    inputs = ['app/src/main/AndroidManifest.xml', *[
        'app/src/main/res/xml/' + name + '.xml'
        for name in ('file_paths', 'backup_rules', 'data_extraction_rules')]]
    report['inputs'] = {name: hashlib.sha256((args.root / name).read_bytes()).hexdigest()
                        for name in inputs if (args.root / name).is_file()}
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
