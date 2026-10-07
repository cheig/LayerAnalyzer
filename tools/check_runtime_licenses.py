#!/usr/bin/env python3
"""Verify reviewed runtime dependencies and the license texts actually shipped."""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / 'app/src/main/assets'


def check(inventory=None, apk=None):
    manifest = json.loads((ROOT / 'docs/dependency-licenses.json').read_text(encoding='utf-8'))
    failures = []
    notices = (ASSETS / 'THIRD_PARTY_NOTICES.txt').read_bytes()
    if notices != (ROOT / 'THIRD_PARTY_NOTICES.md').read_bytes():
        failures.append('APK third-party notices differ from repository notices')
    for name, expected in manifest['licenseFiles'].items():
        path = ASSETS / 'licenses' / name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            failures.append('Missing or changed reviewed license: ' + name)
    actual_names = {p.name for p in (ASSETS / 'licenses').glob('*.txt')}
    if actual_names != set(manifest['licenseFiles']):
        failures.append('License asset set differs from the reviewed manifest')
    normalized_notices = notices.replace(b'\r\n', b'\n')
    for name in manifest['embeddedInNotices']:
        path = ASSETS / 'licenses' / name
        if path.is_file() and path.read_bytes().replace(b'\r\n', b'\n').strip() not in normalized_notices:
            failures.append('Complete license/notice missing from in-app notices: ' + name)
    # LICENSE follows the checkout's text conversion; the reviewed asset keeps
    # its canonical upstream bytes. Compare the complete text across CRLF/LF.
    if (ASSETS / 'licenses/LayerAnalyzer-GPL-3.0.txt').read_bytes().replace(b'\r\n', b'\n') != \
            (ROOT / 'LICENSE').read_bytes().replace(b'\r\n', b'\n'):
        failures.append('APK application license differs from GPL-3.0 LICENSE')
    if inventory is not None:
        resolved = json.loads(Path(inventory).read_text(encoding='utf-8'))
        if resolved['configuration'] != manifest['configuration']:
            failures.append('Expected configuration ' + manifest['configuration'])
        reviewed = {c['coordinate']: c['artifacts'] for c in manifest['components']}
        current = {c['coordinate']: c['artifacts'] for c in resolved['components']}
        for coordinate in sorted(reviewed.keys() | current.keys()):
            if reviewed.get(coordinate) != current.get(coordinate):
                failures.append('Dependency needs license review: ' + coordinate)
    if apk is not None:
        with zipfile.ZipFile(apk) as archive:
            expected_assets = {'assets/THIRD_PARTY_NOTICES.txt': notices}
            expected_assets.update({
                'assets/licenses/' + name: (ASSETS / 'licenses' / name).read_bytes()
                for name in manifest['licenseFiles'] if (ASSETS / 'licenses' / name).is_file()
            })
            expected_assets['assets/wireshark-data/COPYING'] = (ASSETS / 'wireshark-data/COPYING').read_bytes()
            for name, data in expected_assets.items():
                if name not in archive.namelist() or archive.read(name) != data:
                    failures.append('APK contains missing or stale license asset: ' + name)
    return failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', type=Path, help='Fresh exportRuntimeLicenseInventory JSON')
    parser.add_argument('--apk', type=Path, help='APK to inspect without installing it')
    args = parser.parse_args()
    failures = check(args.inventory, args.apk)
    if failures:
        raise SystemExit('\n'.join(failures))
    print('Runtime license materials verified' +
          ('; resolved dependencies match review' if args.inventory else '') +
          ('; APK license bytes match source' if args.apk else '') + '.')


if __name__ == '__main__':
    main()
