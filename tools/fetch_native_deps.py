#!/usr/bin/env python3
"""Install the pinned Wireshark native bundle (Python 3.10+, no dependencies)."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import urllib.error
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, help='use a previously downloaded ZIP')
    parser.add_argument('--check', action='store_true', help='verify installed libraries without downloading')
    args = parser.parse_args()
    if args.archive and args.check:
        parser.error('--archive and --check are mutually exclusive')
    manifest = json.loads((ROOT / 'native_build/native-deps.json').read_text(encoding='utf-8'))
    destination = ROOT / 'app/src/main/cpp/libs'
    installed = all((destination / name).is_file() and sha256(destination / name) == digest
                    for name, digest in manifest['files'].items())
    if args.check:
        if not installed:
            raise SystemExit('Native dependencies are missing or modified; run tools/fetch_native_deps.py to prepare them.')
        print('Verified all installed native library hashes (no download attempted).')
        return
    if args.archive is None and installed:
        print('Native dependencies already match the pinned bundle.')
        return
    with tempfile.TemporaryDirectory(prefix='layeranalyzer-native-') as tmp:
        temporary = Path(tmp)
        archive = args.archive
        if archive is None:
            archive = temporary / 'native-deps.zip'
            print('Downloading ' + manifest['url'])
            request = urllib.request.Request(manifest['url'], headers={'User-Agent': 'LayerAnalyzer-build'})
            try:
                with urllib.request.urlopen(request, timeout=120) as response, archive.open('wb') as output:
                    shutil.copyfileobj(response, output)
            except urllib.error.URLError as error:
                raise SystemExit(
                    f'Native bundle download failed: {error}. Verify that the pinned release asset is public, '
                    'or use --archive with a previously obtained bundle. No libraries were installed.'
                ) from None
        if sha256(archive) != manifest['sha256']:
            raise SystemExit('Native bundle SHA-256 mismatch; refusing to install.')
        with zipfile.ZipFile(archive) as bundle:
            members = [member for member in bundle.infolist() if not member.is_dir()]
            if (len(members) != len(manifest['files'])
                    or {member.filename for member in members} != set(manifest['files'])):
                raise SystemExit('Unexpected native bundle file list.')
            for member in members:
                target = temporary / 'extracted' / member.filename
                if not target.resolve().is_relative_to((temporary / 'extracted').resolve()):
                    raise SystemExit('Unsafe native bundle path.')
                target.parent.mkdir(parents=True, exist_ok=True)
                with bundle.open(member) as source, target.open('wb') as output:
                    shutil.copyfileobj(source, output)
                if sha256(target) != manifest['files'][member.filename]:
                    raise SystemExit('Native library SHA-256 mismatch: ' + member.filename)
        for name in manifest['files']:
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(temporary / 'extracted' / name, target)
    print(f"Installed and verified {len(manifest['files'])} native libraries.")


if __name__ == '__main__':
    main()
