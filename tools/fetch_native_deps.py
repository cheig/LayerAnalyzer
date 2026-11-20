#!/usr/bin/env python3
"""Fetch or verify pinned native dependencies, including separately staged candidates."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tempfile
import urllib.error
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def sha256(path):
    # Native rebuild documentation supports Python 3.10 on Ubuntu 22.04.
    # hashlib.file_digest is only available from 3.11; keep streaming checks
    # without weakening the pinned full-file hash or loading large bundles.
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def validate_manifest(manifest):
    """Validate paths before reading or writing anything outside the staging area."""
    files = manifest.get('files')
    if not isinstance(files, dict) or not files:
        raise ValueError('Native manifest has no files')
    hashes = dict(files)
    fixes = manifest.get('requiredLocalRebuild', {}).get('files', {})
    if set(fixes) - set(files):
        raise ValueError('Local rebuild refers to an unknown library')
    hashes.update(fixes)
    for name, digest in [*files.items(), *hashes.items()]:
        path = PurePosixPath(name)
        if (len(path.parts) != 2 or path.parts[0] not in ('arm64-v8a', 'x86_64')
                or path.as_posix() != name or '\\' in name or ':' in name
                or not re.fullmatch(r'lib[\w+.-]+\.(so|a)', path.name)):
            raise ValueError('Unsafe native manifest path: ' + name)
        if not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest):
            raise ValueError('Invalid native SHA-256: ' + name)
    if not re.fullmatch(r'[0-9a-f]{64}', manifest.get('sha256', '')):
        raise ValueError('Invalid native archive SHA-256')
    return hashes


def verify_archive(archive, manifest, extracted):
    """Preflight the entire archive. Never install a partly validated bundle."""
    validate_manifest(manifest)
    if sha256(archive) != manifest['sha256']:
        raise ValueError('Native bundle SHA-256 mismatch; refusing to install.')
    with zipfile.ZipFile(archive) as bundle:
        members = [member for member in bundle.infolist() if not member.is_dir()]
        if (len(members) != len(manifest['files'])
                or {m.filename for m in members} != set(manifest['files'])):
            raise ValueError('Unexpected native bundle file list.')
        for member in bundle.infolist():
            path = PurePosixPath(member.filename)
            if (path.is_absolute() or '..' in path.parts or '\\' in member.filename
                    or ':' in member.filename or stat.S_ISLNK(member.external_attr >> 16)):
                raise ValueError('Unsafe native bundle path: ' + member.filename)
        for member in members:
            target = extracted / member.filename
            target.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(member) as source, target.open('wb') as output:
                shutil.copyfileobj(source, output)
            if sha256(target) != manifest['files'][member.filename]:
                raise ValueError('Native library SHA-256 mismatch: ' + member.filename)


def matches(destination, files):
    return all((destination / name).is_file() and sha256(destination / name) == digest
               for name, digest in files.items())


def fetch(manifest, destination, archive=None, check=False):
    expected = validate_manifest(manifest)
    destination = destination.resolve()
    # Refuse symlink/junction paths escaping the user-selected destination.
    for name in expected:
        if not (destination / name).resolve().is_relative_to(destination):
            raise ValueError('Native destination path escapes the selected directory: ' + name)
    local_rebuild = manifest.get('requiredLocalRebuild', {})
    if check:
        if not matches(destination, expected):
            detail = ('Prepare the pinned bundle and required local rebuilds: ' + local_rebuild['instructions']
                      if local_rebuild else 'Reinstall through the fetch step with the pinned manifest; '
                      'do not copy libraries from another machine.')
            raise ValueError('Native dependencies are missing or modified. ' + detail)
        print('Verified all installed native library hashes (no download attempted).')
        return
    if archive is None and matches(destination, expected):
        print('Native dependencies match the pinned manifest.')
        return
    if archive is None and local_rebuild and matches(destination, manifest['files']):
        raise ValueError('Base bundle is ready; required local rebuild: ' + local_rebuild['instructions'])
    with tempfile.TemporaryDirectory(prefix='layeranalyzer-native-') as tmp:
        temporary = Path(tmp)
        if archive is None:
            archive = temporary / 'native-deps.zip'
            print('Downloading ' + manifest['url'])
            request = urllib.request.Request(manifest['url'], headers={'User-Agent': 'LayerAnalyzer-build'})
            try:
                with urllib.request.urlopen(request, timeout=120) as response, archive.open('wb') as output:
                    shutil.copyfileobj(response, output)
            except urllib.error.URLError as error:
                raise ValueError(f'Native bundle download failed: {error}. No libraries were installed.') from None
        extracted = temporary / 'extracted'
        verify_archive(archive, manifest, extracted)
        for name in manifest['files']:
            target = destination / name
            # Historical base archives must not roll verified local fixes back.
            if name in local_rebuild.get('files', {}) and target.is_file() and sha256(target) == expected[name]:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(extracted / name, target)
    if not matches(destination, expected):
        raise ValueError('Base bundle installed; required local rebuild: ' + local_rebuild['instructions'])
    print(f"Installed and verified {len(expected)} native libraries.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, help='use a previously downloaded ZIP')
    parser.add_argument('--check', action='store_true', help='verify without downloading')
    parser.add_argument('--manifest', type=Path, help='explicit candidate manifest; default: repository pin')
    parser.add_argument('--destination', type=Path, help='isolated dependency directory; default: app native libs')
    args = parser.parse_args()
    if args.archive and args.check:
        parser.error('--archive and --check are mutually exclusive')
    try:
        manifest = json.loads((args.manifest or ROOT / 'native_build/native-deps.json').read_text(encoding='utf-8'))
        fetch(manifest, args.destination or ROOT / 'app/src/main/cpp/libs', args.archive, args.check)
    except (ValueError, OSError, zipfile.BadZipFile) as error:
        raise SystemExit(str(error)) from None


if __name__ == '__main__':
    main()
