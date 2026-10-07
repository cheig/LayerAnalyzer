#!/usr/bin/env python3
"""Verify the pinned native source archive and each component's audited tree."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import posixpath
import tarfile

ROOT = Path(__file__).resolve().parents[1]


def stream_hash(stream):
    digest = hashlib.sha256()
    for block in iter(lambda: stream.read(1024 * 1024), b''):
        digest.update(block)
    return digest.hexdigest()


def check(archive, manifest):
    with archive.open('rb') as stream:
        actual = stream_hash(stream)
    if actual != manifest['sha256']:
        raise ValueError('Native source archive SHA-256 mismatch')
    components = {item['name']: item for item in manifest['components']}
    trees = {name: [] for name in components}
    names = set()
    with tarfile.open(archive, 'r|gz') as bundle:
        for member in bundle:
            path = PurePosixPath(member.name)
            if member.name in names or path.is_absolute() or '..' in path.parts:
                raise ValueError('Duplicate or unsafe archive path: ' + member.name)
            names.add(member.name)
            if member.isdir():
                continue
            if member.issym():
                resolved = posixpath.normpath(posixpath.join(str(path.parent), member.linkname))
                if member.linkname.startswith('/') or not resolved.startswith('native_build/external/'):
                    raise ValueError('Unsafe symbolic link: ' + member.name)
                payload_hash = hashlib.sha256(member.linkname.encode()).hexdigest()
            elif member.isfile():
                with bundle.extractfile(member) as stream:
                    payload_hash = stream_hash(stream)
            else:
                raise ValueError('Unsupported archive entry: ' + member.name)
            if path.parts[:2] != ('native_build', 'external'):
                continue
            component = path.parts[2]
            if component not in components:
                raise ValueError('Unexpected component: ' + component)
            relative = '/'.join(path.parts[3:])
            trees[component].append(
                relative + '\0' + member.type.decode() + '\0' + oct(member.mode) + '\0' + payload_hash + '\n'
            )
    for name, records in trees.items():
        actual = hashlib.sha256(''.join(sorted(records)).encode()).hexdigest()
        if actual != components[name]['archiveTreeSha256']:
            raise ValueError('Component tree mismatch: ' + name)
        print(f'{name}: verified {len(records)} source entries')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', required=True, type=Path)
    args = parser.parse_args()
    manifest = json.loads((ROOT / 'native_build/native-sources.json').read_text(encoding='utf-8'))
    try:
        check(args.archive, manifest)
    except (ValueError, OSError, tarfile.TarError) as error:
        raise SystemExit(str(error)) from None


if __name__ == '__main__':
    main()
