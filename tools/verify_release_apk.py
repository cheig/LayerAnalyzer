#!/usr/bin/env python3
"""Verify a release APK against the resolved build and pinned public certificate."""
import argparse
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def check_alignment(apk):
    # Build Tools 34 zipalign lacks -P. Inspect the actual ZIP offsets and ELF
    # LOAD segments as well as running its ordinary alignment check below.
    with zipfile.ZipFile(apk) as archive, apk.open('rb') as raw:
        libraries = [entry for entry in archive.infolist()
                     if entry.filename.startswith('lib/') and entry.filename.endswith('.so')]
        if not libraries:
            raise ValueError('APK contains no native libraries')
        for entry in libraries:
            raw.seek(entry.header_offset)
            header = raw.read(30)
            name_size, extra_size = struct.unpack_from('<HH', header, 26)
            offset = entry.header_offset + 30 + name_size + extra_size
            if entry.compress_type != zipfile.ZIP_STORED or offset % 16384:
                raise ValueError('Native ZIP entry must be stored and 16 KB aligned: ' + entry.filename)
            data = archive.read(entry)
            if data[:6] != b'\x7fELF\x02\x01':
                raise ValueError('Expected a little-endian ELF64 library: ' + entry.filename)
            phoff = struct.unpack_from('<Q', data, 32)[0]
            phsize, phcount = struct.unpack_from('<HH', data, 54)
            loads = 0
            for index in range(phcount):
                kind, _, file_offset, address, _, _, _, alignment = struct.unpack_from(
                    '<IIQQQQQQ', data, phoff + index * phsize)
                if kind == 1:  # PT_LOAD
                    loads += 1
                    if alignment < 16384 or file_offset % 16384 != address % 16384:
                        raise ValueError('ELF LOAD segment is not 16 KB aligned: ' + entry.filename)
            if not loads:
                raise ValueError('ELF has no LOAD segments: ' + entry.filename)


def check_identity(signing, badging, build, certificate, tag):
    signers = re.findall(r'^Signer #\d+ certificate SHA-256 digest: ([0-9a-fA-F]+)$',
                         signing, re.MULTILINE)
    if [value.lower() for value in signers] != [certificate.lower()]:
        raise ValueError('APK signer does not match the pinned release certificate')
    if 'Verified using v2 scheme (APK Signature Scheme v2): true' not in signing:
        raise ValueError('APK must have a verified v2 signature')
    if tag != 'v' + build['versionName']:
        raise ValueError('Tag must equal v + APK versionName')
    match = re.search(r"^package: name='([^']+)' versionCode='(\d+)' versionName='([^']+)'",
                      badging, re.MULTILINE)
    expected = (build['applicationId'], str(build['versionCode']), build['versionName'])
    if not match or match.groups() != expected:
        raise ValueError('APK package/version differs from the resolved build')
    if 'application-debuggable' in badging:
        raise ValueError('Release APK must not be debuggable')
    native = re.search(r'^native-code:(.*)$', badging, re.MULTILINE)
    if not native or sorted(re.findall(r"'([^']+)'", native[1])) != sorted(build['abis']):
        raise ValueError('APK ABIs differ from the resolved build')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apk', type=Path, required=True)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--sdk', default=os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT'))
    args = parser.parse_args()
    if not args.sdk:
        parser.error('Set ANDROID_HOME or supply --sdk')
    build_tools = Path(args.sdk) / 'build-tools/34.0.0'

    def run(name, *arguments):
        suffix = ('.bat' if name == 'apksigner' else '.exe') if os.name == 'nt' else ''
        return subprocess.check_output([str(build_tools / (name + suffix)), *map(str, arguments)],
                                       text=True, encoding='utf-8', errors='replace')

    signing = run('apksigner', 'verify', '--verbose', '--print-certs', args.apk)
    badging = run('aapt', 'dump', 'badging', args.apk)
    build = json.loads(args.inventory.read_text(encoding='utf-8'))['build']
    certificate = (ROOT / 'tools/release-signing-certificate.sha256').read_text().strip()
    check_identity(signing, badging, build, certificate, args.tag)
    run('zipalign', '-c', '4', args.apk)
    check_alignment(args.apk)
    print(f'Verified {args.tag} ({build["versionCode"]}), {build["abis"]}; signer SHA-256: {certificate}')


if __name__ == '__main__':
    main()
