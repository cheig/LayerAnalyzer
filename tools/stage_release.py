#!/usr/bin/env python3
"""Create or verify a flat release attachment set from a clean committed checkout."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import zipfile
from datetime import datetime, timezone
from urllib.parse import quote

from check_runtime_licenses import check as check_licenses

ROOT = Path(__file__).resolve().parents[1]
SAFE_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]*\Z')


def digest(path):
    checksum = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            checksum.update(chunk)
    return checksum.hexdigest()


def read_json(path):
    return json.loads(path.read_text(encoding='utf-8'))


def write_text(path, value):
    path.write_text(value, encoding='utf-8', newline='\n')


def write_json(path, value):
    write_text(path, json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def payloads(stage):
    result = {}
    for path in sorted(stage.iterdir()):
        if path.is_symlink() or not path.is_file() or not SAFE_NAME.fullmatch(path.name):
            raise ValueError('Not a flat, portable attachment: ' + path.name)
        if path.name != 'SHA256SUMS':
            result[path.name] = digest(path)
    if not result:
        raise ValueError('Empty attachment set')
    return result


def write_checksums(stage):
    write_text(stage / 'SHA256SUMS', ''.join(
        f'{sha}  {name}\n' for name, sha in payloads(stage).items()))


def verify_checksums(stage):
    raw = (stage / 'SHA256SUMS').read_bytes()
    if b'\r' in raw or not raw.endswith(b'\n'):
        raise ValueError('SHA256SUMS must use UTF-8/LF with a final newline')
    expected = {}
    for line in raw.decode('utf-8').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)', line)
        if not match or match[2] in expected or match[2] == 'SHA256SUMS':
            raise ValueError('Invalid or duplicate checksum entry: ' + line)
        expected[match[2]] = match[1]
    actual = payloads(stage)
    if actual != expected:
        raise ValueError('Attachment set or hashes differ from SHA256SUMS')
    return actual


def verify(stage):
    actual = verify_checksums(stage)
    delivery = read_json(stage / 'delivery-manifest.json')
    if delivery['attachments'] != {k: v for k, v in actual.items()
                                   if k != 'delivery-manifest.json'}:
        raise ValueError('Attachments differ from delivery-manifest.json')
    return len(actual)


def verify_apk(stage, tag=None):
    actual = verify_checksums(stage)
    if len(actual) != 1:
        raise ValueError('APK release must contain only one APK and SHA256SUMS')
    name = next(iter(actual))
    match = re.fullmatch(r'LayerAnalyzer-(arm64-v8a|x86_64)-([0-9][A-Za-z0-9._-]*)\.apk', name)
    if not match or (tag is not None and tag != 'v' + match[2]):
        raise ValueError('APK name must contain the architecture and matching release version')
    return stage / name


def packaged_members(archive, kind, abis, libraries):
    prefix = 'lib/' if kind == 'apk' else 'base/lib/'
    members = [n for n in archive.namelist() if n.startswith(prefix) and n.endswith('.so')]
    expected = {prefix + abi + '/' + name for abi in abis for name in libraries if name.endswith('.so')}
    if set(members) != expected or len(members) != len(expected):
        raise ValueError('Packaged native library set differs from build inventory: ' + kind)
    return sorted(members)


def create_apk(stage, inventory_path, apk):
    if stage.exists() and any(stage.iterdir()):
        raise ValueError('Staging must be new or empty; do not reuse old attachments')
    if subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=all'], cwd=ROOT):
        raise ValueError('Commit reviewed changes before packaging; checkout must be clean')
    inventory = read_json(inventory_path)
    checked_inventory(inventory, read_json(ROOT / 'docs/dependency-licenses.json'))
    failures = check_licenses(inventory_path, apk)
    if failures:
        raise ValueError('\n'.join(failures))
    build = inventory['build']
    if len(build['abis']) != 1 or build['abis'][0] not in ('arm64-v8a', 'x86_64'):
        raise ValueError('APK release requires one supported architecture')
    if not re.fullmatch(r'[0-9][A-Za-z0-9._-]*', build['versionName']):
        raise ValueError('APK version must be portable in a filename')
    deps = read_json(ROOT / 'native_build/native-deps.json')
    sources = read_json(ROOT / 'native_build/native-sources.json')
    provenance = read_json(ROOT / sources['verificationRecord'])
    if (deps['sha256'] != sources['binaryArchiveSha256'] or
            provenance['pinnedBinaryArchiveSha256'] != deps['sha256'] or
            provenance['sourceArchiveSha256'] != sources['sha256']):
        raise ValueError('Native source, binary and provenance archive linkage differs')
    outputs = [name for component in provenance['components'] for name in component['outputs']]
    if (len(outputs) != len(set(outputs)) or
            {c['name'] for c in provenance['components']} != {c['name'] for c in sources['components']} or
            set(deps['files']) != {abi + '/' + name for abi in deps['abis'] for name in outputs}):
        raise ValueError('Native binary file set differs from provenance')
    libraries = set(outputs) | {'liblayanalyzer.so', 'liblayanalyzer_tunnel.so', 'libc++_shared.so'}
    with zipfile.ZipFile(apk) as archive:
        packaged_members(archive, 'apk', build['abis'], libraries)
    stage.mkdir(parents=True, exist_ok=True)
    name = f'LayerAnalyzer-{build["abis"][0]}-{build["versionName"]}.apk'
    shutil.copyfile(apk, stage / name)
    write_checksums(stage)
    verify_apk(stage, 'v' + build['versionName'])
    return 1


def checked_inventory(inventory, review):
    def indexed(components):
        result = {c['coordinate']: c for c in components}
        if len(result) != len(components):
            raise ValueError('Duplicate runtime component')
        return result
    current, reviewed = indexed(inventory['components']), indexed(review['components'])
    if inventory['configuration'] != 'releaseRuntimeClasspath' or current.keys() != reviewed.keys():
        raise ValueError('Runtime component set needs license review')
    for name, component in current.items():
        if component['artifacts'] != reviewed[name]['artifacts']:
            raise ValueError('Runtime artifact needs license review: ' + name)
    return reviewed


def make_sbom(inventory, commit, source_name, stage, deps, sources, provenance):
    reviewed = checked_inventory(inventory, read_json(ROOT / 'docs/dependency-licenses.json'))
    packages, files, relationships = [], [], []

    def relation(left, kind, right):
        relationships.append({'spdxElementId': left, 'relationshipType': kind,
                              'relatedSpdxElement': right})

    def package(identifier, name, version, license_id='NOASSERTION', url='NOASSERTION', comment=''):
        packages.append({'SPDXID': identifier, 'name': name, 'versionInfo': version,
                         'downloadLocation': url, 'filesAnalyzed': False,
                         'licenseConcluded': 'NOASSERTION', 'licenseDeclared': license_id,
                         'copyrightText': 'NOASSERTION', 'comment': comment})
        return identifier

    def file(identifier, name, sha, owner):
        files.append({'SPDXID': identifier, 'fileName': name,
                      'checksums': [{'algorithm': 'SHA256', 'checksumValue': sha}],
                      'licenseConcluded': 'NOASSERTION', 'copyrightText': 'NOASSERTION'})
        relation(owner, 'CONTAINS', identifier)

    app = package('SPDXRef-App', 'LayerAnalyzer', inventory['build']['versionName'],
                  'GPL-3.0-only', comment='Source commit: ' + commit)
    relation('SPDXRef-DOCUMENT', 'DESCRIBES', app)
    file('SPDXRef-AppSource', './' + source_name, digest(stage / source_name), app)
    for index, (coordinate, component) in enumerate(sorted(reviewed.items())):
        group, name, version = coordinate.split(':')
        identifier = package(f'SPDXRef-Maven-{index}', coordinate, version,
                             ' AND '.join(component['licenses']),
                             comment='Resolved releaseRuntimeClasspath before R8; metadata-only='
                             + str(not component['artifacts']).lower())
        packages[-1]['externalRefs'] = [{'referenceCategory': 'PACKAGE-MANAGER',
                                        'referenceType': 'purl',
                                        'referenceLocator': f'pkg:maven/{quote(group)}/{quote(name)}@{quote(version)}'}]
        relation(app, 'DEPENDS_ON', identifier)
        for number, artifact in enumerate(component['artifacts']):
            file(f'{identifier}-Artifact-{number}', f'./gradle/{group}/{artifact["file"]}',
                 artifact['sha256'], identifier)

    native_ids = {}
    source_components = {c['name']: c for c in sources['components']}
    if {c['name'] for c in provenance['components']} != source_components.keys():
        raise ValueError('Native provenance component set differs from source manifest')
    for index, component in enumerate(provenance['components']):
        name = component['name']
        identifier = package(f'SPDXRef-Native-{index}', name, name.rsplit('-', 1)[-1],
                             url=sources['url'], comment=json.dumps({
                                 'source': source_components[name],
                                 'verificationStatus': sources['verificationStatus']}, sort_keys=True))
        relation(app, 'DEPENDS_ON', identifier)
        for output in component['outputs']:
            if output in native_ids:
                raise ValueError('Duplicate native output: ' + output)
            native_ids[output] = identifier
    for index, (name, sha) in enumerate(sorted(deps['files'].items())):
        owner = native_ids[Path(name).name]
        file(f'SPDXRef-NativeInput-{index}', './native-inputs/' + name, sha, owner)
    if set(deps['files']) != {abi + '/' + name for abi in deps['abis'] for name in native_ids}:
        raise ValueError('Native binary file set differs from provenance')

    # Vendored revisions are reviewed against THIRD_PARTY_NOTICES.md and CMake.
    vendored = [
        ('nlohmann-json', '3.11.3', 'MIT AND Apache-2.0'),
        ('spandsp', '8f1e1646bdec99eac5fd2cd92c35563f736b9b89', 'LGPL-2.1-only'),
        ('hev-socks5-tunnel', '00c7eb9ad7ca381b0f1fee880abc1077fe9b93be', 'MIT'),
        ('hev-socks5-core', 'ee0f24505d344f14b14624fa2249e6ccfaed138b', 'MIT'),
        ('hev-task-system', '8d83bbbf79557138726c8ee5a5fae99cbb978d61', 'MIT'),
        ('lwIP', '8c69dfbe537835d5f2a5fd8c08c859f667b108ea', 'BSD-3-Clause'),
        ('libyaml', '0.2.5-wrapper-efa36117a8646d26d12b58e05bac472d7854a70d', 'MIT'),
        ('NDK-runtime', inventory['build']['ndkVersion'], 'NOASSERTION'),
    ]
    if inventory['build']['g729']:
        vendored.append(('bcg729', '1.1.1', 'GPL-3.0-only'))
    if inventory['build']['ilbc']:
        vendored.append(('libilbc', 'e99f6879f6ae1c8c53f9ce7024abb33ce3173795', 'BSD-3-Clause'))
    for name, version, license_id in vendored:
        identifier = package('SPDXRef-Vendored-' + name, name, version, license_id,
                             comment='Build input; see THIRD_PARTY_NOTICES.md and license-materials.zip. '
                             'NDK runtime comes from the toolchain; other source is in the application ZIP.')
        relation(app, 'DEPENDS_ON', identifier)

    # Release .so files are stripped. Record actual bytes separately from pinned input hashes.
    known_libraries = set(native_ids) | {'liblayanalyzer.so', 'liblayanalyzer_tunnel.so', 'libc++_shared.so'}
    for archive_path in sorted(list(stage.glob('*.apk')) + list(stage.glob('*.aab'))):
        kind = archive_path.suffix[1:]
        artifact_id = 'SPDXRef-' + kind
        file(artifact_id, './' + archive_path.name, digest(archive_path), app)
        with zipfile.ZipFile(archive_path) as archive:
            for index, name in enumerate(packaged_members(
                    archive, kind, inventory['build']['abis'], known_libraries)):
                basename = Path(name).name
                owner = native_ids.get(basename, 'SPDXRef-Vendored-NDK-runtime'
                                       if basename == 'libc++_shared.so' else app)
                identifier = f'SPDXRef-{kind}-Library-{index}'
                file(identifier, './' + archive_path.name + '!/' + name,
                     hashlib.sha256(archive.read(name)).hexdigest(), owner)
                relation(artifact_id, 'CONTAINS', identifier)

    return {'spdxVersion': 'SPDX-2.3', 'dataLicense': 'CC0-1.0',
            'SPDXID': 'SPDXRef-DOCUMENT', 'name': 'LayerAnalyzer release inputs',
            'documentNamespace': 'https://spdx.org/spdxdocs/LayerAnalyzer-' + commit + '-'
            + hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest(),
            'creationInfo': {'creators': ['Tool: LayerAnalyzer-stage-release'],
                             'created': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')},
            'comment': 'Resolved Gradle inputs (including metadata), pinned native inputs for both ABIs, '
            'enabled vendored components and actual packaged shared libraries when APK/AAB supplied. '
            'Not a DEX reachability analysis, vulnerability clearance or corresponding-source certification. '
            'Native license conclusions remain NOASSERTION; consult the supplied notices and source. '
            'Android system libraries and host/test/compiler dependencies are outside scope.',
            'packages': packages, 'files': files, 'relationships': relationships}


def create(stage, inventory_path, apk=None, aab=None):
    if aab and not apk:
        raise ValueError('AAB requires the matching APK')
    if stage.exists() and any(stage.iterdir()):
        raise ValueError('Staging must be new or empty; do not reuse old attachments')
    if subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=all'], cwd=ROOT):
        raise ValueError('Commit reviewed changes before packaging; checkout must be clean')
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    inventory = read_json(inventory_path)
    checked_inventory(inventory, read_json(ROOT / 'docs/dependency-licenses.json'))
    failures = check_licenses(inventory_path, apk)
    if failures:
        raise ValueError('\n'.join(failures))
    deps = read_json(ROOT / 'native_build/native-deps.json')
    sources = read_json(ROOT / 'native_build/native-sources.json')
    if deps['sha256'] != sources['binaryArchiveSha256']:
        raise ValueError('Native source/binary archive linkage differs')
    provenance = read_json(ROOT / sources['verificationRecord'])
    if (provenance['sourceArchiveSha256'] != sources['sha256'] or
            provenance['pinnedBinaryArchiveSha256'] != deps['sha256']):
        raise ValueError('Native provenance archive hashes differ')
    stage.mkdir(parents=True, exist_ok=True)
    source_name = f'LayerAnalyzer-source-{commit[:12]}.zip'
    subprocess.run(['git', '-c', 'core.autocrlf=false', 'archive', '--format=zip',
                    '--prefix=LayerAnalyzer/', '-o', str(stage / source_name), commit], cwd=ROOT, check=True)
    for source in [ROOT / 'LICENSE', ROOT / 'THIRD_PARTY_NOTICES.md', ROOT / 'CONTRIBUTING.md',
                   ROOT / 'native_build/native-deps.json', ROOT / 'native_build/native-sources.json']:
        shutil.copyfile(source, stage / source.name)
    for adjustment in sources.get('rebuildAdjustments', []):
        path = ROOT / adjustment['path']
        if digest(path) != adjustment['sha256']:
            raise ValueError('Changed rebuild adjustment: ' + adjustment['path'])
        if (stage / path.name).exists():
            raise ValueError('Duplicate attachment name: ' + path.name)
        shutil.copyfile(path, stage / path.name)
    with zipfile.ZipFile(stage / 'license-materials.zip', 'w', zipfile.ZIP_DEFLATED) as archive:
        for path in sorted((ROOT / 'app/src/main/assets/licenses').glob('*.txt')):
            archive.write(path, 'licenses/' + path.name)
        archive.write(ROOT / 'app/src/main/assets/wireshark-data/COPYING', 'wireshark/COPYING')
    shutil.copyfile(inventory_path, stage / 'releaseRuntimeClasspath.json')
    for path in [apk, aab]:
        if path:
            shutil.copyfile(path, stage / ('LayerAnalyzer-' + commit[:12] + path.suffix))
    write_json(stage / 'layeranalyzer.spdx.json', make_sbom(
        inventory, commit, source_name, stage, deps, sources, provenance))
    write_text(stage / 'SOURCE_AND_BUILD.md',
               '# Source and build material\n\n'
               f'Application commit: `{commit}`. Complete source: [{source_name}]({source_name}).\n\n'
               f'Native source: {sources["url"]}\n\nSHA-256: `{sources["sha256"]}`.\n\n'
               f'Native binaries: {deps["url"]}\n\nSHA-256: `{deps["sha256"]}`.\n\n'
               'Use native-sources.json for source modifications and required rebuild patches '
               '(also attached), and CONTRIBUTING.md for the toolchain and build order. '
               'The application ZIP includes the provenance record, patches and build scripts. '
               'License materials are in LICENSE, THIRD_PARTY_NOTICES.md, license-materials.zip '
               'and the corresponding source trees. The two native archives remain separate downloads.\n\n'
               'Verify every source download anonymously before binary distribution. '
               'This staging operation does not verify remote availability, signing, device behavior '
               'or security readiness. Actions artifacts are not GitHub Releases. '
               'SHA256SUMS covers all attachments except itself; run `sha256sum -c SHA256SUMS` '
               'from this directory after download.\n\n'
               f'Native verification status: {sources["verificationStatus"]}\n')
    write_json(stage / 'delivery-manifest.json', {
        'schemaVersion': 1, 'applicationSourceCommit': commit, 'build': inventory['build'],
        'mode': 'application' if apk else 'source', 'nativeSourceUrl': sources['url'],
        'nativeSourceSha256': sources['sha256'], 'nativeBinarySha256': deps['sha256'],
        'attachments': payloads(stage)})
    write_checksums(stage)
    return verify(stage)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['create', 'verify', 'create-apk', 'verify-apk'])
    parser.add_argument('--staging', required=True, type=Path)
    parser.add_argument('--inventory', type=Path)
    parser.add_argument('--apk', type=Path)
    parser.add_argument('--aab', type=Path)
    parser.add_argument('--tag')
    args = parser.parse_args()
    if args.command in ('create', 'create-apk') and not args.inventory:
        parser.error('create requires --inventory')
    if args.command == 'create-apk' and (not args.apk or args.aab):
        parser.error('create-apk requires --apk and does not accept --aab')
    try:
        stage = args.staging.resolve()
        if args.command == 'verify-apk':
            verify_apk(stage, args.tag)
            count = 1
        elif args.command == 'create-apk':
            count = create_apk(stage, args.inventory, args.apk)
        else:
            count = (verify(stage) if args.command == 'verify' else
                     create(stage, args.inventory, args.apk, args.aab))
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError, zipfile.BadZipFile) as error:
        raise SystemExit(str(error)) from error
    print(f'Verified {count} attachments plus SHA256SUMS in {stage}')


if __name__ == '__main__':
    main()
