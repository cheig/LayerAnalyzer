#!/usr/bin/env python3
"""Check byte-sensitive assets and vendored inputs before building a checkout or archive."""
import hashlib
import json
from pathlib import Path

from check_runtime_licenses import check as check_runtime_licenses

ROOT = Path(__file__).resolve().parents[1]


def main():
    package = ROOT / 'app/src/main/assets/scenario_package'
    manifest = json.loads((package / 'manifest.json').read_text(encoding='utf-8'))
    failures = []
    for name, expected in manifest['files'].items():
        if hashlib.sha256((package / name).read_bytes()).hexdigest() != expected:
            failures.append('Signed asset bytes changed: ' + name)
    cpp = ROOT / 'app/src/main/cpp'
    tunnel = cpp / 'third_party/hev-socks5-tunnel'
    for relative in ['src/hev-main.h', 'src/core/src', 'third-part/lwip/src/include/lwip/init.h',
                     'third-part/hev-task-system/include/hev-task.h', 'third-part/yaml/src/api.c']:
        if not (tunnel / relative).exists():
            failures.append('Missing vendored source: ' + relative)
    for relative, expected in [('include/wireshark', 635), ('third_party/wireshark-reference', 29)]:
        actual = sum(p.is_file() for p in (cpp / relative).rglob('*'))
        if actual != expected:
            failures.append(f'{relative}: expected {expected} files, found {actual}')
    if (ROOT / 'LICENSE').read_bytes() != (cpp / 'third_party/bcg729/COPYING').read_bytes():
        failures.append('Application GPL-3.0 text differs from the bundled license')
    if (ROOT / 'THIRD_PARTY_NOTICES.md').read_bytes() != (ROOT / 'app/src/main/assets/THIRD_PARTY_NOTICES.txt').read_bytes():
        failures.append('APK third-party notices differ from repository notices')
    failures.extend(check_runtime_licenses())
    if failures:
        raise SystemExit('\n'.join(failures))
    print('Source inputs verified: signed payload hashes, vendored trees, reference counts, and license texts.')


if __name__ == '__main__':
    main()
