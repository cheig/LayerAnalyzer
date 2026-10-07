#!/usr/bin/env python3
"""Verify RTP device-test inputs; optionally copy a locally held fixture set.

This does not download or grant redistribution rights to third-party captures.
See CONTRIBUTING.md for provenance and the distinction between compilation and
device execution. Missing or modified inputs fail instead of skipping tests.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / 'app/src/androidTest/assets/rtp'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--from-dir', type=Path, help='local RTP directory containing captures and golden/')
    parser.add_argument('--check', action='store_true', help='verify only (the default without --from-dir)')
    args = parser.parse_args()
    if args.check and args.from_dir:
        parser.error('--check and --from-dir are mutually exclusive')
    manifest = json.loads((ROOT / 'native_build/verification/rtp/fixtures.json').read_text(encoding='utf-8'))
    source = args.from_dir or ASSETS
    failures = []
    for name, entry in manifest['files'].items():
        path = source / name
        if not path.is_file():
            failures.append('Missing: ' + name)
        elif hashlib.sha256(path.read_bytes()).hexdigest() != entry['sha256']:
            failures.append('SHA-256 mismatch: ' + name)
    if failures:
        raise SystemExit('\n'.join(failures) + '\nRTP device-test inputs are incomplete; see CONTRIBUTING.md.')
    if args.from_dir:
        for name in manifest['files']:
            target = ASSETS / name
            if target.resolve() != (source / name).resolve():
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source / name, target)
    print(f"Verified {len(manifest['files'])} RTP device-test inputs. Device execution is still required.")


if __name__ == '__main__':
    main()
