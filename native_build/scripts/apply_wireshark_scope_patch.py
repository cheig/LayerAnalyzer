"""Apply the required TLS-405 Wireshark 4.0.10 backport, idempotently and fail closed."""
import argparse
import hashlib
from pathlib import Path
import subprocess
import shutil
import tempfile

ROOT = Path(__file__).resolve().parents[2]
PATCH = ROOT / 'native_build/patches/wireshark/addr-resolv-scope-lifetime.patch'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / 'native_build/external/wireshark-4.0.10')
    args = parser.parse_args()
    source = args.source.resolve()
    if not (source / 'epan/addr_resolv.c').is_file():
        parser.error('Prepare the pinned Wireshark 4.0.10 sources first')
    # An extracted source archive has no .git. Stage outside the enclosing app
    # repository so git apply cannot silently filter paths by its subdirectory.
    with tempfile.TemporaryDirectory(prefix='tls405-wireshark-') as directory:
        staged = Path(directory)
        (staged / 'epan').mkdir()
        source_file = source / 'epan/addr_resolv.c'
        staged_file = staged / 'epan/addr_resolv.c'
        shutil.copyfile(source_file, staged_file)
        def check(*options):
            return subprocess.run(['git', 'apply', '--check', *options, str(PATCH)],
                cwd=staged, stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode == 0
        if check('--reverse'):
            print('TLS-405 source backport already applied')
        elif check():
            subprocess.run(['git', 'apply', str(PATCH)], cwd=staged, check=True)
            # Git for Windows may honor core.autocrlf even outside a repository.
            staged_file.write_text(staged_file.read_text(encoding='utf-8'), encoding='utf-8', newline='\n')
            shutil.copyfile(staged_file, source_file)
            print('Applied TLS-405 source backport')
        else:
            raise SystemExit('Wireshark source differs from the expected backport; refusing a partial patch')
    print('patch sha256=' + hashlib.sha256(PATCH.read_bytes()).hexdigest())


if __name__ == '__main__':
    main()
