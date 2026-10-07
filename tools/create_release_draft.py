#!/usr/bin/env python3
"""Create a GitHub draft from verified staging; never publish or replace assets."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
from urllib.parse import quote

from stage_release import ROOT, digest, read_json, verify_apk


def api(endpoint, payload=None, paginate=False):
    command = ['gh', 'api', endpoint]
    if paginate:
        command += ['--paginate', '--slurp']
    if payload is not None:
        command += ['--method', 'POST', '--input', '-']
    result = subprocess.run(command, input=json.dumps(payload) if payload is not None else None,
                            text=True, encoding='utf-8', capture_output=True, check=True)
    return json.loads(result.stdout)


def pages(endpoint):
    return [item for page in api(endpoint + '?per_page=100', paginate=True) for item in page]


def check_draft(release, tag, commit):
    if not release['draft']:
        raise ValueError('Release is already published; it will not be modified')
    if release['tag_name'] != tag or release['target_commitish'] != commit:
        raise ValueError('Existing draft does not belong to this exact source commit')


def check_assets(assets, stage, complete=False):
    expected = {path.name: path for path in stage.iterdir()}
    names = [asset['name'] for asset in assets]
    if len(names) != len(set(names)) or not set(names) <= expected.keys():
        raise ValueError('Draft has duplicate or unexpected attachments')
    if complete and set(names) != expected.keys():
        raise ValueError('Draft attachment set is incomplete')
    for asset in assets:
        path = expected[asset['name']]
        if (asset['state'] != 'uploaded' or asset['size'] != path.stat().st_size or
                asset.get('digest') != 'sha256:' + digest(path)):
            raise ValueError('Existing attachment differs; no overwrite: ' + path.name)
    return set(names)


def create(stage, repo, tag, commit):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo):
        raise ValueError('Invalid repository')
    if not re.fullmatch(r'v[0-9][A-Za-z0-9._-]*', tag) or not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ValueError('Expected a version tag and full commit SHA')
    apk = verify_apk(stage, tag)
    checkout = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    if checkout != commit:
        raise ValueError('Draft must use the same source checkout as the workflow commit')
    notes = (ROOT / 'docs/releases' / (tag + '.md')).read_text(encoding='utf-8')
    certificate = (ROOT / 'tools/release-signing-certificate.sha256').read_text().strip()
    sources = read_json(ROOT / 'native_build/native-sources.json')
    tree_url = f'https://github.com/{repo}/blob/{commit}'
    body = notes + (
        f'\n\nSource commit: `{commit}`.\n\n'
        f'APK signing certificate SHA-256: `{certificate}`.\n\n'
        f'APK SHA-256: `{digest(apk)}`.\n\n'
        f'[完整应用源码 / Application source](https://github.com/{repo}/archive/{commit}.zip) · '
        f'[完整原生源码 / Native source]({sources["url"]}) · '
        f'[构建说明与补丁入口 / Build instructions]({tree_url}/CONTRIBUTING.md) · '
        f'[许可证 / License]({tree_url}/LICENSE) · '
        f'[第三方声明 / Third-party notices]({tree_url}/THIRD_PARTY_NOTICES.md)\n\n'
        'Assets contain only the APK and SHA256SUMS. Run `sha256sum -c SHA256SUMS` after download.\n')
    endpoint = f'repos/{repo}'
    ref = api(endpoint + '/git/ref/tags/' + quote(tag, safe=''))['object']
    for _ in range(10):
        if ref['type'] != 'tag':
            break
        ref = api(endpoint + '/git/tags/' + ref['sha'])['object']
    if ref['type'] != 'commit' or ref['sha'] != commit:
        raise ValueError('Remote tag does not resolve to this workflow commit')
    matches = [release for release in pages(endpoint + '/releases') if release['tag_name'] == tag]
    if len(matches) > 1:
        raise ValueError('Multiple releases for this tag')
    if matches:
        release = matches[0]
        check_draft(release, tag, commit)
    else:
        release = api(endpoint + '/releases', {
            'tag_name': tag, 'target_commitish': commit, 'name': 'LayerAnalyzer ' + tag,
            'body': body, 'draft': True, 'prerelease': '-' in tag, 'make_latest': 'false'})
        check_draft(release, tag, commit)
    release_endpoint = endpoint + '/releases/' + str(release['id'])
    existing = check_assets(pages(release_endpoint + '/assets'), stage)
    for path in sorted(stage.iterdir()):
        if path.name not in existing:
            check_draft(api(release_endpoint), tag, commit)
            subprocess.run(['gh', 'release', 'upload', tag, str(path), '--repo', repo], check=True)
    release = api(release_endpoint)
    check_draft(release, tag, commit)
    assets = pages(release_endpoint + '/assets')
    check_assets(assets, stage, complete=True)
    result = {'url': release['html_url'], 'draft': True, 'tag': tag,
              'commit': commit, 'attachments': len(assets)}
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as summary:
            summary.write(f'Created [Release draft]({result["url"]}) with {len(assets)} verified attachments.\n'
                          '\nDownload and validate this CI APK on a device before publishing.\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--staging', required=True, type=Path)
    parser.add_argument('--repo', required=True)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--commit', required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(create(args.staging.resolve(), args.repo, args.tag, args.commit)))
    except subprocess.CalledProcessError as error:
        raise SystemExit(f'GitHub CLI failed ({error.returncode}): {error.stderr or "see step output"}') from error
    except (ValueError, KeyError, OSError) as error:
        raise SystemExit(str(error)) from error


if __name__ == '__main__':
    main()
