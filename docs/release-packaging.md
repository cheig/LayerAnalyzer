# APK release attachments

Each APK release uploads exactly two files:

- `LayerAnalyzer-<architecture>-<version>.apk`, for example
  `LayerAnalyzer-arm64-v8a-1.0.0.apk`.
- `SHA256SUMS`, containing one SHA-256 entry using that exact APK filename.

The Actions artifact contains the same two files. No source ZIP, SBOM, dependency
inventory, delivery manifest, license ZIP or AAB is generated as an automated
release attachment. The actual Gradle runtime inventory remains an intermediate
build input for dependency/license verification.

## Source and license access

The release body links directly to the complete application source archive at the
exact build commit, the pinned complete native source archive, build instructions
and patches, LICENSE and third-party notices. These materials remain in the public
source/dependency repositories. Full license texts and notices are also included
in the APK. Verify source download availability before publishing.

GitHub may additionally display its own automatic Source code ZIP/tar.gz links.
Those are GitHub's repository downloads, not extra assets uploaded by this workflow.

## Automated draft workflow

1. Prepare a reviewed public commit, set `versionName` / `versionCode` in
   `app/build.gradle.kts`, and add `docs/releases/<tag>.md` with changes, known
   issues and a device validation checklist. Increment versionCode for a new version.
2. Configure the four signing Repository secrets listed in CONTRIBUTING and set
   Repository variable `ENABLE_APK_PACKAGING=true`. The public certificate SHA-256
   is pinned in `tools/release-signing-certificate.sha256`; use the same private
   key as existing official installations.
3. Push the exact version tag: `v` plus the APK versionName. Only tag pushes run
   package; PRs and `workflow_dispatch` cannot access its signing secrets.
4. Unit tests, native tests and development builds must pass first. Package then
   runs Release tests/lint/build, checks package/version/ABI and non-debuggable
   status, the pinned v2 signer, ELF/ZIP 16 KB alignment, actual APK license bytes,
   reviewed runtime dependencies and the expected native library set.
5. `create-apk` copies the signed APK under its final name and creates SHA256SUMS.
   `verify-apk` rejects missing, extra, renamed or changed attachments. Upload and
   download use this same two-file staging directory.
6. The separate `release-draft` job downloads the artifact from the same run,
   verifies the tag/checkout commit and filename version, creates a draft, and
   checks GitHub's stored asset sizes and SHA-256 digests. Only this job has
   `contents: write`; it has no signing secrets. Tags containing `-` set prerelease.
7. Download that CI APK for device installation and core-flow validation. Record
   results in the draft and publish manually when ready. The workflow never publishes.

Current packaging keeps Wireshark 4.0.10 / r1 libraries and r2 corresponding source.
Upgrades/backports remain follow-up maintenance; known issues are documented in
[the maintenance assessment](wireshark-security-maintenance.md). A draft is not
public APK distribution or device validation; source tags and CI logs remain public.

Retries keep matching assets and upload only missing ones. Published releases,
drafts for another commit, and unexpected or changed assets are rejected; no
`--clobber` is used. Retry only a failed draft job to retain the same package
artifact. Full rebuilds can differ, so use a new candidate version or explicitly
remove an unpublished failed draft before retrying. Per-tag concurrency serializes
uploads. Rerunning an older tag uses that tag's original workflow and attachment format.

## Local packaging and validation

Use a clean committed checkout and a fresh signed build matching that commit.
Windows uses `gradlew.bat`; supply signing environment variables from CONTRIBUTING.

```sh
./gradlew -I tools/runtime_license_inventory.init.gradle testReleaseUnitTest lintRelease assembleRelease :app:exportRuntimeLicenseInventory
python tools/verify_release_apk.py --apk app/build/outputs/apk/release/app-release.apk --inventory build/license-audit/releaseRuntimeClasspath.json --tag v1.0.0
python tools/stage_release.py create-apk --staging build/release-staging --inventory build/license-audit/releaseRuntimeClasspath.json --apk app/build/outputs/apk/release/app-release.apk
python tools/stage_release.py verify-apk --staging build/release-staging --tag v1.0.0
```

After downloading both attachments, run `sha256sum -c SHA256SUMS` in their directory.
The Python verifier additionally rejects extra files. Run tool checks with:

```sh
python -m unittest discover -s tools/tests -p 'test_release*.py' -v
python tools/check_source_checkout.py
```

The older `stage_release.py create` / `verify` source-audit commands remain available
for explicit source handoffs; they are not used by the APK release workflow.
