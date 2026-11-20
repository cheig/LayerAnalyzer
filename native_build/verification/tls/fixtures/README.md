# Public synthetic TLS fixtures

## TLS-401 locked release suite

The canonical manifest now has `suiteVersion: tls-golden-v1`, eight required IDs,
and explicit reference pins: desktop tshark **3.6.0**, Android Wireshark **4.0.10**.
The original three fixture files and provenance are preserved. Five additions
cover TLS 1.2+h2, TLS 1.3 ChaCha20+h1/h2, real HelloRetryRequest and real KeyUpdate.
All eight have damaged-secret, missing-handshake and missing-response-segment
assets. The five additions use downstream A/upstream B pairs and additionally
contain B's own PCAP and unknown-root/wrong-hostname rejection PCAPs.

Sources, ownership and limitations: [test asset SOURCES.md](../../../../app/src/androidTest/assets/tls/SOURCES.md).
The additions serialize real OpenSSL memory-BIO TLS records as IPv4/TCP PCAP;
they are offline parsing fixtures, not evidence of the production proxy or TUN.
Both TLS peers update traffic keys before the KeyUpdate fixture response. Only
standard NSS `*_0` secrets are retained; Wireshark derives updated secrets from
the actual KeyUpdate records. OpenSSL's nonstandard `*_N` callback labels are excluded.

From the repository root, using the host dependencies listed below:

```powershell
$env:PYTHONPATH = 'build/tls-002/python'
.\native_build\verification\tls\run_suite.ps1 -Tshark 'C:/Program Files/Wireshark/tshark.exe' -Offline
# Explicitly defer ARM64; this MUST return 2, with skipped=8 and gatePassed=false:
.\native_build\verification\tls\run_suite.ps1 -Tshark '<tshark-3.6.0>' -SkipDevice
# With a test ARM64 device, run production JNI (no fixture server or VPN grant needed):
.\native_build\verification\tls\run_suite.ps1 -Tshark '<tshark-3.6.0>' -Arm64Serial '<serial>' -Offline
```

`-Python`, `-Adb`, and `-ResultsRoot` accept explicit tool/output paths. Results
default to a fresh `build/tls-401/<timestamp_random>/`; an existing directory is
rejected. The script runs desktop dissection first, then the selected ARM64
`TlsGoldenSuiteTest`, captures fresh JUnit XML and hash-only fixture reports,
and writes `suite.json`. Exit codes: **0** all required validations pass; **1**
failure/invalid evidence; **2** required device cases not run. Counts represent
fixture/backend verification cells (8 desktop + 8 ARM64), not individual assertions.
Device JUnit also appears separately. Any failed/error/skipped/missing JUnit case,
wrong ABI/version/build type, stale run/manifest hash, failed scenario or differing
body hash prevents success. `comparison` records reference and embedded results
separately for each golden; missing device hashes remain null/NOT_RUN.
Hash/status reports are written by the test to the target app's
`getExternalFilesDir(null)/tls-suite-v1/<runId>/` and collected through `adb exec-out cat`;
this does not require `run-as`, which some OEMs disable. Keylogs and PCAP inputs
remain private and are removed after native sessions close.

No command updates the golden from dissection output. New suite versions require
review of the fixed input, independent client result and actual dissection.

Regenerate only into a **new directory under the repository**:

```powershell
python native_build/verification/tls/generate_release_fixture.py --output build/tls-golden-new --libssl '<OpenSSL-3-shared-library>' --tshark '<tshark-3.6.0>'
python native_build/verification/tls/check_fixture.py --manifest build/tls-golden-new/manifest.json --tshark '<tshark-3.6.0>'
python -m unittest discover -s native_build/verification/tls -p test_suite_runner.py -v
```

On Windows the OpenSSL 3 DLL must have `libcrypto-3.dll` beside it; this run used
Python 3.11.5's `DLLs/libssl-3.dll` (OpenSSL 3.0.9). On Linux use libssl.so.3 with
the matching libcrypto installed. Generation uses public OpenSSL C APIs via ctypes,
explicit root/hostname verification, temporary private keys and bounded BIO pumps.
It preserves the original three P0 fixtures, creates new random handshakes, and
writes only the fixed body input after an independent client has verified it.
The checker verifies negotiated ciphers, HRR random and KeyUpdate handshake type,
not just feature declarations. The manifest hashes every file; damaged fixtures
are independently rederived and compared before dissection.

## Original TLS-002 sources and generator (historical scope: three fixtures)

TLS-002 fixtures contain only the UTF-8 response `LayerAnalyzer TLS fixture v1\n`
(29 bytes; the last byte is LF). Its SHA-256 is
`9b1ce3253f3312a2d0f896f307a944a2effe972d55ba1a33cc939feb6e6fd7c4`.
The three directories contain real TLS 1.2 + HTTP/1.1, TLS 1.3 + HTTP/1.1,
and TLS 1.3 + HTTP/2 exchanges on host IPv4 loopback. They do **not** represent
Android TUN captures, a MITM proxy, or built-in Wireshark validation.

`manifest.json` conforms to `../fixture-manifest.json` and records all asset hashes,
protocols, generation commands, tool versions and connection identities. Local
`.gitattributes` preserves exact asset bytes across Git line-ending settings. For each fixture:

- `capture.pcap`: dumpcap capture, filtered to the script's loopback server port;
  exactly one TCP/TLS connection, including the handshake.
- `session.keys`: NSS secrets for that connection; `direct-test-connection` direction.
- `wrong.keys`: secrets from a second, independently negotiated connection, made
  **after capture stopped**. Both client randoms are recorded in the manifest.
- `client-result.json`: actual trusted/untrusted client outcomes and independently
  parsed response bytes, status, TLS version, ALPN and body hash.
- `golden-body.bin`: response bytes extracted by tshark's HTTP dissector (h1) or
  HTTP/2 stream 1 DATA dissector (h2), then compared with the client's response.
- `ca.pem`: public synthetic CA certificate, generated for this run. Its expiration
  does not prevent offline dissection. Regenerate certificates for new live tests.

All included secrets are deliberately public and apply only to these synthetic
captures. No account traffic, runtime CA private key, device file or real capture
secret is included. The CA signing key remains in memory; the leaf private key is
written only inside a temporary directory needed by Python SSL and removed on
normal exit. A forcibly killed process can leave an OS temporary directory; never
reuse such a directory or install this CA as a system root.

## Install and generate

Run at repository root with Python 3.11+ and a tshark/dumpcap installation supporting
TLS 1.3 and HTTP/2. Npcap loopback is required on Windows. Dependencies are host tools;
they are not packaged in Android. For example:

```powershell
python -m pip install --index-url https://pypi.org/simple --target build/tls-002/python -r native_build/verification/tls/fixtures/requirements.txt
$env:PYTHONPATH = 'build/tls-002/python'
# Set these to the installed tools, or place both tools on PATH.
$env:TSHARK = (Get-Command tshark).Source
$env:DUMPCAP = (Get-Command dumpcap).Source
python native_build/verification/tls/generate_fixture.py generate --output build/tls-fixtures-new --tshark "$env:TSHARK" --dumpcap "$env:DUMPCAP" --interface '\Device\NPF_Loopback'
python native_build/verification/tls/check_fixture.py --manifest build/tls-fixtures-new/manifest.json --tshark "$env:TSHARK" --report build/tls-fixtures-new/check-report.json
python -m unittest discover -s native_build/verification/tls/fixtures -p 'test_*.py' -v
```

On Linux use `--interface lo`; on macOS use `--interface lo0`. The generator accepts
only those loopback names and the Npcap loopback device, and always filters
`host 127.0.0.1 and tcp port <reserved-server-port>`. It will not collect other
interfaces or overwrite an existing manifest/fixture directory. Generate into a
new directory under the repository; review and copy the three directories and
manifest together if intentionally replacing the checked-in fixtures. Random
certificate, keylog and capture hashes should change; the decoded body must not.
`manifest.pending.json` becomes `manifest.json` only after the full checker passes.

The checker fails nonzero for schema/version, duplicate/missing roles or protocols,
path traversal, hashes, mismatched connection randoms, untrusted-root acceptance,
incorrect client bytes or TLS/ALPN, dissection differences, and plaintext obtained
with a wrong or empty keylog. Each dissection uses a fresh Wireshark configuration
directory and an explicit keylog to prevent ambient user secrets affecting tests.
It checks the negotiated ServerHello version and selected server ALPN, rather than
assuming a fixture directory name proves negotiation. h2 never uses HTTP/1 fields.

The checked-in fixtures were generated and verified with tshark **3.6.0** and
Python OpenSSL **3.0.9**; Android bundles Wireshark **4.0.10**. Use `TlsGoldenSuiteTest` to check the embedded library on a device.

## Reusable live endpoints

The same generator provides standalone endpoints with explicit addresses. Start
one process per protocol/port, keep its public CA path unique, and copy only the
public CA to the test client. The private key is never exported by this interface:

```powershell
python native_build/verification/tls/generate_fixture.py serve --protocol tls13-h2 --bind 127.0.0.1 --port 18443 --ca-output build/tls-live/ca.pem
python native_build/verification/tls/generate_fixture.py client --protocol tls13-h2 --host 127.0.0.1 --port 18443 --trust-ca build/tls-live/ca.pem --result build/tls-live/trusted.json
python native_build/verification/tls/generate_fixture.py client --protocol tls13-h2 --host 127.0.0.1 --port 18443 --reject-ca --result build/tls-live/untrusted.json
```

The server's READY JSON contains `serverName: fixture.layeranalyzer.test` and its
bound port. The client uses that hostname for SNI and certificate verification but
connects to the explicit `--host`; it does not resolve or replace the destination.
The untrusted client keeps `CERT_REQUIRED` with an empty trust store; exit 0 means
the **expected certificate rejection** occurred, not a successful TLS connection.
Other failures return nonzero. TLS/ALPN are fixed by `--protocol tls12-h1`,
`tls13-h1`, or `tls13-h2`. HTTP/2 is implemented using hyper-h2/HPACK, including
SETTINGS, HEADERS, DATA and END_STREAM, and drains final client acknowledgements.

For Android emulator tests the client destination is `10.0.2.2`; for physical
devices bind the server to an explicitly chosen controlled LAN address and give
that address to the client. Do not hardcode localhost in device tests. These host
tools do not grant VPN permissions, reset devices, or implement Android test clients.
