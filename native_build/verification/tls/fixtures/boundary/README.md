# TLS-217 boundary fixtures

`clienthello-vectors.json` contains synthetic ECH-extension and GREASE vectors
from `generate_clienthello_vectors.py`. These classifier inputs prove extension
presence only; a successful ECH negotiation is a separate device test.

`protocol_fixture.py` and `ech_peer.go` provide real protocol peers for
`TlsProtocolBoundaryTest`. They are test-only and are not linked into the app.

- KeyUpdate: the public OpenSSL `SSL_key_update` API sends `request_update=1`
  from both endpoints. The message callback observes actual handshake messages,
  including the proxy's `request_update=0` replies. Two 32 KiB payloads must match
  in both directions. Peers exchange both close_notify messages before closing.
- ECH: Go `crypto/tls` uses a fresh X25519 ECH key, HKDF-SHA256 and AES-128-GCM.
  Both endpoints must report `ECHAccepted=true` and `inner.boundary.test` for
  the bypass positive control. A second case includes `outer.boundary.test`:
  the client must report `ECHRejectionError`, the engine must end FAILED, and
  the origin must receive zero application bytes with no replay or bypass.
- The Android test copies opaque TLS bytes between the host client and the real
  production gateway. Physical network binding, Android chain/name verification
  with an in-memory fixture root, JNI, Go, CA leasing and encrypted secret storage
  are real. The peers are host processes; this test does not create a VPN or TUN,
  and does not prove Wireshark decryption of a KeyUpdate capture.

Only public certificates and counters use the bounded HTTP control transport.
No CA private key, proxy token or capture secret leaves Android. Fixture server
keys exist only in temporary directories under the ignored work directory;
DELETE or the 40-second watchdog closes peers and removes those files. The
device test deletes only its own UUID capture secrets. No system CA is installed.

## Run

Use the repository's Go 1.27.2, Python 3.12 and a public OpenSSL 3 library. On
Windows the script loads Python's `DLLs/libssl-3.dll`; it uses public C APIs,
never private CPython SSL object offsets. This run used OpenSSL 3.0.13 and
cryptography 50.0.2 in an isolated ignored venv.

```powershell
$tlsGo = (Resolve-Path build/tls-003/tools/go/bin/go.exe).Path
python -m venv build/tls-217/venv
& build/tls-217/venv/Scripts/python.exe -m pip install cryptography==50.0.2
New-Item -ItemType Directory -Force build/tls-217/protocol-fixture | Out-Null
& $tlsGo build -o build/tls-217/protocol-fixture/ech-peer.exe native_build/verification/tls/fixtures/boundary/ech_peer.go
& build/tls-217/venv/Scripts/python.exe native_build/verification/tls/fixtures/boundary/protocol_fixture.py --ech-peer build/tls-217/protocol-fixture/ech-peer.exe --self-test

# Keep this fixture in a separate terminal. Use the actual controlled LAN IP.
& build/tls-217/venv/Scripts/python.exe native_build/verification/tls/fixtures/boundary/protocol_fixture.py --bind <fixture-host> --port 18087 --ech-peer build/tls-217/protocol-fixture/ech-peer.exe

# On the host, with the fixture running and the device's VPN stopped:
$env:ANDROID_SERIAL = '<device-serial>'
.\gradlew.bat :app:connectedDebugAndroidTest --offline `
  -PlayanalyzerEnableTls=true -PlayanalyzerTlsProbe=false "-PlayanalyzerTlsGo=$tlsGo" `
  '-Pandroid.testInstrumentationRunnerArguments.class=com.example.layanalyzer.TlsProtocolBoundaryTest' `
  '-Pandroid.testInstrumentationRunnerArguments.hostGateway=<fixture-host>' `
  '-Pandroid.testInstrumentationRunnerArguments.boundaryControlPort=18087' `
  '-Pandroid.injected.androidTest.leaveApksInstalledAfterRun=true'
```

Missing tools, unreachable peers, absent protocol messages and TLS OFF fail the
test; there are no skipped-success branches. The host `--self-test` replaces the
device with a raw byte bridge and proves fixture readiness only.
