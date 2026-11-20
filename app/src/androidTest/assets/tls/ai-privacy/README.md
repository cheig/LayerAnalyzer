# TLS-313 AI boundary fixtures

These are **public, synthetic test-only** TLS 1.2/1.3 captures and corresponding
session keylogs. They contain no user traffic or production credentials. They are
packaged in androidTest only, never in the application APK.

`native_build/verification/tls/generate_agent_privacy_fixture.py` creates a verified
OpenSSL client/server handshake entirely through MemoryBIO (no network), exchanges
HTTP/1.1 request/response bytes, and wraps the encrypted records in checksummed
LINKTYPE_RAW IPv4/TCP packets using documentation addresses. The client independently
compares the received response; the server compares the request. Certificate private
keys are temporary and not retained. `manifest.json` pins the committed files by SHA-256.

The plaintext has distinct Cookie, Authorization, URI, request-body/prompt-injection
and response-body sentinels. `TlsAgentBoundaryTest` first proves native decryption
exposes them, then checks production AI tool results exclude them under default
cloud policies. The existing canonical `tls13-h2` fixture supplies HTTP/2 coverage.

Regenerate with Python + cryptography (recorded run: Python 3.12, cryptography 50.0.2):

```powershell
python native_build/verification/tls/generate_agent_privacy_fixture.py --output app/src/androidTest/assets/tls/ai-privacy
```

TLS randomness means regeneration produces new bytes and hashes; commit the manifest
and both capture/keylog pairs together. Never substitute a real capture.
