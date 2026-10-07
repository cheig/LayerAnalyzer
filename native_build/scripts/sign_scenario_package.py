#!/usr/bin/env python3
"""Sign a LayerAnalyzer scenario rule package.

Usage:
    python sign_scenario_package.py <package_dir> <signing-key.pem>

<package_dir> must contain manifest.json (unsigned), playbooks.json,
field_aliases.json, thresholds.json and evaluation_expectations.json.
The script pins the content hashes into the manifest, then writes the
SHA256withRSA signature over canonical JSON: sorted keys, UTF-8,
no whitespace, and the signature field excluded.

The private key never enters the repository; CI holds it as a secret.
The matching public key is shipped as app/src/main/assets/scenario_package_public_key.pem.
"""
import base64
import hashlib
import json
import os
import subprocess
import sys

PACKAGE_FILES = [
    "playbooks.json",
    "field_aliases.json",
    "thresholds.json",
    "evaluation_expectations.json",
]


def canonical(value):
    """Canonical JSON: sorted keys, UTF-8, no whitespace, no ASCII escaping.

    Must match ScenarioPackageManifest.canonicalJson in the app exactly.
    """
    if value is None:
        return "null"
    if isinstance(value, dict):
        return "{" + ",".join(
            json.dumps(key, ensure_ascii=False) + ":" + canonical(value[key])
            for key in sorted(value)
        ) + "}"
    if isinstance(value, list):
        return "[" + ",".join(canonical(item) for item in value) + "]"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def main():
    package_dir, key_path = sys.argv[1], sys.argv[2]
    manifest_path = os.path.join(package_dir, "manifest.json")
    manifest = json.load(open(manifest_path, encoding="utf-8"))
    manifest.pop("signature", None)

    for name in PACKAGE_FILES:
        digest = hashlib.sha256(
            open(os.path.join(package_dir, name), "rb").read()
        ).hexdigest()
        manifest["files"][name] = digest

    payload = canonical(manifest).encode("utf-8")
    payload_path = os.path.join(package_dir, ".manifest-payload.bin")
    signature_path = os.path.join(package_dir, ".manifest-signature.bin")
    open(payload_path, "wb").write(payload)

    subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", key_path,
         "-out", signature_path, payload_path],
        check=True,
    )
    signature = open(signature_path, "rb").read()
    manifest["signature"] = {
        "algorithm": "SHA256withRSA",
        "keyId": os.environ.get("SCENARIO_PACKAGE_KEY_ID", "layanalyzer-scenario-package-dev"),
        "value": base64.b64encode(signature).decode("ascii"),
    }
    json.dump(manifest, open(manifest_path, "w", encoding="utf-8"),
              ensure_ascii=False, indent=2)
    os.remove(payload_path)
    os.remove(signature_path)
    print(f"signed {manifest_path}")


if __name__ == "__main__":
    main()
