#!/usr/bin/env python3
"""Replay TLS-311 JVM-exported PUBLIC fixture bundles in independent tshark processes.

Not a general-purpose importer. Only the TLS-002 synthetic fixture bytes are accepted.
No keylog or decrypted text is printed; temporary extracted assets are always removed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import tempfile
import zipfile

from check_fixture import inspect_capture, require, tool_version


def check(bundle: Path, fixture_id: str, tshark: str) -> dict:
    fixture_root = Path(__file__).resolve().parent / "fixtures"
    fixtures = json.loads((fixture_root / "manifest.json").read_text(encoding="utf-8"))["fixtures"]
    fixture = next(item for item in fixtures if item["fixtureId"] == fixture_id)
    require(fixture["source"] == "synthetic-local-test-only", "Only public test fixtures allowed")
    expected = {item["role"]: fixture_root / item["path"] for item in fixture["files"]}
    with zipfile.ZipFile(bundle) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)) and len(names) <= 131, "Invalid entry count")
        require(sum(entry.file_size for entry in archive.infolist()) <= 32 * 1024 * 1024,
                "Public fixture verification budget exceeded")
        manifest = json.loads(archive.read("manifest.json"))
        segments = [segment["file"] for segment in manifest["segments"]]
        require(set(names) == set(segments + ["manifest.json", "keys.log", "checksums.json"]),
                "Unexpected bundle file")
        index = json.loads(archive.read("checksums.json"))
        require(set(index["files"]) == set(names) - {"checksums.json"}, "Incomplete checksums")
        for name, entry in index["files"].items():
            data = archive.read(name)
            require(len(data) == entry["bytes"] and hashlib.sha256(data).hexdigest() == entry["sha256"],
                    "Bundle checksum mismatch")
        merged = bytearray()
        header = None
        for name in segments:
            data = archive.read(name)
            require(len(data) >= 24, "Truncated segment")
            if header is None:
                header = data[:24]
                merged.extend(header)
            require(data[:24] == header, "Incompatible segment headers")
            merged.extend(data[24:])
        require(bytes(merged) == expected["pcap"].read_bytes(), "Export changed original packet bytes")
        keylog = archive.read("keys.log")
        canonical = lambda data: sorted(line.strip().lower() for line in data.splitlines()
                                        if line.strip() and not line.startswith(b"#"))
        require(canonical(keylog) == canonical(expected["keylog"].read_bytes()), "Unexpected fixture keylog")
    client = json.loads(expected["client-result"].read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory(prefix="la-bundle-replay-") as directory:
        pcap = Path(directory) / "capture.pcap"
        keys = Path(directory) / "keys.log"
        pcap.write_bytes(merged)
        keys.write_bytes(keylog)
        port = client["trusted"]["destinationPort"]
        positive = inspect_capture(tshark, pcap, keys, port, fixture["alpn"])
        negative = inspect_capture(tshark, pcap, None, port, fixture["alpn"])
        require(positive["body"] == expected["golden-body"].read_bytes(), "Exported body mismatch")
        require(not negative["body"], "Raw capture unexpectedly decrypts without keys")
        return {"fixtureId": fixture_id, "segments": len(segments), "bodySha256":
                hashlib.sha256(positive["body"]).hexdigest(), "withoutKeysBodyBytes": len(negative["body"]),
                "result": "PASS"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path("app/build/tls-311"))
    parser.add_argument("--tshark", default="tshark")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    result = {"referenceTshark": tool_version(args.tshark), "fixtures": [
        check(args.directory / (name + ".zip"), name, args.tshark) for name in ("tls12-h1", "tls13-h1")
    ]}
    text = json.dumps(result, indent=2)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(text + "\n", encoding="utf-8")
    print(text)
