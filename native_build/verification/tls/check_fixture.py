#!/usr/bin/env python3
"""Validate synthetic TLS fixtures using an independent tshark dissection.

No TLS secret or decrypted application text is printed. Each tshark process uses
an isolated configuration directory so an ambient keylog cannot pass a negative.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import platform
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

ROOT = Path(__file__).resolve().parent
COMBINATIONS = {("TLS1.2", "http/1.1"), ("TLS1.3", "http/1.1"), ("TLS1.3", "h2")}
RELEASE_IDS = {"tls12-h1", "tls13-h1", "tls13-h2", "tls12-h2", "tls13-chacha-h1",
               "tls13-chacha-h2", "tls13-hrr-h1", "tls13-keyupdate-h1"}
HRR_RANDOM = "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tool_version(tool: str) -> str:
    result = subprocess.run([tool, "--version"], capture_output=True, check=True,
                            timeout=15, encoding="utf-8", errors="replace")
    return result.stdout.splitlines()[0]


def keylog_random(path: Path) -> str:
    randoms = set()
    labels = set()
    for line in path.read_text(encoding="ascii").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        columns = line.split()
        require(len(columns) == 3, "Malformed synthetic keylog")
        label, random, secret = columns
        require(re.fullmatch(r"[0-9a-fA-F]{64}", random) is not None,
                "Invalid keylog client random")
        require(re.fullmatch(r"(?:[0-9a-fA-F]{2})+", secret) is not None,
                "Invalid keylog secret encoding")
        allowed = {"CLIENT_RANDOM", "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
                   "SERVER_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_TRAFFIC_SECRET_0",
                   "SERVER_TRAFFIC_SECRET_0", "EXPORTER_SECRET"}
        require(label in allowed, "Unexpected fixture keylog label")
        require(len(secret) == 96 if label == "CLIENT_RANDOM" else len(secret) in (64, 96, 128),
                "Invalid keylog secret length")
        require(label not in labels, "Repeated fixture keylog label")
        labels.add(label)
        randoms.add(random.lower())
    require(len(randoms) == 1, "Expected exactly one keylog connection")
    return next(iter(randoms))


def field_values(element: ET.Element, name: str, attribute: str = "show") -> list[str]:
    return [field.get(attribute, "") for field in element.iter("field")
            if field.get("name") == name]


def inspect_capture(tshark: str, pcap: Path, keylog: Path | None,
                    port: int, alpn: str) -> dict:
    """Return bytes from the HTTP/HTTP2 dissector, never from expected text."""
    with tempfile.TemporaryDirectory(prefix="la-tshark-") as directory:
        temp = Path(directory)
        empty_keylog = temp / "empty.keys"
        empty_keylog.write_bytes(b"")
        environment = os.environ.copy()
        environment["WIRESHARK_CONFIG_DIR"] = str(temp)
        environment.pop("SSLKEYLOGFILE", None)
        command = [tshark, "-n", "-2", "-r", str(pcap), "-d", f"tcp.port=={port},tls",
                   "-o", f"tls.keylog_file:{keylog or empty_keylog}", "-o", "tls.keys_list:",
                   "-o", "tcp.desegment_tcp_streams:TRUE",
                   "-o", "tls.desegment_ssl_records:TRUE",
                   "-o", "tls.desegment_ssl_application_data:TRUE", "-T", "pdml"]
        process = subprocess.run(command, capture_output=True, timeout=30, env=environment)
        require(process.returncode == 0, "tshark dissection failed (check executable and preferences)")
        document = ET.fromstring(process.stdout)

    streams, randoms, versions, protocols, statuses = set(), set(), set(), set(), []
    ciphers, handshake_types, server_randoms = set(), [], set()
    body = bytearray()
    body_frames = set()
    request_seen = False
    for packet in document.findall("packet"):
        before_body = len(body)
        streams.update(field_values(packet, "tcp.stream"))
        for field in packet.iter("field"):
            if field.get("name") != "tls.handshake":
                continue
            types = field_values(field, "tls.handshake.type")
            handshake_types.extend(types)
            if "1" in types:
                randoms.update(value.replace(":", "").lower()
                               for value in field_values(field, "tls.handshake.random", "value"))
            if "2" in types:
                ciphers.update(field_values(field, "tls.handshake.ciphersuite"))
                server_randoms.update(value.replace(":", "").lower()
                                      for value in field_values(field, "tls.handshake.random", "value"))
                versions.update(field_values(field, "tls.handshake.extensions.supported_version")
                                or field_values(field, "tls.handshake.version"))
            if "2" in types or "8" in types:
                protocols.update(field_values(field, "tls.handshake.extensions_alpn_str"))

        if alpn == "h2":
            # Decode actual HTTP/2 DATA on response stream 1, never http.file_data.
            request_seen |= "GET" in field_values(packet, "http2.headers.method")
            for proto in packet.findall("proto"):
                if proto.get("name") != "http2":
                    continue
                for frame in proto.findall("field"):
                    if frame.get("name") != "http2.stream" or field_values(frame, "http2.streamid") != ["1"]:
                        continue
                    if str(port) in field_values(packet, "tcp.srcport"):
                        statuses.extend(field_values(frame, "http2.headers.status"))
                        for value in field_values(frame, "http2.data.data", "value"):
                            body.extend(bytes.fromhex(value.replace(":", "")))
        else:
            request_seen |= "GET" in field_values(packet, "http.request.method")
            if str(port) in field_values(packet, "tcp.srcport"):
                statuses.extend(field_values(packet, "http.response.code"))
                for value in field_values(packet, "http.file_data", "value"):
                    body.extend(bytes.fromhex(value.replace(":", "")))
        if len(body) > before_body:
            body_frames.update(int(value) for value in field_values(packet, "frame.number"))
    return {"body": bytes(body), "streams": streams, "randoms": randoms,
            "versions": versions, "alpn": protocols, "statuses": statuses,
            "ciphers": ciphers, "hrr": HRR_RANDOM in server_randoms,
            "keyUpdate": "24" in handshake_types,
            "bodyFrames": body_frames,
            "requestSeen": request_seen, "packets": len(document.findall("packet"))}


def incomplete_capture(data: bytes, port: int, missing_handshake: bool, body_frames: set[int] | None = None) -> bytes:
    """Drop a real TCP segment, preserving all later sequence numbers.

    Supports the published little-endian DLT_NULL and DLT_RAW fixtures only.
    Missing handshake drops ClientHello record segments (including HRR retry).
    Missing segment drops a segment identified by the actual body dissection.
    """
    require(data[:4] == bytes.fromhex("d4c3b2a1"), "Unsupported fixture PCAP format")
    link = struct.unpack_from("<I", data, 20)[0]
    require(link in (0, 101), "Unsupported fixture link type")
    ip = 4 if link == 0 else 0
    records, candidates = [], []
    def handshake_payload(payload: bytes) -> bool:
        position = 0
        while position + 5 <= len(payload) and payload[position+1] == 3:
            if payload[position] == 22: return True
            position += 5 + int.from_bytes(payload[position+3:position+5], "big")
        return False
    offset = 24
    while offset < len(data):
        require(offset + 16 <= len(data), "Truncated PCAP record header")
        size = struct.unpack_from("<I", data, offset + 8)[0]
        end = offset + 16 + size
        require(end <= len(data), "Truncated PCAP record")
        packet = data[offset+16:end]
        tcp = ip + (packet[ip] & 15) * 4
        header_end = tcp + (packet[tcp+12] >> 4) * 4
        source_port = struct.unpack_from("!H", packet, tcp)[0]
        if len(packet) > header_end and ((source_port != port and handshake_payload(packet[header_end:]))
                                        if missing_handshake else (len(records) + 1 in (body_frames or set()))):
            candidates.append(len(records))
        records.append(data[offset:end])
        offset = end
    require(bool(candidates), "No TCP payload available for negative fixture")
    omitted = set(candidates) if missing_handshake else {candidates[0]}
    return data[:24] + b"".join(record for index, record in enumerate(records) if index not in omitted)


def negative_checks(tshark: str, files: dict, port: int, alpn: str, body_frames: set[int]) -> dict:
    with tempfile.TemporaryDirectory(prefix="la-negative-") as directory:
        temp = Path(directory)
        corrupt = temp / "corrupt.keys"
        lines = []
        for line in files["keylog"].read_text(encoding="ascii").splitlines():
            if not line.strip() or line.startswith("#"): continue
            label, random, secret = line.split()
            lines.append(f"{label} {random} {'0' * len(secret)}")
        corrupt.write_text("\n".join(lines) + "\n", encoding="ascii")
        if "corrupt-keylog" in files:
            require(files["corrupt-keylog"].read_bytes() == corrupt.read_bytes(), "Corrupt-secret fixture derivation mismatch")
        counts = {"corrupt-secret": len(inspect_capture(tshark, files["pcap"], corrupt, port, alpn)["body"])}
        for name, handshake in (("missing-handshake", True), ("missing-segment", False)):
            capture = temp / f"{name}.pcap"
            capture.write_bytes(incomplete_capture(files["pcap"].read_bytes(), port, handshake, body_frames))
            if name in files:
                require(files[name].read_bytes() == capture.read_bytes(), "Incomplete capture derivation mismatch")
            counts[name] = len(inspect_capture(tshark, capture, files["keylog"], port, alpn)["body"])
        require(not any(counts.values()), "Incomplete/corrupt fixture exposed golden plaintext")
        return counts


def confined_file(directory: Path, relative: str) -> Path:
    require(not Path(relative).is_absolute() and "\\" not in relative and ":" not in relative,
            "Manifest path must be relative with forward slashes")
    require(all(part not in ("", ".", "..") for part in relative.split("/")),
            "Manifest path contains a traversal component")
    path = (directory / relative).resolve()
    require(path.is_relative_to(directory.resolve()), "Manifest path escapes fixture directory")
    require(path.is_file(), f"Missing fixture file: {relative}")
    return path


def check_manifest(manifest: Path, tshark: str) -> list[dict]:
    data = json.loads(manifest.read_text(encoding="utf-8"))
    schema = json.loads((ROOT / "fixture-manifest.json").read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(data)
    fixtures = data["fixtures"]
    require(len({item["fixtureId"] for item in fixtures}) == len(fixtures), "Duplicate fixtureId")
    release = data.get("suiteVersion") == "tls-golden-v1"
    combinations = COMBINATIONS | ({("TLS1.2", "h2")} if release else set())
    require({(item["tlsVersion"], item["alpn"]) for item in fixtures} == combinations,
            "Missing required TLS/ALPN combination")
    if release:
        require({item["fixtureId"] for item in fixtures} == RELEASE_IDS, "Missing required release fixture")
        require(data.get("referenceVersions") == {"embedded": "4.0.10", "desktop": "3.6.0"},
                "Reference version lock changed")
        certificate_checks = data.get("certificateChecks", [])
        expected_certificates = {(id, case) for id in RELEASE_IDS - {"tls12-h1", "tls13-h1", "tls13-h2"}
                                 for case in ("untrusted", "wrong-name")}
        require(len(certificate_checks) == len(expected_certificates) and
                {(case["fixtureId"], case["case"]) for case in certificate_checks} == expected_certificates,
                "Missing required certificate rejection evidence")
    reports = []
    for fixture in fixtures:
        expected = fixture["expectedBody"]["text"].encode("utf-8")
        require(sha256(expected) == fixture["expectedBody"]["sha256"], "Expected body hash mismatch")
        files, metadata = {}, {}
        for entry in fixture["files"]:
            role = entry["role"]
            require(role not in files, "Duplicate fixture file role")
            path = confined_file(manifest.parent, entry["path"])
            require(sha256(path.read_bytes()) == entry["sha256"], f"File hash mismatch: {entry['path']}")
            files[role], metadata[role] = path, entry
        require({"pcap", "keylog", "wrong-keylog", "client-result", "golden-body", "ca-certificate"}
                <= files.keys(), "Missing TLS-002 evidence role")
        if release:
            require({"corrupt-keylog", "missing-handshake", "missing-segment"} <= files.keys(),
                    "Missing release negative fixture")
        random = keylog_random(files["keylog"])
        wrong_random = keylog_random(files["wrong-keylog"])
        require(random != wrong_random, "Wrong keylog belongs to the captured connection")
        require(metadata["pcap"]["connectionId"] == metadata["keylog"]["connectionId"]
                == f"client-random:{random}", "Captured connection identity mismatch")
        require(metadata["wrong-keylog"]["connectionId"] == f"client-random:{wrong_random}",
                "Wrong connection identity mismatch")
        direction = (metadata["keylog"]["keyDirection"], metadata["wrong-keylog"]["keyDirection"])
        require(direction in (("direct-test-connection", "direct-test-connection"),
                              ("downstream-tls-a", "upstream-tls-b")), "Unexpected fixture key direction")

        clients = json.loads(files["client-result"].read_text(encoding="utf-8"))
        require(clients["schemaVersion"] == 1, "Unsupported client-result version")
        for name, identity in (("trusted", random), ("wrongConnection", wrong_random)):
            client = clients[name]
            require(client["success"] is True and client["certificateVerified"] is True,
                    "Trusted client did not verify certificate")
            require(client["tlsVersion"] == fixture["tlsVersion"] and client["alpn"] == fixture["alpn"],
                    "Client negotiated incorrect TLS/ALPN")
            actual = base64.b64decode(client["bodyBase64"], validate=True)
            require(actual == expected and sha256(actual) == client["bodySha256"],
                    "Independent client response mismatch")
            require(client["status"] == 200 and client["connectionId"] == f"client-random:{identity}",
                    "Client response or connection mismatch")
        require(clients["untrusted"]["success"] is False
                and clients["untrusted"]["errorCode"] == "CERTIFICATE_VERIFY_FAILED",
                "Unknown root was not rejected")
        port = clients["trusted"]["destinationPort"]
        require(type(port) is int and 1 <= port <= 65535, "Invalid server port")
        correct = inspect_capture(tshark, files["pcap"], files["keylog"], port, fixture["alpn"])
        wrong = inspect_capture(tshark, files["pcap"], files["wrong-keylog"], port, fixture["alpn"])
        no_key = inspect_capture(tshark, files["pcap"], None, port, fixture["alpn"])
        require(correct["streams"] == {"0"} and correct["randoms"] == {random},
                "PCAP must contain exactly the expected TLS connection")
        expected_version = "0x0303" if fixture["tlsVersion"] == "TLS1.2" else "0x0304"
        require(correct["versions"] == {expected_version}, "Dissector negotiated TLS version mismatch")
        require(correct["alpn"] == {fixture["alpn"]}, "Dissector selected ALPN mismatch")
        require(correct["requestSeen"] and correct["statuses"] == ["200"],
                "Dissector must see one real request and successful response")
        require(correct["body"] == expected == files["golden-body"].read_bytes(),
                "Dissected golden response mismatch")
        require(not wrong["body"] and not no_key["body"], "Negative keylog produced application plaintext")
        if release:
            cipher_codes = {"ECDHE-RSA-AES128-GCM-SHA256": "0xc02f", "TLS_AES_256_GCM_SHA384": "0x1302",
                            "TLS_AES_128_GCM_SHA256": "0x1301", "TLS_CHACHA20_POLY1305_SHA256": "0x1303"}
            cipher = fixture.get("cipherSuite")
            require(cipher in cipher_codes and correct["ciphers"] == {cipher_codes[cipher]} and
                    clients["trusted"]["cipher"] == cipher, "Locked negotiated cipher mismatch")
        negatives = negative_checks(tshark, files, port, fixture["alpn"], correct["bodyFrames"]) if release else {}
        if release and fixture["fixtureId"] not in {"tls12-h1", "tls13-h1", "tls13-h2"}:
            expected_ciphers = {"tls12-h2": "0xc02f", "tls13-chacha-h1": "0x1303",
                                "tls13-chacha-h2": "0x1303", "tls13-hrr-h1": "0x1301",
                                "tls13-keyupdate-h1": "0x1301"}
            require(correct["ciphers"] == {expected_ciphers[fixture["fixtureId"]]}, "Cipher suite mismatch")
            expected_features = {"tls13-hrr-h1": ["hrr"], "tls13-keyupdate-h1": ["key-update"]}
            features = expected_features.get(fixture["fixtureId"], [])
            require(fixture.get("features") == features, "Feature declaration mismatch")
            require(correct["hrr"] == ("hrr" in features), "Real HRR handshake missing/unexpected")
            require(correct["keyUpdate"] == ("key-update" in features), "Real KeyUpdate missing/unexpected")
            require(direction == ("downstream-tls-a", "upstream-tls-b"), "Release exchange requires TLS A/B")
            require({"upstream-pcap", "untrusted-pcap", "wrong-name-pcap"} <= files.keys(),
                    "Missing release PCAP evidence")
            upstream = inspect_capture(tshark, files["upstream-pcap"], files["wrong-keylog"], port, fixture["alpn"])
            require(upstream["body"] == expected and upstream["randoms"] == {wrong_random},
                    "TLS B keylog must decrypt its own upstream capture")
            for role in ("untrusted-pcap", "wrong-name-pcap"):
                result = inspect_capture(tshark, files[role], None, port, fixture["alpn"])
                require(not result["body"] and not result["requestSeen"], "Rejected certificate carried application data")
                negatives[role] = len(result["body"])
        reports.append({"fixtureId": fixture["fixtureId"], "passed": True,
                        "bodySha256": sha256(correct["body"]), "packets": correct["packets"],
                        "wrongKeylogPlaintextBytes": len(wrong["body"]),
                        "noKeylogPlaintextBytes": len(no_key["body"]),
                        "negativePlaintextBytes": negatives, "keyDirection": direction[0],
                        "hrr": correct["hrr"], "keyUpdate": correct["keyUpdate"]})
    return reports


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=ROOT / "fixtures/manifest.json")
    parser.add_argument("--tshark", default="tshark")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        version = tool_version(args.tshark)
        manifest_data = json.loads(args.manifest.read_text(encoding="utf-8"))
        if manifest_data.get("suiteVersion") == "tls-golden-v1":
            require(re.search(r"(?<![\d.])3\.6\.0(?![\d.])", version) is not None,
                    "Release reference tshark must match pinned 3.6.0; review a new suite revision before changing it")
        fixtures = check_manifest(args.manifest.resolve(), args.tshark)
        report = {"schemaVersion": 1, "referenceTshark": version,
                  "environment": {"os": platform.platform(), "python": platform.python_version(),
                                  "abi": platform.machine()},
                  "summary": {"total": len(fixtures), "passed": len(fixtures), "failed": 0, "skipped": 0},
                  "comparison": {"referenceActual": version, "referencePinned": "3.6.0",
                                 "embeddedPinned": "4.0.10", "embeddedStatus": "NOT_RUN",
                                 "differences": "Requires independent Android suite report; desktop success is not embedded success"},
                  "fixtures": fixtures}
        encoded = json.dumps(report, indent=2) + "\n"
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(encoded, encoding="utf-8")
        print(encoded, end="")
        return 0
    except ValidationError:
        print("Fixture check failed: manifest schema validation failed", file=sys.stderr)
        return 1
    except (ValueError, KeyError, OSError, subprocess.SubprocessError, ET.ParseError) as error:
        print(f"Fixture check failed: {type(error).__name__}: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
