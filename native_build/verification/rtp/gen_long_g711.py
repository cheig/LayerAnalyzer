#!/usr/bin/env python3
"""Generate a deterministic one-way G.711A RTP capture.

The output is a classic little-endian pcap with Ethernet + IPv4 + UDP + RTP v2.
Each packet carries 160 bytes (20 ms at 8 kHz) and has monotonically
increasing RTP sequence and timestamp fields.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
from pathlib import Path
from typing import BinaryIO


PCAP_GLOBAL_HEADER_SIZE = 24
PCAP_RECORD_HEADER_SIZE = 16
ETHERNET_HEADER_SIZE = 14
IPV4_HEADER_SIZE = 20
UDP_HEADER_SIZE = 8
RTP_HEADER_SIZE = 12
PACKET_INTERVAL_MS = 20
PACKET_INTERVAL_US = PACKET_INTERVAL_MS * 1_000
G711_PAYLOAD_BYTES = 160
PCAP_LINKTYPE_ETHERNET = 1
RTP_PAYLOAD_TYPE_PCMA = 8

DEFAULT_DURATION_SECONDS = 30 * 60
DEFAULT_OUTPUT = Path("build/verification/rtp/long_g711_30m.pcap")


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for offset in range(0, len(data), 2):
        total += (data[offset] << 8) | data[offset + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4_checksum(header_without_checksum: bytes) -> int:
    return checksum(header_without_checksum)


def build_udp_checksum(
    source_ip: bytes,
    destination_ip: bytes,
    udp_datagram: bytes,
) -> int:
    pseudo_header = (
        source_ip
        + destination_ip
        + b"\x00"
        + bytes([17])
        + struct.pack("!H", len(udp_datagram))
    )
    value = checksum(pseudo_header + udp_datagram)
    return value or 0xFFFF


def build_packet(
    packet_index: int,
    first_rtp_sequence: int,
    first_rtp_timestamp: int,
) -> bytes:
    payload = bytes((packet_index + index * 17) & 0xFF
                    for index in range(G711_PAYLOAD_BYTES))

    rtp_sequence = (first_rtp_sequence + packet_index) & 0xFFFF
    rtp_timestamp = (
        first_rtp_timestamp + packet_index * G711_PAYLOAD_BYTES
    ) & 0xFFFFFFFF
    rtp = struct.pack(
        "!BBHII",
        0x80,
        RTP_PAYLOAD_TYPE_PCMA,
        rtp_sequence,
        rtp_timestamp,
        0x1A2B3C4D,
    ) + payload

    source_port = 4000
    destination_port = 5000
    udp_length = UDP_HEADER_SIZE + len(rtp)
    udp_without_checksum = struct.pack(
        "!HHHH",
        source_port,
        destination_port,
        udp_length,
        0,
    ) + rtp

    source_ip = bytes((192, 0, 2, 1))
    destination_ip = bytes((198, 51, 100, 2))
    udp_checksum = build_udp_checksum(
        source_ip,
        destination_ip,
        udp_without_checksum,
    )
    udp = struct.pack(
        "!HHHH",
        source_port,
        destination_port,
        udp_length,
        udp_checksum,
    ) + rtp

    total_length = IPV4_HEADER_SIZE + len(udp)
    ipv4_without_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        packet_index & 0xFFFF,
        0,
        64,
        17,
        0,
        source_ip,
        destination_ip,
    )
    ipv4 = (
        ipv4_without_checksum[:10]
        + struct.pack("!H", ipv4_checksum(ipv4_without_checksum))
        + ipv4_without_checksum[12:]
    )

    ethernet = (
        bytes.fromhex("020000000002")
        + bytes.fromhex("020000000001")
        + b"\x08\x00"
    )
    return ethernet + ipv4 + udp


def write_capture(
    output: BinaryIO,
    packet_count: int,
    start_epoch_seconds: int,
    first_rtp_sequence: int,
    first_rtp_timestamp: int,
) -> None:
    output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535,
                             PCAP_LINKTYPE_ETHERNET))
    for packet_index in range(packet_count):
        packet = build_packet(
            packet_index,
            first_rtp_sequence,
            first_rtp_timestamp,
        )
        elapsed_us = packet_index * PACKET_INTERVAL_US
        seconds, microseconds = divmod(elapsed_us, 1_000_000)
        output.write(
            struct.pack(
                "<IIII",
                start_epoch_seconds + seconds,
                microseconds,
                len(packet),
                len(packet),
            )
        )
        output.write(packet)


def verify_capture(
    path: Path,
    expected_packets: int,
    start_epoch_seconds: int,
    first_rtp_sequence: int,
    first_rtp_timestamp: int,
) -> None:
    expected_size = (
        PCAP_GLOBAL_HEADER_SIZE
        + expected_packets
        * (
            PCAP_RECORD_HEADER_SIZE
            + ETHERNET_HEADER_SIZE
            + IPV4_HEADER_SIZE
            + UDP_HEADER_SIZE
            + RTP_HEADER_SIZE
            + G711_PAYLOAD_BYTES
        )
    )
    actual_size = path.stat().st_size
    if actual_size != expected_size:
        raise RuntimeError(
            f"file size mismatch: expected {expected_size}, got {actual_size}"
        )

    with path.open("rb") as source:
        global_header = source.read(PCAP_GLOBAL_HEADER_SIZE)
        if len(global_header) != PCAP_GLOBAL_HEADER_SIZE:
            raise RuntimeError("truncated pcap global header")
        magic, version_major, version_minor, _, _, snaplen, linktype = (
            struct.unpack("<IHHIIII", global_header)
        )
        if magic != 0xA1B2C3D4 or (version_major, version_minor) != (2, 4):
            raise RuntimeError("invalid classic pcap header")
        if snaplen != 65535 or linktype != PCAP_LINKTYPE_ETHERNET:
            raise RuntimeError("unexpected pcap snaplen or link type")

        for packet_index in range(expected_packets):
            record_header = source.read(PCAP_RECORD_HEADER_SIZE)
            if len(record_header) != PCAP_RECORD_HEADER_SIZE:
                raise RuntimeError(
                    f"truncated pcap record header at packet {packet_index}"
                )
            seconds, microseconds, captured_length, original_length = (
                struct.unpack("<IIII", record_header)
            )
            expected_elapsed_us = packet_index * PACKET_INTERVAL_US
            expected_seconds, expected_microseconds = divmod(
                expected_elapsed_us,
                1_000_000,
            )
            if (
                seconds != start_epoch_seconds + expected_seconds
                or microseconds != expected_microseconds
            ):
                raise RuntimeError(
                    f"timestamp mismatch at packet {packet_index}"
                )
            if captured_length != original_length:
                raise RuntimeError(
                    f"captured/original length mismatch at packet {packet_index}"
                )

            packet = source.read(captured_length)
            if len(packet) != captured_length:
                raise RuntimeError(f"truncated pcap packet {packet_index}")
            if packet[:ETHERNET_HEADER_SIZE] != (
                bytes.fromhex("020000000002")
                + bytes.fromhex("020000000001")
                + b"\x08\x00"
            ):
                raise RuntimeError(
                    f"invalid Ethernet header at packet {packet_index}"
                )

            ipv4_offset = ETHERNET_HEADER_SIZE
            if packet[ipv4_offset] != 0x45:
                raise RuntimeError(f"invalid IPv4 header at packet {packet_index}")
            if checksum(packet[ipv4_offset:ipv4_offset + IPV4_HEADER_SIZE]) != 0:
                raise RuntimeError(
                    f"invalid IPv4 checksum at packet {packet_index}"
                )

            udp_offset = ipv4_offset + IPV4_HEADER_SIZE
            udp_length = struct.unpack(
                "!H",
                packet[udp_offset + 4:udp_offset + 6],
            )[0]
            if udp_length != UDP_HEADER_SIZE + RTP_HEADER_SIZE + G711_PAYLOAD_BYTES:
                raise RuntimeError(f"invalid UDP length at packet {packet_index}")
            udp_datagram = packet[udp_offset:udp_offset + udp_length]
            source_ip = packet[ipv4_offset + 12:ipv4_offset + 16]
            destination_ip = packet[ipv4_offset + 16:ipv4_offset + 20]
            if checksum(
                source_ip
                + destination_ip
                + b"\x00"
                + bytes([17])
                + struct.pack("!H", udp_length)
                + udp_datagram
            ) != 0:
                raise RuntimeError(
                    f"invalid UDP checksum at packet {packet_index}"
                )

            rtp_offset = udp_offset + UDP_HEADER_SIZE
            if packet[rtp_offset] != 0x80:
                raise RuntimeError(
                    f"invalid RTP version at packet {packet_index}"
                )
            if packet[rtp_offset + 1] != RTP_PAYLOAD_TYPE_PCMA:
                raise RuntimeError(
                    f"invalid RTP payload type at packet {packet_index}"
                )
            rtp_sequence, rtp_timestamp = struct.unpack(
                "!HI",
                packet[rtp_offset + 2:rtp_offset + 8],
            )
            expected_sequence = (first_rtp_sequence + packet_index) & 0xFFFF
            expected_timestamp = (
                first_rtp_timestamp
                + packet_index * G711_PAYLOAD_BYTES
            ) & 0xFFFFFFFF
            if rtp_sequence != expected_sequence:
                raise RuntimeError(
                    f"RTP sequence mismatch at packet {packet_index}"
                )
            if rtp_timestamp != expected_timestamp:
                raise RuntimeError(
                    f"RTP timestamp mismatch at packet {packet_index}"
                )
            payload = packet[rtp_offset + RTP_HEADER_SIZE:]
            if len(payload) != G711_PAYLOAD_BYTES:
                raise RuntimeError(
                    f"payload length mismatch at packet {packet_index}"
                )
            expected_payload = bytes(
                (packet_index + index * 17) & 0xFF
                for index in range(G711_PAYLOAD_BYTES)
            )
            if payload != expected_payload:
                raise RuntimeError(
                    f"payload mismatch at packet {packet_index}"
                )

        if source.read(1):
            raise RuntimeError("unexpected bytes after the final pcap record")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate a standard Ethernet+IPv4+UDP+RTP v2 G.711A pcap."
        )
    )
    duration_group = parser.add_mutually_exclusive_group()
    duration_group.add_argument(
        "--packets",
        type=int,
        help="number of RTP packets (20 ms each)",
    )
    duration_group.add_argument(
        "--duration-seconds",
        type=float,
        help=(
            "capture duration in seconds; must be an exact multiple of 20 ms "
            f"(default: {DEFAULT_DURATION_SECONDS})"
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"output pcap path (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--start-epoch-seconds",
        type=int,
        default=1_700_000_000,
        help="pcap timestamp for packet 0",
    )
    parser.add_argument(
        "--first-rtp-sequence",
        type=int,
        default=1000,
        help="RTP sequence number for packet 0",
    )
    parser.add_argument(
        "--first-rtp-timestamp",
        type=int,
        default=0,
        help="RTP timestamp for packet 0",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="overwrite an existing output file",
    )
    return parser.parse_args()


def resolve_packet_count(arguments: argparse.Namespace) -> int:
    if arguments.packets is not None:
        if arguments.packets <= 0:
            raise ValueError("--packets must be positive")
        return arguments.packets

    duration_seconds = (
        arguments.duration_seconds
        if arguments.duration_seconds is not None
        else DEFAULT_DURATION_SECONDS
    )
    if duration_seconds <= 0:
        raise ValueError("--duration-seconds must be positive")
    packet_count = duration_seconds * 1000.0 / PACKET_INTERVAL_MS
    rounded_packet_count = round(packet_count)
    if abs(packet_count - rounded_packet_count) > 1e-9:
        raise ValueError(
            "--duration-seconds must be an exact multiple of 0.02 seconds"
        )
    return rounded_packet_count


def main() -> int:
    arguments = parse_arguments()
    try:
        packet_count = resolve_packet_count(arguments)
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    if arguments.first_rtp_sequence < 0 or arguments.first_rtp_sequence > 0xFFFF:
        print("error: --first-rtp-sequence must be between 0 and 65535",
              file=sys.stderr)
        return 2
    if arguments.first_rtp_timestamp < 0 or arguments.first_rtp_timestamp > 0xFFFFFFFF:
        print("error: --first-rtp-timestamp must be between 0 and 4294967295",
              file=sys.stderr)
        return 2

    output = arguments.output
    if output.exists() and not arguments.force:
        print(
            f"error: output already exists: {output} (use --force to overwrite)",
            file=sys.stderr,
        )
        return 2
    output.parent.mkdir(parents=True, exist_ok=True)

    temporary = output.with_name(output.name + ".tmp")
    try:
        with temporary.open("wb") as destination:
            write_capture(
                destination,
                packet_count,
                arguments.start_epoch_seconds,
                arguments.first_rtp_sequence,
                arguments.first_rtp_timestamp,
            )
        os.replace(temporary, output)
        verify_capture(
            output,
            packet_count,
            arguments.start_epoch_seconds,
            arguments.first_rtp_sequence,
            arguments.first_rtp_timestamp,
        )
    except Exception:
        temporary.unlink(missing_ok=True)
        raise

    result = {
        "path": str(output.resolve()),
        "packets": packet_count,
        "duration_seconds": packet_count * PACKET_INTERVAL_MS / 1000.0,
        "duration_ms": packet_count * PACKET_INTERVAL_MS,
        "packet_interval_ms": PACKET_INTERVAL_MS,
        "payload_bytes": G711_PAYLOAD_BYTES,
        "file_size_bytes": output.stat().st_size,
        "sha256": sha256_file(output),
        "first_rtp_sequence": arguments.first_rtp_sequence,
        "last_rtp_sequence": (
            arguments.first_rtp_sequence + packet_count - 1
        ) & 0xFFFF,
        "first_rtp_timestamp": arguments.first_rtp_timestamp,
        "last_rtp_timestamp": (
            arguments.first_rtp_timestamp
            + (packet_count - 1) * G711_PAYLOAD_BYTES
        ) & 0xFFFFFFFF,
        "verified": True,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
