#!/usr/bin/env python3
"""Generate an AMR-NB / AMR-WB RTP fixture (RTP4-QA-01).

The public Wireshark sample captures contain no usable AMR RTP capture: the two
`Mobile-*-Call(AMR).pcap` files are Iu-CS over IP captures whose RTP payload is
an IuUP frame, not an AMR frame, so they cannot be decoded without an IuUP
de-framer. The card therefore allows generating the AMR RTP streams, and this
script is the recorded generator.

Input is an AMR storage-format bitstream (`#!AMR\\n` for AMR-NB, `#!AMR-WB\\n`
for AMR-WB), which must come from an encoder that is independent of this
application -- in practice `ffmpeg`. The script only *re-packetizes* it:

  * every storage frame (ToC octet + payload octets) becomes one RTP packet;
  * the RTP payload is written **octet-aligned** per RFC 4867 section 4.4.1
    (CMR octet with CMR=15 "no request", then ToC + payload);
  * one 20 ms frame per packet, so the RTP timestamp advances by 160 (AMR-NB)
    or 320 (AMR-WB) per packet;
  * a minimal SIP offer/answer carries the SDP that maps PT 97 to AMR or AMR-WB
    with `octet-align=1`, so the application discovers the codec the same way it
    discovers it in any other capture.

The inverse operation is used by `make_golden_m4.ps1` to rebuild the storage
bitstream from the fixture's extracted RTP payloads; the two files must be
byte-identical, and `--verify-roundtrip` checks exactly that.

Nothing here is hand-written test data: the payload bits come from the encoder,
and the reference PCM comes from decoding that same bitstream with ffmpeg.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from pathlib import Path

PCAP_LINKTYPE_ETHERNET = 1
ETHERNET_HEADER_SIZE = 14
IPV4_HEADER_SIZE = 20
UDP_HEADER_SIZE = 8
RTP_HEADER_SIZE = 12

# RFC 4867 table 1 (AMR-NB) and table 2 (AMR-WB): frame size in bits per FT.
# Index 8..14 are the SID frame types of the two tables; 15 is NO_DATA.
AMR_NB_FRAME_BITS = [95, 103, 118, 134, 148, 159, 204, 244]
AMR_NB_SID_BITS = 39
AMR_WB_FRAME_BITS = [132, 177, 253, 285, 317, 365, 397, 461, 477]
AMR_WB_SID_BITS = 40

MAGIC_NB = b"#!AMR\n"
MAGIC_WB = b"#!AMR-WB\n"

SAMPLES_PER_FRAME_NB = 160  # 20 ms on AMR-NB's 8 kHz RTP clock
SAMPLES_PER_FRAME_WB = 320  # 20 ms on AMR-WB's 16 kHz RTP clock

# The generated capture uses RFC 5737 documentation addresses only.
CALLER_IP = "192.0.2.10"
CALLEE_IP = "192.0.2.20"
SIP_PORT = 5060
MEDIA_PORT = 40000
RTP_PAYLOAD_TYPE = 97


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for offset in range(0, len(data), 2):
        total += (data[offset] << 8) | data[offset + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def mac(octet: int) -> bytes:
    return bytes([0x02, 0x00, 0x5E, 0x00, 0x53, octet])


def udp_ipv4_packet(
    source_ip: str,
    destination_ip: str,
    source_port: int,
    destination_port: int,
    payload: bytes,
    identifier: int,
    source_mac_octet: int,
    destination_mac_octet: int,
) -> bytes:
    udp_length = UDP_HEADER_SIZE + len(payload)
    udp = struct.pack("!HHHH", source_port, destination_port, udp_length, 0) + payload

    source_bytes = bytes(int(part) for part in source_ip.split("."))
    destination_bytes = bytes(int(part) for part in destination_ip.split("."))
    pseudo = (
        source_bytes
        + destination_bytes
        + b"\x00"
        + bytes([17])
        + struct.pack("!H", udp_length)
    )
    udp_checksum = checksum(pseudo + udp) or 0xFFFF

    total_length = IPV4_HEADER_SIZE + udp_length
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        identifier & 0xFFFF,
        0,
        64,
        17,
        0,
        source_bytes,
        destination_bytes,
    )
    ip_checksum = checksum(header)
    header = header[:10] + struct.pack("!H", ip_checksum) + header[12:]

    ethernet = (
        mac(destination_mac_octet)
        + mac(source_mac_octet)
        + struct.pack("!H", 0x0800)
    )
    return (
        ethernet
        + header
        + struct.pack("!HHHH", source_port, destination_port, udp_length, udp_checksum)
        + payload
    )


def parse_storage_frames(data: bytes, wideband: bool) -> list[bytes]:
    """Split a storage-format bitstream into ``ToC + payload`` frames."""
    magic = MAGIC_WB if wideband else MAGIC_NB
    if not data.startswith(magic):
        raise ValueError(f"input does not start with {magic!r}")
    frames: list[bytes] = []
    offset = len(magic)
    speech_bits = AMR_WB_FRAME_BITS if wideband else AMR_NB_FRAME_BITS
    sid_bits = AMR_WB_SID_BITS if wideband else AMR_NB_SID_BITS
    while offset < len(data):
        toc = data[offset]
        if toc & 0x80:
            raise ValueError(f"ToC octet at offset {offset} has the padding bit set")
        frame_type = (toc >> 3) & 0x0F
        if frame_type < len(speech_bits):
            bits = speech_bits[frame_type]
        elif frame_type == 15:
            bits = 0
        else:
            bits = sid_bits
        length = 1 + (bits + 7) // 8
        if offset + length > len(data):
            raise ValueError(f"truncated frame at offset {offset}")
        frames.append(data[offset:offset + length])
        offset += length
    return frames


def octet_aligned_payload(frame: bytes) -> bytes:
    """RFC 4867 section 4.4.1: CMR octet (no request = 15), then ToC + payload."""
    return bytes([0xF0]) + frame


def build_sdp(address: str, port: int, codec: str, clock_rate: int) -> bytes:
    return (
        "v=0\r\n"
        f"o=- 1 1 IN IP4 {address}\r\n"
        "s=-\r\n"
        f"c=IN IP4 {address}\r\n"
        "t=0 0\r\n"
        f"m=audio {port} RTP/AVP {RTP_PAYLOAD_TYPE}\r\n"
        f"a=rtpmap:{RTP_PAYLOAD_TYPE} {codec}/{clock_rate}\r\n"
        f"a=fmtp:{RTP_PAYLOAD_TYPE} octet-align=1\r\n"
        "a=ptime:20\r\n"
    ).encode("ascii")


def build_sip_message(
    request_line: str,
    headers: list[tuple[str, str]],
    body: bytes,
) -> bytes:
    lines = [request_line]
    for name, value in headers:
        lines.append(f"{name}: {value}")
    lines.append(f"Content-Length: {len(body)}")
    head = "\r\n".join(lines) + "\r\n\r\n"
    return head.encode("ascii") + body


def write_pcap(path: Path, records: list[tuple[int, int, bytes]]) -> None:
    """``records`` is ``(seconds, microseconds, frame_bytes)`` in capture order."""
    out = bytearray()
    out += struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, PCAP_LINKTYPE_ETHERNET)
    for seconds, microseconds, frame in records:
        out += struct.pack("<IIII", seconds, microseconds, len(frame), len(frame))
        out += frame
    path.write_bytes(bytes(out))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path,
                        help="AMR storage-format bitstream (.amr / .awb)")
    parser.add_argument("--output", required=True, type=Path,
                        help="destination .pcap")
    parser.add_argument("--codec", required=True, choices=["amr", "amrwb"],
                        help="amr = AMR-NB/8000, amrwb = AMR-WB/16000")
    parser.add_argument("--ssrc", default="0x4C41594C",
                        help="RTP SSRC (hex or decimal, default 0x4C41594C)")
    parser.add_argument("--rtp-timestamp-base", type=int, default=1000)
    parser.add_argument("--first-frame-sequence", type=int, default=100)
    parser.add_argument("--start-seconds", type=int, default=1)
    parser.add_argument("--verify-roundtrip", action="store_true",
                        help="re-derive the storage bitstream from the packets "
                             "that were just written and require byte equality")
    args = parser.parse_args()

    wideband = args.codec == "amrwb"
    source = args.input.read_bytes()
    frames = parse_storage_frames(source, wideband)
    if not frames:
        raise SystemExit("input contains no frames")

    ssrc = int(str(args.ssrc), 0) & 0xFFFFFFFF
    codec_name = "AMR-WB" if wideband else "AMR"
    clock_rate = 16000 if wideband else 8000

    invitation = build_sip_message(
        f"INVITE sip:test@{CALLEE_IP}:{SIP_PORT} SIP/2.0",
        [
            ("Via", f"SIP/2.0/UDP {CALLER_IP}:{SIP_PORT};branch=z9hG4bK-1-1-0"),
            ("From", f"<sip:caller@{CALLER_IP}>;tag=1"),
            ("To", f"<sip:test@{CALLEE_IP}>"),
            ("Call-ID", "1-1@192.0.2.10"),
            ("CSeq", "1 INVITE"),
            ("Contact", f"<sip:caller@{CALLER_IP}:{SIP_PORT}>"),
            ("Max-Forwards", "70"),
            ("Content-Type", "application/sdp"),
        ],
        build_sdp(CALLER_IP, MEDIA_PORT, codec_name, clock_rate),
    )
    answer = build_sip_message(
        "SIP/2.0 200 OK",
        [
            ("Via", f"SIP/2.0/UDP {CALLER_IP}:{SIP_PORT};branch=z9hG4bK-1-1-0"),
            ("From", f"<sip:caller@{CALLER_IP}>;tag=1"),
            ("To", f"<sip:test@{CALLEE_IP}>;tag=2"),
            ("Call-ID", "1-1@192.0.2.10"),
            ("CSeq", "1 INVITE"),
            ("Contact", f"<sip:test@{CALLEE_IP}:{SIP_PORT}>"),
            ("Content-Type", "application/sdp"),
        ],
        build_sdp(CALLEE_IP, MEDIA_PORT, codec_name, clock_rate),
    )
    acknowledgement = build_sip_message(
        f"ACK sip:test@{CALLEE_IP}:{SIP_PORT} SIP/2.0",
        [
            ("Via", f"SIP/2.0/UDP {CALLER_IP}:{SIP_PORT};branch=z9hG4bK-1-1-0"),
            ("From", f"<sip:caller@{CALLER_IP}>;tag=1"),
            ("To", f"<sip:test@{CALLEE_IP}>;tag=2"),
            ("Call-ID", "1-1@192.0.2.10"),
            ("CSeq", "1 ACK"),
            ("Max-Forwards", "70"),
        ],
        b"",
    )
    teardown = build_sip_message(
        f"BYE sip:caller@{CALLER_IP}:{SIP_PORT} SIP/2.0",
        [
            ("Via", f"SIP/2.0/UDP {CALLEE_IP}:{SIP_PORT};branch=z9hG4bK-1-2-0"),
            ("From", f"<sip:test@{CALLEE_IP}>;tag=2"),
            ("To", f"<sip:caller@{CALLER_IP}>;tag=1"),
            ("Call-ID", "1-1@192.0.2.10"),
            ("CSeq", "2 BYE"),
            ("Max-Forwards", "70"),
        ],
        b"",
    )

    records: list[tuple[int, int, bytes]] = []
    identifier = 1

    def add(seconds: int, microseconds: int, frame: bytes) -> None:
        records.append((seconds, microseconds, frame))

    # Signalling: one call setup with an SDP offer/answer that maps the payload
    # type, then the media, then one BYE.
    add(args.start_seconds, 0, udp_ipv4_packet(
        CALLER_IP, CALLEE_IP, SIP_PORT, SIP_PORT, invitation, identifier, 0x10, 0x20))
    identifier += 1
    add(args.start_seconds, 10_000, udp_ipv4_packet(
        CALLEE_IP, CALLER_IP, SIP_PORT, SIP_PORT, answer, identifier, 0x20, 0x10))
    identifier += 1
    add(args.start_seconds, 20_000, udp_ipv4_packet(
        CALLER_IP, CALLEE_IP, SIP_PORT, SIP_PORT, acknowledgement, identifier, 0x10, 0x20))
    identifier += 1

    media_start_microseconds = args.start_seconds * 1_000_000 + 100_000
    samples_per_frame = SAMPLES_PER_FRAME_WB if wideband else SAMPLES_PER_FRAME_NB
    for index, frame in enumerate(frames):
        timestamp = (index * samples_per_frame) & 0xFFFFFFFF
        sequence = (args.first_frame_sequence + index) & 0xFFFF
        marker = 0x80 if index == 0 else 0x00
        header = struct.pack(
            "!BBHII",
            0x80,
            marker | RTP_PAYLOAD_TYPE,
            sequence,
            (args.rtp_timestamp_base + timestamp) & 0xFFFFFFFF,
            ssrc,
        )
        payload = octet_aligned_payload(frame)
        offset = media_start_microseconds + index * 20_000
        add(offset // 1_000_000, offset % 1_000_000,
            udp_ipv4_packet(CALLEE_IP, CALLER_IP, MEDIA_PORT, MEDIA_PORT,
                            header + payload, identifier, 0x20, 0x10))
        identifier += 1

    last = media_start_microseconds + len(frames) * 20_000 + 100_000
    add(last // 1_000_000, last % 1_000_000, udp_ipv4_packet(
        CALLEE_IP, CALLER_IP, SIP_PORT, SIP_PORT, teardown, identifier, 0x20, 0x10))

    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_pcap(args.output, records)

    if args.verify_roundtrip:
        rebuilt = bytearray(MAGIC_WB if wideband else MAGIC_NB)
        for frame in frames:
            rebuilt += frame
        if bytes(rebuilt) != source:
            raise SystemExit("round-trip failed: re-derived bitstream differs")
        print("round-trip: re-derived storage bitstream is byte-identical")

    digest = hashlib.sha256(args.output.read_bytes()).hexdigest().upper()
    print(f"frames: {len(frames)}")
    print(f"codec: {codec_name}/{clock_rate} octet-aligned, PT {RTP_PAYLOAD_TYPE}")
    print(f"output: {args.output}")
    print(f"sha256: {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
