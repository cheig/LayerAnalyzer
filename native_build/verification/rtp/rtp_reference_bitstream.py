#!/usr/bin/env python3
"""Turn a stream of extracted RTP payloads into the codec bitstream a reference
decoder can read (RTP4-QA-01).

`make_golden_m4.ps1` extracts one RTP stream's payloads with **tshark** (never
with this application) into a text file with one hex payload per line, then
calls this script to reassemble the container or bitstream that an independent
decoder understands:

  raw        concatenate the payloads (G.722, G.726, G.729 -- one RTP packet is
             exactly one codec frame, so the concatenation *is* the bitstream)
  ilbc       the same, behind the iLBC storage header ffmpeg's demuxer wants
  amr        octet-aligned AMR (RFC 4867 section 4.4.1) back to storage format:
             drop the CMR octet of every packet, keep ToC + payload, prepend
             `#!AMR\\n` / `#!AMR-WB\\n`
  ogg-opus   wrap each Opus packet in an RFC 7845 Ogg page
  trim       cut a little-endian 16-bit PCM stream down to N samples

Only `amr` and `ogg-opus` do more than byte copying, and both are recorded
derivations rather than decoders: the audio in the reference always comes from
ffmpeg, never from anything in this repository. For AMR the derivation is
exactly invertible, which is why `gen_amr_rtp_fixture.py --verify-roundtrip`
can and does require byte equality against the encoder's own output.
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

AMR_NB_FRAME_BITS = [95, 103, 118, 134, 148, 159, 204, 244]
AMR_NB_SID_BITS = 39
AMR_WB_FRAME_BITS = [132, 177, 253, 285, 317, 365, 397, 461, 477]
AMR_WB_SID_BITS = 40

OGG_SERIAL = 0x4C41594C
# The reference is the *RTP* payload stream decoded from its first sample, so it
# carries no Opus pre-skip: RFC 7587 sends the stream from sample 0 with the RTP
# timestamp naming the position, and an RTP player does not trim a lookahead the
# sender already accounted for. `--pre-skip 312` reproduces the other
# convention (an Ogg file that compensates the encoder's lookahead); the 312
# sample difference between the two is recorded in CONTRIBUTING.md.
OGG_PRE_SKIP = 0
OPUS_OUTPUT_RATE = 48000


def read_payloads(path: Path) -> list[bytes]:
    """One hex payload per line, as `tshark -T fields -e rtp.payload` prints them."""
    payloads: list[bytes] = []
    for line in path.read_text(encoding="ascii").splitlines():
        line = line.strip()
        if not line:
            continue
        if len(line) % 2:
            raise ValueError(f"odd-length hex payload: {line!r}")
        payloads.append(bytes.fromhex(line))
    if not payloads:
        raise ValueError(f"no payloads in {path}")
    return payloads


def amr_frame_length(toc: int, wideband: bool) -> int:
    frame_type = (toc >> 3) & 0x0F
    table = AMR_WB_FRAME_BITS if wideband else AMR_NB_FRAME_BITS
    if frame_type < len(table):
        bits = table[frame_type]
    elif frame_type == 15:
        bits = 0
    else:
        bits = AMR_WB_SID_BITS if wideband else AMR_NB_SID_BITS
    return 1 + (bits + 7) // 8


def amr_storage_bitstream(payloads: list[bytes], wideband: bool) -> bytes:
    """RFC 4867 section 4.4.1 octet-aligned -> storage format."""
    out = bytearray(b"#!AMR-WB\n" if wideband else b"#!AMR\n")
    for payload in payloads:
        if len(payload) < 2:
            raise ValueError("octet-aligned payload is shorter than CMR + ToC")
        # payload[0] is the CMR octet; the frames start at payload[1].
        offset = 1
        while offset < len(payload):
            toc = payload[offset]
            if toc & 0x80:
                raise ValueError("ToC octet has the padding bit set")
            length = amr_frame_length(toc, wideband)
            if offset + length > len(payload):
                raise ValueError("truncated AMR frame in an octet-aligned payload")
            out += payload[offset:offset + length]
            offset += length
    return bytes(out)


def opus_packet_samples(packet: bytes) -> int:
    """RFC 6716 section 3.1: the packet's duration in 48 kHz samples."""
    if not packet:
        raise ValueError("empty Opus packet")
    toc = packet[0]
    config = toc >> 3
    frame_count_code = toc & 0x03
    if config < 12:
        frame_samples = (480, 960, 1920, 2880)[config % 4]
    elif config < 16:
        frame_samples = 480 if config % 2 == 0 else 960
    else:
        frame_samples = (120, 240, 480, 960)[config % 4]
    if frame_count_code == 0:
        frames = 1
    elif frame_count_code in (1, 2):
        frames = 2
    else:
        if len(packet) < 2:
            raise ValueError("Opus packet is too short for its frame count")
        frames = packet[1] & 0x3F
    return frame_samples * frames


def ogg_crc32(data: bytes) -> int:
    """The Ogg CRC: polynomial 0x04C11DB7, not reflected, no init, no final xor."""
    crc = 0
    for byte in data:
        crc ^= byte << 24
        for _ in range(8):
            crc = ((crc << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if crc & 0x80000000 \
                else (crc << 1) & 0xFFFFFFFF
    return crc


def ogg_page(header_type: int, granule: int, sequence: int, packet: bytes) -> bytes:
    segments = bytearray()
    remaining = len(packet)
    while remaining >= 255:
        segments.append(255)
        remaining -= 255
    segments.append(remaining)
    header = bytearray()
    header += b"OggS"
    header += bytes([0, header_type])
    header += struct.pack("<q", granule)
    header += struct.pack("<I", OGG_SERIAL)
    header += struct.pack("<I", sequence)
    header += b"\x00\x00\x00\x00"  # CRC placeholder
    header += bytes([len(segments)])
    header += bytes(segments)
    page = bytes(header) + packet
    crc = ogg_crc32(page)
    return page[:22] + struct.pack("<I", crc) + page[26:]


def opus_head(channels: int, pre_skip: int) -> bytes:
    return (
        b"OpusHead"
        + bytes([1, channels])
        + struct.pack("<H", pre_skip)
        + struct.pack("<I", OPUS_OUTPUT_RATE)
        + struct.pack("<h", 0)
        + bytes([0])
    )


def ogg_opus_bitstream(payloads: list[bytes], pre_skip: int = OGG_PRE_SKIP) -> bytes:
    vendor = b"LayerAnalyzer-RTP4-QA-01-reference"
    tags = b"OpusTags" + struct.pack("<I", len(vendor)) + vendor + struct.pack("<I", 0)
    out = bytearray()
    out += ogg_page(0x02, 0, 0, opus_head(1, pre_skip))
    out += ogg_page(0x00, 0, 1, tags)
    granule = pre_skip
    for index, payload in enumerate(payloads):
        granule += opus_packet_samples(payload)
        out += ogg_page(0x00, granule, 2 + index, payload)
    return bytes(out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    for name in ("raw", "ilbc", "amr", "ogg-opus"):
        sub = subparsers.add_parser(name)
        sub.add_argument("--hex", required=True, type=Path)
        sub.add_argument("--output", required=True, type=Path)
        if name == "amr":
            sub.add_argument("--wideband", action="store_true")
        if name == "ogg-opus":
            sub.add_argument("--pre-skip", type=int, default=OGG_PRE_SKIP,
                             help="OpusHead pre-skip; see OGG_PRE_SKIP (default 0)")

    trim = subparsers.add_parser("trim")
    trim.add_argument("--input", required=True, type=Path)
    trim.add_argument("--output", required=True, type=Path)
    trim.add_argument("--samples", required=True, type=int)

    args = parser.parse_args()

    if args.command == "trim":
        data = args.input.read_bytes()
        wanted = args.samples * 2
        if len(data) < wanted:
            raise SystemExit(
                f"{args.input} holds {len(data) // 2} samples, fewer than {args.samples}"
            )
        args.output.write_bytes(data[:wanted])
        print(f"trim: {args.samples} samples -> {args.output}")
        return 0

    payloads = read_payloads(args.hex)
    if args.command == "raw":
        data = b"".join(payloads)
    elif args.command == "ilbc":
        data = b"#!iLBC30\n" + b"".join(payloads)
    elif args.command == "amr":
        data = amr_storage_bitstream(payloads, args.wideband)
    else:
        data = ogg_opus_bitstream(payloads, args.pre_skip)

    args.output.write_bytes(data)
    print(f"{args.command}: {len(payloads)} packets -> {len(data)} bytes at {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
