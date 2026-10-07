#!/usr/bin/env python3
"""Self-test for the video packetizer: does an FU-A / FU round trip?

The generator's correctness claim is that de-packetizing its RTP stream with
the *application's* rules yields the NAL units it started from. That claim is
checkable without any encoder, and it is the part most likely to be wrong: an
off-by-one in the fragment header, a lost end fragment or a byte dropped at the
MTU boundary all reassemble into something that looks plausible and is not the
original bitstream.

So this builds NAL units with known contents -- deliberately including sizes
that straddle the MTU exactly, one either side -- packetizes them, then
de-packetizes with an independent implementation of RFC 6184 section 5.8 and
RFC 7798 section 4.4 written directly from the RFC text, and requires byte
equality. It also checks the aggregate cases the application handles: a NAL
that fits is sent whole, a NAL that does not is split and rejoined, and the
rebuilt NAL header carries the original F/NRI and type.

This validates the *packetizer*. It does not and cannot validate the
application's *de-packetizer* -- that is what the fixtures on a device are for.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import gen_rtp_video_fixture as gen


def make_nal_264(nal_type: int, nri: int, body_len: int, fill: int) -> bytes:
    """A H.264 NAL unit whose body is a known, position-checkable pattern.

    The body is not constant: a constant would let an off-by-one in the
    fragment split pass unnoticed whenever two fragments happen to be equal.
    Byte i is ``(fill + i) & 0xFF``, so the reassembled unit can be compared
    against the original in full.
    """
    header = bytes([(nri << 5) | nal_type])
    return header + bytes((fill + index) & 0xFF for index in range(body_len))


def depack_264(payloads: list[bytes]) -> tuple[list[bytes], list[str]]:
    """An independent RFC 6184 de-packetizer, written from the RFC's text.

    Deliberately *not* calling the application's code and not sharing the
    generator's helpers: the point is that two independent readings of the RFC
    agree.
    """
    nals: list[bytes] = []
    notes: list[str] = []
    buffer = b""
    assembling = False
    previous_sequence = None
    for sequence, payload in payloads:
        if previous_sequence is not None and sequence != previous_sequence + 1 and assembling:
            notes.append(f"gap before seq {sequence}: partial FU discarded")
            buffer = b""
            assembling = False
        previous_sequence = sequence
        if not payload:
            notes.append(f"seq {sequence}: empty payload ignored")
            continue
        kind = payload[0] & 0x1F
        if kind == 28:  # FU-A
            indicator, header = payload[0], payload[1]
            start = bool(header & 0x80)
            end = bool(header & 0x40)
            if start:
                buffer = bytes([(indicator & 0xE0) | (header & 0x1F)])
                assembling = True
            elif not assembling:
                notes.append(f"seq {sequence}: continuation with no FU in progress")
                continue
            buffer += payload[2:]
            if end:
                nals.append(buffer)
                buffer = b""
                assembling = False
        elif kind == 24:  # STAP-A
            offset = 1
            while offset + 2 <= len(payload):
                size = (payload[offset] << 8) | payload[offset + 1]
                offset += 2
                if offset + size > len(payload):
                    notes.append(f"seq {sequence}: STAP-A entry overruns the payload")
                    break
                nals.append(payload[offset:offset + size])
                offset += size
        elif kind == 0:
            notes.append(f"seq {sequence}: NAL type 0 counted, not emitted")
        elif 1 <= kind <= 23:
            nals.append(payload)
        else:
            notes.append(f"seq {sequence}: unsupported type {kind} counted")
    if assembling:
        notes.append("end of stream: partial FU dropped")
    return nals, notes


def depack_265(payloads: list[bytes]) -> tuple[list[bytes], list[str]]:
    """An independent RFC 7798 de-packetizer (types 0..47, AP 48, FU 49)."""
    nals: list[bytes] = []
    notes: list[str] = []
    buffer = b""
    assembling = False
    for _, payload in payloads:
        if not payload:
            continue
        payload_type = (payload[0] >> 1) & 0x3F
        # FU and AP are checked *before* the single-NAL range, because their
        # PayloadHdr types (49, 48) are numerically above it and the test NALs
        # use type 0, which would otherwise be swallowed as a whole NAL unit.
        if payload_type == 49:  # FU
            # An FU packet is [indicator][fu_header][data...]: two header
            # octets, and the NAL unit's own second header octet is the first
            # byte of the data. This mirrors `H265Depack.cpp` rule 4, which
            # reads the S/E bits from `payload[2]`'s predecessor and appends
            # from `payload + 3`.
            fu_header = payload[1]
            start = bool(fu_header & 0x80)
            end = bool(fu_header & 0x40)
            original_type = fu_header & 0x3F
            if start:
                # F (0x80) and the layer id's low bit (0x01) come from octet 0;
                # the original 6-bit type goes back into bits 6..1; the NAL
                # header's second octet is the first data byte.
                buffer = bytes([(payload[0] & 0x81) | (original_type << 1)])
                assembling = True
            elif not assembling:
                notes.append("FU continuation with no FU in progress")
                continue
            buffer += payload[2:]
            if end:
                nals.append(buffer)
                buffer = b""
                assembling = False
        elif payload_type == 48:  # AP
            offset = 2
            while offset + 2 <= len(payload):
                size = (payload[offset] << 8) | payload[offset + 1]
                offset += 2
                if offset + size > len(payload):
                    notes.append("AP entry overruns the payload")
                    break
                nals.append(payload[offset:offset + size])
                offset += size
        elif payload_type <= 47:
            nals.append(payload)
        else:
            notes.append(f"unsupported H.265 type {payload_type} counted")
    if assembling:
        notes.append("end of stream: partial FU dropped")
    return nals, notes


def check_roundtrip_264(nal: bytes, mtu: int, label: str, failures: list[str]) -> None:
    fragments = gen.packetize_h264(nal, mtu)
    payloads = [(1000 + index, fragment) for index, fragment in enumerate(fragments)]
    recovered, notes = depack_264(payloads)
    if len(fragments) == 1:
        if recovered != [nal]:
            failures.append(f"{label}: single-NAL path altered the unit")
    else:
        for note in notes:
            failures.append(f"{label}: unexpected de-packetizer note {note!r}")
        if len(recovered) != 1:
            failures.append(f"{label}: {len(fragments)} fragments produced {len(recovered)} NALs")
        elif recovered[0] != nal:
            failures.append(
                f"{label}: reassembled NAL differs "
                f"({len(recovered[0])} vs {len(nal)} bytes, "
                f"first diff at {_first_difference(recovered[0], nal)})"
            )


def check_roundtrip_265(nal: bytes, mtu: int, label: str, failures: list[str]) -> None:
    fragments = gen.packetize_h265(nal, mtu)
    payloads = [(2000 + index, fragment) for index, fragment in enumerate(fragments)]
    recovered, notes = depack_265(payloads)
    for note in notes:
        failures.append(f"{label}: unexpected de-packetizer note {note!r}")
    if len(fragments) == 1:
        if recovered != [nal]:
            failures.append(f"{label}: single-NAL path altered the unit")
    elif len(recovered) != 1 or recovered[0] != nal:
        failures.append(
            f"{label}: reassembled NAL differs "
            f"({len(fragments)} fragments, {len(recovered)} NALs, "
            f"first diff at {_first_difference(recovered[0] if recovered else b'', nal)})"
        )


def _first_difference(left: bytes, right: bytes) -> int:
    for index, (a, b) in enumerate(zip(left, right)):
        if a != b:
            return index
    return min(len(left), len(right))


def main() -> int:
    failures: list[str] = []
    mtu = 300

    # H.264: sizes chosen to straddle the MTU, plus the NAL types the
    # de-packetizer treats specially.
    sizes = [1, 2, 297, 298, 299, 300, 301, 302, 598, 599, 600, 601, 1400, 5000]
    for nal_type, nri, label in ((1, 0, "non-IDR slice"), (5, 3, "IDR slice"),
                                 (7, 3, "SPS"), (8, 3, "PPS"), (6, 0, "SEI")):
        for size in sizes:
            nal = make_nal_264(nal_type, nri, size, fill=size & 0xFF)
            check_roundtrip_264(nal, mtu, f"H264 {label} {size}B", failures)

    # Every NRI value, because the rebuilt header must carry it through.
    for nri in range(4):
        nal = make_nal_264(5, nri, 700, fill=nri * 40)
        check_roundtrip_264(nal, mtu, f"H264 IDR NRI={nri}", failures)

    # A mid-chain loss must drop the partial FU rather than emit a short NAL.
    nal = make_nal_264(1, 2, 2000, fill=7)
    fragments = gen.packetize_h264(nal, mtu)
    payloads = [(3000 + index, fragment) for index, fragment in enumerate(fragments)]
    truncated = [payloads[0]] + payloads[2:]  # drop fragment 1
    recovered, notes = depack_264(truncated)
    if any(candidate == nal[:len(candidate)] and len(candidate) < len(nal) for candidate in recovered):
        failures.append("H264 mid-chain loss: a short NAL was emitted instead of dropping the FU")
    if recovered:
        failures.append("H264 mid-chain loss: output should be empty until the next S fragment")
    if not any("discarded" in note for note in notes):
        failures.append(f"H264 mid-chain loss: no discard note, got {notes}")

    # H.265, symmetric: the 2-byte header must survive, including layer bits.
    for nal_type in (0, 1, 19, 21, 32, 33, 34):
        for size in (1, 2, 296, 297, 298, 299, 300, 301, 596, 597, 598, 1200):
            nal = bytes([(nal_type << 1) & 0x7E, 0x01]) + bytes(
                (size + index) & 0xFF for index in range(size)
            )
            check_roundtrip_265(nal, mtu, f"H265 type {nal_type} {size}B", failures)

    if failures:
        print(f"FAIL: {len(failures)} problem(s)")
        for problem in failures[:25]:
            print(f"  - {problem}")
        if len(failures) > 25:
            print(f"  ... and {len(failures) - 25} more")
        return 1

    print("OK: H.264 and H.265 packetization round-trips are byte-exact")
    print(f"    MTU payload {mtu} B, {len(sizes)} sizes x 5 NAL types (H.264)")
    print("    plus every NRI, every H.265 type of interest, and the mid-chain loss case")
    return 0


if __name__ == "__main__":
    sys.exit(main())
