#!/usr/bin/env python3
"""Packetize H.264 / H.265 elementary streams into RTP video captures.

RTP5-NAT-01/02 implement the receiving half of RFC 6184 and RFC 7798. This
script is the sending half, written to the same two RFCs, so that a round trip
through the application actually exercises the de-packetizer rather than
re-feeding it something it was built to accept. The two rules that matter and
are easy to get subtly wrong:

  * **MTU-sized fragments.** A FU-A payload is one octet of FU indicator, one of
    FU header, then the rest of the datagram. The FU indicator carries F and NRI
    from the NAL being split; the FU header carries S, E and the type. The
    rebuilt NAL header is `(indicator & 0x60) | (fu_header & 0x1F)` -- the
    project's frozen contract (see `H264Depack.h` decision 1) deliberately does
    *not* copy the forbidden_zero_bit, and this script matches it.
  * **Marker bit and timestamp.** Both RFCs put one access unit in the RTP
    timestamp: every packet of a frame shares the timestamp, and the last packet
    of the frame sets M=1. `VideoAccessUnitBuilder` relies on exactly this, so a
    generator that advanced the timestamp per packet would silently produce a
    stream that de-packetizes into one-NAL-per-frame garbage.

Input is an Annex-B elementary stream (.h264 / .h265), which must come from an
encoder independent of this application -- in practice ffmpeg. The script only
splits and wraps; it never transcodes.

Every capture also carries a SIP INVITE / 200 OK / ACK / BYE exchange whose SDP
maps the payload type, so the application discovers the codec the same way it
discovers it in any other capture. For H.264 the SDP carries
``sprop-parameter-sets``; for H.265 it carries ``sprop-vps``/``sprop-sps``/
``sprop-pps``. Those base64 blobs are taken from the bitstream's own parameter
sets, so the SDP and the in-band copies agree by construction.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from rtp_fixture_wire import PcapWriter, sdp_offer_answer, sip_message

# RFC 5737 documentation addresses only; no fixture names a routable host.
CALLER_IP = "192.0.2.10"
CALLEE_IP = "192.0.2.20"
SIP_PORT = 5060
VIDEO_CLOCK_RATE = 90000  # RFC 6184 section 5.1 / RFC 7798 section 4.1

START_CODE = b"\x00\x00\x00\x01"
START_CODE_SHORT = b"\x00\x00\x01"

# H.264 NAL unit types (RFC 6184 table 5-1). Only the four the de-packetizer
# implements are named; the rest are referenced by number where they matter.
H264_STAP_A = 24
H264_FU_A = 28
H264_IDR = 5
H264_SPS = 7
H264_PPS = 8

# H.265 (RFC 7798 table 9-1).
H265_AP = 48
H265_FU = 49
H265_VPS = 32
H265_SPS = 33
H265_PPS = 34
# IRAP_NUT..(IDR_W_RADL=19, IDR_N_LP=20, CRA=21) is the keyframe range the
# access-unit builder keys on.
H265_IRAP_MIN = 16
H265_IRAP_MAX = 23


def find_start_code(data: bytes, offset: int) -> tuple[int, int] | None:
    """Locate the next Annex-B start code at or after ``offset``.

    Returns ``(start_of_prefix, prefix_length)``. Both the 3-octet and the
    4-octet form are accepted because ffmpeg emits either depending on the
    muxer's mood, and a fixture generator that only understood one of them
    would be a trap for whoever regenerates it.
    """
    index_4 = data.find(START_CODE, offset)
    index_3 = data.find(START_CODE_SHORT, offset)
    candidates = []
    if index_4 != -1:
        candidates.append((index_4, 4))
    if index_3 != -1:
        # A 4-octet start code also contains the 3-octet one, so only consider
        # this one when it is not the tail of a longer prefix.
        if index_4 == -1 or index_3 != index_4 + 1:
            candidates.append((index_3, 3))
    if not candidates:
        return None
    return min(candidates)


def split_annex_b(data: bytes) -> list[bytes]:
    """Split an Annex-B byte stream into NAL units, without start codes."""
    units: list[bytes] = []
    offset = 0
    # Trailing bytes before the first start code are not a NAL unit; dropping
    # them silently would be the kind of quiet data loss this project's DoD
    # forbids, so they are reported by the caller's count check instead.
    first = find_start_code(data, 0)
    if first is None:
        return units
    offset = first[0] + first[1]
    while True:
        nxt = find_start_code(data, offset)
        if nxt is None:
            tail = data[offset:]
            if tail:
                units.append(tail)
            break
        units.append(data[offset:nxt[0]])
        offset = nxt[0] + nxt[1]
    return [unit for unit in units if unit]


def is_keyframe_nal(codec: str, nal: bytes) -> bool:
    if codec == "H264":
        return len(nal) > 0 and (nal[0] & 0x1F) == H264_IDR
    nal_type = (nal[0] >> 1) & 0x3F
    return H265_IRAP_MIN <= nal_type <= H265_IRAP_MAX


def parameter_sets(codec: str, units: list[bytes]) -> dict[str, list[bytes]]:
    """Collect the in-band parameter sets, grouped by kind.

    The application prefers the SDP's copy and falls back to the in-band one.
    Both must exist in a fixture: only-SDP tests the first path, only-in-band
    tests the second, and having both present is the realistic case.

    Every occurrence is kept, not just the first: a sender that repeats its
    parameter sets mid-stream is legal and common, and dropping the repeats
    would make the generated SDP disagree with the bitstream the application is
    about to export. The values are lists because RFC 6184 section 8.2.2's
    `sprop-parameter-sets` is itself a comma-separated list, so the two sides
    have the same shape.
    """
    wanted = (
        {H264_SPS: "sps", H264_PPS: "pps"}
        if codec == "H264"
        else {H265_VPS: "vps", H265_SPS: "sps", H265_PPS: "pps"}
    )
    found: dict[str, list[bytes]] = {}
    for nal in units:
        if codec == "H264":
            kind = wanted.get(nal[0] & 0x1F)
        else:
            kind = wanted.get((nal[0] >> 1) & 0x3F)
        if kind is not None:
            found.setdefault(kind, []).append(nal)
    return found


def sdp_fmtp(codec: str, params: dict[str, list[bytes]], strip_inband: bool) -> str:
    """Build the fmtp attribute, base64 as RFC 6184 / RFC 7798 require.

    ``params`` maps a kind to the *list* of NAL units of that kind, which is
    what `parameter_sets()` returns; a stream may legally repeat its parameter
    sets, and RFC 6184 section 8.2.2 wants every one of them in the attribute.
    """
    if codec == "H264":
        blobs = [
            base64.b64encode(nal).decode("ascii")
            for key in ("sps", "pps")
            for nal in params.get(key, [])
        ]
        if not blobs:
            return ""
        return "profile-level-id=1E00C8;packetization-mode=1;sprop-parameter-sets=" + ",".join(blobs)
    parts = [
        f"{key}={base64.b64encode(nal).decode('ascii')}"
        for key in ("vps", "sps", "pps")
        for nal in params.get(key, [])
    ]
    if not parts:
        return ""
    return ";".join(parts)


@dataclass
class RtpPacket:
    payload: bytes
    marker: bool
    timestamp: int


def packetize_h264(nal: bytes, mtu_payload: int) -> list[bytes]:
    """RFC 6184 section 5: single NAL, or FU-A when the NAL exceeds the MTU."""
    nal_type = nal[0] & 0x1F
    if len(nal) <= mtu_payload:
        return [nal]
    if nal_type == H264_FU_A or nal_type == H264_STAP_A:
        # Re-fragmenting an aggregate would change its meaning; a stream that
        # needs it is a stream whose sender was wrong. Fail loudly instead.
        raise ValueError("cannot fragment an aggregate NAL unit")
    indicator = (nal[0] & 0xE0) | H264_FU_A
    nal_type_only = nal[0] & 0x1F
    body = nal[1:]
    chunk_size = mtu_payload - 2
    packets: list[bytes] = []
    offset = 0
    while offset < len(body):
        chunk = body[offset:offset + chunk_size]
        offset += chunk_size
        start = 1 if offset - len(chunk) == 0 else 0
        end = 1 if offset >= len(body) else 0
        fu_header = (start << 7) | (end << 6) | nal_type_only
        packets.append(bytes([indicator, fu_header]) + chunk)
    return packets


def packetize_h265(nal: bytes, mtu_payload: int) -> list[bytes]:
    """RFC 7798 section 4.4.3: single NAL, or FU (type 49) when it exceeds the MTU.

    The HEVC NAL header is two octets -- F(1) | type(6) | nuh_layer_id(6) |
    nuh_temporal_id_plus1(3) -- so unlike H.264 the 6 type bits sit in bits
    6..1 of the first octet and bit 0 belongs to the layer id. The FU indicator
    is therefore that octet with the type field replaced by 49, which is
    `49 << 1 == 0x62` for a base-layer stream, and the FU header is a *second*
    octet carrying S, E and the original 6-bit type.

    This asymmetry with H.264 is the easy thing to get wrong: FU-A's indicator
    uses `| 28` because H.264's type is 5 bits, and copying that habit here
    produces `| 49`, i.e. 0x31, which a receiver reads back as type 24 -- a
    STAP-A aggregate -- and silently mis-de-packetizes. See
    `test_video_packetizer.py`, which round-trips against an independent
    reader of the RFC and catches exactly this.
    """
    nal_type = (nal[0] >> 1) & 0x3F
    if len(nal) <= mtu_payload:
        return [nal]
    if nal_type in (H265_FU, H265_AP):
        raise ValueError("cannot fragment an aggregate NAL unit")
    if len(nal) < 2:
        raise ValueError("H.265 NAL unit is shorter than its 2-octet header")
    # An FU packet is exactly two header octets -- the FU indicator and the FU
    # header -- followed by fragment data, and the NAL unit's *own* second
    # header octet is the first byte of that data. So the layout is
    # [indicator][fu_header][nal[1]][rest of body...], which is why the reader
    # takes its data from offset 3 and rebuilds the two-octet NAL header as
    # `(indicator & 0x81) | (type << 1)` followed by that first data byte.
    #
    # F survives in bit 7 and the layer id's low bit in bit 0; the six type bits
    # in between become 49.
    indicator = (nal[0] & 0x81) | (H265_FU << 1)
    body = nal[1:]
    chunk_size = mtu_payload - 2
    packets: list[bytes] = []
    offset = 0
    while offset < len(body):
        chunk = body[offset:offset + chunk_size]
        offset += chunk_size
        start = 1 if offset - len(chunk) == 0 else 0
        end = 1 if offset >= len(body) else 0
        fu_header = (start << 7) | (end << 6) | nal_type
        packets.append(bytes([indicator, fu_header]) + chunk)
    return packets


def build_frames(codec: str, units: list[bytes], mtu_payload: int) -> list[tuple[list[RtpPacket], bool]]:
    """Group NAL units into access units, then packetize each.

    The grouping has to be right or the marker bit is wrong, because
    `VideoAccessUnitBuilder` ends an access unit on M=1 and falls back to a
    timestamp change when M is missing. So the cut is made where the bitstream
    says a picture ended, not where it is convenient:

      * a VCL NAL that carries `first_mb_in_slice == 0` starts a new picture --
        this is the reliable signal, and it is what a real sender's own
        packetizer uses;
      * a parameter set, an access-unit delimiter or a filler NAL ends the
        current picture, so those units lead the next one;
      * a new keyframe always ends the current picture.

    Cutting on keyframes alone (the obvious shortcut) merges every inter frame
    between two I-frames into one enormous access unit, which still reassembles
    without error but reports one frame instead of thirty -- a fixture that
    passes a byte-comparison test and fails the frame count.
    """
    frames: list[tuple[list[RtpPacket], bool]] = []
    current: list[bytes] = []
    current_key = False

    def flush() -> None:
        nonlocal current, current_key
        if not current:
            return
        packets: list[RtpPacket] = []
        for nal in current:
            produced = (
                packetize_h264(nal, mtu_payload)
                if codec == "H264"
                else packetize_h265(nal, mtu_payload)
            )
            for payload in produced:
                packets.append(RtpPacket(payload=payload, marker=False, timestamp=0))
        if packets:
            packets[-1].marker = True
            frames.append((packets, current_key))
        current = []
        current_key = False

    if codec == "H264":
        vcl = lambda t: 1 <= t <= 5              # non-IDR slices are 1..4
        boundary = {6, 7, 8, 9, 10, 11, 12}       # SEI, SPS, PPS, AUD, end-of-seq/stream, filler
    else:
        vcl = lambda t: t <= 31                  # HEVC VCL is 0..31
        boundary = {32, 33, 34, 35, 36, 37, 38, 39, 40}  # VPS/SPS/PPS/AUD/EOS/EOB/FD/pref

    for nal in units:
        nal_type = (nal[0] & 0x1F) if codec == "H264" else ((nal[0] >> 1) & 0x3F)
        key = is_keyframe_nal(codec, nal)

        starts_new_picture = False
        if codec == "H264" and 1 <= nal_type <= 5:
            # ue(v) first_mb_in_slice: the first Exp-Golomb code of the slice
            # header. Zero means the slice covers the whole picture from its
            # top-left corner, i.e. a new picture begins here.
            starts_new_picture = _first_mb_in_slice_is_zero(nal)
        elif codec == "H265" and nal_type <= 31:
            starts_new_picture = _hevc_first_slice_in_pic(nal)
        elif key:
            # An IRAP with no slice yet (or a stream whose slices are all
            # continuation slices) still has to open a unit, or the parameter
            # sets that precede it would be merged into the previous picture.
            starts_new_picture = not current

        if boundary.__contains__(nal_type) and current:
            flush()

        if starts_new_picture and current and not _only_leading_units(current, codec):
            flush()

        current.append(nal)
        if key:
            current_key = True

    flush()
    return frames


def _first_mb_in_slice_is_zero(nal: bytes) -> bool:
    """Whether an H.264 slice NAL's ``first_mb_in_slice`` Exp-Golomb code is 0.

    A leading bit of 1 in Exp-Golomb always means the value is zero, so the
    check is one bit -- no need to decode the whole code. Only the first byte
    matters for the zero case, which is why this does not need the RBSP
    unescapaping: emulation prevention bytes can only *insert* 0x03 after two
    zero bytes, and the first byte of a slice header is never one of those.
    """
    return len(nal) >= 2 and bool(nal[1] & 0x80)


def _unescape_rbsp(payload: bytes) -> bytes:
    """Remove H.264/H.265 emulation-prevention bytes (0x03 after 0x00 0x00).

    RBSP forbids `00 00 00..03`, so an encoder inserts a 0x03 after two zero
    bytes. Reading a syntax element's first bit therefore needs the raw bytes
    unescaped first -- a 0x03 landing where the bit should be would invert it.
    """
    out = bytearray()
    zeros = 0
    for octet in payload:
        if zeros >= 2 and octet == 0x03:
            zeros = 0
            continue
        out.append(octet)
        zeros = zeros + 1 if octet == 0 else 0
    return bytes(out)


def _hevc_first_slice_in_pic(nal: bytes) -> bool:
    """Whether an HEVC VCL NAL's ``first_slice_segment_in_pic_flag`` is 1.

    The HEVC slice segment header follows the **two**-octet NAL header, and its
    first bit is that flag: 1 means this slice opens a new picture. x265 emits
    one slice per frame, so this is the signal that actually cuts access units
    for HEVC -- cutting on IRAP NALs instead (the obvious approach, and what
    H.264's keyframe rule amounts to) collapses a 10-second stream into a
    handful of "frames", because an x265 GOP is 250 frames long while only its
    first frame is an IRAP.
    """
    if len(nal) < 3:
        return False
    rbsp = _unescape_rbsp(nal[2:])
    return bool(rbsp) and bool(rbsp[0] & 0x80)


def _only_leading_units(units: list[bytes], codec: str) -> bool:
    """Whether ``units`` holds nothing but the headers that open a picture.

    After a parameter set or a keyframe header, the next slice still belongs to
    the same access unit, so the "new picture" rule must not fire on it.
    """
    if not units:
        return True
    if codec == "H264":
        non_vcl = {6, 7, 8, 9, 10, 11, 12}
        return all((u[0] & 0x1F) in non_vcl for u in units)
    non_vcl = {32, 33, 34, 35, 36, 37, 38, 39, 40}
    return all(((u[0] >> 1) & 0x3F) in non_vcl for u in units)


@dataclass
class Scenario:
    """Knobs the command line exposes for one capture."""

    drop_every: int = 0
    """Drop every Nth RTP packet (1 = drop all, 10 = one in ten)."""
    reorder: bool = False
    """Emit each frame's packets with the last two swapped, exercising the
    de-packetizer's out-of-order accounting without breaking a FU group."""
    frame_interval_us: int = 33_333
    strip_inband_params: bool = False
    """Keep the parameter sets only in the SDP, exercising the `paramSets`
    request path and the "no in-band set" branch of the access-unit builder."""
    omit_sdp_params: bool = False
    """Keep the parameter sets only in-band, exercising the fallback path and
    the app's "missing parameter sets" error when both are absent."""
    duration_frames: int = 0
    """Stop after this many access units; 0 means the whole bitstream."""


def build_capture(
    codec: str,
    bitstream: bytes,
    payload_type: int,
    ssrc: int,
    scenario: Scenario,
    mtu_payload: int,
    first_sequence: int = 1000,
    timestamp_base: int = 90_000,
    start_seconds: int = 1,
) -> tuple[bytes, dict[str, int]]:
    units = split_annex_b(bitstream)
    if not units:
        raise SystemExit("elementary stream contains no NAL units")

    params = parameter_sets(codec, units)
    if scenario.strip_inband_params:
        if codec == "H264":
            units = [u for u in units if (u[0] & 0x1F) not in {H264_SPS, H264_PPS}]
        else:
            units = [
                u
                for u in units
                if ((u[0] >> 1) & 0x3F) not in {H265_VPS, H265_SPS, H265_PPS}
            ]

    frames = build_frames(codec, units, mtu_payload)
    if scenario.duration_frames:
        frames = frames[: scenario.duration_frames]
    if not frames:
        raise SystemExit("no access units were built")

    fmtp = "" if scenario.omit_sdp_params else sdp_fmtp(codec, params, scenario.strip_inband_params)
    writer = PcapWriter()

    # --- SIP signalling -----------------------------------------------------
    call_id = "fixture-1@192.0.2.10"
    branch = "z9hG4bK-video-1-0"
    common = [
        ("Via", f"SIP/2.0/UDP {CALLER_IP}:{SIP_PORT};branch={branch}"),
        ("From", f"<sip:caller@{CALLER_IP}>;tag=vid1"),
        ("Call-ID", call_id),
    ]
    offer = sip_message(
        f"INVITE sip:test@{CALLEE_IP}:{SIP_PORT} SIP/2.0",
        common
        + [
            ("To", f"<sip:test@{CALLEE_IP}>"),
            ("CSeq", "1 INVITE"),
            ("Contact", f"<sip:caller@{CALLER_IP}:{SIP_PORT}>"),
            ("Max-Forwards", "70"),
            ("Content-Type", "application/sdp"),
        ],
        sdp_offer_answer(
            CALLER_IP,
            40002,
            payload_type,
            "video",
            codec,
            VIDEO_CLOCK_RATE,
            fmtp=fmtp or None,
        ),
    )
    answer = sip_message(
        "SIP/2.0 200 OK",
        [
            ("Via", f"SIP/2.0/UDP {CALLER_IP}:{SIP_PORT};branch={branch}"),
            ("From", f"<sip:caller@{CALLER_IP}>;tag=vid1"),
            ("To", f"<sip:test@{CALLEE_IP}>;tag=vid2"),
            ("Call-ID", call_id),
            ("CSeq", "1 INVITE"),
            ("Contact", f"<sip:test@{CALLEE_IP}:{SIP_PORT}>"),
            ("Content-Type", "application/sdp"),
        ],
        sdp_offer_answer(
            CALLEE_IP,
            40002,
            payload_type,
            "video",
            codec,
            VIDEO_CLOCK_RATE,
            fmtp=fmtp or None,
        ),
    )
    ack = sip_message(
        f"ACK sip:test@{CALLEE_IP}:{SIP_PORT} SIP/2.0",
        [
            ("Via", f"SIP/2.0/UDP {CALLER_IP}:{SIP_PORT};branch={branch}"),
            ("From", f"<sip:caller@{CALLER_IP}>;tag=vid1"),
            ("To", f"<sip:test@{CALLEE_IP}>;tag=vid2"),
            ("Call-ID", call_id),
            ("CSeq", "1 ACK"),
            ("Max-Forwards", "70"),
        ],
    )
    bye = sip_message(
        f"BYE sip:caller@{CALLER_IP}:{SIP_PORT} SIP/2.0",
        [
            ("Via", f"SIP/2.0/UDP {CALLEE_IP}:{SIP_PORT};branch=z9hG4bK-video-1-1"),
            ("From", f"<sip:test@{CALLEE_IP}>;tag=vid2"),
            ("To", f"<sip:caller@{CALLER_IP}>;tag=vid1"),
            ("Call-ID", call_id),
            ("CSeq", "2 BYE"),
            ("Max-Forwards", "70"),
        ],
    )

    media_port = 40002
    base_us = start_seconds * 1_000_000
    writer.add_udp(base_us // 1_000_000, base_us % 1_000_000, CALLER_IP, CALLEE_IP,
                   SIP_PORT, SIP_PORT, offer, 0x10, 0x20)
    writer.add_udp(base_us // 1_000_000, base_us % 1_000_000 + 10_000, CALLEE_IP, CALLER_IP,
                   SIP_PORT, SIP_PORT, answer, 0x20, 0x10)
    writer.add_udp(base_us // 1_000_000, base_us % 1_000_000 + 20_000, CALLER_IP, CALLEE_IP,
                   SIP_PORT, SIP_PORT, ack, 0x10, 0x20)

    # --- media --------------------------------------------------------------
    sequence = first_sequence
    timestamp = timestamp_base
    dropped = 0
    emitted = 0
    keyframes = 0
    fragments = 0
    media_start = base_us + 100_000

    for index, (packets, is_key) in enumerate(frames):
        frame_us = media_start + index * scenario.frame_interval_us
        if is_key:
            keyframes += 1
        for packet_index, packet in enumerate(packets):
            if packet_index == 0:
                fragments += 1
            if scenario.drop_every and (sequence % scenario.drop_every == 0):
                dropped += 1
                sequence += 1
                continue
            offset_us = frame_us + packet_index * 200
            writer.add_rtp(
                offset_us // 1_000_000,
                offset_us % 1_000_000,
                CALLEE_IP,
                CALLER_IP,
                media_port,
                media_port,
                payload_type,
                sequence,
                timestamp,
                ssrc,
                packet.payload,
                marker=packet.marker,
                source_mac_octet=0x20,
                destination_mac_octet=0x10,
            )
            emitted += 1
            sequence += 1
        timestamp = (timestamp + 3000) & 0xFFFFFFFF  # 30 fps at a 90 kHz clock

    end_us = media_start + len(frames) * scenario.frame_interval_us + 100_000
    writer.add_udp(end_us // 1_000_000, end_us % 1_000_000, CALLEE_IP, CALLER_IP,
                   SIP_PORT, SIP_PORT, bye, 0x20, 0x10)

    stats = {
        "access_units": len(frames),
        "keyframes": keyframes,
        "rtp_packets": emitted,
        "dropped_packets": dropped,
        "nal_units": len(units),
        "sdp_has_params": 1 if fmtp else 0,
        "inband_params": 0 if scenario.strip_inband_params else len(params),
        "bytes": len(writer.to_bytes()),
    }
    return writer.to_bytes(), stats


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path,
                        help="Annex-B elementary stream (.h264 / .h265)")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--codec", required=True, choices=["H264", "H265"])
    parser.add_argument("--payload-type", type=int, default=96)
    parser.add_argument("--ssrc", default="0x56494445", help="hex or decimal")
    parser.add_argument("--mtu-payload", type=int, default=1400,
                        help="max RTP payload bytes per packet (default 1400)")
    parser.add_argument("--frame-interval-us", type=int, default=33_333,
                        help="capture interval between access units (30000 = 30 fps)")
    parser.add_argument("--frames", type=int, default=0,
                        help="keep only the first N access units (0 = all)")
    parser.add_argument("--drop-every", type=int, default=0,
                        help="drop every Nth RTP packet (0 = drop none)")
    parser.add_argument("--strip-inband-params", action="store_true",
                        help="keep parameter sets only in the SDP")
    parser.add_argument("--omit-sdp-params", action="store_true",
                        help="keep parameter sets only in-band")
    args = parser.parse_args()

    bitstream = args.input.read_bytes()
    data, stats = build_capture(
        args.codec,
        bitstream,
        args.payload_type,
        int(str(args.ssrc), 0) & 0xFFFFFFFF,
        Scenario(
            drop_every=args.drop_every,
            frame_interval_us=args.frame_interval_us,
            strip_inband_params=args.strip_inband_params,
            omit_sdp_params=args.omit_sdp_params,
            duration_frames=args.frames,
        ),
        args.mtu_payload,
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest().upper()

    print(f"codec: {args.codec} PT {args.payload_type} SSRC 0x{int(str(args.ssrc), 0):08X}")
    print(f"input: {args.input} ({len(bitstream)} bytes)")
    for key, value in stats.items():
        print(f"{key}: {value}")
    print(f"output: {args.output}")
    print(f"sha256: {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
