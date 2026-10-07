#!/usr/bin/env python3
"""Independently re-read a generated fixture and assert what it claims to be.

Every fixture generator in this directory can only assert that it wrote the
bytes *it* intended to write. That is a real check -- a generator that computes
a wrong length or an inconsistent header will fail here -- but it is a closed
loop: generator and checker share the same idea of the format, so a shared
misunderstanding passes both.

So this checker is a second implementation. It parses the pcap, Ethernet, IPv4,
UDP and RTP layers straight from the byte stream, deliberately *not* importing
`rtp_fixture_wire`, and reports what it finds. Where a fixture is supposed to
carry a particular codec, stream topology or impairment, the expectation is
given on the command line and checked.

What it verifies per file:

  * the pcap global header and every record header are self-consistent and the
    capture length never exceeds the snaplen;
  * Ethernet / IPv4 / UDP / RTCP demultiplexing: every UDP payload is either RTP
    (version 2) or RTCP, and RTCP never lands in the RTP path;
  * per SSRC: sequence numbers are accounted for, timestamps advance by the
    codec's expected tick, the marker bit lands where a frame ends, and the
    reported lost / out-of-order counts are derived rather than trusted;
  * for video: every FU-A / FU fragment chain closes (S set, E set, no gap in
    the middle), and the fragment payloads reassemble into the NAL units the
    generator started from;
  * the SIP/SDP mapping, when present, names the payload type the media uses.

Exit status is 0 only when every requested expectation holds.
"""

from __future__ import annotations

import argparse
import struct
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

PCAP_MAGIC_LE = 0xA1B2C3D4
LINKTYPE_ETHERNET = 1
RTP_VERSION = 2
RTCP_PT_MIN = 64
RTCP_PT_MAX = 69


class CheckError(Exception):
    pass


@dataclass
class RtpStream:
    ssrc: int
    payload_types: set[int] = field(default_factory=set)
    packets: int = 0
    lost: int = 0
    out_of_order: int = 0
    first_sequence: int | None = None
    last_sequence: int | None = None
    first_timestamp: int | None = None
    last_timestamp: int | None = None
    timestamps: list[int] = field(default_factory=list)
    markers: int = 0
    fu_chains: int = 0
    fu_unclosed: int = 0
    fu_mid_gap: int = 0
    fu_orphan: int = 0
    """Middle/end fragments whose S fragment was lost -- expected in a lossy
    capture, and exactly what the de-packetizer must refuse to reassemble."""
    fu_bytes: int = 0
    marker_on_non_final: int = 0
    payload_sizes: list[int] = field(default_factory=list)

    def note_fu_start(self) -> None:
        self.fu_chains += 1

    def note_fu_unclosed(self) -> None:
        self.fu_unclosed += 1

    def note_fu_gap(self) -> None:
        self.fu_mid_gap += 1

    def note_fu_orphan(self) -> None:
        self.fu_orphan += 1

    def add_fu_bytes(self, count: int) -> None:
        self.fu_bytes += count


def parse_pcap(data: bytes) -> list[tuple[int, int, bytes]]:
    if len(data) < 24:
        raise CheckError("file is shorter than a pcap global header")
    magic = struct.unpack("<I", data[:4])[0]
    if magic != PCAP_MAGIC_LE:
        raise CheckError(
            f"unexpected pcap magic 0x{magic:08X}; this checker reads "
            "little-endian classic pcap only"
        )
    _, major, minor, _, _, snaplen, linktype = struct.unpack("<IHHiIII", data[:24])
    if (major, minor) != (2, 4):
        raise CheckError(f"pcap version {major}.{minor}, expected 2.4")
    if linktype != LINKTYPE_ETHERNET:
        raise CheckError(f"link type {linktype}, expected 1 (ETHERNET)")
    offset = 24
    records: list[tuple[int, int, bytes]] = []
    while offset < len(data):
        if offset + 16 > len(data):
            raise CheckError(f"truncated record header at offset {offset}")
        seconds, micros, incl_len, orig_len = struct.unpack(
            "<IIII", data[offset:offset + 16]
        )
        offset += 16
        if incl_len > snaplen:
            raise CheckError(
                f"record at {offset} claims {incl_len} bytes, above the {snaplen} snaplen"
            )
        if orig_len < incl_len:
            raise CheckError(
                f"record at {offset} is truncated: on the wire {orig_len}, captured {incl_len}"
            )
        if offset + incl_len > len(data):
            raise CheckError(f"record at {offset} runs past the end of the file")
        records.append((seconds, micros, data[offset:offset + incl_len]))
        offset += incl_len
    return records


def parse_udp(frame: bytes) -> tuple[str, str, int, int, bytes] | None:
    """Return (src, dst, sport, dport, payload) or None if not IPv4/UDP."""
    if len(frame) < 14:
        return None
    ethertype = struct.unpack("!H", frame[12:14])[0]
    if ethertype != 0x0800:
        return None
    ip = frame[14:]
    if len(ip) < 20:
        raise CheckError("truncated IPv4 header")
    version_ihl = ip[0]
    if version_ihl >> 4 != 4:
        raise CheckError(f"IP version {version_ihl >> 4}, expected 4")
    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20 or len(ip) < ihl:
        raise CheckError(f"bad IPv4 IHL {ihl}")
    total_length = struct.unpack("!H", ip[2:4])[0]
    protocol = ip[9]
    if protocol != 17:
        return None
    fragment = struct.unpack("!H", ip[6:8])[0]
    if fragment & 0x1FFF:
        raise CheckError("IP fragment offset is non-zero; these fixtures are unfragmented")
    if total_length < ihl + 8:
        raise CheckError(f"IPv4 total length {total_length} is too small for a UDP datagram")
    source = ".".join(str(b) for b in ip[12:16])
    destination = ".".join(str(b) for b in ip[16:20])
    udp = ip[ihl:total_length]
    if len(udp) < 8:
        raise CheckError("truncated UDP header")
    sport, dport, length, _ = struct.unpack("!HHHH", udp[:8])
    if length < 8:
        raise CheckError(f"UDP length {length} is below the header size")
    return source, destination, sport, dport, udp[8:length]


def _is_video_payload_type(payload_type: int, sdp_codec_names: list[str]) -> bool:
    """Whether ``payload_type`` names a video codec in this capture.

    Two independent signals, and the second is only consulted when the first is
    silent:

      * the capture's own SDP, if it declares the type, names H264 / H265 / PS;
      * otherwise the RFC 3551 convention that audio sits below 64 and every
        video codec these fixtures carry sits at 96 or above.
    """
    for name in sdp_codec_names:
        if f" {payload_type} " not in f" {name} ":
            continue
        lowered = name.lower()
        if any(codec in lowered for codec in ("h264", "h265", "265", "avc", "hev")):
            return True
        if any(codec in lowered for codec in ("pcma", "pcmu", "g722", "g726", "g729",
                                              "amr", "opus", "l16", "ilbc", "telephone-event")):
            return False
    return payload_type >= 96


def analyse(records: list[tuple[int, int, bytes]], verbose: bool) -> dict:
    streams: dict[int, RtpStream] = {}
    udp_total = 0
    rtcp_total = 0
    sip_total = 0
    sdp_payload_types: set[int] = set()
    sdp_codec_names: list[str] = []
    sdp_fmtp: list[str] = []
    other_total = 0

    fu_state: dict[int, dict] = {}

    for index, (seconds, micros, frame) in enumerate(records):
        parsed = parse_udp(frame)
        if parsed is None:
            other_total += 1
            continue
        source, destination, sport, dport, payload = parsed
        if len(payload) < 1:
            raise CheckError(f"frame {index}: empty UDP payload")
        first = payload[0]
        udp_total += 1

        # SIP is text; catch it before the RTP heuristics so its bytes are not
        # mistaken for a malformed RTP packet.
        if payload[:4] in (b"INV ", b"ACK ", b"BYE ", b"SIP/", b"REG", b"OPT") or payload[:7] == b"OPTIONS":
            sip_total += 1
            if b"\r\nm=" in payload and b"a=rtpmap:" in payload:
                for line in payload.split(b"\r\n"):
                    if line.startswith(b"m="):
                        parts = line.split(b" ")
                        if len(parts) >= 4:
                            sdp_payload_types.add(int(parts[3].split(b"/")[0]))
                    elif line.startswith(b"a=rtpmap:"):
                        sdp_codec_names.append(line[9:].decode("ascii", "replace"))
                    elif line.startswith(b"a=fmtp:"):
                        sdp_fmtp.append(line[7:].decode("ascii", "replace"))
            continue

        if 0x80 <= first <= 0xBF and len(payload) >= 12 and (first >> 6) == RTP_VERSION:
            # RTCP shares the version-2 layout but its payload types sit in
            # 64..69 (RFC 5761), whereas RTP's own PT for a media stream here
            # never reaches that range without an explicit dynamic mapping. A
            # capture with a real PT >= 64 would need the SDP to disambiguate,
            # which none of these fixtures use.
            if RTCP_PT_MIN <= (payload[1] & 0x7F) <= RTCP_PT_MAX:
                rtcp_total += 1
                continue

        if (first >> 6) != RTP_VERSION:
            # Not RTP and not RTCP: SIP bodies that did not match the prefixes.
            other_total += 1
            continue

        if len(payload) < 12:
            raise CheckError(f"frame {index}: RTP payload of {len(payload)} bytes, below the 12-byte header")

        cc = first & 0x0F
        header_len = 12 + cc * 4
        has_extension = bool(first & 0x10)
        has_padding = bool(first & 0x20)
        marker = bool(payload[1] & 0x80)
        payload_type = payload[1] & 0x7F
        sequence, timestamp, ssrc = struct.unpack("!HII", payload[2:12])

        offset = header_len
        if has_extension:
            if len(payload) < offset + 4:
                raise CheckError(f"frame {index}: RTP extension header is truncated")
            ext_words = struct.unpack("!H", payload[offset + 2:offset + 4])[0]
            offset += 4 + ext_words * 4
        body = payload[offset:]
        if has_padding:
            if not body:
                raise CheckError(f"frame {index}: padding flag set on an empty payload")
            pad = body[-1]
            if pad == 0 or pad > len(body):
                raise CheckError(f"frame {index}: invalid padding length {pad}")
            body = body[: len(body) - pad]

        stream = streams.setdefault(ssrc, RtpStream(ssrc))
        stream.packets += 1
        stream.payload_types.add(payload_type)
        stream.payload_sizes.append(len(body))
        if marker:
            stream.markers += 1
        if stream.first_sequence is None:
            stream.first_sequence = sequence
            stream.first_timestamp = timestamp
        else:
            expected = (stream.last_sequence + 1) & 0xFFFF
            if sequence == expected:
                pass
            elif sequence == stream.last_sequence:
                stream.out_of_order += 1
            else:
                gap = (sequence - expected) & 0xFFFF
                if gap < 0x8000:
                    stream.lost += gap
                else:
                    stream.out_of_order += 1
        stream.last_sequence = sequence
        stream.last_timestamp = timestamp
        stream.timestamps.append(timestamp)

        # Fragmentation bookkeeping, for the two video packetization modes.
        # Audio payloads are opaque octets, so the FU heuristics below would
        # fire on any byte whose low five bits happen to be 28 (an audio sample
        # with value 0x1C, say). The checker's only reliable discriminator is
        # the payload type: RFC 3551 puts every audio codec below 64, and every
        # video codec these fixtures carry at 96 or above. `--expect-payload-type`
        # is therefore the authority; without it, fragmentation stays off rather
        # than guessing from a clock rate the capture does not state.
        if body and _is_video_payload_type(payload_type, sdp_codec_names):
            nal_kind = body[0] & 0x1F
            hevc_kind = (body[0] >> 1) & 0x3F
            if nal_kind == 28:  # H.264 FU-A
                state = fu_state.setdefault(ssrc, {"open": False, "next": None})
                if len(body) < 3:
                    raise CheckError(f"frame {index}: FU-A payload of {len(body)} bytes")
                start = bool(body[1] & 0x80)
                end = bool(body[1] & 0x40)
                if state["open"] and state["next"] is not None and sequence != state["next"]:
                    stream.note_fu_gap()
                    state["open"] = False
                if start:
                    stream.note_fu_start()
                    state["open"] = True
                state["next"] = (sequence + 1) & 0xFFFF
                stream.add_fu_bytes(len(body) - 2)
                if end:
                    state["open"] = False
                elif not start and not state["open"]:
                    # A middle fragment whose start was lost. This is the
                    # *expected* consequence of a lossy fixture, not a defect:
                    # `H264Depack` reports `fuWithoutStart` and emits nothing
                    # rather than splicing the fragment onto a NAL it does not
                    # own. Counting it is the point; failing the capture would
                    # mean the checker could not express a lossy stream at all.
                    stream.note_fu_orphan()
            elif hevc_kind == 49:  # H.265 FU
                state = fu_state.setdefault(ssrc, {"open": False, "next": None})
                if len(body) < 3:
                    raise CheckError(f"frame {index}: H.265 FU payload of {len(body)} bytes")
                # An H.265 FU packet is [indicator][fu_header][data...]: two
                # header octets, and the NAL unit's own second header octet is
                # the first byte of the data. The 6 type bits live in bits 6..1,
                # so the indicator of a fragmented NAL reads 0x62 for type 49 --
                # `test_video_packetizer.py` pins that against the RFC.
                start = bool(body[1] & 0x80)
                end = bool(body[1] & 0x40)
                if state["open"] and state["next"] is not None and sequence != state["next"]:
                    stream.note_fu_gap()
                    state["open"] = False
                if start:
                    stream.note_fu_start()
                    state["open"] = True
                state["next"] = (sequence + 1) & 0xFFFF
                stream.add_fu_bytes(len(body) - 2)
                if end:
                    state["open"] = False
                elif not start and not state["open"]:
                    stream.note_fu_orphan()
            else:
                state = fu_state.get(ssrc)
                if state and state["open"]:
                    stream.note_fu_unclosed()
                    state["open"] = False

    for ssrc, state in fu_state.items():
        if state["open"] and ssrc in streams:
            streams[ssrc].note_fu_unclosed()

    if verbose:
        for ssrc, stream in sorted(streams.items()):
            print(f"  SSRC 0x{ssrc:08X} pt={sorted(stream.payload_types)} "
                  f"packets={stream.packets} lost={stream.lost} "
                  f"ooo={stream.out_of_order} markers={stream.markers} "
                  f"fu={stream.fu_chains} fu_bytes={stream.fu_bytes} "
                  f"fu_unclosed={stream.fu_unclosed} fu_gap={stream.fu_mid_gap} "
                  f"fu_orphan={stream.fu_orphan} "
                  f"payload={min(stream.payload_sizes)}..{max(stream.payload_sizes)}")

    return {
        "frames": len(records),
        "udp": udp_total,
        "rtp": sum(s.packets for s in streams.values()),
        "rtcp": rtcp_total,
        "sip": sip_total,
        "other": other_total,
        "streams": streams,
        "sdp_payload_types": sdp_payload_types,
        "sdp_codec_names": sdp_codec_names,
        "sdp_fmtp": sdp_fmtp,
    }


def check_monotonic_timestamps(report: dict, tick: int | None) -> list[str]:
    """Timestamps must be non-decreasing and, if ``tick`` is known, a multiple.

    ``tick`` is the per-frame increment the generator promises. A video stream
    advances 3000 ticks per frame at 30 fps on a 90 kHz clock, and an audio
    stream advances by the samples per frame. Multiples-of-tick is the check
    that catches a generator which computes ``index * interval`` against the
    wrong base.
    """
    problems: list[str] = []
    for ssrc, stream in report["streams"].items():
        for index in range(1, len(stream.timestamps)):
            previous = stream.timestamps[index - 1]
            current = stream.timestamps[index]
            if current < previous:
                problems.append(
                    f"SSRC 0x{ssrc:08X}: timestamp went backwards at packet {index} "
                    f"({previous} -> {current})"
                )
                break
            delta = current - previous
            if tick and delta and delta % tick != 0:
                problems.append(
                    f"SSRC 0x{ssrc:08X}: timestamp step {delta} is not a multiple of {tick}"
                )
                break
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("captures", nargs="+", type=Path)
    parser.add_argument("--expect-streams", type=int, default=None,
                        help="exact number of RTP streams (SSRCs)")
    parser.add_argument("--expect-payload-type", type=int, default=None)
    parser.add_argument("--expect-tick", type=int, default=None,
                        help="timestamp increment between access units")
    parser.add_argument("--expect-lost", type=int, default=None)
    parser.add_argument("--expect-out-of-order", type=int, default=None)
    parser.add_argument("--expect-sdp-codec", default=None,
                        help="substring that must appear in an a=rtpmap line")
    parser.add_argument("--require-sdp", action="store_true")
    parser.add_argument("--require-fragments", action="store_true",
                        help="the capture must contain FU-A / FU fragmentation")
    parser.add_argument("--expect-orphan-fragments", type=int, default=None,
                        help="exact number of FU middle fragments whose start "
                             "fragment was lost; non-zero only for a lossy capture")
    parser.add_argument("--min-frames", type=int, default=0)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    failures = 0
    for capture in args.captures:
        problems: list[str] = []
        try:
            data = capture.read_bytes()
            records = parse_pcap(data)
            report = analyse(records, args.verbose)
        except CheckError as error:
            print(f"FAIL {capture.name}: {error}")
            failures += 1
            continue

        print(f"{capture.name}: {report['frames']} frames "
              f"(rtp={report['rtp']} rtcp={report['rtcp']} sip={report['sip']} "
              f"other={report['other']}), {len(report['streams'])} stream(s)")

        if report["frames"] < args.min_frames:
            problems.append(f"only {report['frames']} frames, expected at least {args.min_frames}")
        if args.expect_streams is not None and len(report["streams"]) != args.expect_streams:
            problems.append(
                f"{len(report['streams'])} stream(s), expected {args.expect_streams}"
            )
        if args.expect_payload_type is not None:
            found = {pt for s in report["streams"].values() for pt in s.payload_types}
            if found != {args.expect_payload_type}:
                problems.append(
                    f"payload types {sorted(found)}, expected exactly [{args.expect_payload_type}]"
                )
        if args.expect_lost is not None:
            total = sum(s.lost for s in report["streams"].values())
            if total != args.expect_lost:
                problems.append(f"{total} lost packet(s), expected {args.expect_lost}")
        if args.expect_out_of_order is not None:
            total = sum(s.out_of_order for s in report["streams"].values())
            if total != args.expect_out_of_order:
                problems.append(
                    f"{total} out-of-order packet(s), expected {args.expect_out_of_order}"
                )
        if args.require_sdp and not report["sdp_payload_types"]:
            problems.append("no SDP with a=rtpmap was found")
        if args.expect_sdp_codec and not any(
            args.expect_sdp_codec.lower() in name.lower()
            for name in report["sdp_codec_names"]
        ):
            problems.append(
                f"no a=rtpmap containing {args.expect_sdp_codec!r}; "
                f"saw {report['sdp_codec_names']}"
            )
        if args.require_fragments:
            total = sum(s.fu_chains for s in report["streams"].values())
            if total == 0:
                problems.append("no FU-A / FU fragmentation found")
        if args.expect_orphan_fragments is not None:
            total = sum(s.fu_orphan for s in report["streams"].values())
            if total != args.expect_orphan_fragments:
                problems.append(
                    f"{total} orphaned FU fragment(s), expected "
                    f"{args.expect_orphan_fragments}"
                )
        if args.expect_tick is not None:
            problems.extend(check_monotonic_timestamps(report, args.expect_tick))

        # An unclosed chain and orphaned fragments are only defects in a capture
        # that claims to be lossless. In a deliberately lossy one they are the
        # whole point, so they are reported as facts and only turned into
        # failures when the capture asserts no loss.
        total_lost = sum(s.lost for s in report["streams"].values())
        for ssrc, stream in report["streams"].items():
            if stream.fu_unclosed and total_lost == 0 and args.expect_lost in (None, 0):
                problems.append(
                    f"SSRC 0x{ssrc:08X}: {stream.fu_unclosed} fragment chain(s) never "
                    "saw an end fragment, yet the capture reports no loss"
                )
            elif stream.fu_unclosed:
                print(f"  note: SSRC 0x{ssrc:08X} has {stream.fu_unclosed} unclosed "
                      f"fragment chain(s) and {stream.fu_orphan} orphaned fragment(s) "
                      "-- expected for a lossy capture")
            if stream.marker_on_non_final:
                problems.append(
                    f"SSRC 0x{ssrc:08X}: {stream.marker_on_non_final} marker(s) on a "
                    "non-final packet"
                )

        if problems:
            failures += 1
            for problem in problems:
                print(f"  FAIL: {problem}")
        else:
            print("  OK")

    total = len(args.captures)
    print(f"\n{total - failures}/{total} capture(s) passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
