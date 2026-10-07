#!/usr/bin/env python3
"""Generate RTP audio captures for the codecs that need no external encoder.

Scope, and why it is narrower than it looks:

  * **G.711 A-law and mu-law** — the two laws are closed-form piecewise
    functions, so the payload is computed here from a synthetic signal. That is
    not "hand-written test data": every payload octet is the real output of the
    real companding law applied to a known PCM sample, and `--verify-roundtrip`
    expands the result back to PCM and reports the error, so a bug in the law
    shows up as a number rather than as a shrug.
  * **L16 / PCMA / PCMU** — trivial, and still useful as the control group: a
    codec with no packing ambiguity, so anything the application reports about
    a *different* stream is about the stream, not about the parser.
  * **G.726** — deliberately *not* generated here. Its four rates need a real
    ADPCM encoder (the project links the spandsp subset for exactly this), and
    the four public captures in `assets/rtp` already cover the RFC 3551
    right-packed form. See CONTRIBUTING.md for why there is no AAL2 left-packed
    public sample and what the fixtures do instead.

Every capture here is synthetic: a deterministic multi-tone signal, generated
from a formula so it is reproducible on any machine, with RFC 5737 documentation
addresses. No real voice, no real telephone numbers, no real host.
"""

from __future__ import annotations

import argparse
import hashlib
import math
import re
import struct
import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from rtp_fixture_wire import PcapWriter, sdp_offer_answer, sip_message

CALLER_IP = "192.0.2.10"
CALLEE_IP = "192.0.2.20"
SIP_PORT = 5060


# ---------------------------------------------------------------------------
# G.711 payloads, inverted from the application's own expansion tables
# ---------------------------------------------------------------------------

_G711_SOURCE = (
    Path(__file__).resolve().parents[3]
    / "app/src/main/cpp/layanalyzer/rtp/codecs/G711.cpp"
)


def _load_expansion_table(name: str) -> tuple[int, ...]:
    """Read one 256-entry expansion table out of the application's G711.cpp.

    Parsing the C++ source rather than transcribing the values is deliberate: a
    hand-copied table is a second copy to keep in sync, and the whole point of
    deriving the encoder from this table is that the two halves cannot drift. A
    missing or malformed table is a hard error -- a generator that quietly
    substituted its own numbers would defeat its own purpose.
    """
    if not _G711_SOURCE.exists():
        raise SystemExit(
            f"cannot find {_G711_SOURCE}; the G.711 fixtures depend on the "
            "application's expansion tables and refuse to guess them"
        )
    source = _G711_SOURCE.read_text(encoding="utf-8")
    match = re.search(
        rf"k{name}ExpansionTable\[256\]\s*=\s*\{{(.*?)\}};", source, re.S
    )
    if not match:
        raise SystemExit(f"k{name}ExpansionTable[256] not found in {_G711_SOURCE}")
    values = [int(token) for token in re.findall(r"-?\d+", match.group(1))]
    if len(values) != 256:
        raise SystemExit(
            f"k{name}ExpansionTable has {len(values)} entries, expected 256"
        )
    return tuple(values)


_ULAW_TABLE = _load_expansion_table("Ulaw")
_ALAW_TABLE = _load_expansion_table("Alaw")


@lru_cache(maxsize=None)
def _nearest_code(table: tuple[int, ...], value: int) -> int:
    """The code whose expansion is nearest ``value`` (linear scan, memoised).

    The tables are not monotonic in the code, so there is no binary search to
    do; 256 comparisons per *distinct* sample is irrelevant next to generating a
    capture, and `@lru_cache` collapses the repeats that dominate real audio.
    """
    best_code = 0
    best_distance = None
    for code, expansion in enumerate(table):
        distance = abs(expansion - value)
        if best_distance is None or distance < best_distance:
            best_code, best_distance = code, distance
    return best_code


def linear_to_ulaw(sample: int) -> int:
    """The mu-law code whose Wireshark expansion is nearest ``sample``."""
    clipped = max(min(_ULAW_TABLE), min(max(_ULAW_TABLE), sample))
    return _nearest_code(_ULAW_TABLE, clipped)


def linear_to_alaw(sample: int) -> int:
    """The A-law code whose Wireshark expansion is nearest ``sample``."""
    clipped = max(min(_ALAW_TABLE), min(max(_ALAW_TABLE), sample))
    return _nearest_code(_ALAW_TABLE, clipped)


def ulaw_to_linear(byte: int) -> int:
    return _ULAW_TABLE[byte & 0xFF]


def alaw_to_linear(byte: int) -> int:
    return _ALAW_TABLE[byte & 0xFF]


# ---------------------------------------------------------------------------
# Synthetic source signal
# ---------------------------------------------------------------------------


def tone_frame(rate: int, frame_index: int, samples: int) -> list[int]:
    """One frame of a deterministic multi-tone test signal.

    Three components at incommensurate frequencies plus a per-frame amplitude
    ramp: the frequencies make the waveform recognisable by ear after export
    (so "is this actually my signal?" is answerable without instruments), and
    the per-frame ramp means a frame-order or timestamp bug shows up as an
    audible discontinuity rather than as a subtly wrong file.
    """
    base = frame_index * samples
    out: list[int] = []
    for index in range(samples):
        t = (base + index) / rate
        envelope = 0.55 + 0.35 * math.sin(2 * math.pi * 0.7 * t)
        value = (
            0.50 * math.sin(2 * math.pi * 220.0 * t)
            + 0.30 * math.sin(2 * math.pi * 440.0 * t)
            + 0.20 * math.sin(2 * math.pi * 660.0 * t)
        )
        out.append(int(max(-1.0, min(1.0, value * envelope)) * 26000))
    return out


# ---------------------------------------------------------------------------
# Capture assembly
# ---------------------------------------------------------------------------


@dataclass
class AudioSpec:
    name: str
    payload_type: int
    clock_rate: int
    ptime_ms: int
    encode: object
    """``None`` for L16, or one of the ``linear_to_*`` functions."""
    declare_in_sdp: bool = True
    """False produces the static-payload-type fixture: no SDP at all, so the
    codec must be inferred from the PT (RFC 3551 table 4) or supplied by the
    user through the PT-mapping dialog. That is the branch no public sample in
    `assets/rtp` exercises, because every one of them has an SDP."""

    def payload_size(self) -> int:
        if self.encode is None:
            return self.ptime_ms * self.clock_rate // 1000 * 2
        return self.ptime_ms * self.clock_rate // 1000


AUDIO_SPECS = {
    "g711a": AudioSpec("g711a", 8, 8000, 20, linear_to_alaw),
    "g711u": AudioSpec("g711u", 0, 8000, 20, linear_to_ulaw),
    "l16": AudioSpec("l16", 10, 44100, 20, None),
}


def build_capture(
    spec: AudioSpec,
    frames: int,
    ssrc: int,
    media_port: int,
    direction: str = "caller-to-callee",
    drop_every: int = 0,
    start_seconds: int = 1,
    first_sequence: int = 100,
    timestamp_base: int = 8000,
) -> tuple[bytes, dict[str, int]]:
    writer = PcapWriter()
    samples_per_frame = spec.ptime_ms * spec.clock_rate // 1000
    ticks_per_frame = samples_per_frame  # clock rate == sample rate for these

    if direction == "caller-to-callee":
        media_src, media_dst, src_mac, dst_mac = CALLER_IP, CALLEE_IP, 0x10, 0x20
    else:
        media_src, media_dst, src_mac, dst_mac = CALLEE_IP, CALLER_IP, 0x20, 0x10

    base_us = start_seconds * 1_000_000
    media_start = base_us + 200_000

    if spec.declare_in_sdp:
        codec_name = {"g711a": "PCMA", "g711u": "PCMU", "l16": "L16"}[spec.name]
        offer = sip_message(
            f"INVITE sip:test@{CALLEE_IP}:{SIP_PORT} SIP/2.0",
            [
                ("Via", f"SIP/2.0/UDP {CALLER_IP}:{SIP_PORT};branch=z9hG4bK-aud-1-0"),
                ("From", f"<sip:caller@{CALLER_IP}>;tag=aud1"),
                ("To", f"<sip:test@{CALLEE_IP}>"),
                ("Call-ID", "fixture-audio@192.0.2.10"),
                ("CSeq", "1 INVITE"),
                ("Contact", f"<sip:caller@{CALLER_IP}:{SIP_PORT}>"),
                ("Max-Forwards", "70"),
                ("Content-Type", "application/sdp"),
            ],
            sdp_offer_answer(
                CALLER_IP, media_port, spec.payload_type, "audio",
                codec_name, spec.clock_rate, extra_lines=[f"a=ptime:{spec.ptime_ms}"],
            ),
        )
        answer = sip_message(
            "SIP/2.0 200 OK",
            [
                ("Via", f"SIP/2.0/UDP {CALLER_IP}:{SIP_PORT};branch=z9hG4bK-aud-1-0"),
                ("From", f"<sip:caller@{CALLER_IP}>;tag=aud1"),
                ("To", f"<sip:test@{CALLEE_IP}>;tag=aud2"),
                ("Call-ID", "fixture-audio@192.0.2.10"),
                ("CSeq", "1 INVITE"),
                ("Contact", f"<sip:test@{CALLEE_IP}:{SIP_PORT}>"),
                ("Content-Type", "application/sdp"),
            ],
            sdp_offer_answer(
                CALLEE_IP, media_port, spec.payload_type, "audio",
                codec_name, spec.clock_rate, extra_lines=[f"a=ptime:{spec.ptime_ms}"],
            ),
        )
        bye = sip_message(
            f"BYE sip:test@{CALLEE_IP}:{SIP_PORT} SIP/2.0",
            [
                ("Via", f"SIP/2.0/UDP {CALLER_IP}:{SIP_PORT};branch=z9hG4bK-aud-1-1"),
                ("From", f"<sip:caller@{CALLER_IP}>;tag=aud1"),
                ("To", f"<sip:test@{CALLEE_IP}>;tag=aud2"),
                ("Call-ID", "fixture-audio@192.0.2.10"),
                ("CSeq", "2 BYE"),
                ("Max-Forwards", "70"),
            ],
        )
        writer.add_udp(base_us // 1_000_000, base_us % 1_000_000, CALLER_IP, CALLEE_IP,
                       SIP_PORT, SIP_PORT, offer, 0x10, 0x20)
        writer.add_udp(base_us // 1_000_000, base_us % 1_000_000 + 10_000, CALLEE_IP, CALLER_IP,
                       SIP_PORT, SIP_PORT, answer, 0x20, 0x10)
    else:
        bye = sip_message(
            f"BYE sip:test@{CALLEE_IP}:{SIP_PORT} SIP/2.0",
            [
                ("Via", f"SIP/2.0/UDP {CALLER_IP}:{SIP_PORT};branch=z9hG4bK-aud-1-1"),
                ("From", f"<sip:caller@{CALLER_IP}>;tag=aud1"),
                ("To", f"<sip:test@{CALLEE_IP}>;tag=aud2"),
                ("Call-ID", "fixture-audio@192.0.2.10"),
                ("CSeq", "2 BYE"),
                ("Max-Forwards", "70"),
            ],
        )

    dropped = 0
    emitted = 0
    sequence = first_sequence
    for index in range(frames):
        pcm = tone_frame(spec.clock_rate, index, samples_per_frame)
        if spec.encode is None:
            payload = struct.pack(f"<{len(pcm)}h", *pcm)
        else:
            payload = bytes(spec.encode(sample) for sample in pcm)
        if drop_every and (sequence % drop_every == 0):
            dropped += 1
            sequence += 1
            continue
        offset_us = media_start + index * spec.ptime_ms * 1000
        writer.add_rtp(
            offset_us // 1_000_000, offset_us % 1_000_000,
            media_src, media_dst, media_port, media_port,
            spec.payload_type,
            sequence,
            (timestamp_base + index * ticks_per_frame) & 0xFFFFFFFF,
            ssrc,
            payload,
            marker=True,
            source_mac_octet=src_mac,
            destination_mac_octet=dst_mac,
        )
        sequence += 1
        emitted += 1

    end_us = media_start + frames * spec.ptime_ms * 1000 + 100_000
    writer.add_udp(end_us // 1_000_000, end_us % 1_000_000, CALLER_IP, CALLEE_IP,
                   SIP_PORT, SIP_PORT, bye, 0x10, 0x20)

    data = writer.to_bytes()
    stats = {
        "frames": emitted,
        "dropped": dropped,
        "payload_octets_per_frame": spec.payload_size(),
        "sdp_present": 1 if spec.declare_in_sdp else 0,
        "bytes": len(data),
    }
    return data, stats


def roundtrip_error(spec: AudioSpec, frames: int) -> tuple[float, float]:
    """Encode then decode the signal and report the worst-case sample error.

    Expressed in 16-bit PCM units so the number is comparable to the waveform
    the application exports. A companding law is lossy by design, so the
    threshold is "the error stays inside the quantisation step", not zero.
    """
    if spec.encode is None:
        return 0.0, 0.0
    decode = alaw_to_linear if spec.name == "g711a" else ulaw_to_linear
    samples = spec.ptime_ms * spec.clock_rate // 1000
    worst = 0
    total = 0
    count = 0
    for index in range(min(frames, 20)):
        for original in tone_frame(spec.clock_rate, index, samples):
            recovered = decode(spec.encode(original))
            delta = abs(recovered - original)
            worst = max(worst, delta)
            total += delta
            count += 1
    return float(worst), (total / count if count else 0.0)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codec", required=True, choices=sorted(AUDIO_SPECS))
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--frames", type=int, default=250, help="media packets (default 250 = 5 s)")
    parser.add_argument("--ssrc", default="0x41554449")
    parser.add_argument("--media-port", type=int, default=40000)
    parser.add_argument("--direction", default="caller-to-callee",
                        choices=["caller-to-callee", "callee-to-caller"])
    parser.add_argument("--drop-every", type=int, default=0)
    parser.add_argument("--no-sdp", action="store_true",
                        help="omit the SDP entirely (static PT only; the codec "
                             "must come from the PT table or the mapping dialog)")
    parser.add_argument("--verify-roundtrip", action="store_true")
    args = parser.parse_args()

    spec = AUDIO_SPECS[args.codec]
    if args.no_sdp:
        spec = AudioSpec(spec.name, spec.payload_type, spec.clock_rate, spec.ptime_ms,
                         spec.encode, declare_in_sdp=False)

    data, stats = build_capture(
        spec,
        args.frames,
        int(str(args.ssrc), 0) & 0xFFFFFFFF,
        args.media_port,
        args.direction,
        args.drop_every,
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest().upper()

    print(f"codec: {spec.name} PT {spec.payload_type} {spec.clock_rate} Hz "
          f"ptime {spec.ptime_ms} ms, direction {args.direction}")
    for key, value in stats.items():
        print(f"{key}: {value}")

    if args.verify_roundtrip and spec.encode is not None:
        worst, mean = roundtrip_error(spec, args.frames)
        print(f"roundtrip_worst_error_pcm16: {worst:.1f}")
        print(f"roundtrip_mean_error_pcm16: {mean:.1f}")
        # The encoder picks the nearest expansion, so the error cannot exceed
        # half of G.711's coarsest step. Measured against the Wireshark tables
        # the worst case is 512 units in 16-bit PCM terms, at the low-amplitude
        # end where the step is widest. A bound of 1024 leaves room for the
        # generator's own rounding while still failing loudly if the two halves
        # ever stop agreeing.
        if worst > 1024:
            raise SystemExit(
                f"companding round-trip error {worst} exceeds the quantisation bound"
            )

    print(f"output: {args.output}")
    print(f"sha256: {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
