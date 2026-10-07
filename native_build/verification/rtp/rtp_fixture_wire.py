#!/usr/bin/env python3
"""Shared Ethernet / IPv4 / UDP / RTP / pcap writer for RTP fixture generation.

Every fixture generator in this directory needs the same five layers, and the
project rule is that the *reference* data must not be produced by the code under
test. Writing those five layers once here keeps the generators honest: the bytes
on the wire are assembled by this module, while the codec payload always comes
from an independent source (ffmpeg for the encoded streams, the arithmetic G.711
/ G.726 tables in `gen_rtp_fixture.py` for the codec-free ones).

The packet layout is deliberately the most boring one there is -- Ethernet II,
IPv4 without options, UDP, RTP version 2 -- because that is what every RTP
sender on the planet emits and therefore what the dissector's happy path is.
Wireshark itself is used to re-read the finished file; nothing here trusts
``gen_amr_rtp_fixture.py``'s copy of the same code, so a divergence between the
two would show up as a disagreement rather than as a shared blind spot.

Little-endian classic pcap, link type 1 (ETHERNET). Timestamps are written as
(seconds, microseconds) exactly as the caller computes them, so a generator
that wants nanosecond resolution cannot have it -- the fixtures are 20 ms apart
at the coarsest, so microseconds lose nothing.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

PCAP_LINKTYPE_ETHERNET = 1
ETHERNET_HEADER_SIZE = 14
IPV4_HEADER_SIZE = 20
UDP_HEADER_SIZE = 8
RTP_HEADER_SIZE = 12

IPPROTO_UDP = 17


def checksum(data: bytes) -> int:
    """The Internet checksum (RFC 1071), as one's complement of the sum."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for offset in range(0, len(data), 2):
        total += (data[offset] << 8) | data[offset + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def mac(octet: int) -> bytes:
    """A locally-administered MAC whose last octet identifies the host.

    RFC 5737 / RFC 1918 style: the first three octets are a fixed vendor prefix
    with the locally-administered bit set, so no fixture can be mistaken for a
    real NIC on the machine that generated or replays it.
    """
    return bytes([0x02, 0x00, 0x5E, 0x00, 0x53, octet])


def ipv4_bytes(address: str) -> bytes:
    return bytes(int(part) for part in address.split("."))


def udp_ipv4_packet(
    source_ip: str,
    destination_ip: str,
    source_port: int,
    destination_port: int,
    payload: bytes,
    identifier: int = 1,
    source_mac_octet: int = 0x10,
    destination_mac_octet: int = 0x20,
    ttl: int = 64,
) -> bytes:
    """One Ethernet + IPv4 + UDP frame carrying ``payload``.

    ``identifier`` is the IP ID field. The generators increment it per packet
    because a stream of identical IP IDs is a fingerprint no real sender
    produces, and some middleboxes treat it as a replay.
    """
    udp_length = UDP_HEADER_SIZE + len(payload)
    udp_datagram = struct.pack(
        "!HHHH", source_port, destination_port, udp_length, 0
    ) + payload

    source_bytes = ipv4_bytes(source_ip)
    destination_bytes = ipv4_bytes(destination_ip)
    pseudo_header = (
        source_bytes
        + destination_bytes
        + b"\x00"
        + bytes([IPPROTO_UDP])
        + struct.pack("!H", udp_length)
    )
    udp_checksum = checksum(pseudo_header + udp_datagram) or 0xFFFF

    total_length = IPV4_HEADER_SIZE + udp_length
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        identifier & 0xFFFF,
        0,
        ttl,
        IPPROTO_UDP,
        0,
        source_bytes,
        destination_bytes,
    )
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]

    ethernet = (
        mac(destination_mac_octet)
        + mac(source_mac_octet)
        + struct.pack("!H", 0x0800)
    )
    return ethernet + header + udp_datagram[:6] + struct.pack("!H", udp_checksum) + udp_datagram[8:]


def rtp_header(
    payload_type: int,
    sequence: int,
    timestamp: int,
    ssrc: int,
    marker: bool = False,
    version: int = 2,
) -> bytes:
    """A 12-byte RTP header with no extensions, padding or CSRCs.

    RFC 3550 section 5.1 lays the first two octets out as:

        byte 0:  V(2) P X CC   -- version in bits 7-6, padding 0x20,
                                  extension 0x10, CSRC count in bits 3-0
        byte 1:  M(1) PT(7)    -- marker 0x80, payload type in bits 6-0

    The marker bit lives in the *second* octet. Putting it in the first one
    alongside the version field is a mistake that still produces a plausible
    12-byte header, and a receiver reads the result as RTP version 3 -- which
    no implementation supports, so every packet is dropped without a message.
    """
    first = ((version & 0x03) << 6)
    second = (0x80 if marker else 0x00) | (payload_type & 0x7F)
    return struct.pack(
        "!BBHII",
        first,
        second,
        sequence & 0xFFFF,
        timestamp & 0xFFFFFFFF,
        ssrc & 0xFFFFFFFF,
    )


@dataclass
class PcapWriter:
    """Accumulates frames with their absolute capture times and writes a pcap."""

    records: list[tuple[int, int, bytes]] = field(default_factory=list)
    _identifier: int = 1

    def next_identifier(self) -> int:
        value = self._identifier
        self._identifier = (self._identifier + 1) & 0xFFFF or 1
        return value

    def add(self, seconds: int, microseconds: int, frame: bytes) -> None:
        self.records.append((seconds, microseconds, frame))

    def add_udp(
        self,
        seconds: int,
        microseconds: int,
        source_ip: str,
        destination_ip: str,
        source_port: int,
        destination_port: int,
        payload: bytes,
        source_mac_octet: int = 0x10,
        destination_mac_octet: int = 0x20,
    ) -> None:
        self.add(
            seconds,
            microseconds,
            udp_ipv4_packet(
                source_ip,
                destination_ip,
                source_port,
                destination_port,
                payload,
                identifier=self.next_identifier(),
                source_mac_octet=source_mac_octet,
                destination_mac_octet=destination_mac_octet,
            ),
        )

    def add_rtp(
        self,
        seconds: int,
        microseconds: int,
        source_ip: str,
        destination_ip: str,
        source_port: int,
        destination_port: int,
        payload_type: int,
        sequence: int,
        timestamp: int,
        ssrc: int,
        payload: bytes,
        marker: bool = False,
        source_mac_octet: int = 0x10,
        destination_mac_octet: int = 0x20,
    ) -> None:
        self.add_udp(
            seconds,
            microseconds,
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            rtp_header(payload_type, sequence, timestamp, ssrc, marker) + payload,
            source_mac_octet=source_mac_octet,
            destination_mac_octet=destination_mac_octet,
        )

    @property
    def frame_count(self) -> int:
        return len(self.records)

    def to_bytes(self) -> bytes:
        out = bytearray()
        out += struct.pack(
            "<IHHiIII",
            0xA1B2C3D4,  # magic
            2,  # version major
            4,  # version minor
            0,  # thiszone
            0,  # sigfigs
            65535,  # snaplen
            PCAP_LINKTYPE_ETHERNET,
        )
        for seconds, microseconds, frame in self.records:
            out += struct.pack(
                "<IIII", seconds, microseconds, len(frame), len(frame)
            )
            out += frame
        return bytes(out)

    def write(self, path) -> None:
        from pathlib import Path

        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(self.to_bytes())


# ---------------------------------------------------------------------------
# SIP signalling
# ---------------------------------------------------------------------------


def sdp_offer_answer(
    address: str,
    port: int,
    payload_type: int,
    media_kind: str,
    codec_name: str,
    clock_rate: int,
    fmtp: str | None = None,
    extra_lines: list[str] | None = None,
) -> bytes:
    """A minimal session description that maps one payload type to one codec.

    ``media_kind`` is ``audio`` or ``video``. ``fmtp`` is emitted verbatim as
    ``a=fmtp:<pt> <fmtp>``, which is where the AMR ``octet-align=1`` and the
    H.264 ``sprop-parameter-sets`` hints live -- the two cases where the
    dissector cannot work the codec out from the payload type alone.
    """
    lines = [
        "v=0",
        f"o=- 1 1 IN IP4 {address}",
        "s=-",
        f"c=IN IP4 {address}",
        "t=0 0",
        f"m={media_kind} {port} RTP/AVP {payload_type}",
        f"a=rtpmap:{payload_type} {codec_name}/{clock_rate}",
    ]
    if fmtp:
        lines.append(f"a=fmtp:{payload_type} {fmtp}")
    if extra_lines:
        lines.extend(extra_lines)
    return ("\r\n".join(lines) + "\r\n").encode("ascii")


def sip_message(request_or_status: str, headers: list[tuple[str, str]], body: bytes = b"") -> bytes:
    lines = [request_or_status]
    lines.extend(f"{name}: {value}" for name, value in headers)
    lines.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body
