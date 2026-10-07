#!/usr/bin/env python3
"""Deterministic pcap fixture generator for LayerAnalyzer behavior baselines.

Generates the fixed captures the native refactor baseline depends on:

  golden_multi.pcap     small multi-protocol capture (TCP, DNS, HTTP, TLS,
                        SIP/SDP, RTP) used as the byte/JSON diff fixture
  stress_50k.pcap       50,000 frames of the repeated mixed block
  stress_500k.pcap      500,000 frames
  stress_1m.pcap        1,000,000 frames
  truncated.pcap        same flow set with captured length cut below the
                        original length (exercises caplen < len handling)
  corrupt.pcap          frames with flipped payload bytes, a zeroed IP
                        version nibble and a bogus final record (exercises
                        the per-frame Wireshark exception boundary)
  mixed_encap.pcapng    pcapng with two interfaces (Ethernet + raw IPv4) so
                        single-file mixed encapsulation can be tested; the
                        classic-pcap export path must reject this capture

All output is byte-deterministic: no randomness, fixed timestamps.

Usage:
  python tools/pcapgen.py --out-dir fixtures [--skip-1m]
"""

import argparse
import os
import struct

TS_BASE = 1700000000  # fixed epoch second so captures are reproducible
USEC_STEP = 1000      # 1 ms between frames

MAC_A = b"\x02\x00\x00\x00\x00\x01"
MAC_B = b"\x02\x00\x00\x00\x00\x02"

IP_A = "10.0.0.1"
IP_B = "10.0.0.2"


# --------------------------------------------------------------------------
# Low-level packet builders (IPv4 checksums computed, UDP/TCS checksums real)
# --------------------------------------------------------------------------

def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ipv4(src: str, dst: str, proto: int, payload: bytes, ident: int) -> bytes:
    def to_bytes(ip: str) -> bytes:
        return bytes(int(p) for p in ip.split("."))
    total_len = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0x00, total_len, ident & 0xFFFF, 0x4000,
        64, proto, 0, to_bytes(src), to_bytes(dst),
    )
    header = header[:10] + struct.pack("!H", _checksum(header)) + header[12:]
    return header + payload


def _udp(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    header = struct.pack("!HHHH", sport, dport, length, 0)
    pseudo = (
        bytes(int(p) for p in src.split("."))
        + bytes(int(p) for p in dst.split("."))
        + struct.pack("!BBH", 0, 17, length)
    )
    checksum = _checksum(pseudo + header + payload) or 0xFFFF
    header = header[:6] + struct.pack("!H", checksum)
    return header + payload


def _tcp(src: str, dst: str, sport: int, dport: int, seq: int, ack: int,
         flags: int, payload: bytes = b"") -> bytes:
    header = struct.pack(
        "!HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, 8192, 0, 0
    )
    pseudo = (
        bytes(int(p) for p in src.split("."))
        + bytes(int(p) for p in dst.split("."))
        + struct.pack("!BBH", 0, 6, 20 + len(payload))
    )
    checksum = _checksum(pseudo + header + payload)
    header = header[16:18] + struct.pack("!H", checksum) + header[18:]
    return header + payload


def _eth(payload: bytes, ethertype: int = 0x0800) -> bytes:
    return MAC_B + MAC_A + struct.pack("!H", ethertype) + payload


FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


# --------------------------------------------------------------------------
# Protocol flow builders; every builder yields (frame_bytes, orig_len) pairs
# --------------------------------------------------------------------------

def tcp_handshake(sport, dport, ident=0):
    return [
        _eth(_ipv4(IP_A, IP_B, 6, _tcp(IP_A, IP_B, sport, dport, 1000, 0, SYN), ident)),
        _eth(_ipv4(IP_B, IP_A, 6, _tcp(IP_B, IP_A, dport, sport, 5000, 1001, SYN | ACK), ident)),
        _eth(_ipv4(IP_A, IP_B, 6, _tcp(IP_A, IP_B, sport, dport, 1001, 5001, ACK), ident)),
    ]


def dns_exchange(ident):
    # Query: example.com A
    qname = b"".join(bytes([len(p)]) + p.encode() for p in "example.com".split(".")) + b"\x00"
    query = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)
    # Response: 93.184.216.34
    answer = qname + struct.pack("!HHIH4s", 1, 1, 300, 4, bytes([93, 184, 216, 34]))
    response = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) + qname + struct.pack("!HH", 1, 1) + answer
    return [
        _eth(_ipv4(IP_A, IP_B, 17, _udp(IP_A, IP_B, 40000 + ident % 1000, 53, query), ident)),
        _eth(_ipv4(IP_B, IP_A, 17, _udp(IP_B, IP_A, 53, 40000 + ident % 1000, response), ident)),
    ]


def http_exchange(ident):
    frames = tcp_handshake(41000 + ident % 1000, 80, ident)
    request = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: layanalyzer-baseline\r\n\r\n"
    response = (b"HTTP/1.1 200 OK\r\nServer: baseline\r\nContent-Type: text/plain\r\n"
                b"Content-Length: 6\r\n\r\nhello!")
    frames.append(_eth(_ipv4(IP_A, IP_B, 6, _tcp(IP_A, IP_B, 41000 + ident % 1000, 80,
                                                 1001, 5001, PSH | ACK, request), ident)))
    frames.append(_eth(_ipv4(IP_B, IP_A, 6, _tcp(IP_B, IP_A, 80, 41000 + ident % 1000,
                                                 5001, 1001 + len(request), PSH | ACK, response), ident)))
    return frames


def tls_exchange(ident):
    frames = tcp_handshake(42000 + ident % 1000, 443, ident)
    # Minimal valid TLS 1.2 ClientHello / ServerHello records.
    client_hello = bytes.fromhex(
        "1603010035" "010000310303" + "11" * 32 + "00"
        "0002000a" "00080005000400170013" "0100"
    )
    server_hello = bytes.fromhex(
        "160303002f" "0200002b0303" + "22" * 32 + "00"
        "0002000a" "0000"
    )
    frames.append(_eth(_ipv4(IP_A, IP_B, 6, _tcp(IP_A, IP_B, 42000 + ident % 1000, 443,
                                                 1001, 5001, PSH | ACK, client_hello), ident)))
    frames.append(_eth(_ipv4(IP_B, IP_A, 6, _tcp(IP_B, IP_A, 443, 42000 + ident % 1000,
                                                 5001, 1001 + len(client_hello), PSH | ACK, server_hello), ident)))
    return frames


def sip_exchange(ident, rtp_packets=4):
    frames = []
    sip_body = (
        "v=0\r\n"
        "o=baseline 1 1 IN IP4 10.0.0.1\r\n"
        "s=baseline-call\r\n"
        "c=IN IP4 10.0.0.1\r\n"
        "t=0 0\r\n"
        "m=audio 5004 RTP/AVP 0\r\n"
        "a=rtpmap:0 PCMU/8000\r\n"
        "a=sendrecv\r\n"
    )
    invite = (
        "INVITE sip:bob@example.com SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-baseline\r\n"
        "From: <sip:alice@example.com>;tag=alice-tag\r\n"
        "To: <sip:bob@example.com>\r\n"
        "Call-ID: baseline-call-id@example.com\r\n"
        "CSeq: 1 INVITE\r\n"
        "Content-Type: application/sdp\r\n"
        "Content-Length: %d\r\n\r\n%s"
    ) % (len(sip_body), sip_body)
    trying = (
        "SIP/2.0 100 Trying\r\n"
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-baseline\r\n"
        "From: <sip:alice@example.com>;tag=alice-tag\r\n"
        "To: <sip:bob@example.com>\r\n"
        "Call-ID: baseline-call-id@example.com\r\n"
        "CSeq: 1 INVITE\r\n\r\n"
    )
    ok = (
        "SIP/2.0 200 OK\r\n"
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-baseline\r\n"
        "From: <sip:alice@example.com>;tag=alice-tag\r\n"
        "To: <sip:bob@example.com>;tag=bob-tag\r\n"
        "Call-ID: baseline-call-id@example.com\r\n"
        "CSeq: 1 INVITE\r\n\r\n"
    )
    ack = (
        "ACK sip:bob@example.com SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-baseline\r\n"
        "Call-ID: baseline-call-id@example.com\r\n"
        "CSeq: 1 ACK\r\n\r\n"
    )
    for text in (invite, trying, ok, ack):
        frames.append(_eth(_ipv4(IP_A, IP_B, 17,
                                 _udp(IP_A, IP_B, 5060, 5060, text.encode()), ident)))
    # RTP: PT 0 (PCMU), incrementing sequence/timestamp, 160-byte silence payload
    for seq in range(rtp_packets):
        rtp = struct.pack("!BBHII", 0x80, 0, seq & 0xFFFF, seq * 160, 0x1234ABCD) + b"\xd5" * 160
        frames.append(_eth(_ipv4(IP_A, IP_B, 17,
                                 _udp(IP_A, IP_B, 5004, 5004, rtp), ident + 1 + seq)))
    return frames


def block(ident):
    """One mixed-protocol block; the stress captures repeat this block."""
    frames = []
    frames += dns_exchange(ident)
    frames += http_exchange(ident)
    frames += tls_exchange(ident)
    frames += sip_exchange(ident)
    return frames


# --------------------------------------------------------------------------
# Writers
# --------------------------------------------------------------------------

def write_pcap(path, frames, truncate_at=None):
    """frames: list of raw frame bytes. truncate_at: fraction (0,1] applied to
    a deterministic subset to exercise caplen < orig len."""
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, frame in enumerate(frames):
            orig_len = len(frame)
            incl_len = orig_len
            if truncate_at is not None and i % 5 == 2:
                incl_len = max(14, int(orig_len * truncate_at))
                frame = frame[:incl_len]
            ts = TS_BASE + (i * USEC_STEP) // 1_000_000
            usec = (i * USEC_STEP) % 1_000_000
            f.write(struct.pack("<IIII", ts, usec, incl_len, orig_len))
            f.write(frame)


def write_pcapng_mixed(path, frames):
    """Write a pcapng with the odd-indexed frames on a raw-IPv4 interface and
    the rest on Ethernet, producing one file with mixed encapsulation."""
    def block(body_type, body, options=b""):
        total = 12 + len(body) + len(options)
        return struct.pack("<IIII", 0x0A0D0D0A, total, body_type, len(body) + len(options)) + body + options

    shb = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb_eth = block(0x00000001, struct.pack("<HHI", 1, 0, 262144))
    idb_raw = block(0x00000001, struct.pack("<HHI", 101, 0, 262144))
    with open(path, "wb") as f:
        f.write(shb + idb_eth + idb_raw)
        for i, frame in enumerate(frames):
            iface = 1 if i % 2 else 0
            payload = frame if iface == 0 else frame[14:]
            ts = ((TS_BASE + (i * USEC_STEP) // 1_000_000) << 32) | ((i * USEC_STEP) % 1_000_000) * 1_000_000 // 1_000_000
            pad = (-len(payload)) % 4
            epb_body = struct.pack("<IIIII", iface, ts >> 32, ts & 0xFFFFFFFF,
                                   len(frame), len(frame)) + payload + b"\x00" * pad
            f.write(block(0x00000006, epb_body))


def corrupt(frames):
    """Return a corrupted copy: flipped payload bytes, a zeroed IP version
    nibble, and a trailing garbage record."""
    out = []
    for i, frame in enumerate(frames):
        buf = bytearray(frame)
        if i % 4 == 1 and len(buf) > 40:
            buf[-3] ^= 0xFF
        if i % 7 == 3:
            buf[14] &= 0x0F  # zero the IP version nibble
        if i % 11 == 5:
            buf[14 + 8] = 0xFF  # corrupt TTL/flags region
        out.append(bytes(buf))
    out.append(b"\xde\xad\xbe\xef" * 8)  # unrecognized trailing record
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", default="fixtures")
    parser.add_argument("--skip-1m", action="store_true",
                        help="skip the 1M-frame stress capture (slow)")
    args = parser.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    out = lambda name: os.path.join(args.out_dir, name)

    golden = block(ident=0)
    write_pcap(out("golden_multi.pcap"), golden)
    print(f"golden_multi.pcap: {len(golden)} frames")

    for name, count in (("stress_50k.pcap", 50_000),
                        ("stress_500k.pcap", 500_000),
                        ("stress_1m.pcap", 1_000_000)):
        if name == "stress_1m.pcap" and args.skip_1m:
            print("stress_1m.pcap: skipped (--skip-1m)")
            continue
        frames = []
        while len(frames) < count:
            frames += block(ident=len(frames) // 24 + 1)
        del frames[count:]
        write_pcap(out(name), frames)
        print(f"{name}: {count} frames")

    write_pcap(out("truncated.pcap"), golden, truncate_at=0.6)
    print(f"truncated.pcap: {len(golden)} frames (subset truncated)")

    write_pcap(out("corrupt.pcap"), corrupt(golden))
    print(f"corrupt.pcap: {len(golden) + 1} frames (corrupted)")

    write_pcapng_mixed(out("mixed_encap.pcapng"), golden)
    print(f"mixed_encap.pcapng: {len(golden)} frames over 2 interfaces")


if __name__ == "__main__":
    main()
