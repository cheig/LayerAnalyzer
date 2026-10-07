#!/usr/bin/env python3
"""合成 pcap 生成器（滚动性能基准用，T0 交付物 a）。

生成任意帧数的 Ethernet/IPv4 pcap，协议混合比例固定为
6 TCP : 2 UDP-DNS : 2 UDP-RTP，端口/源地址随帧号变化以产生真实感
（多会话、多主机，供统计/过滤/搜索/Expert 等扫描有真实工作量）。

用法:
    python scripts/gen_pcap.py <帧数> <输出路径>
    python scripts/gen_pcap.py 50000 jank50k.pcap

产出是合法的经典 pcap（magic=0xA1B2C3D4，network=1 Ethernet），
帧内带正确的 IPv4/UDP 校验和。TCP 校验和置 0，等价 IPv4 下的
checksum offload 场景，Wireshark 可正常解析；少量 SYN/重传/RST
混合其中，让 Expert Info / 统计扫描有真实内容可聚合。
"""
import random
import struct
import sys


def csum(data: bytes) -> int:
    """Internet checksum (RFC 1071)."""
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def ipv4_packet(src: bytes, dst: bytes, proto: int, payload: bytes,
                ident: int) -> bytes:
    hdr = struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(payload),
                      ident & 0xFFFF, 0x4000, 64, proto, 0) + src + dst
    check = csum(hdr)
    return hdr[:10] + struct.pack(">H", check) + hdr[12:] + payload


def udp_checksum(src: bytes, dst: bytes, udp_bytes: bytes) -> int:
    pseudo = src + dst + struct.pack(">BBH", 0, 17, len(udp_bytes))
    v = csum(pseudo + udp_bytes)
    return v if v else 0xFFFF


def dns_query(tid: int, name: str) -> bytes:
    q = struct.pack(">HHHHHH", tid & 0xFFFF, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    return q + b"\x00" + struct.pack(">HH", 1, 1)


def dns_response(tid: int, name: str, addr: bytes) -> bytes:
    q = struct.pack(">HHHHHH", tid & 0xFFFF, 0x8180, 1, 1, 0, 0)
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00" + struct.pack(">HH", 1, 1)
    # answer: 名称压缩指针 + A 记录
    q += struct.pack(">HHHIH", 0xC00C, 1, 1, 60, 4) + addr
    return q


ETH_SRC = bytes.fromhex("0200000000")
ETH_DST = bytes.fromhex("0200000001")


def eth_frame(src_ip: bytes, dst_ip: bytes, proto: int, payload: bytes,
              ident: int) -> bytes:
    return (ETH_DST + ETH_SRC + struct.pack(">H", 0x0800)
            + ipv4_packet(src_ip, dst_ip, proto, payload, ident))


def udp_frame(i: int, src: bytes, dst: bytes, sp: int, dp: int,
              payload: bytes) -> bytes:
    udp = struct.pack(">HHHH", sp, dp, 8 + len(payload), 0)
    check = udp_checksum(src, dst, udp + payload)
    udp = udp[:6] + struct.pack(">H", check)
    return eth_frame(src, dst, 17, udp + payload, i)


def build_tcp_frame(i: int, rng: random.Random) -> bytes:
    # 80 个并发 TCP 流，客户端 10.0.x.y，服务器 93.184.216.x
    stream = i % 80
    client = bytes([10, 0, stream % 40, (stream // 40) + 1])
    server = bytes([93, 184, 216, 34 + (stream % 16)])
    sport = 40000 + (stream % 2000)
    dport = 443 if stream % 3 else 80
    fwd = (i // 80) % 2 == 0
    src, dst = (client, server) if fwd else (server, client)
    sp, dp = (sport, dport) if fwd else (dport, sport)
    seq = (i * 97) & 0xFFFFFFFF
    ack = (i * 61) & 0xFFFFFFFF
    cycle = i % 50
    if cycle == 0:
        flags = 0x002 if fwd else 0x012   # SYN / SYN-ACK
    elif cycle == 1:
        flags = 0x010 | 0x004             # ACK+RST（少量，供 Expert/统计）
    else:
        flags = 0x018                     # PSH+ACK
    payload = bytes(rng.randrange(256) for _ in range(rng.choice((0, 0, 60, 200, 900))))
    tcp = struct.pack(">HHIIBBHHH", sp, dp, seq, ack, 5 << 4, flags, 65535, 0, 0)
    return eth_frame(src, dst, 6, tcp + payload, i)


def build_dns_frame(i: int, rng: random.Random) -> bytes:
    stream = i % 40
    client = bytes([10, 0, stream % 40, (stream // 40) + 1])
    server = bytes([8, 8, 8, 8])
    fwd = (i // 40) % 2 == 0
    name = f"host{i % 500}.example{i % 37}.com"
    tid = 0x1000 + (i % 60000)
    if fwd:
        payload = dns_query(tid, name)
        return udp_frame(i, client, server, 50000 + (i % 1000), 53, payload)
    payload = dns_response(tid, name, bytes([192, 168, i % 250, (i * 7) % 250 + 1]))
    return udp_frame(i, server, client, 53, 50000 + (i % 1000), payload)


def build_rtp_frame(i: int, rng: random.Random) -> bytes:
    stream = i % 20
    client = bytes([10, 0, stream % 40, (stream // 40) + 1])
    server = bytes([172, 16, 5, 10 + (stream % 8)])
    fwd = (i // 20) % 2 == 0
    sp, dp = (30000 + stream * 2, 16384 + stream * 2) if fwd else (16384 + stream * 2, 30000 + stream * 2)
    src, dst = (client, server) if fwd else (server, client)
    # RTP v2, PT=0 (PCMU)，序列号/时间戳随帧推进
    rtp = struct.pack(">BBHII", 0x80, 0, i & 0xFFFF, (i * 160) & 0xFFFFFFFF,
                      0xDEAD0000 + stream)
    payload = rtp + bytes(rng.randrange(256) for _ in range(160))
    return udp_frame(i, src, dst, sp, dp, payload)


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    count = int(sys.argv[1])
    out_path = sys.argv[2]
    if count <= 0:
        print("帧数必须为正整数", file=sys.stderr)
        return 2

    rng = random.Random(20260810)
    base_ts = 1_754_800_000  # 固定基准时间，保证输出可复现
    with open(out_path, "wb") as f:
        # 全局头：magic(LE) + v2.4 + snaplen 65535 + network=1(Ethernet)
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i in range(count):
            mod = i % 10
            if mod < 6:
                frame = build_tcp_frame(i, rng)
            elif mod < 8:
                frame = build_dns_frame(i, rng)
            else:
                frame = build_rtp_frame(i, rng)
            ts = base_ts + i // 1000
            usec = (i % 1000) * 1000
            f.write(struct.pack("<IIII", ts, usec, len(frame), len(frame)))
            f.write(frame)
    print(f"wrote {count} frames -> {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
