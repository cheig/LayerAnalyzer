#!/usr/bin/env python3
"""Controlled UDP echo fixture for the TLS-214 device gate (UDP over HEV).

TLS-214 proved the loopback SOCKS hop now requires RFC 1929 authentication and
that the host-side UDP path reaches SOCKS; the missing evidence was a *device*
run showing UDP actually survives TUN -> HEV -> authenticated SOCKS. This fixture
is that missing controlled origin: it binds one UDP port and returns every
datagram verbatim to its sender, nothing else.

It is deliberately dependency-free (standard library only) so a device run needs
no extra host packages. Start it on the host, then run
`D=LiveCaptureForwardingTest` with `hostGateway`/`hostUdpPort` pointing at it:

    python native_build/verification/tls/udp_echo_fixture.py --port 18081

The script prints one line per datagram (peer, length) so a run can be audited
from its stdout, and exits cleanly on Ctrl-C or SIGTERM.
"""
from __future__ import annotations

import argparse
import socket
import sys


def parse_args(argv):
    parser = argparse.ArgumentParser(description="UDP echo fixture for the TLS-214 device gate")
    parser.add_argument("--host", default="0.0.0.0",
                        help="address to bind (default: 0.0.0.0, reachable from the device)")
    parser.add_argument("--port", type=int, default=18081, help="UDP port to echo on")
    parser.add_argument("--max-datagrams", type=int, default=0,
                        help="stop after this many datagrams (0 = run until interrupted)")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.port))
    print(f"udp-echo fixture listening on {args.host}:{args.port}", flush=True)

    served = 0
    try:
        while args.max_datagrams == 0 or served < args.max_datagrams:
            data, peer = sock.recvfrom(65535)
            sock.sendto(data, peer)
            served += 1
            print(f"echoed {len(data)} bytes to {peer[0]}:{peer[1]} (#{served})", flush=True)
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()
    print(f"udp-echo fixture stopped after {served} datagrams", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
