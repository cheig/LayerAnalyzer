#!/usr/bin/env python3
"""TLS-005 controlled TCP fixture. No TLS, user traffic, secrets, or proxying."""
import argparse
import ipaddress
import socket
import struct


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", required=True, help="Explicit controlled LAN IPv4/IPv6 address")
    parser.add_argument("--port", required=True, type=int)
    args = parser.parse_args()
    address = ipaddress.ip_address(args.bind)
    if not 1 <= args.port <= 65535:
        parser.error("port must be 1..65535")
    with socket.socket(socket.AF_INET if address.version == 4 else socket.AF_INET6) as listener:
        if address.version == 6:
            listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        listener.bind((str(address), args.port))
        listener.listen(16)
        print("READY LAS1", flush=True)
        sequence = 0
        try:
            while True:
                conn, _ = listener.accept()
                sequence += 1
                with conn:
                    conn.settimeout(1)
                    try:
                        conn.sendall(b"LAS1" + struct.pack("!I", sequence))
                    except OSError:
                        pass  # Still count an accepted connection even if peer abandoned it.
        except KeyboardInterrupt:
            print(f"STOP accepted={sequence}", flush=True)


if __name__ == "__main__":
    main()
