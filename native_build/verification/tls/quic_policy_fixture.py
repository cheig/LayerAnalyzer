#!/usr/bin/env python3
"""TLS-314 controlled DNS, UDP and real QUIC peers (test-only).

Install aioquic==1.3.0 in an ignored venv, then run with --host <LAN IPv4>.
UDP/443 multiplexes synthetic 'tls314-' echo payloads and actual QUIC. UDP/18053
answers only udp.tls314.example.invalid with 192.0.2.14; UDP/18081 is an echo.
TCP/18084 drives an aioquic Sans-I/O client: Android forwards its framed UDP
datagrams through a real device socket, returning replies. The client's TLS
certificate is verified against an ephemeral, in-memory fixture certificate.
No private keys, payloads or traffic belonging to other applications are logged.
"""
import argparse
import asyncio
import contextlib
import datetime
import json
import socket
import struct
import time

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.asyncio.server import QuicServer
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import HandshakeCompleted, StreamDataReceived
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

BODY = b"tls314-real-quic-stream-byte-equality"
NAME = "udp.tls314.example.invalid"
QNAME = b"".join(bytes([len(part)]) + part.encode() for part in NAME.split(".")) + b"\0"


def log(**values):
    print(json.dumps(values, sort_keys=True), flush=True)


class EchoQuic(QuicConnectionProtocol):
    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            self._quic.send_stream_data(event.stream_id, event.data, end_stream=event.end_stream)


class Multiplex(QuicServer):
    def datagram_received(self, data, addr):
        if data.startswith(b"tls314-"):
            self._transport.sendto(data, addr)
            log(kind="udp-echo", port=443, bytes=len(data))
        else:
            log(kind="quic-datagram", port=443, bytes=len(data))
            super().datagram_received(data, addr)


class UdpFixture(asyncio.DatagramProtocol):
    def __init__(self, dns=False):
        self.dns = dns

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if self.dns:
            question = QNAME + b"\0\1\0\1"
            if len(data) != 12 + len(question) or data[12:] != question:
                return
            answer = data[:2] + bytes.fromhex("81800001000100000000") + question
            answer += bytes.fromhex("c00c000100010000003c0004c000020e")
        elif data.startswith(b"tls314-"):
            answer = data
        else:
            return
        self.transport.sendto(answer, addr)
        log(kind="dns" if self.dns else "udp-echo", port=18053 if self.dns else 18081, bytes=len(data))


async def run_client(reader, writer, host, certificate):
    """One positive length = send UDP then receive; zero = receive only.
    A negative length terminates with that many JSON result bytes.
    Each Android receive is bounded at 200 ms; the QUIC deadline is 4 seconds.
    """
    config = QuicConfiguration(is_client=True, alpn_protocols=["tls314"], server_name=NAME)
    config.load_verify_locations(cadata=certificate.public_bytes(serialization.Encoding.PEM))
    client = QuicConnection(configuration=config)
    client.connect((host, 443), now=time.time())
    deadline = time.time() + 4
    handshaken = False
    received = bytearray()
    sent = 0
    try:
        while time.time() < deadline:
            timer = client.get_timer()
            if timer is not None and timer <= time.time():
                client.handle_timer(now=time.time())
            pending = client.datagrams_to_send(now=time.time())
            for data, _ in pending or [(b"", None)]:
                writer.write(struct.pack("!i", len(data)) + data)
                await writer.drain()
                sent += bool(data)
                size = struct.unpack("!i", await asyncio.wait_for(reader.readexactly(4), 3))[0]
                if not 0 <= size <= 65535:
                    raise ValueError("invalid datagram length")
                if size:
                    reply = await reader.readexactly(size)
                    client.receive_datagram(reply, (host, 443), now=time.time())
            while (event := client.next_event()) is not None:
                if isinstance(event, HandshakeCompleted):
                    handshaken = True
                    client.send_stream_data(0, BODY, end_stream=True)
                elif isinstance(event, StreamDataReceived):
                    received.extend(event.data)
            if bytes(received) == BODY:
                break
        result = dict(kind="quic-client", handshake=handshaken,
                      bodyEqual=bytes(received) == BODY, receivedBytes=len(received),
                      datagramsSent=sent, tcpFallback=False)
        body = json.dumps(result).encode()
        writer.write(struct.pack("!i", -len(body)) + body)
        await writer.drain()
        log(**result)
    finally:
        writer.close()
        # Android closes its control socket once the result arrives. Windows'
        # overlapped reader may observe that as a reset while closing.
        with contextlib.suppress(ConnectionError):
            await writer.wait_closed()


async def main(host):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, NAME)])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - datetime.timedelta(minutes=5))
                   .not_valid_after(now + datetime.timedelta(days=1))
                   .add_extension(x509.SubjectAlternativeName([x509.DNSName(NAME)]), False)
                   .sign(key, hashes.SHA256()))
    config = QuicConfiguration(is_client=False, alpn_protocols=["tls314"])
    config.certificate, config.private_key = certificate, key
    loop = asyncio.get_running_loop()
    transports = []
    try:
        for port, factory in [(443, lambda: Multiplex(configuration=config, create_protocol=EchoQuic)),
                              (18053, lambda: UdpFixture(dns=True)), (18081, UdpFixture)]:
            transport, _ = await loop.create_datagram_endpoint(factory, local_addr=(host, port), family=socket.AF_INET)
            transports.append(transport)
        server = await asyncio.start_server(lambda r, w: run_client(r, w, host, certificate), host, 18084)
        log(kind="ready", host=host, udpPorts=[18053, 443, 18081], controlPort=18084, aioquic="1.3.0")
        async with server:
            await server.serve_forever()
    finally:
        for transport in transports:
            transport.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    args = parser.parse_args()
    try:
        asyncio.run(main(args.host))
    except KeyboardInterrupt:
        pass
