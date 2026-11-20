"""Negative controls for the gate, not Android runtime/TUN evidence."""
import tempfile
import base64
import copy
import hashlib
import json
import struct
from pathlib import Path
import unittest
from summarize_probe import ABIS, BODY, BODY_SHA, FIXTURES, REQUIRED, summarize


class GateTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "arm64-v8a").mkdir()

    def write(self, text):
        (self.root / "arm64-v8a" / "test.xml").write_text(text, encoding="utf-8")

    def test_missing_results_fail(self):
        result = summarize(self.root)
        self.assertFalse(result["gatePassed"])
        self.assertFalse(result["tunMatrixPassed"])

    def test_required_skip_is_not_pass(self):
        self.write('<testsuite tests="1" skipped="1"><testcase classname="com.example.layanalyzer.TlsTunEndToEndProbeTest" name="tls12H1Tun"><skipped/></testcase></testsuite>')
        result = summarize(self.root)
        counts = result["abis"]["arm64-v8a"]["tests"]["TlsTunEndToEndProbeTest"]
        self.assertEqual(1, counts["skipped"])
        self.assertEqual(0, counts["passed"])
        self.assertFalse(result["gatePassed"])

    def test_duplicate_stale_xml_is_rejected(self):
        case = '<testcase classname="com.example.layanalyzer.TlsTunEndToEndProbeTest" name="tls12H1Tun"/>'
        self.write('<testsuite>' + case + case + '</testsuite>')
        self.assertTrue(summarize(self.root)["abis"]["arm64-v8a"]["errors"])

    def test_passing_xml_does_not_replace_capture(self):
        self.write('<testsuite>' + ''.join(f'<testcase classname="com.example.layanalyzer.TlsTunEndToEndProbeTest" name="case{i}"/>' for i in range(4)) + '</testsuite>')
        result = summarize(self.root)
        self.assertEqual(4, result["abis"]["arm64-v8a"]["tests"]["TlsTunEndToEndProbeTest"]["passed"])
        self.assertFalse(result["tunMatrixPassed"])

    def test_malformed_xml_is_rejected(self):
        self.write('<testsuite>')
        self.assertTrue(summarize(self.root)["abis"]["arm64-v8a"]["errors"])

    def complete_parser_sample(self):
        # Deliberately synthetic parser inputs, never published as device evidence.
        # Required passing XML plus both ABI reports exercise the success branch.
        header = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101)
        pcap = bytearray(header)
        for index in range(6):
            packet = bytearray(20)
            packet[0] = 0x45
            offset = 12 if index % 2 else 16
            packet[offset:offset + 4] = bytes((198, 18, 0, 8))
            pcap.extend(struct.pack('<IIII', 0, 0, len(packet), len(packet)) + packet)
        for abi in ABIS:
            directory = self.root / abi
            directory.mkdir(exist_ok=True)
            cases = []
            for cls, count in REQUIRED.items():
                names = (('tls12H1Tun', 'tls13H1Tun', 'tls13H2Tun', 'socksConnectPreservesReadAhead')
                         if cls == 'TlsTunEndToEndProbeTest' else [f'case{i}' for i in range(count)])
                cases.extend(f'<testcase classname="com.example.layanalyzer.{cls}" name="{name}"/>' for name in names)
            (directory / 'test.xml').write_text('<testsuite>' + ''.join(cases) + '</testsuite>')
            for fixture in FIXTURES:
                target = directory / 'evidence' / fixture
                target.mkdir(parents=True)
                data = dict(schemaVersion=1, fixtureId=fixture, complete=True, abi=abi, api=26,
                    captureMethod='Android VpnService TUN / original packet relay', embeddedVersion='4.0.10',
                    fdRecovered=True, fdFinal=10, fdBaseline=10, routeReleaseMillis=100, stopMillis=200,
                    prepareCalls=1, droppedPacketCount=0, tunPcapBytes=len(pcap), packetCount=6,
                    client=dict(success=True, gatewayReady=True, upstreamVerified=True, configReplaced=True,
                        downstreamHandshake=True, bodySha256=BODY_SHA, tlsVersion=771 if fixture == 'tls12-h1' else 772,
                        alpn='h2' if fixture == 'tls13-h2' else 'http/1.1', downstreamClientRandom='a', upstreamClientRandom='b'))
                for name, field, content in (('capture.pcap', 'tunPcapSha256', pcap),
                    ('tls-a.keys', 'tlsAKeylogSha256', b'parser-sample-a'), ('tls-b.keys', 'tlsBKeylogSha256', b'parser-sample-b')):
                    (target / name).write_bytes(content)
                    data[field] = hashlib.sha256(content).hexdigest()
                for phase in ('empty', 'tlsB', 'tlsA', 'clear', 'reload'):
                    decrypted = phase in ('tlsA', 'reload')
                    data[phase] = dict(schemaVersion=1, success=True, errorCode=None, error=None, preferenceCleared=True, epanRebuilt=True,
                        scan=dict(bodySha256=BODY_SHA if decrypted else '', bodyBytes=29 if decrypted else 0,
                            frames=6, tcpStreams=1, tapName='tls', withTaps=True,
                            records=[dict(bytesBase64=base64.b64encode(BODY).decode(), byteLength=len(BODY),
                                frameNumber=6, fromServer=True)] if decrypted else [], directionKnown=decrypted,
                            sources=[dict(name='Decrypted TLS', frameNumber=6, id='decrypted', byteLength=29)] if decrypted else [],
                            bodyFields=[dict(offsetValid=True, dataSourceId='decrypted', frameNumber=6, start=0, length=29,
                                field='http2.data.data' if fixture == 'tls13-h2' else 'http.file_data')] if decrypted else []))
                (target / 'report.json').write_text(json.dumps(data))

    def test_complete_parser_matrix_and_tampering(self):
        self.complete_parser_sample()
        self.assertTrue(summarize(self.root)['gatePassed'])
        report = self.root / 'x86_64/evidence/tls13-h2/report.json'
        original = json.loads(report.read_text())
        mutations = (
            lambda d: d.update(complete=False),
            lambda d: d.update(packetCount=7),
            lambda d: d.update(tunPcapSha256='bad'),
            lambda d: d.update(tlsAKeylogSha256='bad'),
            lambda d: d['client'].update(upstreamVerified=False),
            lambda d: d['client'].update(alpn='http/1.1'),
            lambda d: d['clear']['scan'].update(bodyBytes=29),
            lambda d: d['tlsA']['scan']['bodyFields'][0].update(dataSourceId='raw'),
            lambda d: d['tlsA']['scan']['bodyFields'][0].update(start=1),
            lambda d: d['tlsA']['scan'].update(sources=[]),
            lambda d: d['tlsA']['scan']['records'][0].update(fromServer=False),
            lambda d: d['tlsA']['scan']['records'][0].update(bytesBase64='invalid'),
            lambda d: d['tlsA']['scan'].update(withTaps=False),
            lambda d: d['clear']['scan'].update(sources=[dict(name='Decrypted TLS')]),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                data = copy.deepcopy(original)
                mutate(data)
                report.write_text(json.dumps(data))
                self.assertFalse(summarize(self.root)['gatePassed'])
        report.write_text(json.dumps(original))
        pcap = report.with_name('capture.pcap')
        pcap.write_bytes(pcap.read_bytes()[:-1])
        original['tunPcapSha256'] = hashlib.sha256(pcap.read_bytes()).hexdigest()
        original['tunPcapBytes'] = pcap.stat().st_size
        report.write_text(json.dumps(original))
        self.assertFalse(summarize(self.root)['gatePassed'])

    def test_skip_rejects_otherwise_complete_matrix(self):
        self.complete_parser_sample()
        xml = self.root / 'arm64-v8a/test.xml'
        xml.write_text(xml.read_text().replace('name="tls12H1Tun"/>', 'name="tls12H1Tun"><skipped/></testcase>'))
        self.assertFalse(summarize(self.root)['gatePassed'])


if __name__ == '__main__': unittest.main()
