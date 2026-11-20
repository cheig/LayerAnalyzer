"""TLS-403 fixed, non-sensitive HTTP origin for real VPN lifecycle checks.

Plain HTTP deliberately exercises the production TLS engine's not_tls path.
It is not evidence of MITM decryption or a long TLS stream.
"""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BODY = b"LayerAnalyzer TLS-403 controlled recovery body\n"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = BODY * 8192 if self.path == "/bulk" else BODY
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", required=True)
    parser.add_argument("--port", type=int, default=18403)
    args = parser.parse_args()
    ThreadingHTTPServer((args.bind, args.port), Handler).serve_forever()
