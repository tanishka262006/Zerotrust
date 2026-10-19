"""A tiny 'private' app. Bound to 127.0.0.1 only: unreachable except through the connector."""
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

name, port = sys.argv[1], int(sys.argv[2])


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"[{name.upper()}] private data, only reachable via the broker\n".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


HTTPServer(("127.0.0.1", port), H).serve_forever()
