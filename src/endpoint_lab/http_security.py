import json
import socket
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from .limits import DEFAULT, InputError


class LocalServer(HTTPServer):
    allow_reuse_address = True

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(10)
        return connection, address

    def handle_error(self, request, client_address):
        pass


class SecureHandler(BaseHTTPRequestHandler):
    server_version = "EndpointLab"
    sys_version = ""

    def log_message(self, format, *args):
        pass

    @property
    def origin(self):
        return f"http://127.0.0.1:{self.server.server_port}"

    def host_valid(self):
        return self.headers.get_all("Host", []) == [self.origin[7:]]

    def respond(self, status, body, content_type="application/json; charset=utf-8"):
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()
        if self.command == "POST" and not getattr(self, "body_consumed", False):
            try:
                self.connection.shutdown(socket.SHUT_WR)
                self.connection.settimeout(0.05)
                self.rfile.read1(65536)
            except (OSError, TimeoutError):
                pass

    def json(self, status, value):
        self.respond(status, json.dumps(value, ensure_ascii=True).encode(), "application/json; charset=utf-8")

    def read_body(self):
        if self.headers.get("Transfer-Encoding"):
            raise InputError("Transfer encoding is not supported.")
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1 or len(lengths[0]) > 10 or not lengths[0].isascii() or not lengths[0].isdecimal():
            raise InputError("One valid Content-Length is required.")
        remaining = int(lengths[0])
        if remaining > DEFAULT.file_bytes:
            raise InputError("Log file exceeds 8 MiB.")
        if self.headers.get("Content-Type") != "application/octet-stream":
            raise InputError("Expected application/octet-stream.")
        chunks, deadline = [], time.monotonic() + 20
        while remaining:
            budget = deadline - time.monotonic()
            if budget <= 0:
                raise TimeoutError
            self.connection.settimeout(min(10, budget))
            chunk = self.rfile.read1(min(65536, remaining))
            if not chunk:
                raise InputError("Truncated request body.")
            chunks.append(chunk)
            remaining -= len(chunk)
        self.body_consumed = True
        return b"".join(chunks)
