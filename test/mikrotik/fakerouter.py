#!/usr/bin/env python3
"""fakerouter.py - a MikroTik that is not there, for the tests (and for trying the pages by hand).

  python3 fakerouter.py rest PORT CERT KEY      RouterOS 7's REST API over HTTPS (GET /rest/...)
  python3 fakerouter.py api PORT CERT KEY       the RouterOS API over TLS (api-ssl): /login, <menu>/print
  python3 fakerouter.py plainapi PORT           the RouterOS API without TLS (api, 8728)

Each serves fixture.py's router to the account fake-igd-read / its password "read-only-please". Anything but
a read - a POST, PUT, PATCH or DELETE over REST; anything but /login and a print over the API - is answered
as RouterOS refuses it AND written to the file FAKE_ROUTER_WRITES (one line each): the tests look there to
prove fake-igd never sends one. Every request is written to FAKE_ROUTER_LOG.
"""
import base64
import json
import os
import socket
import socketserver
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fixture   # noqa: E402

USER, PASSWORD = "fake-igd-read", "read-only-please"
ROUTER = fixture.router()


def note(kind, words):
    path = os.environ.get("FAKE_ROUTER_WRITES" if kind == "write" else "FAKE_ROUTER_LOG")
    if path:
        with open(path, "a") as f:
            f.write(words + "\n")


class Rest(BaseHTTPRequestHandler):
    server_version = "MikroTik"
    sys_version = ""

    def log_message(self, *a):
        pass

    def _auth(self):
        h = self.headers.get("Authorization") or ""
        if not h.startswith("Basic "):
            return None
        try:
            user, _, pw = base64.b64decode(h[6:]).decode().partition(":")
        except ValueError:
            return None
        return user if (user, pw) == (USER, PASSWORD) else None

    def _answer(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        note("log", "REST GET %s %s" % (self.path, "auth" if self.headers.get("Authorization") else "-"))
        if not self._auth():
            return self._answer(401, {"error": 401, "message": "Unauthorized"})
        path = self.path.split("?", 1)[0]
        if not path.startswith("/rest/"):
            return self._answer(404, {"error": 404, "message": "Not Found"})
        menu = path[5:].rstrip("/")
        if menu not in ROUTER:
            return self._answer(400, {"error": 400, "message": "Bad Request", "detail": "no such command"})
        got = ROUTER[menu]
        if menu in ("/system/identity", "/system/resource", "/system/routerboard", "/ip/upnp",
                    "/ip/firewall/connection/tracking"):
            return self._answer(200, got[0] if got else {})
        return self._answer(200, got)

    def _write(self):
        note("write", "REST %s %s" % (self.command, self.path))
        self._answer(403, {"error": 403, "message": "Forbidden", "detail": "not enough permissions"})

    do_POST = do_PUT = do_PATCH = do_DELETE = _write


def encode_length(n):
    if n < 0x80:
        return bytes([n])
    if n < 0x4000:
        return (n | 0x8000).to_bytes(2, "big")
    return (n | 0xC00000).to_bytes(3, "big")


class Api(socketserver.StreamRequestHandler):
    def word(self):
        b = self.rfile.read(1)
        if not b:
            raise EOFError
        n = b[0]
        if n & 0x80 == 0x00:
            pass
        elif n & 0xC0 == 0x80:
            n = ((n & 0x3F) << 8) | self.rfile.read(1)[0]
        elif n & 0xE0 == 0xC0:
            n = ((n & 0x1F) << 16) | int.from_bytes(self.rfile.read(2), "big")
        else:
            n = ((n & 0x0F) << 24) | int.from_bytes(self.rfile.read(3), "big")
        return self.rfile.read(n).decode()

    def sentence(self):
        out = []
        while True:
            w = self.word()
            if w == "":
                return out
            out.append(w)

    def send(self, words):
        self.wfile.write(b"".join(encode_length(len(w.encode())) + w.encode() for w in words) + b"\x00")

    def handle(self):
        signed = False
        try:
            while True:
                s = self.sentence()
                if not s:
                    continue
                cmd, args = s[0], {w[1:].partition("=")[0]: w[1:].partition("=")[2] for w in s[1:] if w.startswith("=")}
                note("log", "API %s" % " ".join(s[:1] + [w for w in s[1:] if not w.startswith("=password")]))
                if cmd == "/login":
                    if (args.get("name"), args.get("password")) == (USER, PASSWORD):
                        signed = True
                        self.send(["!done"])
                    else:
                        self.send(["!trap", "=message=invalid user name or password (6)"])
                        self.send(["!done"])
                    continue
                if not signed:
                    self.send(["!fatal", "not logged in"])
                    return
                if not cmd.endswith("/print"):
                    note("write", "API %s" % " ".join(s))
                    self.send(["!trap", "=message=not enough permissions (9)"])
                    self.send(["!done"])
                    continue
                menu = cmd[:-6]
                if menu not in ROUTER:
                    self.send(["!trap", "=message=no such command prefix"])
                    self.send(["!done"])
                    continue
                for e in ROUTER[menu]:
                    self.send(["!re"] + ["=%s=%s" % kv for kv in e.items()])
                self.send(["!done"])
        except (EOFError, OSError, IndexError):
            return


class TlsServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass

    def __init__(self, addr, handler, ctx=None):
        super().__init__(addr, handler)
        self.ctx = ctx

    def get_request(self):
        sock, addr = super().get_request()
        if self.ctx is not None:
            sock = self.ctx.wrap_socket(sock, server_side=True)
        return sock, addr


class Quiet(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        pass                                # a client that hung up after the handshake (a pin refused)


def serve(kind, port, cert=None, key=None, background=False):
    ctx = None
    if cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
    if kind == "rest":
        srv = Quiet(("127.0.0.1", port), Rest)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True) if ctx else srv.socket
    else:
        srv = TlsServer(("127.0.0.1", port), Api, ctx)
    if background:
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv
    srv.serve_forever()


if __name__ == "__main__":
    k = sys.argv[1]
    serve("api" if k == "plainapi" else k, int(sys.argv[2]), *(sys.argv[3:5] if k != "plainapi" else (None, None)))
