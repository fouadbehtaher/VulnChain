#!/usr/bin/env python3
"""VulnChain demo lab: a deliberately vulnerable app bound to 127.0.0.1 ONLY.

Intentional flaws (for assessment practice):
  - server + framework version disclosure in headers (SIMULATED banners; no
    real Apache or PHP is involved)
  - no security headers
  - directory listing on /backups/ leaking config.bak with credentials
  - exposed /.git/HEAD
  - login panel at /admin that accepts the leaked credentials and issues a
    session cookie; /admin/dashboard requires that session
  - dangerous methods advertised in OPTIONS; TRACE actually echoes
  - /redirect answers 302 to an out-of-scope host (scope-hardening test aid)

Run: python3 vulnerable_app.py [port]     (default 8899)
Never expose this app on a real interface.
"""

import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl

ADMIN_USER = "admin"
ADMIN_PASS = "s3cr3tP@ss"
SESSION = "vulnchain-lab-session"
FLAG = "FLAG{vulnchain_lab_admin_access}"

CONFIG_BAK = (
    "# backup of production config - DO NOT SHIP\n"
    "DB_HOST=127.0.0.1\nDB_USER=acme_app\nDB_PASS=Hunter2!\n"
    f"ADMIN_USER={ADMIN_USER}\nADMIN_PASS={ADMIN_PASS}\n"
    "API_TOKEN=tok_live_9f8e7d6c5b\n")


class LabHandler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.49 (Ubuntu)"   # simulated banner, not real Apache
    sys_version = ""

    def version_string(self):
        return self.server_version

    def _send(self, status, body, content_type="text/html", extra_headers=None):
        payload = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("X-Powered-By", "PHP/7.4.3")   # simulated, no real PHP
        self.send_header("Content-Length", str(len(payload)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)

    def _has_session(self):
        return SESSION in (self.headers.get("Cookie") or "")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, POST, PUT, DELETE, TRACE, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_TRACE(self):
        echo = f"{self.command} {self.path} {self.request_version}\n"
        echo += "".join(f"{k}: {v}\n" for k, v in self.headers.items())
        self._send(200, echo, "message/http")

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/":
            self._send(200, "<h1>Acme Corp</h1><p>Lab target for VulnChain.</p>")
        elif path == "/robots.txt":
            self._send(200, "User-agent: *\nDisallow: /backups/\nDisallow: /admin\n",
                       "text/plain")
        elif path == "/backups/":
            self._send(200, "<html><head><title>Index of /backups/</title></head>"
                            "<body><h1>Index of /backups/</h1>"
                            "<a href='config.bak'>config.bak</a></body></html>")
        elif path == "/backups/config.bak":
            self._send(200, CONFIG_BAK, "text/plain")
        elif path == "/.git/HEAD":
            self._send(200, "ref: refs/heads/main\n", "text/plain")
        elif path == "/.env":
            self._send(403, "Forbidden")
        elif path == "/admin":
            self._send(200, "<h1>Acme Admin</h1><form method='POST'>"
                            "<input name='username'><input name='password' "
                            "type='password'><button>Sign in</button></form>")
        elif path == "/admin/dashboard":
            if self._has_session():
                self._send(200, f"<h1>Admin Dashboard</h1><p>{FLAG}</p>")
            else:
                self._send(401, "<h1>Authentication required</h1>")
        elif path == "/redirect":
            self._send(302, "", extra_headers={
                "Location": "http://169.254.169.254/latest/meta-data"})
        else:
            self._send(404, "Not found")

    def do_POST(self):
        if self.path.split("?", 1)[0] != "/admin":
            self._send(404, "Not found")
            return
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        fields = dict(parse_qsl(body))
        if fields.get("username") == ADMIN_USER and fields.get("password") == ADMIN_PASS:
            self._send(200, f"<h1>Welcome, admin</h1><p>{FLAG}</p>",
                       extra_headers={"Set-Cookie": f"session={SESSION}; HttpOnly"})
        else:
            self._send(403, "<h1>Invalid credentials</h1>")

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8899
    server = ThreadingHTTPServer(("127.0.0.1", port), LabHandler)
    print(f"VulnChain lab on http://127.0.0.1:{port} (loopback only)")
    server.serve_forever()
