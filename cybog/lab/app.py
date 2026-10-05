#!/usr/bin/env python3
"""
CYBOG Lab — intentionally vulnerable local web target.

Stdlib-only HTTP server on 127.0.0.1:8080. Deliberately exposes secrets and
carries NO security headers, so the upstream toolchain (nuclei etc.) produces
real, findable findings. Local lab only — do not expose beyond loopback.
"""
import http.server
import socketserver
import sys

HOST = "127.0.0.1"
PORT = 8080

ROOT_HTML = """<!DOCTYPE html>
<html>
<head><title>CYBOG Lab</title></head>
<body>
<h1>CYBOG Lab</h1>
<p>This is the CYBOG local E2E lab target. It is intentionally insecure.</p>
<ul>
  <li><a href="/admin">Admin</a></li>
  <li><a href="/robots.txt">robots.txt</a></li>
</ul>
</body>
</html>
"""

GIT_CONFIG = """[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
[remote "origin"]
\turl = https://github.com/cybangorg/cybang-lab.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
"""

ENV_FILE = """# CYBOG Lab environment (FAKE — for detection testing only)
APP_ENV=production
APP_SECRET=fake123
DATABASE_URL=mysql://root:SuperSecretPass42!@10.0.0.5:3306/cybangdb
AWS_ACCESS_KEY_ID=AKIAFAKE0EXAMPLE
AWS_SECRET_ACCESS_KEY=fakeawssecret0000000000000000000000
API_KEY=pk-live-fake1234567890
"""

SQL_BACKUP = """-- MySQL dump 10.13  Distrib 8.0.33
-- host: 10.0.0.5    Database: cybangdb
--
USE cybangdb;
CREATE TABLE users (id INT, username VARCHAR(64), email VARCHAR(128));
INSERT INTO users VALUES (1,'admin','admin@cybog-lab.test');
"""

ADMIN_HTML = """<!DOCTYPE html>
<html>
<head><title>Admin panel</title></head>
<body>
<h1>Admin panel</h1>
<p>Welcome. Manage the CYBOG lab here.</p>
<a href="/">Home</a>
</body>
</html>
"""

ROBOTS_TXT = """User-agent: *
Disallow: /backup/
Disallow: /.env
Disallow: /.git/
"""


class LabHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "CYBOGLab/1.0"
    sys_version = ""

    # NOTE: no security headers are emitted on purpose.

    def _send(self, status: int, body: bytes, ctype: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0].split("#", 1)[0]
        if path == "/":
            self._send(200, ROOT_HTML.encode(), "text/html; charset=utf-8")
        elif path == "/.git/config":
            self._send(200, GIT_CONFIG.encode(), "text/plain; charset=utf-8")
        elif path == "/.env":
            self._send(200, ENV_FILE.encode(), "text/plain; charset=utf-8")
        elif path == "/backup/db.sql":
            self._send(200, SQL_BACKUP.encode(), "application/sql; charset=utf-8")
        elif path == "/admin":
            self._send(200, ADMIN_HTML.encode(), "text/html; charset=utf-8")
        elif path == "/robots.txt":
            self._send(200, ROBOTS_TXT.encode(), "text/plain; charset=utf-8")
        else:
            self._send(404, b"Not Found\n", "text/plain; charset=utf-8")

    do_HEAD = do_GET

    def log_message(self, fmt, *args):
        sys.stderr.write("[lab] %s - %s\n" % (self.address_string(), fmt % args))


class ThreadingServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    with ThreadingServer((HOST, PORT), LabHandler) as httpd:
        sys.stderr.write(f"[lab] CYBOG Lab listening on http://{HOST}:{PORT}\n")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
