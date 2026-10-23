"""
Deliberately weak local web server — verification fixture only.

Run it, then scan http://127.0.0.1:8899 with the tool to see real findings.
It intentionally ships no security headers, an exposed .git/HEAD and .env,
an unprotected cookie, a version banner, an open admin panel, a reflectable
query parameter, and a login that throws database errors - so every phase of
the agentic engagement (recon/map/attack/verify) has something real to work
with. Never expose this anywhere.

    python data/lab_target.py
"""

import http.server
import socketserver
from urllib.parse import parse_qs, unquote

PORT = 8899

HOME = """<html><head><title>Lab target</title></head>
<body><h1>Weak lab target</h1>
<p>Navigation <a href="/login">login</a> <a href="/admin">admin</a>
<a href="/dashboard">dashboard</a> <a href="/search">search</a>
<a href="/about">about</a></p>
<p>Nothing else to see here.</p></body></html>"""
ABOUT = "<html><body><h1>About</h1><p>LabCorp internal app (beta).</p></body></html>"
LOGIN = ('<html><body><h1>Login</h1><form method="post" action="/login">'
         '<input name="username"><input name="password" type="password">'
         '<button type="submit">Sign in</button></form></body></html>')
ADMIN = "<html><body><h1>Admin panel</h1><p>User list: alice, bob, carol.</p></body></html>"
DASHBOARD = "<html><body><h1>Dashboard</h1><p>Welcome.</p></body></html>"

GIT_HEAD = "ref: refs/heads/main\n"
ENV_FILE = "DB_PASSWORD=supersecret\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nDEBUG=true\n"
ROBOTS = "User-agent: *\nDisallow: /admin/\nDisallow: /backup.zip\n"

SQL_ERROR_MARKERS = (
    "sqlite3.OperationalError",
    "you have an error in your sql syntax",
    "unclosed quotation mark",
    "psycopg2.errors",
    "pg_query()",
)


def looks_like_admin(path: str) -> bool:
    lowered = path.lower()
    return any(marker in lowered for marker in ("/admin", "/manager", "/phpmyadmin", "/wp-admin"))


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "LabServer/1.0"
    sys_version = ""

    def _respond(self, status, body, ctype="text/html; charset=utf-8", extra=None):
        payload = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        for key, value in (extra or []):
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):  # noqa: N802
        path, _, query = self.path.partition("?")
        params = parse_qs(query)

        # Unprotected session cookie + version disclosure on every page.
        extra = [
            ("Set-Cookie", "session=devsession123; Path=/"),
            ("X-Powered-By", "LabFramework 0.1"),
        ]

        if path in ("/", "/index.html"):
            self._respond(200, HOME, extra=extra)
        elif path == "/about":
            self._respond(200, ABOUT, extra=extra)
        elif path == "/login":
            self._respond(200, LOGIN, extra=extra)
        elif looks_like_admin(path) or path == "/dashboard":
            # No authentication whatsoever - the whole point of this fixture.
            self._respond(200, ADMIN, extra=extra)
        elif path == "/robots.txt":
            self._respond(200, ROBOTS, ctype="text/plain")
        elif path.startswith("/search"):
            # Reflect the q parameter unescaped: the agentic scanner canaries
            # this and detects reflection.
            q = unquote(params.get("q", [""])[0])
            body = '<html><body><h1>Search</h1><p>Results for: ' + q + "</p></body></html>"
            if "'" in q:
                # Deliberate error-based SQLi tell-tale.
                body += ("<p>Query error: sqlite3.OperationalError: "
                         "unrecognized token: \"'\".</p>")
            self._respond(200, body, extra=extra)
        elif path == "/.git/HEAD":
            self._respond(200, GIT_HEAD, ctype="text/plain")
        elif path == "/.env":
            self._respond(200, ENV_FILE, ctype="text/plain")
        else:
            self._respond(404, "not found", ctype="text/plain")
        # No CSP, XFO, XCTO, Referrer-Policy, Permissions-Policy, no HTTPS.

    def do_POST(self):  # noqa: N802
        if self.path != "/login":
            self._respond(404, "not found", ctype="text/plain")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode("utf-8", errors="replace")
        except Exception:
            raw = ""
        if "'" in raw or "%" in raw and "27" in raw:
            # Broken auth + error-based SQLi trail.
            self._respond(
                200,
                "<p>Query error: sqlite3.OperationalError: unrecognized token.</p>",
            )
            return
        self._respond(200, "<p>Invalid credentials.</p>")

    def log_message(self, fmt, *args):
        print("[lab] " + fmt % args, flush=True)


if __name__ == "__main__":
    with socketserver.ThreadingTCPServer(("127.0.0.1", PORT), Handler) as httpd:
        print(f"[lab] weak target on http://127.0.0.1:{PORT}", flush=True)
        httpd.serve_forever()
