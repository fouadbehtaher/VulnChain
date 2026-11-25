"""HTTP helpers shared by scanners. Every request passes through Scope.check.

Connections go to the scope-pinned IP with the original Host header (and SNI
for TLS), so DNS rebinding cannot redirect assessment traffic. Redirect
responses are returned to the caller and NEVER followed.
"""

import http.client
import ssl


def request(scope, host, port, method="GET", path="/", body=None, headers=None,
            timeout=5, use_tls=False, context=None):
    """One scoped HTTP request. Returns (status, headers-dict, body-text)."""
    scope.check(host, port)
    ip = scope.pinned_ip(host)
    conn_cls = http.client.HTTPSConnection if use_tls else http.client.HTTPConnection
    kwargs = {"timeout": timeout}
    if use_tls:
        kwargs["context"] = context or ssl.create_default_context()
    conn = conn_cls(ip, port, **kwargs)
    try:
        hdrs = {"Host": f"{host}:{port}"}
        hdrs.update(headers or {})
        conn.request(method, path, body=body, headers=hdrs)
        resp = conn.getresponse()
        raw = resp.read(65536)
        text = raw.decode("utf-8", errors="replace")
        return resp.status, {k.lower(): v for k, v in resp.getheaders()}, text
    finally:
        conn.close()
