"""HTTP reconnaissance: banners, security headers, methods.

Method handling distinguishes ADVERTISED from VERIFIED: an OPTIONS Allow
header only advertises methods. TRACE is probed once with a unique marker;
only an echoed marker proves TRACE actually executes. PUT/DELETE are never
executed by this tool and are reported as advertised only.
"""

import re
import uuid

from ..findings import Finding
from ..httpclient import request

SECURITY_HEADERS = {
    "content-security-policy": ("medium", "Add a Content-Security-Policy header."),
    "x-content-type-options": ("low", "Add 'X-Content-Type-Options: nosniff'."),
    "x-frame-options": ("low", "Add X-Frame-Options or CSP frame-ancestors."),
    "referrer-policy": ("low", "Add a Referrer-Policy header."),
}

DANGEROUS_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT"}


def run(scope, host, port, use_tls=False):
    findings = []
    try:
        status, headers, body = request(scope, host, port, use_tls=use_tls)
    except OSError:
        return False, findings

    server = headers.get("server", "")
    if server and re.search(r"\d", server):
        findings.append(Finding(
            id=f"VC-BAN-{port}",
            title=f"Server version disclosed: {server}",
            severity="low",
            target=f"{host}:{port}",
            evidence=f"Server: {server}",
            remediation="Suppress version tokens in the server banner.",
            tags=["version_disclosure"],
        ))
    powered = headers.get("x-powered-by", "")
    if powered:
        findings.append(Finding(
            id=f"VC-PWR-{port}",
            title=f"Technology disclosed: {powered}",
            severity="low",
            target=f"{host}:{port}",
            evidence=f"X-Powered-By: {powered}",
            remediation="Remove the X-Powered-By header.",
            tags=["version_disclosure"],
        ))
    for header, (sev, fix) in SECURITY_HEADERS.items():
        if header not in headers:
            findings.append(Finding(
                id=f"VC-HDR-{header[:6].upper()}-{port}",
                title=f"Missing security header: {header}",
                severity=sev,
                target=f"{host}:{port}",
                evidence=f"GET / returned {status} without {header}",
                remediation=fix,
                tags=["missing_header"],
            ))
    if use_tls and "strict-transport-security" not in headers:
        findings.append(Finding(
            id=f"VC-HSTS-{port}",
            title="Missing Strict-Transport-Security",
            severity="medium",
            target=f"{host}:{port}",
            evidence="HTTPS response without HSTS header",
            remediation="Add Strict-Transport-Security with a long max-age.",
            tags=["missing_header"],
        ))
    try:
        _, opt_headers, _ = request(scope, host, port, method="OPTIONS", use_tls=use_tls)
        allow = {m.strip().upper() for m in opt_headers.get("allow", "").split(",")}
        advertised = sorted(allow & DANGEROUS_METHODS)
        verified_trace = False
        if "TRACE" in advertised:
            marker = f"vulnchain-{uuid.uuid4().hex[:12]}"
            try:
                t_status, _, t_body = request(
                    scope, host, port, method="TRACE",
                    headers={"X-VulnChain-Probe": marker}, use_tls=use_tls)
                verified_trace = t_status == 200 and marker in (t_body or "")
            except OSError:
                pass
        advertised = [m for m in advertised if m != "TRACE"]
        if advertised:
            findings.append(Finding(
                id=f"VC-MTH-{port}",
                title=f"Dangerous HTTP methods advertised: {', '.join(advertised)}",
                severity="low",
                target=f"{host}:{port}",
                evidence=f"OPTIONS Allow: {opt_headers.get('allow', '')} "
                         f"(advertised only; not executed by this tool)",
                remediation="Disable PUT/DELETE unless required; verify what the "
                            "server actually accepts.",
                tags=["dangerous_methods_advertised"],
            ))
        if verified_trace:
            findings.append(Finding(
                id=f"VC-TRACE-{port}",
                title="Verified: TRACE method responds with a request echo",
                severity="medium",
                target=f"{host}:{port}",
                evidence="TRACE request with a unique marker was echoed by the server "
                         "(proves TRACE is enabled; browser-side impact not assessed)",
                remediation="Disable TRACE at the web server.",
                tags=["dangerous_methods", "verified_trace"],
                verified=True,
            ))
        elif "TRACE" in (opt_headers.get("allow", "")):
            findings.append(Finding(
                id=f"VC-TRACE-ADV-{port}",
                title="TRACE advertised but not confirmed",
                severity="info",
                target=f"{host}:{port}",
                evidence="OPTIONS advertises TRACE; probe did not confirm execution",
                remediation="Disable TRACE at the web server.",
                tags=["dangerous_methods_advertised"],
            ))
    except OSError:
        pass
    return True, findings
