"""TLS configuration checks: certificate validity and legacy protocol support."""

import socket
import ssl
from datetime import datetime, timezone

from ..findings import Finding

LEGACY = []
for name in ("TLSv1", "TLSv1_1"):
    ver = getattr(ssl.TLSVersion, name, None)
    if ver is not None:
        LEGACY.append((name, ver))


def run(scope, host, port):
    findings = []
    scope.check(host, port)
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                negotiated = tls.version()
    except (ssl.SSLError, OSError) as exc:
        findings.append(Finding(
            id=f"VC-TLS-CERT-{port}",
            title=f"TLS certificate problem on {host}:{port}",
            severity="medium",
            target=f"{host}:{port}",
            evidence=str(exc)[:200],
            remediation="Fix certificate chain, hostname and expiry.",
            tags=["tls_issue"],
        ))
        return findings

    not_after = cert.get("notAfter")
    if not_after:
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc)
        days = (expiry - datetime.now(timezone.utc)).days
        if days < 30:
            findings.append(Finding(
                id=f"VC-TLS-EXP-{port}",
                title=f"Certificate expires in {days} days",
                severity="medium" if days > 0 else "high",
                target=f"{host}:{port}",
                evidence=f"notAfter={not_after}",
                remediation="Renew the certificate before expiry.",
                tags=["tls_issue"],
            ))

    for name, version in LEGACY:
        legacy_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        legacy_ctx.check_hostname = False
        legacy_ctx.verify_mode = ssl.CERT_NONE
        try:
            legacy_ctx.minimum_version = version
            legacy_ctx.maximum_version = version
        except (ValueError, ssl.SSLError):
            continue
        try:
            scope.check(host, port)
            with socket.create_connection((host, port), timeout=5) as sock:
                with legacy_ctx.wrap_socket(sock, server_hostname=host):
                    findings.append(Finding(
                        id=f"VC-TLS-{name}-{port}",
                        title=f"Legacy protocol accepted: {name}",
                        severity="medium",
                        target=f"{host}:{port}",
                        evidence=f"Handshake with {name} succeeded",
                        remediation="Disable TLS 1.0/1.1; require TLS 1.2+.",
                        tags=["tls_issue", "legacy_protocol"],
                    ))
        except (ssl.SSLError, OSError):
            continue
    return findings
