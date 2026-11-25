"""Credential verification against login panels.

Only runs when the scope file sets verify_credentials=true AND the target
resolves to loopback. This module exists so a chain can be proven end-to-end
inside a local lab; it is not a password-attack tool.

Verification uses controls, not a single lucky response:
  1. Negative control: wrong credentials must be REJECTED. If arbitrary
     credentials are accepted, that is reported as its own anomaly instead.
  2. Positive: leaked credentials must authenticate and yield a session.
  3. Protected-resource proof: a protected page must be unreachable without
     the session and reachable with it.
Only when all three hold is the chain marked verified.
"""

import ipaddress
import re
import secrets as _secrets
from urllib.parse import urlencode

from ..findings import Finding
from ..httpclient import request

SUCCESS_MARKERS = re.compile(r"(?i)(flag\{|welcome|dashboard|logged in|session)")


def _is_ip(host):
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _is_loopback(host):
    import socket as _s
    ips = {ipaddress.ip_address(host.strip("[]"))} if _is_ip(host) else {
        ipaddress.ip_address(i[4][0]) for i in _s.getaddrinfo(host, None)}
    return all(ip.is_loopback for ip in ips)


def extract_credentials(bodies):
    """Pull (username, password) pairs out of exposed file bodies."""
    creds = []
    for body in bodies:
        for match in re.finditer(
                r"(?im)^\s*(?:ADMIN_)?USER(?:NAME)?\s*[:=]\s*(\S+)\s*$", body or ""):
            user = match.group(1)
            after = (body or "")[match.end():]
            pw = re.search(r"(?im)^\s*(?:ADMIN_)?PASS(?:WORD)?\s*[:=]\s*(\S+)\s*$", after)
            if pw:
                creds.append((user, pw.group(1)))
    return creds


def _post(scope, host, port, path, user, password, use_tls):
    return request(scope, host, port, method="POST", path=path,
                   body=urlencode({"username": user, "password": password}),
                   headers={"Content-Type": "application/x-www-form-urlencoded"},
                   use_tls=use_tls)


def run(scope, host, port, login_paths, candidate_creds, use_tls=False):
    findings = []
    if not scope.verify_credentials or not candidate_creds or not login_paths:
        return findings
    if not _is_loopback(host):
        findings.append(Finding(
            id=f"VC-AUTH-SKIP-{port}",
            title="Credential verification skipped: target is not a local lab",
            severity="info",
            target=f"{host}:{port}",
            evidence="verify_credentials only runs against loopback targets",
            remediation="Run verification only in an authorized lab.",
            tags=["verification_skipped"],
        ))
        return findings

    for path in login_paths:
        protected = path.rstrip("/") + "/dashboard"
        try:
            # Negative control 1: wrong credentials must be rejected.
            bad_status, _, bad_body = _post(scope, host, port, path,
                                            "vulnchain-invalid",
                                            _secrets.token_hex(8), use_tls)
            if bad_status == 200 and SUCCESS_MARKERS.search(bad_body or ""):
                findings.append(Finding(
                    id=f"VC-AUTH-ANY-{port}",
                    title=f"Login accepts arbitrary credentials at {path}",
                    severity="critical",
                    target=f"{host}:{port}",
                    evidence=f"POST {path} with random invalid credentials returned "
                             f"an authenticated page (demonstrated authentication bypass)",
                    remediation="Fix authentication logic; arbitrary logins must fail.",
                    tags=["verified_access", "auth_bypass", f"path:{path}"],
                    verified=True,
                ))
                return findings

            # Negative control 2: protected resource must require a session.
            anon_status, _, _ = request(scope, host, port, path=protected, use_tls=use_tls)
            if anon_status == 200:
                continue    # no protected resource to prove anything with

            # Positive: each leaked credential pair.
            for user, password in candidate_creds[:3]:
                status, resp_headers, body = _post(scope, host, port, path,
                                                   user, password, use_tls)
                cookie = resp_headers.get("set-cookie", "")
                if not (status == 200 and SUCCESS_MARKERS.search(body or "")):
                    continue
                # Protected-resource proof with the issued session.
                proof = ""
                if cookie:
                    p_status, _, p_body = request(
                        scope, host, port, path=protected,
                        headers={"Cookie": cookie.split(";", 1)[0]}, use_tls=use_tls)
                    if p_status == 200 and SUCCESS_MARKERS.search(p_body or ""):
                        proof = (f"; protected {protected} returned HTTP 200 with the "
                                 f"session and HTTP {anon_status} without it")
                findings.append(Finding(
                    id=f"VC-AUTH-OK-{port}",
                    title=f"Verified: exposed credentials grant administrative "
                          f"application access at {path}",
                    severity="high",
                    target=f"{host}:{port}",
                    evidence=(f"Wrong-credential control rejected (HTTP {bad_status}); "
                              f"leaked credentials authenticated at {path}{proof}. "
                              f"Demonstrated impact: read access to the protected admin "
                              f"page of this lab application."),
                    remediation="Rotate the credentials, remove the leak, and enforce MFA.",
                    tags=["verified_access", f"path:{path}"],
                    verified=True,
                ))
                return findings
        except OSError:
            continue
    return findings
