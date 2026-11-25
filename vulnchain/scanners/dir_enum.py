"""Directory and sensitive-file enumeration with a small built-in wordlist."""

import os
import re

from ..findings import Finding
from ..httpclient import request

LISTING_MARKERS = ("Index of /", "<title>Index of", "Directory Listing For")

CRED_PATTERN = re.compile(
    r"(?i)(pass(word)?|secret|api[_-]?key|token)\s*[:=]\s*\S+")

def default_wordlist():
    path = os.path.join(os.path.dirname(__file__), "..", "wordlists", "common.txt")
    with open(os.path.normpath(path), "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]


def run(scope, host, port, use_tls=False, wordlist=None):
    findings = []
    hits = []   # (path, status, body) for the chain engine
    for word in (wordlist or default_wordlist()):
        path = "/" + word.lstrip("/")
        try:
            status, headers, body = request(scope, host, port, path=path, use_tls=use_tls)
        except OSError:
            continue
        if status in (200, 301, 302, 401, 403):
            hits.append((path, status, body))

        if status == 200 and any(m in body for m in LISTING_MARKERS):
            findings.append(Finding(
                id=f"VC-DIR-{port}-{len(findings)}",
                title=f"Directory listing enabled: {path}",
                severity="low",
                target=f"{host}:{port}",
                evidence=f"GET {path} returned a directory index page "
                         f"(listing observed; impact depends on the files exposed)",
                remediation="Disable autoindex/directory listing on the server.",
                tags=["directory_listing", f"path:{path}"],
            ))
        if status == 200 and CRED_PATTERN.search(body or ""):
            sample = CRED_PATTERN.search(body).group(0)
            findings.append(Finding(
                id=f"VC-CRED-{port}-{len(findings)}",
                title=f"Possible credential material exposed: {path}",
                severity="high",
                target=f"{host}:{port}",
                evidence=f"GET {path} body contains '{sample[:40]}' "
                         f"(credential-shaped content observed; validity not assumed)",
                remediation="Remove the file from the web root and rotate the credentials.",
                tags=["credential_exposure", f"path:{path}"],
            ))
        if status == 200 and path.rstrip("/").endswith((".git/HEAD",)):
            findings.append(Finding(
                id=f"VC-GIT-{port}",
                title="Exposed .git metadata",
                severity="medium",
                target=f"{host}:{port}",
                evidence="GET /.git/HEAD returned a valid git ref (proves metadata "
                         "exposure; full source recoverability not verified)",
                remediation="Block dotfile access at the web server; never deploy .git.",
                tags=["sensitive_file", "source_disclosure", f"path:{path}"],
            ))
        if status in (200, 401, 403) and re.search(r"(?i)(admin|login|dashboard|panel)", path):
            sev = "info" if status == 401 else "low"
            findings.append(Finding(
                id=f"VC-PNL-{port}-{len(findings)}",
                title=f"Login/admin panel found: {path} (HTTP {status})",
                severity=sev,
                target=f"{host}:{port}",
                evidence=f"GET {path} returned {status}",
                remediation="Restrict panel access by IP/VPN and enforce MFA.",
                tags=["login_panel", f"path:{path}", f"status:{status}"],
            ))
    return hits, findings
