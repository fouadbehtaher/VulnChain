"""VulnChain pipeline: scope in, scoped findings and a VAPT report out."""

from datetime import datetime, timezone

from . import chain as chain_engine
from . import report as report_mod
from .scope import Scope
from .scanners import auth_check, dir_enum, http_recon, portscan, tls_check

TLS_PORTS = {443, 8443}


def run_assessment(scope: Scope):
    """Execute every module inside the scope and return (findings, chains, started, finished)."""
    started = datetime.now(timezone.utc)
    findings = []
    hits = []
    for host in scope.allowed_hosts:
        if "/" in host:      # CIDR entries are for allow-listing, not sweeping
            continue
        open_ports, port_findings = portscan.scan(scope, host)
        findings.extend(port_findings)
        for port in open_ports:
            use_tls = port in TLS_PORTS
            is_http, http_findings = http_recon.run(scope, host, port, use_tls=use_tls)
            findings.extend(http_findings)
            if not is_http:
                continue
            dir_hits, dir_findings = dir_enum.run(scope, host, port, use_tls=use_tls)
            hits.extend(dir_hits)
            findings.extend(dir_findings)
            if use_tls:
                findings.extend(tls_check.run(scope, host, port))

            login_paths = [p for p, status, _ in dir_hits
                           if any(k in p.lower() for k in ("admin", "login", "panel"))]
            exposed_bodies = [body for _, status, body in dir_hits if status == 200]
            creds = auth_check.extract_credentials(exposed_bodies)
            findings.extend(auth_check.run(
                scope, host, port, login_paths, creds, use_tls=use_tls))
    finished = datetime.now(timezone.utc)
    chains = chain_engine.correlate(findings)
    return findings, chains, started, finished


def write_reports(scope, findings, chains, started, finished, outdir, formats=("md", "html", "json")):
    import os
    os.makedirs(outdir, exist_ok=True)
    paths = {}
    if "md" in formats:
        path = os.path.join(outdir, "vapt-report.md")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(report_mod.render_markdown(scope, findings, chains, started, finished))
        paths["md"] = path
    if "html" in formats:
        path = os.path.join(outdir, "vapt-report.html")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(report_mod.render_html(scope, findings, chains, started, finished))
        paths["html"] = path
    if "json" in formats:
        path = os.path.join(outdir, "vapt-report.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(report_mod.render_json(scope, findings, chains, started, finished))
        paths["json"] = path
    return paths
