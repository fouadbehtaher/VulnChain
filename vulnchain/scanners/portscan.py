"""TCP connect port scan, limited to ports declared in the scope file."""

from concurrent.futures import ThreadPoolExecutor
import socket

from ..findings import Finding

COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 143: "imap", 443: "https", 445: "smb", 3306: "mysql",
    3389: "rdp", 5432: "postgres", 5900: "vnc", 6379: "redis", 8000: "http-alt",
    8080: "http-alt", 8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb",
}

RISKY_SERVICES = {
    "telnet": ("high", "Telnet is plaintext; replace with SSH."),
    "ftp": ("medium", "FTP is plaintext; replace with SFTP or disable."),
    "vnc": ("medium", "Restrict VNC to localhost or a VPN and require auth."),
    "redis": ("high", "Redis must never be internet-facing; bind to localhost and require auth."),
    "elasticsearch": ("high", "Bind Elasticsearch to localhost and enable security features."),
    "mongodb": ("high", "Bind MongoDB to localhost and enable access control."),
    "smb": ("medium", "Restrict SMB to trusted networks; disable SMBv1."),
    "rdp": ("medium", "Restrict RDP to a VPN; enable NLA and MFA at the gateway."),
}


def scan(scope, host):
    open_ports = []

    def probe(port):
        ips = scope.check(host, port)
        ip = str(sorted(ips, key=lambda i: i.version)[0])
        with socket.create_connection((ip, port), timeout=2):
            return port

    with ThreadPoolExecutor(max_workers=32) as pool:
        futures = {pool.submit(probe, p): p for p in scope.allowed_ports}
        for fut in futures:
            try:
                open_ports.append(fut.result())
            except Exception:
                continue
    open_ports.sort()

    findings = []
    for port in open_ports:
        service = COMMON_SERVICES.get(port, "unknown")
        findings.append(Finding(
            id=f"VC-PORT-{port}",
            title=f"Open port {port} ({service})",
            severity="info",
            target=f"{host}:{port}",
            evidence=f"TCP connect to {host}:{port} succeeded",
            remediation="Confirm this service is intended to be reachable.",
            tags=["open_port", f"service:{service}"],
        ))
        if service in RISKY_SERVICES:
            sev, fix = RISKY_SERVICES[service]
            findings.append(Finding(
                id=f"VC-SVC-{port}",
                title=f"Risky service exposed: {service} on {port}",
                severity=sev,
                target=f"{host}:{port}",
                evidence=f"{service} accepts connections on {host}:{port} "
                         f"(reachability observed; service safety not verified)",
                remediation=fix,
                tags=["risky_service", f"service:{service}"],
            ))
    return open_ports, findings
