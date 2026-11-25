"""Scope enforcement. Nothing runs against a host/port outside the scope file.

Hardening:
- Hostnames are resolved once and pinned; connections go to the pinned IP, so
  DNS rebinding between the check and the request cannot redirect traffic.
- For a hostname to be allowed via CIDR, ALL of its resolved IPs (v4 and v6)
  must fall inside the CIDR.
- Redirects are never followed by the HTTP client, so a 302 cannot pull the
  assessment onto an out-of-scope host.
- A per-host request budget caps total traffic; exhaustion raises.
"""

import ipaddress
import json
import socket


class ScopeViolation(Exception):
    pass


class Scope:
    def __init__(self, name, allowed_hosts, allowed_ports, verify_credentials=False,
                 max_requests_per_host=200):
        self.name = name
        self.allowed_hosts = allowed_hosts          # exact names or CIDRs
        self.allowed_ports = sorted(set(int(p) for p in allowed_ports))
        self.verify_credentials = bool(verify_credentials)
        self.max_requests_per_host = int(max_requests_per_host)
        self._request_count = {}
        self._pinned = {}                           # host -> frozenset of IPs

    @classmethod
    def load(cls, path):
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        for key in ("name", "allowed_hosts", "allowed_ports"):
            if key not in data:
                raise ScopeViolation(f"scope file missing required key: {key}")
        return cls(
            name=data["name"],
            allowed_hosts=data["allowed_hosts"],
            allowed_ports=data["allowed_ports"],
            verify_credentials=data.get("verify_credentials", False),
            max_requests_per_host=data.get("max_requests_per_host", 200),
        )

    def _resolve(self, host):
        if host in self._pinned:
            return self._pinned[host]
        try:
            ips = frozenset({ipaddress.ip_address(host.strip("[]"))})
        except ValueError:
            try:
                infos = socket.getaddrinfo(host, None)
            except socket.gaierror as exc:
                raise ScopeViolation(f"cannot resolve in-scope host {host!r}: {exc}")
            ips = frozenset({ipaddress.ip_address(i[4][0]) for i in infos})
        return ips

    def _host_allowed(self, host, ips):
        for entry in self.allowed_hosts:
            if entry == host:
                return True
            try:
                net = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                continue
            if all(ip in net for ip in ips):
                return True
        return False

    def check(self, host, port):
        """Raise ScopeViolation unless host+port are inside the declared scope.
        Returns the pinned IP set the connection must use."""
        if int(port) not in self.allowed_ports:
            raise ScopeViolation(f"port {port} not in scope for {self.name}")
        ips = self._resolve(host)
        if not self._host_allowed(host, ips):
            raise ScopeViolation(
                f"host {host!r} is not in scope {self.name!r}; refusing to test it")
        self._pinned[host] = ips                    # pin only after allowance
        used = self._request_count.get(host, 0)
        if used >= self.max_requests_per_host:
            raise ScopeViolation(
                f"request budget exhausted for {host} ({self.max_requests_per_host})")
        self._request_count[host] = used + 1
        return ips

    def pinned_ip(self, host):
        """One pinned IP for connecting, after check() has approved the host."""
        ips = self._pinned.get(host)
        if not ips:
            raise ScopeViolation(f"host {host!r} used before scope check")
        v4 = [ip for ip in ips if ip.version == 4]
        return str(sorted(v4 or list(ips))[0])
