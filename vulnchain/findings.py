"""Finding model, CVSS 3.1 base scoring, severity helpers, evidence redaction."""

import math
import re
from dataclasses import dataclass, field, asdict

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

_CVSS_METRICS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}

_SECRET_KV = re.compile(
    r"(?i)(pass(word)?|pwd|secret|api[_-]?key|token)\s*[:=]\s*(\S+)")


def redact(text):
    """Mask credential-looking values so reports never leak secrets."""
    if not text:
        return text
    return _SECRET_KV.sub(lambda m: f"{m.group(0)[:m.group(0).upper().find(m.group(1).upper())]}{m.group(1)}=<redacted>", text)


def cvss31_base(vector):
    """Compute the CVSS 3.1 base score for a vector like
    'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'. Raises ValueError on bad input."""
    parts = dict(p.split(":", 1) for p in vector.split("/")[1:])
    need = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
    if any(k not in parts for k in need):
        raise ValueError(f"incomplete CVSS vector: {vector}")
    scope_changed = parts["S"] == "C"
    pr_table = {"N": 0.85, "L": 0.68 if scope_changed else 0.62,
                "H": 0.5 if scope_changed else 0.27}
    try:
        isc_base = (1 - (1 - _CVSS_METRICS["CIA"][parts["C"]])
                    * (1 - _CVSS_METRICS["CIA"][parts["I"]])
                    * (1 - _CVSS_METRICS["CIA"][parts["A"]]))
    except KeyError as exc:
        raise ValueError(f"bad CVSS metric in {vector}: {exc}")
    if scope_changed:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
    else:
        impact = 6.42 * isc_base
    exploitability = (8.22 * _CVSS_METRICS["AV"][parts["AV"]]
                      * _CVSS_METRICS["AC"][parts["AC"]]
                      * pr_table[parts["PR"]]
                      * _CVSS_METRICS["UI"][parts["UI"]])
    if impact <= 0:
        return 0.0
    raw = impact + exploitability
    if scope_changed:
        raw = 1.08 * raw
    return math.ceil(min(raw, 10.0) * 10) / 10.0


def severity_at_least(sev: str, other: str) -> bool:
    return SEVERITY_ORDER.index(sev) >= SEVERITY_ORDER.index(other)


@dataclass
class Finding:
    id: str                 # stable id, e.g. VC-HDR-001
    title: str
    severity: str           # info|low|medium|high|critical
    target: str             # host:port or URL
    evidence: str           # what we observed; secrets are redacted on creation
    remediation: str
    cvss_vector: str = ""   # CVSS 3.1 vector; empty = internal severity, not scored
    tags: list = field(default_factory=list)   # chain-engine labels
    verified: bool = False  # True only when a control-backed check confirmed impact

    def __post_init__(self):
        self.evidence = redact(self.evidence)

    @property
    def cvss(self):
        return cvss31_base(self.cvss_vector) if self.cvss_vector else 0.0

    @property
    def severity_display(self):
        if self.cvss_vector:
            return f"{self.severity} (CVSS 3.1 base {self.cvss:.1f}, {self.cvss_vector})"
        return f"{self.severity} (internal severity, not CVSS-scored)"

    def to_dict(self):
        data = asdict(self)
        data["cvss"] = self.cvss
        return data
