"""Attack-chain correlation: links individual findings into multi-stage risks.

This is the part a flat scanner misses: a directory listing, a leaked backup
and a login page are each 'medium at most' alone, but together they are a
critical, provable path into the application.
"""

from .findings import SEVERITY_ORDER


def correlate(findings):
    """Return a list of chains: {title, severity, narrative, finding_ids, verified}."""
    by_tag = {}
    for f in findings:
        for tag in f.tags:
            by_tag.setdefault(tag, []).append(f)

    chains = []

    listings = by_tag.get("directory_listing", [])
    creds = by_tag.get("credential_exposure", [])
    panels = by_tag.get("login_panel", [])
    verified = by_tag.get("verified_access", [])
    git = by_tag.get("source_disclosure", [])
    risky = by_tag.get("risky_service", [])

    if (listings or git) and creds and panels:
        members = (listings or git)[:1] + creds[:1] + panels[:1] + verified[:1]
        # No automatic amplification: the chain keeps the highest severity
        # actually demonstrated by its members. Composition is explained in
        # the narrative, not rewarded with a bigger number.
        sev = SEVERITY_ORDER[max(SEVERITY_ORDER.index(f.severity) for f in members)]
        narrative = (
            "An exposed listing or source artifact leaks credential material, "
            "and a reachable login panel turns that leak into administrative "
            "access to the application. Individually moderate issues compose "
            "into a single working attack path.")
        if verified:
            narrative += (" The final step was verified against the local lab: "
                          "the leaked credentials successfully authenticated.")
        chains.append({
            "title": "Exposed credentials to authenticated access",
            "severity": sev,
            "finding_ids": [f.id for f in members],
            "narrative": narrative,
            "verified": bool(verified),
        })

    if risky and by_tag.get("version_disclosure"):
        members = risky[:1] + by_tag["version_disclosure"][:1]
        chains.append({
            "title": "Service exposure amplified by version disclosure",
            "severity": members[0].severity,
            "finding_ids": [f.id for f in members],
            "narrative": (
                "A risky network service is reachable and the stack discloses "
                "exact versions, shortening an attacker's path to known exploits."),
            "verified": False,
        })

    return chains
