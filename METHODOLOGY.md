# Methodology

VulnChain implements the assessment phases of a standard VAPT engagement
(aligned with PTES/OWASP-style phases) as automated modules, and keeps the
intrusive phases (exploitation, post-exploitation, privilege escalation)
manual and out of scope for the tool.

## Phase mapping

| Phase | Module | Notes |
|---|---|---|
| Rules of engagement | `scope.py` | Hard allow-list of hosts/CIDRs, ports and a per-host request budget. Violations raise and abort. |
| Reconnaissance / discovery | `scanners/portscan.py` | TCP connect scan of in-scope ports only; flags risky services (telnet, redis, mongo, ...). |
| Enumeration | `scanners/http_recon.py` | Server/technology banners, missing security headers, dangerous HTTP methods. |
| Enumeration | `scanners/dir_enum.py` | Curated wordlist: panels, backups, `.git`, `.env`, directory listings, leaked credential material. |
| Configuration review | `scanners/tls_check.py` | Certificate expiry/validity, legacy TLS protocol acceptance (TLS 1.0/1.1). |
| Verification (lab only) | `scanners/auth_check.py` | Opt-in per scope AND loopback-only. Control-backed: wrong credentials must fail, the protected page must reject anonymous access, then leaked credentials + session must open it. Arbitrary-credential acceptance is reported as an auth bypass instead. |
| Risk analysis | `chain.py` | Correlates findings into multi-stage attack chains; severity amplifies when weaknesses compose; chains proven in-lab are marked verified. |
| Reporting | `report.py` | Markdown / HTML / JSON VAPT report: executive summary, methodology, chains, findings, remediation, limitations. |

## Scoring

- Severities are internal and qualitative. No finding gets a numeric score
  from a hardcoded per-type template: a directory listing alone does not
  prove confidentiality impact, an echoed TRACE proves the method responds
  (not browser-side impact), and a login proves access (not C/I/A impact on
  the host).
- A tested CVSS 3.1 base calculator (`findings.cvss31_base`) ships with the
  project so the tester can score a specific, demonstrated impact during an
  engagement; the report then shows the full vector next to the score.
- Chain severity is internal and equals the highest member severity; the
  tool never raises a chain above what its members demonstrated. Composition
  is explained in the chain narrative, not rewarded with a bigger number.
  A chain whose final step was verified in the lab is marked verified.
- Evidence is redacted (`findings.redact`) before storage, so reports, JSON
  and logs never contain the secret values that triggered a finding.

## Design rules

1. **Scope first.** Every network call goes through `Scope.check`. A host or
   port outside the file raises `ScopeViolation`. Hostnames are resolved once
   and pinned, all resolved IPs (v4/v6) must fit the allowance, connections
   use the pinned IP, and redirects are never followed.
2. **Loopback-only proof.** `auth_check` refuses to verify credentials against
   any non-loopback target, even if the scope opts in.
3. **Evidence or it didn't happen.** Every finding stores the exact response
   fragment that justifies it.
4. **Stdlib only.** No dependency means the audit surface is the repo itself.
