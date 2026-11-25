# Vulnerability Assessment Report: vulnchain-demo-lab

- Date: 2026-11-25 20:02 UTC
- Duration: 0s
- Scope: hosts 127.0.0.1; ports 8899
- Tool: VulnChain (automated assessment with attack-chain correlation)

## Executive summary

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 2 |
| Medium | 3 |
| Low | 8 |
| Info | 2 |

**1 attack chain(s) identified** - see the chains section for how individual weaknesses compose into one path. Chain severity is internal and equals the strongest demonstrated impact, with no automatic amplification.

## Methodology

1. Scope validation - every request checked against the authorized scope file.
2. Port and service discovery (TCP connect, in-scope ports only).
3. HTTP reconnaissance - banners, security headers, allowed methods.
4. Directory and sensitive-file enumeration (curated wordlist).
5. TLS configuration review (certificate, protocol versions) where applicable.
6. Credential verification - only when scope opts in and the target is a local lab.
7. Attack-chain correlation and risk assessment.

## Attack chains

### Chain 1: Exposed credentials to authenticated access - High (verified in lab)

An exposed listing or source artifact leaks credential material, and a reachable login panel turns that leak into administrative access to the application. Individually moderate issues compose into a single working attack path. The final step was verified against the local lab: the leaked credentials successfully authenticated.

Linked findings: VC-DIR-8899-1, VC-CRED-8899-2, VC-PNL-8899-0, VC-AUTH-OK-8899

## Findings

### VC-CRED-8899-2: Possible credential material exposed: /backups/config.bak

- Severity: high (internal severity, not CVSS-scored)
- Target: 127.0.0.1:8899
- Evidence: GET /backups/config.bak body contains 'PASS=<redacted> (credential-shaped content observed; validity not assumed)
- Remediation: Remove the file from the web root and rotate the credentials.

### VC-AUTH-OK-8899: Verified: exposed credentials grant administrative application access at /admin [verified]

- Severity: high (internal severity, not CVSS-scored)
- Target: 127.0.0.1:8899
- Evidence: Wrong-credential control rejected (HTTP 403); leaked credentials authenticated at /admin; protected /admin/dashboard returned HTTP 200 with the session and HTTP 401 without it. Demonstrated impact: read access to the protected admin page of this lab application.
- Remediation: Rotate the credentials, remove the leak, and enforce MFA.

### VC-HDR-CONTEN-8899: Missing security header: content-security-policy

- Severity: medium (internal severity, not CVSS-scored)
- Target: 127.0.0.1:8899
- Evidence: GET / returned 200 without content-security-policy
- Remediation: Add a Content-Security-Policy header.

### VC-TRACE-8899: Verified: TRACE method responds with a request echo [verified]

- Severity: medium (internal severity, not CVSS-scored)
- Target: 127.0.0.1:8899
- Evidence: TRACE request with a unique marker was echoed by the server (proves TRACE is enabled; browser-side impact not assessed)
- Remediation: Disable TRACE at the web server.

### VC-GIT-8899: Exposed .git metadata

- Severity: medium (internal severity, not CVSS-scored)
- Target: 127.0.0.1:8899
- Evidence: GET /.git/HEAD returned a valid git ref (proves metadata exposure; full source recoverability not verified)
- Remediation: Block dotfile access at the web server; never deploy .git.

### VC-BAN-8899: Server version disclosed: Apache/2.4.49 (Ubuntu)

- Severity: low (internal severity, not CVSS-scored)
- Target: 127.0.0.1:8899
- Evidence: Server: Apache/2.4.49 (Ubuntu)
- Remediation: Suppress version tokens in the server banner.

### VC-PWR-8899: Technology disclosed: PHP/7.4.3

- Severity: low (internal severity, not CVSS-scored)
- Target: 127.0.0.1:8899
- Evidence: X-Powered-By: PHP/7.4.3
- Remediation: Remove the X-Powered-By header.

### VC-HDR-X-CONT-8899: Missing security header: x-content-type-options

- Severity: low (internal severity, not CVSS-scored)
- Target: 127.0.0.1:8899
- Evidence: GET / returned 200 without x-content-type-options
- Remediation: Add 'X-Content-Type-Options: nosniff'.

### VC-HDR-X-FRAM-8899: Missing security header: x-frame-options

- Severity: low (internal severity, not CVSS-scored)
- Target: 127.0.0.1:8899
- Evidence: GET / returned 200 without x-frame-options
- Remediation: Add X-Frame-Options or CSP frame-ancestors.

### VC-HDR-REFERR-8899: Missing security header: referrer-policy

- Severity: low (internal severity, not CVSS-scored)
- Target: 127.0.0.1:8899
- Evidence: GET / returned 200 without referrer-policy
- Remediation: Add a Referrer-Policy header.

### VC-MTH-8899: Dangerous HTTP methods advertised: DELETE, PUT

- Severity: low (internal severity, not CVSS-scored)
- Target: 127.0.0.1:8899
- Evidence: OPTIONS Allow: GET, POST, PUT, DELETE, TRACE, OPTIONS (advertised only; not executed by this tool)
- Remediation: Disable PUT/DELETE unless required; verify what the server actually accepts.

### VC-PNL-8899-0: Login/admin panel found: /admin (HTTP 200)

- Severity: low (internal severity, not CVSS-scored)
- Target: 127.0.0.1:8899
- Evidence: GET /admin returned 200
- Remediation: Restrict panel access by IP/VPN and enforce MFA.

### VC-DIR-8899-1: Directory listing enabled: /backups/

- Severity: low (internal severity, not CVSS-scored)
- Target: 127.0.0.1:8899
- Evidence: GET /backups/ returned a directory index page (listing observed; impact depends on the files exposed)
- Remediation: Disable autoindex/directory listing on the server.

### VC-PORT-8899: Open port 8899 (unknown)

- Severity: info (internal severity, not CVSS-scored)
- Target: 127.0.0.1:8899
- Evidence: TCP connect to 127.0.0.1:8899 succeeded
- Remediation: Confirm this service is intended to be reachable.

### VC-PNL-8899-4: Login/admin panel found: /admin/dashboard (HTTP 401)

- Severity: info (internal severity, not CVSS-scored)
- Target: 127.0.0.1:8899
- Evidence: GET /admin/dashboard returned 401
- Remediation: Restrict panel access by IP/VPN and enforce MFA.

## Limitations

- Automated checks cover reconnaissance and assessment; exploitation and privilege escalation remain manual, authorized activities.
- No CVE feed is bundled; version findings are not matched to known exploits.
- Results reflect the target at test time and the configured wordlist and ports.
- Banner and version findings reflect what the target presents; a lab, proxy or honeypot can simulate banners (the bundled demo lab does exactly that).
- Methods reported as 'advertised' come from an OPTIONS Allow header only; they were not executed. 'Verified' items were confirmed with controls.
