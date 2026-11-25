# VulnChain demo lab

`vulnerable_app.py` is a deliberately vulnerable web app that binds to
**127.0.0.1 only**. It exists so the full VulnChain pipeline, including the
verified credential chain, can be demonstrated without touching any real
target.

Run it:

    python3 lab/vulnerable_app.py 8899

Then assess it:

    python3 -m vulnchain --scope scope.example.json --out reports/

Intentional flaws: version disclosure, missing security headers, directory
listing on `/backups/` leaking `config.bak` with credentials, an exposed
`/.git/HEAD`, a login panel at `/admin` that accepts the leaked credentials,
and dangerous HTTP methods.

Never expose this app on a non-loopback interface.
