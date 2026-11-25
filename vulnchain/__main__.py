"""CLI entry point: python -m vulnchain --scope scope.json --out reports/"""

import argparse
import sys

from .pipeline import run_assessment, write_reports
from .scope import Scope, ScopeViolation


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="vulnchain",
        description="Authorized-scope vulnerability assessment with attack-chain correlation.")
    parser.add_argument("--scope", required=True, help="path to the authorized scope JSON")
    parser.add_argument("--out", default="reports", help="output directory")
    parser.add_argument("--format", default="all", choices=["md", "html", "json", "all"])
    args = parser.parse_args(argv)

    try:
        scope = Scope.load(args.scope)
        findings, chains, started, finished = run_assessment(scope)
    except ScopeViolation as exc:
        print(f"SCOPE VIOLATION: {exc}", file=sys.stderr)
        return 2

    formats = ("md", "html", "json") if args.format == "all" else (args.format,)
    paths = write_reports(scope, findings, chains, started, finished, args.out, formats)
    print(f"{len(findings)} findings, {len(chains)} attack chain(s).")
    for kind, path in paths.items():
        print(f"  {kind}: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
