"""Command-line entry point for the Amnesiac artifact-chain profile."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .adapters import bundle_from_proof_stage
from .verifier import verify_bundle


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="arcs-verify amnesiac-chain",
        description="Independently verify a serialized Amnesiac artifact chain.",
    )
    parser.add_argument("bundle", type=Path, help="Bundle JSON path, or - for stdin.")
    parser.add_argument(
        "--stage",
        choices=("initial", "revised"),
        help="Extract this stage from a Heppner proof_bundle.json envelope.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code)

    try:
        if str(args.bundle) == "-":
            payload = json.load(sys.stdin)
        else:
            payload = json.loads(args.bundle.read_text(encoding="utf-8"))
        bundle = bundle_from_proof_stage(payload, args.stage) if args.stage else payload
    except FileNotFoundError:
        print(f"arcs-verify: bundle not found: {args.bundle}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"arcs-verify: invalid JSON: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"arcs-verify: invalid proof bundle: {exc}", file=sys.stderr)
        return 2

    report = verify_bundle(bundle)
    json.dump(report.to_dict(), sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
