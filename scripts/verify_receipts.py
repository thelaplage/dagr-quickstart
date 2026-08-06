"""Independent receipt verification — runs under the SEPARATE verifier interpreter.

This script is executed by ``dagr_quickstart.verify`` under a distinct interpreter
named by ``F1_VERIFIER_PYTHON`` (see ``ENV_POSTURE.md``). It imports ``arcs_verify``
from that interpreter's own site-packages and must never see the producer/emitter
packages (``dagr_mcp``, ``dagr_mcp_service``). It is invoked in a fresh process so
the verifier never shares memory with the producer.

For each emitted receipt it records, per receipt and per dimension:
  * the genuine envelope's eight boolean checks (each PASS/FAIL) and ``passed``;
  * a single-field mutation which MUST fail (tamper-evidence).

It produces NO aggregate "verified / trusted / safe" verdict — per-receipt,
per-dimension results only, plus a machine-readable ``--report`` JSON.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import subprocess
import sys
from pathlib import Path

PROFILE = "srs.mcp.sdk_enforcement.v0.1"
PRODUCER_PACKAGES = ("dagr_mcp", "dagr_mcp_service")
BOOLEAN_CHECKS = (
    "schema_digest",
    "envelope",
    "profile",
    "raw_content_exclusion",
    "signature_valid",
    "issuer_key_resolved",
    "issuer_key_trusted",
    "attestation_limits_present",
)


def _cli_verify(receipt_path: Path, keyring: Path) -> dict:
    """Run the arcs-verify CLI under THIS (verifier) interpreter, return its JSON."""
    completed = subprocess.run(
        [sys.executable, "-m", "arcs_verify.cli", str(receipt_path),
         "--keyring", str(keyring), "--profile", PROFILE, "--json"],
        capture_output=True, text=True, check=False,
    )
    if not completed.stdout.strip():
        raise RuntimeError(
            f"arcs-verify produced no output (exit {completed.returncode}): "
            f"{completed.stderr.strip()}"
        )
    return json.loads(completed.stdout)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receipts_dir", type=Path)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--report", type=Path, default=None)
    args = parser.parse_args()

    receipts_dir = args.receipts_dir.resolve()
    bundle = args.bundle.resolve()
    report_path = args.report.resolve() if args.report else None

    # Producer isolation: no producer/emitter module may be importable OR already
    # loaded in this verifier process. This is the reciprocal-separation guard.
    import importlib.util as u
    discoverable = {n: (u.find_spec(n) is not None) for n in PRODUCER_PACKAGES}
    if any(discoverable.values()):
        print(json.dumps({"error": "producer packages discoverable in verifier",
                          "discoverable": discoverable}))
        return 2
    import arcs_verify  # noqa: F401  (imported only after the guard passes)
    leaked = sorted(
        m for m in sys.modules
        if any(m == p or m.startswith(p + ".") for p in PRODUCER_PACKAGES)
    )
    if leaked:
        print(json.dumps({"error": "producer modules loaded in verifier",
                          "leaked": leaked}))
        return 2

    receipt_files = sorted(receipts_dir.glob("urn_srs_receipt_*.json"))
    if not receipt_files:
        print(json.dumps({"error": f"no receipts in {receipts_dir}"}))
        return 2

    results = []
    for rf in receipt_files:
        genuine = _cli_verify(rf, bundle)

        # Tamper-evidence: mutate one signed field; verification MUST now fail.
        receipt = json.loads(rf.read_text(encoding="utf-8"))
        mutated = copy.deepcopy(receipt)
        mutated["receipt_id"] = str(mutated.get("receipt_id", "")) + "-tampered"
        tmp = receipts_dir / (rf.stem + ".mutated.json")
        tmp.write_text(json.dumps(mutated), encoding="utf-8")
        try:
            mutated_result = _cli_verify(tmp, bundle)
        finally:
            tmp.unlink(missing_ok=True)

        results.append({
            "receipt_file": rf.name,
            "boolean_checks": {c: ("PASS" if genuine.get(c) else "FAIL")
                               for c in BOOLEAN_CHECKS},
            "genuine_passed": bool(genuine.get("passed")),
            "genuine_all_eight_pass": all(genuine.get(c) for c in BOOLEAN_CHECKS),
            "mutation_rejected": not bool(mutated_result.get("passed")),
            "chain_status": genuine.get("chain_status", "not_applicable"),
        })

    report = {
        "verifier": "arcs-verify (separate F1 interpreter; producer packages absent)",
        "verifier_interpreter": sys.executable,
        "profile": PROFILE,
        "producer_packages_discoverable": discoverable,   # all False
        "receipts_dir": str(receipts_dir),
        "receipts": results,
        # Convenience booleans — still per-receipt derived, NOT an aggregate verdict.
        "every_genuine_passed": all(r["genuine_passed"] for r in results),
        "every_mutation_rejected": all(r["mutation_rejected"] for r in results),
    }
    if report_path:
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    # Exit non-zero if any genuine receipt failed OR any mutation was accepted.
    ok = report["every_genuine_passed"] and report["every_mutation_rejected"]
    print(json.dumps(report))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
