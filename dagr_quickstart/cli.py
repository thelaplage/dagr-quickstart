"""``dagr-quickstart`` console entrypoint.

Runs ONE governed action end to end and prints a checklist: a read admitted by
DAGR, portable receipts emitted and independently verified by arcs-verify, then
the enforced refusal of the write-classed tool. Prints wall-clock time so you can
see it lands well under five minutes.
"""

from __future__ import annotations

import sys
import time

from .governed_action import READ_TOOL, WRITE_TOOL, run_governed_action

CHECK = "✓"  # ✓
CROSS = "✗"  # ✗


def _line(ok: bool, text: str) -> str:
    return f"  {CHECK if ok else CROSS} {text}"


def main(argv: list[str] | None = None) -> int:
    started = time.monotonic()
    result = run_governed_action(verify=True)
    elapsed = time.monotonic() - started

    card = result["receipt_cardinality"]
    verification = result["verification"]
    report = verification["report"]
    verdicts = report["receipts"]
    all_pass = (
        bool(verdicts)
        and report["every_genuine_passed"]
        and report["every_mutation_rejected"]
    )
    producers_absent = not any(
        verification["producer_packages_discoverable_in_verifier"].values()
    )
    read_ok = result["read"]["result"].get("ok") is True
    receipts_ok = card["admission"] >= 1 and card["outcome"] >= 1
    refusal = result["refusal"]
    refusal_ok = refusal["enforced"] and not refusal["body_ran"]

    print()
    print("dagr-quickstart — the minimal governed action")
    print(f"caller → {READ_TOOL}/{WRITE_TOOL} → governed by dagr-mcp "
          "→ signed SRS receipt → arcs-verify")
    print()

    print(_line(read_ok, f"Read tool admitted by DAGR ({READ_TOOL})"))
    print(_line(
        receipts_ok,
        f"Signed receipts emitted ({card['total']} total: "
        f"{card['admission']} admission, {card['outcome']} outcome, "
        f"{card['refused_admission']} refused-admission)",
    ))
    print(_line(
        producers_absent,
        "Verifier environment isolated (producer packages dagr_mcp / "
        "dagr_mcp_service undiscoverable)",
    ))
    print(_line(
        all_pass,
        f"Receipts independently verified by arcs-verify, separate interpreter "
        f"({sum(v['genuine_passed'] for v in verdicts)}/{len(verdicts)} genuine PASS, "
        f"{sum(v['mutation_rejected'] for v in verdicts)}/{len(verdicts)} mutations rejected)",
    ))
    print()
    print(
        f"  {CROSS} {WRITE_TOOL} — REFUSED (write-classed; policy_refused) "
        f"[{refusal['refused_admission_count']} refused-admission receipt, "
        f"body_ran={refusal['body_ran']}]"
    )
    print()
    print(f"Receipts: {result['receipts_dir']}")
    print(f"Keyring:  {result['keyring']}")
    print(f"Elapsed:  {elapsed:.2f}s")
    print()

    ok = read_ok and receipts_ok and producers_absent and all_pass and refusal_ok
    print("RESULT:", "OK" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
