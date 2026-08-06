"""Smoke test: the minimal governed action holds its contract under reciprocal
producer/verifier separation.

A read is admitted with admission+outcome receipts; the write is refused with a
single refused-admission receipt and its body never runs; the verifier runs in a
SEPARATE environment with no producer packages, every genuine receipt passes, and
a single-field mutation of every receipt is rejected.

Requires the two-environment layout from ``bootstrap.sh`` (a separate
``.venv-verifier`` or ``F1_VERIFIER_PYTHON``). If that is absent the test SKIPS
rather than silently passing on a non-isolated verifier — the separation is the
point of this test.
"""

from __future__ import annotations

import pytest

from dagr_quickstart.governed_action import run_governed_action
from dagr_quickstart.verify import verifier_python


@pytest.fixture(scope="module")
def _require_isolated_verifier():
    try:
        verifier_python()
    except AssertionError as exc:
        pytest.skip(f"no isolated verifier environment: {exc}")


def test_read_admitted_write_refused_verified_with_separation(
    tmp_path, _require_isolated_verifier
):
    result = run_governed_action(receipts_root=tmp_path, verify=True)

    # The read was admitted and returned its payload.
    assert result["read"]["result"] == {"ok": True, "echo": "hello"}

    # Receipt cardinality: read -> admission + outcome; write -> refused-admission.
    card = result["receipt_cardinality"]
    assert card["admission"] >= 1
    assert card["outcome"] >= 1
    assert card["refused_admission"] == 1

    # The refusal is enforced and the write body never ran.
    refusal = result["refusal"]
    assert refusal["enforced"] is True
    assert refusal["body_ran"] is False

    verification = result["verification"]

    # Reciprocal separation: no producer package is discoverable in the verifier.
    assert not any(
        verification["producer_packages_discoverable_in_verifier"].values()
    )

    # Every genuine receipt passes; every mutated receipt is rejected.
    report = verification["report"]
    assert report["receipts"], "expected at least one verified receipt"
    assert report["every_genuine_passed"] is True, report
    assert report["every_mutation_rejected"] is True, report
    for r in report["receipts"]:
        assert r["genuine_all_eight_pass"] is True, r
