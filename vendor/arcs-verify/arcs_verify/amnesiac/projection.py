"""Public projection contract for an ARCS Verify report."""

from __future__ import annotations

from typing import Any


def project_report(report: dict[str, Any]) -> dict[str, Any]:
    conclusions = dict(report["conclusions"])
    return {
        "schema": "garpedia_arcs_verify_projection.v0_1",
        "artifact_kind": "arcs_verify_report",
        "owned_by": "arcs-verify",
        "produced_by": "arcs-verify",
        "not_produced_by": "garpedia",
        "structural_pass": bool(report["passed"]),
        "report_hash": report["report_hash"],
        "verified_artifacts": dict(report["verified_artifacts"]),
        "conclusions": conclusions,
        "authenticity_claimed": conclusions["authenticity_verified"] == "true",
        "signature_claimed": conclusions["signature_verified"] == "true",
        "boundary_note": report["boundary_note"],
    }
