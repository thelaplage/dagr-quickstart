"""Pure adapters from serialized producer envelopes to verifier bundles."""

from __future__ import annotations

from typing import Any


def bundle_from_proof_stage(
    proof_bundle: dict[str, Any], stage_name: str
) -> dict[str, Any]:
    """Extract one proof stage without changing any nested artifact bytes."""

    if stage_name not in {"initial", "revised"}:
        raise ValueError("stage_name must be 'initial' or 'revised'")
    try:
        stage = proof_bundle[stage_name]
        return {
            "schema": "packet_time_claim_binding.v0_1",
            "source_capture_hash": stage["capture_hash"],
            "graph": stage["claim_graph"],
            "packet": stage["context_packet"],
            "walk": stage["packet_walk"],
            "rendered": stage["rendered_packet"],
            "inspection": stage["packet_inspection"],
            "receipt": stage["sovereignty_receipt"],
        }
    except KeyError as exc:
        raise ValueError(
            f"proof bundle stage {stage_name!r} is missing {exc.args[0]!r}"
        ) from exc
