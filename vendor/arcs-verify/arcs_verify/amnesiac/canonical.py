"""Independent canonical hashing for serialized Amnesiac artifacts.

This module imports no producer code. Hash payloads are reimplemented from the
serialized contract in arcs-amnesiac commit ca04f5b and are conformance-tested
against committed producer bytes.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def content_hash(payload: dict[str, Any]) -> str:
    serialised = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return "sha256:" + hashlib.sha256(serialised.encode("utf-8")).hexdigest()


def canonical_text(text: str) -> str:
    return " ".join(text.split())


def sha256_prefixed(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def claim_node_content_hash(node: dict[str, Any]) -> str:
    return content_hash(
        {
            "kind": "claim_node",
            "normalized_text": canonical_text(node["normalized_text"]),
            "lifecycle_state": node["lifecycle_state"],
            "source_refs": sorted(node["source_refs"]),
            "anchor_refs": sorted(node["anchor_refs"]),
            "support_state": node["support_state"],
            "verification_state": node["verification_state"],
            "admission_state": node["admission_state"],
            "profile_scope": node.get("profile_scope"),
        }
    )


def claim_edge_content_hash(edge: dict[str, Any]) -> str:
    return content_hash(
        {
            "kind": "claim_edge",
            "from_claim_id": edge["from_claim_id"],
            "to_claim_id": edge["to_claim_id"],
            "edge_type": edge["edge_type"],
            "lifecycle_state": edge["lifecycle_state"],
            "support_refs": sorted(edge["support_refs"]),
            "anchor_refs": sorted(edge["anchor_refs"]),
        }
    )


def claim_graph_substrate_hash(nodes: list[dict], edges: list[dict]) -> str:
    return content_hash(
        {"kind": "claim_graph_state", "nodes": nodes, "edges": edges}
    )


def claim_binding_content_hash(binding: dict[str, Any]) -> str:
    return content_hash(
        {
            "kind": "claim_node",
            "normalized_text": canonical_text(binding["normalized_text"]),
            "lifecycle_state": binding["lifecycle_state"],
            "source_refs": sorted(binding["source_refs"]),
            "anchor_refs": sorted(binding["anchor_refs"]),
            "support_state": binding["support_state"],
            "verification_state": binding["verification_state"],
            "admission_state": binding["admission_state"],
            "profile_scope": binding.get("profile_scope"),
        }
    )


def binding_identity_dict(binding: dict[str, Any]) -> dict[str, Any]:
    return {
        "claim_id": binding["claim_id"],
        "normalized_text": binding["normalized_text"],
        "lifecycle_state": binding["lifecycle_state"],
        "source_refs": list(binding["source_refs"]),
        "anchor_refs": list(binding["anchor_refs"]),
        "support_state": binding["support_state"],
        "verification_state": binding["verification_state"],
        "admission_state": binding["admission_state"],
        "profile_scope": binding.get("profile_scope"),
        "content_hash": binding["content_hash"],
    }


def custody_identity_dict(custody: dict[str, Any]) -> dict[str, Any]:
    return {
        "builder_name": custody["builder_name"],
        "builder_version": custody["builder_version"],
        "builder_input_ref": dict(custody.get("builder_input_ref", {})),
    }


def context_packet_hash(packet: dict[str, Any]) -> str:
    bindings = sorted(packet["claim_bindings"], key=lambda item: item["claim_id"])
    return content_hash(
        {
            "kind": "context_packet",
            "query_text_hash": packet["query_text_hash"],
            "query_ref": packet.get("query_ref"),
            "scope": packet["scope"],
            "substrate_state_hash": packet["substrate_state_hash"],
            "query_plan": packet["query_plan"],
            "evidence_manifest": packet["evidence_manifest"],
            "claim_bindings": [binding_identity_dict(item) for item in bindings],
            "custody_envelope": custody_identity_dict(packet["custody_envelope"]),
            "permission_contract": packet["permission_contract"],
            "verifier": packet["verifier"],
            "admitted_claim_ids": sorted(packet["admitted_claim_ids"]),
            "rejected_candidate_refs": sorted(packet["rejected_candidate_refs"]),
            "unknowns": sorted(packet["unknowns"]),
            "refusal_reasons": sorted(packet["refusal_reasons"]),
        }
    )


def operation_dict(operation: dict[str, Any]) -> dict[str, Any]:
    kind = operation["kind"]
    if kind == "select":
        return {
            "kind": "select",
            "operation_ref": operation["operation_ref"],
            "claim_id": operation["claim_id"],
        }
    if kind == "quote":
        return {
            "kind": "quote",
            "operation_ref": operation["operation_ref"],
            "claim_id": operation["claim_id"],
            "quote_text": operation["quote_text"],
            "claim_content_hash": operation["claim_content_hash"],
            "anchor_refs": list(operation["anchor_refs"]),
            "source_refs": list(operation["source_refs"]),
        }
    if kind == "refuse":
        return {
            "kind": "refuse",
            "operation_ref": operation["operation_ref"],
            "reason": operation["reason"],
            "unsupported_claim_ids": list(
                operation.get("unsupported_claim_ids", [])
            ),
        }
    raise ValueError(f"unsupported operation kind: {kind!r}")


def packet_walk_hash(walk: dict[str, Any]) -> str:
    return content_hash(
        {
            "kind": "packet_walk",
            "walk_id": walk["walk_id"],
            "packet_id": walk["packet_id"],
            "packet_hash": walk["packet_hash"],
            "operations": [operation_dict(item) for item in walk["operations"]],
        }
    )


def rendered_packet_hash(rendered: dict[str, Any]) -> str:
    return content_hash(
        {
            "kind": "rendered_packet",
            "template_kind": rendered["template_kind"],
            "walk_id": rendered["walk_id"],
            "packet_id": rendered["packet_id"],
            "packet_hash": rendered["packet_hash"],
            "walk_hash": rendered["walk_hash"],
            "body": rendered["body"],
            "operation_refs": list(rendered["operation_refs"]),
            "citations": list(rendered["citations"]),
        }
    )


def packet_inspection_hash(inspection: dict[str, Any]) -> str:
    return content_hash(
        {
            "kind": "packet_inspection_projection",
            "packet_id": inspection["packet_id"],
            "packet_hash": inspection["packet_hash"],
            "walk_id": inspection["walk_id"],
            "walk_hash": inspection["walk_hash"],
            "render_hash": inspection.get("render_hash"),
            "renderer_template_kind": inspection.get("renderer_template_kind"),
            "admitted_claim_ids": list(inspection["admitted_claim_ids"]),
            "selected_claim_ids": list(inspection["selected_claim_ids"]),
            "quoted_claim_ids": list(inspection["quoted_claim_ids"]),
            "refusal_reasons": list(inspection["refusal_reasons"]),
            "citation_claim_ids": list(inspection["citation_claim_ids"]),
            "operation_kinds": list(inspection["operation_kinds"]),
            "operation_refs": list(inspection["operation_refs"]),
            "issues": list(inspection["issues"]),
        }
    )


def rendered_body_sha256(body: str) -> str:
    return sha256_prefixed(body.encode("utf-8"))


def sovereignty_receipt_hash(receipt: dict[str, Any]) -> str:
    body = dict(receipt)
    body["receipt_hash"] = ""
    return content_hash(body)


def verification_report_hash(report: dict[str, Any]) -> str:
    body = dict(report)
    body["report_hash"] = ""
    return content_hash(body)
