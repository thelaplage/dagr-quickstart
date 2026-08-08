"""Independent replay of locked renderer templates and inspector projections."""

from __future__ import annotations

from typing import Any

from . import canonical

LOCKED_RENDERER_TEMPLATES = frozenset(
    {
        "quote_with_source",
        "summary_with_sources",
        "refusal_with_reason",
        "comparison",
    }
)


def _quote_operations(walk: dict[str, Any]) -> list[dict[str, Any]]:
    return [item for item in walk["operations"] if item.get("kind") == "quote"]


def _refuse_operations(walk: dict[str, Any]) -> list[dict[str, Any]]:
    return [item for item in walk["operations"] if item.get("kind") == "refuse"]


def _citation(operation: dict[str, Any]) -> dict[str, Any]:
    return {
        "claim_id": operation["claim_id"],
        "anchor_refs": list(operation["anchor_refs"]),
        "source_refs": list(operation["source_refs"]),
    }


def _sources_line(operation: dict[str, Any]) -> str:
    anchors = ", ".join(operation["anchor_refs"]) if operation["anchor_refs"] else "none"
    sources = ", ".join(operation["source_refs"]) if operation["source_refs"] else "none"
    return f"claim={operation['claim_id']}; anchors={anchors}; sources={sources}"


def replay_render(walk: dict[str, Any], template_kind: str) -> dict[str, Any]:
    quotes = _quote_operations(walk)
    refusals = _refuse_operations(walk)
    sections: list[str]
    operation_refs: list[str] = []
    citations: list[dict[str, Any]] = []

    if template_kind == "quote_with_source":
        if not quotes:
            raise ValueError("quote_with_source requires at least one quote operation")
        sections = ["QUOTE_WITH_SOURCE"]
        for index, quote in enumerate(quotes, start=1):
            sections.extend(
                [
                    f"[{index}] {quote['quote_text']}",
                    f"source: {_sources_line(quote)}",
                ]
            )
            operation_refs.append(quote["operation_ref"])
            citations.append(_citation(quote))
    elif template_kind == "summary_with_sources":
        if not quotes:
            raise ValueError("summary_with_sources requires at least one quote operation")
        sections = ["SUMMARY_WITH_SOURCES"]
        for index, quote in enumerate(quotes, start=1):
            sections.extend(
                [
                    f"- item {index}: {quote['quote_text']}",
                    f"  source: {_sources_line(quote)}",
                ]
            )
            operation_refs.append(quote["operation_ref"])
            citations.append(_citation(quote))
    elif template_kind == "refusal_with_reason":
        if not refusals:
            raise ValueError("refusal_with_reason requires at least one refuse operation")
        sections = ["REFUSAL_WITH_REASON"]
        for index, refusal in enumerate(refusals, start=1):
            unsupported = (
                ", ".join(refusal.get("unsupported_claim_ids", []))
                if refusal.get("unsupported_claim_ids", [])
                else "none"
            )
            sections.extend(
                [
                    f"[{index}] reason: {refusal['reason']}",
                    f"unsupported_claim_ids: {unsupported}",
                ]
            )
            operation_refs.append(refusal["operation_ref"])
    elif template_kind == "comparison":
        if len(quotes) < 2:
            raise ValueError("comparison requires at least two quote operations")
        sections = ["COMPARISON"]
        for index, quote in enumerate(quotes, start=1):
            sections.extend(
                [
                    f"branch {index}:",
                    f"quote: {quote['quote_text']}",
                    f"source: {_sources_line(quote)}",
                ]
            )
            operation_refs.append(quote["operation_ref"])
            citations.append(_citation(quote))
    else:
        raise ValueError(f"unsupported renderer template: {template_kind!r}")

    return {
        "template_kind": template_kind,
        "walk_id": walk["walk_id"],
        "packet_id": walk["packet_id"],
        "packet_hash": walk["packet_hash"],
        "walk_hash": walk["walk_hash"],
        "body": "\n".join(sections),
        "operation_refs": operation_refs,
        "citations": citations,
    }


def issue(code: str, message: str, ref: str | None) -> dict[str, Any]:
    return {
        "code": code,
        "severity": "blocker",
        "message": message,
        "ref": ref,
    }


def _packet_binding_shape_findings(packet: dict[str, Any]) -> list[str]:
    findings: list[str] = []
    admitted = list(packet["admitted_claim_ids"])
    manifest = list(packet["evidence_manifest"]["claim_ids"])
    binding_ids = [item["claim_id"] for item in packet["claim_bindings"]]
    if len(admitted) != len(set(admitted)):
        findings.append("admitted_claim_ids contains duplicates")
    if len(manifest) != len(set(manifest)):
        findings.append("evidence_manifest.claim_ids contains duplicates")
    if len(binding_ids) != len(set(binding_ids)):
        findings.append("claim_bindings contains duplicates")
    if set(admitted) != set(manifest):
        findings.append("admitted_claim_ids and evidence_manifest.claim_ids differ")
    if set(admitted) != set(binding_ids):
        findings.append("admitted_claim_ids and claim_bindings differ")
    return findings


def reproduce_inspection(
    *,
    graph: dict[str, Any],
    packet: dict[str, Any],
    walk: dict[str, Any],
    rendered: dict[str, Any],
) -> dict[str, Any]:
    """Reproduce the producer PacketInspectionProjection from serialized data."""

    issues: list[dict[str, Any]] = []
    selected_claim_ids: list[str] = []
    selected_so_far: set[str] = set()
    quoted_claim_ids: list[str] = []
    refusal_reasons: list[str] = []
    operation_kinds: list[str] = []
    operation_refs: list[str] = []

    for finding in _packet_binding_shape_findings(packet):
        issues.append(issue("claim_binding_integrity", finding, packet["packet_id"]))
    for binding in packet["claim_bindings"]:
        recomputed = canonical.claim_binding_content_hash(binding)
        if binding["content_hash"] != recomputed:
            issues.append(
                issue(
                    "claim_binding_integrity",
                    (
                        f"claim binding hash mismatch for {binding['claim_id']}: "
                        f"stored={binding['content_hash']} recomputed={recomputed}"
                    ),
                    packet["packet_id"],
                )
            )
    recomputed_packet_hash = canonical.context_packet_hash(packet)
    if packet["packet_hash"] != recomputed_packet_hash:
        issues.append(
            issue(
                "packet_hash_mismatch",
                (
                    "packet hash mismatch: "
                    f"stored={packet['packet_hash']} recomputed={recomputed_packet_hash}"
                ),
                packet["packet_id"],
            )
        )

    recomputed_walk_hash = canonical.packet_walk_hash(walk)
    if walk["walk_hash"] != recomputed_walk_hash:
        issues.append(
            issue(
                "walk_hash_mismatch",
                (
                    "PacketWalk.walk_hash does not match recomputed operations: "
                    f"stored={walk['walk_hash']} recomputed={recomputed_walk_hash}"
                ),
                walk["walk_id"],
            )
        )

    nodes = {item["claim_id"]: item for item in graph.get("nodes", [])}
    substrate_hash = canonical.claim_graph_substrate_hash(
        graph.get("nodes", []), graph.get("edges", [])
    )
    if packet["substrate_state_hash"] != substrate_hash:
        issues.append(
            issue(
                "claim_graph_drift",
                (
                    "ClaimGraph state differs from packet-time substrate hash: "
                    f"stored={packet['substrate_state_hash']} recomputed={substrate_hash}"
                ),
                packet["packet_id"],
            )
        )
    for binding in packet["claim_bindings"]:
        node = nodes.get(binding["claim_id"])
        if node is None:
            issues.append(
                issue(
                    "claim_graph_drift",
                    (
                        "packet-time claim binding is absent from ClaimGraph: "
                        f"{binding['claim_id']}"
                    ),
                    binding["claim_id"],
                )
            )
            continue
        node_hash = canonical.claim_node_content_hash(node)
        if node["content_hash"] != node_hash:
            issues.append(
                issue(
                    "claim_node_hash_mismatch",
                    (
                        f"ClaimNode content_hash mismatch for {binding['claim_id']}: "
                        f"stored={node['content_hash']} recomputed={node_hash}"
                    ),
                    binding["claim_id"],
                )
            )
        if node_hash != binding["content_hash"]:
            issues.append(
                issue(
                    "claim_graph_drift",
                    f"ClaimNode differs from packet-time binding: {binding['claim_id']}",
                    binding["claim_id"],
                )
            )

    if packet["packet_id"] != walk["packet_id"]:
        issues.append(
            issue(
                "packet_walk_mismatch",
                "PacketWalk.packet_id does not match ContextPacket.packet_id",
                walk["walk_id"],
            )
        )
    if packet["packet_hash"] != walk["packet_hash"]:
        issues.append(
            issue(
                "packet_walk_mismatch",
                "PacketWalk.packet_hash does not match ContextPacket.packet_hash",
                walk["walk_id"],
            )
        )

    bindings = {item["claim_id"]: item for item in packet["claim_bindings"]}
    admitted = set(packet["admitted_claim_ids"])
    manifest = set(packet["evidence_manifest"]["claim_ids"])
    for operation in walk["operations"]:
        kind = str(operation.get("kind"))
        operation_ref = operation.get("operation_ref")
        operation_kinds.append(kind)
        if isinstance(operation_ref, str):
            operation_refs.append(operation_ref)

        if kind == "select":
            claim_id = operation["claim_id"]
            selected_claim_ids.append(claim_id)
            selected_so_far.add(claim_id)
            if claim_id not in admitted:
                issues.append(
                    issue(
                        "claim_not_in_context_packet",
                        f"claim_id is not in ContextPacket.admitted_claim_ids: {claim_id}",
                        operation_ref,
                    )
                )
            if claim_id not in manifest:
                issues.append(
                    issue(
                        "claim_not_in_context_packet",
                        f"claim_id is not in ContextPacket.evidence_manifest.claim_ids: {claim_id}",
                        operation_ref,
                    )
                )
            continue

        if kind == "quote":
            claim_id = operation["claim_id"]
            quoted_claim_ids.append(claim_id)
            if claim_id not in admitted:
                issues.append(
                    issue(
                        "claim_not_in_context_packet",
                        f"claim_id is not in ContextPacket.admitted_claim_ids: {claim_id}",
                        operation_ref,
                    )
                )
            if claim_id not in manifest:
                issues.append(
                    issue(
                        "claim_not_in_context_packet",
                        f"claim_id is not in ContextPacket.evidence_manifest.claim_ids: {claim_id}",
                        operation_ref,
                    )
                )
            binding = bindings.get(claim_id)
            if binding is None:
                issues.append(
                    issue(
                        "claim_binding_integrity",
                        f"QuoteOperation claim_id has no packet-time binding: {claim_id}",
                        operation_ref,
                    )
                )
            else:
                if operation["claim_content_hash"] != binding["content_hash"]:
                    issues.append(
                        issue(
                            "quote_binding_mismatch",
                            (
                                "QuoteOperation claim_content_hash differs from "
                                f"packet-time binding: {claim_id}"
                            ),
                            operation_ref,
                        )
                    )
                if (
                    operation["quote_text"] != binding["normalized_text"]
                    or list(operation["anchor_refs"]) != list(binding["anchor_refs"])
                    or list(operation["source_refs"]) != list(binding["source_refs"])
                ):
                    issues.append(
                        issue(
                            "quote_binding_mismatch",
                            (
                                "QuoteOperation content differs from packet-time "
                                f"claim snapshot: {claim_id}"
                            ),
                            operation_ref,
                        )
                    )
            if claim_id not in selected_so_far:
                issues.append(
                    issue(
                        "quote_without_select",
                        "QuoteOperation appears before matching SelectOperation",
                        operation_ref,
                    )
                )
            if not packet["permission_contract"]["may_quote"]:
                issues.append(
                    issue(
                        "quote_forbidden_by_permission",
                        (
                            "QuoteOperation exists despite ContextPacket "
                            "permission_contract.may_quote=False"
                        ),
                        operation_ref,
                    )
                )
            continue

        if kind == "refuse":
            refusal_reasons.append(operation["reason"])
            continue

        issues.append(
            issue(
                "unsupported_operation_kind",
                f"Unsupported PacketWalk operation kind: {kind!r}",
                str(operation_ref) if operation_ref else None,
            )
        )

    recomputed_render_hash = canonical.rendered_packet_hash(rendered)
    if rendered["render_hash"] != recomputed_render_hash:
        issues.append(
            issue(
                "render_hash_mismatch",
                (
                    "RenderedPacket.render_hash does not match recomputed content: "
                    f"stored={rendered['render_hash']} recomputed={recomputed_render_hash}"
                ),
                rendered["render_hash"],
            )
        )
    if rendered["template_kind"] not in LOCKED_RENDERER_TEMPLATES:
        issues.append(
            issue(
                "template_outside_lock",
                f"Renderer template outside doctrine lock: {rendered['template_kind']!r}",
                rendered["render_hash"],
            )
        )
    if rendered["packet_id"] != packet["packet_id"]:
        issues.append(
            issue(
                "render_mismatch",
                "RenderedPacket.packet_id does not match ContextPacket.packet_id",
                rendered["render_hash"],
            )
        )
    if rendered["packet_hash"] != packet["packet_hash"]:
        issues.append(
            issue(
                "render_mismatch",
                "RenderedPacket.packet_hash does not match ContextPacket.packet_hash",
                rendered["render_hash"],
            )
        )
    if rendered["walk_id"] != walk["walk_id"]:
        issues.append(
            issue(
                "render_mismatch",
                "RenderedPacket.walk_id does not match PacketWalk.walk_id",
                rendered["render_hash"],
            )
        )
    if rendered["walk_hash"] != walk["walk_hash"]:
        issues.append(
            issue(
                "render_mismatch",
                "RenderedPacket.walk_hash does not match PacketWalk.walk_hash",
                rendered["render_hash"],
            )
        )

    citation_claim_ids: list[str] = []
    for citation in rendered["citations"]:
        citation_claim_ids.append(citation["claim_id"])
        if citation["claim_id"] not in quoted_claim_ids:
            issues.append(
                issue(
                    "citation_without_quote",
                    "Rendered citation does not correspond to a QuoteOperation claim_id",
                    citation["claim_id"],
                )
            )

    projection = {
        "packet_id": packet["packet_id"],
        "packet_hash": packet["packet_hash"],
        "walk_id": walk["walk_id"],
        "walk_hash": walk["walk_hash"],
        "render_hash": rendered["render_hash"],
        "renderer_template_kind": rendered["template_kind"],
        "admitted_claim_ids": list(packet["admitted_claim_ids"]),
        "selected_claim_ids": selected_claim_ids,
        "quoted_claim_ids": quoted_claim_ids,
        "refusal_reasons": refusal_reasons,
        "citation_claim_ids": citation_claim_ids,
        "operation_kinds": operation_kinds,
        "operation_refs": operation_refs,
        "issues": issues,
    }
    projection["has_blockers"] = any(item["severity"] == "blocker" for item in issues)
    projection["inspection_hash"] = canonical.packet_inspection_hash(projection)
    return projection
