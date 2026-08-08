"""Independent structural verifier for serialized Amnesiac artifact bundles."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from . import canonical
from .replay import LOCKED_RENDERER_TEMPLATES, replay_render, reproduce_inspection

SUPPORTED_SCHEMAS = frozenset({"packet_time_claim_binding.v0_1"})
SUPPORTED_RECEIPT_SCHEMAS = frozenset({"garp.sovereignty_receipt.v0.1"})
ADMITTED_STATES = frozenset({"active", "deprecated", "superseded", "conflicted"})


class Conclusion(str, Enum):
    TRUE = "true"
    FALSE = "false"
    NOT_EVALUATED = "not_evaluated"


@dataclass(frozen=True, slots=True)
class Finding:
    code: str
    detail: str


@dataclass(slots=True)
class VerificationReport:
    integrity_valid: Conclusion = Conclusion.NOT_EVALUATED
    producer_artifacts_consistent: Conclusion = Conclusion.NOT_EVALUATED
    packet_time_bindings_valid: Conclusion = Conclusion.NOT_EVALUATED
    inspection_reproduced: Conclusion = Conclusion.NOT_EVALUATED
    receipt_hashes_valid: Conclusion = Conclusion.NOT_EVALUATED
    authenticity_verified: Conclusion = Conclusion.NOT_EVALUATED
    signature_verified: Conclusion = Conclusion.NOT_EVALUATED
    findings: list[Finding] = field(default_factory=list)
    verified_artifacts: dict[str, Any] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return all(
            conclusion is Conclusion.TRUE
            for conclusion in (
                self.integrity_valid,
                self.producer_artifacts_consistent,
                self.packet_time_bindings_valid,
                self.inspection_reproduced,
                self.receipt_hashes_valid,
            )
        )

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "schema": "arcs_verify.report.v0_1_1",
            "verification_profile": "full_artifact_chain.v0_1",
            "verified_artifacts": dict(self.verified_artifacts),
            "conclusions": {
                "integrity_valid": self.integrity_valid.value,
                "producer_artifacts_consistent": self.producer_artifacts_consistent.value,
                "packet_time_bindings_valid": self.packet_time_bindings_valid.value,
                "inspection_reproduced": self.inspection_reproduced.value,
                "receipt_hashes_valid": self.receipt_hashes_valid.value,
                "authenticity_verified": self.authenticity_verified.value,
                "signature_verified": self.signature_verified.value,
            },
            "passed": self.passed,
            "findings": [
                {"code": item.code, "detail": item.detail} for item in self.findings
            ],
            "boundary_note": (
                "Structural integrity only. A fully rewritten, internally coherent "
                "artifact set can pass. Historical authenticity requires an external "
                "signature, trusted publication record, or previously anchored digest."
            ),
            "report_hash": "",
        }
        payload["report_hash"] = canonical.verification_report_hash(payload)
        return payload


def _fail(report: VerificationReport, code: str, detail: str) -> None:
    report.findings.append(Finding(code=code, detail=detail))


def _required(bundle: dict[str, Any], report: VerificationReport) -> bool:
    required = ("graph", "packet", "walk", "rendered", "inspection", "receipt")
    missing = [key for key in required if bundle.get(key) is None]
    if missing:
        _fail(
            report,
            "missing_required_artifact",
            "full verification requires: " + ", ".join(missing),
        )
        report.integrity_valid = Conclusion.FALSE
        report.producer_artifacts_consistent = Conclusion.FALSE
        report.packet_time_bindings_valid = Conclusion.FALSE
        report.inspection_reproduced = Conclusion.FALSE
        report.receipt_hashes_valid = Conclusion.FALSE
        return False
    return True


def _same_multiset_free(values: list[str]) -> bool:
    return len(values) == len(set(values))


def verify_bundle(bundle: dict[str, Any]) -> VerificationReport:
    report = VerificationReport()
    report.authenticity_verified = Conclusion.NOT_EVALUATED
    report.signature_verified = Conclusion.NOT_EVALUATED

    if not isinstance(bundle, dict):
        _fail(report, "malformed_bundle", "bundle must be a JSON object")
        report.integrity_valid = Conclusion.FALSE
        return report

    schema = bundle.get("schema")
    if schema not in SUPPORTED_SCHEMAS:
        _fail(report, "unsupported_schema", f"schema {schema!r} not supported")
        report.integrity_valid = Conclusion.FALSE
        return report
    if not _required(bundle, report):
        return report

    try:
        graph = bundle["graph"]
        packet = bundle["packet"]
        walk = bundle["walk"]
        rendered = bundle["rendered"]
        inspection = bundle["inspection"]
        receipt = bundle["receipt"]
        report.verified_artifacts = {
            "source_capture_hash": bundle.get("source_capture_hash"),
            "context_packet_id": packet.get("packet_id"),
            "context_packet_hash": packet.get("packet_hash"),
            "packet_walk_id": walk.get("walk_id"),
            "packet_walk_hash": walk.get("walk_hash"),
            "rendered_packet_hash": rendered.get("render_hash"),
            "packet_inspection_hash": inspection.get("inspection_hash"),
            "sovereignty_receipt_hash": receipt.get("receipt_hash"),
        }

        integrity_ok = True
        consistency_ok = True
        bindings_ok = True

        nodes = list(graph["nodes"])
        edges = list(graph["edges"])
        node_ids = [item["claim_id"] for item in nodes]
        edge_ids = [item["edge_id"] for item in edges]
        if node_ids != sorted(node_ids):
            consistency_ok = False
            _fail(report, "graph_node_order_mismatch", "ClaimGraph nodes are not claim_id sorted")
        if edge_ids != sorted(edge_ids):
            consistency_ok = False
            _fail(report, "graph_edge_order_mismatch", "ClaimGraph edges are not edge_id sorted")
        if not _same_multiset_free(node_ids):
            consistency_ok = False
            _fail(report, "duplicate_claim_id", "ClaimGraph contains duplicate claim_id values")
        if not _same_multiset_free(edge_ids):
            consistency_ok = False
            _fail(report, "duplicate_edge_id", "ClaimGraph contains duplicate edge_id values")

        node_by_id = {item["claim_id"]: item for item in nodes}
        for node in nodes:
            recomputed = canonical.claim_node_content_hash(node)
            if node["content_hash"] != recomputed:
                integrity_ok = False
                _fail(
                    report,
                    "claim_node_hash_mismatch",
                    f"{node['claim_id']}: stored={node['content_hash']} recomputed={recomputed}",
                )
        for edge in edges:
            recomputed = canonical.claim_edge_content_hash(edge)
            if edge["content_hash"] != recomputed:
                integrity_ok = False
                _fail(
                    report,
                    "claim_edge_hash_mismatch",
                    f"{edge['edge_id']}: stored={edge['content_hash']} recomputed={recomputed}",
                )
            if edge["from_claim_id"] not in node_by_id or edge["to_claim_id"] not in node_by_id:
                consistency_ok = False
                _fail(report, "edge_endpoint_missing", f"{edge['edge_id']} references an absent ClaimNode")

        substrate_hash = canonical.claim_graph_substrate_hash(nodes, edges)
        report.verified_artifacts["claim_graph_substrate_hash"] = substrate_hash
        if packet["substrate_state_hash"] != substrate_hash:
            integrity_ok = False
            bindings_ok = False
            _fail(
                report,
                "substrate_hash_mismatch",
                f"stored={packet['substrate_state_hash']} recomputed={substrate_hash}",
            )

        bindings = list(packet["claim_bindings"])
        binding_ids = [item["claim_id"] for item in bindings]
        admitted_ids = list(packet["admitted_claim_ids"])
        manifest_ids = list(packet["evidence_manifest"]["claim_ids"])
        for field_name, values in (
            ("admitted_claim_ids", admitted_ids),
            ("evidence_manifest.claim_ids", manifest_ids),
            ("claim_bindings", binding_ids),
        ):
            if not _same_multiset_free(values):
                consistency_ok = False
                _fail(report, "packet_duplicate_claim_id", f"{field_name} contains duplicates")
        if set(admitted_ids) != set(manifest_ids) or set(admitted_ids) != set(binding_ids):
            consistency_ok = False
            bindings_ok = False
            _fail(
                report,
                "packet_binding_shape_mismatch",
                "admitted_claim_ids, evidence_manifest.claim_ids, and claim_bindings differ",
            )

        binding_by_id = {item["claim_id"]: item for item in bindings}
        for binding in bindings:
            recomputed = canonical.claim_binding_content_hash(binding)
            if binding["content_hash"] != recomputed:
                integrity_ok = False
                bindings_ok = False
                _fail(
                    report,
                    "binding_hash_mismatch",
                    f"{binding['claim_id']}: stored={binding['content_hash']} recomputed={recomputed}",
                )
            if binding["lifecycle_state"] not in ADMITTED_STATES:
                bindings_ok = False
                _fail(report, "binding_not_admitted", binding["claim_id"])
            node = node_by_id.get(binding["claim_id"])
            if node is None:
                bindings_ok = False
                _fail(report, "binding_node_missing", binding["claim_id"])
            elif canonical.claim_node_content_hash(node) != binding["content_hash"]:
                bindings_ok = False
                _fail(report, "graph_drift_from_binding", binding["claim_id"])

        expected_anchor_refs = sorted(
            {ref for item in bindings for ref in item["anchor_refs"]}
        )
        expected_source_refs = sorted(
            {ref for item in bindings for ref in item["source_refs"]}
        )
        if packet["evidence_manifest"]["anchor_refs"] != expected_anchor_refs:
            consistency_ok = False
            _fail(report, "manifest_anchor_refs_mismatch", "manifest anchors differ from bindings")
        if packet["evidence_manifest"]["source_refs"] != expected_source_refs:
            consistency_ok = False
            _fail(report, "manifest_source_refs_mismatch", "manifest sources differ from bindings")

        packet_hash = canonical.context_packet_hash(packet)
        if packet["packet_hash"] != packet_hash:
            integrity_ok = False
            _fail(report, "packet_hash_mismatch", f"stored={packet['packet_hash']} recomputed={packet_hash}")

        walk_hash = canonical.packet_walk_hash(walk)
        if walk["walk_hash"] != walk_hash:
            integrity_ok = False
            _fail(report, "walk_hash_mismatch", f"stored={walk['walk_hash']} recomputed={walk_hash}")
        if walk["packet_id"] != packet["packet_id"] or walk["packet_hash"] != packet["packet_hash"]:
            consistency_ok = False
            _fail(report, "walk_packet_mismatch", "PacketWalk does not reference the supplied ContextPacket")

        selected_so_far: set[str] = set()
        quoted_ids: list[str] = []
        for operation in walk["operations"]:
            kind = operation.get("kind")
            claim_id = operation.get("claim_id")
            if kind == "select":
                if claim_id not in set(admitted_ids) or claim_id not in set(manifest_ids):
                    consistency_ok = False
                    _fail(report, "select_claim_not_available", str(claim_id))
                selected_so_far.add(str(claim_id))
            elif kind == "quote":
                quoted_ids.append(str(claim_id))
                binding = binding_by_id.get(str(claim_id))
                if binding is None:
                    bindings_ok = False
                    _fail(report, "quote_without_binding", str(claim_id))
                else:
                    if operation["claim_content_hash"] != binding["content_hash"]:
                        bindings_ok = False
                        _fail(report, "quote_binding_hash_mismatch", str(claim_id))
                    if (
                        operation["quote_text"] != binding["normalized_text"]
                        or list(operation["anchor_refs"]) != list(binding["anchor_refs"])
                        or list(operation["source_refs"]) != list(binding["source_refs"])
                    ):
                        bindings_ok = False
                        _fail(report, "quote_content_differs_from_binding", str(claim_id))
                if str(claim_id) not in selected_so_far:
                    consistency_ok = False
                    _fail(report, "quote_without_select", str(claim_id))
                if not packet["permission_contract"]["may_quote"]:
                    consistency_ok = False
                    _fail(report, "quote_forbidden_by_permission", str(claim_id))
            elif kind == "refuse":
                if not operation.get("reason"):
                    consistency_ok = False
                    _fail(report, "refuse_without_reason", str(operation.get("operation_ref")))
            else:
                consistency_ok = False
                _fail(report, "unsupported_operation_kind", repr(kind))

        render_hash = canonical.rendered_packet_hash(rendered)
        if rendered["render_hash"] != render_hash:
            integrity_ok = False
            _fail(report, "render_hash_mismatch", f"stored={rendered['render_hash']} recomputed={render_hash}")
        if rendered["template_kind"] not in LOCKED_RENDERER_TEMPLATES:
            consistency_ok = False
            _fail(report, "template_outside_lock", rendered["template_kind"])
        if (
            rendered["packet_id"] != packet["packet_id"]
            or rendered["packet_hash"] != packet["packet_hash"]
            or rendered["walk_id"] != walk["walk_id"]
            or rendered["walk_hash"] != walk["walk_hash"]
        ):
            consistency_ok = False
            _fail(report, "render_reference_mismatch", "RenderedPacket does not reference packet and walk")
        try:
            replayed = replay_render(walk, rendered["template_kind"])
        except ValueError as exc:
            consistency_ok = False
            _fail(report, "render_replay_failed", str(exc))
        else:
            for key in ("body", "operation_refs", "citations"):
                if rendered[key] != replayed[key]:
                    consistency_ok = False
                    _fail(report, "render_replay_mismatch", f"rendered.{key} differs from independent replay")

        report.integrity_valid = Conclusion.TRUE if integrity_ok else Conclusion.FALSE
        report.producer_artifacts_consistent = Conclusion.TRUE if consistency_ok else Conclusion.FALSE
        report.packet_time_bindings_valid = Conclusion.TRUE if bindings_ok else Conclusion.FALSE

        expected_inspection = reproduce_inspection(
            graph=graph, packet=packet, walk=walk, rendered=rendered
        )
        inspection_keys = (
            "packet_id",
            "packet_hash",
            "walk_id",
            "walk_hash",
            "render_hash",
            "renderer_template_kind",
            "admitted_claim_ids",
            "selected_claim_ids",
            "quoted_claim_ids",
            "refusal_reasons",
            "citation_claim_ids",
            "operation_kinds",
            "operation_refs",
            "issues",
            "has_blockers",
            "inspection_hash",
        )
        inspection_ok = all(inspection.get(key) == expected_inspection.get(key) for key in inspection_keys)
        if not inspection_ok:
            _fail(report, "inspection_reproduction_mismatch", "supplied PacketInspection differs from independent reproduction")
        if inspection.get("inspection_hash") != canonical.packet_inspection_hash(inspection):
            inspection_ok = False
            integrity_ok = False
            report.integrity_valid = Conclusion.FALSE
            _fail(report, "inspection_hash_mismatch", "stored inspection_hash does not recompute")
        report.inspection_reproduced = Conclusion.TRUE if inspection_ok else Conclusion.FALSE

        receipt_ok = True
        if receipt.get("schema") not in SUPPORTED_RECEIPT_SCHEMAS:
            receipt_ok = False
            _fail(report, "unsupported_receipt_schema", f"receipt schema {receipt.get('schema')!r} not supported")
        if receipt.get("receipt_hash") != canonical.sovereignty_receipt_hash(receipt):
            receipt_ok = False
            _fail(report, "receipt_hash_mismatch", "stored receipt_hash does not recompute")
        expected_artifact_hashes = {
            "context_packet_hash": packet["packet_hash"],
            "packet_walk_hash": walk["walk_hash"],
            "rendered_packet_hash": rendered["render_hash"],
            "rendered_packet_body_sha256": canonical.rendered_body_sha256(rendered["body"]),
            "packet_inspection_hash": inspection["inspection_hash"],
        }
        if bundle.get("source_capture_hash") is not None:
            expected_artifact_hashes["source_capture_hash"] = bundle["source_capture_hash"]
        for key, expected in expected_artifact_hashes.items():
            if receipt.get("artifact_hashes", {}).get(key) != expected:
                receipt_ok = False
                _fail(report, "receipt_artifact_hash_mismatch", f"{key} does not match recomputed artifact")
        if (
            receipt.get("context_packet_ref", {}).get("context_packet_id") != packet["packet_id"]
            or receipt.get("context_packet_ref", {}).get("content_hash") != packet["packet_hash"]
        ):
            receipt_ok = False
            _fail(report, "receipt_packet_ref_mismatch", "context_packet_ref does not match packet")
        if (
            receipt.get("packet_walk_ref", {}).get("packet_walk_id") != walk["walk_id"]
            or receipt.get("packet_walk_ref", {}).get("operation_log_hash") != walk["walk_hash"]
        ):
            receipt_ok = False
            _fail(report, "receipt_walk_ref_mismatch", "packet_walk_ref does not match walk")
        if receipt.get("subject_type") != "render" or receipt.get("subject_ref") != rendered["render_hash"]:
            receipt_ok = False
            _fail(report, "receipt_subject_mismatch", "receipt subject does not match render")
        report.receipt_hashes_valid = Conclusion.TRUE if receipt_ok else Conclusion.FALSE

    except (KeyError, TypeError, ValueError) as exc:
        _fail(report, "malformed_artifact", f"{type(exc).__name__}: {exc}")
        if report.integrity_valid is Conclusion.NOT_EVALUATED:
            report.integrity_valid = Conclusion.FALSE
        if report.producer_artifacts_consistent is Conclusion.NOT_EVALUATED:
            report.producer_artifacts_consistent = Conclusion.FALSE
        if report.packet_time_bindings_valid is Conclusion.NOT_EVALUATED:
            report.packet_time_bindings_valid = Conclusion.FALSE
        if report.inspection_reproduced is Conclusion.NOT_EVALUATED:
            report.inspection_reproduced = Conclusion.FALSE
        if report.receipt_hashes_valid is Conclusion.NOT_EVALUATED:
            report.receipt_hashes_valid = Conclusion.FALSE

    return report
