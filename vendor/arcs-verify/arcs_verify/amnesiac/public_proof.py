"""Independent verification of the full two-stage Amnesiac public proof envelope.

This module verifies the Heppner public proof bundle shape produced by
``amnesiac-proof`` -- the *unextracted* envelope with top-level ``initial`` and
``revised`` stages -- as a distinct, explicitly scoped entrypoint from
:func:`arcs_verify.amnesiac.verifier.verify_bundle`, which only accepts a
single already-extracted stage and must remain strict about that.

Each stage is verified independently through the existing single-stage
verifier. A small number of additional cross-stage facts, each already
represented in the committed artifact, are independently recomputed here:
source/proofcase identity continuity, the designated candidate's transition
from non-admitted to admitted, and the initial packet's structural staleness
against the revised graph. No new theory of "coherent evolution" is
introduced, and no aggregate verified badge is produced.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import canonical
from .adapters import bundle_from_proof_stage
from .replay import reproduce_inspection
from .verifier import Conclusion, Finding, VerificationReport, verify_bundle

SUPPORTED_PUBLIC_PROOF_SCHEMAS = frozenset({"heppner_public_proof_bundle.v0_1"})


@dataclass(slots=True)
class CrossStageVerificationReport:
    source_identity_continuous: Conclusion = Conclusion.NOT_EVALUATED
    reconsiderable_to_admitted_transition_valid: Conclusion = Conclusion.NOT_EVALUATED
    initial_reported_stale_against_revised_graph: Conclusion = Conclusion.NOT_EVALUATED
    findings: list[Finding] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(
            conclusion is Conclusion.TRUE
            for conclusion in (
                self.source_identity_continuous,
                self.reconsiderable_to_admitted_transition_valid,
                self.initial_reported_stale_against_revised_graph,
            )
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "conclusions": {
                "source_identity_continuous": self.source_identity_continuous.value,
                "reconsiderable_to_admitted_transition_valid": (
                    self.reconsiderable_to_admitted_transition_valid.value
                ),
                "initial_reported_stale_against_revised_graph": (
                    self.initial_reported_stale_against_revised_graph.value
                ),
            },
            "passed": self.passed,
            "findings": [
                {"code": item.code, "detail": item.detail} for item in self.findings
            ],
        }


@dataclass(slots=True)
class PublicProofVerificationReport:
    proofcase_id: str | None = None
    initial: VerificationReport = field(default_factory=VerificationReport)
    revised: VerificationReport = field(default_factory=VerificationReport)
    cross_stage: CrossStageVerificationReport = field(
        default_factory=CrossStageVerificationReport
    )
    findings: list[Finding] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.initial.passed and self.revised.passed and self.cross_stage.passed

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "schema": "arcs_verify.public_proof_report.v0_1",
            "verification_profile": "amnesiac.public_proof_bundle.v0_1",
            "proofcase_id": self.proofcase_id,
            "sections": {
                "initial": self.initial.to_dict(),
                "revised": self.revised.to_dict(),
                "cross_stage": self.cross_stage.to_dict(),
            },
            "passed": self.passed,
            "findings": [
                {"code": item.code, "detail": item.detail} for item in self.findings
            ],
            "boundary_note": (
                "Structural integrity only, across both proof stages and their "
                "declared revision relationship. A fully rewritten, internally "
                "coherent artifact set can pass. Historical authenticity requires "
                "an external signature, trusted publication record, or "
                "previously anchored digest."
            ),
            "report_hash": "",
        }
        payload["report_hash"] = canonical.verification_report_hash(payload)
        return payload


def _fail(findings: list[Finding], code: str, detail: str) -> None:
    findings.append(Finding(code=code, detail=detail))


def _raw_stage(proof_bundle: dict[str, Any], stage_name: str) -> dict[str, Any] | None:
    stage = proof_bundle.get(stage_name)
    return stage if isinstance(stage, dict) else None


def _verify_source_identity(
    initial_raw: dict[str, Any],
    revised_raw: dict[str, Any],
    proofcase_id: Any,
    cross: CrossStageVerificationReport,
) -> None:
    try:
        ok = True
        if not isinstance(proofcase_id, str) or not proofcase_id:
            ok = False
            _fail(cross.findings, "missing_proofcase_id", "top-level proofcase_id is absent or empty")

        initial_packet = initial_raw["context_packet"]
        revised_packet = revised_raw["context_packet"]

        if initial_packet["query_ref"] != revised_packet["query_ref"]:
            ok = False
            _fail(cross.findings, "query_ref_mismatch", "initial and revised stages reference different query_ref")
        if initial_packet["query_text_hash"] != revised_packet["query_text_hash"]:
            ok = False
            _fail(cross.findings, "query_text_hash_mismatch", "initial and revised stages reference different query_text_hash")
        if initial_packet["scope"] != revised_packet["scope"]:
            ok = False
            _fail(cross.findings, "scope_mismatch", "initial and revised stages have different ContextPacket.scope")

        initial_source_ref = initial_packet["custody_envelope"]["builder_input_ref"].get("source_ref")
        revised_source_ref = revised_packet["custody_envelope"]["builder_input_ref"].get("source_ref")
        if initial_source_ref != revised_source_ref:
            ok = False
            _fail(cross.findings, "source_ref_mismatch", "initial and revised stages reference different source_ref")

        if isinstance(proofcase_id, str) and proofcase_id:
            expected_prefix = f"context_packet:{proofcase_id}:"
            for label, packet in (("initial", initial_packet), ("revised", revised_packet)):
                if not str(packet.get("packet_id", "")).startswith(expected_prefix):
                    ok = False
                    _fail(
                        cross.findings,
                        "packet_id_proofcase_mismatch",
                        f"{label} packet_id does not reference declared proofcase_id {proofcase_id!r}",
                    )

        cross.source_identity_continuous = Conclusion.TRUE if ok else Conclusion.FALSE
    except (KeyError, TypeError):
        cross.source_identity_continuous = Conclusion.FALSE
        _fail(cross.findings, "source_identity_malformed", "could not evaluate source identity continuity")


def _verify_reconsiderable_to_admitted_transition(
    proof_bundle: dict[str, Any],
    initial_raw: dict[str, Any],
    revised_raw: dict[str, Any],
    cross: CrossStageVerificationReport,
) -> None:
    try:
        reopening = proof_bundle.get("reopening")
        if not isinstance(reopening, dict):
            cross.reconsiderable_to_admitted_transition_valid = Conclusion.FALSE
            _fail(cross.findings, "missing_reopening_block", "proof bundle has no reopening block")
            return

        request = reopening.get("request", {})
        outcome = reopening.get("outcome", {})
        candidate_ref = outcome.get("candidate_ref")
        ok = True

        if not candidate_ref or request.get("candidate_ref") != candidate_ref:
            ok = False
            _fail(cross.findings, "reopening_candidate_ref_mismatch", "reopening request and outcome disagree on candidate_ref")
        if request.get("request_ref") != outcome.get("request_ref"):
            ok = False
            _fail(cross.findings, "reopening_request_ref_mismatch", "reopening request and outcome disagree on request_ref")

        initial_receipts = [
            item
            for item in initial_raw.get("admission_receipts", [])
            if item.get("candidate_ref") == candidate_ref
        ]
        if not initial_receipts or any(
            item.get("decision") == "admit" or item.get("claim_id") is not None
            for item in initial_receipts
        ):
            ok = False
            _fail(
                cross.findings,
                "candidate_not_reconsiderable_in_initial",
                f"candidate_ref {candidate_ref!r} was not a non-admitted candidate in the initial stage",
            )
        if candidate_ref not in initial_raw.get("rejected_candidate_refs", []):
            ok = False
            _fail(
                cross.findings,
                "candidate_not_in_initial_rejected_refs",
                f"candidate_ref {candidate_ref!r} is missing from initial rejected_candidate_refs",
            )

        revised_receipts = [
            item
            for item in revised_raw.get("admission_receipts", [])
            if item.get("candidate_ref") == candidate_ref and item.get("decision") == "admit"
        ]
        admitted_claim_id = revised_receipts[0].get("claim_id") if revised_receipts else None
        if not revised_receipts or not admitted_claim_id:
            ok = False
            _fail(
                cross.findings,
                "candidate_not_admitted_in_revised",
                f"candidate_ref {candidate_ref!r} has no admitted receipt with a claim_id in the revised stage",
            )
        if candidate_ref in revised_raw.get("rejected_candidate_refs", []):
            ok = False
            _fail(
                cross.findings,
                "candidate_still_rejected_in_revised",
                f"candidate_ref {candidate_ref!r} is still present in revised rejected_candidate_refs",
            )

        if admitted_claim_id:
            revised_node_ids = {node["claim_id"] for node in revised_raw["claim_graph"]["nodes"]}
            if admitted_claim_id not in revised_node_ids:
                ok = False
                _fail(
                    cross.findings,
                    "admitted_claim_absent_from_revised_graph",
                    f"claim_id {admitted_claim_id!r} is not present in the revised ClaimGraph",
                )
            if admitted_claim_id not in revised_raw["context_packet"]["admitted_claim_ids"]:
                ok = False
                _fail(
                    cross.findings,
                    "admitted_claim_absent_from_revised_packet",
                    f"claim_id {admitted_claim_id!r} is not present in the revised ContextPacket.admitted_claim_ids",
                )

        cross.reconsiderable_to_admitted_transition_valid = Conclusion.TRUE if ok else Conclusion.FALSE
    except (KeyError, TypeError):
        cross.reconsiderable_to_admitted_transition_valid = Conclusion.FALSE
        _fail(cross.findings, "transition_malformed", "could not evaluate the reconsiderable-to-admitted transition")


def _verify_initial_staleness(
    proof_bundle: dict[str, Any],
    initial_raw: dict[str, Any],
    revised_raw: dict[str, Any],
    cross: CrossStageVerificationReport,
) -> None:
    stale = proof_bundle.get("stale_initial_inspection_against_revised_graph")
    if not isinstance(stale, dict):
        cross.initial_reported_stale_against_revised_graph = Conclusion.FALSE
        _fail(cross.findings, "missing_stale_inspection_block", "proof bundle has no stale_initial_inspection_against_revised_graph block")
        return
    try:
        recomputed = reproduce_inspection(
            graph=revised_raw["claim_graph"],
            packet=initial_raw["context_packet"],
            walk=initial_raw["packet_walk"],
            rendered=initial_raw["rendered_packet"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        cross.initial_reported_stale_against_revised_graph = Conclusion.FALSE
        _fail(cross.findings, "stale_inspection_reproduction_failed", f"{type(exc).__name__}: {exc}")
        return

    ok = True
    if recomputed != stale:
        ok = False
        _fail(
            cross.findings,
            "stale_inspection_mismatch",
            "independently reproduced staleness inspection differs from the committed stale_initial_inspection_against_revised_graph block",
        )
    if not recomputed.get("has_blockers") or not any(
        item.get("code") == "claim_graph_drift" for item in recomputed.get("issues", [])
    ):
        ok = False
        _fail(
            cross.findings,
            "stale_inspection_not_genuinely_stale",
            "recomputed staleness inspection does not independently show claim_graph_drift blockers",
        )

    cross.initial_reported_stale_against_revised_graph = Conclusion.TRUE if ok else Conclusion.FALSE


def verify_public_proof_bundle(proof_bundle: dict[str, Any]) -> PublicProofVerificationReport:
    """Independently verify a full two-stage Amnesiac public proof envelope.

    Each stage is verified independently via :func:`verify_bundle`. A bounded
    set of cross-stage facts already represented in the artifact -- source
    identity continuity, the designated reconsiderable-to-admitted candidate
    transition, and the initial packet's structural staleness against the
    revised graph -- are independently recomputed and reported separately.
    """

    report = PublicProofVerificationReport()

    if not isinstance(proof_bundle, dict):
        _fail(report.findings, "malformed_proof_bundle", "proof bundle must be a JSON object")
        return report

    schema = proof_bundle.get("schema")
    if schema not in SUPPORTED_PUBLIC_PROOF_SCHEMAS:
        _fail(report.findings, "unsupported_proof_bundle_schema", f"schema {schema!r} not supported")
        return report

    report.proofcase_id = proof_bundle.get("proofcase_id")

    try:
        initial_bundle = bundle_from_proof_stage(proof_bundle, "initial")
    except ValueError as exc:
        _fail(report.findings, "missing_initial_stage", str(exc))
        initial_bundle = None
    try:
        revised_bundle = bundle_from_proof_stage(proof_bundle, "revised")
    except ValueError as exc:
        _fail(report.findings, "missing_revised_stage", str(exc))
        revised_bundle = None

    if initial_bundle is not None:
        report.initial = verify_bundle(initial_bundle)
    if revised_bundle is not None:
        report.revised = verify_bundle(revised_bundle)

    initial_raw = _raw_stage(proof_bundle, "initial")
    revised_raw = _raw_stage(proof_bundle, "revised")
    if initial_raw is None or revised_raw is None:
        _fail(
            report.cross_stage.findings,
            "cross_stage_unevaluable",
            "cross-stage facts cannot be evaluated without both raw stage objects",
        )
        report.cross_stage.source_identity_continuous = Conclusion.FALSE
        report.cross_stage.reconsiderable_to_admitted_transition_valid = Conclusion.FALSE
        report.cross_stage.initial_reported_stale_against_revised_graph = Conclusion.FALSE
        return report

    _verify_source_identity(initial_raw, revised_raw, report.proofcase_id, report.cross_stage)
    _verify_reconsiderable_to_admitted_transition(proof_bundle, initial_raw, revised_raw, report.cross_stage)
    _verify_initial_staleness(proof_bundle, initial_raw, revised_raw, report.cross_stage)

    return report
