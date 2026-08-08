"""Native Amnesiac service: the only layer that imports ``arcs_amnesiac``.

This translates the framework-neutral contracts into real producer calls. It
imports the producer because faithful execution of producer semantics is its
product property. That is the deliberate opposite of ARCS Verify, which must
not import the producer because independence is *its* product property.

The import is guarded. If ``arcs_amnesiac`` is not installed, the module still
loads, and every operation raises ``CapabilityUnavailable`` (which the binding
translates into a fail-closed error result) rather than crashing. The server
therefore fails closed on a missing producer.

Backing levels, stated honestly:

  propose_candidates   real: constructs ``CandidateClaim`` objects and persists
                       them through an injected ``CandidateStore``. Never admits.
  record_outcome       real: refs-only ``bridge_agent_outcome_to_candidate``;
                       persists the produced candidate. Never admits.
  compile_context      reference selector v0: deterministic lifecycle + scope +
                       as_of filtering over a real ``ClaimGraph``, then the real
                       ``build_context_packet_from_graph``. Not governed retrieval.
  request_reopening    real ShadowGraph reopening through the real transition
                       guard. Available only against a producer tree whose FINAL
                       guard is *confirmed by probe*; otherwise capability
                       unavailable. Never lets the MCP caller choose REOPENED.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
from typing import TYPE_CHECKING, Any, Mapping, Protocol

from .amnesiac_contracts import (
    AdmissionStatus,
    CandidateResult,
    CapabilityUnavailable,
    CompileContextRequest,
    CompileContextResponse,
    ExcludedItem,
    ProposalStatus,
    ProposeCandidatesRequest,
    ProposeCandidatesResponse,
    RawPayloadRefused,
    RecordOutcomeRequest,
    RecordOutcomeResponse,
    ReopeningStatus,
    RequestReopeningRequest,
    RequestReopeningResponse,
)
from .amnesiac_stores import (
    AgentOutcomeStore,
    CandidateStore,
    ContextPacketStore,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from arcs_amnesiac.context_packet import ContextPacketScope
    from arcs_amnesiac.shadow_graph import ShadowGraph

# Availability is detected WITHOUT importing the producer. ``dagr_mcp`` carries a
# permanent import-direction guarantee (see tests/test_no_private_import_roots.py
# and the enforcement-harness / custody-gateway closure guards): its canonical
# modules must not pull ``arcs_amnesiac`` into the process merely by being
# imported. The producer is therefore imported lazily, inside the methods that
# actually use it, only when the native path runs.
_AMNESIAC_AVAILABLE = importlib.util.find_spec("arcs_amnesiac") is not None


def amnesiac_available() -> bool:
    return _AMNESIAC_AVAILABLE


# ---------------------------------------------------------------------------
# FINAL-guard detection — fail-closed, not symbol-based.
# ---------------------------------------------------------------------------
#
# The old adapter sketch confirmed the guard with ``hasattr(reo,
# "reopen_candidate")``. That function existed *before* the FINAL guard landed
# and is not evidence the guard is present. We instead exercise the real
# transition: construct a temporary FINAL ``RejectedCandidate`` plus a matching
# ``ReopeningRequest``, invoke ``reopen_candidate`` for EVERY ``ReopeningDecision``,
# and require every call to raise the canonical FINAL-terminal refusal while the
# candidate remains FINAL. If any decision succeeds, the guard is absent and the
# reopening capability stays disabled.


def probe_final_guard(reopening_module: Any = None, shadow_module: Any = None) -> bool:
    """Return True only if a real FINAL-terminal guard is confirmed by probe.

    ``reopening_module`` / ``shadow_module`` default to the installed producer
    modules. They are injectable so a regression test can point the probe at a
    stale, pre-guard producer fixture and confirm the probe reports it as
    unguarded. Any exception, or any decision that succeeds on a FINAL
    candidate, yields False (fail-closed).
    """

    if reopening_module is None or shadow_module is None:
        if not _AMNESIAC_AVAILABLE:
            return False
        try:
            from arcs_amnesiac import shadow_graph as shadow_module  # type: ignore[no-redef]
            from arcs_amnesiac import shadow_graph_reopening as reopening_module  # type: ignore[no-redef]
        except Exception:
            return False

    try:
        RejectedCandidate = shadow_module.RejectedCandidate
        RejectedCandidateLifecycle = shadow_module.RejectedCandidateLifecycle
        ReopeningDecision = reopening_module.ReopeningDecision
        ReopeningRequest = reopening_module.ReopeningRequest
        reopen_candidate = reopening_module.reopen_candidate
    except AttributeError:
        return False

    try:
        candidate = RejectedCandidate(
            candidate_ref="candidate:__final_guard_probe__",
            rejection_reason="final guard probe",
            lifecycle=RejectedCandidateLifecycle.FINAL,
        )
        request = ReopeningRequest(
            request_ref="request:__final_guard_probe__",
            candidate_ref=candidate.candidate_ref,
            arriving_trigger="new_evidence_admitted",
            submitted_by_ref="probe:__final_guard__",
        )
        decisions = list(ReopeningDecision)
        if not decisions:
            return False
        for decision in decisions:
            try:
                reopen_candidate(candidate, request, decision)
            except ValueError as exc:
                # The one canonical FINAL-terminal refusal. Any other refusal
                # is not evidence of this guard.
                if "cannot be reopened" not in str(exc):
                    return False
            else:
                # A decision SUCCEEDED on a FINAL candidate: the guard is absent.
                return False
        # The candidate must never have left FINAL during the probe.
        if candidate.lifecycle is not RejectedCandidateLifecycle.FINAL:
            return False
        return True
    except Exception:
        return False


def final_guard_confirmed() -> bool:
    """Whether the installed producer's FINAL guard is confirmed by probe."""
    return probe_final_guard()


# ---------------------------------------------------------------------------
# refs-only floor for record_outcome
# ---------------------------------------------------------------------------


# The refs-only raw-payload key floor. This deliberately mirrors the garp-sdk
# agent-outcome object's ``RAW_PAYLOAD_FIELD_NAMES`` verbatim, but is kept local
# rather than imported: ``dagr_mcp`` must not carry an import of the garp SDK
# root (import-direction discipline; see tests/test_no_private_import_roots.py).
# The producer's outcome object enforces the same floor structurally, so a
# mapping that survives this local check and reaches the bridge is re-validated
# there; the local floor exists so record_outcome refuses raw keys at its OWN
# seam rather than relying on the producer silently dropping unknown top-level
# keys.
_RAW_PAYLOAD_FIELD_NAMES: frozenset[str] = frozenset(
    {
        "prompt",
        "prompt_text",
        "system_prompt",
        "source_text",
        "source",
        "completion",
        "completion_text",
        "model_output",
        "output_text",
        "response_text",
        "transcript",
        "transcript_text",
        "messages",
        "message_text",
        "raw_text",
        "raw_payload",
        "raw_input",
        "raw_output",
        "raw_arguments",
        "input_text",
        "tool_arguments",
        "tool_args",
        "arguments",
        "claim_text",
        "claim",
        "private_text",
        "private_prompt",
        "private_completion",
    }
)


def _raw_payload_field_names() -> frozenset[str]:
    """The refs-only raw-payload key floor. Refs-only surfaces refuse these keys
    at any nesting depth."""
    return _RAW_PAYLOAD_FIELD_NAMES


def _refuse_raw_payload(value: Any, *, floor: frozenset[str]) -> None:
    """Recursively refuse any mapping key that names a raw/private payload.

    ``AgentOutcomeObject.from_dict`` ignores unknown top-level keys, so a raw
    ``model_output`` / ``claim`` / ``prompt`` / ``tool_arguments`` handed to the
    tool would otherwise be silently dropped rather than refused. This makes the
    refs-only boundary structural at the record_outcome seam itself."""
    if isinstance(value, Mapping):
        for key, item in value.items():
            if isinstance(key, str) and key.strip().lower() in floor:
                raise RawPayloadRefused(
                    f"record_outcome is refs-only; raw-payload field {key!r} is refused"
                )
            _refuse_raw_payload(item, floor=floor)
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            _refuse_raw_payload(item, floor=floor)


class ReopeningAdmissionAuthority(Protocol):
    """An injected admission authority that can ratify a reopening.

    The MCP caller may never choose ``REOPENED`` directly. A REOPENED transition
    is honored only when an injected authority ratifies it and returns a
    ratified decision ref. Returns ``(ReopeningDecision, decision_ref)``.
    """

    def ratify_reopening(
        self, candidate_ref: str, ratified_decision_ref: str
    ) -> tuple[Any, str]: ...


def _short_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:24]


class NativeAmnesiacService:
    """Real producer-backed implementation of the framework-neutral service.

    Injected collaborators (all optional at construction so the module loads and
    fails closed per-operation):

    * ``candidate_store`` — durable ``CandidateStore``; without it propose/record
      report ``candidate_constructed`` instead of ``candidate_recorded``.
    * ``agent_outcome_store`` — resolves ``agent_outcome_ref`` to a refs-only
      outcome object.
    * ``claim_graph`` — the real ``ClaimGraph`` the selector reads.
    * ``shadow_graph`` — the real ``ShadowGraph`` the reopening path reads and,
      after an authorized transition, replaces in place (this instance is the
      in-memory ShadowGraph repository).
    * ``context_packet_store`` — durable ``ContextPacketStore``.
    * ``scope`` — a ``ContextPacketScope`` for compiled packets.
    * ``admission_authority`` — a ``ReopeningAdmissionAuthority``; without it the
      reopening path can only *request* reopening, never REOPEN.
    """

    def __init__(
        self,
        *,
        candidate_store: CandidateStore | None = None,
        agent_outcome_store: AgentOutcomeStore | None = None,
        claim_graph: Any | None = None,
        shadow_graph: "ShadowGraph | None" = None,
        context_packet_store: ContextPacketStore | None = None,
        scope: "ContextPacketScope | None" = None,
        admission_authority: ReopeningAdmissionAuthority | None = None,
        builder_name: str = "amnesiac.reference_context_selector",
        builder_version: str = "0.1.0",
    ) -> None:
        self._candidate_store = candidate_store
        self._agent_outcome_store = agent_outcome_store
        self._claim_graph = claim_graph
        self._shadow_graph = shadow_graph
        self._context_packet_store = context_packet_store
        self._scope = scope
        self._admission_authority = admission_authority
        self._builder_name = builder_name
        self._builder_version = builder_version

    # -- propose_candidates (real, proposal-only) ---------------------------
    def propose_candidates(
        self, request: ProposeCandidatesRequest
    ) -> ProposeCandidatesResponse:
        if not _AMNESIAC_AVAILABLE:
            raise CapabilityUnavailable(
                "amnesiac.propose_candidates",
                "arcs_amnesiac is not installed; cannot construct candidates",
            )
        from arcs_amnesiac.claim_graph_admission import CandidateClaim

        results: list[CandidateResult] = []
        for proposed in request.candidates:
            source_refs = [request.source_ref]
            origin_ref = proposed.origin.get("source_ref") if proposed.origin else None
            if isinstance(origin_ref, str) and origin_ref:
                source_refs.append(origin_ref)
            try:
                candidate = CandidateClaim(
                    normalized_text=proposed.claim,
                    source_refs=tuple(source_refs),
                    anchor_refs=tuple(proposed.anchors),
                    extracted_by="amnesiac.propose_candidates",
                )
            except ValueError:
                # Malformed proposal (e.g. empty claim text). No admission, no
                # ClaimGraph or ShadowGraph transition.
                results.append(
                    CandidateResult(
                        candidate_ref="",
                        content_hash="",
                        proposal_status=ProposalStatus.REJECTED_MALFORMED,
                        admission_status=AdmissionStatus.NOT_REQUESTED,
                    )
                )
                continue

            if self._candidate_store is not None:
                ref = self._candidate_store.put(candidate)
                status = ProposalStatus.CANDIDATE_RECORDED
            else:
                # Constructed a real producer object but no persistence: do not
                # claim it was recorded.
                ref = candidate.candidate_ref
                status = ProposalStatus.CANDIDATE_CONSTRUCTED

            results.append(
                CandidateResult(
                    candidate_ref=ref,
                    content_hash=candidate.content_hash,
                    proposal_status=status,
                    admission_status=AdmissionStatus.NOT_REQUESTED,
                )
            )
        return ProposeCandidatesResponse(
            source_ref=request.source_ref,
            results=results,
            admission_performed=False,
        )

    # -- record_outcome (real, refs-only) -----------------------------------
    def record_outcome(
        self, request: RecordOutcomeRequest
    ) -> RecordOutcomeResponse:
        if not _AMNESIAC_AVAILABLE:
            raise CapabilityUnavailable(
                "amnesiac.record_outcome",
                "arcs_amnesiac is not installed; cannot bridge an agent outcome",
            )
        from arcs_amnesiac.agent_outcome_candidate_bridge import (
            bridge_agent_outcome_to_candidate,
        )

        has_ref = bool(request.agent_outcome_ref)
        has_map = request.agent_outcome is not None
        if has_ref == has_map:
            raise RawPayloadRefused(
                "record_outcome requires exactly one of agent_outcome_ref "
                "or a refs-only agent_outcome mapping"
            )

        floor = _raw_payload_field_names()
        if has_ref:
            if self._agent_outcome_store is None:
                raise CapabilityUnavailable(
                    "amnesiac.record_outcome",
                    "no AgentOutcomeStore is injected; cannot resolve agent_outcome_ref",
                )
            resolved = self._agent_outcome_store.get(request.agent_outcome_ref or "")
            if resolved is None:
                raise CapabilityUnavailable(
                    "amnesiac.record_outcome",
                    f"agent_outcome_ref {request.agent_outcome_ref!r} did not resolve",
                )
            # A stored mapping is still scanned; a stored AgentOutcomeObject is
            # already refs-only by construction.
            if isinstance(resolved, Mapping):
                _refuse_raw_payload(resolved, floor=floor)
            outcome_input: Any = resolved
        else:
            mapping = request.agent_outcome
            _refuse_raw_payload(mapping, floor=floor)
            outcome_input = mapping

        result = bridge_agent_outcome_to_candidate(outcome_input)
        candidate = result.candidate

        if self._candidate_store is not None:
            self._candidate_store.put(candidate)

        return RecordOutcomeResponse(
            outcome_ref=f"agent_outcome:{result.source_outcome_id}",
            bridge_status=result.bridge_status,
            candidate_ref=candidate.candidate_ref,
            candidate_content_hash=candidate.content_hash,
            context_packet_ref=request.context_packet_ref,
            admission_status=AdmissionStatus.NOT_REQUESTED,
            claim_text_excluded=result.claim_text_excluded,
            private_text_excluded=result.private_text_excluded,
            private_path_redacted=result.private_path_redacted,
            tool_arguments_excluded=result.tool_arguments_excluded,
            admission_claimed=result.admission_claimed,
            excluded_as_non_claim=bool(result.blockers),
            warnings=list(result.warnings),
        )

    # -- compile_context (reference selector v0) ----------------------------
    def compile_context(
        self, request: CompileContextRequest
    ) -> CompileContextResponse:
        if not _AMNESIAC_AVAILABLE:
            raise CapabilityUnavailable(
                "amnesiac.compile_context",
                "arcs_amnesiac is not installed; cannot build a ContextPacket",
            )
        if self._claim_graph is None:
            raise CapabilityUnavailable(
                "amnesiac.compile_context",
                "no ClaimGraph is injected; cannot select admitted claims",
            )
        if self._context_packet_store is None:
            raise CapabilityUnavailable(
                "amnesiac.compile_context",
                "no ContextPacketStore is injected; cannot persist the packet",
            )

        from arcs_amnesiac.context_packet import (
            ContextPacketScope,
            build_context_packet_from_graph,
        )

        selected_ids, excluded = self._reference_select(request)

        scope = self._scope or ContextPacketScope(
            profile_id="amnesiac.reference_context_selector.v0",
            corpus_ref=(request.record_scope[0] if request.record_scope else "corpus:default"),
            matter_ref=request.matter,
        )

        reconsiderable_refs: list[str] = []
        rejected_refs: list[str] = []
        if request.include_refused and self._shadow_graph is not None:
            reconsiderable_refs = [
                c.candidate_ref for c in self._shadow_graph.reconsiderable()
            ]
            rejected_refs = [
                c.candidate_ref for c in self._shadow_graph.all_candidates()
            ]

        # packet_id must vary with everything that varies the packet identity
        # (task, selection, and the selection parameters), so two compilations
        # that differ only in scope/as_of/budget do not collide on the same id.
        packet_id = "packet:" + _short_hash(
            "|".join(
                [
                    request.task,
                    ",".join(selected_ids),
                    ",".join(request.record_scope),
                    request.as_of or "",
                    str(request.item_budget),
                    request.matter or "",
                ]
            )
        )
        packet = build_context_packet_from_graph(
            packet_id=packet_id,
            query_text=request.task,
            graph=self._claim_graph,
            seed_claim_ids=selected_ids,
            scope=scope,
            operations=["reference_context_selector.v0"],
            rejected_candidate_refs=rejected_refs or None,
            parameters={
                "selector_profile": "amnesiac.reference_context_selector.v0",
                "record_scope": list(request.record_scope),
                "as_of": request.as_of,
                "item_budget": request.item_budget,
            },
        )
        packet_ref = self._context_packet_store.put(packet)

        return CompileContextResponse(
            context_packet_ref=packet_ref,
            context_packet_hash=packet.packet_hash,
            selected_claim_refs=selected_ids,
            excluded=excluded,
            reconsiderable_refs=reconsiderable_refs,
        )

    def _reference_select(
        self, request: CompileContextRequest
    ) -> tuple[list[str], list[ExcludedItem]]:
        """Deterministic lifecycle + record_scope + as_of filtering only.

        No semantic ranking, no authorization, no purpose limitation. Ordering
        is stable bytewise by claim_id (``list_nodes`` already sorts). Excluded
        items carry deterministic reason codes.
        """
        excluded: list[ExcludedItem] = []
        selected_nodes = []
        for node in self._claim_graph.list_nodes():
            if not node.is_admitted():
                excluded.append(
                    ExcludedItem(node.claim_id, "not_admitted_lifecycle")
                )
                continue
            if request.record_scope and node.profile_scope not in request.record_scope:
                excluded.append(
                    ExcludedItem(node.claim_id, "outside_record_scope")
                )
                continue
            if request.as_of and node.created_at and node.created_at > request.as_of:
                excluded.append(
                    ExcludedItem(node.claim_id, "outside_as_of_boundary")
                )
                continue
            selected_nodes.append(node)

        # Stable bytewise ordering by claim_id.
        selected_nodes.sort(key=lambda n: n.claim_id)

        if request.item_budget is not None and request.item_budget >= 0:
            over_budget = selected_nodes[request.item_budget :]
            for node in over_budget:
                excluded.append(ExcludedItem(node.claim_id, "over_item_budget"))
            selected_nodes = selected_nodes[: request.item_budget]

        return [n.claim_id for n in selected_nodes], excluded

    # -- request_reopening (real ShadowGraph path) --------------------------
    def request_reopening(
        self, request: RequestReopeningRequest
    ) -> RequestReopeningResponse:
        if not _AMNESIAC_AVAILABLE or not final_guard_confirmed():
            return RequestReopeningResponse(
                candidate_ref=request.candidate_ref,
                status=ReopeningStatus.CAPABILITY_UNAVAILABLE,
                detail=(
                    "Reopening requires a merged arcs-amnesiac producer whose "
                    "FINAL guard is confirmed by probe. It is not confirmed here."
                ),
            )
        if self._shadow_graph is None:
            return RequestReopeningResponse(
                candidate_ref=request.candidate_ref,
                status=ReopeningStatus.CAPABILITY_UNAVAILABLE,
                detail="no ShadowGraph repository is injected",
            )

        from arcs_amnesiac.shadow_graph import (
            ReconsiderabilityTrigger,
            RejectedCandidateLifecycle,
            trigger_matches,
        )
        from arcs_amnesiac.shadow_graph_lifecycle import (
            apply_reconsiderability_trigger,
        )
        from arcs_amnesiac.shadow_graph_reopening import (
            ReopeningDecision,
            ReopeningRequest,
            reopen_candidate,
        )

        shadow = self._shadow_graph
        candidate = shadow.get(request.candidate_ref)
        if candidate is None:
            return RequestReopeningResponse(
                candidate_ref=request.candidate_ref,
                status=ReopeningStatus.CANDIDATE_NOT_RECONSIDERABLE,
                detail=f"unknown candidate_ref {request.candidate_ref!r}",
            )
        before = candidate.lifecycle.value

        request_ref = f"request:{_short_hash(request.candidate_ref + '|' + request.trigger_ref)}"
        reopening_request = ReopeningRequest(
            request_ref=request_ref,
            candidate_ref=request.candidate_ref,
            arriving_trigger=request.trigger_ref,
            submitted_by_ref="actor:mcp_caller",
        )

        # FINAL is terminal — go through the REAL guard to prove refusal.
        if candidate.is_final():
            try:
                reopen_candidate(
                    candidate, reopening_request, ReopeningDecision.REQUIRES_REVIEW
                )
            except ValueError as exc:
                return RequestReopeningResponse(
                    candidate_ref=request.candidate_ref,
                    status=ReopeningStatus.FINAL_REFUSED,
                    lifecycle_before=before,
                    lifecycle_after=before,
                    detail=str(exc),
                )
            # The guard did not refuse a FINAL candidate: do not assert success.
            return RequestReopeningResponse(
                candidate_ref=request.candidate_ref,
                status=ReopeningStatus.CAPABILITY_UNAVAILABLE,
                lifecycle_before=before,
                lifecycle_after=before,
                detail="FINAL guard did not refuse; refusing to assert reopening",
            )

        trigger = _coerce_trigger(request.trigger_ref, ReconsiderabilityTrigger)

        # An admission ruling is honored only when an injected authority ratifies
        # it. The MCP caller may NEVER reach REOPENED on its own.
        authority_reopen = bool(
            request.ratified_decision_ref and self._admission_authority is not None
        )

        # A candidate already REOPENED_FOR_REVIEW is back in the active admission
        # loop. Absent a fresh admission ruling, a further reopening request is a
        # no-op record — it must NOT be demoted back to RECONSIDERABLE.
        if (
            candidate.lifecycle is RejectedCandidateLifecycle.REOPENED_FOR_REVIEW
            and not authority_reopen
        ):
            return RequestReopeningResponse(
                candidate_ref=request.candidate_ref,
                status=ReopeningStatus.REOPENING_REQUESTED,
                lifecycle_before=before,
                lifecycle_after=before,
                detail="candidate is already reopened for review (no demotion)",
            )

        working = shadow
        if not candidate.is_reconsiderable():
            # A plain REJECTED candidate needs a matching arriving trigger to
            # become reconsiderable before it can be reopened.
            if trigger is None or not trigger_matches(candidate, trigger):
                if candidate.reconsiderability_trigger is not None:
                    return RequestReopeningResponse(
                        candidate_ref=request.candidate_ref,
                        status=ReopeningStatus.TRIGGER_NOT_SATISFIED,
                        lifecycle_before=before,
                        lifecycle_after=before,
                        detail="arriving trigger does not match recorded trigger",
                    )
                return RequestReopeningResponse(
                    candidate_ref=request.candidate_ref,
                    status=ReopeningStatus.CANDIDATE_NOT_RECONSIDERABLE,
                    lifecycle_before=before,
                    lifecycle_after=before,
                    detail="candidate is not reconsiderable and no trigger applies",
                )
            working = apply_reconsiderability_trigger(shadow, trigger)
            candidate = working.get(request.candidate_ref)

        # Decide which ruling to apply. The MCP caller may NEVER choose
        # REOPENED: a REOPENED transition is honored only when an injected
        # admission authority ratifies it and returns a ratified decision ref.
        decision = ReopeningDecision.REQUIRES_REVIEW
        decision_ref: str | None = None
        if authority_reopen:
            ruled, ruled_ref = self._admission_authority.ratify_reopening(
                request.candidate_ref, request.ratified_decision_ref
            )
            decision = ruled
            decision_ref = ruled_ref

        updated, outcome = reopen_candidate(
            candidate, reopening_request, decision
        )
        # Persist the updated ShadowGraph ONLY after the authorized transition.
        self._shadow_graph = working.add(updated)

        if outcome.is_active_in_admission_loop():
            status = ReopeningStatus.REOPENED
        else:
            status = ReopeningStatus.REOPENING_REQUESTED

        return RequestReopeningResponse(
            candidate_ref=request.candidate_ref,
            status=status,
            decision_ref=decision_ref,
            outcome_ref=outcome.outcome_ref,
            lifecycle_before=before,
            lifecycle_after=updated.lifecycle.value,
        )


def _coerce_trigger(trigger_ref: str, enum_cls: Any) -> Any | None:
    """Map a trigger ref string to a ``ReconsiderabilityTrigger`` or None.

    Accepts either the bare enum value ("new_evidence_admitted") or a
    "trigger:new_evidence_admitted" style ref.
    """
    if not trigger_ref:
        return None
    value = trigger_ref.split(":", 1)[1] if trigger_ref.startswith("trigger:") else trigger_ref
    try:
        return enum_cls(value)
    except ValueError:
        return None


__all__ = [
    "NativeAmnesiacService",
    "ReopeningAdmissionAuthority",
    "amnesiac_available",
    "final_guard_confirmed",
    "probe_final_guard",
]
