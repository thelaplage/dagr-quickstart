"""Framework-neutral Amnesiac service contracts.

This module defines the request and response shapes and the service protocol
for the four Amnesiac agent-memory operations. It imports neither ``fastmcp``
nor ``arcs_amnesiac``. The FastMCP binding depends on this; the native
implementation depends on this; a future alternate binding can depend on this
without inheriting either the framework or the producer.

The load-bearing rule these contracts encode: the model proposes, admission
ratifies. Every response keeps proposal state distinct from admission state, and
no response conflates "recorded a proposal" with "admitted a claim". Admission
is a separate authority boundary that is *out of B1 scope* unless a real
ratifier service is injected with an explicit, ratified decision reference.

Two load-bearing corrections relative to the first-cut adapter sketch:

* ``propose_candidates`` is proposal-only. There is no ``request_admission``
  flag on the public contract; the tool never runs admission.
* ``record_outcome`` is refs-only. It never accepts raw model output, prompts,
  claims, transcripts, or tool arguments. It accepts a resolvable outcome ref or
  a refs-only ``AgentOutcomeObject`` mapping and nothing else.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Protocol, runtime_checkable

# The durable selector identity for compile_context. It travels in the response
# and the receipt and states plainly that this is the reference selector, not
# the full governed context planner.
REFERENCE_CONTEXT_SELECTOR_PROFILE = "amnesiac.reference_context_selector.v0"

# The limitations that MUST appear in every compile_context response. The
# selector is a deterministic lifecycle-and-time filter, nothing more.
REFERENCE_SELECTOR_LIMITATIONS: tuple[str, ...] = (
    "No semantic ranking was performed.",
    "No tenant authorization decision was performed.",
    "No actor entitlement decision was performed.",
    "No purpose-limitation decision was performed.",
    "No contradiction-completeness optimization was performed.",
    "No vector retrieval was performed.",
    "This is not the full governed context planner.",
)


# --- state vocabularies (never use a bare "accepted") -----------------------


class ProposalStatus(str, Enum):
    """State of a proposed candidate at the proposal boundary.

    ``CANDIDATE_RECORDED`` means the candidate was constructed AND accepted by
    the injected ``CandidateStore``. ``CANDIDATE_CONSTRUCTED`` means it was
    constructed as a real producer object but no persistence was available, so
    the server does not claim it was recorded. Neither implies admission.
    """

    CANDIDATE_RECORDED = "candidate_recorded"
    CANDIDATE_CONSTRUCTED = "candidate_constructed"
    REJECTED_MALFORMED = "rejected_malformed"


class AdmissionStatus(str, Enum):
    """Admission state kept strictly distinct from proposal state.

    B1 proposal and outcome-bridge operations always report
    ``NOT_REQUESTED``: admission is a separate authority boundary this binding
    does not cross without an injected ratifier.
    """

    NOT_REQUESTED = "not_requested"
    ADMITTED = "admitted"
    REFUSED = "refused"
    RECONSIDERABLE = "reconsiderable"
    CAPABILITY_UNAVAILABLE = "capability_unavailable"


class ReopeningStatus(str, Enum):
    REOPENING_REQUESTED = "reopening_requested"
    TRIGGER_NOT_SATISFIED = "trigger_not_satisfied"
    REOPENED = "reopened"
    FINAL_REFUSED = "final_refused"
    CANDIDATE_NOT_RECONSIDERABLE = "candidate_not_reconsiderable"
    CAPABILITY_UNAVAILABLE = "capability_unavailable"


# --- propose_candidates (proposal-only) -------------------------------------


@dataclass
class ProposedClaim:
    claim: str
    anchors: list[str] = field(default_factory=list)
    origin: dict[str, Any] = field(default_factory=dict)


@dataclass
class ProposeCandidatesRequest:
    """A request to construct and persist candidate claims.

    There is no ``request_admission`` field. Proposing is not admitting; the
    caller cannot ask this operation to admit.
    """

    source_ref: str
    candidates: list[ProposedClaim]


@dataclass
class CandidateResult:
    candidate_ref: str
    content_hash: str
    proposal_status: ProposalStatus
    # Always NOT_REQUESTED for a proposal: proposal state is distinct from
    # admission state and this operation never runs admission.
    admission_status: AdmissionStatus = AdmissionStatus.NOT_REQUESTED


@dataclass
class ProposeCandidatesResponse:
    source_ref: str
    results: list[CandidateResult]
    # Present so the response is self-describing about what it did NOT do.
    admission_performed: bool = False
    receipt_refs: list[str] = field(default_factory=list)


# --- compile_context (reference selector v0) --------------------------------


@dataclass
class CompileContextRequest:
    task: str
    matter: str | None = None
    record_scope: list[str] = field(default_factory=list)
    as_of: str | None = None
    item_budget: int | None = None
    include_refused: bool = False


@dataclass
class ExcludedItem:
    claim_ref: str
    reason_code: str


@dataclass
class CompileContextResponse:
    context_packet_ref: str
    context_packet_hash: str
    selected_claim_refs: list[str]
    excluded: list[ExcludedItem] = field(default_factory=list)
    reconsiderable_refs: list[str] = field(default_factory=list)
    selector_profile: str = REFERENCE_CONTEXT_SELECTOR_PROFILE
    selection_authority: str = "reference_implementation"
    full_governed_context_planner: bool = False
    limitations: list[str] = field(
        default_factory=lambda: list(REFERENCE_SELECTOR_LIMITATIONS)
    )
    receipt_refs: list[str] = field(default_factory=list)


# --- request_reopening ------------------------------------------------------


@dataclass
class RequestReopeningRequest:
    candidate_ref: str
    trigger_ref: str
    new_evidence_refs: list[str] = field(default_factory=list)
    # An admission ruling is only honored when it arrives from an injected
    # admission authority with a ratified decision reference. The MCP caller
    # cannot set this to force REOPENED.
    ratified_decision_ref: str | None = None


@dataclass
class RequestReopeningResponse:
    candidate_ref: str
    status: ReopeningStatus
    decision_ref: str | None = None
    outcome_ref: str | None = None
    lifecycle_before: str | None = None
    lifecycle_after: str | None = None
    detail: str | None = None
    receipt_refs: list[str] = field(default_factory=list)


# --- record_outcome (refs-only) ---------------------------------------------


@dataclass
class RecordOutcomeRequest:
    """A refs-only request to bridge a governed agent outcome to a candidate.

    Exactly one of ``agent_outcome_ref`` (resolved through an injected
    ``AgentOutcomeStore``) or ``agent_outcome`` (a refs-only
    ``AgentOutcomeObject`` mapping validated by ``AgentOutcomeObject.from_dict``)
    must be provided. Raw model output, prompts, claims, transcripts, and tool
    arguments are never accepted; the native layer refuses any raw-payload key.
    """

    agent_outcome_ref: str | None = None
    agent_outcome: Mapping[str, Any] | None = None
    context_packet_ref: str | None = None


@dataclass
class RecordOutcomeResponse:
    outcome_ref: str
    bridge_status: str
    candidate_ref: str
    candidate_content_hash: str
    context_packet_ref: str | None
    # Bridged outcomes become candidates, not admitted memory.
    admission_status: AdmissionStatus
    # A mirror of the structural attestations the real bridge result carries.
    claim_text_excluded: bool = True
    private_text_excluded: bool = True
    private_path_redacted: bool = True
    tool_arguments_excluded: bool = True
    admission_claimed: bool = False
    excluded_as_non_claim: bool = False
    warnings: list[str] = field(default_factory=list)
    receipt_refs: list[str] = field(default_factory=list)


# --- the service protocol the native layer implements -----------------------


@runtime_checkable
class AmnesiacService(Protocol):
    """The framework-neutral service. amnesiac_native implements this over the
    real producer; a fake implements it for FastMCP-contract tests."""

    def propose_candidates(
        self, request: ProposeCandidatesRequest
    ) -> ProposeCandidatesResponse: ...

    def compile_context(
        self, request: CompileContextRequest
    ) -> CompileContextResponse: ...

    def request_reopening(
        self, request: RequestReopeningRequest
    ) -> RequestReopeningResponse: ...

    def record_outcome(
        self, request: RecordOutcomeRequest
    ) -> RecordOutcomeResponse: ...


class CapabilityUnavailable(RuntimeError):
    """Raised by the native layer when the producer tree required for an
    operation is absent, or a required persistence surface is missing. The
    binding translates this into a fail-closed capability-unavailable *error*
    result rather than a normal-success dictionary, so the server never reports
    success on a missing producer."""

    def __init__(self, operation: str, detail: str) -> None:
        super().__init__(detail)
        self.operation = operation
        self.detail = detail


class RawPayloadRefused(ValueError):
    """Raised when a refs-only surface is handed a raw-payload key such as
    ``model_output``, ``claim``, ``prompt``, or ``tool_arguments``. The refs-only
    custody boundary is structural, not advisory."""
