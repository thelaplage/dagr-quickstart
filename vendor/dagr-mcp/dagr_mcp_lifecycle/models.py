"""Explicit typed values for the binding-neutral MCP lifecycle core.

This module declares the *inputs* and *outputs* of the neutral lifecycle core in
:mod:`dagr_mcp_lifecycle.core`. Every value here is an ordinary frozen
dataclass or a :class:`typing.Literal` over neutral tokens — there is no FastMCP,
MCP SDK, transport, or binding-specific request/result type anywhere in this
module, and it imports nothing from ``dagr_mcp``.

The core is a *planner*: it turns the semantic decisions frozen in Sprint A1 and
named in Sprint A2 into an explicit, deterministic plan of the governance records
a call must produce. A plan says *which* records exist, *what neutral facts* they
carry, and *which responsibilities belong to the adapter* — it never carries a
minted identifier, timestamp, signature, digest value, protocol version, or
binding identifier. Those are adapter-owned (see :data:`AdapterResponsibility`).

The vocabulary is imported from :mod:`dagr_mcp_lifecycle.contract` so the core
and the A2 contract are a single source of truth; the mask in
:mod:`dagr_mcp_lifecycle.binding_mask` remains the projection onto the live
FastMCP oracle.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from dagr_mcp_lifecycle import contract
from dagr_mcp_lifecycle.contract import (
    AttestationLimitFamily,
    InputRequiredMode,
    NeutralCancellationFact,
    NeutralDisposition,
    NeutralOutcome,
    NeutralRefusalGround,
)

CORE_ID = "dagr.mcp.lifecycle_core"
CORE_VERSION = "v0.1"

# --------------------------------------------------------------------------- #
# Governed tool class                                                         #
# --------------------------------------------------------------------------- #
# The governance class of a call, which drives whether an admission record is
# durably observed *before* execution. This is a neutral governance semantic,
# not a transport or request/result type; the adapter maps the binding's
# identically-spelled tool class onto it.

GovernedToolClass = Literal["read", "write", "destructive"]
GOVERNED_TOOL_CLASSES: tuple[GovernedToolClass, ...] = ("read", "write", "destructive")

# Tool classes for which an admission record is *always* durably observed before
# execution, regardless of the read-admission configuration flag.
ADMISSION_BEFORE_EXECUTION_REQUIRED: frozenset[GovernedToolClass] = frozenset(
    {"write", "destructive"}
)

# --------------------------------------------------------------------------- #
# Adapter-owned responsibilities                                              #
# --------------------------------------------------------------------------- #
# The core owns semantic facts only. Everything a concrete binding must do to
# turn a plan into a signed, transported, custody-stored record is enumerated
# here and attached to each plan, so the boundary between the neutral core and
# the adapter is explicit and testable. The core never performs any of these.

AdapterResponsibility = Literal[
    "mint_receipt_id",
    "mint_issued_at",
    "compute_argument_digest",
    "compute_result_digest",
    "mint_review_object_ref",
    "canonicalize_record",
    "sign_record",
    "stamp_protocol_binding",
    "stamp_binding_version",
    "store_custody_projection",
    "transport_record",
]
ADAPTER_RESPONSIBILITIES: tuple[AdapterResponsibility, ...] = (
    "mint_receipt_id",
    "mint_issued_at",
    "compute_argument_digest",
    "compute_result_digest",
    "mint_review_object_ref",
    "canonicalize_record",
    "sign_record",
    "stamp_protocol_binding",
    "stamp_binding_version",
    "store_custody_projection",
    "transport_record",
)

# Responsibilities every governance record hands to the adapter. The core mints
# no identifier, clock, signature, protocol version, or binding identifier, and
# it does not canonicalize, store custody, or transport.
_COMMON_RECORD_RESPONSIBILITIES: tuple[AdapterResponsibility, ...] = (
    "mint_receipt_id",
    "mint_issued_at",
    "canonicalize_record",
    "sign_record",
    "stamp_protocol_binding",
    "stamp_binding_version",
    "transport_record",
)


# --------------------------------------------------------------------------- #
# Inputs                                                                      #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class AdmissionRequest:
    """The neutral, already-resolved admission decision for a governed call.

    ``disposition`` is the policy decision at the boundary. ``refusal_ground`` is
    required exactly when ``disposition == "refused"`` and carries the neutral
    ground verbatim — the core never repairs or re-derives it. For a
    ``deferred`` disposition ``review_object_created`` says whether the review
    object was durably created: ``False`` resolves to a refusal on the
    ``review_object_creation_failed`` ground (the present-but-raises path), never
    silently onto ``required_sink_unavailable``.
    """

    disposition: NeutralDisposition
    tool_class: GovernedToolClass = "read"
    refusal_ground: NeutralRefusalGround | None = None
    review_object_created: bool | None = None
    emit_read_admission_before_execution: bool = True
    has_parent_boundary: bool = False


@dataclass(frozen=True, slots=True)
class ExecutionObservation:
    """A neutral, already-classified observation of a completed/interrupted call.

    The adapter classifies the binding-specific result or raised exception into
    one neutral outcome token before handing it to the core; the core never sees
    a FastMCP ``ToolResult``, an ``mcp.types`` value, or a raw exception. For an
    ``exception`` observation ``exception_class`` carries the raised class name
    (a semantic classification, not a minted value); for ``timeout`` the core
    supplies ``TimeoutError`` itself (§14 of the freeze).
    """

    observation: NeutralOutcome
    exception_class: str | None = None
    input_required_mode: InputRequiredMode | None = None


# --------------------------------------------------------------------------- #
# Record intents                                                              #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class AdmissionRecordIntent:
    """The neutral facts of a single admission governance record.

    Carries no minted value: ``carries_argument_digest`` states the *duty* that
    an argument digest be present (the adapter computes it), and
    ``carries_review_object_ref`` states that a deferred record references a
    review object the adapter mints.
    """

    disposition: NeutralDisposition
    reason_code: NeutralRefusalGround | None
    carries_argument_digest: bool
    carries_review_object_ref: bool
    retry_contract: str | None
    references_parent: bool
    attestation_limit_families: tuple[AttestationLimitFamily, ...]
    adapter_responsibilities: tuple[AdapterResponsibility, ...]


@dataclass(frozen=True, slots=True)
class OutcomeRecordIntent:
    """The neutral facts of a single outcome governance record.

    ``outcome`` is the neutral *record family* (``result`` / ``error`` /
    ``exception`` / ``task_submitted`` / ``cancellation``). ``subsumed_from`` is
    set to ``"timeout"`` when a timeout is recorded onto the exception family;
    it is ``None`` otherwise. ``governance_facts`` are the cancellation Booleans
    (all ``True``) that appear only on a cancellation record.
    """

    outcome: NeutralOutcome
    subsumed_from: NeutralOutcome | None
    exception_class: str | None
    carries_result_digest: bool
    references_admission: bool
    governance_facts: tuple[NeutralCancellationFact, ...]
    governance_facts_value: bool
    attestation_limit_families: tuple[AttestationLimitFamily, ...]
    adapter_responsibilities: tuple[AdapterResponsibility, ...]


# --------------------------------------------------------------------------- #
# Plans and results                                                           #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class AdmissionPlan:
    """The plan for the admission phase of a governed call.

    ``requested_disposition`` is what the policy asked for; ``resolved_disposition``
    is what the core resolved it to (they differ only when a deferral whose review
    object failed to create resolves to a refusal). ``record`` is ``None`` only
    for an admitted read that is configured not to observe admission before
    execution — in which case no governance record is produced and no outcome
    record will be either.
    """

    requested_disposition: NeutralDisposition
    resolved_disposition: NeutralDisposition
    record: AdmissionRecordIntent | None
    admission_recorded: bool
    execution_proceeds: bool


@dataclass(frozen=True, slots=True)
class OutcomePlan:
    """The plan for the outcome phase of an admitted, executed call.

    ``record`` is ``None`` when no admission record was durably observed (the
    admitted-read-skip path), mirroring the binding, which emits no outcome
    receipt when it holds no admission reference.
    """

    observation: NeutralOutcome
    record: OutcomeRecordIntent | None


@dataclass(frozen=True, slots=True)
class LifecyclePlan:
    """The full neutral plan for one governed call: admission then outcome.

    ``record_count`` is the neutral receipt cardinality — the number of durable
    governance records the plan produces — which the tests ground against
    :data:`contract.RECEIPT_CARDINALITY` and the committed A1 fixtures.
    """

    admission: AdmissionPlan
    outcome: OutcomePlan | None
    record_count: int


@dataclass(frozen=True, slots=True)
class UnsupportedLifecycleResult:
    """An explicit, non-outcome result for a neutral event the core cannot plan.

    This is never a supported outcome. It is returned (rather than a coerced
    outcome) for events — ``input_required`` in either mode — that the frozen
    binding carries no dedicated disposition for. ``supported`` is always
    ``False`` so a caller can never mistake it for a planned outcome.
    """

    event: NeutralOutcome
    modes: tuple[str, ...]
    reason: str
    supported: bool = field(default=False)


class UnsupportedLifecycleEvent(Exception):
    """Raised by the strict planners for an unsupported neutral event.

    The core offers both an explicit-result path (:class:`UnsupportedLifecycleResult`)
    and this strict raise, satisfying "fail or return an explicit unsupported
    result"; neither normalizes the event into a supported outcome.
    """

    def __init__(self, event: str, modes: tuple[str, ...], reason: str) -> None:
        self.event = event
        self.modes = modes
        self.reason = reason
        super().__init__(f"unsupported neutral lifecycle event {event!r}: {reason}")


# The neutral events the core does not carry as a supported outcome. ``timeout``
# is *subsumed* onto the exception family (still planned); ``input_required`` is
# *unsupported* (never planned as an outcome). Mirrors the A2 mask.
SUBSUMED_OUTCOMES: dict[NeutralOutcome, NeutralOutcome] = {"timeout": "exception"}
UNSUPPORTED_OUTCOMES: tuple[NeutralOutcome, ...] = ("input_required",)

# The exception class a subsumed timeout is recorded under (§14 of the freeze:
# a raised ``TimeoutError`` is an ordinary inner exception).
TIMEOUT_EXCEPTION_CLASS = "TimeoutError"


__all__ = [
    "CORE_ID",
    "CORE_VERSION",
    "GovernedToolClass",
    "GOVERNED_TOOL_CLASSES",
    "ADMISSION_BEFORE_EXECUTION_REQUIRED",
    "AdapterResponsibility",
    "ADAPTER_RESPONSIBILITIES",
    "AdmissionRequest",
    "ExecutionObservation",
    "AdmissionRecordIntent",
    "OutcomeRecordIntent",
    "AdmissionPlan",
    "OutcomePlan",
    "LifecyclePlan",
    "UnsupportedLifecycleResult",
    "UnsupportedLifecycleEvent",
    "SUBSUMED_OUTCOMES",
    "UNSUPPORTED_OUTCOMES",
    "TIMEOUT_EXCEPTION_CLASS",
]

# A module-private handle so ``core`` can reference the contract without a second
# import site; keeps the single-source-of-truth relationship explicit.
_CONTRACT = contract
