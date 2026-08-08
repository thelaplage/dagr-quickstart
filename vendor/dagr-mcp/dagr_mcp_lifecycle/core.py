"""The binding-neutral, executable MCP lifecycle core (core v0.1).

This module is the Sprint A3 extraction: a pure, deterministic representation of
the semantic decisions frozen in Sprint A1 (``docs/BEHAVIORAL_FREEZE.md``) and
named in Sprint A2 (``docs/NEUTRAL_LIFECYCLE_CONTRACT.md``,
:mod:`dagr_mcp_lifecycle.contract`). It plans the governance records a governed
MCP tool call must produce, entirely in neutral terms.

**What the core is.** A set of pure transition/planning functions over the
explicit typed values in :mod:`dagr_mcp_lifecycle.models`. Given a resolved
admission decision and an already-classified execution observation, it returns a
:class:`~dagr_mcp_lifecycle.models.LifecyclePlan` describing which records exist,
what neutral facts each carries, and which responsibilities belong to the
adapter.

**What the core is not.** It imports nothing from ``dagr_mcp``, ``fastmcp``, the
MCP SDK, or any transport; it depends on no ARCS package; and it performs no
side effect — no network, filesystem, environment, clock, UUID, hashing, or
signing. It mints no identifier, timestamp, signature, digest value, protocol
version, or binding identifier. The only import beyond the standard library is
the neutral :mod:`dagr_mcp_lifecycle.contract` / :mod:`dagr_mcp_lifecycle.models`
vocabulary, so the core stays a single source of truth with the A2 contract.

The FastMCP binding remains the behavioral oracle. This sprint extracts the core;
it does not rewire the production binding (that is A4). The tests drive every A1
characterization through a shadow adapter and compare the core plan to the A2
mask so the extraction cannot silently drift from the frozen behavior.
"""

from __future__ import annotations

from dagr_mcp_lifecycle import contract
from dagr_mcp_lifecycle.models import (
    ADMISSION_BEFORE_EXECUTION_REQUIRED,
    SUBSUMED_OUTCOMES,
    TIMEOUT_EXCEPTION_CLASS,
    UNSUPPORTED_OUTCOMES,
    AdmissionPlan,
    AdmissionRecordIntent,
    AdmissionRequest,
    ExecutionObservation,
    LifecyclePlan,
    OutcomePlan,
    OutcomeRecordIntent,
    UnsupportedLifecycleEvent,
    UnsupportedLifecycleResult,
    _COMMON_RECORD_RESPONSIBILITIES,
)

# --------------------------------------------------------------------------- #
# Attestation-limit families per record (neutral)                            #
# --------------------------------------------------------------------------- #
# Every record carries the base limit and the boundary limit (§10 of the
# freeze). Result/error records add the result family; task-submission records
# add the task family. The concrete limit *strings* are the binding's and are
# bound by the A2 mask (``binding_mask.ATTESTATION_LIMIT_MASK``); the core owns
# only which families apply.

_ADMISSION_LIMIT_FAMILIES: tuple[contract.AttestationLimitFamily, ...] = (
    "base",
    "boundary",
)
_RESULT_LIMIT_FAMILIES: tuple[contract.AttestationLimitFamily, ...] = (
    "base",
    "result",
    "boundary",
)
_TASK_LIMIT_FAMILIES: tuple[contract.AttestationLimitFamily, ...] = (
    "base",
    "task",
    "boundary",
)

# Neutral outcome record families that carry a result digest, and the limit
# families each outcome record adds. Read straight from the A2 contract so a
# change to the contract's digest responsibilities is reflected here.
_RESULT_DIGEST_OUTCOMES: frozenset[str] = frozenset(contract.RESULT_DIGEST_OUTCOMES)


def _outcome_limit_families(
    outcome: contract.NeutralOutcome,
) -> tuple[contract.AttestationLimitFamily, ...]:
    if outcome in ("result", "error"):
        return _RESULT_LIMIT_FAMILIES
    if outcome == "task_submitted":
        return _TASK_LIMIT_FAMILIES
    # exception (incl. subsumed timeout) and cancellation carry base + boundary.
    return _ADMISSION_LIMIT_FAMILIES


# --------------------------------------------------------------------------- #
# Admission planning                                                          #
# --------------------------------------------------------------------------- #


def _admission_before_execution(request: AdmissionRequest) -> bool:
    """Whether an admission record is durably observed before execution.

    Write/destructive always observe admission before execution; a read observes
    it only when the binding is configured to (the default). Mirrors
    ``DAGRMiddleware._must_emit_admission_before_execution``.
    """

    if request.tool_class in ADMISSION_BEFORE_EXECUTION_REQUIRED:
        return True
    return request.emit_read_admission_before_execution


def plan_admission(request: AdmissionRequest) -> AdmissionPlan:
    """Plan the admission phase for a governed call.

    Pure and deterministic: identical requests yield equal plans. The frozen
    semantics reproduced here:

    * **refused** — a single terminal admission record carrying the neutral
      refusal ground verbatim; execution does not proceed. A ``required_sink_unavailable``
      ground is preserved as-is and never repaired (§17 residual).
    * **deferred** — if the review object was created, a single deferred record
      with a review-object reference and the ``retry_after_approval`` continuation
      contract; execution does not proceed. If it was not created, the disposition
      resolves to a refusal on the ``review_object_creation_failed`` ground — never
      onto ``required_sink_unavailable``.
    * **admitted** — for write/destructive, or a read configured to observe
      admission before execution, a single admission record and execution
      proceeds. For a read configured not to, no record is produced and execution
      still proceeds (and no outcome record will follow).
    """

    disposition = request.disposition

    if disposition == "refused":
        ground = request.refusal_ground
        if ground is None:
            raise ValueError("a refused admission requires an explicit refusal_ground")
        if ground not in contract.NEUTRAL_REFUSAL_GROUNDS:
            raise ValueError(f"unknown neutral refusal ground {ground!r}")
        record = AdmissionRecordIntent(
            disposition="refused",
            reason_code=ground,
            carries_argument_digest=True,
            carries_review_object_ref=False,
            retry_contract=None,
            references_parent=request.has_parent_boundary,
            attestation_limit_families=_ADMISSION_LIMIT_FAMILIES,
            adapter_responsibilities=_COMMON_RECORD_RESPONSIBILITIES
            + ("compute_argument_digest",),
        )
        return AdmissionPlan(
            requested_disposition="refused",
            resolved_disposition="refused",
            record=record,
            admission_recorded=True,
            execution_proceeds=False,
        )

    if disposition == "deferred":
        if request.review_object_created is None:
            raise ValueError(
                "a deferred admission requires an explicit review_object_created flag"
            )
        if request.review_object_created is False:
            # The review sink was present but raised during creation: the frozen
            # semantic resolves this to a refusal on review_object_creation_failed
            # (NOT required_sink_unavailable, which is a distinct pre-gate health
            # check — §17). The core surfaces the resolved refusal explicitly.
            record = AdmissionRecordIntent(
                disposition="refused",
                reason_code="review_object_creation_failed",
                carries_argument_digest=True,
                carries_review_object_ref=False,
                retry_contract=None,
                references_parent=request.has_parent_boundary,
                attestation_limit_families=_ADMISSION_LIMIT_FAMILIES,
                adapter_responsibilities=_COMMON_RECORD_RESPONSIBILITIES
                + ("compute_argument_digest",),
            )
            return AdmissionPlan(
                requested_disposition="deferred",
                resolved_disposition="refused",
                record=record,
                admission_recorded=True,
                execution_proceeds=False,
            )
        record = AdmissionRecordIntent(
            disposition="deferred",
            reason_code=None,
            carries_argument_digest=True,
            carries_review_object_ref=True,
            retry_contract=contract.DEFERRAL_CONTINUATION_CONTRACT,
            references_parent=request.has_parent_boundary,
            attestation_limit_families=_ADMISSION_LIMIT_FAMILIES,
            adapter_responsibilities=_COMMON_RECORD_RESPONSIBILITIES
            + ("compute_argument_digest", "mint_review_object_ref"),
        )
        return AdmissionPlan(
            requested_disposition="deferred",
            resolved_disposition="deferred",
            record=record,
            admission_recorded=True,
            execution_proceeds=False,
        )

    if disposition == "admitted":
        recorded = _admission_before_execution(request)
        record = (
            AdmissionRecordIntent(
                disposition="admitted",
                reason_code=None,
                carries_argument_digest=True,
                carries_review_object_ref=False,
                retry_contract=None,
                references_parent=request.has_parent_boundary,
                attestation_limit_families=_ADMISSION_LIMIT_FAMILIES,
                adapter_responsibilities=_COMMON_RECORD_RESPONSIBILITIES
                + ("compute_argument_digest",),
            )
            if recorded
            else None
        )
        return AdmissionPlan(
            requested_disposition="admitted",
            resolved_disposition="admitted",
            record=record,
            admission_recorded=recorded,
            execution_proceeds=True,
        )

    raise ValueError(f"unknown neutral disposition {disposition!r}")


# --------------------------------------------------------------------------- #
# Outcome planning                                                            #
# --------------------------------------------------------------------------- #


def plan_outcome(
    admission: AdmissionPlan,
    observation: ExecutionObservation,
) -> OutcomePlan | UnsupportedLifecycleResult:
    """Plan the outcome phase for an admitted, executed call.

    Returns an :class:`UnsupportedLifecycleResult` — never a coerced outcome —
    for an ``input_required`` observation, in either mode. For every supported
    observation it returns an :class:`OutcomePlan`.

    Only an admitted call that durably recorded admission produces an outcome
    record. If execution never proceeded (a refusal or deferral) or admission was
    not recorded (the admitted-read-skip path), the outcome record is ``None``,
    mirroring the binding, which emits no outcome receipt without an admission
    reference.
    """

    token = observation.observation
    if token not in contract.NEUTRAL_OUTCOMES:
        raise ValueError(f"unknown neutral outcome observation {token!r}")

    if token in UNSUPPORTED_OUTCOMES:
        return _unsupported_result(observation)

    if not admission.execution_proceeds or not admission.admission_recorded:
        # No admission reference exists, so no outcome record is planned. The
        # observation is still recorded on the plan for traceability.
        return OutcomePlan(observation=token, record=None)

    record = _outcome_record(observation)
    return OutcomePlan(observation=token, record=record)


def _unsupported_result(
    observation: ExecutionObservation,
) -> UnsupportedLifecycleResult:
    modes = (
        (observation.input_required_mode,)
        if observation.input_required_mode is not None
        else contract.INPUT_REQUIRED_MODES
    )
    return UnsupportedLifecycleResult(
        event=observation.observation,
        modes=tuple(modes),
        reason=(
            "the frozen FastMCP binding carries no dedicated disposition for a "
            "paused call; it is neutral but unsupported and must not be "
            "normalized into a supported outcome"
        ),
    )


def _outcome_record(observation: ExecutionObservation) -> OutcomeRecordIntent:
    token = observation.observation

    # Timeout is subsumed onto the exception family with exception_class
    # TimeoutError (§14). It is planned, not unsupported.
    subsumed_from: contract.NeutralOutcome | None = None
    exception_class = observation.exception_class
    record_outcome: contract.NeutralOutcome = token
    if token in SUBSUMED_OUTCOMES:
        subsumed_from = token
        record_outcome = SUBSUMED_OUTCOMES[token]
        if record_outcome == "exception":
            exception_class = TIMEOUT_EXCEPTION_CLASS

    if record_outcome == "exception" and exception_class is None:
        raise ValueError("an exception outcome requires an exception_class")

    governance_facts: tuple[contract.NeutralCancellationFact, ...] = ()
    if record_outcome == "cancellation":
        governance_facts = contract.NEUTRAL_CANCELLATION_FACTS

    carries_result_digest = record_outcome in _RESULT_DIGEST_OUTCOMES

    responsibilities = _COMMON_RECORD_RESPONSIBILITIES
    if carries_result_digest:
        responsibilities = responsibilities + ("compute_result_digest",)

    return OutcomeRecordIntent(
        outcome=record_outcome,
        subsumed_from=subsumed_from,
        exception_class=exception_class if record_outcome == "exception" else None,
        carries_result_digest=carries_result_digest,
        references_admission=True,
        governance_facts=governance_facts,
        governance_facts_value=True,
        attestation_limit_families=_outcome_limit_families(record_outcome),
        adapter_responsibilities=responsibilities,
    )


# --------------------------------------------------------------------------- #
# Whole-lifecycle planning                                                    #
# --------------------------------------------------------------------------- #


def plan_lifecycle(
    request: AdmissionRequest,
    observation: ExecutionObservation | None = None,
) -> LifecyclePlan | UnsupportedLifecycleResult:
    """Plan a full governed call: admission, then (if it proceeds) the outcome.

    Pure and deterministic. Returns an :class:`UnsupportedLifecycleResult` if the
    outcome observation is unsupported. When admission does not proceed (refusal
    or deferral), ``observation`` is ignored and the plan carries no outcome.

    ``record_count`` is the neutral receipt cardinality; for the governed
    dispositions it reproduces :data:`contract.RECEIPT_CARDINALITY`
    (admitted → 2, refused → 1, deferred → 1).
    """

    admission = plan_admission(request)

    if not admission.execution_proceeds:
        count = 1 if admission.record is not None else 0
        return LifecyclePlan(admission=admission, outcome=None, record_count=count)

    if observation is None:
        # Admission proceeded but no outcome has been observed yet.
        count = 1 if admission.record is not None else 0
        return LifecyclePlan(admission=admission, outcome=None, record_count=count)

    outcome = plan_outcome(admission, observation)
    if isinstance(outcome, UnsupportedLifecycleResult):
        return outcome

    count = 0
    if admission.record is not None:
        count += 1
    if outcome.record is not None:
        count += 1
    return LifecyclePlan(admission=admission, outcome=outcome, record_count=count)


# --------------------------------------------------------------------------- #
# Strict variants                                                             #
# --------------------------------------------------------------------------- #


def plan_outcome_strict(
    admission: AdmissionPlan,
    observation: ExecutionObservation,
) -> OutcomePlan:
    """Like :func:`plan_outcome` but *raises* on an unsupported event.

    Satisfies the "fail" half of "fail or return an explicit unsupported
    result": an ``input_required`` observation raises
    :class:`UnsupportedLifecycleEvent` rather than returning a plan.
    """

    result = plan_outcome(admission, observation)
    if isinstance(result, UnsupportedLifecycleResult):
        raise UnsupportedLifecycleEvent(result.event, result.modes, result.reason)
    return result


def plan_lifecycle_strict(
    request: AdmissionRequest,
    observation: ExecutionObservation | None = None,
) -> LifecyclePlan:
    """Like :func:`plan_lifecycle` but *raises* on an unsupported event."""

    result = plan_lifecycle(request, observation)
    if isinstance(result, UnsupportedLifecycleResult):
        raise UnsupportedLifecycleEvent(result.event, result.modes, result.reason)
    return result


# --------------------------------------------------------------------------- #
# Coverage introspection                                                      #
# --------------------------------------------------------------------------- #

# Every neutral outcome token is either planned as a supported record family
# (``direct``), planned onto another family (``subsumed``), or explicitly
# unsupported. This mirrors the A2 mask's classification and lets a test prove
# the core implements-or-declares-unsupported for every contract token.


def core_outcome_status(outcome: str) -> str:
    """Classify a neutral outcome by how the core plans it.

    Returns ``"direct"`` (a dedicated record family), ``"subsumed"`` (planned
    onto another family, e.g. timeout → exception), or ``"unsupported"`` (never
    planned as an outcome, e.g. input_required). Raises for an unknown token.
    """

    if outcome not in contract.NEUTRAL_OUTCOMES:
        raise ValueError(f"unknown neutral outcome {outcome!r}")
    if outcome in UNSUPPORTED_OUTCOMES:
        return "unsupported"
    if outcome in SUBSUMED_OUTCOMES:
        return "subsumed"
    return "direct"


__all__ = [
    "plan_admission",
    "plan_outcome",
    "plan_outcome_strict",
    "plan_lifecycle",
    "plan_lifecycle_strict",
    "core_outcome_status",
]
