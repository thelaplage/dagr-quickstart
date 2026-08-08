"""Binding-neutral MCP lifecycle vocabulary (contract v0.1).

This module declares the *portable* names a governed MCP tool call moves
through, with no dependency on any binding. It imports nothing from
``dagr_mcp`` on purpose: a neutral vocabulary that already knew about the
FastMCP binding would not be neutral. The mapping onto a concrete binding lives
in :mod:`dagr_mcp_lifecycle.binding_mask`, and the binding itself remains the
oracle.

Every name here is a *contract token*, not an implementation. The tokens are
frozen so a drift test (``tests/test_neutral_lifecycle_contract.py``) can pin
them, exactly as the Sprint A1 behavioral freeze pins the binding's own
observable surface.

Neutral tokens are chosen to be honest about where the neutral vocabulary and
the current binding *coincide* and where they *differ*:

* ``admitted`` / ``refused`` coincide with the binding disposition tokens;
* ``deferred`` is the neutral name the binding spells ``deferred_for_review``;
* ``result`` / ``error`` / ``cancellation`` are neutral names the binding spells
  ``result_returned`` / ``error_returned`` / ``indeterminate``;
* ``task_submitted`` coincides with the binding outcome token;
* ``timeout`` and ``input_required`` are neutral events the current binding does
  **not** carry as dedicated dispositions (see the mask).

The mask records each of those relationships explicitly and is checked against
the live binding, so this vocabulary can never silently drift away from what the
binding actually does.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

CONTRACT_ID = "dagr.mcp.lifecycle_contract"
CONTRACT_VERSION = "v0.1"

# --------------------------------------------------------------------------- #
# Lifecycle phases                                                            #
# --------------------------------------------------------------------------- #

LifecyclePhase = Literal[
    "call_admission",
    "execution",
    "outcome",
]
LIFECYCLE_PHASES: tuple[LifecyclePhase, ...] = (
    "call_admission",
    "execution",
    "outcome",
)

# --------------------------------------------------------------------------- #
# Call admission                                                              #
# --------------------------------------------------------------------------- #
# A governed call is *admitted*, *refused*, or *deferred* at the boundary,
# before the tool body runs. These are the neutral admission dispositions.

NeutralDisposition = Literal["admitted", "refused", "deferred"]
NEUTRAL_DISPOSITIONS: tuple[NeutralDisposition, ...] = (
    "admitted",
    "refused",
    "deferred",
)

# Neutral refusal grounds. A binding may surface a subset; the mask records
# which of these the FastMCP binding actually reaches.
NeutralRefusalGround = Literal[
    "policy_refused",
    "unknown_tool_fail_closed",
    "required_sink_unavailable",
    "review_object_creation_failed",
]
NEUTRAL_REFUSAL_GROUNDS: tuple[NeutralRefusalGround, ...] = (
    "policy_refused",
    "unknown_tool_fail_closed",
    "required_sink_unavailable",
    "review_object_creation_failed",
)

# A deferral is not a refusal: it references a durable review object and carries
# a continuation contract for a later retry.
DEFERRAL_CONTINUATION_CONTRACT = "retry_after_approval"

# --------------------------------------------------------------------------- #
# Execution start and completion                                              #
# --------------------------------------------------------------------------- #
# Admission is observed *before* execution for governed classes; completion is
# observed *after* the boundary returns. These are neutral phase boundaries, not
# a claim that the tool body itself executed.

ExecutionBoundary = Literal["execution_start", "execution_completion"]
EXECUTION_BOUNDARIES: tuple[ExecutionBoundary, ...] = (
    "execution_start",
    "execution_completion",
)

# --------------------------------------------------------------------------- #
# Terminal outcomes                                                           #
# --------------------------------------------------------------------------- #
# The neutral terminal facts a completed (or interrupted) call can carry.
# ``timeout`` and ``input_required`` are part of the neutral vocabulary but are
# not guaranteed to have a dedicated binding disposition; the mask says which.

NeutralOutcome = Literal[
    "result",
    "error",
    "exception",
    "task_submitted",
    "timeout",
    "cancellation",
    "input_required",
]
NEUTRAL_OUTCOMES: tuple[NeutralOutcome, ...] = (
    "result",
    "error",
    "exception",
    "task_submitted",
    "timeout",
    "cancellation",
    "input_required",
)

# ``input_required`` has two neutral modes: a call that pauses awaiting further
# input and can be resumed (continuable), and a call that stops awaiting input
# without a resumable continuation (interrupted).
InputRequiredMode = Literal["continuable", "interrupted"]
INPUT_REQUIRED_MODES: tuple[InputRequiredMode, ...] = (
    "continuable",
    "interrupted",
)

# --------------------------------------------------------------------------- #
# Cancellation governance facts                                               #
# --------------------------------------------------------------------------- #
# The three neutral governance facts a cancellation may assert. They are
# governance Booleans, not result content. None of them is named with a
# ``result``-shaped token, so a raw-content exclusion profile cannot mistake a
# governance Boolean for result material.

NeutralCancellationFact = Literal[
    "request_cancelled",
    "execution_state_unknown",
    "delivery_incomplete",
]
NEUTRAL_CANCELLATION_FACTS: tuple[NeutralCancellationFact, ...] = (
    "request_cancelled",
    "execution_state_unknown",
    "delivery_incomplete",
)

# --------------------------------------------------------------------------- #
# Receipt cardinality and parent/reference relationships                      #
# --------------------------------------------------------------------------- #
# The neutral count of durable governance records a disposition produces, and
# the reference edges that link them.

RECEIPT_CARDINALITY: dict[NeutralDisposition, int] = {
    "admitted": 2,  # admission observed before execution, then an outcome
    "refused": 1,  # a single terminal admission record; the body never runs
    "deferred": 1,  # a single deferred admission record; the body never runs
}

# Neutral reference edges between records.
#  - ``outcome_to_admission``: an outcome record references its admission record.
#  - ``parent_reference``: an admission record may reference a parent boundary's
#    record when boundaries are deliberately linked.
RECEIPT_REFERENCE_EDGES: tuple[str, ...] = (
    "outcome_to_admission",
    "parent_reference",
)

# --------------------------------------------------------------------------- #
# Custody observations and attestation limits                                 #
# --------------------------------------------------------------------------- #
# Custody observation is a *non-claim* posture: the boundary records that it
# observed a call and excluded raw content, without asserting authority over,
# or modification of, the protocol or the model output. These neutral flag
# names carry the non-claim posture; the mask binds them to the concrete
# custody-gateway fields.

CUSTODY_EXCLUSION_FLAGS: tuple[str, ...] = (
    "raw_payload_excluded",
    "private_path_redacted",
    "tool_arguments_excluded",
    "credential_secret_excluded",
)
CUSTODY_NON_CLAIM_FLAGS: tuple[str, ...] = (
    "record_admission_claimed",
    "mcp_protocol_modified",
    "mcp_authority_granted",
    "model_output_verified",
)

# Neutral attestation-limit families a record may carry. Every record carries
# the base limit; result/error records add a result limit; task records add a
# task-submission limit. The exact limit strings are the binding's; the mask
# binds these families to them.
AttestationLimitFamily = Literal["base", "result", "task", "boundary"]
ATTESTATION_LIMIT_FAMILIES: tuple[AttestationLimitFamily, ...] = (
    "base",
    "result",
    "task",
    "boundary",
)

# --------------------------------------------------------------------------- #
# Argument / result digest responsibilities                                   #
# --------------------------------------------------------------------------- #
# Digests are hash-only projections. The neutral contract fixes *which* facts a
# binding must digest and the canonicalization it must use; the mask binds these
# to the concrete digest functions.

DIGEST_CANONICALIZATION = "RFC8785-JCS"
DIGEST_HASH = "sha256"
DIGEST_PREFIX = "sha256:"

# The neutral digest responsibilities. ``argument_digest`` is always present on
# an admission record; ``result_digest`` is present only when a semantic result
# or error was returned, and absent for task-submission, exception, and
# cancellation outcomes.
DIGEST_RESPONSIBILITIES: tuple[str, ...] = (
    "argument_digest",
    "result_digest",
)
# Neutral outcomes that carry a result digest.
RESULT_DIGEST_OUTCOMES: tuple[NeutralOutcome, ...] = ("result", "error")
# Neutral outcomes that must NOT carry a result digest.
NO_RESULT_DIGEST_OUTCOMES: tuple[NeutralOutcome, ...] = (
    "task_submitted",
    "exception",
    "timeout",
    "cancellation",
)

# --------------------------------------------------------------------------- #
# Protocol and binding stamps                                                 #
# --------------------------------------------------------------------------- #
# The neutral names of the stamps every record carries to identify the protocol
# it governs and the binding that produced it. The mask binds these to concrete
# values; the neutral contract only names the responsibilities.
PROTOCOL_STAMP_FIELDS: tuple[str, ...] = (
    "protocol_binding",
    "boundary_type",
    "receipt_type",
    "profile_id",
    "profile_version",
    "receipt_version",
)
BINDING_STAMP_FIELDS: tuple[str, ...] = ("binding_version",)

# --------------------------------------------------------------------------- #
# Three-layer parity model                                                    #
# --------------------------------------------------------------------------- #
# Any binding claiming parity with another is compared at one of three nested,
# increasingly strict layers. A parity claim must state which layer it is made
# at.

ParityLayer = Literal[
    "semantic",
    "normalized_equality",
    "exact_unsigned_bytes",
]
PARITY_LAYERS: tuple[ParityLayer, ...] = (
    "semantic",
    "normalized_equality",
    "exact_unsigned_bytes",
)

# Layer 2 permits exactly these record fields to differ across bindings while
# the rest of the record must be byte-for-byte equal under canonicalization.
# These are the fields whose values are legitimately volatile (identifier,
# wall clock, signature) and cannot match across independent emitters.
PERMITTED_NORMALIZED_DIFFERENCE_FIELDS: tuple[str, ...] = (
    "receipt_id",
    "issued_at",
    "receipt_signature",
)
# For custody projections the single permitted-volatile field is the observation
# timestamp.
CUSTODY_PERMITTED_NORMALIZED_DIFFERENCE_FIELDS: tuple[str, ...] = (
    "observed_at",
)


@dataclass(frozen=True, slots=True)
class ParityLayerSpec:
    """One layer of the parity model: what it asserts and what it permits."""

    layer: ParityLayer
    summary: str
    permitted_difference_fields: tuple[str, ...] = ()


PARITY_MODEL: tuple[ParityLayerSpec, ...] = (
    ParityLayerSpec(
        layer="semantic",
        summary=(
            "The behavioral facts hold independent of exact bytes: the "
            "disposition and outcome vocabularies, receipt cardinality and "
            "reference edges, the cancellation-fact posture, the digest "
            "responsibilities, the non-claim custody posture, and the protocol "
            "and binding stamps."
        ),
        permitted_difference_fields=(),
    ),
    ParityLayerSpec(
        layer="normalized_equality",
        summary=(
            "The record is byte-for-byte equal under canonicalization once the "
            "permitted-volatile fields are dropped. Only the volatile fields "
            "(identifier, wall clock, signature) may differ; every other field "
            "must match."
        ),
        permitted_difference_fields=PERMITTED_NORMALIZED_DIFFERENCE_FIELDS,
    ),
    ParityLayerSpec(
        layer="exact_unsigned_bytes",
        summary=(
            "The exact RFC 8785 canonical bytes of the unsigned envelope (the "
            "record with its signature block removed) are identical where the "
            "producing identity, identifier, and clock are pinned. This is the "
            "strictest layer and holds only for deterministic fixtures."
        ),
        permitted_difference_fields=(),
    ),
)

# --------------------------------------------------------------------------- #
# Neutral lifecycle event descriptor                                          #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class NeutralLifecycleEvent:
    """A single neutral lifecycle event, independent of any binding."""

    phase: LifecyclePhase
    token: str
    description: str
    modes: tuple[str, ...] = field(default_factory=tuple)


# The canonical, ordered catalogue of neutral lifecycle events. The mask maps
# each event token onto the FastMCP binding (or records it unsupported).
NEUTRAL_LIFECYCLE_EVENTS: tuple[NeutralLifecycleEvent, ...] = (
    NeutralLifecycleEvent(
        "call_admission", "admitted",
        "The call is admitted at the boundary and proceeds to execution.",
    ),
    NeutralLifecycleEvent(
        "call_admission", "refused",
        "The call is refused at the boundary; the tool body never runs.",
    ),
    NeutralLifecycleEvent(
        "call_admission", "deferred",
        "The call is deferred to a durable review object with a retry contract.",
    ),
    NeutralLifecycleEvent(
        "execution", "execution_start",
        "Execution begins after admission is durably observed.",
    ),
    NeutralLifecycleEvent(
        "execution", "execution_completion",
        "The boundary observes the call returning or terminating.",
    ),
    NeutralLifecycleEvent(
        "outcome", "result",
        "A semantic result was returned across the boundary.",
    ),
    NeutralLifecycleEvent(
        "outcome", "error",
        "An error result was returned across the boundary.",
    ),
    NeutralLifecycleEvent(
        "outcome", "exception",
        "The inner handler raised; only the exception class is recorded.",
    ),
    NeutralLifecycleEvent(
        "outcome", "task_submitted",
        "The call was submitted to a task backend; execution is not claimed.",
    ),
    NeutralLifecycleEvent(
        "outcome", "timeout",
        "The call timed out. Neutral event with no dedicated binding "
        "disposition in the current binding.",
    ),
    NeutralLifecycleEvent(
        "outcome", "cancellation",
        "The call was cooperatively cancelled; delivery state is unknown.",
    ),
    NeutralLifecycleEvent(
        "outcome", "input_required",
        "The call paused awaiting further input.",
        modes=INPUT_REQUIRED_MODES,
    ),
)


__all__ = [
    "CONTRACT_ID",
    "CONTRACT_VERSION",
    "LifecyclePhase",
    "LIFECYCLE_PHASES",
    "NeutralDisposition",
    "NEUTRAL_DISPOSITIONS",
    "NeutralRefusalGround",
    "NEUTRAL_REFUSAL_GROUNDS",
    "DEFERRAL_CONTINUATION_CONTRACT",
    "ExecutionBoundary",
    "EXECUTION_BOUNDARIES",
    "NeutralOutcome",
    "NEUTRAL_OUTCOMES",
    "InputRequiredMode",
    "INPUT_REQUIRED_MODES",
    "NeutralCancellationFact",
    "NEUTRAL_CANCELLATION_FACTS",
    "RECEIPT_CARDINALITY",
    "RECEIPT_REFERENCE_EDGES",
    "CUSTODY_EXCLUSION_FLAGS",
    "CUSTODY_NON_CLAIM_FLAGS",
    "AttestationLimitFamily",
    "ATTESTATION_LIMIT_FAMILIES",
    "DIGEST_CANONICALIZATION",
    "DIGEST_HASH",
    "DIGEST_PREFIX",
    "DIGEST_RESPONSIBILITIES",
    "RESULT_DIGEST_OUTCOMES",
    "NO_RESULT_DIGEST_OUTCOMES",
    "PROTOCOL_STAMP_FIELDS",
    "BINDING_STAMP_FIELDS",
    "ParityLayer",
    "PARITY_LAYERS",
    "PERMITTED_NORMALIZED_DIFFERENCE_FIELDS",
    "CUSTODY_PERMITTED_NORMALIZED_DIFFERENCE_FIELDS",
    "ParityLayerSpec",
    "PARITY_MODEL",
    "NeutralLifecycleEvent",
    "NEUTRAL_LIFECYCLE_EVENTS",
]
