"""Pure helpers for ``review_object_type == \"tool_call_disposition\"`` ReviewObject rows.

No sink writes, harness execution, or disk I/O - callers assemble explicitly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Mapping

from dagr_mcp.sdk_spine import (
    ReviewDecision,
    ReviewObject,
    normalize_review_decision_outcome,
    normalize_review_decision_ref,
    now_utc_iso,
    stable_payload_hash,
    validate_actor_ref,
)


class ToolCallDispositionError(ValueError):
    """Invalid inputs for a tool-call disposition review object."""


_DEFAULT_ALLOWED_ACTIONS = ("approve", "reject", "defer", "escalate")

_OPTIONAL_DISPOSITION_PAYLOAD_KEYS = frozenset(
    {
        "context_hash",
        "context_ref",
        "reason",
        "gate_timeout_seconds",
        "profile_ref",
        "policy_profile_ref",
        "policy_pack_ref",
        "policy_ref",
        "event_refs",
        "arguments_hash",
        "harness_version",
        "adapter_type",
    }
)
_REQUIRED_DISPOSITION_PAYLOAD_KEYS = frozenset(
    {
        "tool_name",
        "tool_class",
        "policy_decision",
        "retention_class",
        "required_sinks",
    }
)
_FORBIDDEN_DISPOSITION_PAYLOAD_KEYS = frozenset(
    {
        "arguments",
        "raw_arguments",
        "tool_arguments",
        "result",
        "raw_result",
        "prompt",
        "raw_prompt",
        "output",
        "raw_output",
        "private_corpus_text",
    }
)
_FORBIDDEN_DECISION_DETAIL_KEYS = _FORBIDDEN_DISPOSITION_PAYLOAD_KEYS | frozenset(
    {"payload", "metadata"}
)


def resolved_argument_hash_from_disposition_payload(
    payload: Mapping[str, Any],
) -> str:
    """Resolve the tool-argument hash from a disposition ``context_payload``.

    **Canonical** field: ``argument_hash`` (builder + spec).

    **Legacy** field: ``arguments_hash`` - accepted only when ``argument_hash`` is
    absent, or when both keys are present with **identical** string values. Harness
    ``ReviewObject`` gate rows and harness event ``detail`` blobs include canonical
    ``argument_hash``; event ``detail`` may still duplicate the digest under legacy
    ``arguments_hash`` as a transitional alias. MCP receipt extensions keep
    ``mcp_arguments_hash`` (protocol-specific naming).
    """

    has_new = "argument_hash" in payload
    has_legacy = "arguments_hash" in payload
    if not has_new and not has_legacy:
        raise ToolCallDispositionError(
            "disposition payload must include argument_hash or legacy arguments_hash"
        )

    if has_new and has_legacy:
        new_val = payload["argument_hash"]
        legacy_val = payload["arguments_hash"]
        if new_val != legacy_val:
            raise ToolCallDispositionError(
                "argument_hash and legacy arguments_hash disagree; normalize upstream"
            )
        return str(new_val)

    if has_new:
        return str(payload["argument_hash"])
    return str(payload["arguments_hash"])


@dataclass(frozen=True, slots=True)
class ToolCallDispositionInput:
    """Structured inputs for ``build_tool_call_disposition_review_object``."""

    tool_name: str
    tool_class: str
    policy_decision: str
    arguments: Mapping[str, Any]
    context: Mapping[str, Any] | None = None
    retention_class: str = "hash_only"
    required_sinks: tuple[str, ...] = ()
    reason: str | None = None
    gate_timeout_seconds: int | None = None
    profile_ref: str | None = None
    policy_profile_ref: str | None = None
    policy_pack_ref: str | None = None
    event_refs: tuple[str, ...] = ()
    review_object_id: str | None = None
    origin_event_id: str | None = None
    allowed_actions: tuple[str, ...] | None = None
    created_at: str | None = None
    policy_ref: str | None = None
    harness_version: str | None = None
    adapter_type: str | None = None


def timeout_decision_outcome() -> Literal["expired"]:
    """Canonical ``ReviewDecision.decision`` when a gate disposition times out.

    **Policy:** timeouts map to ``expired``, not ``rejected`` (the latter is an
    affirmative denial). A future runtime watchdog may call this when
    ``gate_timeout_seconds`` elapses; this module does not schedule timeouts.

    Execution receipts must not be emitted after terminal ``rejected`` or
    ``expired`` disposition decisions - enforcement of that belongs in harness /
    sink wiring, not here.
    """

    return "expired"


def hash_tool_call_arguments(arguments: Mapping[str, Any]) -> str:
    """Deterministic ``sha256:…`` over normalized JSON for ``arguments``."""

    if not isinstance(arguments, Mapping):
        raise ToolCallDispositionError(
            f"arguments must be a mapping, not {type(arguments).__name__}"
        )
    try:
        return stable_payload_hash(dict(arguments))
    except TypeError as exc:
        raise ToolCallDispositionError(
            "arguments must be JSON-stable for hashing"
        ) from exc


def hash_tool_call_context(context: Mapping[str, Any] | None) -> str | None:
    """Same hashing discipline as arguments; returns ``None`` when ``context`` is omitted."""

    if context is None:
        return None
    if not isinstance(context, Mapping):
        raise ToolCallDispositionError(
            f"context must be a mapping or None, not {type(context).__name__}"
        )
    try:
        return stable_payload_hash(dict(context))
    except TypeError as exc:
        raise ToolCallDispositionError(
            "context must be JSON-stable for hashing"
        ) from exc


def argument_hash_for_tool_call(arguments: Mapping[str, Any]) -> str:
    """Stable ``sha256:…`` digest for later comparison against a disposition row.

    Equivalent to :func:`hash_tool_call_arguments` - separate name for binding docs
    and harness-adjacent callers discussing retry/resume posture.
    """

    return hash_tool_call_arguments(arguments)


def reviewed_argument_hash_from_review_object(review_object: ReviewObject) -> str:
    """Return the reviewed arguments digest from a pending ``tool_call_disposition`` row."""

    validate_tool_call_disposition_review_object(review_object)
    return resolved_argument_hash_from_disposition_payload(
        review_object.context_payload
    )


def arguments_match_review_object(
    arguments: Mapping[str, Any],
    review_object: ReviewObject,
) -> bool:
    """Compare recomputed digest to the disposition payload (canonical + legacy rules).

    Raises :exc:`ToolCallDispositionError` when ``review_object`` fails disposition
    validation or ``arguments`` are not hashable as a mapping. Returns ``False`` when
    digests differ.
    """

    validate_tool_call_disposition_review_object(review_object)
    reviewed = resolved_argument_hash_from_disposition_payload(
        review_object.context_payload
    )
    submitted = argument_hash_for_tool_call(arguments)
    return reviewed == submitted


def require_arguments_match_review_object(
    arguments: Mapping[str, Any],
    review_object: ReviewObject,
) -> None:
    """Fail closed when recomputed digest does not match the disposition row."""

    if not arguments_match_review_object(arguments, review_object):
        raise ToolCallDispositionError(
            "submitted arguments digest does not match reviewed argument_hash"
        )


_EXECUTION_READINESS_SUMMARY_KEYS = frozenset(
    {"status", "allows_execution", "argument_hash", "reviewed_argument_hash", "reason"}
)


def tool_call_disposition_execution_readiness(
    review_object: ReviewObject,
    decision: ReviewDecision | None,
    arguments: Mapping[str, Any],
) -> dict[str, Any]:
    """Pure readiness summary - combines disposition validation + optional decision + digest match.

    Does **not** execute inner handlers, write sinks, emit events, or emit receipts.
    ``decision`` is typically a replayed ``ReviewDecision`` or ``None`` when still
    pending. Invalid decisions raise :exc:`ToolCallDispositionError`.

    Returned mapping keys are ``status``, ``allows_execution``, ``argument_hash``,
    ``reviewed_argument_hash``, ``reason`` only - never raw argument blobs.
    """

    validate_tool_call_disposition_review_object(review_object)
    reviewed_hash = resolved_argument_hash_from_disposition_payload(
        review_object.context_payload
    )
    submitted_hash = argument_hash_for_tool_call(arguments)

    base_hashes: dict[str, Any] = {
        "argument_hash": submitted_hash,
        "reviewed_argument_hash": reviewed_hash,
    }

    if decision is None:
        row: dict[str, Any] = {
            **base_hashes,
            "status": "pending",
            "allows_execution": False,
            "reason": "no_decision",
        }
    else:
        validate_tool_call_disposition_decision(decision)
        outcome = normalize_review_decision_outcome(decision.decision)

        if outcome == "deferred":
            row = {
                **base_hashes,
                "status": "deferred",
                "allows_execution": False,
                "reason": "decision_deferred",
            }
        elif outcome == "rejected":
            row = {
                **base_hashes,
                "status": "rejected",
                "allows_execution": False,
                "reason": "decision_rejected",
            }
        elif outcome == "expired":
            row = {
                **base_hashes,
                "status": "expired",
                "allows_execution": False,
                "reason": "decision_expired",
            }
        elif outcome == "approved":
            if submitted_hash != reviewed_hash:
                row = {
                    **base_hashes,
                    "status": "mismatch",
                    "allows_execution": False,
                    "reason": "argument_hash_mismatch",
                }
            else:
                row = {
                    **base_hashes,
                    "status": "approved",
                    "allows_execution": True,
                    "reason": "approved_arguments_match",
                }
        else:
            raise ToolCallDispositionError(
                f"unexpected disposition outcome after normalization: {outcome!r}"
            )

    unknown = set(row.keys()) - _EXECUTION_READINESS_SUMMARY_KEYS
    if unknown:
        raise ToolCallDispositionError(
            f"unexpected execution readiness keys: {sorted(unknown)}"
        )
    return row


def build_tool_call_disposition_review_object(
    inp: ToolCallDispositionInput,
) -> ReviewObject:
    """Mint a pending ``ReviewObject`` with content-minimized ``context_payload``."""

    name = inp.tool_name.strip()
    if not name:
        raise ToolCallDispositionError("tool_name must be non-empty")

    tc = inp.tool_class.strip()
    if not tc:
        raise ToolCallDispositionError("tool_class must be non-empty")

    pd = inp.policy_decision.strip()
    if not pd:
        raise ToolCallDispositionError("policy_decision must be non-empty")

    if not isinstance(inp.arguments, Mapping):
        raise ToolCallDispositionError(
            f"arguments must be a mapping, not {type(inp.arguments).__name__}"
        )

    argument_hash = hash_tool_call_arguments(inp.arguments)
    context_hash = hash_tool_call_context(inp.context)

    payload: dict[str, Any] = {
        "tool_name": name,
        "tool_class": tc,
        "policy_decision": pd,
        "argument_hash": argument_hash,
        "retention_class": inp.retention_class,
        "required_sinks": list(inp.required_sinks),
        "reason": inp.reason,
        "gate_timeout_seconds": inp.gate_timeout_seconds,
        "profile_ref": inp.profile_ref,
        "policy_profile_ref": inp.policy_profile_ref,
        "policy_pack_ref": inp.policy_pack_ref,
        "event_refs": list(inp.event_refs),
    }
    if context_hash is not None:
        payload["context_hash"] = context_hash

    if inp.policy_ref is not None:
        payload["policy_ref"] = inp.policy_ref
    if inp.harness_version is not None:
        payload["harness_version"] = inp.harness_version
    if inp.adapter_type is not None:
        payload["adapter_type"] = inp.adapter_type

    actions = (
        tuple(inp.allowed_actions)
        if inp.allowed_actions is not None
        else _DEFAULT_ALLOWED_ACTIONS
    )

    obj = ReviewObject(
        review_object_type="tool_call_disposition",
        governance_state="pending",
        context_payload=payload,
        allowed_actions=list(actions),
        created_at=inp.created_at or now_utc_iso(),
        review_object_id=inp.review_object_id,
        origin_event_id=inp.origin_event_id,
    )
    validate_tool_call_disposition_review_object(obj)
    return obj


def _validate_sha256_attestation(value: str, *, field: str) -> None:
    if not isinstance(value, str):
        raise ToolCallDispositionError(f"{field} must be a string")
    if not value.startswith("sha256:"):
        raise ToolCallDispositionError(f"{field} must start with sha256:")
    suffix = value[7:]
    if len(suffix) != 64:
        raise ToolCallDispositionError(
            f"{field} must be sha256: followed by 64 hex characters"
        )
    try:
        int(suffix, 16)
    except ValueError as exc:
        raise ToolCallDispositionError(f"{field} has non-hex digest suffix") from exc


def validate_tool_call_disposition_decision(decision: ReviewDecision) -> None:
    """Narrow validation for ``ReviewDecision`` rows tied to ``tool_call_disposition``.

    Ensures the outcome is one of ``approved`` / ``rejected`` / ``deferred`` /
    ``expired``, forbids raw-content-shaped keys in ``detail``, rejects a
    mismatched ``review_object_type`` entry in ``detail`` when present, and
    validates optional ``actor_ref`` on the decision and in ``detail`` (when
    present) using ``validate_actor_ref``. Does **not** require ``actor_ref``.
    """

    if not isinstance(decision.decision, str):
        raise ToolCallDispositionError(
            f"decision.decision must be str, not {type(decision.decision).__name__}"
        )
    try:
        normalize_review_decision_outcome(decision.decision)
    except ValueError as exc:
        raise ToolCallDispositionError(str(exc)) from exc

    if decision.reason is not None and not isinstance(decision.reason, str):
        raise ToolCallDispositionError(
            f"decision.reason must be str or None, not {type(decision.reason).__name__}"
        )

    detail = decision.detail
    if not isinstance(detail, dict):
        raise ToolCallDispositionError(
            f"decision.detail must be a dict, not {type(detail).__name__}"
        )
    for key in detail:
        if key in _FORBIDDEN_DECISION_DETAIL_KEYS:
            raise ToolCallDispositionError(f"forbidden decision.detail key: {key!r}")

    rot = detail.get("review_object_type")
    if rot is not None and rot != "tool_call_disposition":
        raise ToolCallDispositionError(
            "decision.detail review_object_type must be "
            f"'tool_call_disposition' when present, not {rot!r}"
        )

    if decision.actor_ref is not None:
        try:
            validate_actor_ref(decision.actor_ref, required=False)
        except ValueError as exc:
            raise ToolCallDispositionError(str(exc)) from exc

    if "actor_ref" in detail:
        detail_actor = detail["actor_ref"]
        if detail_actor is None:
            raise ToolCallDispositionError(
                "decision.detail actor_ref must not be null when the key is present"
            )
        if not isinstance(detail_actor, str):
            raise ToolCallDispositionError(
                "decision.detail actor_ref must be a string when present"
            )
        try:
            normalized_detail = validate_actor_ref(detail_actor, required=False)
        except ValueError as exc:
            raise ToolCallDispositionError(str(exc)) from exc
        if decision.actor_ref is not None:
            top_norm = validate_actor_ref(decision.actor_ref, required=False)
            if normalized_detail != top_norm:
                raise ToolCallDispositionError(
                    "actor_ref mismatch between decision.actor_ref and decision.detail"
                )


_STATUS_SUMMARY_KEYS = frozenset(
    {"review_object_ref", "status", "allows_execution", "decision_ref", "actor_ref"}
)


def _review_sink_supports_decision_replay(review_sink: Any) -> bool:
    return any(
        callable(getattr(review_sink, name, None))
        for name in (
            "terminal_decision_lookup",
            "terminal_decision",
            "latest_decision_lookup",
            "latest_decision",
        )
    )


def _actor_ref_for_tool_disposition_status(decision: ReviewDecision) -> str | None:
    if decision.actor_ref is None:
        return None
    return validate_actor_ref(decision.actor_ref, required=False)


def _terminal_tool_disposition_status_row(
    review_object_ref: str,
    *,
    outcome: str,
    decision_ref: str | None,
    decision: ReviewDecision,
) -> dict[str, Any]:
    allows = outcome == "approved"
    if outcome == "approved":
        label = "approved"
    elif outcome == "rejected":
        label = "rejected"
    elif outcome == "expired":
        label = "expired"
    else:
        raise ToolCallDispositionError(
            f"terminal disposition summary expected approved/rejected/expired, got {outcome!r}"
        )
    row: dict[str, Any] = {
        "review_object_ref": review_object_ref,
        "status": label,
        "allows_execution": allows,
    }
    if decision_ref is not None:
        row["decision_ref"] = decision_ref
    actor = _actor_ref_for_tool_disposition_status(decision)
    if actor is not None:
        row["actor_ref"] = actor
    return row


def tool_call_disposition_decision_status(
    review_sink: Any,
    review_object_ref: str,
) -> dict[str, Any]:
    """Summarize disposition decisions for ``review_object_ref`` - pure read helper.

    Uses ``terminal_decision_lookup`` / ``latest_decision_lookup`` when present,
    otherwise falls back to ``terminal_decision`` / ``latest_decision``. Does **not**
    poll, execute tools, or emit events/receipts. Raises ``ToolCallDispositionError``
    when validation fails or replay methods are missing.
    """

    if not isinstance(review_object_ref, str) or not review_object_ref.strip():
        raise ToolCallDispositionError("review_object_ref must be a non-empty str")
    rid = review_object_ref.strip()
    if not _review_sink_supports_decision_replay(review_sink):
        raise ToolCallDispositionError(
            "review_sink must expose terminal_decision_lookup / terminal_decision "
            "or latest_decision_lookup / latest_decision"
        )

    decision_ref: str | None = None
    term_dec: ReviewDecision | None = None

    fn_tl = getattr(review_sink, "terminal_decision_lookup", None)
    if callable(fn_tl):
        tl = fn_tl(rid)
        if tl is not None:
            term_dec = tl.decision
            decision_ref = tl.decision_ref

    if term_dec is None:
        fn_t = getattr(review_sink, "terminal_decision", None)
        if callable(fn_t):
            term_dec = fn_t(rid)

    if term_dec is not None:
        validate_tool_call_disposition_decision(term_dec)
        outcome = normalize_review_decision_outcome(term_dec.decision)
        row = _terminal_tool_disposition_status_row(
            rid,
            outcome=outcome,
            decision_ref=decision_ref,
            decision=term_dec,
        )
        unknown = set(row.keys()) - _STATUS_SUMMARY_KEYS
        if unknown:
            raise ToolCallDispositionError(
                f"unexpected decision status keys: {sorted(unknown)}"
            )
        return row

    latest_dec: ReviewDecision | None = None
    latest_ref: str | None = None

    fn_ll = getattr(review_sink, "latest_decision_lookup", None)
    if callable(fn_ll):
        ll = fn_ll(rid)
        if ll is not None:
            latest_dec = ll.decision
            latest_ref = ll.decision_ref

    if latest_dec is None:
        fn_l = getattr(review_sink, "latest_decision", None)
        if callable(fn_l):
            latest_dec = fn_l(rid)

    if latest_dec is None:
        return {
            "review_object_ref": rid,
            "status": "pending",
            "allows_execution": False,
        }

    validate_tool_call_disposition_decision(latest_dec)
    outcome_latest = normalize_review_decision_outcome(latest_dec.decision)
    if outcome_latest == "deferred":
        row = {
            "review_object_ref": rid,
            "status": "deferred",
            "allows_execution": False,
        }
        if latest_ref is not None:
            row["decision_ref"] = latest_ref
        actor = _actor_ref_for_tool_disposition_status(latest_dec)
        if actor is not None:
            row["actor_ref"] = actor
        unknown = set(row.keys()) - _STATUS_SUMMARY_KEYS
        if unknown:
            raise ToolCallDispositionError(
                f"unexpected decision status keys: {sorted(unknown)}"
            )
        return row

    raise ToolCallDispositionError(
        "replay invariant violated: latest decision is terminal but "
        "terminal_decision_lookup / terminal_decision returned None"
    )


_LINKAGE_PAYLOAD_KEYS = frozenset(
    {"review_object_ref", "decision_ref", "argument_hash", "actor_ref", "outcome"}
)


def build_tool_call_disposition_linkage(
    review_object_ref: str,
    *,
    decision_ref: str | None = None,
    argument_hash: str | None = None,
    actor_ref: str | None = None,
    outcome: str | None = None,
) -> dict[str, Any]:
    """Build a hash/ref-only linkage mapping for future events or receipts.

    **Pure:** no sink writes, event emission, or receipt emission. Callers pass
    explicit scalars only (no arbitrary ``dict`` merge) so raw tool content cannot
    be smuggled via extra keys.
    """

    if not isinstance(review_object_ref, str) or not review_object_ref.strip():
        raise ToolCallDispositionError(
            "review_object_ref must be a non-empty str"
        )

    out: dict[str, Any] = {"review_object_ref": review_object_ref.strip()}

    if decision_ref is not None:
        if not isinstance(decision_ref, str) or not decision_ref.strip():
            raise ToolCallDispositionError(
                "decision_ref must be a non-empty str when supplied"
            )
        try:
            out["decision_ref"] = normalize_review_decision_ref(decision_ref.strip())
        except ValueError as exc:
            raise ToolCallDispositionError(str(exc)) from exc

    if argument_hash is not None:
        if not isinstance(argument_hash, str) or not argument_hash.strip():
            raise ToolCallDispositionError(
                "argument_hash must be a non-empty str when supplied"
            )
        ah = argument_hash.strip()
        _validate_sha256_attestation(ah, field="argument_hash")
        out["argument_hash"] = ah

    if actor_ref is not None:
        if not isinstance(actor_ref, str) or not actor_ref.strip():
            raise ToolCallDispositionError(
                "actor_ref must be a non-empty str when supplied"
            )
        try:
            out["actor_ref"] = validate_actor_ref(actor_ref.strip(), required=False)
        except ValueError as exc:
            raise ToolCallDispositionError(str(exc)) from exc

    if outcome is not None:
        if not isinstance(outcome, str) or not outcome.strip():
            raise ToolCallDispositionError(
                "outcome must be a non-empty str when supplied"
            )
        try:
            out["outcome"] = normalize_review_decision_outcome(outcome)
        except ValueError as exc:
            raise ToolCallDispositionError(str(exc)) from exc

    unknown = set(out) - _LINKAGE_PAYLOAD_KEYS
    if unknown:
        raise ToolCallDispositionError(
            f"linkage payload contained unexpected keys: {sorted(unknown)}"
        )

    return out


def tool_call_disposition_allows_execution(decision: ReviewDecision | None) -> bool:
    """Return whether a validated disposition ``ReviewDecision`` permits execution.

    **Pure:** does not run inner handlers, write sinks, or emit events/receipts.
    Only canonical outcome ``approved`` returns ``True`` after
    ``validate_tool_call_disposition_decision``. ``None`` and all other outcomes
    (including ``deferred``) return ``False``; invalid decisions raise
    ``ToolCallDispositionError`` from the validation step.
    """

    if decision is None:
        return False
    validate_tool_call_disposition_decision(decision)
    return normalize_review_decision_outcome(decision.decision) == "approved"


def validate_tool_call_disposition_payload(payload: Mapping[str, Any]) -> None:
    """Narrow structural validation for ``tool_call_disposition`` ``context_payload``."""

    if not isinstance(payload, Mapping):
        raise ToolCallDispositionError(
            f"disposition payload must be a mapping, not {type(payload).__name__}"
        )

    for forbidden in _FORBIDDEN_DISPOSITION_PAYLOAD_KEYS:
        if forbidden in payload:
            raise ToolCallDispositionError(
                f"forbidden disposition payload key: {forbidden!r}"
            )

    allowed = _REQUIRED_DISPOSITION_PAYLOAD_KEYS | _OPTIONAL_DISPOSITION_PAYLOAD_KEYS | {
        "argument_hash",
    }
    for key in payload:
        if key not in allowed:
            raise ToolCallDispositionError(f"unknown disposition payload key: {key!r}")

    missing = _REQUIRED_DISPOSITION_PAYLOAD_KEYS - set(payload.keys())
    if missing:
        raise ToolCallDispositionError(
            f"disposition payload missing required keys: {sorted(missing)}"
        )

    arg_hash = resolved_argument_hash_from_disposition_payload(payload)
    _validate_sha256_attestation(arg_hash, field="argument_hash")

    if "context_hash" in payload:
        _validate_sha256_attestation(str(payload["context_hash"]), field="context_hash")

    sinks = payload["required_sinks"]
    if not isinstance(sinks, list):
        raise ToolCallDispositionError("required_sinks must be a list")

    if "event_refs" in payload:
        refs = payload["event_refs"]
        if not isinstance(refs, list):
            raise ToolCallDispositionError("event_refs must be a list when present")

    if "gate_timeout_seconds" in payload and payload["gate_timeout_seconds"] is not None:
        g = payload["gate_timeout_seconds"]
        if isinstance(g, bool) or not isinstance(g, int) or g <= 0:
            raise ToolCallDispositionError(
                "gate_timeout_seconds must be a positive integer when present"
            )


def validate_tool_call_disposition_review_object(review_object: ReviewObject) -> None:
    """Validate a ``ReviewObject`` row for ``tool_call_disposition``."""

    if review_object.review_object_type != "tool_call_disposition":
        raise ToolCallDispositionError(
            f"expected review_object_type tool_call_disposition, got "
            f"{review_object.review_object_type!r}"
        )
    if review_object.governance_state != "pending":
        raise ToolCallDispositionError(
            f"expected governance_state pending for validated mint, got "
            f"{review_object.governance_state!r}"
        )
    validate_tool_call_disposition_payload(review_object.context_payload)


__all__ = [
    "ToolCallDispositionError",
    "ToolCallDispositionInput",
    "argument_hash_for_tool_call",
    "arguments_match_review_object",
    "build_tool_call_disposition_linkage",
    "build_tool_call_disposition_review_object",
    "hash_tool_call_arguments",
    "hash_tool_call_context",
    "require_arguments_match_review_object",
    "resolved_argument_hash_from_disposition_payload",
    "reviewed_argument_hash_from_review_object",
    "timeout_decision_outcome",
    "tool_call_disposition_decision_status",
    "tool_call_disposition_execution_readiness",
    "tool_call_disposition_allows_execution",
    "validate_tool_call_disposition_decision",
    "validate_tool_call_disposition_payload",
    "validate_tool_call_disposition_review_object",
]
