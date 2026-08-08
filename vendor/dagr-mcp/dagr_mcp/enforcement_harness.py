"""Canonical enforcement harness extracted from garp-local's monolith.

This module is the keystone the SDK was previously missing: a ``wrap_handler``
that wraps an inner MCP-style tool handler in a governed boundary which emits
events, enforces tool policy, gates review-required calls through the
ToolCallDisposition review-object contract, and writes hash-only enforcement
receipts.

It is a behavior-preserving port of garp-local's
``garp_core.enforcement_harness``. The sink protocols, in-memory sinks,
ToolCallDisposition contract, and policy-profile projection it composes were
already shipped in garp-sdk, so this module rewrites only the import roots
(``garp_core.*`` -> ``dagr_mcp.*``) and recreates no substrate of its own.

It does not implement an MCP server and ships no runtime policy packs; it is
the substrate that lets downstream adapters (e.g. arcs-anchor's MCP harness
adapter) consume a canonical SDK harness rather than depending on the
monolith.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Literal, Mapping, Sequence

from dagr_mcp.policy_profile import PolicyProfileProjection
from dagr_mcp.tool_call_disposition import (
    ToolCallDispositionError,
    ToolCallDispositionInput,
    build_tool_call_disposition_review_object,
)
from dagr_mcp.sdk_spine import (
    ArtifactSink,
    EventEnvelope,
    EventSink,
    LintFindingSink,
    ReceiptEnvelope,
    ReceiptSink,
    ReviewObjectSink,
    SinkHealth,
    SinkUnavailableError,
    now_utc_iso,
    stable_payload_hash,
)


ToolClass = Literal[
    "read",
    "write",
    "destructive",
    "external_action",
    "credentialed_action",
    "unknown",
]
PolicyDecisionValue = Literal["allow", "deny", "gate", "defer", "fail_closed"]

DEFAULT_ATTESTATION_LIMITS = [
    "Receipt attests only to governance conditions at the harness boundary.",
    "Receipt does not attest to MCP server internal retention.",
    "Receipt does not prove model or provider non-retention.",
]

RAW_ARTIFACT_CLASSES_EXCLUDED = [
    "raw_prompt",
    "raw_output",
    "raw_tool_arguments",
    "raw_tool_result",
]


def _event_argument_hash_fields(arguments_hash: str) -> dict[str, str]:
    """Event ``detail`` fragment: canonical ``argument_hash`` plus legacy alias.

    ``arguments_hash`` remains a transitional duplicate of the same digest string
    emitted as ``argument_hash`` until consumers migrate off legacy event keys.
    """

    return {"argument_hash": arguments_hash, "arguments_hash": arguments_hash}


@dataclass(frozen=True, slots=True)
class HarnessConfig:
    harness_version: str
    module_id: str
    module_version: str
    profile_ref: str
    policy_ref: str
    adapter_type: str = "mcp"
    policy_hash: str | None = None
    default_receipt_required: bool = False
    fail_closed_on_unknown_tool: bool = True


@dataclass(slots=True)
class HarnessContext:
    harness_version: str
    adapter_type: str
    module_id: str
    module_version: str
    profile_ref: str
    policy_ref: str
    tool_name: str
    arguments_hash: str
    actor_ref: str | None = None
    session_ref: str | None = None
    request_ref: str | None = None
    raw_arguments_allowed: bool = False
    result_hash: str | None = None
    raw_result_allowed: bool = False
    event_chain_refs: list[str] = field(default_factory=list)
    receipt_refs: list[str] = field(default_factory=list)
    review_object_ref: str | None = None
    admission_receipt_ref: str | None = None
    sink_health_snapshot: dict[str, SinkHealth] = field(default_factory=dict)
    attestation_limits: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class ToolPolicy:
    tool_name: str
    tool_class: ToolClass
    decision: PolicyDecisionValue
    receipt_required: bool = False
    review_required: bool = False
    retention_class: str = "hash_only"
    required_sinks: list[str] = field(default_factory=lambda: ["event"])
    reason: str | None = None
    gate_timeout_seconds: int | None = None


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    decision: PolicyDecisionValue
    reason: str
    policy_ref: str
    required_sinks: list[str]
    receipt_required: bool
    review_required: bool
    retention_class: str
    attestation_limits: list[str]
    policy_hash: str | None = None


@dataclass(frozen=True, slots=True)
class HarnessSinks:
    event: EventSink
    receipt: ReceiptSink | None = None
    review: ReviewObjectSink | None = None
    artifact: ArtifactSink | None = None
    lint: LintFindingSink | None = None


@dataclass(slots=True)
class GovernedResult:
    ok: bool
    result: Any | None = None
    failure_reason: str | None = None
    event_refs: list[str] = field(default_factory=list)
    receipt_refs: list[str] = field(default_factory=list)
    review_object_ref: str | None = None
    policy_decision: PolicyDecision | None = None
    context: HarnessContext | None = None


PoliciesInput = Mapping[str, ToolPolicy] | Sequence[ToolPolicy] | None
WrappedHandler = Callable[[str, Any, Any], GovernedResult]


def wrap_handler(
    inner: Any,
    config: HarnessConfig,
    sinks: HarnessSinks,
    policies: PoliciesInput = None,
    policy_profile: PolicyProfileProjection | None = None,
    srs_bridge: Any | None = None,
) -> Callable[[str, Any, Any], GovernedResult]:
    policy_by_tool = _normalize_policies(policies)
    failure_behavior = (
        policy_profile.harness.sink_requirements.required_sink_failure_behavior
        if policy_profile is not None
        else "fail_closed"
    )

    def wrapped(
        tool_name: str,
        arguments: Any,
        context: Any = None,
    ) -> GovernedResult:
        arguments_hash = stable_payload_hash(arguments)
        harness_context = _build_context(
            config=config,
            tool_name=tool_name,
            arguments_hash=arguments_hash,
            caller_context=context,
        )

        event_health_failure = _check_required_sink(
            "event",
            sinks,
            harness_context.sink_health_snapshot,
            failure_behavior=failure_behavior,
        )
        if event_health_failure:
            return _governed_failure(
                failure_reason=event_health_failure,
                context=harness_context,
            )

        requested_ref = _safe_write_event(
            sinks=sinks,
            event_type="mcp.tool.call.requested",
            config=config,
            context=harness_context,
            detail={
                "tool_name": tool_name,
                **_event_argument_hash_fields(arguments_hash),
                "adapter_type": config.adapter_type,
                "module_id": config.module_id,
            },
        )
        if requested_ref is None:
            return _governed_failure(
                failure_reason="event_sink_unavailable",
                context=harness_context,
            )
        harness_context.event_chain_refs.append(requested_ref)

        policy_decision = _evaluate_policy(
            tool_name=tool_name,
            config=config,
            policy=policy_by_tool.get(tool_name),
        )
        harness_context.attestation_limits = list(policy_decision.attestation_limits)

        effective_sinks = _effective_required_sinks(
            policy_decision=policy_decision,
            policy_profile=policy_profile,
        )
        sink_failure = _check_effective_required_sinks(
            effective_sinks,
            sinks,
            harness_context.sink_health_snapshot,
            failure_behavior=failure_behavior,
        )
        if sink_failure:
            if srs_bridge is not None:
                try:
                    harness_context.admission_receipt_ref = srs_bridge.emit_admission(
                        harness_context=harness_context, tool_name=tool_name,
                        disposition="refused", reason_code="required_sink_unavailable")
                except Exception:
                    pass
            _append_event_if_available(
                sinks=sinks,
                event_type="mcp.tool.call.rejected",
                config=config,
                context=harness_context,
                detail={
                    "tool_name": tool_name,
                    **_event_argument_hash_fields(arguments_hash),
                    "policy_decision": policy_decision.decision,
                    "reason": sink_failure,
                },
            )
            return _governed_failure(
                failure_reason=sink_failure,
                policy_decision=policy_decision,
                context=harness_context,
            )

        if policy_decision.decision in {"deny", "defer", "fail_closed"}:
            if srs_bridge is not None:
                reason_code = "unknown_tool_fail_closed" if policy_decision.reason == "unknown_tool" else "policy_refused"
                try:
                    harness_context.admission_receipt_ref = srs_bridge.emit_admission(
                        harness_context=harness_context, tool_name=tool_name,
                        disposition="refused", reason_code=reason_code)
                except Exception:
                    return _governed_failure(
                        failure_reason="pre_execution_receipt_failure",
                        policy_decision=policy_decision, context=harness_context)
            _append_event_if_available(
                sinks=sinks,
                event_type="mcp.tool.call.rejected",
                config=config,
                context=harness_context,
                detail={
                    "tool_name": tool_name,
                    **_event_argument_hash_fields(arguments_hash),
                    "policy_decision": policy_decision.decision,
                    "reason": policy_decision.reason,
                },
            )
            return _governed_failure(
                failure_reason=_failure_reason_for_decision(policy_decision),
                policy_decision=policy_decision,
                context=harness_context,
            )

        if policy_decision.decision == "gate":
            if not isinstance(arguments, Mapping):
                return _governed_failure(
                    failure_reason="tool_call_arguments_not_mapping",
                    policy_decision=policy_decision,
                    context=harness_context,
                )
            return _gate_call(
                sinks=sinks,
                config=config,
                context=harness_context,
                tool_name=tool_name,
                arguments=arguments,
                policy_decision=policy_decision,
                tool_policy=policy_by_tool.get(tool_name),
                srs_bridge=srs_bridge,
            )

        if srs_bridge is not None:
            try:
                harness_context.admission_receipt_ref = srs_bridge.emit_admission(
                    harness_context=harness_context, tool_name=tool_name,
                    disposition="admitted")
            except Exception:
                return _governed_failure(
                    failure_reason="pre_execution_receipt_failure",
                    policy_decision=policy_decision, context=harness_context)

        result = None
        try:
            result = _call_inner(inner, tool_name, arguments, context)
        except Exception as exc:  # noqa: BLE001 - governed failures must not leak raw exceptions.
            if srs_bridge is not None and harness_context.admission_receipt_ref is not None:
                try:
                    srs_bridge.emit_outcome(
                        harness_context=harness_context,
                        admission_receipt_ref=harness_context.admission_receipt_ref,
                        outcome="exception", exception_class=type(exc).__name__)
                except Exception:
                    pass
            _append_event_if_available(
                sinks=sinks,
                event_type="mcp.tool.call.failed",
                config=config,
                context=harness_context,
                detail={
                    "tool_name": tool_name,
                    **_event_argument_hash_fields(arguments_hash),
                    "policy_decision": policy_decision.decision,
                    "failure_class": type(exc).__name__,
                },
            )
            return _governed_failure(
                failure_reason="inner_exception",
                policy_decision=policy_decision,
                context=harness_context,
            )

        harness_context.result_hash = stable_payload_hash(result)
        if srs_bridge is not None and harness_context.admission_receipt_ref is not None:
            try:
                outcome_ref = srs_bridge.emit_outcome(
                    harness_context=harness_context,
                    admission_receipt_ref=harness_context.admission_receipt_ref,
                    outcome="result_returned",
                    result_value=result)
                harness_context.receipt_refs.extend(
                    [harness_context.admission_receipt_ref, outcome_ref])
            except Exception:
                pass
        _append_event_if_available(
            sinks=sinks,
            event_type="mcp.tool.call.executed",
            config=config,
            context=harness_context,
            detail={
                "tool_name": tool_name,
                **_event_argument_hash_fields(arguments_hash),
                "result_hash": harness_context.result_hash,
                "policy_decision": policy_decision.decision,
            },
        )

        if policy_decision.receipt_required:
            receipt_ref = _write_receipt(
                sinks=sinks,
                config=config,
                context=harness_context,
                policy_decision=policy_decision,
                tool_name=tool_name,
            )
            if receipt_ref is None:
                _append_event_if_available(
                    sinks=sinks,
                    event_type="mcp.tool.call.failed",
                    config=config,
                    context=harness_context,
                    detail={
                        "tool_name": tool_name,
                        **_event_argument_hash_fields(arguments_hash),
                        "result_hash": harness_context.result_hash,
                        "policy_decision": policy_decision.decision,
                        "failure_class": "ReceiptWriteFailure",
                    },
                )
                return _governed_failure(
                    failure_reason="receipt_write_failed",
                    policy_decision=policy_decision,
                    context=harness_context,
                )
            harness_context.receipt_refs.append(receipt_ref)

        return GovernedResult(
            ok=True,
            result=result,
            event_refs=list(harness_context.event_chain_refs),
            receipt_refs=list(harness_context.receipt_refs),
            review_object_ref=harness_context.review_object_ref,
            policy_decision=policy_decision,
            context=harness_context,
        )

    return wrapped


def _normalize_policies(policies: PoliciesInput) -> dict[str, ToolPolicy]:
    if policies is None:
        return {}
    if isinstance(policies, Mapping):
        return dict(policies)
    return {policy.tool_name: policy for policy in policies}


def _build_context(
    *,
    config: HarnessConfig,
    tool_name: str,
    arguments_hash: str,
    caller_context: Any,
) -> HarnessContext:
    return HarnessContext(
        harness_version=config.harness_version,
        adapter_type=config.adapter_type,
        module_id=config.module_id,
        module_version=config.module_version,
        profile_ref=config.profile_ref,
        policy_ref=config.policy_ref,
        tool_name=tool_name,
        arguments_hash=arguments_hash,
        actor_ref=_context_value(caller_context, "actor_ref"),
        session_ref=_context_value(caller_context, "session_ref"),
        request_ref=_context_value(caller_context, "request_ref"),
    )


def _context_value(context: Any, key: str) -> str | None:
    if isinstance(context, Mapping):
        value = context.get(key)
    else:
        value = getattr(context, key, None)
    if value is None:
        return None
    return str(value)


def _evaluate_policy(
    *,
    tool_name: str,
    config: HarnessConfig,
    policy: ToolPolicy | None,
) -> PolicyDecision:
    if policy is None:
        if config.fail_closed_on_unknown_tool:
            return PolicyDecision(
                decision="fail_closed",
                reason="unknown_tool",
                policy_ref=config.policy_ref,
                policy_hash=config.policy_hash,
                required_sinks=["event"],
                receipt_required=False,
                review_required=False,
                retention_class="hash_only",
                attestation_limits=list(DEFAULT_ATTESTATION_LIMITS),
            )
        receipt_required = config.default_receipt_required
        required_sinks = ["event"]
        if receipt_required:
            required_sinks.append("receipt")
        return PolicyDecision(
            decision="allow",
            reason=f"unknown_tool_allowed:{tool_name}",
            policy_ref=config.policy_ref,
            policy_hash=config.policy_hash,
            required_sinks=required_sinks,
            receipt_required=receipt_required,
            review_required=False,
            retention_class="hash_only",
            attestation_limits=list(DEFAULT_ATTESTATION_LIMITS),
        )

    receipt_required = policy.receipt_required or config.default_receipt_required
    review_required = policy.review_required or policy.decision == "gate"
    required_sinks = _normalized_required_sinks(
        policy.required_sinks,
        receipt_required=receipt_required,
        review_required=review_required,
    )
    return PolicyDecision(
        decision=policy.decision,
        reason=policy.reason or f"policy_{policy.decision}",
        policy_ref=config.policy_ref,
        policy_hash=config.policy_hash,
        required_sinks=required_sinks,
        receipt_required=receipt_required,
        review_required=review_required,
        retention_class=policy.retention_class,
        attestation_limits=list(DEFAULT_ATTESTATION_LIMITS),
    )


def _normalized_required_sinks(
    required_sinks: Sequence[str],
    *,
    receipt_required: bool,
    review_required: bool,
) -> list[str]:
    normalized: list[str] = []
    for sink_name in ["event", *required_sinks]:
        _append_unique(normalized, _normalize_sink_name(sink_name))
    if receipt_required:
        _append_unique(normalized, "receipt")
    if review_required:
        _append_unique(normalized, "review")
    return normalized


def _append_unique(values: list[str], value: str) -> None:
    if value not in values:
        values.append(value)


def _normalize_sink_name(sink_name: str) -> str:
    if sink_name in {"review_object", "review_object_sink"}:
        return "review"
    if sink_name.endswith("_sink"):
        return sink_name.removesuffix("_sink")
    return sink_name


def _effective_required_sinks(
    *,
    policy_decision: PolicyDecision,
    policy_profile: PolicyProfileProjection | None,
) -> list[str]:
    merged: list[str] = []
    for sink_name in policy_decision.required_sinks:
        _append_unique(merged, _normalize_sink_name(sink_name))

    if policy_profile is None:
        return merged

    sr = policy_profile.harness.sink_requirements
    if sr.event_sink_required:
        _append_unique(merged, "event")
    if sr.receipt_sink_required:
        _append_unique(merged, "receipt")
    if sr.artifact_sink_required:
        _append_unique(merged, "artifact")
    if sr.review_object_sink_required:
        _append_unique(merged, "review")
    if sr.lint_finding_sink_required:
        _append_unique(merged, "lint")

    return merged


def effective_required_sink_names(
    policy_decision: PolicyDecision,
    policy_profile: PolicyProfileProjection | None = None,
) -> list[str]:
    """Sink names ``wrap_handler`` would health-check for this decision and projection.

    Exposed for operator probes and integrations that must mirror harness union logic
    without invoking ``wrap_handler``.
    """

    return list(
        _effective_required_sinks(
            policy_decision=policy_decision,
            policy_profile=policy_profile,
        )
    )


def _check_effective_required_sinks(
    sink_names: Sequence[str],
    sinks: HarnessSinks,
    snapshot: dict[str, SinkHealth],
    *,
    failure_behavior: str,
) -> str | None:
    for sink_name in sink_names:
        failure = _check_required_sink(
            sink_name,
            sinks,
            snapshot,
            failure_behavior=failure_behavior,
        )
        if failure:
            return failure
    return None


def _check_required_sink(
    sink_name: str,
    sinks: HarnessSinks,
    snapshot: dict[str, SinkHealth],
    *,
    failure_behavior: str = "fail_closed",
) -> str | None:
    normalized = _normalize_sink_name(sink_name)
    sink = _sink_by_name(normalized, sinks)
    if sink is None:
        return _sink_failure_reason(normalized)
    try:
        health = sink.health()
    except Exception:  # noqa: BLE001 - sink health failures are governed failures.
        return _sink_failure_reason(normalized)
    snapshot[normalized] = health

    if health.status == "available" and health.writable:
        return None

    if health.status == "degraded":
        if failure_behavior in {"degraded", "advisory"} and health.writable:
            return None
        return f"{normalized}_sink_degraded"

    if health.status in {"unavailable", "unknown"} or not health.writable:
        return _sink_failure_reason(normalized)

    return _sink_failure_reason(normalized)


def _sink_by_name(sink_name: str, sinks: HarnessSinks) -> Any | None:
    if sink_name == "event":
        return sinks.event
    if sink_name == "receipt":
        return sinks.receipt
    if sink_name == "review":
        return sinks.review
    if sink_name == "artifact":
        return sinks.artifact
    if sink_name in {"lint", "lint_finding"}:
        return sinks.lint
    return None


def _sink_failure_reason(sink_name: str) -> str:
    if sink_name == "review":
        return "review_object_sink_unavailable"
    if sink_name in {"lint", "lint_finding"}:
        return "lint_finding_sink_unavailable"
    return f"{sink_name}_sink_unavailable"


def _safe_write_event(
    *,
    sinks: HarnessSinks,
    event_type: str,
    config: HarnessConfig,
    context: HarnessContext,
    detail: dict[str, Any],
) -> str | None:
    try:
        return sinks.event.write_event(
            EventEnvelope(
                event_type=event_type,
                occurred_at=now_utc_iso(),
                subject_ref=context.session_ref or context.request_ref,
                actor_ref=context.actor_ref,
                policy_ref=config.policy_ref,
                detail=detail,
                lineage_refs=list(context.event_chain_refs),
            )
        )
    except SinkUnavailableError:
        return None


def _append_event_if_available(
    *,
    sinks: HarnessSinks,
    event_type: str,
    config: HarnessConfig,
    context: HarnessContext,
    detail: dict[str, Any],
) -> str | None:
    event_ref = _safe_write_event(
        sinks=sinks,
        event_type=event_type,
        config=config,
        context=context,
        detail=detail,
    )
    if event_ref is not None:
        context.event_chain_refs.append(event_ref)
    return event_ref


def _governed_failure(
    *,
    failure_reason: str,
    context: HarnessContext,
    policy_decision: PolicyDecision | None = None,
) -> GovernedResult:
    return GovernedResult(
        ok=False,
        failure_reason=failure_reason,
        event_refs=list(context.event_chain_refs),
        receipt_refs=list(context.receipt_refs),
        review_object_ref=context.review_object_ref,
        policy_decision=policy_decision,
        context=context,
    )


def _failure_reason_for_decision(policy_decision: PolicyDecision) -> str:
    if policy_decision.reason == "unknown_tool":
        return "unknown_tool"
    if policy_decision.decision == "deny":
        return "denied"
    if policy_decision.decision == "defer":
        return "deferred"
    return "fail_closed"


def _gate_call(
    *,
    sinks: HarnessSinks,
    config: HarnessConfig,
    context: HarnessContext,
    tool_name: str,
    arguments: Mapping[str, Any],
    policy_decision: PolicyDecision,
    tool_policy: ToolPolicy | None,
    srs_bridge: Any | None = None,
) -> GovernedResult:
    if sinks.review is None:
        if srs_bridge is not None:
            try:
                context.admission_receipt_ref = srs_bridge.emit_admission(
                    harness_context=context, tool_name=tool_name, disposition="refused",
                    reason_code="review_object_creation_failed")
            except Exception:
                pass
        return _governed_failure(
            failure_reason="review_object_sink_unavailable",
            policy_decision=policy_decision,
            context=context,
        )

    try:
        review_inp = ToolCallDispositionInput(
            tool_name=tool_name,
            tool_class=tool_policy.tool_class
            if tool_policy is not None
            else "unknown",
            policy_decision=policy_decision.decision,
            arguments=arguments,
            context=None,
            retention_class=policy_decision.retention_class,
            required_sinks=tuple(policy_decision.required_sinks),
            reason=policy_decision.reason,
            gate_timeout_seconds=tool_policy.gate_timeout_seconds
            if tool_policy
            else None,
            profile_ref=config.profile_ref,
            event_refs=tuple(context.event_chain_refs),
            origin_event_id=context.event_chain_refs[0]
            if context.event_chain_refs
            else None,
            allowed_actions=("approve", "reject", "defer", "escalate"),
            policy_ref=policy_decision.policy_ref,
            harness_version=config.harness_version,
            adapter_type=config.adapter_type,
        )
        review_object = build_tool_call_disposition_review_object(review_inp)
    except ToolCallDispositionError:
        return _governed_failure(
            failure_reason="tool_call_disposition_invalid",
            policy_decision=policy_decision,
            context=context,
        )

    try:
        review_object_ref = sinks.review.create_review_object(review_object)
    except Exception:  # Review routing failure is a terminal institutional refusal.
        if srs_bridge is not None:
            try:
                context.admission_receipt_ref = srs_bridge.emit_admission(
                    harness_context=context, tool_name=tool_name, disposition="refused",
                    reason_code="review_object_creation_failed")
            except Exception:
                pass
        return _governed_failure(
            failure_reason="review_object_sink_unavailable",
            policy_decision=policy_decision,
            context=context,
        )

    context.review_object_ref = review_object_ref
    if srs_bridge is not None:
        try:
            context.admission_receipt_ref = srs_bridge.emit_admission(
                harness_context=context, tool_name=tool_name,
                disposition="deferred_for_review", review_object_ref=review_object_ref,
                retry_contract="retry_after_approval")
            context.receipt_refs.append(context.admission_receipt_ref)
        except Exception:
            return _governed_failure(
                failure_reason="pre_execution_receipt_failure",
                policy_decision=policy_decision, context=context)
    _append_event_if_available(
        sinks=sinks,
        event_type="mcp.tool.call.gated",
        config=config,
        context=context,
        detail={
            "tool_name": tool_name,
            **_event_argument_hash_fields(context.arguments_hash),
            "policy_decision": policy_decision.decision,
            "review_object_ref": review_object_ref,
            "reason": policy_decision.reason,
        },
    )

    if policy_decision.receipt_required:
        receipt_ref = _write_receipt(
            sinks=sinks,
            config=config,
            context=context,
            policy_decision=policy_decision,
            tool_name=tool_name,
        )
        if receipt_ref is None:
            return _governed_failure(
                failure_reason="receipt_write_failed",
                policy_decision=policy_decision,
                context=context,
            )
        context.receipt_refs.append(receipt_ref)

    return _governed_failure(
        failure_reason="gated_pending",
        policy_decision=policy_decision,
        context=context,
    )


def _write_receipt(
    *,
    sinks: HarnessSinks,
    config: HarnessConfig,
    context: HarnessContext,
    policy_decision: PolicyDecision,
    tool_name: str,
) -> str | None:
    if sinks.receipt is None:
        return None
    try:
        return sinks.receipt.write_receipt(
            ReceiptEnvelope(
                receipt_type="sdk_enforcement",
                boundary_type="mcp_tool_call",
                protocol_binding="mcp",
                issued_at=now_utc_iso(),
                artifact_classes_covered=_covered_artifact_classes(
                    context.result_hash
                ),
                artifact_classes_excluded=list(RAW_ARTIFACT_CLASSES_EXCLUDED),
                attestation_limits=list(policy_decision.attestation_limits),
                subject_ref=context.session_ref or context.request_ref,
                policy_ref=policy_decision.policy_ref,
                policy_hash=policy_decision.policy_hash,
                extensions={
                    "mcp": _mcp_receipt_extension(
                        tool_name=tool_name,
                        context=context,
                        policy_decision=policy_decision,
                    )
                },
                critical_extensions=["mcp"],
            )
        )
    except SinkUnavailableError:
        return None


def _covered_artifact_classes(result_hash: str | None) -> list[str]:
    classes = ["mcp_tool_call_metadata", "mcp_argument_hash"]
    if result_hash is not None:
        classes.append("mcp_result_hash")
    return classes


def _mcp_receipt_extension(
    *,
    tool_name: str,
    context: HarnessContext,
    policy_decision: PolicyDecision,
) -> dict[str, Any]:
    extension: dict[str, Any] = {
        "mcp_tool_name": tool_name,
        "mcp_arguments_hash": context.arguments_hash,
        "mcp_policy_decision_ref": (
            f"policy_decision:{policy_decision.policy_ref}:"
            f"{policy_decision.decision}"
        ),
    }
    if context.result_hash is not None:
        extension["mcp_result_hash"] = context.result_hash
    if context.review_object_ref is not None:
        extension["mcp_review_object_ref"] = context.review_object_ref
    return extension


def _call_inner(inner: Any, tool_name: str, arguments: Any, context: Any) -> Any:
    if hasattr(inner, "handle_tool_call"):
        return inner.handle_tool_call(tool_name, arguments, context=context)
    if callable(inner):
        return inner(tool_name, arguments, context=context)
    raise TypeError("inner must be callable or expose handle_tool_call")


__all__ = [
    "GovernedResult",
    "HarnessConfig",
    "HarnessContext",
    "HarnessSinks",
    "PolicyDecision",
    "ToolPolicy",
    "effective_required_sink_names",
    "wrap_handler",
]
