"""In-process ``execute_governed_call`` orchestration (Sprint A8).

Scope: ``docs/GATEWAY_SERVICE_ADAPTER_SCOPE.md`` §3 (service boundary), §6
(invocation topology, shape A/C in-process), §8 (authority/tenant
projection), §9 (receipt topology), §10 (failure matrix), work package A8.

This module composes the two *existing*, unchanged lifecycle bindings
(:mod:`dagr_mcp.fastmcp_binding`, :mod:`dagr_mcp_sdk_binding`) behind one
neutral, transport-free operation,
:func:`execute_governed_call`. It reimplements no lifecycle decision: both
bindings still defer every admission/outcome decision to
:mod:`dagr_mcp_lifecycle.core` exactly as they do standalone. This module's
own job is narrower — select the configured binding (§5, via
:func:`dagr_mcp_service.resolution.select_binding`), resolve an in-process
target through a connector, wire the binding's *existing* resolver seams so
it stamps the caller's already-trusted ``actor_ref``/``tenant_ref`` (never a
tool argument), capture the receipt identifiers the binding's own emitter
mints, and project the binding's return value or raised exception onto a
:class:`~dagr_mcp_service.contract.GovernedCallResponse`.

**No caller authority.** ``execute_governed_call`` accepts only the internal,
already-resolved :class:`~dagr_mcp_service.contract.GovernedCallRequest` —
never :class:`~dagr_mcp_service.contract.CallerGovernedCallRequest` or a raw
mapping. It performs no deserialization of caller bytes and derives no
identity from tool arguments, metadata, or selector keys; the trusted
``actor_ref``/``tenant_ref`` it projects into the selected binding come only
from the request's own already-resolved fields.

**Receipt capture without touching receipt bytes.** Neither binding exposes
emitted receipt identifiers as a return value today (both discard the
outcome id and never return the admission id past their own call boundary).
Rather than modify either binding, this module wraps the operator-configured
sink in a narrow capturing proxy (:class:`_CapturingSink`) that forwards
every ``write(envelope)`` unchanged and additionally records the envelope
locally. The signed envelope bytes the sink durably stores are identical to
what the binding would have written unmodified; this module only *also*
looks at what was written; it never edits it.

**Response classification from receipt structure, not exception identity.**
The FastMCP binding raises a single ``ToolError`` for every terminal
admission outcome (refused, deferred, and pre-execution-receipt-unavailable
alike), so a caller cannot reliably distinguish these by exception type
alone. This module instead classifies the outcome from the *captured
receipt envelopes themselves* — their count and their ``disposition``/
``outcome`` fields — which is authoritative, binding-independent, and never
depends on parsing an exception message.

**Import discipline.** Importing this module (or ``dagr_mcp_service``) never
imports ``mcp``, ``fastmcp``, or a transport library. The concrete binding
module for whichever binding a given call actually selects is imported
lazily, inside the function that drives that one call.

**Sprint A9 additions.** Two narrow, additive changes support
:mod:`dagr_mcp_service.connectors.remote` without altering any A8-tested
behavior: (1) an optional ``connector.bind_trusted_context(...)`` rebinding
step, called only when a connector defines it, that lets a connector see the
caller's already-resolved trusted actor/tenant context without changing the
frozen two-argument ``connector.resolve(target_handle, tool_name)`` seam; and
(2) :func:`_classify` now distinguishes a connector-raised plain builtin
``ConnectionError`` (``diagnostic_code="remote_unavailable"`` — no socket-level
connection was ever established) from every other admitted-call exception
(``diagnostic_code="remote_exception"``, unchanged). Neither change alters
behavior for :mod:`dagr_mcp_service.connectors.memory`, which defines no
``bind_trusted_context`` and never raises ``ConnectionError``.
"""

from __future__ import annotations

import asyncio
import inspect
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import rfc8785

from dagr_mcp.srs_receipts import (
    ReceiptContentError,
    SignedReceiptEmitter,
    SigningIdentity,
    sha256_digest,
)
from dagr_mcp_service.contract import (
    ALL_DIAGNOSTIC_CODES,
    DEFERRAL_CONTINUATION_CONTRACT,
    NEUTRAL_REFUSAL_GROUNDS,
    BusinessResult,
    CancellationFacts,
    GovernedCallRequest,
    GovernedCallResponse,
    GovernedDecision,
    ReceiptHandle,
)
from dagr_mcp_service.resolution import (
    FASTMCP_BINDING_VERSION,
    SDK_BINDING_VERSION,
    BindingResolutionRefused,
    select_binding,
)

# Mirrors both bindings' own default (``DAGRMiddlewareConfig``/
# ``SdkBindingConfig``); used only when the operator config leaves the field
# unset, so the resulting per-binding config's behavior matches what either
# binding would do standalone.
_DEFAULT_PRE_EXECUTION_RECEIPT_FAILURE: dict[str, str] = {
    "read": "fail_open",
    "write": "fail_closed",
    "destructive": "fail_closed",
}

# The binding-token spellings both the A2 (FastMCP) and A5 (SDK) masks are
# already frozen/tested to use for a neutral outcome that reaches a receipt
# (see ``dagr_mcp_lifecycle/binding_mask.py``, ``dagr_mcp_sdk_binding/mask.py``,
# and the emitter's own ``outcome in {"result_returned", "error_returned"}`` /
# ``outcome == "indeterminate"`` checks in ``dagr_mcp/srs_receipts.py``). This
# module reads them back off the captured envelope rather than re-deriving a
# neutral->binding mapping of its own.
_ADMITTED_DISPOSITION_TOKEN = "admitted"
_REFUSED_DISPOSITION_TOKEN = "refused"
_DEFERRED_DISPOSITION_TOKEN = "deferred_for_review"


@dataclass(frozen=True, slots=True, kw_only=True)
class GatewayAdapterConfig:
    """Operator/deployment configuration for :func:`execute_governed_call`.

    Everything here is operator-supplied, static, deployment-level
    configuration — never a per-call tool argument. There is deliberately no
    ``actor_resolver`` field: the trusted actor/tenant projection is always
    derived internally from the already-resolved
    :class:`~dagr_mcp_service.contract.GovernedCallRequest`, never from this
    config or from caller input.
    """

    binding_registry: Mapping[str, str]
    connector: Any
    identity: SigningIdentity
    sink: Any
    runtime_instance_id: str
    boundary_id: str
    policy_pack_id: str
    policy_pack_version: str
    tool_classes: Mapping[str, str] = field(default_factory=dict)
    policy_resolver: Any | None = None
    review_object_creator: Any | None = None
    pre_execution_receipt_failure: Mapping[str, str] = field(
        default_factory=lambda: dict(_DEFAULT_PRE_EXECUTION_RECEIPT_FAILURE)
    )
    post_execution_receipt_failure: str = "alert_and_return_result"
    emit_read_admission_before_execution: bool = True
    emergency_spool_path: Path | None = None
    parent_receipt_ref: str | None = None
    additional_attestation_limits: tuple[str, ...] = ()
    is_binding_available: Callable[[str], bool] | None = None


@dataclass(frozen=True, slots=True)
class _CapturedReceipt:
    """Narrow, immutable record of one receipt the sink actually wrote.

    ``receipt_id`` is the identifier ``inner.write(envelope)`` itself
    returned, never read back from the pre-write envelope -- the sink is
    free to mint or rewrite the identifier it durably stores under. Only the
    additional fields :func:`_classify` needs are retained; the full
    envelope is never held past the ``write`` call that produced it.
    """

    receipt_id: str
    receipt_kind: str
    disposition: str | None = None
    outcome: str | None = None
    reason_code: str | None = None
    review_object_ref: str | None = None


class _CapturingSink:
    """Forwards every write unchanged; also records what the sink wrote.

    Never alters the envelope, never intercepts ``write_trust_bundle``
    behavior, and never withholds a write from the real sink. This is a pure
    observation seam (§9), not a second receipt store. ``write_failed``
    tracks whether a write this sink attempted raised, so a caller can tell
    "the sink write failed" apart from "no write was ever attempted" -- the
    latter is not grounded evidence of a sink failure.
    """

    def __init__(self, inner: Any, captured: list[_CapturedReceipt]) -> None:
        self._inner = inner
        self._captured = captured
        self.write_failed = False

    def write(self, envelope: Mapping[str, Any]) -> str:
        try:
            receipt_id = self._inner.write(envelope)
        except Exception:
            self.write_failed = True
            raise
        self._captured.append(
            _CapturedReceipt(
                receipt_id=str(receipt_id),
                receipt_kind=envelope["receipt_kind"],
                disposition=envelope.get("disposition"),
                outcome=envelope.get("outcome"),
                reason_code=envelope.get("reason_code"),
                review_object_ref=envelope.get("review_object_ref"),
            )
        )
        return receipt_id

    def write_trust_bundle(self, *args: Any, **kwargs: Any) -> Any:
        return self._inner.write_trust_bundle(*args, **kwargs)


def _freeze_arguments(arguments: Mapping[str, Any]) -> dict[str, Any]:
    """Detach ``arguments`` into an independent, JSON-compatible snapshot.

    Serializes the caller-owned mapping to RFC 8785 canonical JSON bytes and
    decodes those bytes back into a fresh value graph, so every nested dict
    and list reachable from the return value is a brand-new object sharing
    no structure with ``arguments`` -- nothing the caller still holds a
    reference to can reach it. This is what :func:`execute_governed_call`
    calls, synchronously and before any ``await``, to build the one
    detached snapshot that is both digested and passed to whichever binding
    is selected; neither binding is ever given the original mapping back.

    Canonicalization failure (a value outside the existing JSON-compatible
    argument domain :func:`~dagr_mcp.srs_receipts.sha256_digest` itself
    already requires) raises the same
    :class:`~dagr_mcp.srs_receipts.ReceiptContentError`, so a value
    ``copy.deepcopy`` could copy but ``sha256_digest`` could never digest is
    rejected here exactly as it always was, rather than silently admitted
    through a broader copy mechanism.
    """

    try:
        canonical = rfc8785.dumps(dict(arguments))
    except Exception as exc:
        raise ReceiptContentError("value is not RFC 8785 canonicalizable") from exc
    return json.loads(canonical)


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


def _receipt_handle(record: _CapturedReceipt) -> ReceiptHandle:
    return ReceiptHandle(
        receipt_id=record.receipt_id,
        receipt_kind=record.receipt_kind,
        location_handle=None,
    )


def _refusal_diagnostic(reason_code: str | None) -> str:
    """Narrow a possibly-opaque binding reason code to the closed vocabulary.

    Mirrors the exact §7 discipline both bindings already apply when
    projecting a refusal reason code onto the neutral core: a known neutral
    refusal ground is preserved verbatim; anything else (including absent)
    narrows to ``policy_refused`` rather than being rejected or fabricated.
    """

    if reason_code in NEUTRAL_REFUSAL_GROUNDS:
        return reason_code  # type: ignore[return-value]
    return "policy_refused"


def _classify(
    request: GovernedCallRequest,
    captured: list[_CapturedReceipt],
    *,
    raw_result: Any = None,
    raised: BaseException | None = None,
) -> GovernedCallResponse:
    """Build the response from captured receipt structure, never raw content.

    Exactly one of ``raw_result``/``raised`` is meaningful, selected by
    whether the binding call returned normally or raised. The receipts
    captured along the way are the authoritative source for which response
    class applies — never the raised exception's message/type.

    Callers must only invoke this with ``raised`` set and zero ``captured``
    entries when they have already confirmed (via
    ``_CapturingSink.write_failed``) that a sink write was actually
    attempted and failed; otherwise a pre-admission failure that never
    reached a receipt write would be misreported as a sink outage (see the
    call sites in ``_execute_via_fastmcp``/``_execute_via_sdk``).
    """

    receipts = tuple(_receipt_handle(record) for record in captured)

    if raised is None:
        # The outcome record (when one was durably captured) is the
        # authoritative source for the outcome family, including
        # ``task_submitted`` — a family a raw is_error/isError inspection of
        # ``raw_result`` cannot detect. When the outcome receipt itself
        # could not be durably written (best-effort post-execution failure;
        # only the admission record is captured), fall back to inspecting
        # ``raw_result`` directly the same way both bindings' own projectors
        # do, since that is the only signal left.
        outcome_record = (
            captured[1] if len(captured) >= 2 and captured[1].receipt_kind == "outcome" else None
        )
        if outcome_record is not None and outcome_record.outcome == "task_submitted":
            return GovernedCallResponse(
                request_ref=request.request_ref,
                logical_call_id=request.request_ref,
                decision=GovernedDecision(disposition="admitted", outcome="task_submitted"),
                receipts=receipts,
            )
        if outcome_record is not None:
            is_error = outcome_record.outcome == "error_returned"
        else:
            is_error = bool(
                getattr(raw_result, "is_error", getattr(raw_result, "isError", False))
            )
        return GovernedCallResponse(
            request_ref=request.request_ref,
            logical_call_id=request.request_ref,
            decision=GovernedDecision(
                disposition="admitted", outcome="error" if is_error else "result"
            ),
            business_result=BusinessResult(
                result_kind="error" if is_error else "result",
                payload=raw_result,
            ),
            receipts=receipts,
        )

    if isinstance(raised, asyncio.CancelledError):
        # ``disposition="admitted"`` here also covers the (narrow, only
        # reachable with an operator-supplied *async* policy_resolver
        # cancelled mid-await, before either binding has resolved a
        # disposition at all) case of zero captured receipts. A8's own
        # actor-resolver closures are synchronous and never await, so this
        # module never introduces that race itself; it is recorded here
        # rather than fabricating a decision the type system has no better
        # slot for (GovernedDecision.outcome is only representable under
        # disposition="admitted").
        return GovernedCallResponse(
            request_ref=request.request_ref,
            logical_call_id=request.request_ref,
            decision=GovernedDecision(disposition="admitted", outcome="cancellation"),
            receipts=receipts,
            cancellation_facts=CancellationFacts(
                request_cancelled=True,
                execution_state_unknown=True,
                delivery_incomplete=True,
            ),
            diagnostic_code="cancelled",
        )

    if not captured:
        # Reached only for a confirmed sink-write failure (see the call
        # sites' ``write_failed`` guard): the durable admission write itself
        # raised before this module's capturing proxy could record anything.
        return GovernedCallResponse(
            request_ref=request.request_ref,
            logical_call_id=request.request_ref,
            decision=GovernedDecision(disposition="refused"),
            receipts=(),
            diagnostic_code="required_sink_unavailable",
        )

    admission = captured[0]
    disposition_token = admission.disposition

    if disposition_token == _REFUSED_DISPOSITION_TOKEN:
        return GovernedCallResponse(
            request_ref=request.request_ref,
            logical_call_id=request.request_ref,
            decision=GovernedDecision(disposition="refused"),
            receipts=receipts,
            diagnostic_code=_refusal_diagnostic(admission.reason_code),
        )

    if disposition_token == _DEFERRED_DISPOSITION_TOKEN:
        return GovernedCallResponse(
            request_ref=request.request_ref,
            logical_call_id=request.request_ref,
            decision=GovernedDecision(disposition="deferred"),
            receipts=receipts,
            review_object_ref=admission.review_object_ref,
            retry_instruction=DEFERRAL_CONTINUATION_CONTRACT,
            diagnostic_code="deferred_for_review",
        )

    if disposition_token == _ADMITTED_DISPOSITION_TOKEN:
        # Admission proceeded and the tool ran; ``raised`` is the tool body's
        # own exception (an ordinary business exception, or — rarely — a
        # best-effort outcome-receipt write failure leaving only the
        # admission receipt captured). Either way the neutral outcome family
        # is "exception" per both bindings' own frozen projection.
        #
        # A9 addition: a connector may raise a plain builtin ``ConnectionError``
        # to report that no connection could be established at all (see
        # ``dagr_mcp_service.connectors.remote._translate_transport_failure``)
        # — a strictly narrower, more accurately grounded claim than the
        # generic "an exception occurred" bucket, and the only case this
        # module can honestly distinguish as ``remote_unavailable`` rather
        # than ``remote_exception``. No other exception type changes this
        # branch's existing, A8-frozen behavior.
        diagnostic_code = (
            "remote_unavailable" if isinstance(raised, ConnectionError) else "remote_exception"
        )
        return GovernedCallResponse(
            request_ref=request.request_ref,
            logical_call_id=request.request_ref,
            decision=GovernedDecision(disposition="admitted", outcome="exception"),
            receipts=receipts,
            diagnostic_code=diagnostic_code,
        )

    raise RuntimeError(
        "execute_governed_call: captured admission receipt carries an "
        f"unrecognized disposition {disposition_token!r}; this indicates a "
        "core<->mask divergence that should already fail closed inside the "
        "selected binding before reaching this module"
    )


def _actor_resolution_kwargs(request: GovernedCallRequest) -> dict[str, Any]:
    return {
        "actor_ref": request.actor_ref.ref,
        "tenant_id": request.tenant_ref.ref if request.tenant_ref is not None else None,
    }


def _binding_config_kwargs(request: GovernedCallRequest, config: GatewayAdapterConfig) -> dict[str, Any]:
    return {
        "runtime_instance_id": config.runtime_instance_id,
        "boundary_id": config.boundary_id,
        "policy_pack_id": config.policy_pack_id,
        "policy_pack_version": config.policy_pack_version,
        "tool_classes": config.tool_classes,
        "policy_resolver": config.policy_resolver,
        "review_object_creator": config.review_object_creator,
        "pre_execution_receipt_failure": config.pre_execution_receipt_failure,
        "post_execution_receipt_failure": config.post_execution_receipt_failure,
        "emit_read_admission_before_execution": config.emit_read_admission_before_execution,
        "emergency_spool_path": config.emergency_spool_path,
        "parent_receipt_ref": (
            request.parent_receipt_ref
            if request.parent_receipt_ref is not None
            else config.parent_receipt_ref
        ),
        "logical_call_id_override": request.request_ref,
        "subject_ref_override": request.session_ref,
        "additional_attestation_limits": config.additional_attestation_limits,
    }


async def _execute_via_fastmcp(
    request: GovernedCallRequest,
    arguments: Mapping[str, Any],
    handler: Callable[[Mapping[str, Any]], Any],
    config: GatewayAdapterConfig,
) -> GovernedCallResponse:
    from fastmcp.server.middleware import MiddlewareContext
    from mcp.types import CallToolRequestParams

    from dagr_mcp.fastmcp_binding import ActorResolution, DAGRMiddleware, DAGRMiddlewareConfig

    captured: list[_CapturedReceipt] = []
    capturing_sink = _CapturingSink(config.sink, captured)
    emitter = SignedReceiptEmitter(identity=config.identity, sink=capturing_sink)

    def _actor_resolver(_context: Any, _snapshot: Any) -> ActorResolution:
        return ActorResolution(**_actor_resolution_kwargs(request))

    middleware = DAGRMiddleware(
        emitter=emitter,
        config=DAGRMiddlewareConfig(
            actor_resolver=_actor_resolver,
            **_binding_config_kwargs(request, config),
        ),
    )

    context: MiddlewareContext[Any] = MiddlewareContext(
        message=CallToolRequestParams(name=request.tool_name, arguments=dict(arguments)),
        method="tools/call",
    )

    async def call_next(_context: MiddlewareContext[Any]) -> Any:
        return await _maybe_await(handler(dict(arguments)))

    try:
        raw_result = await middleware.on_call_tool(context, call_next)
    except asyncio.CancelledError as exc:
        return _classify(request, captured, raised=exc)
    except Exception as exc:  # noqa: BLE001 - classified structurally, content never leaked.
        if not captured and not capturing_sink.write_failed:
            # No receipt write was ever attempted -- this is a pre-admission
            # operator/internal failure (e.g. a raising ``policy_resolver``),
            # not grounded evidence of a sink outage. Propagate it rather
            # than fabricate a ``required_sink_unavailable`` diagnostic.
            raise
        return _classify(request, captured, raised=exc)

    return _classify(request, captured, raw_result=raw_result)


async def _execute_via_sdk(
    request: GovernedCallRequest,
    arguments: Mapping[str, Any],
    handler: Callable[[Mapping[str, Any]], Any],
    config: GatewayAdapterConfig,
) -> GovernedCallResponse:
    from dagr_mcp_sdk_binding.adapter import (
        ActorResolution,
        SdkBindingConfig,
        SdkLifecycleAdapter,
        TaskSubmissionUnsupported,
    )

    captured: list[_CapturedReceipt] = []
    capturing_sink = _CapturingSink(config.sink, captured)
    emitter = SignedReceiptEmitter(identity=config.identity, sink=capturing_sink)

    def _actor_resolver(_request_context: Any, _snapshot: Any) -> ActorResolution:
        return ActorResolution(**_actor_resolution_kwargs(request))

    adapter = SdkLifecycleAdapter(
        emitter=emitter,
        config=SdkBindingConfig(
            actor_resolver=_actor_resolver,
            **_binding_config_kwargs(request, config),
        ),
    )

    async def delegate(call_arguments: Mapping[str, Any]) -> Any:
        return await _maybe_await(handler(dict(call_arguments)))

    try:
        raw_result = await adapter.governed_call(
            request.tool_name, dict(arguments), delegate, request_context=None
        )
    except asyncio.CancelledError as exc:
        return _classify(request, captured, raised=exc)
    except TaskSubmissionUnsupported:
        # An explicit binding-capability difference (§5.1): this binding
        # cannot carry a submitted-task result over the bound tools/call
        # seam. Admission already proceeded (captured has the admission
        # receipt); there is no resolvable neutral outcome family for it, so
        # ``outcome`` stays unset rather than a fabricated family.
        return GovernedCallResponse(
            request_ref=request.request_ref,
            logical_call_id=request.request_ref,
            decision=GovernedDecision(disposition="admitted"),
            receipts=tuple(_receipt_handle(record) for record in captured),
            diagnostic_code="unsupported_lifecycle_state",
        )
    except Exception as exc:  # noqa: BLE001 - classified structurally, content never leaked.
        if not captured and not capturing_sink.write_failed:
            # No receipt write was ever attempted -- this is a pre-admission
            # operator/internal failure (e.g. a raising ``policy_resolver``),
            # not grounded evidence of a sink outage. Propagate it rather
            # than fabricate a ``required_sink_unavailable`` diagnostic.
            raise
        return _classify(request, captured, raised=exc)

    return _classify(request, captured, raw_result=raw_result)


async def execute_governed_call(
    request: GovernedCallRequest,
    *,
    arguments: Mapping[str, Any],
    config: GatewayAdapterConfig,
) -> GovernedCallResponse:
    """Run one governed MCP tool call in-process through a selected binding.

    ``request`` must already be the internal, service-resolved
    :class:`~dagr_mcp_service.contract.GovernedCallRequest` — never a caller
    mapping or :class:`~dagr_mcp_service.contract.CallerGovernedCallRequest`.
    ``arguments`` is the transient, keyword-only raw-argument mapping this
    one call needs to actually invoke the resolved in-process target.
    Before anything else -- synchronously, before any ``await`` in this
    function or in either binding -- it is detached into one independent
    snapshot via :func:`_freeze_arguments`; that same snapshot is what gets
    digested, what gets verified against ``request.argument_digest``, and
    the *only* argument mapping either binding path ever receives. Neither
    binding rereads ``arguments`` itself, so a caller mutating its own
    mapping after this function returns control (e.g. during an awaited
    policy resolver) can never change what is actually digested, executed,
    or receipted. The snapshot is held only for the duration of this call —
    never stored on the request, a receipt, or the response.

    Order of operations, each fail-closed with zero tool executions on
    refusal: (1) detach ``arguments`` into one snapshot and verify it
    matches ``request.argument_digest``; (2) resolve the configured binding
    (§5); (3) resolve the in-process target via ``config.connector``; (4)
    drive exactly one governed call, through the selected binding on the
    detached snapshot, which alone decides admission/outcome via the
    neutral core.
    """

    if not isinstance(request, GovernedCallRequest):
        raise TypeError(
            f"request must be a GovernedCallRequest, got {type(request).__name__}"
        )

    logical_call_id = request.request_ref

    snapshot_arguments = _freeze_arguments(arguments)

    computed_digest = sha256_digest(snapshot_arguments)
    if computed_digest != request.argument_digest:
        return GovernedCallResponse(
            request_ref=request.request_ref,
            logical_call_id=logical_call_id,
            decision=GovernedDecision(disposition="refused"),
            diagnostic_code="malformed_request",
        )

    if config.is_binding_available is not None:
        resolved_binding = select_binding(
            config.binding_registry,
            request.binding_selector,
            is_binding_available=config.is_binding_available,
        )
    else:
        resolved_binding = select_binding(config.binding_registry, request.binding_selector)

    if isinstance(resolved_binding, BindingResolutionRefused):
        assert resolved_binding.reason in ALL_DIAGNOSTIC_CODES
        return GovernedCallResponse(
            request_ref=request.request_ref,
            logical_call_id=logical_call_id,
            decision=GovernedDecision(disposition="refused"),
            diagnostic_code=resolved_binding.reason,
        )

    resolved_target = config.connector.resolve(
        request.target_server_ref.handle, request.tool_name
    )
    if not callable(resolved_target):
        assert resolved_target.reason in ALL_DIAGNOSTIC_CODES
        return GovernedCallResponse(
            request_ref=request.request_ref,
            logical_call_id=logical_call_id,
            decision=GovernedDecision(disposition="refused"),
            diagnostic_code=resolved_target.reason,
        )

    # A9 addition: an *optional* hook a connector may define to receive the
    # caller's already-resolved trusted actor/tenant context (e.g. a remote
    # connector's credential provider seam). ``resolve(target_handle,
    # tool_name)`` itself is the frozen A8 seam and stays exactly two
    # positional arguments — it structurally cannot carry per-call trust —
    # so this is an additive rebinding step, not a signature change.
    # ``dagr_mcp_service.connectors.memory.InMemoryToolConnector`` defines no
    # such method, so ``getattr(..., None)`` is ``None`` and this is a no-op
    # for every existing A8 deployment/test.
    bind_trusted_context = getattr(config.connector, "bind_trusted_context", None)
    if bind_trusted_context is not None:
        resolved_target = bind_trusted_context(
            resolved_target,
            target_handle=request.target_server_ref.handle,
            tool_name=request.tool_name,
            actor_ref=request.actor_ref.ref,
            tenant_ref=request.tenant_ref.ref if request.tenant_ref is not None else None,
            parent_receipt_ref=request.parent_receipt_ref,
            request_ref=request.request_ref,
        )

    if resolved_binding.binding_version == FASTMCP_BINDING_VERSION:
        return await _execute_via_fastmcp(request, snapshot_arguments, resolved_target, config)
    if resolved_binding.binding_version == SDK_BINDING_VERSION:
        return await _execute_via_sdk(request, snapshot_arguments, resolved_target, config)

    raise RuntimeError(  # pragma: no cover - select_binding only returns supported versions.
        f"select_binding returned an unsupported binding_version: "
        f"{resolved_binding.binding_version!r}"
    )


__all__ = ["GatewayAdapterConfig", "execute_governed_call"]
