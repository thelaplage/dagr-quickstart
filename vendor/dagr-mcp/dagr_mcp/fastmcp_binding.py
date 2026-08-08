"""FastMCP middleware binding for signed DAGR/SRS receipts."""

from __future__ import annotations

import asyncio
import copy
import inspect
import json
import os
import tempfile
import uuid
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, NoReturn, Protocol, TypeAlias

import rfc8785

from fastmcp.exceptions import ToolError
from fastmcp.server.dependencies import get_access_token
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools.base import ToolResult

try:
    from mcp.types import CreateTaskResult

    CREATE_TASK_RESULT_IMPORT_PATH = "mcp.types.CreateTaskResult"
except ImportError:  # pragma: no cover - exercised by the FastMCP main canary.
    from mcp_types import CreateTaskResult  # type: ignore[no-redef]

    CREATE_TASK_RESULT_IMPORT_PATH = "mcp_types.CreateTaskResult"

from dagr_mcp.sdk_spine import ReviewObject, now_utc_iso
from dagr_mcp.srs_receipts import (
    ReceiptContentError,
    ReceiptContext,
    ReceiptWriteError,
    SignedReceiptEmitter,
    fastmcp_tool_result_digest,
    sha256_digest,
)

# Sprint A4 — the live FastMCP path binds onto the binding-neutral lifecycle
# core. The core (:mod:`dagr_mcp_lifecycle.core`) is authoritative for the
# lifecycle *decisions* — admission disposition resolution, whether execution
# proceeds, whether an admission record is durably observed before execution,
# the outcome record family, the result-digest / governance-fact / cancellation
# posture, and the receipt cardinality. This module is the FastMCP adapter: it
# converts binding inputs into neutral core models, invokes the core, and
# projects the resulting plan back into the existing emitter calls. The core
# imports nothing from this package or FastMCP; the neutral→binding token
# projection is the A2 mask (:mod:`dagr_mcp_lifecycle.binding_mask`), imported
# lazily in the projection helpers below to avoid a mask↔binding import cycle.
from dagr_mcp_lifecycle.contract import NEUTRAL_REFUSAL_GROUNDS
from dagr_mcp_lifecycle.core import plan_admission, plan_outcome_strict
from dagr_mcp_lifecycle.models import (
    AdmissionPlan,
    AdmissionRequest,
    ExecutionObservation,
    OutcomeRecordIntent,
)

ToolClass: TypeAlias = Literal["read", "write", "destructive"]
Disposition: TypeAlias = Literal["admitted", "refused", "deferred_for_review"]
ReceiptFailureMode: TypeAlias = Literal["fail_closed", "fail_open"]
PostExecutionReceiptFailureMode: TypeAlias = Literal["alert_and_return_result"]

BINDING_VERSION = "fastmcp.middleware.v0.1"
DEFAULT_ANONYMOUS_ACTOR_REF = "actor:anonymous_or_local"
DEFAULT_BOUNDARY_LIMIT = (
    "The middleware is installed once at the institutional trust boundary; "
    "receipts attest only to observations at that boundary."
)
PROXY_BOUNDARY_LIMIT = (
    "The receipt attests only to what crossed and returned through the proxy boundary."
)


@dataclass(frozen=True, slots=True)
class RequestSnapshot:
    """Hash-only request facts captured before policy evaluation."""

    tool_name: str
    arguments_digest: str
    logical_call_id: str
    subject_ref: str
    # How ``subject_ref`` was obtained, from the closed v0.2.1 vocabulary. It is
    # ``None`` only for a snapshot built outside :meth:`_snapshot_request`, which
    # declares nothing rather than guessing a class on the caller's behalf.
    subject_ref_origin: str | None = None
    session_ref: str | None = None
    request_ref: str | None = None
    meta_digest: str | None = None


@dataclass(frozen=True, slots=True)
class ActorResolution:
    """Actor identity projected into receipt-safe scoped references."""

    actor_ref: str = DEFAULT_ANONYMOUS_ACTOR_REF
    tenant_id: str | None = None
    workspace_id: str | None = None


@dataclass(frozen=True, slots=True)
class BindingPolicy:
    """Admission disposition and tool class resolved for a tool call."""

    disposition: Disposition = "admitted"
    tool_class: ToolClass = "read"
    reason_code: str | None = None
    parent_receipt_ref: str | None = None
    additional_attestation_limits: tuple[str, ...] = ()


class ActorResolver(Protocol):
    def __call__(
        self,
        context: MiddlewareContext[Any],
        snapshot: RequestSnapshot,
    ) -> ActorResolution | Awaitable[ActorResolution]:
        ...


class PolicyResolver(Protocol):
    def __call__(
        self,
        snapshot: RequestSnapshot,
        actor: ActorResolution,
    ) -> BindingPolicy | Awaitable[BindingPolicy]:
        ...


OperatorAdmissionDisposition: TypeAlias = Literal["admitted", "refused"]


@dataclass(frozen=True, slots=True)
class OperatorAdmissionDecision:
    """Neutral admitted/refused decision, first tranche only (Gate A).

    This is deliberately narrower than :class:`BindingPolicy`: no tool class,
    no parent-receipt linkage, no attestation limits, and no
    ``deferred_for_review`` — a caller translates its own product decision
    into this neutral shape before it reaches DAGR, which never learns
    product semantics. ``refusal_ground`` is fixed to the single neutral
    refusal ground this tranche authorizes.
    """

    disposition: OperatorAdmissionDisposition
    refusal_ground: Literal["policy_refused"] | None = None


class OperatorAdmissionResolver(Protocol):
    """Opt-in seam for a product-neutral admitted/refused decision.

    Sibling to :class:`PolicyResolver` on :class:`DAGRMiddlewareConfig`. Where
    ``policy_resolver`` returns a full binding-vocabulary :class:`BindingPolicy`,
    this hook lets a caller supply only the neutral disposition, without
    needing to speak ``tool_class`` / attestation-limit / receipt-linkage
    vocabulary. Consulted only when ``policy_resolver`` is unset; unconfigured,
    it changes nothing.
    """

    def __call__(
        self,
        snapshot: RequestSnapshot,
        actor: ActorResolution,
    ) -> OperatorAdmissionDecision | Awaitable[OperatorAdmissionDecision]:
        ...


ReviewObjectCreator: TypeAlias = Callable[
    [RequestSnapshot, ActorResolution, BindingPolicy],
    str | Awaitable[str],
]


@dataclass(slots=True)
class DAGRMiddlewareConfig:
    """Configuration for the FastMCP binding."""

    runtime_instance_id: str
    boundary_id: str
    policy_pack_id: str
    policy_pack_version: str
    tool_classes: Mapping[str, ToolClass] = field(default_factory=dict)
    actor_resolver: ActorResolver | None = None
    policy_resolver: PolicyResolver | None = None
    operator_admission_resolver: OperatorAdmissionResolver | None = None
    # Opt-in deterministic timeout (seconds) for an *async* operator-admission
    # resolver. ``None`` (the default) applies no timeout and preserves prior
    # behavior byte-for-byte. When set, an awaitable resolver that exceeds it
    # fails closed to ``refused / policy_refused`` before delegate dispatch,
    # exactly like any other resolver-infrastructure failure. A synchronous
    # resolver returns before the timeout can apply and is unaffected.
    operator_admission_resolver_timeout_s: float | None = None
    # Opt-in "resolver required" governance selector. A tool named here, or a
    # tool whose resolved tool class is named here, requires the operator-
    # admission resolver to be configured; if it is *required but absent* (no
    # ``operator_admission_resolver`` set) the call fails closed to
    # ``refused / policy_refused`` before delegate dispatch. Empty (the default)
    # declares nothing required and preserves prior behavior byte-for-byte.
    operator_admission_required_tools: frozenset[str] = field(
        default_factory=frozenset
    )
    operator_admission_required_tool_classes: frozenset[ToolClass] = field(
        default_factory=frozenset
    )
    review_object_creator: ReviewObjectCreator | Any | None = None
    pre_execution_receipt_failure: Mapping[ToolClass, ReceiptFailureMode] = field(
        default_factory=lambda: {
            "read": "fail_open",
            "write": "fail_closed",
            "destructive": "fail_closed",
        }
    )
    post_execution_receipt_failure: PostExecutionReceiptFailureMode = (
        "alert_and_return_result"
    )
    emit_read_admission_before_execution: bool = True
    emergency_spool_path: Path | None = None
    parent_receipt_ref: str | None = None
    logical_call_id_override: str | None = None
    subject_ref_override: str | None = None
    result_projection_observer: Callable[[Mapping[str, Any]], None] | None = None
    additional_attestation_limits: tuple[str, ...] = (DEFAULT_BOUNDARY_LIMIT,)


# --------------------------------------------------------------------------- #
# Neutral lifecycle adapter (Sprint A4)                                        #
# --------------------------------------------------------------------------- #
# The core resolves the lifecycle in neutral tokens; these helpers are the thin
# projection back onto the FastMCP binding vocabulary. The neutral→binding token
# tables are owned by the A2 mask, which remains the single projection authority
# and is verified against the live binding. The mask is imported lazily so it can
# keep importing this module at load time without a cycle.

# The neutral disposition each binding disposition token maps *to* on the way
# into the core. This is the inverse of the mask's ``project_disposition`` and is
# the one place the adapter reads the binding disposition token.
_NEUTRAL_DISPOSITION_BY_BINDING: dict[Disposition, str] = {
    "admitted": "admitted",
    "refused": "refused",
    "deferred_for_review": "deferred",
}


def _to_neutral_disposition(binding_disposition: Disposition) -> str:
    return _NEUTRAL_DISPOSITION_BY_BINDING[binding_disposition]


def _project_binding_disposition(neutral_disposition: str) -> Disposition:
    """Project a neutral disposition onto the binding admission token (A2 mask)."""

    from dagr_mcp_lifecycle.binding_mask import project_disposition

    return project_disposition(neutral_disposition)  # type: ignore[return-value]


def _project_binding_outcome(neutral_outcome: str) -> str:
    """Project a neutral outcome record family onto the emitter token (A2 mask)."""

    from dagr_mcp_lifecycle.binding_mask import project_outcome

    token = project_outcome(neutral_outcome).binding_token
    if token is None:  # pragma: no cover - plan_outcome_strict excludes unsupported.
        raise ToolError(f"neutral outcome {neutral_outcome!r} carries no binding token")
    return token


def _project_binding_cancellation_fact(neutral_fact: str) -> str:
    """Project a neutral cancellation fact onto its binding field name (A2 mask)."""

    from dagr_mcp_lifecycle.binding_mask import project_cancellation_fact

    return project_cancellation_fact(neutral_fact)


class DAGRMiddleware(Middleware):
    """FastMCP ``tools/call`` middleware that emits signed admission receipts."""

    def __init__(self, *, emitter: SignedReceiptEmitter, config: DAGRMiddlewareConfig):
        self.emitter = emitter
        self.config = config
        self.local_telemetry: list[dict[str, Any]] = []

    async def on_call_tool(
        self,
        context: MiddlewareContext[Any],
        call_next: CallNext[Any, ToolResult],
    ) -> ToolResult:
        snapshot = self._snapshot_request(context)
        actor = await self._resolve_actor(context, snapshot)
        policy = await self._resolve_policy(snapshot, actor)
        receipt_context = self._receipt_context(snapshot, actor, policy)

        neutral_disposition = _to_neutral_disposition(policy.disposition)

        # A deferral must durably create its review object *before* the neutral
        # core can resolve the disposition: a review object that fails to create
        # resolves — in the core — to a refusal on review_object_creation_failed
        # (never onto required_sink_unavailable; §17 residual is preserved). The
        # review object is an adapter side effect, so it is minted here.
        review_object_ref: str | None = None
        review_object_created: bool | None = None
        if neutral_disposition == "deferred":
            try:
                review_object_ref = await self._create_review_object(
                    snapshot, actor, policy
                )
                review_object_created = True
            except Exception as exc:  # noqa: BLE001 - review creation failure is terminal.
                self._record_review_failure(receipt_context, snapshot, exc)
                review_object_created = False

        # The core owns the admission decision: disposition resolution, whether
        # execution proceeds, and whether an admission record is durably observed
        # before execution.
        admission_plan = plan_admission(
            self._neutral_admission_request(
                policy, neutral_disposition, review_object_created
            )
        )

        if not admission_plan.execution_proceeds:
            # Refused or deferred: a single terminal admission record, then raise.
            self._project_terminal_admission(
                admission_plan, receipt_context, snapshot, policy, review_object_ref
            )

        admission_receipt_ref: str | None = None
        if admission_plan.admission_recorded:
            try:
                admission_receipt_ref = self._emit_admission(
                    receipt_context,
                    snapshot,
                    policy,
                    disposition="admitted",
                )
            except Exception as exc:  # noqa: BLE001 - fail policy classifies it.
                self._record_receipt_failure(
                    receipt_context,
                    snapshot,
                    attempted_receipt_kind="admission",
                    failure=exc,
                )
                if self._pre_execution_failure_mode(policy.tool_class) == "fail_closed":
                    raise ToolError(
                        "Admission receipt could not be durably accepted"
                    ) from None

        try:
            result = await call_next(context)
        except asyncio.CancelledError:
            # Neutral outcome: cancellation. ``plan_outcome_strict`` (invoked in
            # ``_project_core_outcome``) is the runtime authority for the outcome
            # family, the absent result digest, and the three cancellation
            # governance facts. The frozen A1 binding literals passed below —
            # ``outcome="indeterminate"`` and the three governance Booleans, pinned
            # by source inspection (test_freeze_binding_maps_cancellation_to_...) —
            # are a *checked projection invariant*, not a second decision: the core
            # plan is verified to project to exactly these and fails closed on any
            # mismatch before a receipt is emitted.
            if admission_receipt_ref is not None:
                self._project_core_outcome(
                    admission_plan,
                    ExecutionObservation("cancellation"),
                    receipt_context,
                    snapshot,
                    admission_receipt_ref,
                    frozen_outcome="indeterminate",
                    frozen_binding_owned_fields={
                        "request_cancelled": True,
                        "execution_state_unknown": True,
                        "delivery_incomplete": True,
                    },
                )
            raise
        except Exception as exc:
            # Neutral outcome: exception. The adapter inspects the raised object,
            # derives its adapter-owned exception_class, and identifies a raised
            # TimeoutError — routing it through the core's timeout→exception
            # subsumption (§14) while an ordinary exception is classified directly.
            # ``plan_outcome_strict`` is the runtime authority for the outcome
            # family and the absent result digest; the frozen A1 literals
            # ``outcome="exception"`` / ``exception_class=type(exc).__name__`` are a
            # checked projection invariant, verified against the core plan and
            # failing closed before any receipt is emitted.
            if admission_receipt_ref is not None:
                observation = (
                    ExecutionObservation("timeout")
                    if isinstance(exc, TimeoutError)
                    else ExecutionObservation(
                        "exception", exception_class=type(exc).__name__
                    )
                )
                self._project_core_outcome(
                    admission_plan,
                    observation,
                    receipt_context,
                    snapshot,
                    admission_receipt_ref,
                    frozen_outcome="exception",
                    exception_class=type(exc).__name__,
                )
            raise

        if admission_receipt_ref is None:
            return result

        if isinstance(result, CreateTaskResult):
            self._emit_planned_outcome(
                admission_plan,
                receipt_context,
                snapshot,
                admission_receipt_ref,
                result,
                ExecutionObservation("task_submitted"),
            )
            return result

        try:
            projection = project_fastmcp_tool_result(result)
            if self.config.result_projection_observer is not None:
                self.config.result_projection_observer(copy.deepcopy(projection))
            result_digest = fastmcp_tool_result_digest(
                content=projection["content"],
                structured_content=projection["structuredContent"],
                meta=projection["_meta"],
                is_error=projection["isError"],
            )
            observation = ExecutionObservation(
                "error" if projection["isError"] else "result"
            )
        except Exception as exc:  # noqa: BLE001 - post-execution failure policy applies.
            self._record_receipt_failure(
                receipt_context,
                snapshot,
                attempted_receipt_kind="outcome",
                attempted_outcome="result_returned",
                admission_receipt_ref=admission_receipt_ref,
                failure=exc,
            )
            return result

        self._emit_planned_outcome(
            admission_plan,
            receipt_context,
            snapshot,
            admission_receipt_ref,
            result,
            observation,
            result_digest=result_digest,
        )
        return result

    def _snapshot_request(self, context: MiddlewareContext[Any]) -> RequestSnapshot:
        message = context.message
        tool_name = str(getattr(message, "name", ""))
        arguments = getattr(message, "arguments", None)
        if arguments is None:
            arguments = {}
        meta = _get_meta(message)

        request_id = _context_attr(context.fastmcp_context, "request_id")
        session_id = _context_attr(context.fastmcp_context, "session_id")
        request_ref = _scoped_hash_ref("request", request_id) if request_id else None
        session_ref = _scoped_hash_ref("session", session_id) if session_id else None
        logical_call_id = (
            self.config.logical_call_id_override
            or request_ref
            or f"call:{uuid.uuid4()}"
        )
        # Each branch below both obtains the subject reference and declares how it
        # was obtained. The last two branches build the same subject string but
        # are not the same decision: one derives it from a correlation the
        # operator supplied, the other from a call id this binding minted.
        if self.config.subject_ref_override:
            subject_ref = self.config.subject_ref_override
            subject_ref_origin = "supplied_subject"
        elif session_ref:
            subject_ref = session_ref
            subject_ref_origin = "derived_from_session"
        elif request_ref:
            subject_ref = request_ref
            subject_ref_origin = "derived_from_request"
        elif self.config.logical_call_id_override:
            subject_ref = f"tool-call:{logical_call_id}"
            subject_ref_origin = "derived_from_supplied_correlation"
        else:
            subject_ref = f"tool-call:{logical_call_id}"
            subject_ref_origin = "binding_minted"

        return RequestSnapshot(
            tool_name=tool_name,
            arguments_digest=sha256_digest(arguments),
            logical_call_id=logical_call_id,
            subject_ref=subject_ref,
            subject_ref_origin=subject_ref_origin,
            session_ref=session_ref,
            request_ref=request_ref,
            meta_digest=sha256_digest(meta) if meta is not None else None,
        )

    async def _resolve_actor(
        self,
        context: MiddlewareContext[Any],
        snapshot: RequestSnapshot,
    ) -> ActorResolution:
        if self.config.actor_resolver is not None:
            resolved = self.config.actor_resolver(context, snapshot)
            if inspect.isawaitable(resolved):
                resolved = await resolved
            return resolved
        return default_actor_resolution()

    async def _resolve_policy(
        self,
        snapshot: RequestSnapshot,
        actor: ActorResolution,
    ) -> BindingPolicy:
        if self.config.policy_resolver is not None:
            # ``policy_resolver`` precedence is preserved: when it is configured
            # the operator-admission seam (and its required-selector gate) is not
            # consulted, so the two resolvers are never silently both active.
            resolved = self.config.policy_resolver(snapshot, actor)
            if inspect.isawaitable(resolved):
                resolved = await resolved
            return resolved
        if self.config.operator_admission_resolver is not None:
            return await self._resolve_operator_admission(snapshot, actor)
        tool_class = self.config.tool_classes.get(snapshot.tool_name, "read")
        if self._operator_admission_required(snapshot.tool_name, tool_class):
            # Required governance selector: the operator-admission resolver is
            # declared required for this tool/class but is absent. Fail closed to
            # a single terminal refusal before any delegate dispatch, exactly like
            # a resolver-infrastructure failure — the seam mints no new authority.
            return BindingPolicy(
                disposition="refused",
                tool_class=tool_class,
                reason_code="policy_refused",
            )
        return BindingPolicy(disposition="admitted", tool_class=tool_class)

    def _operator_admission_required(
        self, tool_name: str, tool_class: ToolClass
    ) -> bool:
        """Whether the operator-admission resolver is *required* for this call.

        Opt-in only: with both selector sets empty (the default) this always
        returns ``False``, so an unconfigured binding is byte-identical to the
        prior default-admit behavior and unrelated tools/classes are unaffected.
        """

        return (
            tool_name in self.config.operator_admission_required_tools
            or tool_class in self.config.operator_admission_required_tool_classes
        )

    async def _resolve_operator_admission(
        self,
        snapshot: RequestSnapshot,
        actor: ActorResolution,
    ) -> BindingPolicy:
        """Project the neutral operator-admission decision onto a BindingPolicy.

        Every resolver-infrastructure failure — a raised exception, a timeout,
        or a result outside the closed neutral vocabulary — fails closed to a
        single neutral refusal (``refused / policy_refused``) before any delegate
        dispatch, and never fails open to execution. The seam mints no new
        authority: it may only *admit* or *refuse-on-policy_refused*; it never
        constructs receipts, selects keys/issuers, alters subject references or
        arguments, calls the delegate, or changes lifecycle/cardinality.
        """

        tool_class = self.config.tool_classes.get(snapshot.tool_name, "read")
        refused = BindingPolicy(
            disposition="refused",
            tool_class=tool_class,
            reason_code="policy_refused",
        )
        resolver = self.config.operator_admission_resolver
        assert resolver is not None
        timeout = self.config.operator_admission_resolver_timeout_s
        try:
            decision = resolver(snapshot, actor)
            if inspect.isawaitable(decision):
                if timeout is not None:
                    # ``asyncio.wait_for`` raises ``TimeoutError`` (an
                    # ``Exception``) on expiry after cancelling the awaitable, so
                    # a timeout fails closed through the same branch as any other
                    # resolver-infrastructure failure.
                    decision = await asyncio.wait_for(decision, timeout)
                else:
                    decision = await decision
        except Exception:  # noqa: BLE001 - resolver failure/timeout must fail closed.
            return refused
        return self._project_operator_admission_decision(decision, tool_class, refused)

    @staticmethod
    def _project_operator_admission_decision(
        decision: Any,
        tool_class: ToolClass,
        refused: BindingPolicy,
    ) -> BindingPolicy:
        """Closed-vocabulary projection of a resolver result onto a BindingPolicy.

        Only an exact :class:`OperatorAdmissionDecision` from the closed neutral
        vocabulary may admit. A wrong result type, an unsupported disposition
        string, a contradictory admitted-with-ground result, or a refusal ground
        outside the single authorized ``policy_refused`` all fail closed to the
        pre-built ``refused / policy_refused`` policy. Nothing here mints new
        authority — an admit yields a plain admitted policy and every other shape
        yields the same single neutral refusal.
        """

        # Wrong result type (plain object, dict, ``None``, duck-typed lookalike):
        # fail closed rather than trusting an unvalidated ``.disposition``.
        if not isinstance(decision, OperatorAdmissionDecision):
            return refused
        if decision.disposition == "admitted":
            # A contradictory admitted result that also carries a refusal ground
            # is malformed; fail closed rather than admit.
            if decision.refusal_ground is not None:
                return refused
            return BindingPolicy(disposition="admitted", tool_class=tool_class)
        # ``refused`` and every other shape resolve to the same single neutral
        # refusal. This closes the ground vocabulary too: the sole authorized
        # ground is ``policy_refused`` (``None`` defaults to it), and an invalid
        # ground is never propagated — it fails closed to ``policy_refused`` — so
        # the resolver cannot mint an out-of-vocabulary refusal ground. An
        # unsupported disposition string falls through here and fails closed.
        return refused

    def _receipt_context(
        self,
        snapshot: RequestSnapshot,
        actor: ActorResolution,
        policy: BindingPolicy,
    ) -> ReceiptContext:
        return ReceiptContext(
            runtime_instance_id=self.config.runtime_instance_id,
            boundary_id=self.config.boundary_id,
            policy_pack_id=self.config.policy_pack_id,
            policy_pack_version=self.config.policy_pack_version,
            subject_ref=snapshot.subject_ref,
            subject_ref_origin=snapshot.subject_ref_origin,
            logical_call_id=snapshot.logical_call_id,
            actor_ref=actor.actor_ref,
            tenant_id=actor.tenant_id,
            workspace_id=actor.workspace_id,
            binding_version=BINDING_VERSION,
            parent_receipt_ref=(
                policy.parent_receipt_ref
                if policy.parent_receipt_ref is not None
                else self.config.parent_receipt_ref
            ),
        )

    def _neutral_admission_request(
        self,
        policy: BindingPolicy,
        neutral_disposition: str,
        review_object_created: bool | None,
    ) -> AdmissionRequest:
        """Convert the resolved binding policy into the neutral core request.

        The core is authoritative for the refusal *decision*; the neutral refusal
        ground it receives is drawn from the closed neutral vocabulary
        (:func:`_neutral_refusal_ground`). A known ground — including
        ``required_sink_unavailable`` — is passed through verbatim and never
        repaired (§17 residual). An *opaque* binding reason code outside that
        vocabulary is not silently narrowed away: the neutral ground resolves to
        ``policy_refused`` (a valid refusal, so the core still decides the
        disposition, cardinality, and that execution does not proceed) while the
        opaque code itself is preserved verbatim on the emitted receipt by
        :meth:`_project_terminal_admission` (§7). ``review_object_created`` is set
        only for a deferral and is what lets the core resolve a failed review
        object to a refusal on ``review_object_creation_failed``.
        """

        return AdmissionRequest(
            disposition=neutral_disposition,  # type: ignore[arg-type]
            tool_class=policy.tool_class,
            refusal_ground=(
                self._neutral_refusal_ground(policy)  # type: ignore[arg-type]
                if neutral_disposition == "refused"
                else None
            ),
            review_object_created=review_object_created,
            emit_read_admission_before_execution=(
                self.config.emit_read_admission_before_execution
            ),
            has_parent_boundary=(
                policy.parent_receipt_ref is not None
                or self.config.parent_receipt_ref is not None
            ),
        )

    @staticmethod
    def _binding_refusal_reason_code(policy: BindingPolicy) -> str:
        """The verbatim binding refusal reason code (adapter-owned projection, §7).

        The core is authoritative for the refusal *decision*; the reason code
        stamped on the receipt is an adapter-owned projection detail. A binding
        policy may carry an opaque reason code outside the core's closed neutral
        :data:`NEUTRAL_REFUSAL_GROUNDS` vocabulary; it is preserved here verbatim
        (defaulting to ``policy_refused``) exactly as the pre-core binding emitted
        it, rather than narrowed to a neutral ground.
        """

        return policy.reason_code or "policy_refused"

    @staticmethod
    def _neutral_refusal_ground(policy: BindingPolicy) -> str:
        """Map the binding refusal reason code onto a closed neutral ground (§7).

        A known neutral ground is passed through so the core carries it verbatim;
        an opaque code (or ``None``) resolves to ``policy_refused`` — still a valid
        refusal, so the core stays authoritative for the decision — while the
        opaque code itself is emitted verbatim by
        :meth:`_binding_refusal_reason_code`.
        """

        code = policy.reason_code or "policy_refused"
        if code in NEUTRAL_REFUSAL_GROUNDS:
            return code
        return "policy_refused"

    def _project_terminal_admission(
        self,
        admission_plan: AdmissionPlan,
        receipt_context: ReceiptContext,
        snapshot: RequestSnapshot,
        policy: BindingPolicy,
        review_object_ref: str | None,
    ) -> NoReturn:
        """Project a non-proceeding admission plan (refused/deferred) and raise.

        The core has already resolved the disposition — including a deferral whose
        review object failed to create, which it resolves to a refusal on
        ``review_object_creation_failed``. This method only emits the single
        terminal admission record the plan describes and raises the frozen
        ``ToolError`` for the resolved disposition; it makes no lifecycle decision.
        """

        record = admission_plan.record
        assert record is not None  # refused/deferred always plan a record.
        binding_disposition = _project_binding_disposition(record.disposition)

        if record.disposition == "refused":
            # The core owns the refusal *decision*. The reason code stamped on the
            # receipt is an adapter-owned projection: a policy refusal emits the
            # binding's own (possibly opaque) reason code verbatim (§7), whereas a
            # deferral the core resolved to a refusal (its review object failed to
            # create) emits the core's governance ground unchanged.
            reason_code = (
                record.reason_code
                if admission_plan.requested_disposition == "deferred"
                else self._binding_refusal_reason_code(policy)
            )
            try:
                self._emit_admission(
                    receipt_context,
                    snapshot,
                    policy,
                    disposition=binding_disposition,
                    reason_code=reason_code,
                )
            except Exception as exc:  # noqa: BLE001 - do not leak signer/sink failures.
                self._record_receipt_failure(
                    receipt_context,
                    snapshot,
                    attempted_receipt_kind="admission",
                    failure=exc,
                )
            raise ToolError("Call refused by admission policy")

        # Deferred: a single deferred admission record carrying the review-object
        # reference and the core's continuation contract (retry_after_approval).
        try:
            self._emit_admission(
                receipt_context,
                snapshot,
                policy,
                disposition=binding_disposition,
                review_object_ref=review_object_ref,
                retry_contract=record.retry_contract,
            )
        except Exception as exc:  # noqa: BLE001
            self._record_receipt_failure(
                receipt_context,
                snapshot,
                attempted_receipt_kind="admission",
                failure=exc,
            )
            raise ToolError(
                "Review admission receipt could not be durably accepted"
            ) from None

        raise ToolError(f"Call deferred for review: {review_object_ref}")

    async def _create_review_object(
        self,
        snapshot: RequestSnapshot,
        actor: ActorResolution,
        policy: BindingPolicy,
    ) -> str:
        creator = self.config.review_object_creator
        if creator is None:
            raise RuntimeError("review object creator is not configured")

        if callable(creator):
            ref = creator(snapshot, actor, policy)
        elif hasattr(creator, "create_review_object"):
            ref = creator.create_review_object(
                ReviewObject(
                    review_object_type="mcp_tool_call",
                    governance_state="pending",
                    context_payload={
                        "tool_name": snapshot.tool_name,
                        "argument_digest": snapshot.arguments_digest,
                        "actor_ref": actor.actor_ref,
                        "logical_call_id": snapshot.logical_call_id,
                    },
                    allowed_actions=["approve", "reject", "defer"],
                    created_at=now_utc_iso(),
                    origin_event_id=snapshot.request_ref,
                )
            )
        elif hasattr(creator, "create"):
            ref = creator.create(
                {
                    "review_object_type": "mcp_tool_call",
                    "governance_state": "pending",
                    "tool_name": snapshot.tool_name,
                    "argument_digest": snapshot.arguments_digest,
                    "actor_ref": actor.actor_ref,
                    "logical_call_id": snapshot.logical_call_id,
                }
            )
        else:
            raise TypeError("review object creator is not callable")

        if inspect.isawaitable(ref):
            ref = await ref
        if not isinstance(ref, str) or not ref:
            raise RuntimeError("review object creator returned an invalid ref")
        return ref

    def _pre_execution_failure_mode(self, tool_class: ToolClass) -> ReceiptFailureMode:
        return self.config.pre_execution_receipt_failure.get(tool_class, "fail_closed")

    def _emit_admission(
        self,
        receipt_context: ReceiptContext,
        snapshot: RequestSnapshot,
        policy: BindingPolicy,
        *,
        disposition: Disposition,
        review_object_ref: str | None = None,
        retry_contract: str | None = None,
        reason_code: str | None = None,
    ) -> str:
        return self.emitter.emit_admission(
            context=receipt_context,
            requested_tool_name=snapshot.tool_name,
            argument_digest=snapshot.arguments_digest,
            disposition=disposition,
            review_object_ref=review_object_ref,
            retry_contract=retry_contract,
            reason_code=reason_code,
            additional_attestation_limits=self._attestation_limits(policy),
        )

    def _emit_planned_outcome(
        self,
        admission_plan: AdmissionPlan,
        receipt_context: ReceiptContext,
        snapshot: RequestSnapshot,
        admission_receipt_ref: str,
        result: Any,
        observation: ExecutionObservation,
        *,
        result_digest: str | None = None,
    ) -> None:
        """Project a core-planned post-execution outcome onto the emitter.

        The core decides the outcome record family, whether it carries a result
        digest, and (via ``plan_outcome_strict``) refuses any unsupported neutral
        event (``input_required``) rather than coercing it. The adapter only
        projects the neutral family onto the binding token and supplies the digest
        it computed when the family carries one. Used for the ``result`` /
        ``error`` / ``task_submitted`` families; ``exception`` and ``cancellation``
        keep their A1-frozen inline emit calls in :meth:`on_call_tool`.
        """

        record = plan_outcome_strict(admission_plan, observation).record
        if record is None:  # pragma: no cover - guarded by admission_receipt_ref.
            return
        self._emit_post_execution_outcome(
            receipt_context,
            snapshot,
            admission_receipt_ref,
            result,
            outcome=_project_binding_outcome(record.outcome),
            result_digest=result_digest if record.carries_result_digest else None,
        )

    def _project_core_outcome(
        self,
        admission_plan: AdmissionPlan,
        observation: ExecutionObservation,
        receipt_context: ReceiptContext,
        snapshot: RequestSnapshot,
        admission_receipt_ref: str,
        *,
        frozen_outcome: str,
        exception_class: str | None = None,
        frozen_binding_owned_fields: Mapping[str, bool] | None = None,
    ) -> None:
        """Emit the cancellation / raised-exception outcome under the core's authority.

        ``plan_outcome_strict`` makes the neutral core the runtime authority for
        the outcome record family, whether a result digest is carried, the
        cancellation governance facts, and the timeout→exception subsumption. The
        frozen A1 binding literals the caller passes inline in ``on_call_tool``
        (``frozen_outcome`` and, for a cancellation, ``frozen_binding_owned_fields``)
        are a *checked projection invariant*: this method verifies the core plan,
        projected through the A2 mask, equals them and **fails closed** — raising a
        deterministic projection error *before* any receipt is emitted — on any
        mismatch, so a frozen literal can never act as a second decision authority.

        ``exception_class`` is the adapter-owned raised-class name (§4); the core
        never mints it. The emitted values are the core-derived projection, not the
        frozen literals, which serve only as the invariant.
        """

        record = plan_outcome_strict(admission_plan, observation).record
        if record is None:  # pragma: no cover - guarded by admission_receipt_ref.
            return

        # The core owns the outcome family; the mask projects it onto the emitter
        # token. The frozen inline literal must equal that projection.
        projected_outcome = _project_binding_outcome(record.outcome)
        if projected_outcome != frozen_outcome:
            raise ToolError(
                "core outcome projection diverged from the frozen binding literal: "
                f"core={projected_outcome!r} frozen={frozen_outcome!r}"
            )

        # The core owns whether a result digest is carried; a cancellation and an
        # exception carry none. A carried digest here is a core↔adapter
        # contradiction and must fail closed rather than emit a receipt.
        if record.carries_result_digest:
            raise ToolError(
                "core outcome projection diverged from the frozen binding literal: "
                f"a result digest was planned for a {frozen_outcome!r} outcome"
            )

        # Cancellation governance facts: the core owns which facts hold and their
        # value; the mask projects each onto its binding field. The frozen inline
        # dict must equal that projection exactly (empty ⇒ ``None`` for exceptions).
        projected_fields = self._project_governance_facts(record)
        if projected_fields != frozen_binding_owned_fields:
            raise ToolError(
                "core cancellation governance facts diverged from the frozen "
                f"binding literal: core={projected_fields!r} "
                f"frozen={frozen_binding_owned_fields!r}"
            )

        self._emit_outcome_best_effort(
            receipt_context,
            snapshot,
            admission_receipt_ref,
            outcome=projected_outcome,
            exception_class=exception_class,
            binding_owned_fields=projected_fields,
        )

    @staticmethod
    def _project_governance_facts(
        record: OutcomeRecordIntent,
    ) -> dict[str, bool] | None:
        """Project a core outcome record's governance facts onto binding fields.

        Returns ``None`` when the record carries no governance fact (every family
        but cancellation), matching the ``binding_owned_fields=None`` an exception
        outcome emits.
        """

        if not record.governance_facts:
            return None
        return {
            _project_binding_cancellation_fact(fact): record.governance_facts_value
            for fact in record.governance_facts
        }

    def _emit_post_execution_outcome(
        self,
        receipt_context: ReceiptContext,
        snapshot: RequestSnapshot,
        admission_receipt_ref: str,
        result: Any,
        *,
        outcome: str,
        result_digest: str | None = None,
    ) -> None:
        try:
            self.emitter.emit_outcome(
                context=receipt_context,
                admission_receipt_ref=admission_receipt_ref,
                outcome=outcome,
                result_digest=result_digest,
                additional_attestation_limits=self._attestation_limits(None),
            )
        except Exception as exc:  # noqa: BLE001 - post-execution policy returns result.
            self._record_receipt_failure(
                receipt_context,
                snapshot,
                attempted_receipt_kind="outcome",
                attempted_outcome=outcome,
                admission_receipt_ref=admission_receipt_ref,
                failure=exc,
            )
            if self.config.post_execution_receipt_failure != "alert_and_return_result":
                self.local_telemetry.append(
                    {
                        "event_type": "unsupported_post_execution_failure_mode",
                        "mode": self.config.post_execution_receipt_failure,
                        "result_class": type(result).__name__,
                    }
                )

    def _emit_outcome_best_effort(
        self,
        receipt_context: ReceiptContext,
        snapshot: RequestSnapshot,
        admission_receipt_ref: str,
        *,
        outcome: str,
        result_digest: str | None = None,
        exception_class: str | None = None,
        binding_owned_fields: Mapping[str, bool] | None = None,
    ) -> None:
        try:
            self.emitter.emit_outcome(
                context=receipt_context,
                admission_receipt_ref=admission_receipt_ref,
                outcome=outcome,
                result_digest=result_digest,
                exception_class=exception_class,
                additional_attestation_limits=self._attestation_limits(None),
                binding_owned_fields=binding_owned_fields,
            )
        except Exception as exc:  # noqa: BLE001
            self._record_receipt_failure(
                receipt_context,
                snapshot,
                attempted_receipt_kind="outcome",
                attempted_outcome=outcome,
                admission_receipt_ref=admission_receipt_ref,
                failure=exc,
            )

    def _attestation_limits(self, policy: BindingPolicy | None) -> tuple[str, ...]:
        limits = list(self.config.additional_attestation_limits)
        if policy is not None:
            limits.extend(policy.additional_attestation_limits)
        return tuple(dict.fromkeys(limits))

    def _record_review_failure(
        self,
        receipt_context: ReceiptContext,
        snapshot: RequestSnapshot,
        failure: BaseException,
    ) -> None:
        self.local_telemetry.append(
            {
                "event_type": "review_object_creation_failed",
                "occurred_at": now_utc_iso(),
                "runtime_instance_id": receipt_context.runtime_instance_id,
                "boundary_id": receipt_context.boundary_id,
                "logical_call_id": snapshot.logical_call_id,
                "requested_tool_name": snapshot.tool_name,
                "failure_class": type(failure).__name__,
            }
        )

    def _record_receipt_failure(
        self,
        receipt_context: ReceiptContext,
        snapshot: RequestSnapshot,
        *,
        attempted_receipt_kind: str,
        failure: BaseException,
        attempted_outcome: str | None = None,
        admission_receipt_ref: str | None = None,
    ) -> None:
        event = {
            "event_type": "receipt_gap",
            "occurred_at": now_utc_iso(),
            "runtime_instance_id": receipt_context.runtime_instance_id,
            "boundary_id": receipt_context.boundary_id,
            "logical_call_id": snapshot.logical_call_id,
            "requested_tool_name": snapshot.tool_name,
            "attempted_receipt_kind": attempted_receipt_kind,
            "attempted_outcome": attempted_outcome,
            "admission_receipt_ref": admission_receipt_ref,
            "failure_class": _classified_failure(failure),
        }
        self.local_telemetry.append(event)
        self._append_emergency_spool(event)

    def _append_emergency_spool(self, event: Mapping[str, Any]) -> None:
        if self.config.emergency_spool_path is None:
            return
        try:
            path = Path(self.config.emergency_spool_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            payload = json.dumps(
                event,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8") + b"\n"
            fd, tmp_name = tempfile.mkstemp(
                prefix=".receipt-gap-",
                suffix=".tmp",
                dir=path.parent,
            )
            try:
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, "wb") as handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
                with path.open("ab") as target:
                    target.write(payload)
                    target.flush()
                    os.fsync(target.fileno())
                os.unlink(tmp_name)
            except Exception:
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass
                raise
        except Exception as exc:  # noqa: BLE001 - local telemetry only.
            self.local_telemetry.append(
                {
                    "event_type": "receipt_gap_spool_failed",
                    "occurred_at": now_utc_iso(),
                    "failure_class": type(exc).__name__,
                }
            )


def default_actor_resolution() -> ActorResolution:
    """Resolve FastMCP authenticated contexts without retaining raw tokens."""

    try:
        token = get_access_token()
    except Exception:  # noqa: BLE001 - direct/stdio calls have no token context.
        token = None
    if token is None:
        return ActorResolution()

    claims = getattr(token, "claims", None) or {}
    if not isinstance(claims, Mapping):
        claims = {}
    if claims:
        actor_ref = _scoped_hash_ref("actor", claims)
    else:
        token_fallback = {
            "client_id": getattr(token, "client_id", None),
            "scopes": sorted(str(scope) for scope in getattr(token, "scopes", []) or []),
            "resource": getattr(token, "resource", None),
        }
        actor_ref = _scoped_hash_ref("actor", token_fallback)
    tenant_id = _claim_string(claims, ("tenant_id", "tid", "tenant"))
    workspace_id = _claim_string(claims, ("workspace_id", "wid", "workspace"))
    return ActorResolution(
        actor_ref=actor_ref,
        tenant_id=_scoped_hash_ref("tenant", tenant_id) if tenant_id else None,
        workspace_id=_scoped_hash_ref("workspace", workspace_id)
        if workspace_id
        else None,
    )


def project_fastmcp_tool_result(result: Any) -> dict[str, Any]:
    """Return the exact four-member ``fastmcp.tool_result.v1`` projection."""

    content = _jsonable(getattr(result, "content", []))
    structured_content = _jsonable(
        getattr(result, "structured_content", getattr(result, "structuredContent", None))
    )
    meta = _jsonable(getattr(result, "meta", getattr(result, "_meta", None)))
    is_error = bool(getattr(result, "is_error", getattr(result, "isError", False)))
    projection = {
        "content": content,
        "structuredContent": structured_content,
        "_meta": meta,
        "isError": is_error,
    }
    rfc8785.dumps(projection)
    return projection


def _jsonable(value: Any) -> Any:
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [_jsonable(item) for item in value]
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        return model_dump(mode="json", by_alias=True, exclude_none=True)
    if hasattr(value, "dict") and callable(value.dict):
        return value.dict(by_alias=True, exclude_none=True)
    try:
        dumped = json.loads(json.dumps(value))
    except TypeError:
        dumped = str(value)
    return dumped


def _classified_failure(failure: BaseException) -> str:
    if isinstance(failure, ReceiptWriteError):
        return "receipt_sink_failure"
    if isinstance(failure, ReceiptContentError):
        return "receipt_signing_or_content_failure"
    if isinstance(failure, OSError):
        return "receipt_spool_io_failure"
    return type(failure).__name__


def _context_attr(context: Any, name: str) -> str | None:
    if context is None:
        return None
    try:
        value = getattr(context, name)
    except Exception:  # noqa: BLE001
        return None
    if value is None:
        return None
    return str(value)


def _get_meta(message: Any) -> Any | None:
    for name in ("meta", "_meta"):
        try:
            value = getattr(message, name)
        except Exception:  # noqa: BLE001
            continue
        if value is not None:
            return value
    return None


def _scoped_hash_ref(prefix: str, value: Any) -> str:
    digest = sha256_digest(value).removeprefix("sha256:")
    return f"{prefix}:sha256:{digest}"


def _claim_string(claims: Mapping[str, Any], keys: Sequence[str]) -> str | None:
    for key in keys:
        value = claims.get(key)
        if isinstance(value, str) and value:
            return value
    return None


__all__ = [
    "ActorResolution",
    "BINDING_VERSION",
    "CREATE_TASK_RESULT_IMPORT_PATH",
    "DAGRMiddleware",
    "DAGRMiddlewareConfig",
    "BindingPolicy",
    "OperatorAdmissionDecision",
    "OperatorAdmissionResolver",
    "RequestSnapshot",
    "project_fastmcp_tool_result",
]
