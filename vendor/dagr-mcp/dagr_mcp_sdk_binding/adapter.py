"""Official Python MCP SDK lifecycle adapter for signed DAGR/SRS receipts.

Sprint A5 — the second DAGR lifecycle binding. This module is the official-SDK
*adapter*: it converts binding inputs (an ``mcp`` request context, tool
arguments, a delegated tool dispatch) into neutral core models, invokes the
neutral core (:mod:`dagr_mcp_lifecycle.core`) for every lifecycle *decision*, and
projects the resulting plan back onto the shared signed-receipt emitter through
the A5 mask (:mod:`dagr_mcp_sdk_binding.mask`).

The neutral core is authoritative for admission disposition resolution, whether
execution proceeds, whether an admission record is durably observed before
execution, deferral/review resolution, the outcome record family, the
result-digest / governance-fact / cancellation posture, the timeout→exception
subsumption, receipt cardinality, and the explicit rejection of ``input_required``.
This adapter owns only binding responsibilities: SDK request/result extraction,
trusted request-context extraction, exception-object inspection, argument/result
canonicalization and digests, signing, custody storage, and transport-native
error projection.

It reuses the neutral adapter layer in :mod:`dagr_mcp_sdk_binding.neutral` (the
value types, the neutral admission-request projection, and the §7
opaque-reason-code discipline) rather than re-deriving the FastMCP decision tree.
It imports the official SDK (``mcp``) but never ``fastmcp``, and starts no
transport at import.
"""

from __future__ import annotations

import asyncio
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

from mcp import types as mcp_types
from mcp.shared.context import RequestContext

from dagr_mcp.sdk_spine import ReviewObject, now_utc_iso
from dagr_mcp.srs_receipts import (
    ReceiptContentError,
    ReceiptContext,
    ReceiptWriteError,
    SignedReceiptEmitter,
    sha256_digest,
)
from dagr_mcp_lifecycle.core import plan_admission, plan_outcome_strict
from dagr_mcp_lifecycle.models import (
    AdmissionPlan,
    ExecutionObservation,
    OutcomeRecordIntent,
)
from dagr_mcp_sdk_binding import neutral
from dagr_mcp_sdk_binding.neutral import (
    DEFAULT_ANONYMOUS_ACTOR_REF,
    DEFAULT_BOUNDARY_LIMIT,
    ActorResolution,
    BindingPolicy,
    Disposition,
    ReceiptFailureMode,
    RequestSnapshot,
    ToolClass,
)

BINDING_VERSION = "official-mcp-sdk.python.v0.1"

PostExecutionReceiptFailureMode: TypeAlias = Literal["alert_and_return_result"]

# The neutral outcome result the delegated dispatch may return, in the shapes the
# official SDK call-tool handler accepts.
ToolCallResult: TypeAlias = Any


# --------------------------------------------------------------------------- #
# Transport-native error projections                                          #
# --------------------------------------------------------------------------- #
# A refused or deferred admission never executes the tool. The adapter signals
# this to the caller (and, through the SDK call-tool wrapper, to the client as an
# isError result) by raising a binding error whose message carries no sensitive
# detail. This mirrors the FastMCP binding raising ``ToolError``.


class SDKBindingError(Exception):
    """Base class for official-SDK binding transport-native errors."""


class ToolRefused(SDKBindingError):
    """Raised when admission refuses a call; the tool body never runs."""


class ToolDeferred(SDKBindingError):
    """Raised when a call is deferred to a durable review object."""


class AdmissionReceiptUnavailable(SDKBindingError):
    """Raised (fail-closed) when a required admission receipt cannot be accepted."""


class TaskSubmissionUnsupported(SDKBindingError):
    """Raised (fail-closed) when a delegated tool returns a ``CreateTaskResult``.

    The ``mcp.types.CreateTaskResult`` type exists, and the lowlevel
    ``Server.call_tool`` handler wraps a returned ``CreateTaskResult`` in a
    ``ServerResult``. But the *bound* ``tools/call`` client seam
    (``mcp.client.session.ClientSession.call_tool``) hardcodes
    ``result_type=CallToolResult`` and validates the response against it;
    ``CallToolResult.content`` is a required field the serialized
    ``CreateTaskResult`` does not carry, so the client raises a pydantic
    ``ValidationError``. ``CreateTaskResult`` is genuinely received only through
    the *separate*, deprecated experimental tasks extension
    (``ClientSession.experimental.call_tool_as_task``, a task-augmented
    ``CallToolRequest`` parsed with ``result_type=CreateTaskResult``).

    This binding therefore does **not** observe ``task_submitted`` through the
    ``tools/call`` seam it binds. Rather than falsely stamping a ``task_submitted``
    outcome or coercing the value into ``result_returned`` / ``error_returned``, it
    fails closed. The A5 mask marks ``task_submitted`` unsupported for this binding
    (see :data:`dagr_mcp_sdk_binding.mask.BINDING_UNSUPPORTED_OUTCOME_TOKENS`), and
    the FastMCP binding's ``task_submitted`` behavior is unchanged.
    """


# --------------------------------------------------------------------------- #
# Construction contracts                                                       #
# --------------------------------------------------------------------------- #

# A delegated tool handler: given the (already hash-captured) model arguments,
# returns an SDK-native result or raises. Never receives trusted authority.
ToolHandler: TypeAlias = Callable[[Mapping[str, Any]], Awaitable[Any] | Any]


class SdkActorResolver(Protocol):
    """Resolve actor identity from the *trusted* SDK request context only.

    It is deliberately handed the trusted :class:`RequestContext` (and the
    hash-only snapshot), never the model-supplied tool arguments, so a tool
    argument can never define actor/tenant/authority.
    """

    def __call__(
        self,
        request_context: RequestContext[Any, Any, Any] | None,
        snapshot: RequestSnapshot,
    ) -> ActorResolution | Awaitable[ActorResolution]:
        ...


class SdkPolicyResolver(Protocol):
    """Resolve the admission disposition and tool class for a call."""

    def __call__(
        self,
        snapshot: RequestSnapshot,
        actor: ActorResolution,
    ) -> BindingPolicy | Awaitable[BindingPolicy]:
        ...


ReviewObjectCreator: TypeAlias = Callable[
    [RequestSnapshot, ActorResolution, BindingPolicy],
    "str | Awaitable[str]",
]


@dataclass(slots=True)
class SdkBindingConfig:
    """Configuration for the official-SDK binding (no module-global state)."""

    runtime_instance_id: str
    boundary_id: str
    policy_pack_id: str
    policy_pack_version: str
    tool_classes: Mapping[str, ToolClass] = field(default_factory=dict)
    actor_resolver: SdkActorResolver | None = None
    policy_resolver: SdkPolicyResolver | None = None
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
# Neutral → binding projection helpers (owned by the A5 mask)                  #
# --------------------------------------------------------------------------- #
# The neutral→binding token tables are owned by the A5 mask, imported lazily so a
# future circular dependency cannot form and so importing the adapter alone does
# not force the mask's grounding reads.


def _project_binding_disposition(neutral_disposition: str) -> Disposition:
    from dagr_mcp_sdk_binding.mask import project_disposition

    return project_disposition(neutral_disposition)  # type: ignore[return-value]


def _project_binding_outcome(neutral_outcome: str) -> str:
    from dagr_mcp_sdk_binding.mask import project_outcome

    token = project_outcome(neutral_outcome).binding_token
    if token is None:  # pragma: no cover - defensive; task_submitted fails closed earlier.
        # A neutral outcome the A5 mask marks unsupported for this binding (e.g.
        # task_submitted, see BINDING_UNSUPPORTED_OUTCOME_TOKENS) carries no binding
        # token. The adapter never routes such an outcome here — task_submitted is
        # rejected in governed_call before any emission — so this is a fail-closed
        # backstop, never a coercion.
        raise SDKBindingError(
            f"neutral outcome {neutral_outcome!r} carries no binding token"
        )
    return token


def _project_binding_cancellation_fact(neutral_fact: str) -> str:
    from dagr_mcp_sdk_binding.mask import project_cancellation_fact

    return project_cancellation_fact(neutral_fact)


# --------------------------------------------------------------------------- #
# Result projection / digest                                                  #
# --------------------------------------------------------------------------- #


def project_sdk_tool_result(result: Any) -> dict[str, Any]:
    """Return the four-member MCP tool-result projection for *result*.

    Byte-compatible with the FastMCP binding's ``project_fastmcp_tool_result``
    (same keys, same order, same ``jsonable`` normalization), so a result digest
    computed here equals the FastMCP digest for an equivalent tool result. Handles
    a ``mcp.types.CallToolResult`` and raw content / structured returns.
    """

    if isinstance(result, Mapping):
        content: Any = []
        structured_content: Any = neutral.jsonable(result)
        meta: Any = None
        is_error = False
    elif isinstance(result, Sequence) and not isinstance(
        result, str | bytes | bytearray
    ):
        content = neutral.jsonable(result)
        structured_content = None
        meta = None
        is_error = False
    else:
        content = neutral.jsonable(getattr(result, "content", []) or [])
        structured_content = neutral.jsonable(
            getattr(result, "structured_content", getattr(result, "structuredContent", None))
        )
        meta = neutral.jsonable(
            getattr(result, "meta", getattr(result, "_meta", None))
        )
        is_error = bool(getattr(result, "is_error", getattr(result, "isError", False)))
    projection = {
        "content": content,
        "structuredContent": structured_content,
        "_meta": meta,
        "isError": is_error,
    }
    rfc8785.dumps(projection)
    return projection


# --------------------------------------------------------------------------- #
# The adapter                                                                 #
# --------------------------------------------------------------------------- #


class SdkLifecycleAdapter:
    """Governs an official-SDK ``tools/call`` around the neutral lifecycle core."""

    def __init__(
        self,
        *,
        emitter: SignedReceiptEmitter,
        config: SdkBindingConfig,
    ) -> None:
        self.emitter = emitter
        self.config = config
        self.local_telemetry: list[dict[str, Any]] = []

    async def governed_call(
        self,
        tool_name: str,
        arguments: Mapping[str, Any] | None,
        delegate: ToolHandler,
        *,
        request_context: RequestContext[Any, Any, Any] | None = None,
    ) -> Any:
        """Run the neutral lifecycle around a delegated tool dispatch.

        The neutral core owns every lifecycle decision. This method extracts the
        SDK request facts, resolves actor/policy from the *trusted* context,
        obtains the admission plan from the core, honours it (refusing/deferring
        without calling ``delegate``), executes the delegated tool for an admitted
        call, classifies the SDK-native result or raised object into a neutral
        observation, and lets the core plan the outcome record.
        """

        snapshot = self._snapshot_request(tool_name, arguments, request_context)
        actor = await self._resolve_actor(request_context, snapshot)
        policy = await self._resolve_policy(snapshot, actor)
        receipt_context = self._receipt_context(snapshot, actor, policy)

        neutral_disposition = neutral.to_neutral_disposition(policy.disposition)

        # A deferral must durably create its review object *before* the core can
        # resolve the disposition; a review object that fails to create resolves —
        # in the core — to a refusal on review_object_creation_failed (never onto
        # required_sink_unavailable). The review object is an adapter side effect.
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

        admission_plan = plan_admission(
            neutral.neutral_admission_request(
                policy,
                neutral_disposition,
                review_object_created,
                emit_read_admission_before_execution=(
                    self.config.emit_read_admission_before_execution
                ),
                has_parent_boundary=(
                    policy.parent_receipt_ref is not None
                    or self.config.parent_receipt_ref is not None
                ),
            )
        )

        if not admission_plan.execution_proceeds:
            # Refused or deferred: emit the single terminal admission record and
            # raise the transport-native error. The core resolved the disposition.
            self._project_terminal_admission(
                admission_plan, receipt_context, snapshot, policy, review_object_ref
            )

        admission_receipt_ref: str | None = None
        if admission_plan.admission_recorded:
            try:
                admission_receipt_ref = self._emit_admission(
                    receipt_context, snapshot, policy, disposition="admitted"
                )
            except Exception as exc:  # noqa: BLE001 - fail policy classifies it.
                self._record_receipt_failure(
                    receipt_context,
                    snapshot,
                    attempted_receipt_kind="admission",
                    failure=exc,
                )
                if self._pre_execution_failure_mode(policy.tool_class) == "fail_closed":
                    raise AdmissionReceiptUnavailable(
                        "Admission receipt could not be durably accepted"
                    ) from None

        try:
            result = await _maybe_await(delegate(arguments or {}))
        except asyncio.CancelledError:
            # Neutral outcome: cancellation. plan_outcome_strict is the runtime
            # authority; the frozen A1 literals below are a checked projection
            # invariant that fails closed on any core↔mask divergence.
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
        except Exception as exc:  # noqa: BLE001 - classified into a neutral outcome.
            # Neutral outcome: exception. A raised TimeoutError routes through the
            # core's timeout→exception subsumption (§14); an ordinary exception is
            # classified directly. The adapter observes the raise here, before the
            # SDK call-tool wrapper would convert it into an isError result.
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

        # task_submitted is an explicit binding capability difference. The bound
        # tools/call client seam cannot carry a CreateTaskResult (see
        # TaskSubmissionUnsupported); this binding fails closed rather than
        # falsely claiming a task_submitted observation or coercing the value into
        # result_returned/error_returned. Checked before the fail-open early return
        # so a returned CreateTaskResult never flows through the tools/call seam,
        # regardless of admission-receipt state. FastMCP behavior is unchanged.
        if isinstance(result, mcp_types.CreateTaskResult):
            raise TaskSubmissionUnsupported(
                "A delegated tool returned mcp.types.CreateTaskResult, but the "
                "bound tools/call client seam does not carry it; task submission "
                "requires the separate experimental tasks extension and is "
                "unsupported by the official-SDK binding."
            )

        if admission_receipt_ref is None:
            return result

        try:
            projection = project_sdk_tool_result(result)
            if self.config.result_projection_observer is not None:
                self.config.result_projection_observer(dict(projection))
            result_digest = sha256_digest(projection)
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
            observation,
            result_digest=result_digest,
        )
        return result

    # ------------------------------------------------------------------ #
    # Trusted-context extraction                                         #
    # ------------------------------------------------------------------ #

    def _snapshot_request(
        self,
        tool_name: str,
        arguments: Mapping[str, Any] | None,
        request_context: RequestContext[Any, Any, Any] | None,
    ) -> RequestSnapshot:
        args = dict(arguments) if arguments else {}
        request_id = _rc_attr(request_context, "request_id")
        session_id = _session_id(request_context)
        meta = _rc_meta(request_context)

        request_ref = (
            neutral.scoped_hash_ref("request", request_id) if request_id else None
        )
        session_ref = (
            neutral.scoped_hash_ref("session", session_id) if session_id else None
        )
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
            tool_name=str(tool_name),
            arguments_digest=sha256_digest(args),
            logical_call_id=logical_call_id,
            subject_ref=subject_ref,
            subject_ref_origin=subject_ref_origin,
            session_ref=session_ref,
            request_ref=request_ref,
            meta_digest=sha256_digest(meta) if meta is not None else None,
        )

    async def _resolve_actor(
        self,
        request_context: RequestContext[Any, Any, Any] | None,
        snapshot: RequestSnapshot,
    ) -> ActorResolution:
        if self.config.actor_resolver is not None:
            resolved = self.config.actor_resolver(request_context, snapshot)
            if inspect.isawaitable(resolved):
                resolved = await resolved
            return resolved
        return default_sdk_actor_resolution()

    async def _resolve_policy(
        self,
        snapshot: RequestSnapshot,
        actor: ActorResolution,
    ) -> BindingPolicy:
        if self.config.policy_resolver is not None:
            resolved = self.config.policy_resolver(snapshot, actor)
            if inspect.isawaitable(resolved):
                resolved = await resolved
            return resolved
        return BindingPolicy(
            disposition="admitted",
            tool_class=self.config.tool_classes.get(snapshot.tool_name, "read"),
        )

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

    # ------------------------------------------------------------------ #
    # Terminal admission (refused / deferred)                            #
    # ------------------------------------------------------------------ #

    def _project_terminal_admission(
        self,
        admission_plan: AdmissionPlan,
        receipt_context: ReceiptContext,
        snapshot: RequestSnapshot,
        policy: BindingPolicy,
        review_object_ref: str | None,
    ) -> NoReturn:
        record = admission_plan.record
        assert record is not None  # refused/deferred always plan a record.
        binding_disposition = _project_binding_disposition(record.disposition)

        if record.disposition == "refused":
            reason_code = (
                record.reason_code
                if admission_plan.requested_disposition == "deferred"
                else neutral.binding_refusal_reason_code(policy)
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
            raise ToolRefused("Call refused by admission policy")

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
            raise AdmissionReceiptUnavailable(
                "Review admission receipt could not be durably accepted"
            ) from None

        raise ToolDeferred(f"Call deferred for review: {review_object_ref}")

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

    # ------------------------------------------------------------------ #
    # Outcome emission                                                    #
    # ------------------------------------------------------------------ #

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
        observation: ExecutionObservation,
        *,
        result_digest: str | None = None,
    ) -> None:
        """Project a core-planned post-execution outcome onto the emitter.

        The core decides the outcome record family, whether it carries a result
        digest, and (via ``plan_outcome_strict``) refuses any unsupported neutral
        event rather than coercing it. Used for the ``result`` / ``error``
        families. ``task_submitted`` is not routed here: it is a binding capability
        difference the adapter fails closed on in :meth:`governed_call`.
        """

        record = plan_outcome_strict(admission_plan, observation).record
        if record is None:  # pragma: no cover - guarded by admission_receipt_ref.
            return
        self._emit_post_execution_outcome(
            receipt_context,
            snapshot,
            admission_receipt_ref,
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

        ``plan_outcome_strict`` is the runtime authority for the outcome family,
        the absent result digest, the cancellation governance facts, and the
        timeout→exception subsumption. The frozen literals the caller passes are a
        *checked projection invariant*: this method verifies the core plan,
        projected through the A5 mask, equals them and **fails closed** — raising
        before any receipt is emitted — on any divergence.
        """

        record = plan_outcome_strict(admission_plan, observation).record
        if record is None:  # pragma: no cover - guarded by admission_receipt_ref.
            return

        projected_outcome = _project_binding_outcome(record.outcome)
        if projected_outcome != frozen_outcome:
            raise SDKBindingError(
                "core outcome projection diverged from the frozen binding literal: "
                f"core={projected_outcome!r} frozen={frozen_outcome!r}"
            )

        if record.carries_result_digest:
            raise SDKBindingError(
                "core outcome projection diverged from the frozen binding literal: "
                f"a result digest was planned for a {frozen_outcome!r} outcome"
            )

        projected_fields = self._project_governance_facts(record)
        if projected_fields != frozen_binding_owned_fields:
            raise SDKBindingError(
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

    # ------------------------------------------------------------------ #
    # Telemetry                                                           #
    # ------------------------------------------------------------------ #

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
            "failure_class": neutral.classified_failure(failure),
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
                prefix=".receipt-gap-", suffix=".tmp", dir=path.parent
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


# --------------------------------------------------------------------------- #
# Default trusted actor resolution                                            #
# --------------------------------------------------------------------------- #


def default_sdk_actor_resolution() -> ActorResolution:
    """Resolve an authenticated official-SDK context without retaining raw tokens.

    Reads the official SDK's trusted auth context
    (``mcp.server.auth.middleware.auth_context.get_access_token``) — a
    ``contextvars``-backed token set by the transport auth middleware, never a
    tool argument. Absent an authenticated context (direct/stdio/in-memory calls)
    it returns the anonymous/local actor.
    """

    try:
        from mcp.server.auth.middleware.auth_context import get_access_token

        token = get_access_token()
    except Exception:  # noqa: BLE001 - no auth context in direct/in-memory calls.
        token = None
    if token is None:
        return ActorResolution()

    claims = getattr(token, "claims", None) or {}
    if not isinstance(claims, Mapping):
        claims = {}
    if claims:
        actor_ref = neutral.scoped_hash_ref("actor", claims)
    else:
        token_fallback = {
            "client_id": getattr(token, "client_id", None),
            "scopes": sorted(str(scope) for scope in getattr(token, "scopes", []) or []),
            "resource": getattr(token, "resource", None),
        }
        actor_ref = neutral.scoped_hash_ref("actor", token_fallback)
    tenant_id = neutral.claim_string(claims, ("tenant_id", "tid", "tenant"))
    workspace_id = neutral.claim_string(
        claims, ("workspace_id", "wid", "workspace")
    )
    return ActorResolution(
        actor_ref=actor_ref,
        tenant_id=neutral.scoped_hash_ref("tenant", tenant_id)
        if tenant_id
        else None,
        workspace_id=neutral.scoped_hash_ref("workspace", workspace_id)
        if workspace_id
        else None,
    )


# --------------------------------------------------------------------------- #
# Small SDK context helpers                                                   #
# --------------------------------------------------------------------------- #


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


def _rc_attr(context: Any, name: str) -> str | None:
    if context is None:
        return None
    try:
        value = getattr(context, name)
    except Exception:  # noqa: BLE001
        return None
    if value is None:
        return None
    return str(value)


def _session_id(context: Any) -> str | None:
    if context is None:
        return None
    session = getattr(context, "session", None)
    if session is None:
        return None
    for name in ("session_id", "client_session_id"):
        value = getattr(session, name, None)
        if value:
            return str(value)
    return None


def _rc_meta(context: Any) -> Any | None:
    if context is None:
        return None
    meta = getattr(context, "meta", None)
    if meta is None:
        return None
    model_dump = getattr(meta, "model_dump", None)
    if callable(model_dump):
        try:
            return model_dump(mode="json", by_alias=True, exclude_none=True)
        except Exception:  # noqa: BLE001
            return None
    return neutral.jsonable(meta)


__all__ = [
    "BINDING_VERSION",
    "PostExecutionReceiptFailureMode",
    "ToolClass",
    "Disposition",
    "ReceiptFailureMode",
    "DEFAULT_ANONYMOUS_ACTOR_REF",
    "DEFAULT_BOUNDARY_LIMIT",
    "ActorResolution",
    "BindingPolicy",
    "RequestSnapshot",
    "SDKBindingError",
    "ToolRefused",
    "ToolDeferred",
    "AdmissionReceiptUnavailable",
    "TaskSubmissionUnsupported",
    "ToolHandler",
    "SdkActorResolver",
    "SdkPolicyResolver",
    "ReviewObjectCreator",
    "SdkBindingConfig",
    "SdkLifecycleAdapter",
    "default_sdk_actor_resolution",
    "project_sdk_tool_result",
]
