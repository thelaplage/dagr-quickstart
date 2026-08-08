"""Neutral Gateway request/response contract (Sprint A7).

Scope: ``docs/GATEWAY_SERVICE_ADAPTER_SCOPE.md`` §3 (service boundary), §4
(response contract), work package A7 ("Contract and models only"). This
module declares ``GovernedCallRequest``, ``GovernedCallResponse``, and their
supporting value types. It contains **no** transport, execution, binding
invocation, receipt emission, or real actor/tenant resolution — every
"trusted" or "resolved" field documents a value some *other*, not-yet-written
component (A8's adapter) will populate; nothing in this module derives such a
value from a transport context, because this module has no transport
context.

**Reused, not reinvented.** The disposition/refusal-ground/outcome vocabulary
is imported unchanged from :mod:`dagr_mcp_lifecycle.contract` — the same
binding-neutral tokens both existing bindings already project onto. This
module adds only the diagnostics named in §4/§10 that the neutral core does
not already carry (``unknown_binding``, ``binding_unavailable``,
``malformed_request``, ``remote_unavailable``, ``tool_error``,
``remote_exception``, ``deferred_for_review``, ``cancelled``,
``unsupported_lifecycle_state``); refusal grounds are never re-spelled here.

**No caller-authority shortcuts — a two-stage contract, not just typed
fields.** Per §3.3, a caller must not be able to *assert* trusted actor/tenant
identity, role, policy outcome, organization authority, a credential, a
signing identity, an arbitrary receipt id, an arbitrary custody disposition,
or an arbitrary binding-version stamp. Wrapper dataclasses alone do not prove
that: if a single request type accepted both untrusted caller facts and
trusted resolved references, a naive external deserializer could still fill
the trusted fields straight from caller input. This module instead splits the
boundary into two distinct types:

* :class:`CallerGovernedCallRequest` — the public, caller-facing input. It has
  no ``actor_ref``/``tenant_ref`` fields at all (they are not merely
  ignored — they do not exist on this type), and its
  :meth:`CallerGovernedCallRequest.from_untrusted_mapping` deserializer
  rejects any payload key outside a closed allowlist, raising ``ValueError``
  rather than silently dropping an unrecognized or prohibited key (see
  :data:`PROHIBITED_CALLER_AUTHORITY_KEYS` and
  ``tests/test_gateway_service_contract.py``).
* :class:`GovernedCallRequest` — the internal, service-resolved request.
  ``actor_ref``/``tenant_ref`` are only reachable via
  :meth:`GovernedCallRequest.from_caller_request`, which takes them as
  separate, already-resolved keyword arguments the caller-facing payload
  cannot supply — mirroring how §8.2 says these refs are "derived ... from
  the trusted transport/auth context only," never from caller-controlled
  input. This module performs no such resolution itself (there is no
  transport context here); A8's adapter is where a real trusted-context
  resolver supplies these arguments.

**No idempotency claim.** Nothing in this module encodes a deduplication key,
a durable replay ledger, or an "exactly once" guarantee. §11 leaves the
idempotency/retry ledger explicitly open; a retried call is expected to
produce a *new* ``GovernedCallRequest``/``GovernedCallResponse`` pair with
fresh references, exactly as the existing bindings mint fresh receipt ids per
attempt.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Any, Literal

from dagr_mcp_lifecycle.contract import (
    DEFERRAL_CONTINUATION_CONTRACT,
    DIGEST_PREFIX,
    NEUTRAL_CANCELLATION_FACTS,
    NEUTRAL_DISPOSITIONS,
    NEUTRAL_OUTCOMES,
    NEUTRAL_REFUSAL_GROUNDS,
    RECEIPT_CARDINALITY,
    NeutralCancellationFact,
    NeutralDisposition,
    NeutralOutcome,
    NeutralRefusalGround,
)
from dagr_mcp_service.resolution import BindingSelectorKey

SERVICE_ID = "dagr.mcp.gateway_service_contract"
SERVICE_VERSION = "v0.1"

# --------------------------------------------------------------------------- #
# Boundary type (§3.2 — pinned for v0.1)                                      #
# --------------------------------------------------------------------------- #
# Reuses the spelling of GatewayBoundaryType.MCP_TOOL_CALL
# (dagr_mcp.mcp_record_custody_gateway) without importing that enum: the
# custody-gateway module carries three other boundary members
# (mcp_resource_read, mcp_prompt_retrieval, agent_delegation) that are not
# meaningful for a v0.1 tool-call-only Gateway request, and this module's
# request type intentionally accepts only the one pinned value.
BOUNDARY_TYPE = "mcp_tool_call"

# --------------------------------------------------------------------------- #
# A7-specific diagnostic vocabulary (§4, §5.2, §10)                           #
# --------------------------------------------------------------------------- #
# A closed extension of the neutral vocabulary, not a fork of it: every
# refusal-ground diagnostic reuses NeutralRefusalGround verbatim (§4's
# "refused" row: "Diagnostic = refusal ground verbatim"); these are the codes
# §4/§5.2/§10 name that have no existing home in
# dagr_mcp_lifecycle.contract.NEUTRAL_REFUSAL_GROUNDS or NEUTRAL_OUTCOMES.
GatewayDiagnosticCode = Literal[
    "unknown_binding",
    "binding_unavailable",
    "malformed_request",
    "remote_unavailable",
    "tool_error",
    "remote_exception",
    "deferred_for_review",
    "cancelled",
    "unsupported_lifecycle_state",
]
GATEWAY_DIAGNOSTIC_CODES: tuple[GatewayDiagnosticCode, ...] = (
    "unknown_binding",
    "binding_unavailable",
    "malformed_request",
    "remote_unavailable",
    "tool_error",
    "remote_exception",
    "deferred_for_review",
    "cancelled",
    "unsupported_lifecycle_state",
)
# The full diagnostic-code surface a GovernedCallResponse.diagnostic_code may
# take: the A7 additions above, plus the neutral refusal grounds reused
# verbatim (never re-spelled).
ALL_DIAGNOSTIC_CODES: frozenset[str] = frozenset(GATEWAY_DIAGNOSTIC_CODES) | frozenset(
    NEUTRAL_REFUSAL_GROUNDS
)



def _non_empty_str(field_name: str, value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value


def _optional_str(field_name: str, value: Any) -> str | None:
    if value is None:
        return None
    return _non_empty_str(field_name, value)


# --------------------------------------------------------------------------- #
# Opaque, already-resolved reference wrapper types (§3.2, §3.3, §8)           #
# --------------------------------------------------------------------------- #
# These wrap a plain string rather than exposing one directly on
# GovernedCallRequest. The wrapping is deliberate, not decorative: §3.2 says
# the request's actor/tenant fields "document the resolved value the service
# will stamp" rather than accept caller-asserted trust, and §8.5 says these
# are "resolved from trusted context before the tool name and arguments are
# even forwarded." Nothing in this module performs that resolution (there is
# no transport context here to resolve from) — but constructing one of these
# types is only possible with an already-formed ref string, never with a
# free-form role/policy/credential value, keeping the prohibited §3.3 shapes
# structurally distinct from a legitimate resolved reference.


@dataclass(frozen=True, slots=True, kw_only=True)
class TrustedActorRef:
    """An opaque, already-resolved actor reference (§3.2, §8.2).

    Mirrors the scoped-hash-ref convention both existing bindings already use
    (``actor:sha256:...``, see ``default_actor_resolution()`` /
    ``default_sdk_actor_resolution()``) without importing either binding's
    helper — this package must stay usable without either binding installed.
    """

    ref: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "ref", _non_empty_str("TrustedActorRef.ref", self.ref))


@dataclass(frozen=True, slots=True, kw_only=True)
class TrustedTenantRef:
    """An opaque, already-resolved tenant/organization reference (§3.2, §8.2)."""

    ref: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "ref", _non_empty_str("TrustedTenantRef.ref", self.ref))


@dataclass(frozen=True, slots=True, kw_only=True)
class TargetServerRef:
    """An operator-allowlisted remote MCP server *handle* (§3.2, §12 SSRF).

    Deliberately not a URL: §12 requires the target to be "an
    operator-allowlisted server *handle*, not an arbitrary URL from the model
    or caller." This type carries only the handle; allowlist resolution is
    out of scope for A7 (no connector exists yet to resolve it against).
    """

    handle: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "handle", _non_empty_str("TargetServerRef.handle", self.handle))


# --------------------------------------------------------------------------- #
# CallerGovernedCallRequest (§3.2 caller-supplied facts, §3.3 boundary)       #
# --------------------------------------------------------------------------- #
# The public, untrusted caller-facing input type. It is deliberately a
# SEPARATE dataclass from GovernedCallRequest, not a subset accessed by
# convention: it has no actor_ref/tenant_ref fields to smuggle a value into
# in the first place, and its from_untrusted_mapping() deserializer is the
# one boundary a real transport front (A9) would call on external bytes.

# The closed set of keys from_untrusted_mapping() accepts. Anything else is
# rejected — including, but not limited to, PROHIBITED_CALLER_AUTHORITY_KEYS
# below. A closed allowlist (rather than a denylist of just the named
# prohibited keys) is the narrower, fail-closed choice: an unanticipated key
# is refused the same way a named one is, never silently ignored.
_CALLER_REQUEST_REQUIRED_KEYS: frozenset[str] = frozenset(
    {
        "request_ref",
        "binding_selector",
        "target_server_ref",
        "tool_name",
        "argument_digest",
        "policy_profile_ref",
    }
)
_CALLER_REQUEST_OPTIONAL_KEYS: frozenset[str] = frozenset(
    {"boundary_type", "parent_receipt_ref", "session_ref", "meta_digest"}
)
_CALLER_REQUEST_ALLOWED_KEYS: frozenset[str] = (
    _CALLER_REQUEST_REQUIRED_KEYS | _CALLER_REQUEST_OPTIONAL_KEYS
)

# Named per §3.3's prohibited list, for a clearer rejection message when a
# payload matches one of these exactly. Membership here is a subset of "any
# key outside _CALLER_REQUEST_ALLOWED_KEYS" — every one of these is already
# rejected by the allowlist check alone; this set exists only for diagnostics.
PROHIBITED_CALLER_AUTHORITY_KEYS: frozenset[str] = frozenset(
    {
        "actor_ref",
        "tenant_ref",
        "role",
        "policy_decision",
        "policy_outcome",
        "disposition",
        "credential",
        "credentials",
        "signing_identity",
        "signer",
        "binding_version",
        "receipt_id",
        "custody_status",
        "custody_disposition",
    }
)


@dataclass(frozen=True, slots=True, kw_only=True)
class CallerGovernedCallRequest:
    """The public, transport-agnostic caller input (§3.2's caller-supplied
    facts only — none of §3.3's prohibited authority fields).

    This type has no ``actor_ref``/``tenant_ref``/credential/role/policy/
    binding-version-stamp field at all; a caller cannot assert trusted
    identity through it because there is nowhere on it to put one. Pair with
    :meth:`GovernedCallRequest.from_caller_request`, which accepts the
    already-resolved trusted references as separate keyword arguments the
    caller-facing payload never supplies.
    """

    request_ref: str
    binding_selector: BindingSelectorKey
    target_server_ref: TargetServerRef
    tool_name: str
    argument_digest: str
    policy_profile_ref: str
    boundary_type: str = BOUNDARY_TYPE
    parent_receipt_ref: str | None = None
    session_ref: str | None = None
    meta_digest: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "request_ref", _non_empty_str("request_ref", self.request_ref)
        )
        object.__setattr__(
            self, "tool_name", _non_empty_str("tool_name", self.tool_name)
        )
        object.__setattr__(
            self,
            "policy_profile_ref",
            _non_empty_str("policy_profile_ref", self.policy_profile_ref),
        )
        object.__setattr__(
            self,
            "parent_receipt_ref",
            _optional_str("parent_receipt_ref", self.parent_receipt_ref),
        )
        object.__setattr__(
            self, "session_ref", _optional_str("session_ref", self.session_ref)
        )
        object.__setattr__(
            self, "meta_digest", _optional_str("meta_digest", self.meta_digest)
        )

        if not isinstance(self.binding_selector, BindingSelectorKey):
            raise TypeError(
                "binding_selector must be a resolution.BindingSelectorKey, "
                f"got {type(self.binding_selector).__name__}"
            )
        if not isinstance(self.target_server_ref, TargetServerRef):
            raise TypeError(
                "target_server_ref must be a TargetServerRef, "
                f"got {type(self.target_server_ref).__name__}"
            )

        argument_digest = _non_empty_str("argument_digest", self.argument_digest)
        if not argument_digest.startswith(DIGEST_PREFIX):
            raise ValueError(
                f"argument_digest must start with {DIGEST_PREFIX!r}, "
                f"got {argument_digest!r}"
            )
        object.__setattr__(self, "argument_digest", argument_digest)

        if self.boundary_type != BOUNDARY_TYPE:
            raise ValueError(
                f"boundary_type is pinned to {BOUNDARY_TYPE!r} for v0.1, "
                f"got {self.boundary_type!r}"
            )

    @classmethod
    def from_untrusted_mapping(cls, payload: Mapping[str, Any]) -> "CallerGovernedCallRequest":
        """Deserialize an external, untrusted payload (§3.3 boundary).

        Rejects — raises ``ValueError``, never silently drops — any key
        outside the closed caller-facing allowlist, including every field
        named in §3.3's prohibited-authority list
        (:data:`PROHIBITED_CALLER_AUTHORITY_KEYS`). This is the strict
        external deserializer the module docstring describes: a caller
        cannot get a trusted-authority value accepted by supplying an extra
        key, because any key this type does not itself declare is refused
        before construction is attempted.
        """

        if not isinstance(payload, Mapping):
            raise TypeError(f"payload must be a mapping, got {type(payload).__name__}")

        unknown_keys = set(payload) - _CALLER_REQUEST_ALLOWED_KEYS
        if unknown_keys:
            smuggled = unknown_keys & PROHIBITED_CALLER_AUTHORITY_KEYS
            if smuggled:
                raise ValueError(
                    "payload asserts caller authority over a service-resolved "
                    f"or prohibited field (§3.3): {sorted(smuggled)!r}"
                )
            raise ValueError(
                f"payload contains unrecognized field(s): {sorted(unknown_keys)!r}"
            )

        missing_keys = _CALLER_REQUEST_REQUIRED_KEYS - set(payload)
        if missing_keys:
            raise ValueError(
                f"payload is missing required field(s): {sorted(missing_keys)!r}"
            )

        binding_selector_value = payload["binding_selector"]
        if not isinstance(binding_selector_value, str):
            raise TypeError(
                "binding_selector must be a string selector key, got "
                f"{type(binding_selector_value).__name__}"
            )
        target_server_value = payload["target_server_ref"]
        if not isinstance(target_server_value, str):
            raise TypeError(
                "target_server_ref must be a string handle, got "
                f"{type(target_server_value).__name__}"
            )

        return cls(
            request_ref=payload["request_ref"],
            binding_selector=BindingSelectorKey(key=binding_selector_value),
            target_server_ref=TargetServerRef(handle=target_server_value),
            tool_name=payload["tool_name"],
            argument_digest=payload["argument_digest"],
            policy_profile_ref=payload["policy_profile_ref"],
            boundary_type=payload.get("boundary_type", BOUNDARY_TYPE),
            parent_receipt_ref=payload.get("parent_receipt_ref"),
            session_ref=payload.get("session_ref"),
            meta_digest=payload.get("meta_digest"),
        )

    def to_dict(self) -> dict[str, Any]:
        """Deterministic dict projection (repo convention: dataclasses.asdict)."""

        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )


# --------------------------------------------------------------------------- #
# GovernedCallRequest (§3.2) — internal, service-resolved request            #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True, kw_only=True)
class GovernedCallRequest:
    """The neutral, transport-agnostic input to the (not-yet-implemented)
    ``execute_governed_call`` operation (§3.1, §3.2).

    This is the *internal, service-resolved* request — the second stage of
    the two-stage contract the module docstring describes. It carries the
    minimum request facts §3.2 enumerates, including the trusted
    ``actor_ref``/``tenant_ref`` a caller cannot itself supply: construct
    this type via :meth:`from_caller_request`, not directly from external
    input. ``argument_digest`` carries only a digest/reference, never raw
    tool arguments (§3.2, §12); this module does not model a raw-argument-
    forwarding field at all — that belongs to the connector (A9), which
    alone needs raw arguments in transit and only for the duration of a
    single forward.
    """

    request_ref: str
    binding_selector: BindingSelectorKey
    actor_ref: TrustedActorRef
    target_server_ref: TargetServerRef
    tool_name: str
    argument_digest: str
    policy_profile_ref: str
    tenant_ref: TrustedTenantRef | None = None
    boundary_type: str = BOUNDARY_TYPE
    parent_receipt_ref: str | None = None
    session_ref: str | None = None
    meta_digest: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "request_ref", _non_empty_str("request_ref", self.request_ref)
        )
        object.__setattr__(
            self, "tool_name", _non_empty_str("tool_name", self.tool_name)
        )
        object.__setattr__(
            self,
            "policy_profile_ref",
            _non_empty_str("policy_profile_ref", self.policy_profile_ref),
        )
        object.__setattr__(
            self,
            "parent_receipt_ref",
            _optional_str("parent_receipt_ref", self.parent_receipt_ref),
        )
        object.__setattr__(
            self, "session_ref", _optional_str("session_ref", self.session_ref)
        )
        object.__setattr__(
            self, "meta_digest", _optional_str("meta_digest", self.meta_digest)
        )

        if not isinstance(self.binding_selector, BindingSelectorKey):
            raise TypeError(
                "binding_selector must be a resolution.BindingSelectorKey, "
                f"got {type(self.binding_selector).__name__}"
            )
        if not isinstance(self.actor_ref, TrustedActorRef):
            raise TypeError(
                f"actor_ref must be a TrustedActorRef, got {type(self.actor_ref).__name__}"
            )
        if self.tenant_ref is not None and not isinstance(self.tenant_ref, TrustedTenantRef):
            raise TypeError(
                "tenant_ref must be a TrustedTenantRef or None, "
                f"got {type(self.tenant_ref).__name__}"
            )
        if not isinstance(self.target_server_ref, TargetServerRef):
            raise TypeError(
                "target_server_ref must be a TargetServerRef, "
                f"got {type(self.target_server_ref).__name__}"
            )

        argument_digest = _non_empty_str("argument_digest", self.argument_digest)
        if not argument_digest.startswith(DIGEST_PREFIX):
            raise ValueError(
                f"argument_digest must start with {DIGEST_PREFIX!r}, "
                f"got {argument_digest!r}"
            )
        object.__setattr__(self, "argument_digest", argument_digest)

        if self.boundary_type != BOUNDARY_TYPE:
            raise ValueError(
                f"boundary_type is pinned to {BOUNDARY_TYPE!r} for v0.1, "
                f"got {self.boundary_type!r}"
            )

    @classmethod
    def from_caller_request(
        cls,
        caller_request: CallerGovernedCallRequest,
        *,
        actor_ref: TrustedActorRef,
        tenant_ref: TrustedTenantRef | None = None,
    ) -> "GovernedCallRequest":
        """Build the internal resolved request from a caller payload plus
        separately-resolved trust (§3.3, §8.2, §8.5).

        ``actor_ref``/``tenant_ref`` are keyword-only and are never read off
        ``caller_request`` — that type has no such fields to read. This is
        the seam a real trusted-context resolver (A8) calls after deriving
        actor/tenant from the authenticated transport, never from
        ``caller_request`` itself.
        """

        if not isinstance(caller_request, CallerGovernedCallRequest):
            raise TypeError(
                "caller_request must be a CallerGovernedCallRequest, "
                f"got {type(caller_request).__name__}"
            )
        return cls(
            request_ref=caller_request.request_ref,
            binding_selector=caller_request.binding_selector,
            actor_ref=actor_ref,
            tenant_ref=tenant_ref,
            target_server_ref=caller_request.target_server_ref,
            tool_name=caller_request.tool_name,
            argument_digest=caller_request.argument_digest,
            policy_profile_ref=caller_request.policy_profile_ref,
            boundary_type=caller_request.boundary_type,
            parent_receipt_ref=caller_request.parent_receipt_ref,
            session_ref=caller_request.session_ref,
            meta_digest=caller_request.meta_digest,
        )

    def to_dict(self) -> dict[str, Any]:
        """Deterministic dict projection (repo convention: dataclasses.asdict)."""

        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )


# --------------------------------------------------------------------------- #
# GovernedCallResponse value types (§4 — six concerns, never conflated)       #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True, kw_only=True)
class GovernedDecision:
    """Concern #2 — the resolved neutral disposition/outcome (§4).

    ``outcome`` is present only for an admitted call that reached execution;
    a refused or deferred call never carries one.
    """

    disposition: NeutralDisposition
    outcome: NeutralOutcome | None = None

    def __post_init__(self) -> None:
        if self.disposition not in NEUTRAL_DISPOSITIONS:
            raise ValueError(
                f"disposition must be one of {NEUTRAL_DISPOSITIONS!r}, "
                f"got {self.disposition!r}"
            )
        if self.outcome is not None:
            if self.outcome not in NEUTRAL_OUTCOMES:
                raise ValueError(
                    f"outcome must be one of {NEUTRAL_OUTCOMES!r}, got {self.outcome!r}"
                )
            if self.disposition != "admitted":
                raise ValueError(
                    "outcome may only be set when disposition == 'admitted' "
                    f"(got disposition={self.disposition!r})"
                )


@dataclass(frozen=True, slots=True, kw_only=True)
class ReceiptHandle:
    """Concern #3 — one emitted receipt reference (§4, §9).

    Never the signer, signing key, or an unrestricted storage path (§4, §12)
    — only an id and, optionally, a location handle.
    """

    receipt_id: str
    receipt_kind: Literal["admission", "outcome"]
    location_handle: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "receipt_id", _non_empty_str("receipt_id", self.receipt_id)
        )
        if self.receipt_kind not in ("admission", "outcome"):
            raise ValueError(
                f"receipt_kind must be 'admission' or 'outcome', got {self.receipt_kind!r}"
            )
        object.__setattr__(
            self,
            "location_handle",
            _optional_str("location_handle", self.location_handle),
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class BusinessResult:
    """Concern #1 — the MCP business result (§4).

    Present only for an admitted call that returned a semantic result or a
    tool-level error payload. ``payload`` is pass-through content returned to
    the *caller*, never placed on a receipt — unlike ``argument_digest`` on
    the request, this is not a refs-only field, because it is never
    persisted here. ``payload`` is untyped (``Any``) because no binding
    invocation exists yet to fix its shape; ``GovernedCallResponse.to_dict()``/
    ``to_json()`` only round-trip when ``payload`` is itself a JSON-safe
    value (a bound MCP tool result such as ``ToolResult``/``CallToolResult``
    is not, and would need the same already-projected form
    ``project_fastmcp_tool_result``/``project_sdk_tool_result`` produce
    elsewhere in this repository) — A8's adapter is responsible for placing
    an already-projected value here, not this module.
    """

    result_kind: Literal["result", "error"]
    payload: Any = None

    def __post_init__(self) -> None:
        if self.result_kind not in ("result", "error"):
            raise ValueError(
                f"result_kind must be 'result' or 'error', got {self.result_kind!r}"
            )


@dataclass(frozen=True, slots=True, kw_only=True)
class CancellationFacts:
    """The three neutral cancellation governance Booleans (§4's "cancellation/
    indeterminate" row), reusing :data:`NEUTRAL_CANCELLATION_FACTS`'s exact
    field names from :mod:`dagr_mcp_lifecycle.contract` rather than
    reinventing them.
    """

    request_cancelled: bool = False
    execution_state_unknown: bool = False
    delivery_incomplete: bool = False

    def __post_init__(self) -> None:
        for name in NEUTRAL_CANCELLATION_FACTS:
            value = getattr(self, name)
            if not isinstance(value, bool):
                raise ValueError(f"{name} must be a bool, got {type(value).__name__}")


# --------------------------------------------------------------------------- #
# GovernedCallResponse (§4)                                                   #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True, kw_only=True)
class GovernedCallResponse:
    """The neutral output of the (not-yet-implemented) ``execute_governed_call``
    operation (§3.1, §4).

    The five/six response concerns §4 separates are distinct fields here —
    never one conflated dict or blob:

    1. ``business_result`` (business result)
    2. ``decision`` (DAGR decision)
    3. ``receipts`` (receipt handles/references)
    4. ``custody_ref`` (custody observation reference)
    5. ``retry_instruction`` (retry/continuation instruction)
    6. ``diagnostic_code`` (adapter diagnostic code)

    ``decision`` is ``None`` only for the explicitly-unsupported-lifecycle-
    state response class (§4's last row): a neutral event (``input_required``
    in either mode) the core carries no disposition for at all, mirroring
    :class:`dagr_mcp_lifecycle.models.UnsupportedLifecycleResult`'s own
    non-coercion discipline — this response type never coerces such an event
    into a fabricated ``admitted``/``refused``/``deferred`` decision.

    No idempotency or exactly-once guarantee is encoded by this type or by
    any field on it; see the module docstring.
    """

    request_ref: str
    logical_call_id: str
    decision: GovernedDecision | None
    business_result: BusinessResult | None = None
    receipts: tuple[ReceiptHandle, ...] = ()
    review_object_ref: str | None = None
    custody_ref: str | None = None
    parent_receipt_ref: str | None = None
    retry_instruction: str | None = None
    diagnostic_code: str | None = None
    cancellation_facts: CancellationFacts | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "request_ref", _non_empty_str("request_ref", self.request_ref)
        )
        object.__setattr__(
            self,
            "logical_call_id",
            _non_empty_str("logical_call_id", self.logical_call_id),
        )
        object.__setattr__(
            self,
            "review_object_ref",
            _optional_str("review_object_ref", self.review_object_ref),
        )
        object.__setattr__(
            self, "custody_ref", _optional_str("custody_ref", self.custody_ref)
        )
        object.__setattr__(
            self,
            "parent_receipt_ref",
            _optional_str("parent_receipt_ref", self.parent_receipt_ref),
        )
        object.__setattr__(
            self,
            "retry_instruction",
            _optional_str("retry_instruction", self.retry_instruction),
        )

        if not isinstance(self.receipts, tuple):
            raise TypeError(f"receipts must be a tuple, got {type(self.receipts).__name__}")
        for handle in self.receipts:
            if not isinstance(handle, ReceiptHandle):
                raise TypeError(
                    f"every receipts entry must be a ReceiptHandle, got {type(handle).__name__}"
                )

        if self.diagnostic_code is not None:
            diagnostic_code = _non_empty_str("diagnostic_code", self.diagnostic_code)
            if diagnostic_code not in ALL_DIAGNOSTIC_CODES:
                raise ValueError(
                    f"diagnostic_code {diagnostic_code!r} is not a member of the "
                    "closed A7 diagnostic vocabulary or the neutral refusal grounds"
                )
            object.__setattr__(self, "diagnostic_code", diagnostic_code)

        if self.decision is None:
            if self.diagnostic_code != "unsupported_lifecycle_state":
                raise ValueError(
                    "a response with decision=None must carry "
                    "diagnostic_code='unsupported_lifecycle_state' (§4's "
                    "explicitly-unsupported-lifecycle-state row); every other "
                    "response class must carry a GovernedDecision"
                )
            if self.business_result is not None:
                raise ValueError(
                    "an unsupported-lifecycle-state response carries no business_result"
                )
            if self.cancellation_facts is not None:
                raise ValueError(
                    "an unsupported-lifecycle-state response carries no cancellation_facts"
                )
            if self.receipts:
                raise ValueError(
                    "an unsupported-lifecycle-state response carries no receipts"
                )
            return

        if not isinstance(self.decision, GovernedDecision):
            raise TypeError(
                f"decision must be a GovernedDecision or None, got {type(self.decision).__name__}"
            )

        # Receipt cardinality follows the disposition (§4, §9, §10), not a
        # single global maximum: dagr_mcp_lifecycle.contract.RECEIPT_CARDINALITY
        # gives each disposition's ceiling (admitted: 2, refused/deferred: 1).
        # This is a ceiling, not an exact count — the neutral core can
        # legitimately emit fewer: an admitted read configured to skip
        # pre-execution admission emits 0 (dagr_mcp_lifecycle.models.AdmissionPlan
        # / OutcomePlan's ``record: ... | None``), and a required-sink-unavailable
        # refusal is "0 or 1, best effort" (§10) — both still satisfy
        # ``<= ceiling`` under their disposition without a special case.
        receipt_ceiling = RECEIPT_CARDINALITY[self.decision.disposition]
        if len(self.receipts) > receipt_ceiling:
            raise ValueError(
                f"receipts carries {len(self.receipts)} handles, exceeding the "
                f"{self.decision.disposition!r} disposition's receipt-cardinality "
                f"ceiling of {receipt_ceiling}"
            )

        if self.business_result is not None:
            if not isinstance(self.business_result, BusinessResult):
                raise TypeError(
                    "business_result must be a BusinessResult or None, "
                    f"got {type(self.business_result).__name__}"
                )
            if self.decision.disposition != "admitted" or self.decision.outcome not in (
                "result",
                "error",
            ):
                raise ValueError(
                    "business_result is only present for an admitted call with "
                    "outcome 'result' or 'error'"
                )

        if self.cancellation_facts is not None:
            if not isinstance(self.cancellation_facts, CancellationFacts):
                raise TypeError(
                    "cancellation_facts must be a CancellationFacts or None, "
                    f"got {type(self.cancellation_facts).__name__}"
                )
            if self.decision.outcome != "cancellation":
                raise ValueError(
                    "cancellation_facts is only present when decision.outcome == 'cancellation'"
                )

        if (
            self.retry_instruction == DEFERRAL_CONTINUATION_CONTRACT
            and self.decision.disposition != "deferred"
        ):
            raise ValueError(
                f"retry_instruction {DEFERRAL_CONTINUATION_CONTRACT!r} is only "
                "valid for a deferred disposition"
            )

    def to_dict(self) -> dict[str, Any]:
        """Deterministic dict projection (repo convention: dataclasses.asdict)."""

        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )


__all__ = [
    "SERVICE_ID",
    "SERVICE_VERSION",
    "BOUNDARY_TYPE",
    "GatewayDiagnosticCode",
    "GATEWAY_DIAGNOSTIC_CODES",
    "ALL_DIAGNOSTIC_CODES",
    "TrustedActorRef",
    "TrustedTenantRef",
    "TargetServerRef",
    "PROHIBITED_CALLER_AUTHORITY_KEYS",
    "CallerGovernedCallRequest",
    "GovernedCallRequest",
    "GovernedDecision",
    "ReceiptHandle",
    "BusinessResult",
    "CancellationFacts",
    "GovernedCallResponse",
    # Re-exported neutral vocabulary, for callers that only import this module.
    "NeutralDisposition",
    "NEUTRAL_DISPOSITIONS",
    "NeutralRefusalGround",
    "NEUTRAL_REFUSAL_GROUNDS",
    "NeutralOutcome",
    "NEUTRAL_OUTCOMES",
    "NeutralCancellationFact",
    "NEUTRAL_CANCELLATION_FACTS",
    "DEFERRAL_CONTINUATION_CONTRACT",
]
