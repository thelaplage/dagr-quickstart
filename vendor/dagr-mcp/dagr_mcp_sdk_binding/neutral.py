"""Binding-neutral adapter contracts and utilities for the official-SDK binding.

Sprint A5 introduces a *second* DAGR lifecycle binding (:mod:`dagr_mcp_sdk_binding`)
alongside the frozen FastMCP binding (:mod:`dagr_mcp.fastmcp_binding`). The two
bindings must not duplicate the lifecycle *decision tree* — that authority lives
entirely in the neutral core (:mod:`dagr_mcp_lifecycle.core`), which both
bindings call, and in the shared signed-receipt emitter
(:mod:`dagr_mcp.srs_receipts`), which both bindings use. This module is the
narrow, genuinely binding-neutral **adapter layer** the SDK binding uses around
those shared authorities:

* the resolved value types a boundary produces (:class:`RequestSnapshot`,
  :class:`ActorResolution`, :class:`BindingPolicy`);
* the projection of a resolved policy into the neutral core's
  :class:`~dagr_mcp_lifecycle.models.AdmissionRequest`, including the §7
  opaque-reason-code discipline;
* small pure hash/JSON helpers with no transport or SDK dependency.

It imports nothing from ``fastmcp`` or ``mcp`` and starts no transport, so
importing it (or the neutral core) never drags a binding SDK into memory.

It lives in the SDK binding package (not in ``dagr_mcp``) so the A1-frozen
``dagr_mcp`` public surface stays byte-identical. The pre-existing FastMCP
binding keeps its own equivalent value types unchanged — the A1 behavioral
freeze pins that module's emitted bytes and public surface, so it is deliberately
**not** rewired. New bindings reuse this neutral layer instead of re-deriving the
decision logic.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal, TypeAlias

from dagr_mcp.srs_receipts import (
    ReceiptContentError,
    ReceiptWriteError,
    sha256_digest,
)
from dagr_mcp_lifecycle.contract import NEUTRAL_REFUSAL_GROUNDS
from dagr_mcp_lifecycle.models import AdmissionRequest

ToolClass: TypeAlias = Literal["read", "write", "destructive"]
# The DAGR admission-disposition vocabulary a policy resolver returns. It is the
# established binding token set (the neutral core spells ``deferred_for_review``
# as ``deferred``); both bindings map it onto the neutral disposition through
# :data:`_NEUTRAL_DISPOSITION_BY_BINDING`.
Disposition: TypeAlias = Literal["admitted", "refused", "deferred_for_review"]
ReceiptFailureMode: TypeAlias = Literal["fail_closed", "fail_open"]

DEFAULT_ANONYMOUS_ACTOR_REF = "actor:anonymous_or_local"
# Kept byte-identical to ``dagr_mcp.fastmcp_binding.DEFAULT_BOUNDARY_LIMIT`` so
# the two bindings' ``attestation_limits`` match across the cross-binding corpus.
DEFAULT_BOUNDARY_LIMIT = (
    "The middleware is installed once at the institutional trust boundary; "
    "receipts attest only to observations at that boundary."
)


@dataclass(frozen=True, slots=True)
class RequestSnapshot:
    """Hash-only request facts captured before policy evaluation."""

    tool_name: str
    arguments_digest: str
    logical_call_id: str
    subject_ref: str
    # How ``subject_ref`` was obtained, from the closed v0.2.1 vocabulary. It is
    # ``None`` only for a snapshot built outside the adapter's own request
    # snapshot, which declares nothing rather than guessing a class.
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


# The neutral disposition each binding disposition token maps to on the way into
# the core. Shared by every binding so the mapping has a single home.
_NEUTRAL_DISPOSITION_BY_BINDING: dict[Disposition, str] = {
    "admitted": "admitted",
    "refused": "refused",
    "deferred_for_review": "deferred",
}


def to_neutral_disposition(binding_disposition: Disposition) -> str:
    """Map a DAGR binding disposition token onto the neutral disposition."""

    return _NEUTRAL_DISPOSITION_BY_BINDING[binding_disposition]


def neutral_refusal_ground(policy: BindingPolicy) -> str:
    """Map a binding refusal reason code onto a closed neutral ground (§7).

    A known neutral ground is passed through so the core carries it verbatim; an
    opaque code (or ``None``) resolves to ``policy_refused`` — still a valid
    refusal, so the core stays authoritative for the decision — while the opaque
    code itself is preserved on the receipt by :func:`binding_refusal_reason_code`.
    """

    code = policy.reason_code or "policy_refused"
    if code in NEUTRAL_REFUSAL_GROUNDS:
        return code
    return "policy_refused"


def binding_refusal_reason_code(policy: BindingPolicy) -> str:
    """The verbatim binding refusal reason code stamped on the receipt (§7).

    The core owns the refusal *decision*; the reason code is an adapter-owned
    projection. An opaque code outside the closed neutral vocabulary is preserved
    verbatim (defaulting to ``policy_refused``) rather than narrowed.
    """

    return policy.reason_code or "policy_refused"


def neutral_admission_request(
    policy: BindingPolicy,
    neutral_disposition: str,
    review_object_created: bool | None,
    *,
    emit_read_admission_before_execution: bool,
    has_parent_boundary: bool,
) -> AdmissionRequest:
    """Project a resolved binding policy into the neutral core admission request.

    The core is authoritative for the refusal *decision*; the neutral refusal
    ground it receives is drawn from the closed neutral vocabulary. A known
    ground — including ``required_sink_unavailable`` — is passed through verbatim.
    An opaque binding reason code resolves to ``policy_refused`` for the core
    while the opaque code is emitted verbatim by the adapter.
    """

    return AdmissionRequest(
        disposition=neutral_disposition,  # type: ignore[arg-type]
        tool_class=policy.tool_class,
        refusal_ground=(
            neutral_refusal_ground(policy)  # type: ignore[arg-type]
            if neutral_disposition == "refused"
            else None
        ),
        review_object_created=review_object_created,
        emit_read_admission_before_execution=emit_read_admission_before_execution,
        has_parent_boundary=has_parent_boundary,
    )


def scoped_hash_ref(prefix: str, value: Any) -> str:
    """Return a ``{prefix}:sha256:<hex>`` scoped reference for *value*."""

    digest = sha256_digest(value).removeprefix("sha256:")
    return f"{prefix}:sha256:{digest}"


def claim_string(claims: Mapping[str, Any], keys: Sequence[str]) -> str | None:
    """Return the first non-empty string claim among *keys*, else ``None``."""

    for key in keys:
        value = claims.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def jsonable(value: Any) -> Any:
    """Project *value* into an RFC 8785-canonicalizable, JSON-safe structure.

    Byte-compatible with the FastMCP binding's ``_jsonable`` so a result digest
    computed here matches the one the FastMCP binding computes for equivalent
    content.
    """

    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, Mapping):
        return {str(key): jsonable(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [jsonable(item) for item in value]
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


def classified_failure(failure: BaseException) -> str:
    """Classify a receipt-gap failure into a stable, content-free label."""

    if isinstance(failure, ReceiptWriteError):
        return "receipt_sink_failure"
    if isinstance(failure, ReceiptContentError):
        return "receipt_signing_or_content_failure"
    if isinstance(failure, OSError):
        return "receipt_spool_io_failure"
    return type(failure).__name__


__all__ = [
    "ToolClass",
    "Disposition",
    "ReceiptFailureMode",
    "DEFAULT_ANONYMOUS_ACTOR_REF",
    "DEFAULT_BOUNDARY_LIMIT",
    "RequestSnapshot",
    "ActorResolution",
    "BindingPolicy",
    "to_neutral_disposition",
    "neutral_refusal_ground",
    "binding_refusal_reason_code",
    "neutral_admission_request",
    "scoped_hash_ref",
    "claim_string",
    "jsonable",
    "classified_failure",
]
