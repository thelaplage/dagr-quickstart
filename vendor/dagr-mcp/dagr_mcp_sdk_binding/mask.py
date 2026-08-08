"""The explicit ``official-mcp-sdk.python.v0.1`` mask over the neutral contract.

This module maps the official Python MCP SDK binding
(:mod:`dagr_mcp_sdk_binding.adapter`) onto the neutral lifecycle vocabulary in
:mod:`dagr_mcp_lifecycle.contract`. It is the A5 analog of the FastMCP A2 mask
(:mod:`dagr_mcp_lifecycle.binding_mask`) — a *separate* mask for a *separate*
binding. The two masks are never merged.

Like the FastMCP mask it is a *mask*: it describes, in neutral terms, what the
binding does, and never normalizes or repairs the binding. Every binding-side
value it names is grounded in the actually-installed official SDK (``mcp.types``)
or the shared receipt emitter (``dagr_mcp.srs_receipts``), so the mask cannot
silently drift. :func:`verify_mask_matches_binding` is the drift guard.

The outcome/disposition *tokens* the mask projects onto belong to the shared
receipt profile ``srs.mcp.sdk_enforcement/v0.1`` (not to either binding), so this
mask projects the neutral vocabulary onto the *same* profile tokens the FastMCP
mask does. What is distinct to this binding is its **binding-version stamp**
(``official-mcp-sdk.python.v0.1``) and the fact that its mapping is grounded in
``mcp.types`` rather than FastMCP types.

This module imports the official SDK (``mcp``) but never ``fastmcp``, and starts
no transport at import.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Mapping, get_args

import rfc8785

from mcp import types as mcp_types

from dagr_mcp import srs_receipts
from dagr_mcp.mcp_record_custody_gateway import (
    MCP_RECORD_CUSTODY_GATEWAY_SCHEMA,
    GatewayBoundaryType,
    GatewayCustodyStatus,
    GatewayReceiptFamily,
)
from dagr_mcp_lifecycle import contract
from dagr_mcp_sdk_binding import neutral

MASK_ID = "dagr.mcp.sdk_binding_mask"
MASK_VERSION = "v0.1"

# The exact, pinned binding this mask is written against — an explicit identifier
# so the mask can never be read as describing an unpinned/"latest" binding. It is
# distinct from the FastMCP ``fastmcp.middleware.v0.1`` target and is never reused.
MASK_BINDING_TARGET = "official-mcp-sdk.python.v0.1"

# The binding-version stamp every receipt from this binding carries. It must be a
# registered binding identity the shared emitter accepts.
BINDING_VERSION = "official-mcp-sdk.python.v0.1"

# The official SDK import root this binding targets, and the exact SDK version
# proven by the Phase 1 inventory (docs/OFFICIAL_MCP_SDK_BINDING.md).
SDK_IMPORT_ROOT = "mcp"
SDK_INVENTORY_VERSION = "1.29.0"

# The public interception seam used by this binding (handler registration on the
# lowlevel server — there is no FastMCP-style middleware API on it).
SDK_INTERCEPTION_SEAM = "mcp.server.lowlevel.Server.call_tool handler registration"

# The receipt-profile outcome tokens the shared emitter can stamp. Identical to
# the FastMCP mask's set because the *profile* — not the binding — owns them. This
# is the profile's capability, NOT this binding's: a token can be stampable by the
# profile yet not observable by this binding (see BINDING_UNSUPPORTED_OUTCOME_TOKENS).
BINDING_OUTCOME_TOKENS: frozenset[str] = frozenset(
    {
        "result_returned",
        "error_returned",
        "exception",
        "task_submitted",
        "indeterminate",
    }
)

# Profile outcome tokens this binding deliberately does NOT observe — an explicit
# binding capability difference, not a normalization. ``task_submitted`` is a
# genuine profile token (the FastMCP binding stamps it), but the official-SDK
# ``tools/call`` client seam cannot carry a ``CreateTaskResult`` (see the
# OUTCOME_MASK note below and docs/OFFICIAL_MCP_SDK_BINDING.md §"tasks"), so this
# binding fails closed rather than stamping it. Every member must be a real profile
# token (⊆ BINDING_OUTCOME_TOKENS) and must be classified ``unsupported`` in
# OUTCOME_MASK; verify_mask_matches_binding asserts both.
BINDING_UNSUPPORTED_OUTCOME_TOKENS: frozenset[str] = frozenset({"task_submitted"})

# The DAGR admission disposition tokens the shared emitter stamps in the
# ``disposition`` field (profile-owned; identical across bindings).
BINDING_DISPOSITION_TOKENS: frozenset[str] = frozenset(
    get_args(neutral.Disposition)
)

# --------------------------------------------------------------------------- #
# Mask entry model                                                            #
# --------------------------------------------------------------------------- #

# ``direct``     — the neutral event has a dedicated binding disposition/token.
# ``subsumed``   — the neutral event is observed onto another binding token
#                  (e.g. a raised timeout is recorded as an exception).
# ``unsupported``— the binding carries no dedicated observation for the event.
MappingStatus = Literal["direct", "subsumed", "unsupported"]


@dataclass(frozen=True, slots=True)
class BindingMaskEntry:
    """One neutral token's projection onto the official SDK binding."""

    neutral_token: str
    binding_token: str | None
    status: MappingStatus
    note: str


# --------------------------------------------------------------------------- #
# Admission dispositions                                                       #
# --------------------------------------------------------------------------- #

DISPOSITION_MASK: tuple[BindingMaskEntry, ...] = (
    BindingMaskEntry(
        "admitted", "admitted", "direct",
        "Admitted at the boundary; an admission receipt is written before the "
        "delegated tool dispatch for governed classes.",
    ),
    BindingMaskEntry(
        "refused", "refused", "direct",
        "A single terminal refused admission receipt; the adapter never calls "
        "the delegated tool and projects a transport-native error.",
    ),
    BindingMaskEntry(
        "deferred", "deferred_for_review", "direct",
        "A deferred admission receipt carrying review_object_ref and "
        "retry_contract='retry_after_approval'. The neutral name 'deferred' is "
        "the binding token 'deferred_for_review'.",
    ),
)

# Which neutral refusal grounds this binding reaches, and the reason_code it
# emits for each. Identical governance grounds to FastMCP (the grounds are the
# neutral core's, not a binding invention).
REFUSAL_GROUND_MASK: tuple[BindingMaskEntry, ...] = (
    BindingMaskEntry(
        "policy_refused", "policy_refused", "direct",
        "Explicit deny policy (also the default when a binding reason code is "
        "opaque/out-of-vocabulary; the opaque code is emitted verbatim).",
    ),
    BindingMaskEntry(
        "unknown_tool_fail_closed", "unknown_tool_fail_closed", "direct",
        "No policy resolves the tool; the binding fails closed.",
    ),
    BindingMaskEntry(
        "required_sink_unavailable", "required_sink_unavailable", "direct",
        "A required sink is unavailable at the pre-gate health check; preserved "
        "verbatim and never repaired into another ground.",
    ),
    BindingMaskEntry(
        "review_object_creation_failed", "review_object_creation_failed", "direct",
        "A configured review sink is present but raises during review-object "
        "creation. Not reachable via a missing review sink (that surfaces as "
        "required_sink_unavailable).",
    ),
)

# --------------------------------------------------------------------------- #
# Terminal outcomes                                                            #
# --------------------------------------------------------------------------- #

OUTCOME_MASK: tuple[BindingMaskEntry, ...] = (
    BindingMaskEntry(
        "result", "result_returned", "direct",
        "A mcp.types.CallToolResult with isError=False (or content/dict/tuple "
        "normalized to one); carries a result_digest over the four-member "
        "MCP tool-result projection.",
    ),
    BindingMaskEntry(
        "error", "error_returned", "direct",
        "A mcp.types.CallToolResult with isError=True; carries a result_digest. "
        "Includes the SDK's own conversion of a handler-raised exception into an "
        "isError result when the adapter did not observe the raise first.",
    ),
    BindingMaskEntry(
        "exception", "exception", "direct",
        "The delegated tool raised and the adapter observed it before the SDK "
        "wrapper converted it; extensions.mcp.exception_class carries the class "
        "name only. No result_digest.",
    ),
    BindingMaskEntry(
        "task_submitted", None, "unsupported",
        "Explicit binding capability difference. The mcp.types.CreateTaskResult "
        "type exists and the lowlevel Server.call_tool handler wraps a returned "
        "CreateTaskResult in a ServerResult, but the bound tools/call CLIENT seam "
        "(ClientSession.call_tool) hardcodes result_type=CallToolResult and "
        "validates the response against it; CallToolResult.content is required and "
        "a serialized CreateTaskResult has none, so the client raises a pydantic "
        "ValidationError. CreateTaskResult is genuinely received only through the "
        "SEPARATE, deprecated experimental tasks extension "
        "(ClientSession.experimental.call_tool_as_task, a task-augmented "
        "CallToolRequest parsed as CreateTaskResult). This binding therefore does "
        "not observe task_submitted through tools/call; the adapter fails closed "
        "and never coerces it into result/error. FastMCP task_submitted is "
        "unchanged (a genuine capability difference, not a normalization).",
    ),
    BindingMaskEntry(
        "timeout", "exception", "subsumed",
        "There is no dedicated SDK timeout state. A raised TimeoutError is an "
        "ordinary inner exception and is recorded as outcome='exception' with "
        "exception_class='TimeoutError' (frozen §14). Cooperative cancellation "
        "is a distinct path (see 'cancellation').",
    ),
    BindingMaskEntry(
        "cancellation", "indeterminate", "direct",
        "anyio/asyncio CancelledError (a BaseException that propagates past the "
        "SDK call_tool wrapper) maps to outcome='indeterminate' carrying the "
        "three cancellation governance Booleans. No result_digest.",
    ),
    BindingMaskEntry(
        "input_required", None, "unsupported",
        "The official SDK exposes elicitation (mcp.types.ElicitRequest/"
        "ElicitResult and UrlElicitationRequiredError), but the neutral contract "
        "marks input_required unsupported for this binding. The adapter fails "
        "explicitly and never normalizes it into result/error/exception.",
    ),
)

# The two neutral input_required modes, both unsupported, and the SDK shape each
# would have taken had the binding supported it (grounded in mcp).
INPUT_REQUIRED_MASK: tuple[BindingMaskEntry, ...] = (
    BindingMaskEntry(
        "continuable", None, "unsupported",
        "A resumable paused call — the SDK's session-driven elicitation "
        "(mcp.types.ElicitRequest/ElicitResult) — is not carried as a DAGR "
        "disposition. It fails explicitly rather than being coerced.",
    ),
    BindingMaskEntry(
        "interrupted", None, "unsupported",
        "A non-resumable paused call — the SDK's UrlElicitationRequiredError "
        "(protocol error -32042) — is not carried as a DAGR disposition. It "
        "fails explicitly rather than being coerced.",
    ),
)

# --------------------------------------------------------------------------- #
# Cancellation governance facts                                               #
# --------------------------------------------------------------------------- #
# All three are binding-owned Booleans that appear ONLY on the indeterminate
# outcome and must be Boolean-valued. Their field names are the shared emitter's.

CANCELLATION_FACT_MASK: tuple[BindingMaskEntry, ...] = (
    BindingMaskEntry(
        "request_cancelled", "request_cancelled", "direct",
        "Boolean, indeterminate-only.",
    ),
    BindingMaskEntry(
        "execution_state_unknown", "execution_state_unknown", "direct",
        "Boolean, indeterminate-only.",
    ),
    BindingMaskEntry(
        "delivery_incomplete", "delivery_incomplete", "direct",
        "Boolean, indeterminate-only. Deliberately not named with a "
        "result-shaped token so raw-content exclusion cannot mistake it for "
        "result material.",
    ),
)

# --------------------------------------------------------------------------- #
# Receipt cardinality and reference edges                                     #
# --------------------------------------------------------------------------- #
RECEIPT_CARDINALITY: dict[str, int] = dict(contract.RECEIPT_CARDINALITY)

OUTCOME_TO_ADMISSION_FIELD = "admission_receipt_ref"
PARENT_REFERENCE_FIELD = "parent_receipt_ref"

# --------------------------------------------------------------------------- #
# Custody observations and attestation limits                                 #
# --------------------------------------------------------------------------- #
CUSTODY_SCHEMA_VERSION: str = MCP_RECORD_CUSTODY_GATEWAY_SCHEMA
CUSTODY_STATUS_COUNT: int = len(tuple(GatewayCustodyStatus))
CUSTODY_BOUNDARY_TYPE_COUNT: int = len(tuple(GatewayBoundaryType))
CUSTODY_RECEIPT_FAMILY_COUNT: int = len(tuple(GatewayReceiptFamily))

# Concrete attestation-limit strings, read from the shared emitter, per neutral
# family. Identical to FastMCP's — the limits are profile-owned, not binding-owned.
ATTESTATION_LIMIT_MASK: dict[contract.AttestationLimitFamily, str] = {
    "base": srs_receipts.BASE_LIMIT,
    "result": srs_receipts.RESULT_LIMIT,
    "task": srs_receipts.TASK_LIMIT,
    "boundary": neutral.DEFAULT_BOUNDARY_LIMIT,
}

# --------------------------------------------------------------------------- #
# Argument / result digest responsibilities                                   #
# --------------------------------------------------------------------------- #
DIGEST_CANONICALIZATION: str = srs_receipts.CANONICALIZATION
# The four-member MCP tool-result projection this binding digests. Identical key
# order to the FastMCP projection so a result digest matches across bindings.
SDK_RESULT_PROJECTION_KEYS: tuple[str, ...] = (
    "content",
    "structuredContent",
    "_meta",
    "isError",
)

# --------------------------------------------------------------------------- #
# Protocol and binding stamps                                                 #
# --------------------------------------------------------------------------- #
PROTOCOL_STAMPS: dict[str, str] = {
    "protocol_binding": "mcp",
    "boundary_type": "mcp_tool_call",
    "receipt_type": "sdk_enforcement",
    "profile_id": srs_receipts.PROFILE_ID,
    "profile_version": srs_receipts.PROFILE_VERSION,
    "receipt_version": srs_receipts.RECEIPT_VERSION,
}
BINDING_STAMPS: dict[str, str] = {"binding_version": BINDING_VERSION}
SIGNATURE_STAMPS: dict[str, str] = {
    "algorithm": srs_receipts.SIGNATURE_ALGORITHM,
    "canonicalization": srs_receipts.CANONICALIZATION,
}

# --------------------------------------------------------------------------- #
# Protocol-stamp discipline                                                   #
# --------------------------------------------------------------------------- #
ProtocolStampStatus = Literal["pinned", "unsupported"]

OBSERVED_PROTOCOL_BINDING: str = "mcp"

# The negotiated MCP protocol version (from the initialize handshake) is not
# stamped by this binding, exactly as in the FastMCP binding.
NEGOTIATED_MCP_PROTOCOL_VERSION_STATUS: MappingStatus = "unsupported"

REJECTED_PROTOCOL_STAMP_FORMS: tuple[str, ...] = (
    "",
    "draft",
    "latest",
    "main",
    "dev",
    "snapshot",
    "unpinned",
    "mutable",
    "*",
    "any",
    "inferred",
)


def classify_protocol_stamp(stamp: str | None) -> ProtocolStampStatus:
    """Classify an observed protocol stamp against the binding's discipline."""

    if stamp == OBSERVED_PROTOCOL_BINDING:
        return "pinned"
    return "unsupported"


def assert_protocol_stamps_pinned() -> None:
    """Fail if any declared stamp is empty or a mutable/wildcard/draft form."""

    rejected = {form.lower() for form in REJECTED_PROTOCOL_STAMP_FORMS}
    for name, value in {**PROTOCOL_STAMPS, **BINDING_STAMPS}.items():
        assert value, (name, "empty protocol/binding stamp")
        assert value.lower() not in rejected, (name, value)

    assert PROTOCOL_STAMPS["protocol_binding"] == OBSERVED_PROTOCOL_BINDING
    assert "protocol_version" not in PROTOCOL_STAMPS
    assert "protocolVersion" not in PROTOCOL_STAMPS
    assert NEGOTIATED_MCP_PROTOCOL_VERSION_STATUS == "unsupported"

    assert classify_protocol_stamp(OBSERVED_PROTOCOL_BINDING) == "pinned"
    assert classify_protocol_stamp(None) == "unsupported"
    for bad in REJECTED_PROTOCOL_STAMP_FORMS:
        assert classify_protocol_stamp(bad) == "unsupported"


# --------------------------------------------------------------------------- #
# Projection helpers                                                           #
# --------------------------------------------------------------------------- #


def _entry_index(entries: tuple[BindingMaskEntry, ...]) -> dict[str, BindingMaskEntry]:
    return {entry.neutral_token: entry for entry in entries}


_DISPOSITION_INDEX = _entry_index(DISPOSITION_MASK)
_OUTCOME_INDEX = _entry_index(OUTCOME_MASK)
_CANCELLATION_INDEX = _entry_index(CANCELLATION_FACT_MASK)


def project_disposition(neutral_disposition: str) -> str:
    """Return the binding disposition token for a neutral disposition."""

    entry = _DISPOSITION_INDEX.get(neutral_disposition)
    if entry is None or entry.binding_token is None:
        raise KeyError(f"no binding disposition for neutral {neutral_disposition!r}")
    return entry.binding_token


def project_outcome(neutral_outcome: str) -> BindingMaskEntry:
    """Return the full mask entry for a neutral outcome (may be unsupported)."""

    entry = _OUTCOME_INDEX.get(neutral_outcome)
    if entry is None:
        raise KeyError(f"unknown neutral outcome {neutral_outcome!r}")
    return entry


def project_cancellation_fact(neutral_fact: str) -> str:
    """Return the binding field name for a neutral cancellation fact."""

    entry = _CANCELLATION_INDEX.get(neutral_fact)
    if entry is None or entry.binding_token is None:
        raise KeyError(f"no binding field for cancellation fact {neutral_fact!r}")
    return entry.binding_token


def unsigned_envelope(receipt: Mapping[str, Any]) -> dict[str, Any]:
    """Return the record with its signature block removed (Layer 3 preimage)."""

    return {k: v for k, v in receipt.items() if k != "receipt_signature"}


def unsigned_envelope_bytes(receipt: Mapping[str, Any]) -> bytes:
    """Return the exact RFC 8785 canonical bytes of the unsigned envelope."""

    return rfc8785.dumps(unsigned_envelope(receipt))


def normalized_projection(receipt: Mapping[str, Any]) -> dict[str, Any]:
    """Drop the Layer-2 permitted-volatile top-level fields from a record."""

    volatile = set(contract.PERMITTED_NORMALIZED_DIFFERENCE_FIELDS)
    return {k: v for k, v in receipt.items() if k not in volatile}


def normalized_projection_bytes(receipt: Mapping[str, Any]) -> bytes:
    """Return the RFC 8785 canonical bytes of the Layer-2 normalized projection."""

    return rfc8785.dumps(normalized_projection(receipt))


def strip_binding_stamp(receipt: Mapping[str, Any]) -> dict[str, Any]:
    """Remove ONLY this binding's identity stamp from a record.

    Removes ``extensions.mcp.binding_version`` (the single binding-specific stamp
    field, :data:`contract.BINDING_STAMP_FIELDS`) and nothing else. Used by the
    cross-binding conformance corpus to compare two bindings' unsigned bytes: the
    binding-version stamp is intentionally different, so it — and only it — is
    removed. This is not a broad "normalize everything" helper; it strips exactly
    the one documented, permitted difference.
    """

    out = {k: (dict(v) if isinstance(v, dict) else v) for k, v in receipt.items()}
    ext = out.get("extensions")
    if isinstance(ext, dict):
        ext = {k: (dict(v) if isinstance(v, dict) else v) for k, v in ext.items()}
        mcp_ext = ext.get("mcp")
        if isinstance(mcp_ext, dict):
            mcp_ext = dict(mcp_ext)
            mcp_ext.pop("binding_version", None)
            ext["mcp"] = mcp_ext
        out["extensions"] = ext
    return out


def custody_normalized_projection(projection: Mapping[str, Any]) -> dict[str, Any]:
    """Drop the custody permitted-volatile field (observed_at)."""

    volatile = set(contract.CUSTODY_PERMITTED_NORMALIZED_DIFFERENCE_FIELDS)
    return {k: v for k, v in projection.items() if k not in volatile}


# --------------------------------------------------------------------------- #
# Mapping totality                                                             #
# --------------------------------------------------------------------------- #


def verify_mapping_total(
    *,
    live_dispositions: set[str] | None = None,
    live_outcome_tokens: set[str] | None = None,
    live_cancellation_fields: set[str] | None = None,
    neutral_dispositions: tuple[str, ...] | None = None,
    neutral_outcomes: tuple[str, ...] | None = None,
    neutral_cancellation_facts: tuple[str, ...] | None = None,
) -> None:
    """Prove the mask is a total, duplicate-free classification.

    Every neutral disposition / outcome / cancellation fact is classified exactly
    once as ``direct``, ``subsumed``, or ``unsupported`` — no duplicates and no
    unclassified tokens — and every binding-side token this binding can stamp is
    represented. Defaults read the shared vocabulary/emitter oracle; keyword
    arguments let a test inject an augmented oracle to demonstrate the failure.
    """

    live_dispositions = (
        set(BINDING_DISPOSITION_TOKENS)
        if live_dispositions is None
        else set(live_dispositions)
    )
    live_outcome_tokens = (
        set(BINDING_OUTCOME_TOKENS)
        if live_outcome_tokens is None
        else set(live_outcome_tokens)
    )
    live_cancellation_fields = (
        set(srs_receipts.CANCELLATION_FIELD_NAMES)
        if live_cancellation_fields is None
        else set(live_cancellation_fields)
    )
    neutral_dispositions = neutral_dispositions or contract.NEUTRAL_DISPOSITIONS
    neutral_outcomes = neutral_outcomes or contract.NEUTRAL_OUTCOMES
    neutral_cancellation_facts = (
        neutral_cancellation_facts or contract.NEUTRAL_CANCELLATION_FACTS
    )

    valid_status = set(get_args(MappingStatus))

    def _partition(entries: tuple[BindingMaskEntry, ...], neutral: tuple[str, ...]) -> None:
        tokens = [e.neutral_token for e in entries]
        assert len(tokens) == len(set(tokens)), ("duplicate neutral token", tokens)
        assert set(tokens) == set(neutral), (set(tokens), set(neutral))
        for entry in entries:
            assert entry.status in valid_status, entry
            if entry.status == "unsupported":
                assert entry.binding_token is None, entry

    _partition(DISPOSITION_MASK, neutral_dispositions)
    _partition(OUTCOME_MASK, neutral_outcomes)
    _partition(CANCELLATION_FACT_MASK, neutral_cancellation_facts)

    direct_disposition_tokens = {
        e.binding_token
        for e in DISPOSITION_MASK
        if e.status == "direct" and e.binding_token is not None
    }
    assert direct_disposition_tokens == live_dispositions, (
        direct_disposition_tokens,
        live_dispositions,
    )

    # Every profile token this binding OBSERVES is covered exactly once, and the
    # only profile tokens it does not cover are the ones it explicitly marks
    # unsupported (BINDING_UNSUPPORTED_OUTCOME_TOKENS). The unsupported tokens must
    # be genuine profile tokens (⊆ live) and classified ``unsupported`` here.
    assert BINDING_UNSUPPORTED_OUTCOME_TOKENS <= live_outcome_tokens, (
        BINDING_UNSUPPORTED_OUTCOME_TOKENS,
        live_outcome_tokens,
    )
    # Each binding-unsupported profile token corresponds to an unsupported neutral
    # entry (the token name coincides with the neutral token by profile design).
    for token in BINDING_UNSUPPORTED_OUTCOME_TOKENS:
        entry = _OUTCOME_INDEX.get(token)
        assert entry is not None and entry.status == "unsupported", (token, entry)
    covered_outcome_tokens = {
        e.binding_token
        for e in OUTCOME_MASK
        if e.status in ("direct", "subsumed") and e.binding_token is not None
    }
    observed_outcome_tokens = live_outcome_tokens - BINDING_UNSUPPORTED_OUTCOME_TOKENS
    assert covered_outcome_tokens == observed_outcome_tokens, (
        covered_outcome_tokens,
        observed_outcome_tokens,
    )

    masked_cancellation_fields = {
        e.binding_token
        for e in CANCELLATION_FACT_MASK
        if e.binding_token is not None
    }
    assert masked_cancellation_fields == live_cancellation_fields, (
        masked_cancellation_fields,
        live_cancellation_fields,
    )


# --------------------------------------------------------------------------- #
# Drift guard                                                                  #
# --------------------------------------------------------------------------- #


def verify_mask_matches_binding() -> None:
    """Fail if the mask has drifted from the live binding / SDK / emitter oracle.

    Reads only from the shared emitter, the neutral vocabulary, and the installed
    official SDK (``mcp.types``), so it can never pass while lying.
    """

    # The mask's pinned target is this binding's version stamp, and that stamp is
    # a registered binding identity the shared emitter accepts.
    assert MASK_BINDING_TARGET == BINDING_VERSION
    assert BINDING_VERSION in srs_receipts.ALL_REGISTERED_BINDING_VERSIONS
    assert BINDING_VERSION in srs_receipts.ADDITIONAL_BINDING_VERSIONS
    # The stamp must NOT collide with the FastMCP binding's or the frozen A1 set.
    assert BINDING_VERSION not in srs_receipts.REGISTERED_BINDING_VERSIONS
    assert BINDING_VERSION != "fastmcp.middleware.v0.1"

    # Total, duplicate-free classification with full coverage, pinned stamps.
    verify_mapping_total()
    assert_protocol_stamps_pinned()

    # Dispositions: the direct binding tokens are exactly the shared DAGR
    # disposition vocabulary, and every neutral disposition is masked once.
    direct_disposition_tokens = {
        e.binding_token
        for e in DISPOSITION_MASK
        if e.status == "direct" and e.binding_token is not None
    }
    assert direct_disposition_tokens == set(BINDING_DISPOSITION_TOKENS)
    assert {e.neutral_token for e in DISPOSITION_MASK} == set(
        contract.NEUTRAL_DISPOSITIONS
    )

    # Outcomes: every mapped token is one the emitter can stamp; unsupported
    # entries carry no token; the neutral catalogue is masked once each.
    for entry in OUTCOME_MASK:
        if entry.status == "unsupported":
            assert entry.binding_token is None, entry
        else:
            assert entry.binding_token in BINDING_OUTCOME_TOKENS, entry
    assert {e.neutral_token for e in OUTCOME_MASK} == set(contract.NEUTRAL_OUTCOMES)

    # task_submitted is an explicit binding capability difference: it is a genuine
    # profile token (the emitter can stamp it, the FastMCP binding does) that this
    # binding does not observe, because the bound tools/call client seam cannot
    # carry a CreateTaskResult.
    assert BINDING_UNSUPPORTED_OUTCOME_TOKENS <= BINDING_OUTCOME_TOKENS
    assert "task_submitted" in BINDING_UNSUPPORTED_OUTCOME_TOKENS
    assert project_outcome("task_submitted").status == "unsupported"
    assert project_outcome("task_submitted").binding_token is None

    # input_required is unsupported in both neutral modes.
    assert {e.neutral_token for e in INPUT_REQUIRED_MASK} == set(
        contract.INPUT_REQUIRED_MODES
    )
    assert all(e.status == "unsupported" for e in INPUT_REQUIRED_MASK)
    assert project_outcome("input_required").status == "unsupported"

    # Cancellation facts agree with the shared emitter registry.
    assert {e.neutral_token for e in CANCELLATION_FACT_MASK} == set(
        contract.NEUTRAL_CANCELLATION_FACTS
    )
    masked_fields = {
        e.binding_token for e in CANCELLATION_FACT_MASK if e.binding_token is not None
    }
    assert masked_fields == set(srs_receipts.CANCELLATION_FIELD_NAMES)

    # Attestation-limit strings are identity-equal to the shared constants.
    assert ATTESTATION_LIMIT_MASK["base"] == srs_receipts.BASE_LIMIT
    assert ATTESTATION_LIMIT_MASK["result"] == srs_receipts.RESULT_LIMIT
    assert ATTESTATION_LIMIT_MASK["task"] == srs_receipts.TASK_LIMIT
    assert ATTESTATION_LIMIT_MASK["boundary"] == neutral.DEFAULT_BOUNDARY_LIMIT

    # Grounding in the actually-installed official SDK: the shapes this mask maps
    # onto exist in mcp.types. A CallToolResult carries isError (result/error
    # discrimination); ElicitResult proves elicitation IS available yet is
    # deliberately unsupported.
    assert "isError" in mcp_types.CallToolResult.model_fields
    assert hasattr(mcp_types, "ElicitResult")

    # Grounding for the task_submitted capability difference. The CreateTaskResult
    # TYPE exists (so the mask names a real shape), but the bound tools/call client
    # seam cannot carry it: CallToolResult.content is REQUIRED and CreateTaskResult
    # has no content field, so ClientSession.call_tool's
    # CallToolResult.model_validate(response) raises on a CreateTaskResult. This is
    # the exact byte-fact that makes task_submitted unobservable through tools/call.
    assert hasattr(mcp_types, "CreateTaskResult")
    assert mcp_types.CallToolResult.model_fields["content"].is_required()
    assert "content" not in mcp_types.CreateTaskResult.model_fields


__all__ = [
    "MASK_ID",
    "MASK_VERSION",
    "MASK_BINDING_TARGET",
    "BINDING_VERSION",
    "SDK_IMPORT_ROOT",
    "SDK_INVENTORY_VERSION",
    "SDK_INTERCEPTION_SEAM",
    "BINDING_OUTCOME_TOKENS",
    "BINDING_UNSUPPORTED_OUTCOME_TOKENS",
    "BINDING_DISPOSITION_TOKENS",
    "MappingStatus",
    "BindingMaskEntry",
    "DISPOSITION_MASK",
    "REFUSAL_GROUND_MASK",
    "OUTCOME_MASK",
    "INPUT_REQUIRED_MASK",
    "CANCELLATION_FACT_MASK",
    "RECEIPT_CARDINALITY",
    "OUTCOME_TO_ADMISSION_FIELD",
    "PARENT_REFERENCE_FIELD",
    "CUSTODY_SCHEMA_VERSION",
    "CUSTODY_STATUS_COUNT",
    "CUSTODY_BOUNDARY_TYPE_COUNT",
    "CUSTODY_RECEIPT_FAMILY_COUNT",
    "ATTESTATION_LIMIT_MASK",
    "DIGEST_CANONICALIZATION",
    "SDK_RESULT_PROJECTION_KEYS",
    "PROTOCOL_STAMPS",
    "BINDING_STAMPS",
    "SIGNATURE_STAMPS",
    "ProtocolStampStatus",
    "OBSERVED_PROTOCOL_BINDING",
    "NEGOTIATED_MCP_PROTOCOL_VERSION_STATUS",
    "REJECTED_PROTOCOL_STAMP_FORMS",
    "classify_protocol_stamp",
    "assert_protocol_stamps_pinned",
    "project_disposition",
    "project_outcome",
    "project_cancellation_fact",
    "unsigned_envelope",
    "unsigned_envelope_bytes",
    "normalized_projection",
    "normalized_projection_bytes",
    "strip_binding_stamp",
    "custody_normalized_projection",
    "verify_mapping_total",
    "verify_mask_matches_binding",
]
