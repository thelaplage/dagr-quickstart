"""The explicit ``fastmcp.middleware.v0.1`` mask over the neutral contract.

This module maps the existing, unmodified FastMCP binding onto the neutral
lifecycle vocabulary declared in :mod:`dagr_mcp_lifecycle.contract`. It is a
*mask*: it describes what the binding does, in neutral terms, and it never
normalizes, repairs, or changes the binding.

The binding remains the oracle. Every binding-side value the mask names is read
back from the live ``dagr_mcp.fastmcp_binding`` / ``dagr_mcp.srs_receipts``
modules (or verified against an emitted receipt in the tests), so the mask
cannot silently drift away from the binding. :func:`verify_mask_matches_binding`
is the drift guard the tests call.

Nothing here emits a receipt, moves binding code, or introduces a second
binding.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Mapping, get_args

import rfc8785

from dagr_mcp import fastmcp_binding, srs_receipts
from dagr_mcp.mcp_record_custody_gateway import (
    MCP_RECORD_CUSTODY_GATEWAY_SCHEMA,
    GatewayBoundaryType,
    GatewayCustodyStatus,
    GatewayReceiptFamily,
)
from dagr_mcp_lifecycle import contract

MASK_ID = "dagr.mcp.lifecycle_binding_mask"
MASK_VERSION = "v0.1"

# The exact, pinned binding this mask is written against. It is spelled out
# here as an explicit identifier so the mask can never be read as describing an
# unpinned/"latest" binding. ``verify_mask_matches_binding`` asserts it is the
# live binding version, so this literal cannot drift from the oracle.
MASK_BINDING_TARGET = "fastmcp.middleware.v0.1"

# The binding this mask describes. Read from the live binding module.
BINDING_VERSION: str = fastmcp_binding.BINDING_VERSION
TASK_RESULT_IMPORT_PATH: str = fastmcp_binding.CREATE_TASK_RESULT_IMPORT_PATH

# The complete set of outcome tokens the emitter can stamp. The mask declares
# it; ``verify_mask_matches_binding`` and the tests confirm the live emitter
# produces exactly these and no others.
BINDING_OUTCOME_TOKENS: frozenset[str] = frozenset(
    {
        "result_returned",
        "error_returned",
        "exception",
        "task_submitted",
        "indeterminate",
    }
)

# --------------------------------------------------------------------------- #
# Mask entry model                                                            #
# --------------------------------------------------------------------------- #

# ``direct``     — the neutral event has a dedicated binding disposition/token.
# ``subsumed``   — the neutral event is observed, but onto another binding token
#                  rather than a dedicated one (e.g. a raised timeout is recorded
#                  as an exception).
# ``unsupported``— the binding has no observation for the neutral event; it
#                  carries no dedicated token and would not be distinctly
#                  recognized.
MappingStatus = Literal["direct", "subsumed", "unsupported"]


@dataclass(frozen=True, slots=True)
class BindingMaskEntry:
    """One neutral token's projection onto the FastMCP binding."""

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
        "Admitted at the boundary; an admission receipt is written before "
        "execution for governed classes.",
    ),
    BindingMaskEntry(
        "refused", "refused", "direct",
        "A single terminal refused admission receipt; the binding raises "
        "ToolError and the inner handler never runs.",
    ),
    BindingMaskEntry(
        "deferred", "deferred_for_review", "direct",
        "A deferred admission receipt carrying review_object_ref and "
        "retry_contract='retry_after_approval'. The neutral name 'deferred' is "
        "the binding token 'deferred_for_review'.",
    ),
)

# Which neutral refusal grounds the FastMCP binding actually reaches, and the
# binding reason_code it emits for each.
REFUSAL_GROUND_MASK: tuple[BindingMaskEntry, ...] = (
    BindingMaskEntry(
        "policy_refused", "policy_refused", "direct",
        "Explicit deny policy.",
    ),
    BindingMaskEntry(
        "unknown_tool_fail_closed", "unknown_tool_fail_closed", "direct",
        "No policy resolves the tool; the binding fails closed.",
    ),
    BindingMaskEntry(
        "required_sink_unavailable", "required_sink_unavailable", "direct",
        "A required sink — including a review sink made effectively required by "
        "a review_required gate — is unavailable at the pre-gate health check.",
    ),
    BindingMaskEntry(
        "review_object_creation_failed", "review_object_creation_failed", "direct",
        "A configured review sink is present but raises during review-object "
        "creation. Not reachable via a missing review sink; that surfaces as "
        "required_sink_unavailable.",
    ),
)

# --------------------------------------------------------------------------- #
# Terminal outcomes                                                            #
# --------------------------------------------------------------------------- #

OUTCOME_MASK: tuple[BindingMaskEntry, ...] = (
    BindingMaskEntry(
        "result", "result_returned", "direct",
        "A ToolResult with isError=False; carries a result_digest.",
    ),
    BindingMaskEntry(
        "error", "error_returned", "direct",
        "A ToolResult with isError=True; carries a result_digest.",
    ),
    BindingMaskEntry(
        "exception", "exception", "direct",
        "The inner handler raised; extensions.mcp.exception_class carries the "
        "class name only. No result_digest.",
    ),
    BindingMaskEntry(
        "task_submitted", "task_submitted", "direct",
        f"The result is a {TASK_RESULT_IMPORT_PATH}; submission only, no "
        "execution or completion claim. No result_digest.",
    ),
    BindingMaskEntry(
        "timeout", "exception", "subsumed",
        "There is no dedicated timeout disposition. A raised TimeoutError is an "
        "ordinary inner exception and is recorded as outcome='exception' with "
        "exception_class='TimeoutError'. Cooperative cancellation is a distinct "
        "path (see 'cancellation').",
    ),
    BindingMaskEntry(
        "cancellation", "indeterminate", "direct",
        "asyncio.CancelledError maps to outcome='indeterminate' carrying the "
        "three cancellation governance Booleans. No result_digest.",
    ),
    BindingMaskEntry(
        "input_required", None, "unsupported",
        "The binding has no elicitation / continuation branch. It carries no "
        "dedicated disposition for a paused call, in either the continuable or "
        "interrupted mode.",
    ),
)

# The two neutral input_required modes, both unsupported by this binding.
INPUT_REQUIRED_MASK: tuple[BindingMaskEntry, ...] = (
    BindingMaskEntry(
        "continuable", None, "unsupported",
        "A resumable paused call is not distinctly observed. Any object the "
        "boundary happens to return as a ToolResult would be masked by its "
        "isError flag as result_returned / error_returned, not as a "
        "continuation.",
    ),
    BindingMaskEntry(
        "interrupted", None, "unsupported",
        "A non-resumable paused call is not distinctly observed by the binding.",
    ),
)

# --------------------------------------------------------------------------- #
# Cancellation governance facts                                               #
# --------------------------------------------------------------------------- #
# All three are binding-owned Booleans that appear ONLY on the indeterminate
# outcome and must be Boolean-valued.

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
# The binding's observable cardinality per disposition (mirrors the neutral
# contract; the tests ground it against the behavioral-freeze fixtures).
RECEIPT_CARDINALITY: dict[str, int] = dict(contract.RECEIPT_CARDINALITY)

# Binding field names carrying the reference edges.
OUTCOME_TO_ADMISSION_FIELD = "admission_receipt_ref"
PARENT_REFERENCE_FIELD = "parent_receipt_ref"

# --------------------------------------------------------------------------- #
# Custody observations and attestation limits                                 #
# --------------------------------------------------------------------------- #
# The custody-gateway projection carries the non-claim / exclusion posture. The
# mask binds the neutral flag names to the concrete gateway fields (which are
# identically named) and pins the vocabulary sizes against the gateway module.
CUSTODY_SCHEMA_VERSION: str = MCP_RECORD_CUSTODY_GATEWAY_SCHEMA
CUSTODY_STATUS_COUNT: int = len(tuple(GatewayCustodyStatus))
CUSTODY_BOUNDARY_TYPE_COUNT: int = len(tuple(GatewayBoundaryType))
CUSTODY_RECEIPT_FAMILY_COUNT: int = len(tuple(GatewayReceiptFamily))

# Concrete attestation-limit strings, read from the binding, per neutral family.
ATTESTATION_LIMIT_MASK: dict[contract.AttestationLimitFamily, str] = {
    "base": srs_receipts.BASE_LIMIT,
    "result": srs_receipts.RESULT_LIMIT,
    "task": srs_receipts.TASK_LIMIT,
    "boundary": fastmcp_binding.DEFAULT_BOUNDARY_LIMIT,
}

# --------------------------------------------------------------------------- #
# Argument / result digest responsibilities                                   #
# --------------------------------------------------------------------------- #
DIGEST_CANONICALIZATION: str = srs_receipts.CANONICALIZATION
FASTMCP_RESULT_PROJECTION_KEYS: tuple[str, ...] = (
    "content",
    "structuredContent",
    "_meta",
    "isError",
)

# --------------------------------------------------------------------------- #
# Protocol and binding stamps                                                 #
# --------------------------------------------------------------------------- #
# Values read from the binding constants where they exist. The three inline
# literals the emitter writes in ``_common`` (protocol_binding / boundary_type /
# receipt_type) are declared here and verified against an emitted receipt by the
# tests, so this table cannot drift from the bytes the emitter produces.
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
# The binding observably stamps exactly one protocol identifier: the pinned
# protocol-binding token ``mcp`` (``PROTOCOL_STAMPS["protocol_binding"]``). It
# does NOT observe the MCP ``initialize`` handshake's negotiated
# ``protocolVersion`` anywhere, so the mask declares the negotiated MCP protocol
# *version* ``unsupported`` rather than inventing a version the binding cannot
# observe. Only an exact, observable, pinned identifier is ever treated as a
# valid protocol stamp; every empty / draft / latest / wildcard / inferred form
# is classified ``unsupported``.

ProtocolStampStatus = Literal["pinned", "unsupported"]

# The exact observable protocol identifier the binding pins on every record.
OBSERVED_PROTOCOL_BINDING: str = "mcp"

# The negotiated MCP protocol version is not observed by this binding.
NEGOTIATED_MCP_PROTOCOL_VERSION_STATUS: MappingStatus = "unsupported"

# Stamp forms that are never a valid pinned protocol identifier. An observed
# stamp equal (case-insensitively) to any of these — or empty, or ``None`` — is
# classified ``unsupported`` and must never be minted onto a record.
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
    """Classify an observed protocol stamp against the binding's discipline.

    Returns ``"pinned"`` only for the exact observable identifier the binding
    stamps. Every empty, draft, latest, wildcard, inferred, or otherwise
    unknown stamp — including ``None`` — is ``"unsupported"``: the binding
    cannot observe it, so the mask refuses to treat it as a pinned protocol
    identifier.
    """

    if stamp == OBSERVED_PROTOCOL_BINDING:
        return "pinned"
    return "unsupported"


def assert_protocol_stamps_pinned() -> None:
    """Fail if any declared stamp is empty or a mutable/wildcard/draft form.

    Every value in :data:`PROTOCOL_STAMPS` and :data:`BINDING_STAMPS` must be a
    non-empty, pinned identifier. The exact protocol-binding token classifies as
    ``pinned`` and every rejected form (and ``None``) classifies as
    ``unsupported``. The binding invents no MCP protocol version, so no
    ``protocol_version`` field is declared.
    """

    rejected = {form.lower() for form in REJECTED_PROTOCOL_STAMP_FORMS}
    for name, value in {**PROTOCOL_STAMPS, **BINDING_STAMPS}.items():
        assert value, (name, "empty protocol/binding stamp")
        assert value.lower() not in rejected, (name, value)

    # The declared protocol-binding stamp is the exact observable identifier.
    assert PROTOCOL_STAMPS["protocol_binding"] == OBSERVED_PROTOCOL_BINDING

    # No invented MCP protocol version: the mask declares none and treats the
    # negotiated version as unsupported.
    assert "protocol_version" not in PROTOCOL_STAMPS
    assert "protocolVersion" not in PROTOCOL_STAMPS
    assert NEGOTIATED_MCP_PROTOCOL_VERSION_STATUS == "unsupported"

    # The classifier accepts only the exact observable stamp.
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
    """Drop the Layer-2 permitted-volatile fields from a record."""

    volatile = set(contract.PERMITTED_NORMALIZED_DIFFERENCE_FIELDS)
    return {k: v for k, v in receipt.items() if k not in volatile}


def normalized_projection_bytes(receipt: Mapping[str, Any]) -> bytes:
    """Return the RFC 8785 canonical bytes of the Layer-2 normalized projection."""

    return rfc8785.dumps(normalized_projection(receipt))


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

    * Every neutral disposition / outcome / cancellation fact is classified
      **exactly once** as ``direct``, ``subsumed``, or ``unsupported`` — no
      duplicates and no unclassified tokens.
    * Every binding-side disposition, outcome, and governance token visible in
      the A1 oracle is **represented** by a mask entry.

    Defaults read the live binding oracle
    (``fastmcp_binding.Disposition`` / :data:`BINDING_OUTCOME_TOKENS` /
    ``srs_receipts.CANCELLATION_FIELD_NAMES``) and the frozen neutral vocabulary,
    so adding a token to *either* side fails this check until it is classified.
    The keyword arguments exist so a test can inject an augmented oracle and
    demonstrate that failure without mutating the live modules.
    """

    live_dispositions = (
        set(get_args(fastmcp_binding.Disposition))
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
        # Exactly once: no duplicate neutral token.
        assert len(tokens) == len(set(tokens)), ("duplicate neutral token", tokens)
        # No unclassified neutral token, and no mask entry for a phantom token.
        assert set(tokens) == set(neutral), (set(tokens), set(neutral))
        # Every entry carries a valid classification.
        for entry in entries:
            assert entry.status in valid_status, entry
            if entry.status == "unsupported":
                assert entry.binding_token is None, entry

    _partition(DISPOSITION_MASK, neutral_dispositions)
    _partition(OUTCOME_MASK, neutral_outcomes)
    _partition(CANCELLATION_FACT_MASK, neutral_cancellation_facts)

    # Binding coverage — every live disposition token is represented.
    direct_disposition_tokens = {
        e.binding_token
        for e in DISPOSITION_MASK
        if e.status == "direct" and e.binding_token is not None
    }
    assert direct_disposition_tokens == live_dispositions, (
        direct_disposition_tokens,
        live_dispositions,
    )

    # Binding coverage — every live outcome token is represented (direct or
    # subsumed), and no mapped entry names a token the emitter cannot stamp.
    covered_outcome_tokens = {
        e.binding_token
        for e in OUTCOME_MASK
        if e.status in ("direct", "subsumed") and e.binding_token is not None
    }
    assert covered_outcome_tokens == live_outcome_tokens, (
        covered_outcome_tokens,
        live_outcome_tokens,
    )

    # Binding coverage — every governance (cancellation) field is represented.
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
    """Fail if the mask has drifted from the live binding oracle.

    Raises :class:`AssertionError` on any drift. The tests call this; it reads
    only from the live binding modules, so it can never pass while lying about
    the binding.
    """

    # The mask's pinned target is the live binding version (no unpinned target).
    assert MASK_BINDING_TARGET == fastmcp_binding.BINDING_VERSION, (
        MASK_BINDING_TARGET,
        fastmcp_binding.BINDING_VERSION,
    )

    # The mapping is a total, duplicate-free classification with full binding
    # coverage, and the protocol stamps are pinned with no invented version.
    verify_mapping_total()
    assert_protocol_stamps_pinned()

    # Dispositions: the direct binding tokens are exactly the binding's
    # Disposition Literal members.
    live_dispositions = set(get_args(fastmcp_binding.Disposition))
    direct_disposition_tokens = {
        e.binding_token
        for e in DISPOSITION_MASK
        if e.status == "direct" and e.binding_token is not None
    }
    assert direct_disposition_tokens == live_dispositions, (
        direct_disposition_tokens,
        live_dispositions,
    )

    # Every neutral disposition is masked exactly once.
    assert {e.neutral_token for e in DISPOSITION_MASK} == set(
        contract.NEUTRAL_DISPOSITIONS
    )

    # Outcomes: every mapped (direct or subsumed) binding token is one the
    # emitter can actually stamp; unsupported entries carry no token.
    for entry in OUTCOME_MASK:
        if entry.status == "unsupported":
            assert entry.binding_token is None, entry
        else:
            assert entry.binding_token in BINDING_OUTCOME_TOKENS, entry

    # The neutral outcome catalogue is masked exactly once each.
    assert {e.neutral_token for e in OUTCOME_MASK} == set(contract.NEUTRAL_OUTCOMES)

    # input_required is unsupported in both neutral modes.
    assert {e.neutral_token for e in INPUT_REQUIRED_MASK} == set(
        contract.INPUT_REQUIRED_MODES
    )
    assert all(e.status == "unsupported" for e in INPUT_REQUIRED_MASK)
    assert project_outcome("input_required").status == "unsupported"

    # Cancellation facts: neutral names and binding field names both agree with
    # the emitter's registry.
    assert {e.neutral_token for e in CANCELLATION_FACT_MASK} == set(
        contract.NEUTRAL_CANCELLATION_FACTS
    )
    masked_fields = {
        e.binding_token for e in CANCELLATION_FACT_MASK if e.binding_token is not None
    }
    assert masked_fields == set(srs_receipts.CANCELLATION_FIELD_NAMES), (
        masked_fields,
        srs_receipts.CANCELLATION_FIELD_NAMES,
    )

    # Binding version stamp is the live binding version and is registered.
    assert BINDING_STAMPS["binding_version"] == fastmcp_binding.BINDING_VERSION
    assert BINDING_VERSION in srs_receipts.REGISTERED_BINDING_VERSIONS

    # Attestation-limit strings are identity-equal to the binding constants.
    assert ATTESTATION_LIMIT_MASK["base"] == srs_receipts.BASE_LIMIT
    assert ATTESTATION_LIMIT_MASK["result"] == srs_receipts.RESULT_LIMIT
    assert ATTESTATION_LIMIT_MASK["task"] == srs_receipts.TASK_LIMIT
    assert ATTESTATION_LIMIT_MASK["boundary"] == fastmcp_binding.DEFAULT_BOUNDARY_LIMIT

    # Result-projection key order matches the binding's projection function.
    assert (
        tuple(fastmcp_binding.project_fastmcp_tool_result(_NullResult()).keys())
        == FASTMCP_RESULT_PROJECTION_KEYS
    )


class _NullResult:
    """Minimal stand-in used only to read the binding projection key order."""

    content: tuple[Any, ...] = ()
    structured_content = None
    meta = None
    is_error = False


__all__ = [
    "MASK_ID",
    "MASK_VERSION",
    "MASK_BINDING_TARGET",
    "BINDING_VERSION",
    "TASK_RESULT_IMPORT_PATH",
    "BINDING_OUTCOME_TOKENS",
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
    "FASTMCP_RESULT_PROJECTION_KEYS",
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
    "custody_normalized_projection",
    "verify_mapping_total",
    "verify_mask_matches_binding",
]
