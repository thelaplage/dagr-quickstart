"""Receipt-handle resolution and composition seam (Sprint A10).

Scope: ``docs/GATEWAY_SERVICE_ADAPTER_SCOPE.md`` §9 (receipt/verification
topology), §13 (``access.py``), work package A10. This module resolves a
:class:`dagr_mcp_service.contract.ReceiptHandle` returned by A8/A9's
``execute_governed_call`` back to the *exact* existing signed receipt
envelope an operator-configured receipt source durably holds, verifies it
with the repository's own parse/schema/signature discipline, and composes a
verified admission/outcome pair into an in-memory, service-layer result.

**No new receipt family.** This module never signs, mints, rewrites, or
repairs a receipt. It only reads bytes an existing
:class:`dagr_mcp.srs_receipts.SignedReceiptEmitter` already durably wrote
(through :class:`dagr_mcp.srs_receipts.RawEnvelopeFileSink` or an
operator-supplied equivalent) and verifies them with the exact profile
constants (:data:`dagr_mcp.srs_receipts.RECEIPT_VERSION`,
:data:`~dagr_mcp.srs_receipts.PROFILE_ID`,
:data:`~dagr_mcp.srs_receipts.PROFILE_VERSION`) and raw-content discipline
(:func:`dagr_mcp.srs_receipts.enforce_raw_content_exclusion`) the emitter
itself already enforces at write time. The result this module returns is a
plain, in-memory dataclass — never a second signed envelope.

**Narrowest provider seam, not a general storage API.**
:class:`ReceiptByteProvider` receives only a complete
:class:`~dagr_mcp_service.contract.ReceiptHandle` plus already-resolved,
already-trusted actor/tenant/request refs (never a caller-supplied path,
filename, URI, signer, key, or credential) and returns immutable bytes or
raises one of two narrow, content-free exceptions
(:class:`ReceiptNotFound`, :class:`ReceiptSourceUnavailable`).
:class:`FilesystemReceiptSource` is the one concrete provider this module
ships: it reads the existing ``RawEnvelopeFileSink`` on-disk layout without
widening that sink's own public write API (no read method is added to
:class:`~dagr_mcp.srs_receipts.RawEnvelopeFileSink` itself) and without
accepting a caller-suppliable path — the on-disk filename is always
re-derived from the requested ``receipt_id`` using the identical
sanitization the sink already applies at write time, confined to one
resolved root directory, opened with ``O_NOFOLLOW`` so a planted symlink at
the exact expected filename cannot redirect a read outside that root.

**Handle-only by default; inline access is a separate, operator-invoked
operation.** Nothing in this module is reachable from a caller's tool
arguments or from :class:`~dagr_mcp_service.contract.CallerGovernedCallRequest`.
:func:`execute_governed_call` (A8/A9) is completely unmodified by this
lane and continues to return handle-only responses. An operator/deployment
that wants receipt content calls :func:`resolve_receipt` or
:func:`compose_receipts` (or the convenience wrapper
:func:`access_governed_call_receipts`) itself, after
``execute_governed_call`` returns — never as a side effect of the governed
call itself, and never gated by anything a model or tool caller can set.

**Unresolved authorization posture.** Per the governing scope document's
hard authority gate, this repository ratifies no cross-tenant receipt-access
authorization system and no wire format for presenting actor/tenant
identity to a receipt-access boundary. This module therefore does not claim
to *authorize* access at all — it enforces *structural consistency* between
whatever already-trusted ``actor_ref``/``tenant_ref`` the calling service
passes in :class:`ReceiptAccessContext` (derived the same way A8 already
derives them — from a transport/auth context, never from a tool argument or
receipt-handle text) and the envelope's own ``actor_ref``/``tenant_id``
fields, when both sides are present. Fail-closed on a mismatch; silent when
one side has nothing to check. A configured
:class:`ReceiptAccessConfig` may additionally *require* actor/tenant context
to be present at all (``require_actor_context``/``require_tenant_context``)
so a deployment that needs one is never silently skipped — but requiring it
is an operator opt-in, not a claim that this constitutes a ratified
authorization system.

**Import discipline.** Importing this module (or ``dagr_mcp_service``) opens
no file and starts no transport. ``cryptography`` and ``rfc8785`` are
already base dependencies of this package (used for signing since A1); this
module adds no new dependency — schema/profile conformance is checked with a
narrow, hand-written structural check against the exact fields
:mod:`dagr_mcp.srs_receipts`'s emitter already writes, not a general JSON
Schema validator (the ``jsonschema`` package remains a ``dev``-only
dependency; the repository's actual JSON Schema/profile conformance is
proved out-of-band by the independent ``arcs-verify`` project against the
identical envelope this module returns).
"""

from __future__ import annotations

import copy
import json
import os
import re
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Protocol

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from types import MappingProxyType

from dagr_mcp.srs_receipts import (
    PROFILE_ID,
    PROFILE_VERSION,
    RECEIPT_VERSION,
    ReceiptContentError,
    enforce_raw_content_exclusion,
)
from dagr_mcp_service.contract import GovernedCallResponse, ReceiptHandle

# --------------------------------------------------------------------------- #
# Closed diagnostic vocabulary (§9's "diagnostics" requirement)               #
# --------------------------------------------------------------------------- #

ReceiptAccessDiagnosticCode = Literal[
    "unknown_handle",
    "receipt_unavailable",
    "malformed_envelope",
    "schema_failure",
    "signature_failure",
    "identifier_mismatch",
    "family_mismatch",
    "association_mismatch",
    "access_unauthorized",
    "provider_failure",
]
RECEIPT_ACCESS_DIAGNOSTIC_CODES: tuple[ReceiptAccessDiagnosticCode, ...] = (
    "unknown_handle",
    "receipt_unavailable",
    "malformed_envelope",
    "schema_failure",
    "signature_failure",
    "identifier_mismatch",
    "family_mismatch",
    "association_mismatch",
    "access_unauthorized",
    "provider_failure",
)


# --------------------------------------------------------------------------- #
# Provider seam                                                               #
# --------------------------------------------------------------------------- #


class ReceiptSourceError(Exception):
    """Base class for a content-free, narrow receipt-source failure.

    Never carries the raw underlying exception's message on its own — call
    sites in this module translate any provider-raised exception (this
    class or otherwise) into a closed :data:`ReceiptAccessDiagnosticCode`
    without propagating exception text into a result.
    """


class ReceiptNotFound(ReceiptSourceError):
    """The configured source holds no receipt for this identifier.

    Also the correct exception for "found something at that location but it
    is not usable as a receipt" (a directory, a special file, a symlink that
    could not be safely followed) — a provider should never distinguish
    those cases from genuine absence, since the distinction itself would
    leak information about what does or does not exist at the source.
    """


class ReceiptSourceUnavailable(ReceiptSourceError):
    """The configured source recognizes the identifier but cannot serve it
    right now (e.g. a remote storage backend timeout).

    :class:`FilesystemReceiptSource` never raises this — a local read either
    succeeds or the receipt is treated as absent (:class:`ReceiptNotFound`).
    This exception exists for a future, genuinely remote provider that can
    honestly distinguish "temporarily unavailable" from "does not exist".
    """


class ReceiptByteProvider(Protocol):
    """The narrowest operator-controlled receipt-access provider seam.

    Receives only the complete, already-constructed
    :class:`~dagr_mcp_service.contract.ReceiptHandle` plus already-resolved,
    already-trusted refs — never a caller-supplied path, filename, URI
    scheme, signer, private key, or credential. Returns one immutable bytes
    snapshot, or raises :class:`ReceiptNotFound`/:class:`ReceiptSourceUnavailable`.
    """

    def fetch(
        self,
        handle: ReceiptHandle,
        *,
        actor_ref: str | None,
        tenant_ref: str | None,
        request_ref: str | None,
    ) -> bytes: ...


_FILENAME_SANITIZE_RE = re.compile(r"[^A-Za-z0-9._-]+")


class FilesystemReceiptSource:
    """Reads receipts durably written by ``RawEnvelopeFileSink``, confined to
    one operator-configured root directory.

    Never accepts a caller-suppliable path: the on-disk filename this class
    looks for is always re-derived from the requested ``receipt_id`` using
    the identical sanitization
    :meth:`dagr_mcp.srs_receipts.RawEnvelopeFileSink.write` already applies
    at write time (replace every character outside
    ``[A-Za-z0-9._-]`` with ``_``, then append ``.json``). Because that
    substitution removes every path separator, the derived name is always a
    single path component directly under the configured root — there is no
    substring of any ``receipt_id`` that can traverse to a parent directory,
    reach an absolute path, or otherwise escape the root, and the resulting
    name can never equal exactly ``..`` or ``.`` (it always ends in the
    literal suffix ``.json``).

    Two different ``receipt_id`` values can in principle sanitize to the
    same filename (the sink's own write-side naming scheme, unmodified by
    this class, already has this property). This class does not try to
    resolve that ambiguity itself — it opens whatever file the sanitized
    name names and returns its bytes; the caller's own
    :func:`resolve_receipt` always separately verifies the parsed envelope's
    *own* ``receipt_id`` field against the requested handle, so a filename
    collision can never be mistaken for a correct resolution: it fails
    closed as ``identifier_mismatch`` instead.

    Opens the final path component with ``O_NOFOLLOW`` (where the platform
    supports it), so a symlink planted at the exact expected filename cannot
    redirect a read outside the configured root — the check and the open
    happen atomically as one syscall, not as a separate stat-then-open that
    a concurrent replacement could race. Rejects anything that is not a
    plain regular file (a directory or special file opened this way fails
    closed as :class:`ReceiptNotFound`, never raised as a distinguishable
    error). Reads the entire file in one pass into one immutable ``bytes``
    object and closes the descriptor before returning; nothing is read from
    disk a second time by this class or by any of this module's callers.
    """

    def __init__(self, root: Path) -> None:
        resolved = Path(root).resolve(strict=True)
        if not resolved.is_dir():
            raise ValueError(f"FilesystemReceiptSource root is not a directory: {root!r}")
        self._root = resolved

    def fetch(
        self,
        handle: ReceiptHandle,
        *,
        actor_ref: str | None,
        tenant_ref: str | None,
        request_ref: str | None,
    ) -> bytes:
        # This provider's storage layout is not tenant/actor-partitioned in
        # this repository; the refs are accepted (matching the shared
        # ReceiptByteProvider protocol) and intentionally unused here.
        del actor_ref, tenant_ref, request_ref

        filename = _FILENAME_SANITIZE_RE.sub("_", handle.receipt_id) + ".json"
        candidate = self._root / filename
        if candidate.parent != self._root:
            raise ReceiptNotFound(  # pragma: no cover - structurally unreachable; defensive.
                "receipt handle does not resolve within the configured source"
            )

        try:
            fd = os.open(candidate, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError as exc:
            raise ReceiptNotFound("receipt handle does not resolve within the configured source") from exc

        try:
            file_status = os.fstat(fd)
            if not stat.S_ISREG(file_status.st_mode):
                raise ReceiptNotFound("receipt handle does not resolve to a regular file")
            remaining = file_status.st_size
            chunks: list[bytes] = []
            while remaining > 0:
                chunk = os.read(fd, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            return b"".join(chunks)
        finally:
            os.close(fd)


# --------------------------------------------------------------------------- #
# Trusted access context and configuration                                   #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True, kw_only=True)
class ReceiptAccessContext:
    """Already-resolved, already-trusted values a caller cannot itself
    supply (mirrors §8's actor/tenant discipline: derived by the calling
    service from a transport/auth context, never from receipt-handle text
    or a tool argument).
    """

    actor_ref: str | None = None
    tenant_ref: str | None = None
    request_ref: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class ReceiptAccessConfig:
    """Operator/deployment configuration for :func:`resolve_receipt` and
    :func:`compose_receipts` — never a per-call tool argument.

    ``trust_bundle`` is the public keyring
    (:meth:`dagr_mcp.srs_receipts.SigningIdentity.trust_bundle`'s own output)
    — public key material only; this module never receives a
    :class:`~dagr_mcp.srs_receipts.SigningIdentity` or a private key.
    """

    provider: ReceiptByteProvider
    trust_bundle: Mapping[str, Any]
    require_actor_context: bool = False
    require_tenant_context: bool = False


# --------------------------------------------------------------------------- #
# Envelope verification (§9's required parse/schema/digest/signature steps)   #
# --------------------------------------------------------------------------- #

_REQUIRED_BASE_FIELDS: tuple[str, ...] = (
    "receipt_version",
    "profile_id",
    "profile_version",
    "receipt_id",
    "receipt_type",
    "receipt_kind",
    "boundary_type",
    "protocol_binding",
    "subject_ref",
    "issuer_id",
    "runtime_instance_id",
    "boundary_id",
    "logical_call_id",
    "issued_at",
    "artifact_classes_covered",
    "artifact_classes_excluded",
    "attestation_limits",
    "retention_class_applied",
    "extensions",
    "receipt_signature",
)
_REQUIRED_ADMISSION_FIELDS: tuple[str, ...] = (
    "requested_tool_name",
    "tool_resolution_status",
    "argument_digest",
    "policy_pack_id",
    "policy_pack_version",
    "disposition",
)
_REQUIRED_OUTCOME_FIELDS: tuple[str, ...] = ("admission_receipt_ref", "outcome")
_KNOWN_DISPOSITIONS: frozenset[str] = frozenset({"admitted", "refused", "deferred_for_review"})
_KNOWN_OUTCOMES: frozenset[str] = frozenset(
    {"result_returned", "error_returned", "exception", "task_submitted", "indeterminate"}
)
_SIGNATURE_MEMBERS: frozenset[str] = frozenset({"algorithm", "canonicalization", "key_id", "signature"})


def _envelope_schema_error(envelope: Any) -> bool:
    """True if ``envelope`` fails this module's narrow structural check
    against the exact profile the emitter (:mod:`dagr_mcp.srs_receipts`)
    already writes. Not a general JSON Schema validator — see the module
    docstring's import-discipline note.
    """

    if not isinstance(envelope, dict):
        return True
    for field_name in _REQUIRED_BASE_FIELDS:
        if field_name not in envelope:
            return True
    if envelope.get("receipt_version") != RECEIPT_VERSION:
        return True
    if envelope.get("profile_id") != PROFILE_ID:
        return True
    if envelope.get("profile_version") != PROFILE_VERSION:
        return True
    if envelope.get("receipt_type") != "sdk_enforcement":
        return True
    if envelope.get("boundary_type") != "mcp_tool_call":
        return True
    if envelope.get("protocol_binding") != "mcp":
        return True

    kind = envelope.get("receipt_kind")
    if kind == "admission":
        for field_name in _REQUIRED_ADMISSION_FIELDS:
            if field_name not in envelope:
                return True
        if envelope.get("disposition") not in _KNOWN_DISPOSITIONS:
            return True
    elif kind == "outcome":
        for field_name in _REQUIRED_OUTCOME_FIELDS:
            if field_name not in envelope:
                return True
        if envelope.get("outcome") not in _KNOWN_OUTCOMES:
            return True
    else:
        return True

    signature = envelope.get("receipt_signature")
    if not isinstance(signature, dict) or set(signature) != _SIGNATURE_MEMBERS:
        return True
    if signature.get("algorithm") != "Ed25519" or signature.get("canonicalization") != "RFC8785-JCS":
        return True

    return False


def _b64url_decode(value: Any) -> bytes | None:
    import base64

    if not isinstance(value, str) or not value:
        return None
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception:
        return None


def _parse_time(value: Any) -> datetime:
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _signature_valid(envelope: dict[str, Any], trust_bundle: Mapping[str, Any]) -> bool:
    """Verify ``envelope``'s Ed25519 signature against ``trust_bundle``.

    Reproduces exactly the verification the repository's own test-only
    verifier (``tests/receipt_verification.py``) and the independent
    ``arcs-verify`` project perform: canonicalize the envelope with the
    signature value removed (RFC 8785 — the same canonicalization
    :meth:`dagr_mcp.srs_receipts.SigningIdentity.sign_envelope` used to
    produce it), then verify the decoded signature bytes against the
    decoded public key bytes for the envelope's own ``key_id``. Also
    enforces the issuer entry's own trust window
    (``trusted is True``, matching ``issuer_id``, ``issued_at`` within
    ``[not_before, not_after]``) — a validly-signed receipt from a key the
    trust bundle does not mark trusted still fails here.
    """

    signature = envelope["receipt_signature"]
    key_id = signature.get("key_id")
    issuers = trust_bundle.get("issuers") if isinstance(trust_bundle, Mapping) else None
    entries = [
        entry
        for entry in (issuers or [])
        if isinstance(entry, Mapping) and entry.get("key_id") == key_id
    ]
    if len(entries) != 1:
        return False
    entry = entries[0]

    public_key_bytes = _b64url_decode(entry.get("public_key"))
    signature_bytes = _b64url_decode(signature.get("signature"))
    if public_key_bytes is None or len(public_key_bytes) != 32:
        return False
    if signature_bytes is None or len(signature_bytes) != 64:
        return False

    preimage = copy.deepcopy(envelope)
    del preimage["receipt_signature"]["signature"]
    try:
        canonical = rfc8785.dumps(preimage)
    except Exception:
        return False

    try:
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(signature_bytes, canonical)
    except InvalidSignature:
        return False

    if entry.get("trusted") is not True or entry.get("issuer_id") != envelope.get("issuer_id"):
        return False

    try:
        issued_at = _parse_time(envelope["issued_at"])
        not_before = _parse_time(entry["not_before"])
        not_after = _parse_time(entry["not_after"])
    except Exception:
        return False

    return not_before <= issued_at <= not_after


def _verify_and_parse_envelope(
    raw_bytes: bytes,
    *,
    expected_receipt_id: str,
    expected_receipt_kind: str,
    trust_bundle: Mapping[str, Any],
) -> tuple[Mapping[str, Any] | None, ReceiptAccessDiagnosticCode | None]:
    """Run the full required verification sequence over one immutable byte
    snapshot (§9 items 1-7): parse, structural/profile check, raw-content
    exclusion, signature+trust verification, then identifier and
    family/type binding against the requested handle — in that order, each
    fail-closed.
    """

    try:
        parsed = json.loads(raw_bytes)
    except Exception:
        return None, "malformed_envelope"
    if not isinstance(parsed, dict):
        return None, "malformed_envelope"

    if _envelope_schema_error(parsed):
        return None, "schema_failure"

    try:
        enforce_raw_content_exclusion(parsed)
    except ReceiptContentError:
        return None, "schema_failure"

    if not _signature_valid(parsed, trust_bundle):
        return None, "signature_failure"

    if parsed.get("receipt_id") != expected_receipt_id:
        return None, "identifier_mismatch"
    if parsed.get("receipt_kind") != expected_receipt_kind:
        return None, "family_mismatch"

    return MappingProxyType(parsed), None


# --------------------------------------------------------------------------- #
# Results                                                                     #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True, kw_only=True)
class VerifiedReceipt:
    """One fully verified, unmodified receipt envelope (§9's "exact verified
    envelope" requirement). ``envelope`` is exactly the parsed on-disk JSON —
    the same representation the independent ``arcs-verify`` project consumes
    — never re-serialized, reordered, or stripped of its own
    ``receipt_signature``.
    """

    handle: ReceiptHandle
    envelope: Mapping[str, Any]


@dataclass(frozen=True, slots=True, kw_only=True)
class ReceiptAccessResult:
    """The outcome of resolving one :class:`ReceiptHandle` — exactly one of
    ``verified``/``diagnostic_code`` is set, never both, never neither.
    """

    handle: ReceiptHandle
    verified: VerifiedReceipt | None = None
    diagnostic_code: ReceiptAccessDiagnosticCode | None = None

    def __post_init__(self) -> None:
        if (self.verified is None) == (self.diagnostic_code is None):
            raise ValueError(
                "ReceiptAccessResult must set exactly one of verified/diagnostic_code"
            )
        if self.diagnostic_code is not None and self.diagnostic_code not in RECEIPT_ACCESS_DIAGNOSTIC_CODES:
            raise ValueError(f"diagnostic_code {self.diagnostic_code!r} is not a recognized code")
        if self.verified is not None and self.verified.handle is not self.handle:
            raise ValueError("verified.handle must be the same handle object that was resolved")


@dataclass(frozen=True, slots=True, kw_only=True)
class ReceiptComposition:
    """Ordered composition of at most one admission and one outcome receipt
    for a single logical call (§9's admission/outcome composition
    semantics). Order is always (1) admission, (2) outcome — never inferred
    from input list position; each is independently verified and cross-
    checked before either is populated here.
    """

    logical_call_id: str
    admission: VerifiedReceipt | None = None
    outcome: VerifiedReceipt | None = None
    diagnostic_code: ReceiptAccessDiagnosticCode | None = None

    def __post_init__(self) -> None:
        if self.diagnostic_code is not None and self.diagnostic_code not in RECEIPT_ACCESS_DIAGNOSTIC_CODES:
            raise ValueError(f"diagnostic_code {self.diagnostic_code!r} is not a recognized code")
        if self.admission is not None and self.admission.handle.receipt_kind != "admission":
            raise ValueError("admission field must hold a receipt_kind=='admission' VerifiedReceipt")
        if self.outcome is not None and self.outcome.handle.receipt_kind != "outcome":
            raise ValueError("outcome field must hold a receipt_kind=='outcome' VerifiedReceipt")


# --------------------------------------------------------------------------- #
# Public operations                                                          #
# --------------------------------------------------------------------------- #


def resolve_receipt(
    handle: ReceiptHandle,
    *,
    config: ReceiptAccessConfig,
    context: ReceiptAccessContext | None = None,
) -> ReceiptAccessResult:
    """Resolve one returned :class:`ReceiptHandle` to its exact verified
    receipt envelope through ``config``'s operator-configured provider.

    Fail-closed at every step: an unresolvable handle, a malformed or
    unverifiable envelope, an identifier/family mismatch, or an applicable
    actor/tenant/request association mismatch all return a
    :class:`ReceiptAccessResult` with ``verified=None`` and a closed
    diagnostic code — never a raw exception, a partial envelope, or content
    from a different receipt.
    """

    if not isinstance(handle, ReceiptHandle):
        raise TypeError(f"handle must be a ReceiptHandle, got {type(handle).__name__}")

    resolved_context = context if context is not None else ReceiptAccessContext()

    if config.require_actor_context and resolved_context.actor_ref is None:
        return ReceiptAccessResult(handle=handle, diagnostic_code="access_unauthorized")
    if config.require_tenant_context and resolved_context.tenant_ref is None:
        return ReceiptAccessResult(handle=handle, diagnostic_code="access_unauthorized")

    try:
        raw_bytes = config.provider.fetch(
            handle,
            actor_ref=resolved_context.actor_ref,
            tenant_ref=resolved_context.tenant_ref,
            request_ref=resolved_context.request_ref,
        )
    except ReceiptNotFound:
        return ReceiptAccessResult(handle=handle, diagnostic_code="unknown_handle")
    except ReceiptSourceUnavailable:
        return ReceiptAccessResult(handle=handle, diagnostic_code="receipt_unavailable")
    except Exception:  # noqa: BLE001 - provider failures are always content-free here.
        return ReceiptAccessResult(handle=handle, diagnostic_code="provider_failure")

    envelope, diagnostic_code = _verify_and_parse_envelope(
        raw_bytes,
        expected_receipt_id=handle.receipt_id,
        expected_receipt_kind=handle.receipt_kind,
        trust_bundle=config.trust_bundle,
    )
    if diagnostic_code is not None:
        return ReceiptAccessResult(handle=handle, diagnostic_code=diagnostic_code)
    assert envelope is not None  # narrows the type for the checks below.

    if resolved_context.actor_ref is not None and envelope.get("actor_ref") not in (
        None,
        resolved_context.actor_ref,
    ):
        return ReceiptAccessResult(handle=handle, diagnostic_code="association_mismatch")
    if resolved_context.tenant_ref is not None and envelope.get("tenant_id") not in (
        None,
        resolved_context.tenant_ref,
    ):
        return ReceiptAccessResult(handle=handle, diagnostic_code="association_mismatch")
    if resolved_context.request_ref is not None and envelope.get("logical_call_id") not in (
        None,
        resolved_context.request_ref,
    ):
        return ReceiptAccessResult(handle=handle, diagnostic_code="association_mismatch")

    return ReceiptAccessResult(handle=handle, verified=VerifiedReceipt(handle=handle, envelope=envelope))


def compose_receipts(
    handles: Sequence[ReceiptHandle],
    *,
    config: ReceiptAccessConfig,
    expected_logical_call_id: str,
    expected_parent_receipt_ref: str | None = None,
    context: ReceiptAccessContext | None = None,
) -> ReceiptComposition:
    """Resolve and cross-verify an admission/outcome pair for one logical call.

    ``handles`` may hold zero, one, or two entries in any order — receipt
    kind is read from each handle's own ``receipt_kind``, never inferred
    from list position. More than one handle of the same kind is itself a
    fail-closed ``family_mismatch`` (an ambiguous, malformed input the
    lifecycle model never legitimately produces). A refusal or deferral
    legitimately composes with only an admission handle and no outcome
    handle; an admitted call whose outcome receipt failed to write
    (``alert_and_return_result``) legitimately composes the same way. The
    reverse — an outcome handle with no admission handle at all — never
    composes: every outcome envelope the emitter writes already requires
    its own ``admission_receipt_ref``, so an outcome offered without its
    admission counterpart is an unverifiable custody claim and fails closed
    as ``association_mismatch`` rather than composing a lone, unproven
    outcome. Cross-checks (§9's custody/association discipline) fail closed
    on any mismatch between the two envelopes' ``admission_receipt_ref``,
    ``logical_call_id``, ``runtime_instance_id``, ``boundary_id``,
    ``actor_ref``, or ``tenant_id``, and on a ``logical_call_id``/
    ``parent_receipt_ref`` mismatch against the caller-supplied expectation.
    """

    if not isinstance(expected_logical_call_id, str) or not expected_logical_call_id.strip():
        raise ValueError("expected_logical_call_id must be a non-empty string")

    admission_handles = [h for h in handles if h.receipt_kind == "admission"]
    outcome_handles = [h for h in handles if h.receipt_kind == "outcome"]
    if len(admission_handles) > 1 or len(outcome_handles) > 1:
        return ReceiptComposition(
            logical_call_id=expected_logical_call_id, diagnostic_code="family_mismatch"
        )

    admission_result = (
        resolve_receipt(admission_handles[0], config=config, context=context)
        if admission_handles
        else None
    )
    if admission_result is not None and admission_result.diagnostic_code is not None:
        return ReceiptComposition(
            logical_call_id=expected_logical_call_id,
            diagnostic_code=admission_result.diagnostic_code,
        )

    outcome_result = (
        resolve_receipt(outcome_handles[0], config=config, context=context)
        if outcome_handles
        else None
    )
    if outcome_result is not None and outcome_result.diagnostic_code is not None:
        return ReceiptComposition(
            logical_call_id=expected_logical_call_id,
            diagnostic_code=outcome_result.diagnostic_code,
        )

    admission_envelope = admission_result.verified.envelope if admission_result is not None else None
    outcome_envelope = outcome_result.verified.envelope if outcome_result is not None else None

    if outcome_envelope is not None and admission_envelope is None:
        # Every outcome envelope the emitter writes carries its own
        # admission_receipt_ref (dagr_mcp.srs_receipts.SignedReceiptEmitter.
        # emit_outcome requires it) -- the lifecycle model never legitimately
        # produces an outcome without a preceding admission. Composing an
        # outcome handle with no admission handle at all leaves that
        # required custody link unverified; fail closed rather than return
        # a partial composition that looks verified but proves no admission
        # ever existed for it.
        return ReceiptComposition(
            logical_call_id=expected_logical_call_id, diagnostic_code="association_mismatch"
        )

    for envelope in (admission_envelope, outcome_envelope):
        if envelope is not None and envelope.get("logical_call_id") != expected_logical_call_id:
            return ReceiptComposition(
                logical_call_id=expected_logical_call_id, diagnostic_code="association_mismatch"
            )

    if (
        expected_parent_receipt_ref is not None
        and admission_envelope is not None
        and admission_envelope.get("parent_receipt_ref") != expected_parent_receipt_ref
    ):
        return ReceiptComposition(
            logical_call_id=expected_logical_call_id, diagnostic_code="association_mismatch"
        )

    if admission_envelope is not None and outcome_envelope is not None:
        if outcome_envelope.get("admission_receipt_ref") != admission_envelope.get("receipt_id"):
            return ReceiptComposition(
                logical_call_id=expected_logical_call_id, diagnostic_code="association_mismatch"
            )
        for field_name in ("runtime_instance_id", "boundary_id", "actor_ref", "tenant_id"):
            if admission_envelope.get(field_name) != outcome_envelope.get(field_name):
                return ReceiptComposition(
                    logical_call_id=expected_logical_call_id, diagnostic_code="association_mismatch"
                )

    return ReceiptComposition(
        logical_call_id=expected_logical_call_id,
        admission=admission_result.verified if admission_result is not None else None,
        outcome=outcome_result.verified if outcome_result is not None else None,
    )


def access_governed_call_receipts(
    response: GovernedCallResponse,
    *,
    config: ReceiptAccessConfig,
    context: ReceiptAccessContext | None = None,
) -> ReceiptComposition:
    """Convenience composition over one :class:`GovernedCallResponse`'s own
    ``receipts``/``logical_call_id``/``parent_receipt_ref`` fields.

    This is the "optional inline-receipt mode" entry point: it is a
    completely separate operation an operator/deployment calls *after*
    ``execute_governed_call`` returns, never a parameter on the original
    request. It only reads ``response`` — it never mutates it, never
    fabricates a ``location_handle`` on it, and never feeds back into a new
    call.
    """

    return compose_receipts(
        response.receipts,
        config=config,
        expected_logical_call_id=response.logical_call_id,
        expected_parent_receipt_ref=response.parent_receipt_ref,
        context=context,
    )


__all__ = [
    "ReceiptAccessDiagnosticCode",
    "RECEIPT_ACCESS_DIAGNOSTIC_CODES",
    "ReceiptSourceError",
    "ReceiptNotFound",
    "ReceiptSourceUnavailable",
    "ReceiptByteProvider",
    "FilesystemReceiptSource",
    "ReceiptAccessContext",
    "ReceiptAccessConfig",
    "VerifiedReceipt",
    "ReceiptAccessResult",
    "ReceiptComposition",
    "resolve_receipt",
    "compose_receipts",
    "access_governed_call_receipts",
]
