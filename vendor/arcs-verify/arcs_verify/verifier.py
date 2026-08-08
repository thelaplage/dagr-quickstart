from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator

FROZEN_SCHEMA_SHA256 = (
    "d03aad1d5517e2acb65d5c866905aed7219bcbbfadd1a4a97eac546dd23f0333"
)

# SRS envelope schema pins, keyed by the artifact version each digest names.
# v0.2.0 is retained verbatim: it is the pin that verifies every historical
# v0.2.0-era receipt and it keeps FROZEN_SCHEMA_SHA256 as its own value. v0.2.1
# is the additive successor vendored from arcs-srs merge ccc4e4bb; it differs
# from v0.2.0 only in $id, title, and the optional subject_ref_origin property.
#
# Accepting a second pin is purely additive: an input that verified under the
# v0.2.0 pin before this change verifies identically after it, and an input
# offered with any unpinned schema still fails schema_digest. No pre-existing
# disposition moves.
ENVELOPE_SCHEMA_PINS = {
    "v0.2.0": FROZEN_SCHEMA_SHA256,
    "v0.2.1": (
        "2afa1ec9f093fd7c06c4f5db7bfd37cc63e64e3dcbe47c963f4df586a1c18ca1"
    ),
}

ACCEPTED_SCHEMA_SHA256 = frozenset(ENVELOPE_SCHEMA_PINS.values())

MCP_PROFILE = "srs.mcp.sdk_enforcement.v0.1"
CONNECTION_PROFILE = "srs.connection.lifecycle.v0.1"

PROFILE_IDENTITIES = {
    MCP_PROFILE: ("srs.mcp.sdk_enforcement", "v0.1"),
    CONNECTION_PROFILE: ("srs.connection.lifecycle", "v0.1"),
}

RECEIPT_VERSION = "srs.core.v5.1"

SIGNATURE_FAILURE_CODES = {
    "preimage_canonicalization_failed",
    "signature_invalid",
    "key_id_unresolved",
    "key_untrusted",
    "version_binding_mismatch",
    "signature_object_invalid",
    "signature_encoding_invalid",
    "public_key_encoding_invalid",
    "legacy_unverified",
}

RAW_KEY_RE = re.compile(
    r"(?:^|_)("
    r"api_?key|apikey|password|secret(?:_?value)?|"
    r"credential(?:_?material)?|private_?key|privatekey|"
    r"access_?token|accesstoken|refresh_?token|refreshtoken|"
    r"provider_?token|session_?cookie|authorization(?:_?header)?|"
    r"prompt_?text|transcript|raw_?(?:payload|content|prompt|output)|"
    r"tool_?arguments?|arguments|tool_?result|result_?body|result|"
    r"request_?body|response_?body|content_?payloads?|"
    r"document_?body|message_?body|file_?body|"
    r"raw_?scope_?grant|scope_?document|user_?content|tenant_?content|"
    r"headers?"
    r")(?:$|_)",
    re.IGNORECASE,
)

def _normalize_key(value: str) -> str:
    snake = re.sub(r"(?<!^)(?=[A-Z])", "_", value)
    return snake.replace("-", "_").lower()


PRIVATE_MARKERS = (
    "/" + "Users" + "/",
    "/" + "home" + "/",
    "/" + "private" + "/" + "var",
    "C:" + "\\" + "\\",
    "~" + "/" + "garp-",
    "~" + "/" + "arcs-anchor",
)

PROHIBITED_VALUE_RE = re.compile(
    r"(?:"
    r"Bearer\s+[A-Za-z0-9._~-]+|"
    r"\bsk-(?:ant-)?[A-Za-z0-9_-]{8,}|"
    r"\bgh[pousr]_[A-Za-z0-9]{20,}|"
    r"\bxox[baprs]-[A-Za-z0-9-]{10,}|"
    r"\bAIza[0-9A-Za-z_-]{20,}"
    r")"
)

BASE_REQUIRED = {
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
    "issued_at",
    "artifact_classes_covered",
    "artifact_classes_excluded",
    "attestation_limits",
    "extensions",
    "receipt_signature",
}

MCP_REQUIRED = BASE_REQUIRED | {"logical_call_id"}

# Registered binding-owned governance fields for the DAGR MCP receipt/profile.
# The DAGR emitter records these top-level delivery-state facts as strict JSON
# Booleans (see dagr_mcp CANCELLATION_FIELD_NAMES). They are deliberately named
# without a result-shaped token so they do not collide with raw-content
# exclusion, which means ARCS must independently type-check them: a re-signed
# receipt can otherwise smuggle raw tool-result material through one of these
# names. ARCS cannot trust issuer-side validation, so it enforces the Boolean
# contract itself. Absent is permitted; present requires a JSON Boolean.
MCP_BOOLEAN_GOVERNANCE_FIELDS = (
    "delivery_incomplete",
    "request_cancelled",
    "execution_state_unknown",
)

CONNECTION_REQUIRED = BASE_REQUIRED | {
    "tenant_id",
    "actor_ref",
    "source_record_refs",
}

SIGNATURE_MEMBERS = {
    "algorithm",
    "canonicalization",
    "key_id",
    "signature",
}

RESULT_LIMIT = (
    "The receipt establishes the request, admission disposition, and semantic "
    "result returned at the configured boundary. It does not independently "
    "establish that the underlying tool body executed for this invocation, "
    "because middleware such as caches may satisfy a call without handler "
    "execution."
)

TASK_LIMIT = (
    "The receipt establishes admission and submission to the configured task "
    "backend. It does not establish execution or completion."
)

CONNECTION_GENERAL_LIMIT = (
    "The receipt establishes the governance conditions enforced at the named "
    "connection boundary for the declared lifecycle event. It does not "
    "establish provider-side behavior."
)

CONNECTION_EVENT_LIMITS = {
    "connect": (
        "The receipt does not establish that the provider accepted, activated, "
        "maintained, or continued the connection."
    ),
    "scope_grant": (
        "The receipt does not establish that the provider enforced or honored "
        "the referenced scope set."
    ),
    "retention_selection": (
        "The receipt does not establish provider-side retention, deletion, "
        "legal-hold, or preservation behavior."
    ),
    "revoke": (
        "The receipt does not establish that provider credentials were "
        "invalidated or that provider-side access ceased."
    ),
    "delete": (
        "The receipt does not establish provider-side deletion, erasure, or "
        "destruction of provider-held data."
    ),
}

OPAQUE_REF_RE = re.compile(
    r"^[A-Za-z][A-Za-z0-9+.-]*:[A-Za-z0-9._~:@/-]+$"
)
SHA256_REF_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
STABLE_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9._:-]+$")


@dataclass(slots=True)
class VerificationReport:
    schema_digest: bool = False
    envelope: bool = False
    profile: bool = False
    raw_content_exclusion: bool = False
    signature_valid: bool = False
    issuer_key_resolved: bool = False
    issuer_key_trusted: bool = False
    attestation_limits_present: bool = False
    chain_status: str = "not_applicable"
    failure_codes: list[str] = field(default_factory=list)
    details: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(
            (
                self.schema_digest,
                self.envelope,
                self.profile,
                self.raw_content_exclusion,
                self.signature_valid,
                self.issuer_key_resolved,
                self.issuer_key_trusted,
                self.attestation_limits_present,
            )
        ) and self.chain_status == "not_applicable"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["passed"] = self.passed
        return data


def _b64url_decode(value: str, *, code: str) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise ValueError(code)
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise ValueError(code) from exc
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
        raise ValueError(code)
    return decoded


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _walk(value: Any) -> Iterable[tuple[str | None, Any]]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key), item
            yield from _walk(item)
    elif isinstance(value, list):
        for item in value:
            yield None, item
            yield from _walk(item)


def _missing_required(
    receipt: dict[str, Any],
    required: set[str],
) -> list[str]:
    missing = sorted(required - receipt.keys())
    if not missing:
        return []
    return ["profile.missing_required:" + ",".join(missing)]


def _is_opaque_reference(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    if value.startswith(("http:", "https:", "file:")):
        return False
    if any(marker in value for marker in PRIVATE_MARKERS):
        return False
    if any(marker in value for marker in ("?", "#", "%")):
        return False
    return OPAQUE_REF_RE.fullmatch(value) is not None


def _is_reference_or_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and (
            SHA256_REF_RE.fullmatch(value) is not None
            or _is_opaque_reference(value)
        )
    )


def _is_stable_identifier(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and STABLE_IDENTIFIER_RE.fullmatch(value) is not None
    )


def _raw_content_failure(
    key: str,
    value: Any,
) -> str | None:
    normalized = _normalize_key(key)

    if RAW_KEY_RE.search(normalized) is None:
        return None

    if normalized.endswith(("_digest", "_hash")):
        if (
            isinstance(value, str)
            and SHA256_REF_RE.fullmatch(value) is not None
        ):
            return None
        return f"raw_content.invalid_digest_evidence:{key}"

    if normalized.endswith("_ref"):
        if _is_reference_or_digest(value):
            return None
        return f"raw_content.invalid_reference_evidence:{key}"

    if normalized.endswith("_refs"):
        if (
            isinstance(value, list)
            and bool(value)
            and all(_is_reference_or_digest(item) for item in value)
        ):
            return None
        return f"raw_content.invalid_reference_evidence:{key}"

    if normalized.endswith("_id"):
        if _is_stable_identifier(value) or _is_opaque_reference(value):
            return None
        return f"raw_content.invalid_identifier_evidence:{key}"

    if normalized.endswith("_ids"):
        if (
            isinstance(value, list)
            and bool(value)
            and all(
                _is_stable_identifier(item)
                or _is_opaque_reference(item)
                for item in value
            )
        ):
            return None
        return f"raw_content.invalid_identifier_evidence:{key}"

    return f"raw_content.forbidden_key:{key}"


def _contains_prohibited_value(value: str) -> bool:
    return (
        any(marker in value for marker in PRIVATE_MARKERS)
        or PROHIBITED_VALUE_RE.search(value) is not None
    )


def _mcp_profile_errors(receipt: dict[str, Any]) -> list[str]:
    errors = _missing_required(receipt, MCP_REQUIRED)

    expected = {
        "receipt_version": RECEIPT_VERSION,
        "profile_id": "srs.mcp.sdk_enforcement",
        "profile_version": "v0.1",
        "receipt_type": "sdk_enforcement",
        "boundary_type": "mcp_tool_call",
        "protocol_binding": "mcp",
    }

    for key, value in expected.items():
        if receipt.get(key) != value:
            errors.append(f"profile.invalid_{key}")

    kind = receipt.get("receipt_kind")

    if kind == "admission":
        for key in (
            "requested_tool_name",
            "tool_resolution_status",
            "argument_digest",
            "policy_pack_id",
            "policy_pack_version",
            "disposition",
        ):
            if key not in receipt:
                errors.append(f"profile.admission_missing_{key}")

        disposition = receipt.get("disposition")

        if disposition not in {
            "admitted",
            "refused",
            "deferred_for_review",
        }:
            errors.append("profile.invalid_disposition")

        if disposition == "deferred_for_review":
            if not receipt.get("review_object_ref"):
                errors.append(
                    "profile.deferred_missing_review_object_ref"
                )
            if receipt.get("retry_contract") != "retry_after_approval":
                errors.append(
                    "profile.deferred_invalid_retry_contract"
                )

    elif kind == "outcome":
        if not receipt.get("admission_receipt_ref"):
            errors.append(
                "profile.outcome_missing_admission_receipt_ref"
            )

        outcome = receipt.get("outcome")

        if outcome not in {
            "result_returned",
            "error_returned",
            "exception",
            "task_submitted",
            "indeterminate",
        }:
            errors.append("profile.invalid_outcome")

        if outcome in {"result_returned", "error_returned"}:
            if not receipt.get("result_digest"):
                errors.append("profile.result_missing_digest")
            if RESULT_LIMIT not in receipt.get("attestation_limits", []):
                errors.append(
                    "profile.result_missing_attestation_limit"
                )

        if (
            outcome == "task_submitted"
            and TASK_LIMIT not in receipt.get("attestation_limits", [])
        ):
            errors.append("profile.task_missing_attestation_limit")

    else:
        errors.append("profile.invalid_receipt_kind")

    if (
        receipt.get("tool_resolution_status") == "not_observed"
        and "resolved_tool_ref" in receipt
    ):
        errors.append("profile.resolution_ref_for_not_observed")

    for governance_field in MCP_BOOLEAN_GOVERNANCE_FIELDS:
        if (
            governance_field in receipt
            and not isinstance(receipt[governance_field], bool)
        ):
            errors.append(
                f"profile.non_boolean_governance_field:{governance_field}"
            )

    excluded = set(receipt.get("artifact_classes_excluded") or [])

    if not {
        "raw_prompt",
        "raw_output",
        "raw_tool_arguments",
        "raw_tool_result",
    }.issubset(excluded):
        errors.append("profile.raw_artifact_exclusions_missing")

    return errors


def _connection_profile_errors(
    receipt: dict[str, Any],
) -> list[str]:
    errors = _missing_required(receipt, CONNECTION_REQUIRED)

    expected = {
        "receipt_version": RECEIPT_VERSION,
        "profile_id": "srs.connection.lifecycle",
        "profile_version": "v0.1",
        "receipt_type": "connection",
        "boundary_type": "connection_boundary",
    }

    for key, value in expected.items():
        if receipt.get(key) != value:
            errors.append(f"profile.invalid_{key}")

    binding = receipt.get("protocol_binding")

    if not isinstance(binding, str) or not binding:
        errors.append("profile.invalid_protocol_binding")

    extensions = receipt.get("extensions")

    if not isinstance(extensions, dict):
        errors.append("profile.extensions_not_object")
    elif (
        "forum_projection" in extensions
        and binding != "arcs-forum"
    ):
        errors.append("profile.forum_projection_binding_mismatch")

    source_refs = receipt.get("source_record_refs")

    if (
        not isinstance(source_refs, list)
        or not source_refs
        or not all(_is_reference_or_digest(item) for item in source_refs)
    ):
        errors.append("profile.invalid_source_record_refs")

    covered = set(receipt.get("artifact_classes_covered") or [])

    if "connection_governance_event" not in covered:
        errors.append(
            "profile.connection_governance_event_not_covered"
        )

    excluded = set(receipt.get("artifact_classes_excluded") or [])

    if not {
        "credential_material",
        "provider_tokens",
        "content_payloads",
    }.issubset(excluded):
        errors.append("profile.raw_artifact_exclusions_missing")

    limits = receipt.get("attestation_limits")
    limit_values = set(limits) if isinstance(limits, list) else set()

    if CONNECTION_GENERAL_LIMIT not in limit_values:
        errors.append(
            "profile.connection_general_attestation_limit_missing"
        )

    kind = receipt.get("receipt_kind")

    if kind not in CONNECTION_EVENT_LIMITS:
        errors.append("profile.invalid_receipt_kind")
        return errors

    if CONNECTION_EVENT_LIMITS[kind] not in limit_values:
        errors.append(
            f"profile.{kind}_attestation_limit_missing"
        )

    if kind == "connect":
        if not _is_opaque_reference(receipt.get("provider_ref")):
            errors.append("profile.connect_missing_provider_ref")

    elif kind == "scope_grant":
        scope_refs = receipt.get("scope_refs")
        if (
            not isinstance(scope_refs, list)
            or not scope_refs
            or not all(
                _is_reference_or_digest(item)
                for item in scope_refs
            )
        ):
            errors.append("profile.scope_grant_invalid_scope_refs")

    elif kind == "retention_selection":
        if not _is_stable_identifier(
            receipt.get("retention_class")
        ):
            errors.append(
                "profile.retention_selection_invalid_retention_class"
            )

    elif kind == "revoke":
        if (
            "reason_code" in receipt
            and not _is_stable_identifier(
                receipt.get("reason_code")
            )
        ):
            errors.append("profile.revoke_invalid_reason_code")

        for forbidden in (
            "reason",
            "reason_text",
            "reason_message",
        ):
            if forbidden in receipt:
                errors.append(
                    f"profile.revoke_free_form_reason_forbidden:{forbidden}"
                )

    if (
        "retention_class" in receipt
        and not _is_stable_identifier(
            receipt.get("retention_class")
        )
    ):
        errors.append("profile.invalid_retention_class")

    return errors


def _profile_errors(
    receipt: dict[str, Any],
    selected_profile: str,
) -> list[str]:
    if selected_profile == MCP_PROFILE:
        return _mcp_profile_errors(receipt)

    if selected_profile == CONNECTION_PROFILE:
        return _connection_profile_errors(receipt)

    return ["profile.unsupported_selection"]


def verify_receipt(
    receipt: dict[str, Any],
    keyring: dict[str, Any],
    *,
    schema_path: Path,
    selected_profile: str | None = None,
) -> VerificationReport:
    report = VerificationReport()
    selected = selected_profile or MCP_PROFILE

    schema_bytes = schema_path.read_bytes()
    report.schema_digest = (
        hashlib.sha256(schema_bytes).hexdigest()
        in ACCEPTED_SCHEMA_SHA256
    )

    if not report.schema_digest:
        report.failure_codes.append("schema.digest_mismatch")

    schema = json.loads(schema_bytes)
    schema_errors = sorted(
        Draft202012Validator(schema).iter_errors(receipt),
        key=lambda error: list(error.path),
    )

    report.envelope = not schema_errors

    for error in schema_errors:
        report.failure_codes.append("envelope.schema_invalid")
        report.details.append(error.message)

    profile_errors = _profile_errors(receipt, selected)
    report.profile = not profile_errors
    report.failure_codes.extend(profile_errors)

    raw_errors: list[str] = []

    for key, value in _walk(receipt):
        if key is not None:
            failure = _raw_content_failure(key, value)
            if failure is not None:
                raw_errors.append(failure)

        if (
            isinstance(value, str)
            and _contains_prohibited_value(value)
        ):
            raw_errors.append("raw_content.prohibited_value")

    report.raw_content_exclusion = not raw_errors
    report.failure_codes.extend(raw_errors)

    limits = receipt.get("attestation_limits")
    report.attestation_limits_present = (
        isinstance(limits, list)
        and bool(limits)
        and all(
            isinstance(item, str) and item.strip()
            for item in limits
        )
    )

    if not report.attestation_limits_present:
        report.failure_codes.append(
            "attestation.missing_or_empty"
        )

    signature = receipt.get("receipt_signature")

    if isinstance(signature, str):
        report.failure_codes.append("legacy_unverified")
        return _dedupe(report)

    if (
        not isinstance(signature, dict)
        or set(signature) != SIGNATURE_MEMBERS
        or signature.get("algorithm") != "Ed25519"
        or signature.get("canonicalization") != "RFC8785-JCS"
    ):
        report.failure_codes.append("signature_object_invalid")
        return _dedupe(report)

    key_id = signature.get("key_id")
    entries = (
        keyring.get("issuers", [])
        if isinstance(keyring, dict)
        else []
    )
    entry = next(
        (
            item
            for item in entries
            if isinstance(item, dict)
            and item.get("key_id") == key_id
        ),
        None,
    )

    report.issuer_key_resolved = entry is not None

    if entry is None:
        report.failure_codes.append("key_id_unresolved")
        return _dedupe(report)

    try:
        public_key_bytes = _b64url_decode(
            entry.get("public_key"),
            code="public_key_encoding_invalid",
        )
        signature_bytes = _b64url_decode(
            signature.get("signature"),
            code="signature_encoding_invalid",
        )

        if len(public_key_bytes) != 32:
            raise ValueError("public_key_encoding_invalid")

        if len(signature_bytes) != 64:
            raise ValueError("signature_encoding_invalid")

    except ValueError as exc:
        report.failure_codes.append(str(exc))
        return _dedupe(report)

    preimage = copy.deepcopy(receipt)
    del preimage["receipt_signature"]["signature"]

    try:
        canonical = rfc8785.dumps(preimage)
    except Exception:
        report.failure_codes.append(
            "preimage_canonicalization_failed"
        )
        return _dedupe(report)

    try:
        Ed25519PublicKey.from_public_bytes(
            public_key_bytes
        ).verify(
            signature_bytes,
            canonical,
        )
        report.signature_valid = True
    except InvalidSignature:
        report.failure_codes.append("signature_invalid")

    identity = PROFILE_IDENTITIES.get(selected)

    if (
        identity is None
        or receipt.get("receipt_version") != RECEIPT_VERSION
        or receipt.get("profile_id") != identity[0]
        or receipt.get("profile_version") != identity[1]
    ):
        report.failure_codes.append("version_binding_mismatch")
        report.signature_valid = False

    try:
        issued_at = _parse_time(receipt["issued_at"])
        trusted = (
            entry.get("trusted") is True
            and entry.get("issuer_id")
            == receipt.get("issuer_id")
        )
        trusted = (
            trusted
            and _parse_time(entry["not_before"])
            <= issued_at
            <= _parse_time(entry["not_after"])
        )
    except Exception:
        trusted = False

    report.issuer_key_trusted = bool(trusted)

    if not report.issuer_key_trusted:
        report.failure_codes.append("key_untrusted")

    return _dedupe(report)


def _dedupe(
    report: VerificationReport,
) -> VerificationReport:
    report.failure_codes = list(
        dict.fromkeys(report.failure_codes)
    )
    report.details = list(dict.fromkeys(report.details))
    return report
