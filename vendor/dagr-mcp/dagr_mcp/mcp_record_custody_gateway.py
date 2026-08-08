"""GARP MCP Record Custody Gateway contract.

Refs-only SDK object representing a custody record candidate composed at an
MCP boundary, before evidence scatters. v0.1 scope per
docs/internal/IN___GARP_MCP_Record_Custody_Gateway_v0_1_MAY25 in garp-doctrine.

This module is deliberately smaller than the runtime Gateway:

- no MCP client/server runtime;
- no HTTP adapter;
- no OpenTelemetry collector;
- no filesystem I/O;
- no garp-local / garp-core / garp-boundary / arcs-amnesiac import;
- no sink write;
- no record admission;
- no reconstruction;
- no MCP protocol modification;
- no model-output verification;
- no MCP authority grant;
- no public eligibility decision;
- no stealth interception;
- no identity provider role;
- no new receipt family.

The object carries opaque references and hashes only. It never embeds prompt
text, transcript text, tool arguments, HTTP bodies, headers, raw payloads,
private operator paths, or credential secrets.

The Gateway emits SRS receipts under three families from the v5.1 registry:
``connection``, ``provenance``, ``sdk_enforcement``. It binds to four boundary
types: ``mcp_tool_call``, ``mcp_resource_read``, ``mcp_prompt_retrieval``,
``agent_delegation``. It produces one of nine custody statuses per scope §3A.

The ``body_kind`` values ``agent_delegation_issued`` and
``agent_delegation_revoked`` are registered in the SovereigntyReceipt Binding
Memo. Constructing a Gateway projection may carry either value in refs-only
``extensions.garp.body`` content, while raw payloads, private paths, tool
arguments, and credential secrets remain refused.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

MCP_RECORD_CUSTODY_GATEWAY_SCHEMA = "garp.mcp_record_custody_gateway.v0.1"
MCP_RECORD_CUSTODY_GATEWAY_KIND = "mcp_record_custody_gateway"

MCP_RECORD_CUSTODY_GATEWAY_VOCABULARY: tuple[str, ...] = (
    "This records a custody record candidate composed at an MCP boundary.",
    "It does not admit a record.",
    "It does not modify the MCP protocol.",
    "It does not verify model output.",
    "It does not grant MCP authority.",
    "It does not decide public eligibility.",
    "It does not act as a stealth interception layer.",
    "It does not produce reconstructed receipts.",
    "It does not act as an identity provider.",
    "It does not introduce a new SRS receipt family.",
    "It carries refs and hashes only, never raw prompt, transcript, "
    "tool-argument, HTTP, header, credential-secret, or private-path payloads.",
    "Body kind agent_delegation_issued and agent_delegation_revoked are "
    "registered SovereigntyReceipt GARP body kinds.",
)

PRIVATE_REFERENCE_MARKERS: tuple[str, ...] = (
    "/" + "Users" + "/",
    "/" + "home" + "/",
    "/private/",
    "/var/folders/",
    "/mnt/user-data",
    "C:" + "\\" + "\\",
    "C:/",
    "file://",
    "query_logs/",
    "garp-local-main/",
)

RAW_PAYLOAD_FIELD_NAMES: frozenset[str] = frozenset(
    {
        "prompt",
        "prompt_text",
        "system_prompt",
        "completion",
        "completion_text",
        "model_output",
        "output_text",
        "response_text",
        "transcript",
        "transcript_text",
        "messages",
        "message_text",
        "raw_text",
        "raw_payload",
        "raw_input",
        "raw_output",
        "input_text",
        "private_text",
        "private_prompt",
        "private_completion",
        "tool_arguments",
        "tool_args",
        "arguments",
        "request_body",
        "response_body",
        "http_body",
        "raw_headers",
        "request_headers",
        "response_headers",
        "headers",
    }
)

CREDENTIAL_SECRET_FIELD_NAMES: frozenset[str] = frozenset(
    {
        "credential_secret",
        "client_secret",
        "access_token",
        "refresh_token",
        "id_token",
        "bearer_token",
        "api_key",
        "private_key",
        "password",
        "passphrase",
        "signing_key",
        "shared_secret",
    }
)

AGENT_DELEGATION_BODY_KINDS: frozenset[str] = frozenset(
    {
        "agent_delegation_issued",
        "agent_delegation_revoked",
    }
)


class MCPRecordCustodyGatewayError(ValueError):
    """Raised when an MCPRecordCustodyGateway contract object is malformed."""


class GatewayProtocolBinding(StrEnum):
    """Protocol binding value per SRS Core v5.1 §6 registry."""

    MCP = "mcp"
    AUTH_MD = "auth_md"
    UNSPECIFIED = "unspecified"


class GatewayBoundaryType(StrEnum):
    """Boundary type per SRS Core v5.1 §5 registry, scoped to v0.1 coverage."""

    MCP_TOOL_CALL = "mcp_tool_call"
    MCP_RESOURCE_READ = "mcp_resource_read"
    MCP_PROMPT_RETRIEVAL = "mcp_prompt_retrieval"
    AGENT_DELEGATION = "agent_delegation"


class GatewayReceiptFamily(StrEnum):
    """Receipt family per SRS Core v5.1 §2 registry, scoped to v0.1 coverage."""

    CONNECTION = "connection"
    PROVENANCE = "provenance"
    SDK_ENFORCEMENT = "sdk_enforcement"


class GatewayCustodyStatus(StrEnum):
    """Nine canonical custody observation statuses per scope §3A."""

    CUSTODY_RECORD_READY = "custody_record_ready"
    CUSTODY_RECORD_PARTIAL = "custody_record_partial"
    TRACE_ONLY = "trace_only"
    UNSUPPORTED_BOUNDARY_TYPE = "unsupported_boundary_type"
    MISSING_ACTOR_CONTEXT = "missing_actor_context"
    MISSING_TARGET_CONTEXT = "missing_target_context"
    PRIVACY_BLOCKED = "privacy_blocked"
    POLICY_REFUSED = "policy_refused"
    NEEDS_REVIEW = "needs_review"


def _canonical_json(payload: Mapping[str, Any]) -> str:
    return json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )


def _sha256_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _now_utc_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def mcp_record_custody_gateway_hash(payload: Mapping[str, Any]) -> str:
    """Return the deterministic sha256 digest over a gateway projection body.

    The ``gateway_hash`` field is ignored so a serialized object can be
    verified in place.
    """

    body = dict(payload)
    body["gateway_hash"] = ""
    return _sha256_text(_canonical_json(body))


def _require_non_empty(field_name: str, value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise MCPRecordCustodyGatewayError(
            f"{field_name} must be a non-empty string"
        )
    return value.strip()


def _optional_str(field_name: str, value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise MCPRecordCustodyGatewayError(
            f"{field_name} must be a non-empty string when provided"
        )
    return value.strip()


def _coerce_enum(field_name: str, value: Any, enum_cls: type[StrEnum]) -> StrEnum:
    if isinstance(value, enum_cls):
        return value
    if isinstance(value, str):
        try:
            return enum_cls(value)
        except ValueError as exc:
            allowed = sorted(member.value for member in enum_cls)
            raise MCPRecordCustodyGatewayError(
                f"{field_name} must be one of {allowed}, got {value!r}"
            ) from exc
    raise MCPRecordCustodyGatewayError(
        f"{field_name} must be a {enum_cls.__name__} or its string value, "
        f"got {type(value).__name__}"
    )


def _require_true(field_name: str, value: Any) -> bool:
    if value is not True:
        raise MCPRecordCustodyGatewayError(f"{field_name} must be True")
    return True


def _require_false(field_name: str, value: Any) -> bool:
    if value is not False:
        raise MCPRecordCustodyGatewayError(f"{field_name} must be False")
    return False


def _normalize_ref_list(field_name: str, values: Any) -> list[str]:
    if values is None:
        return []
    if isinstance(values, (str, bytes)) or not isinstance(values, (list, tuple)):
        raise MCPRecordCustodyGatewayError(
            f"{field_name} must be a list of ref strings"
        )
    return [_require_non_empty(f"{field_name}[]", item) for item in values]


def _iter_strings(value: Any):
    if isinstance(value, str):
        yield value
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            yield from _iter_strings(key)
            yield from _iter_strings(item)
        return
    if isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            yield from _iter_strings(item)


def _assert_public_safe(payload: Any) -> None:
    for text in _iter_strings(payload):
        for marker in PRIVATE_REFERENCE_MARKERS:
            if marker in text:
                raise MCPRecordCustodyGatewayError(
                    "MCPRecordCustodyGateway payload contains private "
                    f"reference marker {marker!r}"
                )


def _assert_no_raw_payload_fields(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if isinstance(key, str):
                key_lower = key.strip().lower()
                if key_lower in RAW_PAYLOAD_FIELD_NAMES:
                    raise MCPRecordCustodyGatewayError(
                        "MCPRecordCustodyGateway must not embed raw/private "
                        f"payload field {key!r}"
                    )
                if key_lower in CREDENTIAL_SECRET_FIELD_NAMES:
                    raise MCPRecordCustodyGatewayError(
                        "MCPRecordCustodyGateway must not embed credential "
                        f"secret field {key!r}"
                    )
            _assert_no_raw_payload_fields(item)
        return
    if isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            _assert_no_raw_payload_fields(item)



def _normalize_extensions(value: Mapping[str, Any] | None) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise MCPRecordCustodyGatewayError("extensions must be a mapping")
    _assert_no_raw_payload_fields(value)
    try:
        return json.loads(json.dumps(value, ensure_ascii=False, sort_keys=True))
    except (TypeError, ValueError) as exc:
        raise MCPRecordCustodyGatewayError(
            "extensions must be JSON-stable"
        ) from exc


@dataclass(frozen=True, slots=True, kw_only=True)
class MCPRecordCustodyGateway:
    """Refs-only Gateway custody projection at an MCP boundary.

    Required fields identify the projection (``gateway_event_id``,
    ``record_candidate_ref``, ``generated_by``) and pin the boundary class
    (``boundary_type``, ``receipt_family``). Optional ref fields carry pointers
    to substrate objects produced upstream (Bridge, Handle Registry, User
    Context) without embedding their content.

    Exclusion flags (must be True) enforce the §2 fail-closed posture against
    raw payload, private paths, tool arguments, and credential secrets.

    Non-claim flags (must be False) keep the projection from claiming
    admission, MCP protocol modification, MCP authority, or model-output
    verification.

    For ``boundary_type = agent_delegation`` the canonical cross-receipt
    linkage anchor is ``delegated_credential_ref`` (mirrors
    ``extensions.auth_md.credential_id`` per the Two-Receipt Linkage
    Discipline). Setting it is the responsibility of the runtime; the
    contract exposes the field and does not enforce two-receipt match here.
    """

    gateway_event_id: str
    record_candidate_ref: str
    generated_by: str
    boundary_type: GatewayBoundaryType | str
    receipt_family: GatewayReceiptFamily | str
    protocol_binding: GatewayProtocolBinding | str = GatewayProtocolBinding.MCP
    custody_status: GatewayCustodyStatus | str = (
        GatewayCustodyStatus.CUSTODY_RECORD_READY
    )
    actor_ref: str | None = None
    target_ref: str | None = None
    session_ref: str | None = None
    boundary_ref: str | None = None
    trace_context_ref: str | None = None
    bridge_ref: str | None = None
    user_context_ref: str | None = None
    delegated_credential_ref: str | None = None
    policy_outcome_ref: str | None = None
    request_hash: str | None = None
    response_hash: str | None = None
    output_ref: str | None = None
    span_refs: list[str] = field(default_factory=list)
    event_refs: list[str] = field(default_factory=list)
    receipt_refs: list[str] = field(default_factory=list)
    linkage_refs: list[str] = field(default_factory=list)
    blocker_codes: list[str] = field(default_factory=list)
    refusal_codes: list[str] = field(default_factory=list)
    extensions: Mapping[str, Any] = field(default_factory=dict)
    schema_version: str = MCP_RECORD_CUSTODY_GATEWAY_SCHEMA
    raw_payload_excluded: bool = True
    private_path_redacted: bool = True
    tool_arguments_excluded: bool = True
    credential_secret_excluded: bool = True
    record_admission_claimed: bool = False
    mcp_protocol_modified: bool = False
    mcp_authority_granted: bool = False
    model_output_verified: bool = False
    observed_at: str = field(default_factory=_now_utc_iso)

    def __post_init__(self) -> None:
        if self.schema_version != MCP_RECORD_CUSTODY_GATEWAY_SCHEMA:
            raise MCPRecordCustodyGatewayError(
                f"schema_version must be {MCP_RECORD_CUSTODY_GATEWAY_SCHEMA!r}"
            )

        object.__setattr__(
            self,
            "gateway_event_id",
            _require_non_empty("gateway_event_id", self.gateway_event_id),
        )
        object.__setattr__(
            self,
            "record_candidate_ref",
            _require_non_empty("record_candidate_ref", self.record_candidate_ref),
        )
        object.__setattr__(
            self,
            "generated_by",
            _require_non_empty("generated_by", self.generated_by),
        )
        object.__setattr__(
            self, "observed_at", _require_non_empty("observed_at", self.observed_at)
        )

        object.__setattr__(
            self, "actor_ref", _optional_str("actor_ref", self.actor_ref)
        )
        object.__setattr__(
            self, "target_ref", _optional_str("target_ref", self.target_ref)
        )
        object.__setattr__(
            self, "session_ref", _optional_str("session_ref", self.session_ref)
        )
        object.__setattr__(
            self, "boundary_ref", _optional_str("boundary_ref", self.boundary_ref)
        )
        object.__setattr__(
            self,
            "trace_context_ref",
            _optional_str("trace_context_ref", self.trace_context_ref),
        )
        object.__setattr__(
            self, "bridge_ref", _optional_str("bridge_ref", self.bridge_ref)
        )
        object.__setattr__(
            self,
            "user_context_ref",
            _optional_str("user_context_ref", self.user_context_ref),
        )
        object.__setattr__(
            self,
            "delegated_credential_ref",
            _optional_str(
                "delegated_credential_ref", self.delegated_credential_ref
            ),
        )
        object.__setattr__(
            self,
            "policy_outcome_ref",
            _optional_str("policy_outcome_ref", self.policy_outcome_ref),
        )
        object.__setattr__(
            self, "request_hash", _optional_str("request_hash", self.request_hash)
        )
        object.__setattr__(
            self, "response_hash", _optional_str("response_hash", self.response_hash)
        )
        object.__setattr__(
            self, "output_ref", _optional_str("output_ref", self.output_ref)
        )

        object.__setattr__(
            self,
            "boundary_type",
            _coerce_enum("boundary_type", self.boundary_type, GatewayBoundaryType),
        )
        object.__setattr__(
            self,
            "receipt_family",
            _coerce_enum("receipt_family", self.receipt_family, GatewayReceiptFamily),
        )
        object.__setattr__(
            self,
            "protocol_binding",
            _coerce_enum(
                "protocol_binding", self.protocol_binding, GatewayProtocolBinding
            ),
        )
        object.__setattr__(
            self,
            "custody_status",
            _coerce_enum("custody_status", self.custody_status, GatewayCustodyStatus),
        )

        object.__setattr__(
            self,
            "raw_payload_excluded",
            _require_true("raw_payload_excluded", self.raw_payload_excluded),
        )
        object.__setattr__(
            self,
            "private_path_redacted",
            _require_true("private_path_redacted", self.private_path_redacted),
        )
        object.__setattr__(
            self,
            "tool_arguments_excluded",
            _require_true("tool_arguments_excluded", self.tool_arguments_excluded),
        )
        object.__setattr__(
            self,
            "credential_secret_excluded",
            _require_true(
                "credential_secret_excluded", self.credential_secret_excluded
            ),
        )

        object.__setattr__(
            self,
            "record_admission_claimed",
            _require_false(
                "record_admission_claimed", self.record_admission_claimed
            ),
        )
        object.__setattr__(
            self,
            "mcp_protocol_modified",
            _require_false("mcp_protocol_modified", self.mcp_protocol_modified),
        )
        object.__setattr__(
            self,
            "mcp_authority_granted",
            _require_false("mcp_authority_granted", self.mcp_authority_granted),
        )
        object.__setattr__(
            self,
            "model_output_verified",
            _require_false("model_output_verified", self.model_output_verified),
        )

        object.__setattr__(
            self, "span_refs", _normalize_ref_list("span_refs", self.span_refs)
        )
        object.__setattr__(
            self, "event_refs", _normalize_ref_list("event_refs", self.event_refs)
        )
        object.__setattr__(
            self,
            "receipt_refs",
            _normalize_ref_list("receipt_refs", self.receipt_refs),
        )
        object.__setattr__(
            self,
            "linkage_refs",
            _normalize_ref_list("linkage_refs", self.linkage_refs),
        )
        object.__setattr__(
            self,
            "blocker_codes",
            _normalize_ref_list("blocker_codes", self.blocker_codes),
        )
        object.__setattr__(
            self,
            "refusal_codes",
            _normalize_ref_list("refusal_codes", self.refusal_codes),
        )

        object.__setattr__(self, "extensions", _normalize_extensions(self.extensions))

        _assert_no_raw_payload_fields(self.to_dict(include_hash=False))
        _assert_public_safe(self.to_dict(include_hash=False))

    def to_dict(self, *, include_hash: bool = True) -> dict[str, Any]:
        body: dict[str, Any] = {
            "schema_version": self.schema_version,
            "gateway_kind": MCP_RECORD_CUSTODY_GATEWAY_KIND,
            "gateway_event_id": self.gateway_event_id,
            "record_candidate_ref": self.record_candidate_ref,
            "generated_by": self.generated_by,
            "boundary_type": self.boundary_type.value,
            "receipt_family": self.receipt_family.value,
            "protocol_binding": self.protocol_binding.value,
            "custody_status": self.custody_status.value,
            "actor_ref": self.actor_ref,
            "target_ref": self.target_ref,
            "session_ref": self.session_ref,
            "boundary_ref": self.boundary_ref,
            "trace_context_ref": self.trace_context_ref,
            "bridge_ref": self.bridge_ref,
            "user_context_ref": self.user_context_ref,
            "delegated_credential_ref": self.delegated_credential_ref,
            "policy_outcome_ref": self.policy_outcome_ref,
            "request_hash": self.request_hash,
            "response_hash": self.response_hash,
            "output_ref": self.output_ref,
            "span_refs": list(self.span_refs),
            "event_refs": list(self.event_refs),
            "receipt_refs": list(self.receipt_refs),
            "linkage_refs": list(self.linkage_refs),
            "blocker_codes": list(self.blocker_codes),
            "refusal_codes": list(self.refusal_codes),
            "extensions": dict(self.extensions),
            "raw_payload_excluded": self.raw_payload_excluded,
            "private_path_redacted": self.private_path_redacted,
            "tool_arguments_excluded": self.tool_arguments_excluded,
            "credential_secret_excluded": self.credential_secret_excluded,
            "record_admission_claimed": self.record_admission_claimed,
            "mcp_protocol_modified": self.mcp_protocol_modified,
            "mcp_authority_granted": self.mcp_authority_granted,
            "model_output_verified": self.model_output_verified,
            "observed_at": self.observed_at,
            "gateway_vocabulary": list(MCP_RECORD_CUSTODY_GATEWAY_VOCABULARY),
            "gateway_hash": "",
        }
        if include_hash:
            body["gateway_hash"] = mcp_record_custody_gateway_hash(body)
        return body

    def to_json(self) -> str:
        return _canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "MCPRecordCustodyGateway":
        if not isinstance(data, Mapping):
            raise MCPRecordCustodyGatewayError(
                "gateway payload must be a mapping"
            )
        payload = dict(data)
        payload.pop("gateway_hash", None)
        payload.pop("gateway_vocabulary", None)
        payload.pop("gateway_kind", None)
        return cls(**payload)

    @classmethod
    def from_json(cls, value: str) -> "MCPRecordCustodyGateway":
        try:
            data = json.loads(value)
        except json.JSONDecodeError as exc:
            raise MCPRecordCustodyGatewayError(
                "gateway JSON is invalid"
            ) from exc
        return cls.from_dict(data)


def build_mcp_record_custody_gateway(**kwargs: Any) -> dict[str, Any]:
    """Build, validate, and serialize an MCPRecordCustodyGateway dict."""

    return MCPRecordCustodyGateway(**kwargs).to_dict()


__all__ = [
    "CREDENTIAL_SECRET_FIELD_NAMES",
    "MCP_RECORD_CUSTODY_GATEWAY_KIND",
    "MCP_RECORD_CUSTODY_GATEWAY_SCHEMA",
    "MCP_RECORD_CUSTODY_GATEWAY_VOCABULARY",
    "PRIVATE_REFERENCE_MARKERS",
    "RAW_PAYLOAD_FIELD_NAMES",
    "AGENT_DELEGATION_BODY_KINDS",
    "GatewayBoundaryType",
    "GatewayCustodyStatus",
    "GatewayProtocolBinding",
    "GatewayReceiptFamily",
    "MCPRecordCustodyGateway",
    "MCPRecordCustodyGatewayError",
    "build_mcp_record_custody_gateway",
    "mcp_record_custody_gateway_hash",
]
