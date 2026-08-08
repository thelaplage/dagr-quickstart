from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any, Literal, Mapping, Protocol, Sequence


SinkStatus = Literal["available", "degraded", "unavailable", "unknown"]
SinkDurability = Literal["memory", "file", "database", "remote", "unknown"]
SinkType = Literal["event", "receipt", "artifact", "review_object", "lint_finding"]
GovernanceFailureMode = Literal["fail_closed", "governed_pending", "degraded_with_note"]
PayloadValue = bytes | str | dict[str, Any] | list[Any] | None

SINK_STATUS_AVAILABLE: SinkStatus = "available"
SINK_STATUS_DEGRADED: SinkStatus = "degraded"
SINK_STATUS_UNAVAILABLE: SinkStatus = "unavailable"
SINK_STATUS_UNKNOWN: SinkStatus = "unknown"

SINK_DURABILITY_MEMORY: SinkDurability = "memory"
SINK_DURABILITY_FILE: SinkDurability = "file"
SINK_DURABILITY_DATABASE: SinkDurability = "database"
SINK_DURABILITY_REMOTE: SinkDurability = "remote"
SINK_DURABILITY_UNKNOWN: SinkDurability = "unknown"

SINK_TYPE_EVENT: SinkType = "event"
SINK_TYPE_RECEIPT: SinkType = "receipt"
SINK_TYPE_ARTIFACT: SinkType = "artifact"
SINK_TYPE_REVIEW_OBJECT: SinkType = "review_object"
SINK_TYPE_LINT_FINDING: SinkType = "lint_finding"

# Advertised on ``SinkHealth.capabilities``; checked via ``supports_capability``.
SINK_CAP_EVENT_WRITE = "garp.sdk.sink.event.write"
SINK_CAP_EVENT_BATCH_WRITE = "garp.sdk.sink.event.batch_write"
SINK_CAP_RECEIPT_WRITE = "garp.sdk.sink.receipt.write"
SINK_CAP_RECEIPT_VERIFY = "garp.sdk.sink.receipt.verify"
SINK_CAP_ARTIFACT_WRITE = "garp.sdk.sink.artifact.write"
SINK_CAP_ARTIFACT_READ = "garp.sdk.sink.artifact.read"
SINK_CAP_ARTIFACT_LIST = "garp.sdk.sink.artifact.list"
SINK_CAP_REVIEW_CREATE = "garp.sdk.sink.review_object.create"
SINK_CAP_REVIEW_RECORD_DECISION = "garp.sdk.sink.review_object.record_decision"
SINK_CAP_REVIEW_LIST_PENDING = "garp.sdk.sink.review_object.list_pending"
SINK_CAP_LINT_WRITE_FINDINGS = "garp.sdk.sink.lint.write_findings"
SINK_CAP_LINT_SUMMARIZE = "garp.sdk.sink.lint.summarize"

_SINK_CAPABILITIES_WRITE: frozenset[str] = frozenset(
    {
        SINK_CAP_EVENT_WRITE,
        SINK_CAP_EVENT_BATCH_WRITE,
        SINK_CAP_RECEIPT_WRITE,
        SINK_CAP_ARTIFACT_WRITE,
        SINK_CAP_REVIEW_CREATE,
        SINK_CAP_REVIEW_RECORD_DECISION,
        SINK_CAP_LINT_WRITE_FINDINGS,
    }
)
_SINK_CAPABILITIES_READ: frozenset[str] = frozenset(
    {
        SINK_CAP_RECEIPT_VERIFY,
        SINK_CAP_ARTIFACT_READ,
        SINK_CAP_ARTIFACT_LIST,
        SINK_CAP_REVIEW_LIST_PENDING,
        SINK_CAP_LINT_SUMMARIZE,
    }
)
_ALL_CAPS_BY_SINK_TYPE: dict[SinkType, frozenset[str]] = {
    SINK_TYPE_EVENT: frozenset({SINK_CAP_EVENT_WRITE, SINK_CAP_EVENT_BATCH_WRITE}),
    SINK_TYPE_RECEIPT: frozenset({SINK_CAP_RECEIPT_WRITE, SINK_CAP_RECEIPT_VERIFY}),
    SINK_TYPE_ARTIFACT: frozenset(
        {
            SINK_CAP_ARTIFACT_WRITE,
            SINK_CAP_ARTIFACT_READ,
            SINK_CAP_ARTIFACT_LIST,
        }
    ),
    SINK_TYPE_REVIEW_OBJECT: frozenset(
        {
            SINK_CAP_REVIEW_CREATE,
            SINK_CAP_REVIEW_RECORD_DECISION,
            SINK_CAP_REVIEW_LIST_PENDING,
        }
    ),
    SINK_TYPE_LINT_FINDING: frozenset(
        {SINK_CAP_LINT_WRITE_FINDINGS, SINK_CAP_LINT_SUMMARIZE}
    ),
}

FAIL_CLOSED: GovernanceFailureMode = "fail_closed"
GOVERNED_PENDING: GovernanceFailureMode = "governed_pending"
DEGRADED_WITH_NOTE: GovernanceFailureMode = "degraded_with_note"


class SinkUnavailableError(RuntimeError):
    """Raised when a required sink operation cannot run because the sink is unavailable."""


class SinkWriteError(RuntimeError):
    """Raised when a sink write fails after availability checks pass."""


class SinkReadError(RuntimeError):
    """Raised when a sink read cannot return the requested object."""


class ReceiptVerificationError(RuntimeError):
    """Raised when receipt verification cannot be completed."""


@dataclass(frozen=True, slots=True)
class SinkHealth:
    """Snapshot returned by ``health()`` on every sink implementation.

    ``status`` plus ``degraded_reason`` / ``last_error`` convey *why* a sink is not
    fully usable. ``capabilities`` must stay aligned with ``supports_capability``:
    tokens listed here are exactly those for which ``supports_capability`` may be
    true under the same writable/readable posture.
    """

    status: SinkStatus
    sink_type: SinkType
    implementation: str
    checked_at: str
    durability: SinkDurability
    writable: bool
    readable: bool
    capabilities: frozenset[str] = field(default_factory=frozenset)
    degraded_reason: str | None = None
    last_error: str | None = None


@dataclass(frozen=True, slots=True)
class EventEnvelope:
    event_type: str
    occurred_at: str
    event_id: str | None = None
    subject_ref: str | None = None
    actor_ref: str | None = None
    policy_ref: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)
    lineage_refs: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class ReceiptEnvelope:
    receipt_type: str
    boundary_type: str
    protocol_binding: str
    issued_at: str
    artifact_classes_covered: list[str]
    artifact_classes_excluded: list[str]
    attestation_limits: list[str]
    receipt_id: str | None = None
    subject_ref: str | None = None
    policy_ref: str | None = None
    policy_hash: str | None = None
    extensions: dict[str, Any] = field(default_factory=dict)
    critical_extensions: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class GovernedArtifact:
    artifact_type: str
    created_at: str
    private: bool
    required: bool
    optional_derived: bool
    artifact_ref: str | None = None
    payload_hash: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ReviewObject:
    review_object_type: str
    governance_state: str
    context_payload: dict[str, Any]
    allowed_actions: list[str]
    created_at: str
    review_object_id: str | None = None
    origin_event_id: str | None = None


@dataclass(frozen=True, slots=True)
class ReviewDecision:
    decision: str
    review_object_id: str
    decided_at: str
    actor_ref: str | None = None
    reason: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ReviewDecisionLookup:
    """Sink replay row binding a durable ``decision_ref`` to a ``ReviewDecision``.

    ``terminal`` is ``True`` when the outcome is execution-terminal for disposition
    policy (``approved``, ``rejected``, ``expired``); ``deferred`` yields ``False``.
    """

    decision_ref: str
    decision: ReviewDecision
    terminal: bool


# Canonical ``ReviewObject.governance_state`` vocabulary (plus legacy aliases below).
REVIEW_OBJECT_STATES = frozenset(
    {"pending", "approved", "rejected", "deferred", "expired"}
)
REVIEW_DECISION_OUTCOMES = frozenset({"approved", "rejected", "deferred", "expired"})

_ACTOR_REF_PREFIXES = frozenset(
    {
        "local_operator",
        "delegated_agent",
        "service_account",
        "external_reviewer",
    }
)
_ACTOR_REF_SLUG_RE = re.compile(r"^[a-z0-9._-]{1,96}$")

_REVIEW_OBJECT_STATE_ALIASES: dict[str, str] = {
    # Legacy in-memory sink vocabulary maps onto canonical ``pending``.
    "in_review": "pending",
    "escalated": "pending",
}
# Subset of governance states still awaiting disposition for ``list_pending``.
REVIEW_OBJECT_PENDING_STATES = frozenset({"pending", "deferred"})

_REVIEW_OBJECT_STATE_CANONICAL_LOOKUP: dict[str, str] = {
    alias: target for alias, target in _REVIEW_OBJECT_STATE_ALIASES.items()
}
for _state in REVIEW_OBJECT_STATES:
    _REVIEW_OBJECT_STATE_CANONICAL_LOOKUP.setdefault(_state, _state)


def normalize_review_object_state(value: str) -> str:
    """Return canonical ``governance_state`` or raise ``ValueError``."""

    if not isinstance(value, str):
        raise ValueError(
            f"review object governance_state must be str, not {type(value).__name__}"
        )
    key = value.strip().lower()
    if not key:
        raise ValueError("review object governance_state must be non-empty")
    canonical = _REVIEW_OBJECT_STATE_CANONICAL_LOOKUP.get(key)
    if canonical is None or canonical not in REVIEW_OBJECT_STATES:
        raise ValueError(
            f"unknown review object governance_state {value!r}; "
            f"expected one of {sorted(REVIEW_OBJECT_STATES)} "
            f"(legacy aliases: {sorted(_REVIEW_OBJECT_STATE_ALIASES)})"
        )
    return canonical


def normalize_review_decision_outcome(value: str) -> str:
    """Return canonical ``ReviewDecision.decision`` outcome or raise ``ValueError``."""

    if not isinstance(value, str):
        raise ValueError(
            f"review decision outcome must be str, not {type(value).__name__}"
        )
    key = value.strip().lower()
    if not key:
        raise ValueError("review decision outcome must be non-empty")
    if key not in REVIEW_DECISION_OUTCOMES:
        raise ValueError(
            f"unknown review decision outcome {value!r}; "
            f"expected one of {sorted(REVIEW_DECISION_OUTCOMES)}"
        )
    return key


# Opaque ref returned by ``FileReviewObjectSink.record_decision`` /
# ``GarpLocalReviewObjectSink.record_decision`` (``review_decision:<namespace>:<n>``).
# In-memory sinks use a separate ``decision:<n>`` prefix - not validated here.
_REVIEW_DECISION_REF_RE = re.compile(
    r"^review_decision:(?P<ns>[A-Za-z][A-Za-z0-9_]*):(?P<idx>[1-9]\d*)$"
)


def is_review_decision_ref(value: object) -> bool:
    """Return True if ``value`` is a sink-shaped ``review_decision`` opaque ref."""

    if not isinstance(value, str):
        return False
    return bool(_REVIEW_DECISION_REF_RE.fullmatch(value.strip()))


def normalize_review_decision_ref(value: str) -> str:
    """Return canonical ``review_decision:<namespace>:<n>`` or raise ``ValueError``."""

    if not isinstance(value, str):
        raise ValueError(
            f"review decision ref must be str, not {type(value).__name__}"
        )
    raw = value.strip()
    match = _REVIEW_DECISION_REF_RE.fullmatch(raw)
    if not match:
        raise ValueError(f"not a review_decision ref: {value!r}")
    ns = match.group("ns").lower()
    idx = match.group("idx")
    return f"review_decision:{ns}:{idx}"


def review_decision_ref_from_sink_ref(ref: str) -> str:
    """Validate a value returned from ``record_decision`` on durable JSONL sinks.

    Same rules as ``normalize_review_decision_ref`` - use when bridging sink
    returns into linkage payloads without widening accepted shapes.
    """

    return normalize_review_decision_ref(ref)


def normalize_actor_ref(actor_ref: str) -> str:
    """Normalize and validate a synthetic ``actor_ref`` token (no identity provider).

    Allowed forms: ``<prefix>:<slug>`` where *prefix* is one of ``local_operator``,
    ``delegated_agent``, ``service_account``, ``external_reviewer``, and *slug* is
    1–96 characters from ``[a-z0-9._-]`` (lower-case ASCII only). No ``@`` (email-like)
    tokens and no spaces.
    """

    if not isinstance(actor_ref, str):
        raise ValueError(
            f"actor_ref must be str, not {type(actor_ref).__name__}"
        )
    raw = actor_ref.strip()
    if not raw:
        raise ValueError("actor_ref must be non-empty")
    if " " in raw or "\t" in raw or "\n" in raw:
        raise ValueError("actor_ref must not contain whitespace")
    if "@" in raw:
        raise ValueError("actor_ref must not look like an email address")
    if ":" not in raw:
        raise ValueError("actor_ref must use prefix:slug form")
    prefix, _, slug = raw.partition(":")
    if not slug:
        raise ValueError("actor_ref slug segment is empty")
    prefix_key = prefix.strip().lower()
    if prefix_key not in _ACTOR_REF_PREFIXES:
        raise ValueError(
            f"unknown actor_ref prefix {prefix.strip()!r}; "
            f"expected one of {sorted(_ACTOR_REF_PREFIXES)}"
        )
    slug_key = slug.strip()
    if slug_key != slug:
        raise ValueError("actor_ref slug must not have leading or trailing whitespace")
    if _ACTOR_REF_SLUG_RE.fullmatch(slug_key) is None:
        raise ValueError(
            "actor_ref slug must be 1..96 characters from [a-z0-9._-] (lower-case)"
        )
    return f"{prefix_key}:{slug_key}"


def validate_actor_ref(actor_ref: str | None, *, required: bool = False) -> str | None:
    """Return normalized ``actor_ref``, or ``None`` when absent and not required."""

    if actor_ref is None:
        if required:
            raise ValueError("actor_ref is required")
        return None
    return normalize_actor_ref(actor_ref)


@dataclass(frozen=True, slots=True)
class LintFinding:
    rule_id: str
    severity: str
    message: str
    rule_family: str | None = None
    object_ref: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class VerificationResult:
    ok: bool
    reason: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)


class EventSink(Protocol):
    """Append-only audit trail for boundary events.

    **Durability:** Successful ``write_event`` / ``write_events`` calls must return
    non-empty refs and associate each envelope with its ref in the backing store.
    Implementations must **not silently drop events** (no successful return without
    persistence).

    **Capabilities:** Advertise ``garp.sdk.sink.event.write`` and
    ``garp.sdk.sink.event.batch_write`` via ``health().capabilities`` whenever writes
    are permitted; ``supports_capability`` must agree with ``health()``.
    """

    def write_event(self, event: EventEnvelope) -> str:
        ...

    def write_events(self, events: Sequence[EventEnvelope]) -> list[str]:
        ...

    def health(self) -> SinkHealth:
        ...

    def supports_capability(self, capability: str) -> bool:
        ...


class ReceiptSink(Protocol):
    """Stores immutable receipt envelopes; verification is fail-closed.

    **Verification posture:** ``verify_receipt`` returns structured ``ok=False``
    results when the sink is unavailable, IO fails, rows are malformed, or the
    receipt is missing - callers must not treat verification as solely exceptional.
    Missing cryptography surfaces as explicit ``not_implemented`` / ``not_applicable``
    detail keys, not silent ``ok=True``.

    **Hash-first receipts:** Valid receipts never require raw tool payloads inside
    ``ReceiptEnvelope``; hashes and attestations suffice.

    **Capabilities:** ``garp.sdk.sink.receipt.write`` when writes succeed under policy;
    ``garp.sdk.sink.receipt.verify`` only when verification reads are trustworthy.
    """

    def write_receipt(self, receipt: ReceiptEnvelope) -> str:
        ...

    def verify_receipt(self, receipt_ref: str) -> VerificationResult:
        ...

    def health(self) -> SinkHealth:
        ...

    def supports_capability(self, capability: str) -> bool:
        ...


class ArtifactSink(Protocol):
    """Governed artifact metadata (and optional payloads) with stable refs.

    ``GovernedArtifact.required``, ``optional_derived``, ``private``, and companion
    fields mirrored via ``metadata`` must round-trip through ``write_artifact`` →
    ``read_artifact`` / ``list_artifacts``. Sinks do not quietly falsify ``required``
    artifacts as satisfied.

    **Capabilities:** Write/read/list tokens mirror writable/readable posture.
    """

    def write_artifact(
        self,
        artifact: GovernedArtifact,
        payload: PayloadValue = None,
    ) -> str:
        ...

    def read_artifact(self, artifact_ref: str) -> GovernedArtifact:
        ...

    def list_artifacts(
        self,
        scope: Mapping[str, Any] | None = None,
    ) -> list[GovernedArtifact]:
        ...

    def health(self) -> SinkHealth:
        ...

    def supports_capability(self, capability: str) -> bool:
        ...


class ReviewObjectSink(Protocol):
    """Human/agent review queue with durable decision lineage.

    ``record_decision`` is **fail-closed**: implementations raise ``SinkReadError``
    when ``review_object_id`` is unknown and ``SinkWriteError`` when payloads are
    inconsistent (IDs / outcomes). Orphan decision rows must not appear consumable.

    **Capabilities:** Create / record / list_pending reflect writable vs readable
    semantics for queue mutation vs scans.
    """

    def create_review_object(self, review_object: ReviewObject) -> str:
        ...

    def record_decision(self, review_object_id: str, decision: ReviewDecision) -> str:
        ...

    def list_pending(
        self,
        review_object_type: str | None = None,
    ) -> list[ReviewObject]:
        ...

    def health(self) -> SinkHealth:
        ...

    def supports_capability(self, capability: str) -> bool:
        ...


class LintFindingSink(Protocol):
    """Persists lint findings; ``summarize`` is advisory.

    ``summarize`` aggregates counts for dashboards - it does **not** gate execution.

    **Severity:** Including ``blocker`` severity describes impact only; harness/policy
    decides enforcement vs advisory posture.

    **Preservation:** ``rule_family`` and ``severity`` must survive sink round-trips.

    **Capabilities:** Write-findings vs summarize track writable/readable posture.
    """

    def write_finding(self, finding: LintFinding) -> str:
        ...

    def write_findings(self, findings: Sequence[LintFinding]) -> str:
        ...

    def list_findings(
        self,
        scope: Mapping[str, Any] | None = None,
    ) -> list[LintFinding]:
        ...

    def summarize(self, scope: Mapping[str, Any] | None = None) -> Mapping[str, Any]:
        ...

    def health(self) -> SinkHealth:
        ...

    def supports_capability(self, capability: str) -> bool:
        ...


def capabilities_for_sink_type(
    sink_type: SinkType,
    *,
    writable: bool,
    readable: bool,
) -> frozenset[str]:
    """Compute capability tokens implied by sink posture."""

    full = _ALL_CAPS_BY_SINK_TYPE.get(sink_type, frozenset())
    selected: set[str] = set()
    for cap in full:
        if cap in _SINK_CAPABILITIES_WRITE and not writable:
            continue
        if cap in _SINK_CAPABILITIES_READ and not readable:
            continue
        selected.add(cap)
    return frozenset(selected)


def sink_supports_capability(sink: Any, capability: str) -> bool:
    """Prefer explicit ``supports_capability`` implementations when present."""

    getter = getattr(sink, "supports_capability", None)
    if callable(getter):
        return bool(getter(capability))
    return capability in sink.health().capabilities


def now_utc_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def make_sink_health(
    *,
    sink_type: SinkType,
    status: SinkStatus = SINK_STATUS_AVAILABLE,
    implementation: str = "memory",
    durability: SinkDurability = SINK_DURABILITY_MEMORY,
    writable: bool = True,
    readable: bool = True,
    degraded_reason: str | None = None,
    last_error: str | None = None,
    capabilities: frozenset[str] | None = None,
) -> SinkHealth:
    caps = (
        capabilities
        if capabilities is not None
        else capabilities_for_sink_type(sink_type, writable=writable, readable=readable)
    )
    return SinkHealth(
        status=status,
        sink_type=sink_type,
        implementation=implementation,
        checked_at=now_utc_iso(),
        durability=durability,
        writable=writable,
        readable=readable,
        capabilities=caps,
        degraded_reason=degraded_reason,
        last_error=last_error,
    )


def stable_payload_hash(payload: Any) -> str:
    if isinstance(payload, bytes):
        payload_bytes = payload
    elif isinstance(payload, str):
        payload_bytes = payload.encode("utf-8")
    elif payload is None:
        payload_bytes = b"null"
    else:
        try:
            payload_bytes = json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        except TypeError:
            payload_bytes = str(payload).encode("utf-8")
    return f"sha256:{hashlib.sha256(payload_bytes).hexdigest()}"


def maybe_assign_ref(prefix: str, counter: int) -> str:
    return f"{prefix}:{counter}"


class _InMemorySinkBase:
    sink_type: SinkType

    def __init__(self, *, available: bool = True) -> None:
        self._available = available

    def set_available(self, available: bool) -> None:
        self._available = available

    def health(self) -> SinkHealth:
        status: SinkStatus = (
            SINK_STATUS_AVAILABLE if self._available else SINK_STATUS_UNAVAILABLE
        )
        return make_sink_health(
            sink_type=self.sink_type,
            status=status,
            implementation="memory",
            durability=SINK_DURABILITY_MEMORY,
            writable=self._available,
            readable=self._available,
        )

    def supports_capability(self, capability: str) -> bool:
        return capability in self.health().capabilities

    def _ensure_available(self) -> None:
        if not self._available:
            raise SinkUnavailableError(f"{self.sink_type} sink is unavailable")


class InMemoryEventSink(_InMemorySinkBase):
    sink_type = SINK_TYPE_EVENT

    def __init__(self, *, available: bool = True) -> None:
        super().__init__(available=available)
        self._counter = 0
        self.events: dict[str, EventEnvelope] = {}

    def write_event(self, event: EventEnvelope) -> str:
        self._ensure_available()
        event_ref = event.event_id or self._next_ref()
        self.events[event_ref] = (
            event if event.event_id == event_ref else replace(event, event_id=event_ref)
        )
        return event_ref

    def write_events(self, events: Sequence[EventEnvelope]) -> list[str]:
        return [self.write_event(event) for event in events]

    def _next_ref(self) -> str:
        self._counter += 1
        return maybe_assign_ref("event", self._counter)


class InMemoryReceiptSink(_InMemorySinkBase):
    sink_type = SINK_TYPE_RECEIPT

    def __init__(self, *, available: bool = True) -> None:
        super().__init__(available=available)
        self._counter = 0
        self.receipts: dict[str, ReceiptEnvelope] = {}

    def write_receipt(self, receipt: ReceiptEnvelope) -> str:
        self._ensure_available()
        receipt_ref = receipt.receipt_id or self._next_ref()
        self.receipts[receipt_ref] = (
            receipt
            if receipt.receipt_id == receipt_ref
            else replace(receipt, receipt_id=receipt_ref)
        )
        return receipt_ref

    def verify_receipt(self, receipt_ref: str) -> VerificationResult:
        if not self._available:
            return VerificationResult(
                ok=False,
                reason="receipt_sink_unavailable",
                detail={
                    "receipt_ref": receipt_ref,
                    "signature_verification": "not_applicable",
                    "cryptographic_verification": "not_applicable",
                },
            )
        if receipt_ref not in self.receipts:
            return VerificationResult(
                ok=False,
                reason="receipt_not_found",
                detail={
                    "receipt_ref": receipt_ref,
                    "signature_verification": "not_applicable",
                    "cryptographic_verification": "not_applicable",
                },
            )
        return VerificationResult(
            ok=True,
            detail={
                "receipt_ref": receipt_ref,
                "signature_verification": "not_implemented",
                "cryptographic_verification": "not_implemented",
            },
        )

    def _next_ref(self) -> str:
        self._counter += 1
        return maybe_assign_ref("receipt", self._counter)


class InMemoryArtifactSink(_InMemorySinkBase):
    sink_type = SINK_TYPE_ARTIFACT

    def __init__(self, *, available: bool = True) -> None:
        super().__init__(available=available)
        self._counter = 0
        self.artifacts: dict[str, GovernedArtifact] = {}
        self.payloads: dict[str, PayloadValue] = {}

    def write_artifact(
        self,
        artifact: GovernedArtifact,
        payload: PayloadValue = None,
    ) -> str:
        self._ensure_available()
        artifact_ref = artifact.artifact_ref or self._next_ref()
        self.artifacts[artifact_ref] = (
            artifact
            if artifact.artifact_ref == artifact_ref
            else replace(artifact, artifact_ref=artifact_ref)
        )
        self.payloads[artifact_ref] = payload
        return artifact_ref

    def read_artifact(self, artifact_ref: str) -> GovernedArtifact:
        self._ensure_available()
        try:
            return self.artifacts[artifact_ref]
        except KeyError as exc:
            raise SinkReadError(f"artifact not found: {artifact_ref}") from exc

    def list_artifacts(
        self,
        scope: Mapping[str, Any] | None = None,
    ) -> list[GovernedArtifact]:
        self._ensure_available()
        if not scope:
            return list(self.artifacts.values())
        return [
            artifact
            for artifact in self.artifacts.values()
            if _artifact_matches_scope(artifact, scope)
        ]

    def _next_ref(self) -> str:
        self._counter += 1
        return maybe_assign_ref("artifact", self._counter)


class InMemoryReviewObjectSink(_InMemorySinkBase):
    sink_type = SINK_TYPE_REVIEW_OBJECT

    def __init__(self, *, available: bool = True) -> None:
        super().__init__(available=available)
        self._review_counter = 0
        self._decision_counter = 0
        self.review_objects: dict[str, ReviewObject] = {}
        self.decisions: dict[str, ReviewDecision] = {}
        self._decided_review_object_ids: set[str] = set()

    def create_review_object(self, review_object: ReviewObject) -> str:
        self._ensure_available()
        normalized_state = normalize_review_object_state(review_object.governance_state)
        review_object_ref = review_object.review_object_id or self._next_review_ref()
        prepared = (
            replace(
                review_object,
                review_object_id=review_object_ref,
                governance_state=normalized_state,
            )
            if review_object.review_object_id != review_object_ref
            else replace(review_object, governance_state=normalized_state)
        )
        self.review_objects[review_object_ref] = prepared
        return review_object_ref

    def record_decision(self, review_object_id: str, decision: ReviewDecision) -> str:
        self._ensure_available()
        if review_object_id not in self.review_objects:
            raise SinkReadError(f"review object not found: {review_object_id}")
        if decision.review_object_id != review_object_id:
            raise SinkWriteError("decision review_object_id does not match target")

        normalized_outcome = normalize_review_decision_outcome(decision.decision)
        decision_ref = self._next_decision_ref()
        self.decisions[decision_ref] = replace(
            decision,
            decision=normalized_outcome,
        )
        self._decided_review_object_ids.add(review_object_id)
        self.review_objects[review_object_id] = replace(
            self.review_objects[review_object_id],
            governance_state=normalized_outcome,
        )
        return decision_ref

    def list_pending(
        self,
        review_object_type: str | None = None,
    ) -> list[ReviewObject]:
        self._ensure_available()
        return [
            review_object
            for review_object in self.review_objects.values()
            if review_object.review_object_id not in self._decided_review_object_ids
            and review_object.governance_state in REVIEW_OBJECT_PENDING_STATES
            and (
                review_object_type is None
                or review_object.review_object_type == review_object_type
            )
        ]

    def _next_review_ref(self) -> str:
        self._review_counter += 1
        return maybe_assign_ref("review", self._review_counter)

    def _next_decision_ref(self) -> str:
        self._decision_counter += 1
        return maybe_assign_ref("decision", self._decision_counter)


class InMemoryLintFindingSink(_InMemorySinkBase):
    sink_type = SINK_TYPE_LINT_FINDING

    def __init__(self, *, available: bool = True) -> None:
        super().__init__(available=available)
        self._counter = 0
        self.batches: dict[str, list[LintFinding]] = {}

    @property
    def findings(self) -> list[LintFinding]:
        return [
            finding
            for batch_findings in self.batches.values()
            for finding in batch_findings
        ]

    def write_finding(self, finding: LintFinding) -> str:
        self._ensure_available()
        batch_ref = self._next_ref()
        self.batches[batch_ref] = [finding]
        return batch_ref

    def write_findings(self, findings: Sequence[LintFinding]) -> str:
        self._ensure_available()
        batch_ref = self._next_ref()
        self.batches[batch_ref] = list(findings)
        return batch_ref

    def list_findings(
        self,
        scope: Mapping[str, Any] | None = None,
    ) -> list[LintFinding]:
        self._ensure_available()
        return self._findings_for_scope(scope)

    def summarize(self, scope: Mapping[str, Any] | None = None) -> Mapping[str, Any]:
        self._ensure_available()
        findings = self._findings_for_scope(scope)
        by_family = Counter(
            finding.rule_family for finding in findings if finding.rule_family
        )
        return {
            "total": len(findings),
            "by_severity": dict(Counter(finding.severity for finding in findings)),
            "by_rule_id": dict(Counter(finding.rule_id for finding in findings)),
            "by_rule_family": dict(by_family),
        }

    def _findings_for_scope(
        self,
        scope: Mapping[str, Any] | None = None,
    ) -> list[LintFinding]:
        if not scope:
            return self.findings
        return [
            finding
            for finding in self.findings
            if _lint_finding_matches_scope(finding, scope)
        ]

    def _next_ref(self) -> str:
        self._counter += 1
        return maybe_assign_ref("lint_batch", self._counter)


def _artifact_matches_scope(
    artifact: GovernedArtifact,
    scope: Mapping[str, Any],
) -> bool:
    for key, expected in scope.items():
        if key == "metadata":
            if artifact.metadata != expected:
                return False
        elif key in artifact.metadata:
            if artifact.metadata[key] != expected:
                return False
        elif not hasattr(artifact, key) or getattr(artifact, key) != expected:
            return False
    return True


def _lint_finding_matches_scope(
    finding: LintFinding,
    scope: Mapping[str, Any],
) -> bool:
    for key, expected in scope.items():
        if key == "detail":
            if finding.detail != expected:
                return False
        elif key in finding.detail:
            if finding.detail[key] != expected:
                return False
        elif not hasattr(finding, key) or getattr(finding, key) != expected:
            return False
    return True


__all__ = [
    "ArtifactSink",
    "capabilities_for_sink_type",
    "DEGRADED_WITH_NOTE",
    "EventEnvelope",
    "EventSink",
    "FAIL_CLOSED",
    "GOVERNED_PENDING",
    "GovernanceFailureMode",
    "GovernedArtifact",
    "InMemoryArtifactSink",
    "InMemoryEventSink",
    "InMemoryLintFindingSink",
    "InMemoryReceiptSink",
    "InMemoryReviewObjectSink",
    "LintFinding",
    "LintFindingSink",
    "PayloadValue",
    "ReceiptEnvelope",
    "ReceiptSink",
    "ReceiptVerificationError",
    "REVIEW_DECISION_OUTCOMES",
    "REVIEW_OBJECT_PENDING_STATES",
    "REVIEW_OBJECT_STATES",
    "ReviewDecision",
    "ReviewDecisionLookup",
    "ReviewObject",
    "ReviewObjectSink",
    "normalize_actor_ref",
    "is_review_decision_ref",
    "normalize_review_decision_outcome",
    "normalize_review_object_state",
    "normalize_review_decision_ref",
    "review_decision_ref_from_sink_ref",
    "SINK_DURABILITY_DATABASE",
    "SINK_DURABILITY_FILE",
    "SINK_DURABILITY_MEMORY",
    "SINK_DURABILITY_REMOTE",
    "SINK_DURABILITY_UNKNOWN",
    "SINK_STATUS_AVAILABLE",
    "SINK_STATUS_DEGRADED",
    "SINK_STATUS_UNAVAILABLE",
    "SINK_STATUS_UNKNOWN",
    "SINK_TYPE_ARTIFACT",
    "SINK_TYPE_EVENT",
    "SINK_TYPE_LINT_FINDING",
    "SINK_TYPE_RECEIPT",
    "SINK_TYPE_REVIEW_OBJECT",
    "SINK_CAP_ARTIFACT_LIST",
    "SINK_CAP_ARTIFACT_READ",
    "SINK_CAP_ARTIFACT_WRITE",
    "SINK_CAP_EVENT_BATCH_WRITE",
    "SINK_CAP_EVENT_WRITE",
    "SINK_CAP_LINT_SUMMARIZE",
    "SINK_CAP_LINT_WRITE_FINDINGS",
    "SINK_CAP_RECEIPT_VERIFY",
    "SINK_CAP_RECEIPT_WRITE",
    "SINK_CAP_REVIEW_CREATE",
    "SINK_CAP_REVIEW_LIST_PENDING",
    "SINK_CAP_REVIEW_RECORD_DECISION",
    "sink_supports_capability",
    "SinkDurability",
    "SinkHealth",
    "SinkReadError",
    "SinkStatus",
    "SinkType",
    "SinkUnavailableError",
    "SinkWriteError",
    "VerificationResult",
    "make_sink_health",
    "maybe_assign_ref",
    "now_utc_iso",
    "stable_payload_hash",
    "validate_actor_ref",
]
