"""Framework-neutral persistence protocols for the Amnesiac tools.

These protocols are the seam between the native service and whatever durable
store an integrator owns. They are framework-neutral: this module imports
neither ``fastmcp`` nor ``arcs_amnesiac`` at runtime. Producer types appear only
in annotations under ``TYPE_CHECKING`` so the contracts read honestly without
coupling the module to the producer.

The load-bearing rule: ``propose_candidates`` and ``record_outcome`` may only
report ``candidate_recorded`` after a ``CandidateStore`` accepts the candidate.
The in-memory implementations here are deterministic and are provided for tests
and demos; a production integrator supplies a durable store instead.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Mapping, Protocol, runtime_checkable

if TYPE_CHECKING:  # pragma: no cover - typing only, never imported at runtime
    from arcs_amnesiac.claim_graph_admission import CandidateClaim
    from arcs_amnesiac.context_packet import ContextPacket

    # NOTE: ``AgentOutcomeObject`` (from the garp SDK) is referenced only as a
    # string annotation below. It is intentionally NOT imported here: ``dagr_mcp``
    # must not carry an import of the garp SDK root (import-direction discipline;
    # see tests/test_no_private_import_roots.py). Annotations are strings under
    # ``from __future__ import annotations`` and are never evaluated at runtime.
    AgentOutcomeObject = object  # type: ignore[assignment,misc]


@runtime_checkable
class CandidateStore(Protocol):
    """Durable store for constructed ``CandidateClaim`` objects.

    ``put`` persists a candidate and returns its durable ref. ``get`` resolves a
    ref back to the candidate, or ``None`` if unknown. Persistence is the only
    thing that lets an operation report ``candidate_recorded``.
    """

    def put(self, candidate: "CandidateClaim") -> str: ...

    def get(self, candidate_ref: str) -> "CandidateClaim | None": ...


@runtime_checkable
class AgentOutcomeStore(Protocol):
    """Resolver for refs-only agent outcomes.

    ``get`` resolves an outcome ref to an ``AgentOutcomeObject`` or a refs-only
    mapping the bridge can coerce, or ``None`` if the ref is unknown. The store
    never carries raw model output — it holds refs-only outcome objects.
    """

    def get(self, outcome_ref: str) -> "AgentOutcomeObject | Mapping[str, Any] | None": ...


@runtime_checkable
class ContextPacketStore(Protocol):
    """Durable store for compiled ``ContextPacket`` objects."""

    def put(self, packet: "ContextPacket") -> str: ...

    def get(self, packet_ref: str) -> "ContextPacket | None": ...


class InMemoryCandidateStore:
    """Deterministic in-memory ``CandidateStore`` for tests and demos.

    Keyed by the candidate's own content-addressed ``candidate_ref`` so the
    same candidate always resolves to the same durable ref.
    """

    def __init__(self) -> None:
        self._by_ref: dict[str, Any] = {}

    def put(self, candidate: "CandidateClaim") -> str:
        ref = candidate.candidate_ref
        self._by_ref[ref] = candidate
        return ref

    def get(self, candidate_ref: str) -> "CandidateClaim | None":
        return self._by_ref.get(candidate_ref)

    def __len__(self) -> int:
        return len(self._by_ref)

    def all_refs(self) -> tuple[str, ...]:
        return tuple(self._by_ref)


class InMemoryAgentOutcomeStore:
    """Deterministic in-memory ``AgentOutcomeStore`` for tests and demos."""

    def __init__(self) -> None:
        self._by_ref: dict[str, Any] = {}

    def put(self, outcome_ref: str, outcome: "AgentOutcomeObject | Mapping[str, Any]") -> str:
        self._by_ref[outcome_ref] = outcome
        return outcome_ref

    def get(self, outcome_ref: str) -> "AgentOutcomeObject | Mapping[str, Any] | None":
        return self._by_ref.get(outcome_ref)


class InMemoryContextPacketStore:
    """Deterministic in-memory ``ContextPacketStore`` for tests and demos.

    Keyed by the packet's content-addressed ``packet_id``.
    """

    def __init__(self) -> None:
        self._by_ref: dict[str, Any] = {}

    def put(self, packet: "ContextPacket") -> str:
        ref = packet.packet_id
        self._by_ref[ref] = packet
        return ref

    def get(self, packet_ref: str) -> "ContextPacket | None":
        return self._by_ref.get(packet_ref)

    def __len__(self) -> int:
        return len(self._by_ref)


__all__ = [
    "CandidateStore",
    "AgentOutcomeStore",
    "ContextPacketStore",
    "InMemoryCandidateStore",
    "InMemoryAgentOutcomeStore",
    "InMemoryContextPacketStore",
]
