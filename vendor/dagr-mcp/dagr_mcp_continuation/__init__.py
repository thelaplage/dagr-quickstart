"""Neutral MCP continuation contract (v0.1).

Authority: DAGR MCP 2026-07-28 Decision Ratification Record v0.1, merged at
``33099657b5beb41e2388018183aaf2a1e8f31659`` in ``garp-doctrine``. That record
ratifies exactly one immediate implementation package — this one — as an
additive, framework-neutral contract. It is not an MCP wire adapter, an SDK
binding, or a receipt change.

This package represents the identity and round linkage of a *paused-and-
resumable* MCP call in binding-neutral terms, and enforces the ratified
three-condition admission prerequisite before any such continuation is built.
It imports only the existing canonical neutral lifecycle vocabulary
(:mod:`dagr_mcp_lifecycle.contract`); it knows nothing about any wire format,
SDK, or binding, and it mints no identifiers, clock values, hashes, or round
numbers of its own — every identity value comes from the caller.

It is a sibling of ``dagr_mcp_lifecycle`` rather than a submodule of it: the
neutral lifecycle package's own public surface is frozen against a walked,
committed snapshot (``tests/golden/neutral_lifecycle/public_api_surface.json``),
and that freeze is a directory scan over every file in that package. A new
top-level package keeps this addition outside every existing frozen
package-surface snapshot in the repository, with no golden, dependency,
package-root export, or packaging-configuration change required.

Only the canonical ``continuable`` value of
:data:`dagr_mcp_lifecycle.contract.InputRequiredMode` is eligible for a neutral
continuation. ``interrupted`` — the other mode of that same type — remains
unsupported here, exactly as it is unsupported by the current FastMCP binding
mask. Adapter-level mapping of ``input_required`` onto a concrete wire
continuation is later, binding-owned work; this package does not name or model
any wire ``resultType``.
"""

from __future__ import annotations

from dataclasses import dataclass

from dagr_mcp_lifecycle.contract import InputRequiredMode

__all__ = [
    "ContinuationContractError",
    "ContinuationIdentity",
    "NeutralContinuation",
    "require_continuation_admission",
    "build_neutral_continuation",
]

# The single canonical outcome eligible for neutral continuation. Typed against
# the existing contract's InputRequiredMode rather than a fresh enum, so this
# package cannot drift into a second, competing lifecycle vocabulary.
_ELIGIBLE_OUTCOME: InputRequiredMode = "continuable"

_ADMISSION_REFUSAL_MESSAGE = (
    "Refused, deferred, or unrecorded-admission paths cannot continue."
)


class ContinuationContractError(ValueError):
    """A continuation was rejected by the neutral admission or outcome gate."""


@dataclass(frozen=True, slots=True)
class ContinuationIdentity:
    """Adapter-supplied identity and round linkage for one continuation attempt.

    Every value is supplied by the adapter/caller — this package mints nothing.
    ``interaction_id`` is stable across the interaction; ``request_id``
    identifies the current attempt and must be fresh for a retry;
    ``parent_request_id`` links this attempt to its immediate predecessor; and
    ``round_number`` is the adapter-supplied round count.
    """

    interaction_id: str
    request_id: str
    parent_request_id: str
    round_number: int

    def __post_init__(self) -> None:
        for name in ("interaction_id", "request_id", "parent_request_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ContinuationContractError(
                    f"{name} must be a non-empty string"
                )

        if self.interaction_id == self.request_id:
            raise ContinuationContractError(
                "interaction_id must be distinct from request_id"
            )
        if self.request_id == self.parent_request_id:
            raise ContinuationContractError(
                "request_id must be distinct from parent_request_id"
            )

        # bool is a subclass of int: checked first so a True/False round is
        # rejected rather than silently accepted as 1/0.
        if isinstance(self.round_number, bool) or not isinstance(
            self.round_number, int
        ):
            raise ContinuationContractError(
                "round_number must be an int, not bool"
            )
        if self.round_number < 1:
            raise ContinuationContractError("round_number must be >= 1")


@dataclass(frozen=True, slots=True)
class NeutralContinuation:
    """A continuation admitted for exactly one adapter-supplied identity.

    Holds only the validated identity and the canonical ``continuable``
    outcome — nothing wire-shaped, no raw request state, no admission record.
    """

    identity: ContinuationIdentity
    outcome: InputRequiredMode

    def __post_init__(self) -> None:
        if self.outcome != _ELIGIBLE_OUTCOME:
            raise ContinuationContractError(
                "only the canonical 'continuable' outcome is eligible for "
                "neutral continuation"
            )


def require_continuation_admission(
    *,
    execution_proceeds: bool,
    admission_recorded: bool,
    admission_record: object | None,
) -> None:
    """Enforce the ratified three-condition admission prerequisite.

    Passes only when all three hold simultaneously:
    ``execution_proceeds is True``, ``admission_recorded is True``, and
    ``admission_record is not None``. Identity checks, not truthiness — a
    truthy non-Boolean such as ``1`` or ``"true"`` must not satisfy either
    Boolean condition. Every other combination raises
    :class:`ContinuationContractError`.
    """

    if (
        execution_proceeds is True
        and admission_recorded is True
        and admission_record is not None
    ):
        return
    raise ContinuationContractError(_ADMISSION_REFUSAL_MESSAGE)


def build_neutral_continuation(
    *,
    outcome: InputRequiredMode,
    identity: ContinuationIdentity,
    execution_proceeds: bool,
    admission_recorded: bool,
    admission_record: object | None,
) -> NeutralContinuation:
    """Validate admission, then the outcome, then return a NeutralContinuation.

    The opaque ``admission_record`` is checked only for identity against
    ``None`` here; it is never stored, inspected, or exposed on the result.
    """

    require_continuation_admission(
        execution_proceeds=execution_proceeds,
        admission_recorded=admission_recorded,
        admission_record=admission_record,
    )
    return NeutralContinuation(identity=identity, outcome=outcome)
