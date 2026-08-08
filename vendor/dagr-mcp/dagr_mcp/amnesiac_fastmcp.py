"""FastMCP binding and installation surface for the four Amnesiac tools.

This layer registers tools on a supplied ``FastMCP`` server and translates the
framework-neutral contract objects into tool results. It recreates no domain
semantics; every decision is made by the injected ``AmnesiacService``.

Two load-bearing properties relative to the first-cut sketch:

* Capability-unavailable is returned as a FastMCP *error result*
  (``isError = true``) with structured content, or as a ``ToolError`` — never as
  an ordinary successful dictionary. The existing ``DAGRMiddleware`` therefore
  classifies it as ``error_returned`` (or ``exception``), never
  ``result_returned``.
* ``install_amnesiac_tools`` is the single installation surface. It merges the
  Amnesiac tool classes into ``DAGRMiddlewareConfig.tool_classes``, installs or
  validates the existing ``DAGRMiddleware`` with the existing
  ``SignedReceiptEmitter``, and creates no parallel receipt family. Unknown or
  omitted classifications fail validation rather than silently defaulting a
  write tool to read.

Write/read classification for the existing DAGRMiddleware:
  amnesiac.propose_candidates  write   (recording a proposal is a write)
  amnesiac.record_outcome      write
  amnesiac.request_reopening   write
  amnesiac.compile_context     read
"""

from __future__ import annotations

import dataclasses
from dataclasses import asdict
from enum import Enum
from typing import Any

from .amnesiac_contracts import (
    AmnesiacService,
    CapabilityUnavailable,
    CompileContextRequest,
    ProposeCandidatesRequest,
    ProposedClaim,
    RawPayloadRefused,
    RecordOutcomeRequest,
    RequestReopeningRequest,
)

# The read/write classification for the four tools. ``propose_candidates``,
# ``record_outcome`` and ``request_reopening`` are writes even when they only
# record a proposal; ``compile_context`` is a read.
AMNESIAC_TOOL_CLASSES: dict[str, str] = {
    "amnesiac.propose_candidates": "write",
    "amnesiac.record_outcome": "write",
    "amnesiac.request_reopening": "write",
    "amnesiac.compile_context": "read",
}

# Back-compat alias for the earlier name.
AMNESIAC_TOOL_WRITE_KINDS = AMNESIAC_TOOL_CLASSES

AMNESIAC_TOOL_NAMES: tuple[str, ...] = tuple(AMNESIAC_TOOL_CLASSES)


def _capability_unavailable_result(operation: str, detail: str) -> Any:
    """Build a FastMCP error result for a fail-closed capability-unavailable.

    ``isError`` is set so DAGRMiddleware classifies the outcome as
    ``error_returned`` rather than ``result_returned``. The structured content
    carries the canonical ``{status, operation, detail}`` shape."""
    from fastmcp.tools.base import ToolResult

    structured = {
        "status": "capability_unavailable",
        "operation": operation,
        "detail": detail,
        "note": (
            "The native Amnesiac producer required for this operation is not "
            "available. The server fails closed rather than reporting success."
        ),
    }
    return ToolResult(
        content=f"capability_unavailable: {operation}: {detail}",
        structured_content=structured,
        is_error=True,
    )


def _tool_error(message: str) -> Exception:
    from fastmcp.exceptions import ToolError

    return ToolError(message)


def register_amnesiac_tools(server: Any, service: AmnesiacService) -> None:
    """Register the four Amnesiac tools on a supplied FastMCP server.

    ``server`` is a ``fastmcp.FastMCP`` instance. ``service`` is any
    ``AmnesiacService`` (native for production, fake for contract tests). This
    only registers the tool functions; receipts and classification come from the
    installed ``DAGRMiddleware`` (see :func:`install_amnesiac_tools`)."""

    @server.tool(name="amnesiac.propose_candidates")
    def propose_candidates(
        source_ref: str,
        candidates: list[dict[str, Any]],
    ) -> Any:
        """Construct and persist candidate claims. Proposal-only: never admits."""
        request = ProposeCandidatesRequest(
            source_ref=source_ref,
            candidates=[
                ProposedClaim(
                    claim=c["claim"],
                    anchors=list(c.get("anchors", [])),
                    origin=dict(c.get("origin", {})),
                )
                for c in candidates
            ],
        )
        try:
            response = service.propose_candidates(request)
        except CapabilityUnavailable as exc:
            return _capability_unavailable_result(exc.operation, exc.detail)
        return _serialize(response)

    @server.tool(name="amnesiac.compile_context")
    def compile_context(
        task: str,
        matter: str | None = None,
        record_scope: list[str] | None = None,
        as_of: str | None = None,
        item_budget: int | None = None,
        include_refused: bool = False,
    ) -> Any:
        """Reference selector v0: deterministic lifecycle/scope/time filtering."""
        request = CompileContextRequest(
            task=task,
            matter=matter,
            record_scope=list(record_scope or []),
            as_of=as_of,
            item_budget=item_budget,
            include_refused=include_refused,
        )
        try:
            response = service.compile_context(request)
        except CapabilityUnavailable as exc:
            return _capability_unavailable_result(exc.operation, exc.detail)
        return _serialize(response)

    @server.tool(name="amnesiac.request_reopening")
    def request_reopening(
        candidate_ref: str,
        trigger_ref: str,
        new_evidence_refs: list[str] | None = None,
        ratified_decision_ref: str | None = None,
    ) -> Any:
        """Request reopening of a rejected candidate through the real guard.

        The caller cannot force REOPENED; a REOPENED transition is honored only
        when an injected admission authority ratifies ``ratified_decision_ref``.
        """
        request = RequestReopeningRequest(
            candidate_ref=candidate_ref,
            trigger_ref=trigger_ref,
            new_evidence_refs=list(new_evidence_refs or []),
            ratified_decision_ref=ratified_decision_ref,
        )
        try:
            response = service.request_reopening(request)
        except CapabilityUnavailable as exc:
            return _capability_unavailable_result(exc.operation, exc.detail)
        # Reopening carries capability_unavailable in its own status vocabulary
        # (guard not confirmed / no ShadowGraph repository). Per the fail-closed
        # rule it must still surface as an error result, never an ordinary
        # result_returned success.
        if getattr(response.status, "value", response.status) == "capability_unavailable":
            return _capability_unavailable_result(
                "amnesiac.request_reopening",
                response.detail or "reopening capability is unavailable",
            )
        return _serialize(response)

    @server.tool(name="amnesiac.record_outcome")
    def record_outcome(
        agent_outcome_ref: str | None = None,
        agent_outcome: dict[str, Any] | None = None,
        context_packet_ref: str | None = None,
    ) -> Any:
        """Bridge a refs-only agent outcome to a candidate. Refs-only.

        Accepts exactly one of ``agent_outcome_ref`` (resolved through an
        injected ``AgentOutcomeStore``) or a refs-only ``agent_outcome`` mapping.
        Raw model output, prompts, claims, transcripts, and tool arguments are
        refused."""
        request = RecordOutcomeRequest(
            agent_outcome_ref=agent_outcome_ref,
            agent_outcome=agent_outcome,
            context_packet_ref=context_packet_ref,
        )
        try:
            response = service.record_outcome(request)
        except RawPayloadRefused as exc:
            raise _tool_error(str(exc)) from exc
        except CapabilityUnavailable as exc:
            return _capability_unavailable_result(exc.operation, exc.detail)
        return _serialize(response)


# ---------------------------------------------------------------------------
# The single installation surface.
# ---------------------------------------------------------------------------


class AmnesiacClassificationError(ValueError):
    """Raised when the merged ``tool_classes`` does not classify all four
    Amnesiac tools exactly. Unknown or omitted classifications fail here rather
    than silently defaulting a write tool to read at the middleware."""


def merge_amnesiac_tool_classes(existing: Any) -> dict[str, str]:
    """Merge the Amnesiac tool classes into an existing ``tool_classes`` mapping.

    Returns a new dict; the input is not mutated. A conflicting classification
    for an Amnesiac tool name is an error, not a silent override."""
    merged: dict[str, str] = dict(existing or {})
    for name, cls in AMNESIAC_TOOL_CLASSES.items():
        if name in merged and merged[name] != cls:
            raise AmnesiacClassificationError(
                f"{name!r} is already classified as {merged[name]!r}; "
                f"Amnesiac requires {cls!r}"
            )
        merged[name] = cls
    return merged


def validate_amnesiac_tool_classes(tool_classes: Any) -> None:
    """Fail unless every Amnesiac tool is classified exactly as required.

    An omitted or wrong classification raises ``AmnesiacClassificationError``.
    This is the fail-closed check that prevents a write tool from silently
    defaulting to read at the middleware."""
    mapping = dict(tool_classes or {})
    for name, expected in AMNESIAC_TOOL_CLASSES.items():
        actual = mapping.get(name)
        if actual is None:
            raise AmnesiacClassificationError(
                f"{name!r} has no read/write classification; refusing to install "
                "(it would silently default to 'read')"
            )
        if actual != expected:
            raise AmnesiacClassificationError(
                f"{name!r} is classified {actual!r} but Amnesiac requires "
                f"{expected!r}"
            )


@dataclasses.dataclass(frozen=True)
class AmnesiacInstallation:
    """The result of installing the Amnesiac tools."""

    tool_names: tuple[str, ...]
    tool_classes: dict[str, str]
    middleware: Any | None
    config: Any


def install_amnesiac_tools(
    server: Any,
    service: AmnesiacService,
    *,
    emitter: Any | None = None,
    config: Any | None = None,
    middleware: Any | None = None,
) -> AmnesiacInstallation:
    """Single installation surface for the Amnesiac tools.

    Two modes:

    * **Install** — pass ``emitter`` and ``config`` (a ``DAGRMiddlewareConfig``).
      The Amnesiac tool classes are merged into ``config.tool_classes``, a
      ``DAGRMiddleware`` is built with the existing ``SignedReceiptEmitter`` and
      added to ``server``, and the four tools are registered.
    * **Validate** — pass an already-installed ``middleware``. Its
      ``config.tool_classes`` must already classify all four tools; otherwise
      installation fails. No second middleware and no parallel receipt family is
      created.

    In both modes the classification is validated fail-closed: an unknown or
    omitted Amnesiac classification raises ``AmnesiacClassificationError``.
    """
    from .fastmcp_binding import DAGRMiddleware, DAGRMiddlewareConfig  # noqa: F401

    if middleware is not None:
        # Validate mode: the middleware already carries the config. Confirm the
        # four tools are classified, then register tools only.
        validate_amnesiac_tool_classes(getattr(middleware.config, "tool_classes", {}))
        register_amnesiac_tools(server, service)
        return AmnesiacInstallation(
            tool_names=AMNESIAC_TOOL_NAMES,
            tool_classes=dict(middleware.config.tool_classes),
            middleware=middleware,
            config=middleware.config,
        )

    if emitter is None or config is None:
        raise ValueError(
            "install_amnesiac_tools requires either an installed `middleware`, "
            "or both `emitter` and `config` to install one"
        )

    merged = merge_amnesiac_tool_classes(getattr(config, "tool_classes", {}))
    validate_amnesiac_tool_classes(merged)
    new_config = dataclasses.replace(config, tool_classes=merged)
    installed = DAGRMiddleware(emitter=emitter, config=new_config)
    server.add_middleware(installed)
    register_amnesiac_tools(server, service)
    return AmnesiacInstallation(
        tool_names=AMNESIAC_TOOL_NAMES,
        tool_classes=merged,
        middleware=installed,
        config=new_config,
    )


def _serialize(response: Any) -> dict[str, Any]:
    """Convert a contract dataclass to a JSON-stable dict, rendering enums to
    their string values so the tool result is deterministic."""

    def convert(value: Any) -> Any:
        if isinstance(value, Enum):
            return value.value
        if isinstance(value, dict):
            return {k: convert(v) for k, v in value.items()}
        if isinstance(value, list):
            return [convert(v) for v in value]
        return value

    return convert(asdict(response))


__all__ = [
    "AMNESIAC_TOOL_CLASSES",
    "AMNESIAC_TOOL_NAMES",
    "AMNESIAC_TOOL_WRITE_KINDS",
    "AmnesiacClassificationError",
    "AmnesiacInstallation",
    "install_amnesiac_tools",
    "merge_amnesiac_tool_classes",
    "register_amnesiac_tools",
    "validate_amnesiac_tool_classes",
]
