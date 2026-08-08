"""In-process, allowlisted local-target connector for the Gateway (Sprint A8).

Scope: ``docs/GATEWAY_SERVICE_ADAPTER_SCOPE.md`` §13 (``connectors/memory.py``),
work package A8. This module resolves a
:class:`dagr_mcp_service.contract.GovernedCallRequest`'s
``(target_server_ref.handle, tool_name)`` pair to an operator-registered,
in-process Python callable — never a URL, hostname, port, subprocess, socket,
or arbitrary caller-supplied import path.

**In-process only.** :class:`InMemoryToolConnector` is constructed from a
plain, operator-provided mapping of target handles to tool-name -> callable
registries. It performs a dict lookup only; it never opens a socket, spawns a
process, negotiates a transport, or imports a caller-named module. Resolving
an unknown target handle or an unknown tool name returns a
:class:`MemoryTargetResolutionRefused` fact instead of raising or
substituting — the caller (A8's ``execute_governed_call``) decides how to
translate that into a fail-closed :class:`~dagr_mcp_service.contract.
GovernedCallResponse` before any tool ever executes.

**No raw-argument retention.** This module never receives or stores call
arguments at all — it resolves *only* ``target_server_ref.handle`` and
``tool_name`` (both non-sensitive routing facts) to a callable. Arguments
remain the caller's transient concern, forwarded directly to the resolved
callable and never passed through, cached, or logged here.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any, Literal, TypeAlias

# A resolved in-process target: given the (already argument-digest-verified)
# call arguments, returns a result or raises. Mirrors the shape of both
# existing bindings' own dispatch-delegate seams
# (``dagr_mcp_sdk_binding.adapter.ToolHandler`` / the FastMCP binding's
# ``call_next``-invoked tool body) so the same registered callable can be
# driven through either binding unchanged.
LocalToolHandler: TypeAlias = Callable[[Mapping[str, Any]], "Awaitable[Any] | Any"]

MemoryTargetResolutionFailureReason = Literal[
    "remote_unavailable", "unknown_tool_fail_closed"
]


@dataclass(frozen=True, slots=True, kw_only=True)
class MemoryTargetResolutionRefused:
    """A fail-closed local-target resolution outcome.

    ``reason`` reuses two of the existing stable diagnostics rather than
    inventing a new taxonomy: an unregistered ``target_server_ref.handle``
    reads as the referenced "remote" being unavailable
    (:data:`dagr_mcp_service.contract.GATEWAY_DIAGNOSTIC_CODES`'s
    ``remote_unavailable``); an unregistered tool name under a known handle
    reuses the neutral core's own ``unknown_tool_fail_closed`` refusal
    ground. There is no third variant that substitutes another target —
    every non-success path is one of these two refusals.
    """

    target_handle: str
    tool_name: str
    reason: MemoryTargetResolutionFailureReason


class InMemoryToolConnector:
    """Resolves ``(target_handle, tool_name)`` to a registered local callable.

    ``targets`` is operator/deployment configuration — never a model tool
    argument and never a caller-selected transport — mapping an
    allowlisted target handle to its exposed tool-name -> callable registry.
    This performs a plain two-level dict lookup; it imports or invokes
    nothing else, and it never mutates the registry it was constructed with.
    """

    def __init__(self, targets: Mapping[str, Mapping[str, LocalToolHandler]]) -> None:
        self._targets: dict[str, dict[str, LocalToolHandler]] = {
            str(handle): dict(tools) for handle, tools in targets.items()
        }

    def resolve(
        self, target_handle: str, tool_name: str
    ) -> LocalToolHandler | MemoryTargetResolutionRefused:
        tools = self._targets.get(target_handle)
        if tools is None:
            return MemoryTargetResolutionRefused(
                target_handle=target_handle,
                tool_name=tool_name,
                reason="remote_unavailable",
            )
        handler = tools.get(tool_name)
        if handler is None:
            return MemoryTargetResolutionRefused(
                target_handle=target_handle,
                tool_name=tool_name,
                reason="unknown_tool_fail_closed",
            )
        return handler


__all__ = [
    "LocalToolHandler",
    "MemoryTargetResolutionFailureReason",
    "MemoryTargetResolutionRefused",
    "InMemoryToolConnector",
]
