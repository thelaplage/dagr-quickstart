"""Supported construction surface for the official-SDK DAGR binding.

Wires an :class:`dagr_mcp_sdk_binding.adapter.SdkLifecycleAdapter` onto an
``mcp.server.lowlevel.Server`` using the official public seam — the
``@server.list_tools()`` and ``@server.call_tool()`` handler registrations. The
governed call handler reads the *trusted* ``server.request_context`` and hands it
(never the model arguments) to actor/policy resolution.

There is no module-global mutable configuration: a caller constructs an adapter
and passes it, along with a tool registry or a delegated call handler, to
:func:`wrap_server` or :func:`build_governed_server`. Importing this module
imports the official SDK but never ``fastmcp`` and starts no transport.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from mcp import types as mcp_types
from mcp.server.lowlevel import Server

from dagr_mcp_sdk_binding.adapter import SdkLifecycleAdapter, ToolHandler

# A delegated call handler dispatches an admitted call for tools not in the
# explicit registry: ``async def handler(name, arguments) -> result``.
DelegatedCallHandler = "Callable[[str, Mapping[str, Any]], Any]"


@dataclass(frozen=True, slots=True)
class GovernedTool:
    """A fixture tool: its official-SDK definition and its dispatch handler."""

    definition: mcp_types.Tool
    handler: ToolHandler


def _registry(tools: Sequence[GovernedTool]) -> dict[str, GovernedTool]:
    registry: dict[str, GovernedTool] = {}
    for tool in tools:
        registry[tool.definition.name] = tool
    return registry


def _make_delegate(
    name: str,
    registry: Mapping[str, GovernedTool],
    delegated_call_handler,
) -> ToolHandler:
    """Return the dispatch delegate for *name* (registry, else delegated handler).

    The delegate is invoked by the adapter ONLY when admission proceeds, so an
    unknown/refused tool never reaches a missing handler.
    """

    tool = registry.get(name)
    if tool is not None:
        return tool.handler
    if delegated_call_handler is not None:
        async def _delegate(arguments):
            return await _maybe_await(delegated_call_handler(name, arguments))

        return _delegate

    def _missing(_arguments):
        raise LookupError(f"no delegated handler for admitted tool {name!r}")

    return _missing


async def _maybe_await(value):
    import inspect

    if inspect.isawaitable(value):
        return await value
    return value


def wrap_server(
    server: Server,
    adapter: SdkLifecycleAdapter,
    *,
    tools: Sequence[GovernedTool] = (),
    delegated_call_handler=None,
) -> Server:
    """Register DAGR-governed ``list_tools`` / ``call_tool`` handlers on *server*.

    ``tools`` are the fixture tools exposed by ``tools/list`` and dispatched by
    ``tools/call``. ``delegated_call_handler`` dispatches admitted calls for names
    not in ``tools``. The governed handler runs the neutral lifecycle around each
    dispatch and emits signed receipts.
    """

    registry = _registry(tools)
    definitions = [tool.definition for tool in tools]

    @server.list_tools()
    async def _list_tools() -> list[mcp_types.Tool]:
        return list(definitions)

    @server.call_tool()
    async def _call_tool(name: str, arguments: dict) -> object:
        try:
            request_context = server.request_context
        except LookupError:
            request_context = None
        delegate = _make_delegate(name, registry, delegated_call_handler)
        return await adapter.governed_call(
            name, arguments, delegate, request_context=request_context
        )

    return server


def build_governed_server(
    name: str,
    *,
    adapter: SdkLifecycleAdapter,
    tools: Sequence[GovernedTool] = (),
    delegated_call_handler=None,
    version: str | None = None,
) -> Server:
    """Create a fresh lowlevel ``Server`` and register the DAGR governed handlers."""

    server: Server = Server(name, version=version)
    return wrap_server(
        server,
        adapter,
        tools=tools,
        delegated_call_handler=delegated_call_handler,
    )


__all__ = [
    "GovernedTool",
    "wrap_server",
    "build_governed_server",
]
