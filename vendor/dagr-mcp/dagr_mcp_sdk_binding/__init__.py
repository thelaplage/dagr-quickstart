"""DAGR lifecycle binding over the official Python MCP SDK (Sprint A5).

The *second* DAGR lifecycle binding. The first is the FastMCP binding
(:mod:`dagr_mcp.fastmcp_binding`, ``fastmcp.middleware.v0.1``); this one binds the
official ``mcp`` SDK's lowlevel server (``official-mcp-sdk.python.v0.1``). Both
bindings defer every lifecycle decision to the single neutral core
(:mod:`dagr_mcp_lifecycle.core`); this package owns only the official-SDK binding
responsibilities.

Submodules:

* :mod:`dagr_mcp_sdk_binding.adapter` — the lifecycle adapter and construction config.
* :mod:`dagr_mcp_sdk_binding.mask` — the ``official-mcp-sdk.python.v0.1`` binding mask.
* :mod:`dagr_mcp_sdk_binding.server` — the supported ``mcp`` server construction surface.

The binding-version stamp is available as :data:`BINDING_VERSION` *without*
importing the official SDK. The three submodules are declared but loaded lazily
(PEP 562): importing this package — or the neutral core — never eagerly imports
``mcp`` or ``fastmcp`` and never starts a transport. The first attribute access
imports the requested submodule.
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING

# Pure metadata: importable with neither the official SDK nor FastMCP present.
BINDING_VERSION = "official-mcp-sdk.python.v0.1"

__all__ = ["BINDING_VERSION", "adapter", "mask", "server"]

_LAZY_SUBMODULES = frozenset({"adapter", "mask", "server"})


def __getattr__(name: str):
    if name in _LAZY_SUBMODULES:
        module = importlib.import_module(f"{__name__}.{name}")
        globals()[name] = module
        return module
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | _LAZY_SUBMODULES | {"BINDING_VERSION"})


if TYPE_CHECKING:  # pragma: no cover - import-time typing only, not eager at runtime.
    from dagr_mcp_sdk_binding import adapter, mask, server
