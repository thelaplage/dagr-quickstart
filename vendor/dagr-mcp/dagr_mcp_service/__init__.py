"""DAGR Gateway Service Adapter — neutral contract and model layer (Sprint A7).

This package is the *service-seam* sibling of :mod:`dagr_mcp_lifecycle`
(binding-neutral lifecycle vocabulary) and :mod:`dagr_mcp_sdk_binding`
(a concrete binding). Its purpose and scope are recorded in
``docs/GATEWAY_SERVICE_ADAPTER_SCOPE.md`` (§13, §15, work package A7).

**What this sprint (A7) adds.** Two submodules — data models, validation, and
the one pure configuration lookup A7's acceptance criteria (§15) name
explicitly:

* :mod:`dagr_mcp_service.contract` — a two-stage request contract
  (``CallerGovernedCallRequest``, the untrusted caller-facing input, and
  ``GovernedCallRequest``, the internal service-resolved request — see §3.3)
  plus ``GovernedCallResponse`` and the supporting value types that separate
  the response's distinct concerns (business result, DAGR decision, receipt
  handles, custody reference, retry/continuation instruction, diagnostic
  code) per §4 of the scope document.
* :mod:`dagr_mcp_service.resolution` — binding *selector* types (a selector
  key type and a ``BindingHandle``-shaped resolved-identity type) plus
  ``select_binding(...)``: a narrow, pure, transport-free lookup from an
  operator-configured selector key to a registered binding identity,
  fail-closed on an unknown or unavailable binding (§5.2).

**What Sprint A8 adds.** Two more submodules — the first executable,
in-process Gateway composition seam:

* :mod:`dagr_mcp_service.adapter` — ``execute_governed_call``: orchestrates
  one governed call over a selected binding (shape A/C in-process, no
  network transport), reusing both existing bindings' own resolver seams and
  the neutral lifecycle core unchanged.
* :mod:`dagr_mcp_service.connectors` — the in-process (``memory``) and
  client-side remote (``remote``) target connectors.

**What Sprint A10 adds.** One more submodule — the receipt-handle
resolution and composition seam:

* :mod:`dagr_mcp_service.access` — ``resolve_receipt``/``compose_receipts``:
  resolves a returned ``ReceiptHandle`` back to its exact, existing signed
  receipt envelope through an operator-configured provider, verifies it with
  the repository's own parse/schema/signature discipline, and composes a
  verified admission/outcome pair. Reads only; mints no new receipt.

**What this package still does NOT add.** No idempotency, deduplication, or
exactly-once guarantee is encoded here or claimed by it (see scope §11 —
those questions remain open). No subscription endpoint, receipt streaming,
or public Gateway host.

**Import discipline.** This package must be importable with neither ``mcp``
nor ``fastmcp`` (nor any HTTP/ASGI/database/queue library) installed, and
importing it must never start a transport or bind a socket — the same
discipline :mod:`dagr_mcp_lifecycle` and :mod:`dagr_mcp_sdk_binding` already
guarantee via PEP 562 lazy submodules. ``adapter`` imports the concrete
binding module a given call actually selects lazily, inside the function
that drives that one call — never at this package's or ``adapter``'s own
module-load time.
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING

# Pure metadata: importable with neither a transport library nor any
# submodule's own dependencies present.
SERVICE_PACKAGE_ID = "dagr.mcp.gateway_service"
SERVICE_PACKAGE_VERSION = "v0.1"

__all__ = [
    "SERVICE_PACKAGE_ID",
    "SERVICE_PACKAGE_VERSION",
    "contract",
    "resolution",
    "adapter",
    "connectors",
    "access",
]

_LAZY_SUBMODULES = frozenset({"contract", "resolution", "adapter", "connectors", "access"})


def __getattr__(name: str):
    if name in _LAZY_SUBMODULES:
        module = importlib.import_module(f"{__name__}.{name}")
        globals()[name] = module
        return module
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(
        set(globals()) | _LAZY_SUBMODULES | {"SERVICE_PACKAGE_ID", "SERVICE_PACKAGE_VERSION"}
    )


if TYPE_CHECKING:  # pragma: no cover - import-time typing only, not eager at runtime.
    from dagr_mcp_service import access, adapter, connectors, contract, resolution
