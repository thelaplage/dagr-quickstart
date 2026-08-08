"""Binding-neutral MCP lifecycle contract and the FastMCP binding mask.

This package is deliberately separate from the ``dagr_mcp`` binding package.

* :mod:`dagr_mcp_lifecycle.contract` declares the *binding-neutral* lifecycle
  vocabulary — the portable names a governed MCP call moves through, independent
  of any one binding. It imports nothing from ``dagr_mcp``.
* :mod:`dagr_mcp_lifecycle.binding_mask` is the explicit mask that maps the
  existing, unmodified ``fastmcp.middleware.v0.1`` binding onto that vocabulary.
  It *depends on* ``dagr_mcp`` on purpose — the binding is the oracle.

**Import direction is deliberate.** Importing this package root, or
``dagr_mcp_lifecycle.contract``, must never eagerly import the FastMCP binding
(``dagr_mcp`` / ``fastmcp``): the neutral vocabulary has to be usable without the
binding present. So the root eagerly binds only the neutral ``contract``
submodule; ``binding_mask`` is a declared but lazily-imported submodule that
pulls in ``dagr_mcp`` only when it is itself imported.

The mask *describes* the binding; it never normalizes or repairs it. The
external FastMCP binding (``dagr_mcp.fastmcp_binding`` + ``dagr_mcp.srs_receipts``)
remains the sole behavioral oracle. Nothing here extracts, moves, or replaces
binding implementation, and nothing here emits receipts.

This package ships publicly but is *outside* the Sprint A1 ``dagr_mcp``-only
public-API snapshot. Its own public surface is frozen separately by
``tests/test_lifecycle_contract_hardening.py`` against
``tests/golden/neutral_lifecycle/public_api_surface.json`` so a later change
cannot silently claim parity with the A1 binding surface.
"""

# NB: no ``from __future__ import annotations`` here — that binds an
# ``annotations`` attribute on the package, which would be an accidental public
# export. The root deliberately exposes submodules only.

# Eager import of the neutral vocabulary only. This is binding-free (it imports
# nothing from ``dagr_mcp`` / ``fastmcp``), so importing the package root keeps
# the neutral contract available without pulling the binding into memory.
from dagr_mcp_lifecycle import contract as contract

# ``binding_mask`` is intentionally NOT imported here: it depends on ``dagr_mcp``
# and importing it eagerly would violate the neutral package's import direction.
# It is declared public and is bound lazily on first explicit use — either as an
# attribute (``dagr_mcp_lifecycle.binding_mask``) via the PEP 562 ``__getattr__``
# below, or by a direct submodule import (``from dagr_mcp_lifecycle import
# binding_mask``). Both routes pull ``dagr_mcp`` in only at that moment.
_LAZY_SUBMODULES = frozenset({"binding_mask"})

__all__ = ["contract", "binding_mask"]


def __getattr__(name):
    """Lazily bind the declared-but-unimported submodules (PEP 562).

    ``binding_mask`` is a declared public name that the root does not import
    eagerly, because importing it pulls the FastMCP binding (``dagr_mcp`` /
    ``fastmcp``) into memory and the neutral package must be importable without
    the binding present. On first explicit access the real submodule is imported
    and cached on the package, so later accesses never re-enter this hook. Every
    other unknown attribute raises :class:`AttributeError` in the normal way.
    """

    if name in _LAZY_SUBMODULES:
        # Import lazily. ``import_module`` binds the submodule as an attribute of
        # this package (caching it in ``globals()``), so the next access resolves
        # directly without re-entering ``__getattr__``; the explicit assignment
        # makes that caching intent unmistakable.
        import importlib

        module = importlib.import_module(f"{__name__}.{name}")
        globals()[name] = module
        return module
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__():
    """Expose the lazily-bound submodules alongside the real package globals.

    Without this, a declared-but-not-yet-accessed ``binding_mask`` would be
    absent from ``dir(dagr_mcp_lifecycle)`` until first access. Listing it keeps
    the declared public surface (``__all__``) discoverable and consistent
    regardless of whether the lazy submodule has been loaded yet.
    """

    return sorted(set(globals()) | _LAZY_SUBMODULES)
