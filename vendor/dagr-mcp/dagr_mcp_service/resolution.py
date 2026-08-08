"""Binding-selector types and lookup for the DAGR Gateway Service Adapter (A7).

Scope: ``docs/GATEWAY_SERVICE_ADAPTER_SCOPE.md`` §5 (binding resolution) and
§13 (proposed package shape), work package A7 ("Contract and models only").
The A7 acceptance criteria (scope §15) explicitly require the selector-key ->
binding-identity lookup itself, not only its data shapes: "selector key ->
binding identity; fail-closed unknown binding; fail-closed unavailable
binding." :func:`select_binding` is that narrowest pure, transport-free
configuration lookup. It does **not** build A8's orchestration
(``execute_governed_call``): it takes operator-provided configuration and a
selector key and returns either a resolved :class:`BindingHandle` or a
:class:`BindingResolutionRefused` fact. It never imports or invokes a binding
implementation, executes a tool, or binds a transport.

Two binding identities are registered as Gateway-selectable per §5:

* ``fastmcp.middleware.v0.1`` (:mod:`dagr_mcp.fastmcp_binding`)
* ``official-mcp-sdk.python.v0.1`` (:mod:`dagr_mcp_sdk_binding`)

Both strings are also members of
:data:`dagr_mcp.srs_receipts.ALL_REGISTERED_BINDING_VERSIONS`, but that set
additionally contains ``"direct-harness.v0.1"`` — the direct in-process
harness's own binding identity, which is not a Gateway-selectable binding
(the harness is not a remote/service binding at all). This module therefore
does not reuse ``ALL_REGISTERED_BINDING_VERSIONS`` directly as the Gateway's
selectable set; it defines the narrower, correct two-member set below.

The ``official-mcp-sdk.python.v0.1`` identity is imported directly from
:mod:`dagr_mcp_sdk_binding` — its package root is pure metadata (see that
package's own PEP 562 lazy-submodule discipline) and importing it pulls in
neither ``mcp`` nor ``fastmcp``. The ``fastmcp.middleware.v0.1`` identity
cannot be imported the same way: its only source,
``dagr_mcp.fastmcp_binding.BINDING_VERSION``, lives in a module that imports
``fastmcp`` at module scope. Importing it here would violate this package's
"no transport import at import time" rule (§13), so the literal is reproduced
instead. ``tests/test_gateway_service_resolution.py`` cross-checks this
reproduced literal against the live ``dagr_mcp.fastmcp_binding.BINDING_VERSION``
in a process that is allowed to import ``fastmcp``, so the duplication cannot
silently drift.

**Availability, not invocation.** "Unavailable" per §5.2 means the binding's
*optional dependency* is not installed (e.g. the ``official-sdk`` extra
absent), not that the binding raised or misbehaved. :func:`select_binding`
checks this with ``importlib.util.find_spec`` on the binding's underlying
top-level library module name — a pure existence probe that locates the
module without importing (executing) it, so no binding implementation module
is ever imported by this lookup.
"""

from __future__ import annotations

import importlib.util
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Literal

from dagr_mcp_sdk_binding import BINDING_VERSION as _SDK_BINDING_VERSION

# Reproduced, not imported — see module docstring for why.
FASTMCP_BINDING_VERSION = "fastmcp.middleware.v0.1"
SDK_BINDING_VERSION = _SDK_BINDING_VERSION

# The exact, narrow set of binding identities the Gateway may select between
# (§5). Deliberately smaller than
# ``dagr_mcp.srs_receipts.ALL_REGISTERED_BINDING_VERSIONS``: it excludes
# ``"direct-harness.v0.1"``, which is registered on the shared receipt emitter
# but is not a Gateway-selectable binding.
SUPPORTED_BINDING_VERSIONS: frozenset[str] = frozenset(
    {FASTMCP_BINDING_VERSION, SDK_BINDING_VERSION}
)

# The top-level, importable library each binding depends on, used only for a
# find_spec existence probe (§5.2 "unavailable") — never imported by this
# module. fastmcp is a base runtime dependency (always findable once this
# package is installed at all); mcp is the ``official-sdk`` optional extra.
_BINDING_LIBRARY_PROBE_MODULES: dict[str, str] = {
    FASTMCP_BINDING_VERSION: "fastmcp",
    SDK_BINDING_VERSION: "mcp",
}


def _binding_library_importable(binding_version: str) -> bool:
    probe_module = _BINDING_LIBRARY_PROBE_MODULES[binding_version]
    return importlib.util.find_spec(probe_module) is not None


BindingResolutionFailureReason = Literal["unknown_binding", "binding_unavailable"]


@dataclass(frozen=True, slots=True, kw_only=True)
class BindingSelectorKey:
    """The configured binding selector a caller-facing request carries.

    Per §3.2, this is "a *selector key*, not a free binding string": the
    caller supplies a key that is resolved against operator-provided
    configuration by :func:`select_binding`. It is deliberately an opaque
    wrapper around a plain string rather than a bare ``str`` field on the
    request, so a request cannot smuggle an arbitrary binding-version stamp
    through this field by construction alone (§3.3's prohibited "arbitrary
    binding-version stamp").
    """

    key: str

    def __post_init__(self) -> None:
        if not isinstance(self.key, str) or not self.key.strip():
            raise ValueError("BindingSelectorKey.key must be a non-empty string")


@dataclass(frozen=True, slots=True, kw_only=True)
class BindingHandle:
    """A resolved binding identity (§13's ``BindingHandle``-shaped type).

    ``binding_version`` must be a member of :data:`SUPPORTED_BINDING_VERSIONS`
    — the stamp is always the *selected binding's* fixed identity, never an
    arbitrary caller-suppliable string (§3.3).
    """

    binding_version: str

    def __post_init__(self) -> None:
        if self.binding_version not in SUPPORTED_BINDING_VERSIONS:
            raise ValueError(
                "BindingHandle.binding_version must be one of "
                f"{sorted(SUPPORTED_BINDING_VERSIONS)!r}, got "
                f"{self.binding_version!r}"
            )


@dataclass(frozen=True, slots=True, kw_only=True)
class BindingResolutionRefused:
    """A fail-closed binding-resolution outcome (§5.2).

    Returned by :func:`select_binding` instead of a :class:`BindingHandle`
    when the selector key is not present in operator configuration
    (``reason="unknown_binding"``) or names a registered binding whose
    optional dependency is not installed (``reason="binding_unavailable"``).
    ``reason`` reuses the exact diagnostic spellings
    :data:`dagr_mcp_service.contract.GATEWAY_DIAGNOSTIC_CODES` names for
    these two failure states, so a caller can carry this value straight onto
    a ``GovernedCallResponse.diagnostic_code`` without re-spelling it. There
    is deliberately no third variant that substitutes another binding —
    every non-success path is one of these two refusals.
    """

    selector_key: str
    reason: BindingResolutionFailureReason

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "selector_key",
            self.selector_key if isinstance(self.selector_key, str) else str(self.selector_key),
        )
        if self.reason not in ("unknown_binding", "binding_unavailable"):
            raise ValueError(
                "BindingResolutionRefused.reason must be 'unknown_binding' or "
                f"'binding_unavailable', got {self.reason!r}"
            )


def select_binding(
    binding_registry: Mapping[str, str],
    selector: BindingSelectorKey,
    *,
    is_binding_available: Callable[[str], bool] = _binding_library_importable,
) -> BindingHandle | BindingResolutionRefused:
    """Resolve ``selector`` against operator-provided ``binding_registry`` (§5).

    ``binding_registry`` is operator/deployment configuration mapping selector
    keys to registered binding-version strings — never a model tool argument
    and never a caller-selected binding-version stamp (§3.3, §5). This
    function performs a single dict lookup plus one availability probe; it
    imports or invokes no binding implementation, executes no tool, and binds
    no transport.

    Fails closed on both named §5.2 conditions, and never substitutes:

    * the selector key is absent from ``binding_registry``, or maps to a
      value outside :data:`SUPPORTED_BINDING_VERSIONS` -> ``unknown_binding``;
    * the key resolves to a supported binding version whose underlying
      library is not importable -> ``binding_unavailable``.

    ``is_binding_available`` defaults to a pure ``importlib.util.find_spec``
    probe; tests inject a stub to exercise the ``binding_unavailable`` path
    deterministically without uninstalling a real dependency.
    """

    if not isinstance(binding_registry, Mapping):
        raise TypeError(
            f"binding_registry must be a Mapping, got {type(binding_registry).__name__}"
        )
    if not isinstance(selector, BindingSelectorKey):
        raise TypeError(
            f"selector must be a BindingSelectorKey, got {type(selector).__name__}"
        )

    binding_version = binding_registry.get(selector.key)
    if binding_version is None or binding_version not in SUPPORTED_BINDING_VERSIONS:
        return BindingResolutionRefused(selector_key=selector.key, reason="unknown_binding")

    if not is_binding_available(binding_version):
        return BindingResolutionRefused(selector_key=selector.key, reason="binding_unavailable")

    return BindingHandle(binding_version=binding_version)


__all__ = [
    "FASTMCP_BINDING_VERSION",
    "SDK_BINDING_VERSION",
    "SUPPORTED_BINDING_VERSIONS",
    "BindingResolutionFailureReason",
    "BindingSelectorKey",
    "BindingHandle",
    "BindingResolutionRefused",
    "select_binding",
]
