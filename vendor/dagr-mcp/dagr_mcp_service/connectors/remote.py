"""Client-side remote MCP connector for the Gateway (Sprint A9).

Scope: ``docs/GATEWAY_SERVICE_ADAPTER_SCOPE.md`` §7 (transport decision
surface), §8 (authority/tenant model), §12 (security/privacy), §13
(``connectors/http.py`` — implemented here as ``connectors/remote.py``, one
concrete connector rather than a transport framework), work package A9. This
module resolves a :class:`dagr_mcp_service.contract.GovernedCallRequest`'s
``(target_server_ref.handle, tool_name)`` pair to an operator-allowlisted
*remote* MCP server reached over the pinned ``mcp==1.28.1`` client's
Streamable HTTP transport (:mod:`mcp.client.streamable_http`,
:class:`mcp.client.session.ClientSession`) — the only transport §7
recommends for a real remote target and the one this module implements.

**No caller-supplied URL, scheme, host, port, path, transport, headers,
credential, timeout, or redirect policy.** :class:`RemoteTargetConfig` is
closed, immutable, operator-authored configuration keyed by
``target_server_ref.handle`` (§3.2 SSRF discipline, mirroring
:mod:`dagr_mcp_service.connectors.memory`'s allowlist model). A caller's
``GovernedCallRequest`` carries only the target *handle*; every connection
fact this module needs is looked up from that handle against
:class:`RemoteToolConnector`'s operator-provided registry, never read from a
tool argument or from the request.

**Endpoint validation happens at configuration-construction time, not at
call time.** ``RemoteTargetConfig.__post_init__`` requires ``https`` unless
the operator explicitly opts a ``127.0.0.1``/``localhost``/``::1`` ``http``
target into ``allow_insecure_loopback=True`` (the loopback exception §7
carves out for tests), and rejects URL userinfo (``user:pass@host``, a
classic host-confusion vector) and a URL fragment outright. A config with
an unsupported scheme, userinfo, or fragment cannot be constructed at all,
so it can never reach :class:`RemoteToolConnector`'s registry and can never
cause a socket to open.

**Redirects and environment proxies.** The outbound ``httpx.AsyncClient``
always sets ``trust_env=False``, so ``HTTP_PROXY``/``HTTPS_PROXY``/``NO_PROXY``
environment variables can never silently reroute a credentialed connection
through an unconfigured proxy. ``allow_redirects`` defaults to ``False``; if
an operator opts a target into it, a request-event hook strips every header
name the credential provider supplied whenever a redirect response's
``Location`` resolves to a different origin than ``endpoint_uri`` — httpx's
own redirect handling only strips ``Authorization`` (and only cross-origin),
which is not sufficient for an arbitrary operator-chosen credential header
name.

**No ratified wire representation for trusted actor/tenant identity.** Per
the governing scope document's hard authority gate, this repository does not
ratify an HTTP header name, JWT claim, or any other wire format for
``actor_ref``/``tenant_ref``. This module never serializes either value into
a header, URL, or tool argument. :class:`TrustedOutboundContext` carries them
as opaque internal refs to an operator-controlled
:data:`RemoteCredentialProvider` callable *only* — the provider decides, out
of band, whether and how to turn them into outbound credential material
(e.g. a bearer header for a specific deployment's own JWT-issuing service).
This module makes no claim that the remote server authenticates or
understands the resulting header; it only proves the trusted values reach
the provider seam and that whatever the provider returns reaches the wire.

**Credential lifetime.** A provider's :class:`RemoteCredential` is obtained
immediately before the connection opens, held only as a local variable for
the duration of one call, merged into a per-call ``httpx.AsyncClient`` that
is never retained past that call, and never logged, receipted, or returned
to a caller. A provider failure raises before any socket opens; it is never
mistaken for a *remote* failure (§10's "do not label it a remote server
failure when no connection was attempted") because it is indistinguishable,
at the Gateway response layer, from any other ordinary tool-body exception
that also never claims network involvement (``diagnostic_code=
"remote_exception"`` — the same generic, closed-vocabulary code both existing
bindings already use for a raised exception with no more specific cause).

**Import discipline.** Importing this module never imports ``httpx``,
``mcp.client.*``, or any HTTP/network library — those are imported lazily,
only inside the coroutine that actually opens a connection, matching
:mod:`dagr_mcp_service.adapter`'s own "concrete binding module imported
lazily, inside the function that drives one call" discipline.

**No retry, idempotency, or transport framework.** One ``call_tool`` per
invocation of the handler this module returns; no reconnect-and-replay, no
backoff, no dedup key, no generic pluggable-transport abstraction — one
concrete Streamable HTTP connector, per §13's explicit preference.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal, TypeAlias
from urllib.parse import urlsplit

# A resolved remote target handler: given the (already argument-digest-
# verified) call arguments, returns the remote tool's result or raises.
# Structurally identical to
# ``dagr_mcp_service.connectors.memory.LocalToolHandler`` (both connectors
# are driven through the same A8 ``connector.resolve(...)`` seam), redefined
# here rather than imported so this module stays independently importable
# without pulling in the memory connector.
RemoteToolHandler: TypeAlias = Callable[[Mapping[str, Any]], "Awaitable[Any] | Any"]

RemoteTargetResolutionFailureReason = Literal["remote_unavailable"]

_LOOPBACK_HOSTNAMES: frozenset[str] = frozenset({"127.0.0.1", "localhost", "::1"})

# httpx.codes.REQUEST_TIMEOUT, reproduced as a plain int rather than importing
# httpx at module scope (see the module docstring's import-discipline note).
# mcp.shared.session.BaseSession.send_request stamps exactly this numeric
# value on the McpError it raises when its own anyio.fail_after read-timeout
# fires -- confirmed by reading mcp/shared/session.py at the pinned
# mcp==1.28.1 revision installed in this repository's venv.
_MCP_REQUEST_TIMEOUT_CODE = 408


@dataclass(frozen=True, slots=True, kw_only=True)
class TrustedOutboundContext:
    """The narrowest internal-refs-only context a credential provider may see.

    Carries no raw tool arguments (§ "Trusted outbound context" — "It must
    not receive raw tool arguments"), no credential, and no signing
    identity. ``actor_ref``/``tenant_ref`` are already-resolved opaque refs
    from :class:`dagr_mcp_service.contract.GovernedCallRequest` (the same
    scoped-hash-ref convention both existing bindings use) — never a raw
    claim, never caller-suppliable, and never placed on the wire by this
    module itself.
    """

    target_handle: str
    tool_name: str
    actor_ref: str
    tenant_ref: str | None
    parent_receipt_ref: str | None
    request_ref: str


@dataclass(frozen=True, slots=True, kw_only=True)
class RemoteCredential:
    """Narrowly typed, ephemeral provider output (§ "Credential semantics").

    ``headers`` is the only outbound-wire effect a provider may produce: a
    closed set of HTTP header values merged onto the one outbound connection
    this credential was minted for. Not caller-deserializable — there is no
    caller-facing constructor path onto this type; only an operator-supplied
    :data:`RemoteCredentialProvider` produces one, out of band, per call.
    """

    headers: Mapping[str, str] = field(default_factory=dict)


# An operator-controlled, out-of-band credential/context provider. Returning
# ``None`` is a provider's own explicit "no credential needed for this call"
# signal (legitimate for a no-auth target); raising is a provider *failure*
# and executes no remote tool (see ``_call_remote_tool``). Never configured
# through a tool argument or the request itself -- only through
# ``RemoteTargetConfig.credential_provider``, operator/deployment
# configuration.
RemoteCredentialProvider: TypeAlias = Callable[
    [TrustedOutboundContext], "Awaitable[RemoteCredential | None] | RemoteCredential | None"
]


@dataclass(frozen=True, slots=True, kw_only=True)
class RemoteTargetConfig:
    """Closed, immutable, operator-authored remote target (§3.2 SSRF, §7).

    Every connection fact a call needs lives here, fixed by the operator at
    configuration time. A caller's ``GovernedCallRequest`` supplies only
    ``target_server_ref.handle`` — a lookup key into
    :class:`RemoteToolConnector`'s registry — never a URL, scheme, host,
    port, path, transport, header, credential, timeout, or redirect policy.

    ``endpoint_uri`` must use ``https`` unless ``allow_insecure_loopback`` is
    explicitly ``True`` *and* the host is ``127.0.0.1``/``localhost``/``::1``
    — the one operator-controlled exception §7 permits for loopback tests.
    Validation happens here, at construction time: a config this
    constructor rejects can never enter a connector's registry and can
    therefore never cause a socket to open for an unsupported scheme.
    """

    handle: str
    endpoint_uri: str
    timeout_seconds: float = 30.0
    allow_redirects: bool = False
    tls_verify: bool = True
    allow_insecure_loopback: bool = False
    credential_provider: RemoteCredentialProvider | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.handle, str) or not self.handle.strip():
            raise ValueError("RemoteTargetConfig.handle must be a non-empty string")
        if not isinstance(self.endpoint_uri, str) or not self.endpoint_uri.strip():
            raise ValueError("RemoteTargetConfig.endpoint_uri must be a non-empty string")
        if not isinstance(self.timeout_seconds, int | float) or self.timeout_seconds <= 0:
            raise ValueError("RemoteTargetConfig.timeout_seconds must be a positive number")

        parsed = urlsplit(self.endpoint_uri)
        if parsed.username is not None or parsed.password is not None:
            raise ValueError(
                "RemoteTargetConfig.endpoint_uri must not carry URL userinfo "
                f"(user:pass@host); got {self.endpoint_uri!r}"
            )
        if parsed.fragment:
            raise ValueError(
                "RemoteTargetConfig.endpoint_uri must not carry a fragment; "
                f"got {self.endpoint_uri!r}"
            )
        if parsed.scheme == "https":
            return
        if parsed.scheme == "http":
            if self.allow_insecure_loopback and parsed.hostname in _LOOPBACK_HOSTNAMES:
                return
            raise ValueError(
                "RemoteTargetConfig.endpoint_uri uses 'http' but is not an "
                "explicit, operator-approved insecure-loopback target "
                "(allow_insecure_loopback=True to a 127.0.0.1/localhost/::1 "
                f"host); got {self.endpoint_uri!r}"
            )
        raise ValueError(
            "RemoteTargetConfig.endpoint_uri must use 'https' (or 'http' to "
            f"an explicit insecure-loopback target); got scheme {parsed.scheme!r}"
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class RemoteTargetResolutionRefused:
    """A fail-closed remote-target resolution outcome.

    ``reason`` reuses the existing ``remote_unavailable`` diagnostic
    (:data:`dagr_mcp_service.contract.GATEWAY_DIAGNOSTIC_CODES`) rather than
    inventing a new taxonomy — the same spelling
    :class:`dagr_mcp_service.connectors.memory.MemoryTargetResolutionRefused`
    already uses for an unregistered target handle. There is no other
    variant and no substitution: an unknown handle is always this refusal,
    and it is returned, never raised, before any connection is attempted.
    """

    target_handle: str
    tool_name: str
    reason: RemoteTargetResolutionFailureReason = "remote_unavailable"


def _flatten_exception_group(exc: BaseException) -> list[BaseException]:
    if isinstance(exc, BaseExceptionGroup):
        leaves: list[BaseException] = []
        for sub in exc.exceptions:
            leaves.extend(_flatten_exception_group(sub))
        return leaves
    return [exc]


def _translate_transport_failure(exc: BaseException) -> BaseException:
    """Classify a raised transport failure into one of three honest buckets.

    The pinned ``mcp`` client wraps almost every failure raised from inside
    ``streamable_http_client``'s task group in a ``BaseExceptionGroup`` —
    confirmed empirically against the installed ``mcp==1.28.1`` client, not
    assumed from documentation — so this function always flattens first.

    Priority order, each grounded in an accurately distinct claim:

    1. ``asyncio.CancelledError`` — passed through unchanged, so the caller's
       own ``except asyncio.CancelledError`` (and, above it, both bindings'
       identical handling) sees genuine cancellation, never a translated
       substitute.
    2. ``httpx.ConnectError`` (DNS failure, refused connection) — translated
       to a plain :class:`ConnectionError`. No socket-level connection was
       ever established, so execution definitely did not happen; this is the
       one case this module can honestly ground as "the target is
       unavailable," not merely "an exception occurred."
    3. An ``McpError`` whose ``error.code`` matches the exact numeric value
       ``mcp.shared.session.BaseSession.send_request`` stamps when its own
       read-timeout fires, or any other ``httpx.TimeoutException`` (a
       connection that opened but did not complete in time) — translated to
       a plain builtin :class:`TimeoutError`. Both existing bindings already
       special-case ``isinstance(exc, TimeoutError)`` and subsume it into the
       core's own honest "execution state unknown" timeout handling
       (confirmed by reading ``dagr_mcp/fastmcp_binding.py`` and
       ``dagr_mcp_sdk_binding/adapter.py`` — unmodified by this module); a
       plain :class:`TimeoutError` is the only signal this module needs to
       send for that existing, frozen path to apply correctly.
    4. Anything else — a generic :class:`RuntimeError`, the honest "some
       other protocol/decoding exception occurred" bucket
       (``diagnostic_code="remote_exception"`` downstream) with no further
       claim about cause.

    None of the four returned exception types is ever constructed with the
    original exception's message, a URL, a header, or credential material —
    only a fixed, content-free description.
    """

    import httpx
    from mcp.shared.exceptions import McpError

    leaves = _flatten_exception_group(exc)

    for leaf in leaves:
        if isinstance(leaf, asyncio.CancelledError):
            return leaf

    for leaf in leaves:
        if isinstance(leaf, httpx.ConnectError):
            return ConnectionError("remote MCP target connection failed")

    for leaf in leaves:
        if isinstance(leaf, McpError) and getattr(leaf.error, "code", None) == (
            _MCP_REQUEST_TIMEOUT_CODE
        ):
            return TimeoutError("timed out waiting for a response from the remote MCP target")
        if isinstance(leaf, httpx.TimeoutException):
            return TimeoutError("timed out communicating with the remote MCP target")

    return RuntimeError("remote MCP protocol or decoding exception")


async def _resolve_credential_headers(
    target: RemoteTargetConfig, context: TrustedOutboundContext | None
) -> dict[str, str]:
    """Run the operator's credential provider exactly once, immediately
    before the connection opens (§ "Credential semantics" ordering).

    A provider that raises executes no remote tool: the exception propagates
    out of this function *before* ``_call_remote_tool`` ever imports
    ``httpx``/``mcp.client`` or opens a socket. It is never wrapped as a
    :class:`ConnectionError` (that would falsely claim a remote-server
    failure when no connection was attempted); it is left as whatever type
    the provider itself raised, which both existing bindings' generic
    exception handling classifies as an ordinary admitted-call exception —
    the same honest, closed-vocabulary ``remote_exception`` bucket used for
    any other tool-body failure.
    """

    if target.credential_provider is None:
        return {}

    result = target.credential_provider(context)
    if isinstance(result, Awaitable):
        result = await result

    if result is None:
        return {}
    if not isinstance(result, RemoteCredential):
        raise TypeError(
            "credential_provider must return a RemoteCredential or None, "
            f"got {type(result).__name__}"
        )
    return dict(result.headers)


def _origin(url: str) -> tuple[str, str | None, int | None]:
    """The ``(scheme, hostname, port)`` triple ``urlsplit`` exposes for
    ``url``, used only for an equality comparison — never logged, never
    embedded in an exception, never sent anywhere.
    """

    parsed = urlsplit(url)
    return (parsed.scheme, parsed.hostname, parsed.port)


def _redirect_credential_guard(
    target_origin: tuple[str, str | None, int | None], header_names: tuple[str, ...]
) -> Callable[[Any], "Awaitable[None]"]:
    """Build an ``httpx`` request-event hook that strips every
    credential-provider-supplied header name from a request whose URL's
    origin differs from ``target_origin`` (§ "Redirects" — a cross-origin
    redirect must not forward credentials).

    httpx's own redirect handling
    (``httpx.Client._redirect_headers``) already drops ``Authorization`` on a
    cross-origin redirect, but nothing else — an operator-chosen credential
    header under any other name would otherwise ride along unchanged. This
    hook is only ever installed when ``target.allow_redirects`` is ``True``
    *and* the resolved credential actually set at least one header; the
    ``allow_redirects=False`` default already makes redirection impossible in
    every other case, since httpx never sends a second request without it.
    """

    async def _guard(request: Any) -> None:
        if _origin(str(request.url)) == target_origin:
            return
        for name in header_names:
            if name in request.headers:
                del request.headers[name]

    return _guard


async def _call_remote_tool(
    target: RemoteTargetConfig,
    tool_name: str,
    arguments: Mapping[str, Any],
    *,
    context: TrustedOutboundContext | None,
) -> Any:
    """Open one connection, call one tool, close the connection (§9's
    "Connection lifecycle", § "Argument integrity" steps 4-6).

    ``arguments`` is already a detached value reachable only from the one
    snapshot :func:`dagr_mcp_service.adapter.execute_governed_call` freezes
    synchronously, before any ``await``, and digests against
    ``request.argument_digest`` -- that snapshot, not any copy taken along
    the way, is the actual integrity boundary: nothing reachable from it is
    ever shared with a caller-owned mapping, so there is nothing left for a
    caller to mutate out from under it by the time it reaches this
    function. The ``dict(arguments)`` copy below is only one further
    serialization-boundary convenience immediately before the call, not
    what makes the value trustworthy.
    """

    import httpx
    from datetime import timedelta

    from mcp.client.session import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    headers = await _resolve_credential_headers(target, context)
    call_arguments = dict(arguments)
    timeout = timedelta(seconds=target.timeout_seconds)

    event_hooks: dict[str, list[Any]] | None = None
    if target.allow_redirects and headers:
        guard = _redirect_credential_guard(_origin(target.endpoint_uri), tuple(headers))
        event_hooks = {"request": [guard]}

    try:
        # ``streamable_http_client`` only closes an ``httpx.AsyncClient`` it
        # created itself (``client_provided`` in its own source); a client
        # this function passes in via ``http_client=`` is treated as
        # caller-managed and is never closed by that transport. Owning it in
        # this function's own ``async with`` is what actually proves
        # connection cleanup on every exit path (result, tool error,
        # exception, timeout, cancellation) — confirmed by reading
        # ``mcp/client/streamable_http.py`` at the pinned mcp==1.28.1
        # revision installed in this repository's venv.
        #
        # ``trust_env=False``: environment proxy variables (``HTTP_PROXY``/
        # ``HTTPS_PROXY``/``NO_PROXY``) must never silently reroute a
        # credentialed connection through a proxy the operator did not
        # configure through ``RemoteTargetConfig`` itself (§ "Redirects and
        # environment proxies").
        async with httpx.AsyncClient(
            headers=headers,
            timeout=httpx.Timeout(target.timeout_seconds),
            follow_redirects=target.allow_redirects,
            verify=target.tls_verify,
            trust_env=False,
            event_hooks=event_hooks,
        ) as http_client:
            async with streamable_http_client(
                target.endpoint_uri, http_client=http_client, terminate_on_close=True
            ) as (read_stream, write_stream, _get_session_id):
                async with ClientSession(
                    read_stream, write_stream, read_timeout_seconds=timeout
                ) as session:
                    await session.initialize()
                    return await session.call_tool(
                        tool_name, call_arguments, read_timeout_seconds=timeout
                    )
    except asyncio.CancelledError:
        raise
    except BaseException as exc:  # noqa: BLE001 - translated to one of three honest, typed causes.
        raise _translate_transport_failure(exc) from None


class RemoteToolConnector:
    """Resolves ``(target_handle, tool_name)`` to a remote-tool-calling closure.

    ``targets`` is operator/deployment configuration — never a model tool
    argument and never a caller-selected transport — mapping an
    allowlisted target handle to its fixed :class:`RemoteTargetConfig`. This
    performs a plain dict lookup in :meth:`resolve`; no connection, DNS
    lookup, or socket of any kind is opened by resolution itself, only by
    invoking the callable it returns.
    """

    def __init__(self, targets: Mapping[str, RemoteTargetConfig]) -> None:
        normalized: dict[str, RemoteTargetConfig] = {}
        for handle, target in targets.items():
            if not isinstance(target, RemoteTargetConfig):
                raise TypeError(
                    "RemoteToolConnector targets values must be RemoteTargetConfig, "
                    f"got {type(target).__name__}"
                )
            if target.handle != handle:
                raise ValueError(
                    "RemoteToolConnector targets key must match "
                    f"RemoteTargetConfig.handle; got key {handle!r} for a config "
                    f"whose handle is {target.handle!r}"
                )
            normalized[str(handle)] = target
        self._targets: dict[str, RemoteTargetConfig] = normalized

    def resolve(
        self, target_handle: str, tool_name: str
    ) -> RemoteToolHandler | RemoteTargetResolutionRefused:
        """Look up ``target_handle`` only — no network I/O (§ requirement 4/5).

        Matches :class:`dagr_mcp_service.connectors.memory.
        InMemoryToolConnector.resolve`'s exact ``(self, target_handle,
        tool_name)`` shape, the frozen A8 connector seam
        :func:`dagr_mcp_service.adapter.execute_governed_call` calls
        unconditionally. The returned callable, if invoked directly without
        :meth:`bind_trusted_context`, still functions (with an empty
        :class:`TrustedOutboundContext` of ``None``) — useful for direct
        unit-level exercise of a target's transport behavior — but
        ``execute_governed_call`` always calls :meth:`bind_trusted_context`
        immediately afterward when a connector defines it, so a governed call
        never actually reaches the remote target without its resolved
        trusted actor/tenant context attached.
        """

        target = self._targets.get(target_handle)
        if target is None:
            return RemoteTargetResolutionRefused(target_handle=target_handle, tool_name=tool_name)

        async def _handler(call_arguments: Mapping[str, Any]) -> Any:
            return await _call_remote_tool(target, tool_name, call_arguments, context=None)

        return _handler

    def bind_trusted_context(
        self,
        handler: RemoteToolHandler,
        *,
        target_handle: str,
        tool_name: str,
        actor_ref: str,
        tenant_ref: str | None,
        parent_receipt_ref: str | None,
        request_ref: str,
    ) -> RemoteToolHandler:
        """Rebind ``handler`` with the caller's already-resolved trusted
        context (§ "Trusted outbound context"), so the credential provider
        this target may configure can see it.

        This is an *additive, optional* hook on top of the frozen A8
        ``connector.resolve(target_handle, tool_name)`` seam: ``resolve``'s
        own signature is unchanged (still exactly two positional arguments
        plus ``self``, matching
        :class:`dagr_mcp_service.connectors.memory.InMemoryToolConnector`'s
        frozen signature) because it structurally cannot carry per-call
        trusted actor/tenant refs. :func:`dagr_mcp_service.adapter.
        execute_governed_call` calls this method only when a connector
        defines it (via ``getattr(config.connector, "bind_trusted_context",
        None)``), so :class:`~dagr_mcp_service.connectors.memory.
        InMemoryToolConnector` — which defines no such method and has no use
        for a credential/context seam — is completely unaffected and
        requires no change.

        The ``handler`` argument is accepted for protocol symmetry with any
        future connector that might genuinely wrap a passed-in callable; this
        connector already has everything it needs (via ``target_handle``/
        ``tool_name`` closed over the same registry :meth:`resolve` used) and
        constructs a fresh closure directly rather than wrapping ``handler``.
        """

        del handler  # see docstring: this connector rebuilds directly.
        target = self._targets[target_handle]
        context = TrustedOutboundContext(
            target_handle=target_handle,
            tool_name=tool_name,
            actor_ref=actor_ref,
            tenant_ref=tenant_ref,
            parent_receipt_ref=parent_receipt_ref,
            request_ref=request_ref,
        )

        async def _handler_with_context(call_arguments: Mapping[str, Any]) -> Any:
            return await _call_remote_tool(target, tool_name, call_arguments, context=context)

        return _handler_with_context


__all__ = [
    "RemoteToolHandler",
    "RemoteTargetResolutionFailureReason",
    "RemoteTargetResolutionRefused",
    "RemoteTargetConfig",
    "TrustedOutboundContext",
    "RemoteCredential",
    "RemoteCredentialProvider",
    "RemoteToolConnector",
]
