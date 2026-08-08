"""Generic governed one-shot/restart-safe stdio MCP connector v0.1.

Client-side stdio child-process connector for the Gateway.

**The exact public claim is "generic governed one-shot/restart-safe stdio MCP
connector v0.1" -- and "generic" there is bounded, not universal.** Every
governed call is an independent, self-contained
spawn -> ``initialize`` -> one ``tools/list`` or ``tools/call`` -> teardown
cycle, so the connector is *generic* with respect to the child binary (any
unmodified external MCP server that speaks stdio) and *restart-safe* (no state
survives a call, so a crashed or restarted child costs nothing beyond the call
that hit it). It is **not** claimed suitable for MCP servers that require any
of the following, all of which are explicitly **unsupported in v0.1 and
recorded as future scope, not as hidden defects**:

* long-lived session state held across governed calls;
* server-initiated subscriptions or any server-push notification stream that
  must outlive a single call;
* persistent server-side resources (open handles, caches, loaded models) whose
  cost or identity must survive teardown;
* cross-call initialization state -- anything negotiated during ``initialize``
  and expected to still be in force on a *later* governed call;
* sampling roots, elicitation, or any other negotiated capability that must be
  retained across calls.

A server needing any of those will still *run* under this connector, but each
call sees a freshly initialized process, so behavior that depends on retained
state will not be preserved. Supporting it is a distinct future lane (a
persistent-child connector), not a patch to this one.

Scope: ``docs/GATEWAY_SERVICE_ADAPTER_SCOPE.md`` §7 (transport decision
surface — "stdio is retained as a simpler co-located option"), §12
(security/privacy), §13 (``connectors/stdio.py``, named there as an optional
sibling to ``connectors/http.py``). This module resolves a
:class:`dagr_mcp_service.contract.GovernedCallRequest`'s
``(target_server_ref.handle, tool_name)`` pair to an operator-launched *child
process* speaking MCP over stdio — a co-located external MCP server the
operator runs as an explicit, argv-and-environment-pinned subprocess, never a
network target, never a caller-suppliable command.

It governs an **unmodified, arbitrary external MCP server binary** without
importing or forking that server's implementation: this module only ever
speaks the standard MCP stdio initialize / ``tools/list`` / ``tools/call``
lifecycle to it as a client, through the repository's own pinned
``mcp==1.29.0`` client transport (:mod:`mcp.client.stdio`,
:class:`mcp.client.session.ClientSession`) — the same discipline
:mod:`dagr_mcp_service.connectors.remote` already applies to its own pinned
Streamable HTTP client.

**No caller-supplied command, argument, environment variable, or working
directory.** :class:`StdioTargetConfig` is closed, immutable,
operator-authored configuration keyed by ``target_server_ref.handle`` (§12
SSRF-equivalent discipline, mirroring
:mod:`dagr_mcp_service.connectors.memory`'s and
:mod:`dagr_mcp_service.connectors.remote`'s allowlist models). A caller's
``GovernedCallRequest`` carries only the target *handle*; the argv, the
environment, and the working directory a call actually launches are looked
up from that handle against :class:`StdioToolConnector`'s operator-provided
registry, never read from a tool argument, a request field, or the parent
process's own live environment beyond the narrow, explicit merge described
below.

**The command allowlist boundary.** Two independent facts make the launched
command an explicit, closed allowlist rather than an arbitrary-execution
surface: (1) :class:`StdioToolConnector`'s ``targets`` mapping is the entire
set of commands this connector can ever launch — there is no code path from
a caller-controlled value to a command it does not already contain; and (2)
``StdioTargetConfig.__post_init__`` requires ``command[0]`` (the executable)
to be an **absolute filesystem path**, never a bare name resolved against
``$PATH`` at call time — the stdio analogue of
:class:`~dagr_mcp_service.connectors.remote.RemoteTargetConfig` pinning
``https``/host/port at construction time rather than trusting whatever a
runtime lookup would have resolved to. ``command`` is always passed to the
OS process launcher as an explicit argv list (never joined into, or
interpreted by, a shell), so there is no shell-metacharacter injection
surface regardless of argument content.

**Environment handling and disclosed secret-handling limits.** A target's
``env`` is *additive* configuration merged over the underlying SDK's own
``mcp.client.stdio.get_default_environment()`` — a small, deliberately safe
subset of the parent process's environment (``HOME``, ``LOGNAME``, ``PATH``,
``SHELL``, ``TERM``, ``USER`` on POSIX) rather than this process's full
``os.environ``. This module therefore never leaks unrelated ambient secrets
(signing key material paths, database credentials, unrelated API keys) from
the DAGR runtime's own environment into a launched child merely because the
child was launched. Conversely, an operator's declared ``env`` values *may*
themselves be secret (e.g. an API key a specific child tool needs) — this
module discloses, and does not attempt to hide, that such values exist only
as OS-level environment variables of the spawned process: they are never
digested, never logged, never placed in an exception message, and never
reach :mod:`dagr_mcp.srs_receipts` (which this module does not import and
never touches), but this module has no control over what the child process
itself does with its own environment once launched — that boundary is the
external server's, not DAGR's.

**No per-call trusted-context injection seam.** Unlike
:mod:`dagr_mcp_service.connectors.remote` (which defines
``bind_trusted_context`` so a per-call credential provider can attach an
HTTP header), this module defines no such hook: per §7's own comparison
table, a stdio target's trusted-context source is "subprocess env / launch
args," which is necessarily fixed once, at :class:`StdioTargetConfig`
construction time, for every call to that target — there is no live,
per-call wire location (no header, no query string) to inject a
caller-specific credential into after the process is already configured.
:func:`dagr_mcp_service.adapter.execute_governed_call` only calls
``bind_trusted_context`` when ``getattr(connector, "bind_trusted_context",
None)`` is not ``None``; this connector defines no such attribute, so it is
unaffected by (and does not need) that optional A9 hook, exactly like
:class:`~dagr_mcp_service.connectors.memory.InMemoryToolConnector`.

**Tool discovery is explicit and out-of-band, never automatic.**
:meth:`resolve` performs a plain, synchronous, I/O-free two-level lookup —
target handle, then tool name against that target's ``known_tools`` — never
a live ``tools/list`` call. ``known_tools`` is a required, operator-supplied
closed set (mirroring
:class:`~dagr_mcp_service.connectors.memory.InMemoryToolConnector`'s
own fail-closed unknown-tool discipline rather than
:class:`~dagr_mcp_service.connectors.remote.RemoteToolConnector`'s
forward-and-let-the-target-error posture): a tool name outside that set is
refused (``unknown_tool_fail_closed``) before any process is ever spawned.
:func:`discover_tools` is the module's own explicit, operator-invoked
capability for *populating* that set — spawn once, negotiate, call
``tools/list``, shut down, return the discovered tool names — so an operator
builds ``known_tools`` from the real child's own declared capability rather
than guessing it, without making every ``resolve()`` call pay for a live
round trip or making tool availability an ambient, undeclared fact.

**Process cleanup and orphan prevention.** Every call spawns a fresh child,
negotiates once, issues exactly one ``tools/call``, and tears the process
down — mirroring :mod:`dagr_mcp_service.connectors.remote`'s "one connection,
one call, then close" discipline (§ "No retry, idempotency, or transport
framework" there) rather than holding a long-lived child across calls. Process
teardown is entirely the pinned SDK's own ``mcp.client.stdio.stdio_client``
context-manager exit path: it closes the child's stdin, waits up to its own
fixed grace period for a clean exit, and — only if the child has not exited
by then — escalates to the platform-specific process-*tree* termination
(``os.killpg`` on POSIX, targeting the whole process group ``stdio_client``
itself placed the child in via ``start_new_session=True``, so a
misbehaving child that forked its own children is torn down with it, not
left as an orphan). This module adds no termination logic of its own; it
relies on, and does not modify, that pinned behavior.

**stderr never corrupts the stdout JSON-RPC channel.** ``mcp.client.stdio``
already keeps the child's stdout (the JSON-RPC channel this module's
``ClientSession`` parses) and stderr (diagnostic text) on two independent
OS-level file descriptors; nothing in this module ever merges them. Each
call additionally redirects the child's stderr to a private, per-call
temporary file (never the parent process's own stderr, and never
``subprocess.PIPE`` left undrained, which could deadlock a chatty child on a
full pipe buffer) so stderr output can never race with, or be mistaken for,
protocol bytes. That file is *anonymous* — ``tempfile.TemporaryFile`` gives
it no reachable pathname at any point in its life, on any exit path
including timeout and cancellation, and the kernel reclaims it when the last
descriptor closes (see :func:`_stdio_session` for why an anonymous file
rather than a named one cleaned up in a ``finally``). Its contents are never
read back, digested, logged, or placed in a receipt or in a raised
exception's message.

**Honest, closed failure-cause translation.** :func:`_translate_stdio_failure`
mirrors :mod:`dagr_mcp_service.connectors.remote`'s own four-bucket
priority order, adapted to what a stdio transport can honestly ground:

1. ``asyncio.CancelledError`` — passed through unchanged.
2. ``OSError`` raised **before the session is handed to its caller**, while
   the SDK's own ``stdio_client`` attempts to spawn the child (confirmed by
   reading the installed ``mcp==1.29.0`` client: ``stdio_client`` catches
   exactly ``OSError`` around process creation and re-raises after closing
   its own streams) — translated to a plain :class:`ConnectionError`. No
   child process ever started, so execution definitely did not happen. This
   bucket is **phase-gated** (see :func:`_stdio_session`'s ``post_forward``
   flag): once the session has been yielded, a ``tools/call`` may already be
   on the wire, so an ``OSError`` from that point on is *not* eligible for
   this bucket and falls through to bucket 4. ``ConnectionError`` is the one
   exception type the A8 adapter narrows to the ``remote_unavailable``
   diagnostic, and ``remote_unavailable`` is the one diagnostic that reads as
   "nothing ran" — so the gate exists to make that reading provable rather
   than merely likely.
3. An ``McpError`` whose ``error.code`` matches the exact numeric value
   ``mcp.shared.session.BaseSession.send_request`` stamps when its own
   read-timeout fires (confirmed against the installed ``mcp==1.29.0``
   source — transport-agnostic, the same code
   :mod:`dagr_mcp_service.connectors.remote` already reuses for Streamable
   HTTP), or a plain builtin :class:`TimeoutError` — translated to a plain
   :class:`TimeoutError`.
4. Anything else — including a child that exited mid-call (the SDK's own
   receive loop fails every in-flight request with a distinct
   ``CONNECTION_CLOSED`` ``McpError`` when the read stream ends, but this
   module does not promote that to :class:`ConnectionError`: the child did
   start and may have begun executing, so "unavailable" would overclaim,
   exactly the same restraint :mod:`dagr_mcp_service.connectors.remote`
   already applies to a generic protocol/decoding failure), a malformed
   JSON-RPC line from the child, or an unsupported-protocol-version
   ``RuntimeError`` the SDK's own ``ClientSession.initialize`` raises —
   collapsed into a single generic :class:`RuntimeError`, the honest "some
   other protocol/decoding exception occurred" bucket, with no further claim
   about cause.

None of the four returned exception types is ever constructed with the
original exception's message, the child's command, an argument value, or an
environment value — only a fixed, content-free description, exactly
mirroring the remote connector's own discipline.

**Post-forward outcome semantics: what an admitted failure does and does not
prove.** Admission is decided, and the admission receipt is emitted, *before*
this module is ever invoked — a REFUSED or DEFERRED call returns from
:func:`dagr_mcp_service.adapter.execute_governed_call` without any connector
handler being called, so it reaches the child **zero times**. An ADMITTED
call is forwarded **exactly once**: one spawn, one ``tools/call``, no retry
layer anywhere in this module. What follows concerns only the admitted case,
and it uses the existing admitted receipt vocabulary — no new receipt field
and no new disposition is introduced here.

The pivotal boundary is whether the ``tools/call`` was written to the child's
stdin. Before it: no side effect can have occurred. After it: the child may
have performed the side effect and this module may simply never learn the
result. The five post-forward failure modes all resolve inside the existing
vocabulary as follows.

===========================  ==========  =============  ====================================
Failure mode                 Forwarded?  Side effect?   Response
===========================  ==========  =============  ====================================
Spawn failure (pre-forward)  no          impossible     ``admitted``/``exception``,
                                                        ``remote_unavailable``
Timeout after forwarding     yes         **unknown**    ``admitted``/``exception``,
                                                        ``remote_exception``
Cancellation after forward   yes         **unknown**    ``admitted``/``cancellation``,
                                                        ``cancelled``
Child exit after forwarding  yes         **unknown**    ``admitted``/``exception``,
                                                        ``remote_exception``
Malformed response           yes         **unknown**    ``admitted``/``exception``,
                                                        ``remote_exception``
Connection close after fwd   yes         **unknown**    ``admitted``/``exception``,
                                                        ``remote_exception``
===========================  ==========  =============  ====================================

Cancellation is the one post-forward mode with a *dedicated* indeterminacy
representation: the adapter answers it with
``GovernedDecision(disposition="admitted", outcome="cancellation")`` plus
:class:`~dagr_mcp_service.contract.CancellationFacts`\\ ``(request_cancelled=
True, execution_state_unknown=True, delivery_incomplete=True)`` — the
vocabulary already states, in a dedicated field, that the execution state is
unknown.

The other four post-forward modes have no such dedicated field. The admitted
receipt vocabulary permits only ``exception`` for them, so this is stated
explicitly and without hedging:

    **``outcome="exception"`` means the transport or tool result was not
    successfully observed. It does not prove the side effect did not occur.**
    A child that appended a row, sent a message, or charged an account and
    *then* hung, crashed, or answered with an unparseable line produces
    exactly the same ``admitted``/``exception`` response as one that did
    nothing at all. The receipt attests that DAGR admitted the call,
    forwarded it once, and did not observe a result — nothing more.

Consequently ``remote_unavailable`` — the one diagnostic that can be read as
"the call never reached the target" — is reachable only from the pre-forward
spawn-failure path, structurally enforced by the phase gate described in
bucket 2 above. An admitted call that was forwarded is never represented as
refused, prevented, or definitely-not-executed. Verification of an emitted
receipt checks the *evidence* (schema, profile, raw-content exclusion,
signature, issuer trust); it does not and cannot check the truth of the
real-world event the call may or may not have caused.

**Import discipline.** Importing this module never imports ``mcp`` or
``anyio`` — both are imported lazily, only inside the coroutines that
actually spawn a child or negotiate a session, matching
:mod:`dagr_mcp_service.connectors.remote`'s own "concrete binding module
imported lazily" discipline.
"""

from __future__ import annotations

import asyncio
import os
import tempfile
from collections.abc import Awaitable, Callable, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, Literal, TypeAlias

# A resolved stdio target handler: given the (already argument-digest-
# verified) call arguments, returns the child tool's result or raises.
# Structurally identical to
# ``dagr_mcp_service.connectors.memory.LocalToolHandler`` /
# ``dagr_mcp_service.connectors.remote.RemoteToolHandler`` (all three
# connectors are driven through the same A8 ``connector.resolve(...)``
# seam), redefined here rather than imported so this module stays
# independently importable without pulling in either sibling connector.
StdioToolHandler: TypeAlias = Callable[[Mapping[str, Any]], "Awaitable[Any] | Any"]

StdioTargetResolutionFailureReason = Literal["remote_unavailable", "unknown_tool_fail_closed"]

# httpx.codes.REQUEST_TIMEOUT, reproduced as a plain int rather than
# importing httpx (this module has no other reason to depend on it).
# mcp.shared.session.BaseSession.send_request stamps exactly this numeric
# value on the McpError it raises when its own anyio.fail_after read-timeout
# fires -- confirmed by reading mcp/shared/session.py at the pinned
# mcp==1.29.0 revision installed in this repository's venv. The check is
# transport-agnostic (BaseSession, not the stdio transport specifically),
# the same fact dagr_mcp_service.connectors.remote already relies on for
# Streamable HTTP.
_MCP_REQUEST_TIMEOUT_CODE = 408


@dataclass(frozen=True, slots=True, kw_only=True)
class StdioTargetConfig:
    """Closed, immutable, operator-authored stdio child target (§12, §13).

    Every launch fact a call needs lives here, fixed by the operator at
    configuration time. A caller's ``GovernedCallRequest`` supplies only
    ``target_server_ref.handle`` -- a lookup key into
    :class:`StdioToolConnector`'s registry -- never a command, argument,
    environment variable, or working directory.

    ``command`` is the full argv (executable first, then arguments);
    ``command[0]`` must be an absolute filesystem path (never a bare name
    resolved against ``$PATH`` at call time -- see the module docstring's
    "command allowlist boundary" section). ``known_tools`` is required and
    closed: build it with :func:`discover_tools` against the real child
    ahead of time, or declare it directly from the child's own published
    capability; :meth:`StdioToolConnector.resolve` never guesses it and
    never calls the child to find out.
    """

    handle: str
    command: tuple[str, ...]
    known_tools: frozenset[str]
    env: Mapping[str, str] = field(default_factory=dict)
    cwd: str | None = None
    timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        if not isinstance(self.handle, str) or not self.handle.strip():
            raise ValueError("StdioTargetConfig.handle must be a non-empty string")

        if not isinstance(self.command, tuple) or not self.command:
            raise ValueError("StdioTargetConfig.command must be a non-empty tuple of strings")
        for part in self.command:
            if not isinstance(part, str) or not part:
                raise ValueError(
                    f"StdioTargetConfig.command entries must be non-empty strings, got {part!r}"
                )
        if not os.path.isabs(self.command[0]):
            raise ValueError(
                "StdioTargetConfig.command[0] (the executable) must be an absolute "
                f"path, never resolved against $PATH at call time; got {self.command[0]!r}"
            )

        if not isinstance(self.known_tools, frozenset):
            raise TypeError(
                f"StdioTargetConfig.known_tools must be a frozenset, got {type(self.known_tools).__name__}"
            )
        for name in self.known_tools:
            if not isinstance(name, str) or not name:
                raise ValueError(
                    f"StdioTargetConfig.known_tools entries must be non-empty strings, got {name!r}"
                )

        for key, value in self.env.items():
            if not isinstance(key, str) or not key:
                raise ValueError(f"StdioTargetConfig.env keys must be non-empty strings, got {key!r}")
            if not isinstance(value, str):
                raise ValueError(
                    f"StdioTargetConfig.env values must be strings, got {value!r} for key {key!r}"
                )

        if self.cwd is not None and (not isinstance(self.cwd, str) or not self.cwd.strip()):
            raise ValueError("StdioTargetConfig.cwd must be a non-empty string or None")

        if not isinstance(self.timeout_seconds, int | float) or self.timeout_seconds <= 0:
            raise ValueError("StdioTargetConfig.timeout_seconds must be a positive number")


@dataclass(frozen=True, slots=True, kw_only=True)
class StdioTargetResolutionRefused:
    """A fail-closed stdio-target resolution outcome.

    ``reason`` reuses two of the existing stable diagnostics rather than
    inventing a new taxonomy -- an unregistered ``target_server_ref.handle``
    reads as the referenced "remote" being unavailable
    (:data:`dagr_mcp_service.contract.GATEWAY_DIAGNOSTIC_CODES`'s
    ``remote_unavailable``, the same spelling
    :class:`~dagr_mcp_service.connectors.remote.RemoteTargetResolutionRefused`
    already uses); an unregistered tool name under a known target reuses the
    neutral core's own ``unknown_tool_fail_closed`` refusal ground, the same
    spelling
    :class:`~dagr_mcp_service.connectors.memory.MemoryTargetResolutionRefused`
    already uses for the identical case. There is no third variant that
    substitutes another target -- every non-success path is one of these two
    refusals, and neither ever spawns a process.
    """

    target_handle: str
    tool_name: str
    reason: StdioTargetResolutionFailureReason


def _flatten_exception_group(exc: BaseException) -> list[BaseException]:
    if isinstance(exc, BaseExceptionGroup):
        leaves: list[BaseException] = []
        for sub in exc.exceptions:
            leaves.extend(_flatten_exception_group(sub))
        return leaves
    return [exc]


def _translate_stdio_failure(exc: BaseException, *, post_forward: bool = False) -> BaseException:
    """Classify a raised stdio transport failure into one of four honest
    buckets. See the module docstring's "Honest, closed failure-cause
    translation" section for the full priority order and rationale.

    ``post_forward`` is the phase gate that keeps the ``ConnectionError``
    bucket honest. ``ConnectionError`` is the *only* exception type this
    module raises that the A8 adapter turns into the narrower
    ``remote_unavailable`` diagnostic -- a claim that no execution happened.
    That claim is grounded only while the session is still being established
    (spawn/negotiate), before any ``tools/call`` could have been written to
    the child's stdin. Once :func:`_stdio_session` has yielded, the caller
    may have forwarded the call and the child may already have performed a
    side effect, so *no* failure from that point on is allowed to reach the
    ``ConnectionError`` bucket -- not even an ``OSError`` -- and it falls
    through to the generic :class:`RuntimeError` "not successfully observed"
    bucket instead. This is a one-directional guard: it can only ever move a
    classification away from claiming non-execution, never toward it.
    """

    from mcp.shared.exceptions import McpError

    leaves = _flatten_exception_group(exc)

    for leaf in leaves:
        if isinstance(leaf, asyncio.CancelledError):
            return leaf

    if not post_forward:
        for leaf in leaves:
            if isinstance(leaf, OSError) and not isinstance(leaf, TimeoutError | ConnectionError):
                return ConnectionError("stdio MCP child process could not be started")

    for leaf in leaves:
        if isinstance(leaf, McpError) and getattr(leaf.error, "code", None) == (
            _MCP_REQUEST_TIMEOUT_CODE
        ):
            return TimeoutError("timed out waiting for a response from the stdio MCP child")
        if isinstance(leaf, TimeoutError):
            return TimeoutError("timed out communicating with the stdio MCP child")

    return RuntimeError("stdio MCP protocol or decoding exception")


@asynccontextmanager
async def _stdio_session(target: StdioTargetConfig):
    """Spawn one child, negotiate once, yield a ready session, tear it down.

    Shared by :func:`_call_stdio_tool` and :func:`discover_tools` so the
    spawn/negotiate/errlog/teardown sequence -- and the one place failures
    are translated (see :func:`_translate_stdio_failure`) -- exists exactly
    once. A failure raised by the caller's own code inside the ``async
    with`` block (e.g. a ``session.call_tool``/``session.list_tools`` this
    function does not itself issue) is thrown back into this generator at
    the ``yield`` below, so it passes through the same ``except`` clause --
    but deliberately *not* with the same classification. ``post_forward``
    flips to ``True`` the instant this function yields, which permanently
    closes the ``ConnectionError``/"nothing was ever executed" bucket for
    the remainder of the call (see :func:`_translate_stdio_failure`).
    Everything before the yield is provably pre-forward: the child has been
    spawned and ``initialize`` has completed, but no ``tools/call`` has been
    written to its stdin, so no side effect can have begun.
    """

    from datetime import timedelta

    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    timeout = timedelta(seconds=target.timeout_seconds)
    server_params = StdioServerParameters(
        command=target.command[0],
        args=list(target.command[1:]),
        env=dict(target.env) if target.env else None,
        cwd=target.cwd,
    )

    post_forward = False
    # The stderr sink is an *anonymous* temporary file: ``tempfile.TemporaryFile``
    # unlinks it immediately after creation (POSIX) or opens it delete-on-close
    # (Windows), so it has no reachable pathname for its whole lifetime and the
    # kernel releases its storage when the last descriptor closes.
    #
    # This is deliberately *not* a named ``mkstemp`` file removed in a
    # ``finally``. That form was correct as far as its own tests could show,
    # but its correctness was a property of the cleanup *running*: this
    # function is an async generator context manager, so on the timeout and
    # cancellation paths the ``finally`` runs when the generator is finalized,
    # and any path that leaves the generator suspended defers the unlink to
    # garbage collection. An anonymous file makes "no stray file" structural
    # rather than something the exit paths have to keep getting right -- there
    # is no name that could ever be observed, and no unlink that could be
    # skipped or deferred, on any exit path.
    #
    # Nothing here reads the sink back: its only purpose is to keep the child's
    # stderr off the pipe carrying protocol bytes (an unconsumed stderr pipe can
    # fill and deadlock the child). Its contents are never digested, logged, or
    # placed in a receipt or in a raised exception's message, so having no name
    # costs nothing.
    with tempfile.TemporaryFile(mode="w", encoding="utf-8") as errlog:
        try:
            async with stdio_client(server_params, errlog=errlog) as (
                read_stream,
                write_stream,
            ):
                async with ClientSession(
                    read_stream, write_stream, read_timeout_seconds=timeout
                ) as session:
                    await session.initialize()
                    post_forward = True
                    yield session, timeout
        except asyncio.CancelledError:
            raise
        except BaseException as exc:  # noqa: BLE001 - translated to one of four honest, typed causes.
            raise _translate_stdio_failure(exc, post_forward=post_forward) from None


async def _call_stdio_tool(
    target: StdioTargetConfig, tool_name: str, arguments: Mapping[str, Any]
) -> Any:
    """Spawn one child, negotiate once, call one tool, tear the child down.

    ``arguments`` is already a detached value reachable only from the one
    snapshot :func:`dagr_mcp_service.adapter.execute_governed_call` freezes
    synchronously, before any ``await``, and digests against
    ``request.argument_digest`` -- see
    :mod:`dagr_mcp_service.connectors.remote`'s identical note on why the
    ``dict(arguments)`` copy below is a serialization-boundary convenience,
    not what makes the value trustworthy.
    """

    call_arguments = dict(arguments)
    async with _stdio_session(target) as (session, timeout):
        return await session.call_tool(tool_name, call_arguments, read_timeout_seconds=timeout)


async def discover_tools(
    command: Sequence[str],
    *,
    env: Mapping[str, str] | None = None,
    cwd: str | None = None,
    timeout_seconds: float = 10.0,
) -> tuple[str, ...]:
    """Spawn ``command`` once, negotiate, call ``tools/list``, tear it down.

    The module's own explicit, operator-invoked tool-discovery capability
    (§ "expose discovered tools through the existing DAGR Gateway/connector
    model") -- never called by :meth:`StdioToolConnector.resolve` itself.
    Run this ahead of time to build a target's ``known_tools``:

    .. code-block:: python

        names = await discover_tools(["/usr/bin/my-mcp-server"])
        target = StdioTargetConfig(
            handle="local:my-server",
            command=("/usr/bin/my-mcp-server",),
            known_tools=frozenset(names),
        )

    ``command`` and ``env``/``cwd`` are validated the same way
    :class:`StdioTargetConfig` validates them (non-empty argv, absolute
    executable path) before anything is spawned.
    """

    probe_target = StdioTargetConfig(
        handle="__discover_tools_probe__",
        command=tuple(command),
        known_tools=frozenset(),
        env=dict(env) if env else {},
        cwd=cwd,
        timeout_seconds=timeout_seconds,
    )

    async with _stdio_session(probe_target) as (session, _timeout):
        result = await session.list_tools()
        return tuple(tool.name for tool in result.tools)


class StdioToolConnector:
    """Resolves ``(target_handle, tool_name)`` to a stdio-child-calling closure.

    ``targets`` is operator/deployment configuration -- never a model tool
    argument and never a caller-selected command -- mapping an allowlisted
    target handle to its fixed :class:`StdioTargetConfig`. This performs a
    plain dict lookup plus a closed-set membership check in :meth:`resolve`;
    no process is spawned by resolution itself, only by invoking the
    callable it returns.
    """

    def __init__(self, targets: Mapping[str, StdioTargetConfig]) -> None:
        normalized: dict[str, StdioTargetConfig] = {}
        for handle, target in targets.items():
            if not isinstance(target, StdioTargetConfig):
                raise TypeError(
                    "StdioToolConnector targets values must be StdioTargetConfig, "
                    f"got {type(target).__name__}"
                )
            if target.handle != handle:
                raise ValueError(
                    "StdioToolConnector targets key must match "
                    f"StdioTargetConfig.handle; got key {handle!r} for a config "
                    f"whose handle is {target.handle!r}"
                )
            normalized[str(handle)] = target
        self._targets: dict[str, StdioTargetConfig] = normalized

    def resolve(
        self, target_handle: str, tool_name: str
    ) -> StdioToolHandler | StdioTargetResolutionRefused:
        """Look up ``target_handle``/``tool_name`` only -- no process I/O.

        Matches :class:`dagr_mcp_service.connectors.memory.
        InMemoryToolConnector.resolve`'s and
        :class:`dagr_mcp_service.connectors.remote.RemoteToolConnector.
        resolve`'s exact ``(self, target_handle, tool_name)`` shape, the
        frozen A8 connector seam
        :func:`dagr_mcp_service.adapter.execute_governed_call` calls
        unconditionally.
        """

        target = self._targets.get(target_handle)
        if target is None:
            return StdioTargetResolutionRefused(
                target_handle=target_handle, tool_name=tool_name, reason="remote_unavailable"
            )
        if tool_name not in target.known_tools:
            return StdioTargetResolutionRefused(
                target_handle=target_handle,
                tool_name=tool_name,
                reason="unknown_tool_fail_closed",
            )

        async def _handler(call_arguments: Mapping[str, Any]) -> Any:
            return await _call_stdio_tool(target, tool_name, call_arguments)

        return _handler


__all__ = [
    "StdioToolHandler",
    "StdioTargetResolutionFailureReason",
    "StdioTargetResolutionRefused",
    "StdioTargetConfig",
    "StdioToolConnector",
    "discover_tools",
]
