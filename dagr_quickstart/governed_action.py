"""The minimal governed action, wired against the real ecosystem packages.

Runs end to end over the real FastMCP middleware transport:

1. Build a FastMCP server with exactly two tools:
   - ``ping``       — ``read``-classed, admitted; returns a trivial payload.
   - ``write_note`` — ``write``-classed, refused by a server-owned policy.
2. Wrap it in the real ``DAGRMiddleware`` with a ``SignedReceiptEmitter``.
3. Invoke ``ping`` through an in-process FastMCP ``Client``: DAGR emits one
   signed admission receipt and one signed outcome receipt.
4. Invoke ``write_note``: DAGR emits one ``admission(refused)`` receipt and
   raises **before** the tool body runs (an invocation sentinel proves it).
5. ``arcs-verify`` recomputes each emitted receipt as an independent subprocess.

Nothing here mints a verdict. Dispositions and receipt facts are reported exactly
as DAGR produces them; ``arcs-verify`` reports exactly what it recomputes.

To make this YOUR governed integration, change three things and nothing else:
  * the two ``@server.tool`` bodies (call your real system),
  * ``TOOL_CLASSES`` / the ``policy_resolver`` (declare your admission policy),
  * the identity / boundary IDs below (name your issuer + boundary).
"""

from __future__ import annotations

import asyncio
import json
import uuid
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dagr_mcp.fastmcp_binding import (
    ActorResolution,
    BindingPolicy,
    DAGRMiddleware,
    DAGRMiddlewareConfig,
)
from dagr_mcp.srs_receipts import (
    RawEnvelopeFileSink,
    SignedReceiptEmitter,
    SigningIdentity,
)

from .verify import assert_producers_absent_in_verifier, run_verifier

# --- Identity + boundary naming (rename these for your own integration) ----- #
# Public, NON-PRODUCTION demo signing seed. Deterministic so the quickstart is
# reproducible and testable. It has NO production validity and must never be
# reused by any deployed signing identity.
DEMO_SIGNING_SEED = bytes.fromhex(
    "d0c5a11ab0c0de1a5e11ab0c0de1a5e1"
    "1ab0c0de1a5e11ab0c0de1a5e11ab0c0"
)
ISSUER_ID = "issuer:dagr-quickstart:demo"
KEY_ID = "issuer.dagr-quickstart.demo/receipt-signing/demo"
RUNTIME_INSTANCE_ID = "runtime:dagr-quickstart:demo"
BOUNDARY_ID = "boundary:dagr-quickstart:demo:fastmcp"
POLICY_PACK_ID = "policy:dagr-quickstart:read-admit-write-refuse"
POLICY_PACK_VERSION = "v0.1"

# --- Tool names + admission policy ------------------------------------------ #
READ_TOOL = "ping"
WRITE_TOOL = "write_note"

TOOL_CLASSES = {
    READ_TOOL: "read",
    WRITE_TOOL: "write",
}

ATTESTATION_LIMIT = (
    "dagr-quickstart is a minimal demo boundary: one read tool is admitted and "
    "one write tool is refused. Receipts attest to governed tool calls at this "
    "boundary only; they are not a claim that any real-world effect occurred."
)

# Deterministic proof that a *refused* write call never runs its tool body. The
# write handler records an invocation at the top of its body; a refused admission
# short-circuits in DAGRMiddleware before ``call_next`` is reached, so the counter
# stays at zero. This is observability only — the refusal is enforced by
# DAGRMiddleware regardless of this counter.
_WRITE_BODY_RAN = {"count": 0}


def _demo_signing_identity() -> SigningIdentity:
    return SigningIdentity(
        issuer_id=ISSUER_ID,
        key_id=KEY_ID,
        private_key=Ed25519PrivateKey.from_private_bytes(DEMO_SIGNING_SEED),
    )


def _actor_resolver(_context: Any, _snapshot: Any) -> ActorResolution:
    # Authoritative actor/tenant context is server-owned, never taken from caller
    # tool arguments. A real integration resolves this from its own session/auth.
    return ActorResolution(
        actor_ref="actor:dagr-quickstart:demo-caller",
        tenant_id="tenant:dagr-quickstart:demo",
    )


def _policy_resolver(snapshot: Any, _actor: Any) -> BindingPolicy:
    # Server-owned admission policy. The write tool is refused; everything else is
    # admitted. Disposition is DAGR's to enforce; a refused call's body never runs.
    if snapshot.tool_name == WRITE_TOOL:
        return BindingPolicy(
            disposition="refused",
            tool_class="write",
            reason_code="policy_refused",
        )
    return BindingPolicy(disposition="admitted", tool_class="read")


def _build_server(emitter: SignedReceiptEmitter):
    from fastmcp import FastMCP

    config = DAGRMiddlewareConfig(
        runtime_instance_id=RUNTIME_INSTANCE_ID,
        boundary_id=BOUNDARY_ID,
        policy_pack_id=POLICY_PACK_ID,
        policy_pack_version=POLICY_PACK_VERSION,
        tool_classes=TOOL_CLASSES,
        actor_resolver=_actor_resolver,
        policy_resolver=_policy_resolver,
        additional_attestation_limits=(ATTESTATION_LIMIT,),
    )

    server = FastMCP("dagr-quickstart")
    server.add_middleware(DAGRMiddleware(emitter=emitter, config=config))

    @server.tool(name=READ_TOOL)
    async def ping(message: str = "hello") -> dict[str, Any]:
        # A trivial read. Replace with a real read against your system.
        return {"ok": True, "echo": message}

    @server.tool(name=WRITE_TOOL)
    async def write_note(text: str) -> dict[str, Any]:
        # Refused at admission; this body is never reached in the governed run.
        _WRITE_BODY_RAN["count"] += 1  # pragma: no cover - refused before it runs
        raise RuntimeError(  # pragma: no cover - unreachable when refused
            "write_note is refused at this boundary and must never execute"
        )

    return server


def _read_receipts(directory: Path) -> list[dict[str, Any]]:
    return [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(directory.glob("urn_srs_receipt_*.json"))
    ]


async def _run_async(*, receipts_dir: Path, verify: bool) -> dict[str, Any]:
    from fastmcp.client import Client
    from fastmcp.exceptions import ToolError

    _WRITE_BODY_RAN["count"] = 0
    receipts_dir = Path(receipts_dir)
    receipts_dir.mkdir(parents=True, exist_ok=True)

    identity = _demo_signing_identity()
    sink = RawEnvelopeFileSink(receipts_dir)
    keyring_path = sink.write_trust_bundle(identity.trust_bundle())
    emitter = SignedReceiptEmitter(identity=identity, sink=sink)

    server = _build_server(emitter)

    async with Client(server) as client:
        read_result = (await client.call_tool(READ_TOOL, {"message": "hello"})).data

        refusal_enforced = False
        refusal_message = None
        try:
            await client.call_tool(WRITE_TOOL, {"text": "should never be written"})
        except ToolError as exc:
            refusal_enforced = True
            refusal_message = str(exc)

    receipts = _read_receipts(receipts_dir)
    admissions = [r for r in receipts if r["receipt_kind"] == "admission"]
    outcomes = [r for r in receipts if r["receipt_kind"] == "outcome"]
    refused = [r for r in admissions if r.get("disposition") == "refused"]

    verification: dict[str, Any] | None = None
    if verify:
        # Reciprocal separation: the verifier runs under a SEPARATE interpreter
        # whose environment has no producer packages. Both facts are asserted
        # (fail-closed) before the verdicts are trusted.
        producers_absent = assert_producers_absent_in_verifier()
        report_path = receipts_dir / "verification_report.json"
        report = run_verifier(receipts_dir, keyring_path, report_path)
        verification = {
            "independence": "arcs-verify runs under a separate interpreter; "
            "producer packages absent from its environment",
            "producer_packages_discoverable_in_verifier": producers_absent,
            "report": report,
            "report_path": str(report_path),
        }

    return {
        "scenario": "governed_action.minimal",
        "transport": "fastmcp.middleware.v0.1 (in-process FastMCP Client)",
        "read": {"tool": READ_TOOL, "result": read_result},
        "refusal": {
            "tool": WRITE_TOOL,
            "enforced": refusal_enforced,
            "message": refusal_message,
            "body_ran": _WRITE_BODY_RAN["count"] > 0,
            "refused_admission_count": len(refused),
        },
        "receipt_cardinality": {
            "admission": len(admissions),
            "outcome": len(outcomes),
            "refused_admission": len(refused),
            "total": len(receipts),
        },
        "receipts": receipts,
        "verification": verification,
        "receipts_dir": str(receipts_dir),
        "keyring": str(keyring_path),
    }


def run_governed_action(
    *,
    receipts_root: Path | str | None = None,
    verify: bool = True,
) -> dict[str, Any]:
    """Run the minimal governed action, emitting into a fresh per-run directory."""

    root = (
        Path(receipts_root)
        if receipts_root is not None
        else Path(__file__).resolve().parents[1] / "receipts"
    )
    receipts_dir = root / f"run-{uuid.uuid4().hex[:12]}"
    return asyncio.run(_run_async(receipts_dir=receipts_dir, verify=verify))
