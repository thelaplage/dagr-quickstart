"""First-run proof: observed admitted-vs-refused native-action execution.

This module does not implement or change enforcement. It drives the existing
``dagr_mcp.enforcement_harness.wrap_handler`` twice -- once under a policy that
admits the call, once under a policy that refuses it -- over the *same* inner
handler and the *same* arguments, and records what was actually observed:
whether the inner handler ran, and what receipts were emitted.

The inner handler is a demonstration stand-in for a native host action
(MFD-FRONTDOOR-01: the thing a real front door would bind to, e.g. sending a
WhatsApp message). It has no host integration; its only observable effect is
an in-process invocation counter and ledger. Nothing about this module alters
``wrap_handler``'s control flow -- the refused scenario's non-execution is the
harness's own pre-execution return, not a second code path introduced here.
"""

from __future__ import annotations

import datetime
import json
import shlex
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .enforcement_harness import (
    GovernedResult,
    HarnessConfig,
    HarnessSinks,
    ToolPolicy,
    wrap_handler,
)
from .sdk_spine import InMemoryEventSink
from .srs_bridge import BridgeConfig, HarnessSRSBridge
from .srs_receipts import RawEnvelopeFileSink, SignedReceiptEmitter, SigningIdentity

PROFILE = "srs.mcp.sdk_enforcement.v0.1"
NATIVE_ACTION_TOOL = "frontdoor.native_action"
NATIVE_ACTION_ARGUMENTS = {"native_action_ref": "frontdoor:demo:1"}

SIDE_EFFECTS_SCHEMA = "dagr.first_run.side_effects.v0.1"
_CAPTURE_KEY_SEED = b"\x01" * 32
_CAPTURE_EPOCH = "2026-01-01T00:00:00Z"

QUICKSTART_COMMANDS = [
    "python -m venv .venv",
    "source .venv/bin/activate  # Windows: .venv\\Scripts\\activate",
    "python -m pip install dagr-mcp",
    "dagr-mcp first-run --output ./dagr-first-run-output",
]


class NativeActionSentinel:
    """Demonstration stand-in for a native host action.

    Not a real host integration. Its only observable consequence is an
    append-only ledger and a monotonic invocation counter, read before and
    after each scenario to prove whether the inner handler ran.
    """

    def __init__(self) -> None:
        self.invocation_count = 0
        self.ledger: list[dict[str, Any]] = []

    def __call__(self, tool_name: str, arguments: Any, context: Any = None) -> dict[str, Any]:
        self.invocation_count += 1
        entry = {"seq": self.invocation_count, "tool_name": tool_name}
        self.ledger.append(entry)
        return {"native_action_executed": True, "seq": entry["seq"]}


class _FixedClock:
    """Deterministic ``issued_at`` sequence for capture mode.

    Each call advances by one second from a fixed epoch, so two separate
    capture-mode runs -- which make the same emitter calls in the same
    order -- produce the identical timestamp sequence.
    """

    def __init__(self, start: str = _CAPTURE_EPOCH) -> None:
        self._current = datetime.datetime.fromisoformat(start.replace("Z", "+00:00"))

    def __call__(self) -> str:
        value = self._current.isoformat(timespec="seconds").replace("+00:00", "Z")
        self._current += datetime.timedelta(seconds=1)
        return value


def _capture_receipt_id_factory():
    counters: dict[str, int] = {}

    def factory(receipt_kind: str) -> str:
        counters[receipt_kind] = counters.get(receipt_kind, 0) + 1
        return f"urn:srs:receipt:{receipt_kind}:first-run-capture-{counters[receipt_kind]:04d}"

    return factory


def _build_emitter(directory: Path, *, capture: bool) -> tuple[SigningIdentity, SignedReceiptEmitter]:
    sink = RawEnvelopeFileSink(directory)
    if capture:
        identity = SigningIdentity(
            issuer_id="issuer:dagr:first-run-capture",
            key_id="issuer.dagr.first-run-capture/receipt-signing/fixed",
            private_key=Ed25519PrivateKey.from_private_bytes(_CAPTURE_KEY_SEED),
        )
        emitter = SignedReceiptEmitter(
            identity=identity,
            sink=sink,
            receipt_id_factory=_capture_receipt_id_factory(),
            issued_at_factory=_FixedClock(),
        )
    else:
        identity = SigningIdentity.generate(
            issuer_id="issuer:dagr:first-run",
            key_id="issuer.dagr.first-run/receipt-signing/ephemeral",
        )
        emitter = SignedReceiptEmitter(identity=identity, sink=sink)
    sink.write_trust_bundle(identity.trust_bundle())
    return identity, emitter


def _config() -> HarnessConfig:
    return HarnessConfig(
        harness_version="v0.1",
        module_id="dagr-mcp-first-run",
        module_version="v0.1",
        profile_ref=PROFILE,
        policy_ref="policy:dagr:first-run@v0.1",
    )


@dataclass
class ScenarioObservation:
    name: str
    policy_decision: str
    result: GovernedResult
    invocation_count_before: int
    invocation_count_after: int

    @property
    def native_action_executed(self) -> bool:
        return self.invocation_count_after > self.invocation_count_before


@dataclass
class FirstRunProof:
    admitted: ScenarioObservation
    refused: ScenarioObservation
    directory: Path
    capture_mode: bool
    side_effects_path: Path
    quickstart_path: Path


def _run_scenario(
    *,
    name: str,
    decision: str,
    sentinel: NativeActionSentinel,
    config: HarnessConfig,
    sinks: HarnessSinks,
    bridge: HarnessSRSBridge,
    request_ref: str,
) -> ScenarioObservation:
    handler = wrap_handler(
        sentinel,
        config,
        sinks,
        policies=[
            ToolPolicy(
                tool_name=NATIVE_ACTION_TOOL,
                tool_class="external_action",
                decision=decision,
                reason=f"first_run_demo_{decision}",
            )
        ],
        srs_bridge=bridge,
    )
    before = sentinel.invocation_count
    result = handler(
        NATIVE_ACTION_TOOL,
        NATIVE_ACTION_ARGUMENTS,
        {"request_ref": request_ref, "actor_ref": "actor:dagr:first-run"},
    )
    after = sentinel.invocation_count
    return ScenarioObservation(
        name=name,
        policy_decision=decision,
        result=result,
        invocation_count_before=before,
        invocation_count_after=after,
    )


def _receipt_refs(observation: ScenarioObservation) -> dict[str, str | None]:
    result = observation.result
    if result.ok:
        refs = result.receipt_refs
        return {
            "admission_receipt_ref": refs[0] if len(refs) > 0 else None,
            "outcome_receipt_ref": refs[1] if len(refs) > 1 else None,
        }
    context = result.context
    admission_ref = context.admission_receipt_ref if context is not None else None
    return {"admission_receipt_ref": admission_ref, "outcome_receipt_ref": None}


def _scenario_payload(observation: ScenarioObservation) -> dict[str, Any]:
    return {
        "policy_decision": observation.policy_decision,
        "governed_ok": observation.result.ok,
        "failure_reason": observation.result.failure_reason,
        "native_action_executed": observation.native_action_executed,
        "inner_invocation_count_before": observation.invocation_count_before,
        "inner_invocation_count_after": observation.invocation_count_after,
        **_receipt_refs(observation),
    }


def _arcs_verify_command(directory: Path) -> str:
    receipt_glob = shlex.quote(str(directory)) + "/urn_srs_receipt_*.json"
    keyring = str(directory / "issuer-keys.json")
    return (
        "for receipt in "
        f"{receipt_glob}; do "
        "arcs-verify \"$receipt\" "
        f"--keyring {shlex.quote(keyring)} "
        f"--profile {PROFILE}; "
        "done"
    )


def build_side_effects_payload(
    *,
    admitted: ScenarioObservation,
    refused: ScenarioObservation,
    directory: Path,
    capture_mode: bool,
) -> dict[str, Any]:
    return {
        "schema": SIDE_EFFECTS_SCHEMA,
        "mfd_frontdoor_01_linkage": (
            "proposed_action -> native_action -> "
            "native_result_or_non_execution -> receipt_chain"
        ),
        "capture_mode": capture_mode,
        "scenarios": {
            "admitted": _scenario_payload(admitted),
            "refused": _scenario_payload(refused),
        },
        "quickstart_commands": list(QUICKSTART_COMMANDS),
        "arcs_verify_command": _arcs_verify_command(directory),
    }


def run_first_run_proof(output: Path | None = None, *, capture: bool = False) -> FirstRunProof:
    directory = output or Path(tempfile.mkdtemp(prefix="dagr-mcp-first-run-"))
    directory.mkdir(parents=True, exist_ok=True)

    _identity, emitter = _build_emitter(directory, capture=capture)
    bridge = HarnessSRSBridge(
        emitter=emitter,
        config=BridgeConfig(
            runtime_instance_id="runtime:dagr:first-run",
            boundary_id="boundary:dagr:first-run-harness",
            policy_pack_id="policy:dagr:first-run",
            policy_pack_version="v0.1",
        ),
    )

    sentinel = NativeActionSentinel()
    config = _config()
    sinks = HarnessSinks(event=InMemoryEventSink())

    # Admitted first, then refused, sharing one sentinel: this is the
    # stronger ordering, because it proves the refused scenario's "unchanged"
    # reading is a before/after delta, not an absolute-zero check that a
    # hardcoded literal could satisfy by coincidence.
    admitted = _run_scenario(
        name="admitted",
        decision="allow",
        sentinel=sentinel,
        config=config,
        sinks=sinks,
        bridge=bridge,
        request_ref="call:dagr:first-run:admitted",
    )
    refused = _run_scenario(
        name="refused",
        decision="deny",
        sentinel=sentinel,
        config=config,
        sinks=sinks,
        bridge=bridge,
        request_ref="call:dagr:first-run:refused",
    )

    side_effects = build_side_effects_payload(
        admitted=admitted, refused=refused, directory=directory, capture_mode=capture,
    )
    side_effects_path = directory / "side_effects.json"
    side_effects_path.write_text(
        json.dumps(side_effects, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    quickstart_path = directory / "quickstart.txt"
    quickstart_path.write_text("\n".join(QUICKSTART_COMMANDS) + "\n", encoding="utf-8")

    return FirstRunProof(
        admitted=admitted,
        refused=refused,
        directory=directory,
        capture_mode=capture,
        side_effects_path=side_effects_path,
        quickstart_path=quickstart_path,
    )


__all__ = [
    "FirstRunProof",
    "NativeActionSentinel",
    "ScenarioObservation",
    "build_side_effects_payload",
    "run_first_run_proof",
]
