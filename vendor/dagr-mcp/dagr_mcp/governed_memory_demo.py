"""Run a vertical DAGR + Amnesiac governed-memory demonstration.

The native mode uses the optional ``arcs-amnesiac`` and ``garp-sdk`` producer
packages. Four Amnesiac operations are called through a real FastMCP server with
DAGR middleware installed, so the output directory contains signed admission
and outcome receipts plus a refs/digests-only workflow index.

The reference mode exists for contract smoke and CI. It implements the same
framework-neutral service protocol but is explicitly marked non-native in the
workflow index and must not be presented as an Amnesiac producer proof.
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib
import json
import tempfile
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .amnesiac_contracts import (
    AdmissionStatus,
    CandidateResult,
    CompileContextResponse,
    ExcludedItem,
    ProposalStatus,
    ProposeCandidatesResponse,
    RecordOutcomeResponse,
    ReopeningStatus,
    RequestReopeningResponse,
)
from .amnesiac_native import NativeAmnesiacService, amnesiac_available
from .amnesiac_stores import (
    InMemoryAgentOutcomeStore,
    InMemoryCandidateStore,
    InMemoryContextPacketStore,
)

WORKFLOW_SCHEMA = "dagr.amnesiac.governed_memory_demo.v0.1"
PROFILE = "srs.mcp.sdk_enforcement.v0.1"
RAW_DEMO_TEXT = (
    "The uploaded filing was received on the recorded date.",
    "A second proposition remains only a candidate.",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _jsonable(value: Any) -> Any:
    if hasattr(value, "value"):
        return value.value
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if hasattr(value, "__dataclass_fields__"):
        return _jsonable(asdict(value))
    return value


class _ReferenceDemoService:
    """Deterministic protocol implementation for CI, not a producer proof."""

    def propose_candidates(self, request):
        return ProposeCandidatesResponse(
            source_ref=request.source_ref,
            results=[
                CandidateResult(
                    candidate_ref=f"candidate:reference:{index}",
                    content_hash="sha256:" + hashlib.sha256(
                        item.claim.encode("utf-8")
                    ).hexdigest(),
                    proposal_status=ProposalStatus.CANDIDATE_RECORDED,
                    admission_status=AdmissionStatus.NOT_REQUESTED,
                )
                for index, item in enumerate(request.candidates, start=1)
            ],
            admission_performed=False,
        )

    def compile_context(self, request):
        return CompileContextResponse(
            context_packet_ref="packet:reference:1",
            context_packet_hash="sha256:" + "1" * 64,
            selected_claim_refs=["claim:admitted:1"],
            excluded=[
                ExcludedItem(
                    claim_ref="candidate:reference:2",
                    reason_code="not_admitted_lifecycle",
                )
            ],
            reconsiderable_refs=["candidate:reconsiderable:1"],
        )

    def request_reopening(self, request):
        return RequestReopeningResponse(
            candidate_ref=request.candidate_ref,
            status=ReopeningStatus.REOPENING_REQUESTED,
            outcome_ref="reopening-outcome:reference:1",
            lifecycle_before="reconsiderable",
            lifecycle_after="reconsiderable",
            detail="request recorded; no admission authority was invoked",
        )

    def record_outcome(self, request):
        return RecordOutcomeResponse(
            outcome_ref=request.agent_outcome_ref or "agent_outcome:reference:1",
            bridge_status="candidate_created",
            candidate_ref="candidate:from_outcome:reference:1",
            candidate_content_hash="sha256:" + "2" * 64,
            context_packet_ref=request.context_packet_ref,
            admission_status=AdmissionStatus.NOT_REQUESTED,
        )


def _native_service() -> NativeAmnesiacService:
    if not amnesiac_available():
        raise RuntimeError(
            "native governed-memory demo requires the optional producer packages; "
            "install the repository with `python -m pip install -e '.[amnesiac]'`"
        )

    from arcs_amnesiac.claim_graph import ClaimGraph
    from arcs_amnesiac.claim_graph_types import ClaimNode, LifecycleState
    from arcs_amnesiac.shadow_graph import (
        RejectedCandidate,
        RejectedCandidateLifecycle,
        ShadowGraph,
    )

    AgentOutcomeObject = importlib.import_module(
        "garp_sdk.agent_outcome_object"
    ).AgentOutcomeObject

    graph = ClaimGraph()
    graph.add_node(
        ClaimNode(
            claim_id="claim:admitted:1",
            normalized_text="An admitted record is available for the task.",
            lifecycle_state=LifecycleState.ACTIVE,
            admission_state="admitted",
        )
    )
    graph.add_node(
        ClaimNode(
            claim_id="claim:candidate:1",
            normalized_text="A candidate remains outside admitted context.",
            lifecycle_state=LifecycleState.CANDIDATE,
        )
    )

    shadow = ShadowGraph().add(
        RejectedCandidate(
            candidate_ref="candidate:reconsiderable:1",
            rejection_reason="additional corroboration required",
            lifecycle=RejectedCandidateLifecycle.RECONSIDERABLE,
        )
    )

    outcome_store = InMemoryAgentOutcomeStore()
    outcome_store.put(
        "agent_outcome:demo:1",
        AgentOutcomeObject.from_dict(
            {
                "outcome_id": "demo:1",
                "source_kind": "governed_memory_demo",
                "generated_by": "agent:dagr:demo",
                "summary_label": "review completed",
                "summary_ref": "summary:demo:1",
            }
        ),
    )

    return NativeAmnesiacService(
        candidate_store=InMemoryCandidateStore(),
        agent_outcome_store=outcome_store,
        claim_graph=graph,
        shadow_graph=shadow,
        context_packet_store=InMemoryContextPacketStore(),
    )


def _build_emitter(directory: Path) -> tuple[Any, Any]:
    from .srs_receipts import RawEnvelopeFileSink, SignedReceiptEmitter, SigningIdentity

    identity = SigningIdentity.generate(
        issuer_id="issuer:dagr:governed-memory-demo",
        key_id="issuer.dagr.governed-memory-demo/receipt-signing/ephemeral",
    )
    sink = RawEnvelopeFileSink(directory)
    sink.write_trust_bundle(identity.trust_bundle())
    return identity, SignedReceiptEmitter(identity=identity, sink=sink)


def _result_payload(result: Any) -> dict[str, Any]:
    payload = getattr(result, "structured_content", None)
    if not isinstance(payload, dict):
        raise RuntimeError("governed-memory tool returned no structured content")
    return _jsonable(payload)


async def run_governed_memory_demo_async(
    output: Path | None = None,
    *,
    service_mode: str = "native",
) -> Path:
    try:
        from fastmcp import FastMCP
        from fastmcp.client import Client
    except ModuleNotFoundError as exc:  # pragma: no cover - base dependency
        raise RuntimeError("FastMCP is required for the governed-memory demo") from exc

    directory = output or Path(tempfile.mkdtemp(prefix="dagr-governed-memory-"))
    directory.mkdir(parents=True, exist_ok=True)

    if service_mode == "native":
        service = _native_service()
        service_claim = "native_arcs_amnesiac"
    elif service_mode == "reference":
        service = _ReferenceDemoService()
        service_claim = "reference_contract_only"
    else:
        raise ValueError("service_mode must be 'native' or 'reference'")

    from .amnesiac_fastmcp import install_amnesiac_tools
    from .fastmcp_binding import DAGRMiddlewareConfig

    _identity, emitter = _build_emitter(directory)
    server = FastMCP("dagr-governed-memory-demo")
    install_amnesiac_tools(
        server,
        service,
        emitter=emitter,
        config=DAGRMiddlewareConfig(
            runtime_instance_id="runtime:dagr:governed-memory-demo",
            boundary_id="boundary:dagr:governed-memory-demo",
            policy_pack_id="policy:dagr:governed-memory-demo",
            policy_pack_version="v0.1",
            tool_classes={},
        ),
    )

    async with Client(server) as client:
        proposed = await client.call_tool(
            "amnesiac.propose_candidates",
            {
                "source_ref": "source:demo:1",
                "candidates": [
                    {"claim": RAW_DEMO_TEXT[0], "anchors": ["anchor:demo:1"]},
                    {"claim": RAW_DEMO_TEXT[1], "anchors": ["anchor:demo:2"]},
                ],
            },
        )
        context = await client.call_tool(
            "amnesiac.compile_context",
            {
                "task": "prepare a governed record summary",
                "matter": "matter:demo",
                "record_scope": [],
                "include_refused": True,
            },
        )
        reopened = await client.call_tool(
            "amnesiac.request_reopening",
            {
                "candidate_ref": "candidate:reconsiderable:1",
                "trigger_ref": "new_evidence_admitted",
                "new_evidence_refs": ["source:demo:new-evidence"],
            },
        )
        outcome = await client.call_tool(
            "amnesiac.record_outcome",
            {
                "agent_outcome_ref": "agent_outcome:demo:1",
                "context_packet_ref": _result_payload(context)["context_packet_ref"],
            },
        )

    results = {
        "propose_candidates": _result_payload(proposed),
        "compile_context": _result_payload(context),
        "request_reopening": _result_payload(reopened),
        "record_outcome": _result_payload(outcome),
    }

    receipt_paths = sorted(directory.glob("urn_srs_receipt_*.json"))
    trust_path = directory / "issuer-keys.json"
    manifest = {
        "schema": WORKFLOW_SCHEMA,
        "service_mode": service_mode,
        "service_claim": service_claim,
        "profile": PROFILE,
        "operations": {
            name: {
                "result": payload,
                "raw_input_retained": False,
            }
            for name, payload in results.items()
        },
        "receipt_set": [
            {"path": path.name, "sha256": _sha256(path)} for path in receipt_paths
        ],
        "trust_bundle": {"path": trust_path.name, "sha256": _sha256(trust_path)},
        "limitations": [
            "The workflow index is an unsigned artifact index, not a verification report.",
            "DAGR receipts contain references and digests, not raw claims or tool results.",
            "Independent verification must be performed by ARCS Verify from serialized bytes.",
            "The reference service mode is contract smoke only and is not producer evidence.",
            "compile_context remains the reference selector, not the full governed context planner.",
        ],
    }

    encoded = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    for raw_text in RAW_DEMO_TEXT:
        if raw_text in encoded:
            raise RuntimeError("raw demo claim leaked into workflow index")
    (directory / "governed-memory-workflow.json").write_text(
        encoded, encoding="utf-8"
    )
    return directory


def run_governed_memory_demo(
    output: Path | None = None,
    *,
    service_mode: str = "native",
) -> Path:
    return asyncio.run(
        run_governed_memory_demo_async(output, service_mode=service_mode)
    )
