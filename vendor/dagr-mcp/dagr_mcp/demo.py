"""Generate signed DAGR/SRS receipts from the demo paths."""

from __future__ import annotations

import argparse
import asyncio
import json
import shlex
import sys
import tempfile
from pathlib import Path

from .enforcement_harness import HarnessConfig, HarnessSinks, ToolPolicy, wrap_handler
from .sdk_spine import InMemoryEventSink
from .srs_bridge import BridgeConfig, HarnessSRSBridge
from .srs_receipts import RawEnvelopeFileSink, SignedReceiptEmitter, SigningIdentity


PROFILE = "srs.mcp.sdk_enforcement.v0.1"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, prog="dagr-mcp")
    subparsers = parser.add_subparsers(dest="command")
    demo = subparsers.add_parser("demo", help="run the receipt demo")
    demo.add_argument(
        "--output",
        type=Path,
        help="Receipt output directory. Defaults to an ephemeral directory.",
    )
    demo.add_argument(
        "--direct",
        action="store_true",
        help="Use the direct WP3 harness path instead of the FastMCP middleware path.",
    )
    memory = subparsers.add_parser(
        "governed-memory-demo",
        help="run the DAGR + Amnesiac governed-memory workflow",
    )
    memory.add_argument(
        "--output",
        type=Path,
        help="Artifact output directory. Defaults to an ephemeral directory.",
    )
    memory.add_argument(
        "--service-mode",
        choices=("native", "reference"),
        default="native",
        help=(
            "native uses the optional real Amnesiac producer; reference is "
            "contract smoke only"
        ),
    )
    first_run = subparsers.add_parser(
        "first-run",
        help=(
            "run the admitted-vs-refused native-action proof: same handler, "
            "same arguments, differing only in the governance decision"
        ),
    )
    first_run.add_argument(
        "--output",
        type=Path,
        help="Proof output directory. Defaults to an ephemeral directory.",
    )
    first_run.add_argument(
        "--capture",
        action="store_true",
        help=(
            "Use a fixed signing identity and injected clock so receipt "
            "digests are byte-identical across runs. Default is ephemeral."
        ),
    )
    return parser


def _build_emitter(directory: Path) -> tuple[SigningIdentity, SignedReceiptEmitter]:
    sink = RawEnvelopeFileSink(directory)
    identity = SigningIdentity.generate(
        issuer_id="issuer:dagr:demo",
        key_id="issuer.dagr.demo/receipt-signing/ephemeral",
    )
    sink.write_trust_bundle(identity.trust_bundle())
    return identity, SignedReceiptEmitter(identity=identity, sink=sink)


def run_direct_demo(output: Path | None = None) -> Path:
    directory = output or Path(tempfile.mkdtemp(prefix="dagr-mcp-demo-"))
    _identity, emitter = _build_emitter(directory)
    bridge = HarnessSRSBridge(
        emitter=emitter,
        config=BridgeConfig(
            runtime_instance_id="runtime:dagr:demo",
            boundary_id="boundary:dagr:direct-harness",
            policy_pack_id="policy:dagr:demo",
            policy_pack_version="v0.1",
        ),
    )

    def lookup(tool_name: str, arguments: object, context: object = None) -> dict[str, object]:
        return {"record_ref": "record:demo:1", "found": True}

    governed = wrap_handler(
        lookup,
        HarnessConfig(
            harness_version="v0.1",
            module_id="dagr-mcp-demo",
            module_version="v0.1",
            profile_ref="srs.mcp.sdk_enforcement.v0.1",
            policy_ref="policy:dagr:demo@v0.1",
        ),
        HarnessSinks(event=InMemoryEventSink()),
        policies=[ToolPolicy(tool_name="records.lookup", tool_class="read", decision="allow")],
        srs_bridge=bridge,
    )
    result = governed(
        "records.lookup",
        {"record_ref": "record:demo:1"},
        {"request_ref": "call:dagr:demo:1", "actor_ref": "actor:dagr:demo"},
    )
    if not result.ok:
        raise RuntimeError(f"governed demo failed: {result.failure_reason}")
    return directory


async def run_fastmcp_demo_async(output: Path | None = None) -> Path:
    try:
        from fastmcp import FastMCP
        from fastmcp.client import Client
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "FastMCP is required for the default demo. "
            "Install dagr-mcp with dependencies, or run `dagr-mcp demo --direct`."
        ) from exc

    from .fastmcp_binding import DAGRMiddleware, DAGRMiddlewareConfig

    directory = output or Path(tempfile.mkdtemp(prefix="dagr-mcp-demo-"))
    _identity, emitter = _build_emitter(directory)
    server = FastMCP("dagr-mcp-demo")
    server.add_middleware(
        DAGRMiddleware(
            emitter=emitter,
            config=DAGRMiddlewareConfig(
                runtime_instance_id="runtime:dagr:demo",
                boundary_id="boundary:dagr:fastmcp",
                policy_pack_id="policy:dagr:demo",
                policy_pack_version="v0.1",
                tool_classes={"records_lookup": "read"},
            ),
        )
    )

    @server.tool
    async def records_lookup(record_ref: str) -> dict[str, object]:
        return {"record_ref": record_ref, "found": True}

    async with Client(server) as client:
        await client.call_tool("records_lookup", {"record_ref": "record:demo:1"})
    return directory


def run_demo(output: Path | None = None, *, direct: bool = False) -> Path:
    if direct:
        return run_direct_demo(output)
    return asyncio.run(run_fastmcp_demo_async(output))


def arcs_verify_command(directory: Path) -> str:
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


def main(argv: list[str] | None = None) -> int:
    raw_args = list(sys.argv[1:] if argv is None else argv)
    commands = {"demo", "governed-memory-demo", "first-run"}
    if not raw_args or raw_args[0] not in commands:
        raw_args = ["demo", *raw_args]
    args = build_parser().parse_args(raw_args)
    if args.command == "governed-memory-demo":
        from .governed_memory_demo import run_governed_memory_demo

        directory = run_governed_memory_demo(
            args.output, service_mode=args.service_mode
        )
    elif args.command == "first-run":
        from .first_run_demo import run_first_run_proof

        proof = run_first_run_proof(args.output, capture=args.capture)
        directory = proof.directory
    else:
        directory = run_demo(args.output, direct=args.direct)
    receipt_paths = sorted(directory.glob("urn_srs_receipt_*.json"))
    payload = {
        "output_directory": str(directory),
        "trust_bundle": str(directory / "issuer-keys.json"),
        "receipts": [str(path) for path in receipt_paths],
        "next_command": arcs_verify_command(directory),
    }
    workflow = directory / "governed-memory-workflow.json"
    if workflow.exists():
        payload["workflow_index"] = str(workflow)
    side_effects = directory / "side_effects.json"
    if side_effects.exists():
        payload["side_effects"] = json.loads(side_effects.read_text())
        payload["side_effects_file"] = str(side_effects)
        payload["quickstart_file"] = str(directory / "quickstart.txt")
    print(json.dumps(payload, indent=2))
    print(arcs_verify_command(directory))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
