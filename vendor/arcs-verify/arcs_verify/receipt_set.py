"""Verify a DAGR workflow receipt set from a refs/digests-only artifact index."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

WORKFLOW_SCHEMAS = frozenset({"dagr.amnesiac.governed_memory_demo.v0.1"})
PROFILE_DEFAULT = "srs.mcp.sdk_enforcement.v0.1"


@dataclass(slots=True)
class ReceiptSetReport:
    workflow_schema: str | None = None
    workflow_path: str | None = None
    service_mode: str | None = None
    manifest_integrity: bool = True
    receipt_linkage_valid: bool = True
    receipt_reports: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, str]] = field(default_factory=list)

    @property
    def receipts_valid(self) -> bool:
        return bool(self.receipt_reports) and all(
            bool(item.get("report", {}).get("passed"))
            for item in self.receipt_reports
        )

    @property
    def passed(self) -> bool:
        return (
            self.manifest_integrity
            and self.receipt_linkage_valid
            and self.receipts_valid
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "arcs_verify.receipt_set_report.v0_1",
            "verification_profile": "dagr.workflow_receipt_set.v0_1",
            "workflow_schema": self.workflow_schema,
            "workflow_path": self.workflow_path,
            "service_mode": self.service_mode,
            "manifest_integrity": self.manifest_integrity,
            "receipt_linkage_valid": self.receipt_linkage_valid,
            "receipts_valid": self.receipts_valid,
            "receipt_reports": list(self.receipt_reports),
            "findings": list(self.findings),
            "passed": self.passed,
            "boundary_note": (
                "This report verifies the enumerated receipt bytes, trust-bundle "
                "bytes, receipt signatures and admission/outcome linkage. The "
                "workflow index is unsigned, and this report does not verify "
                "Amnesiac producer semantics, durable-memory admission, or the "
                "truth of the underlying event."
            ),
        }


def _finding(report: ReceiptSetReport, code: str, detail: str) -> None:
    report.findings.append({"code": code, "detail": detail})


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _safe_relative(base: Path, raw: Any) -> Path:
    if not isinstance(raw, str) or not raw:
        raise ValueError("artifact path must be a non-empty string")
    if raw.startswith("./") or "/./" in raw or raw.endswith("/."):
        raise ValueError(f"unsafe relative artifact path: {raw!r}")
    posix = PurePosixPath(raw)
    if posix.is_absolute() or ".." in posix.parts:
        raise ValueError(f"unsafe relative artifact path: {raw!r}")
    resolved = (base / Path(*posix.parts)).resolve()
    base_resolved = base.resolve()
    try:
        resolved.relative_to(base_resolved)
    except ValueError as exc:
        raise ValueError(f"artifact path escapes workflow directory: {raw!r}") from exc
    return resolved


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON artifact must be an object: {path}")
    return value


def _schema_for_receipt(receipt: dict[str, Any]) -> Path:
    name = (
        "srs-envelope-v0.2.1.schema.json"
        if "subject_ref_origin" in receipt
        else "srs-envelope-v0.2.0.schema.json"
    )
    return Path(__file__).resolve().parent / "data" / name


def verify_receipt_set(workflow_path: Path) -> ReceiptSetReport:
    report = ReceiptSetReport(workflow_path=str(workflow_path))
    try:
        workflow = _load_json(workflow_path)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        report.manifest_integrity = False
        _finding(report, "workflow_unreadable", str(exc))
        return report

    report.workflow_schema = workflow.get("schema")
    report.service_mode = workflow.get("service_mode")
    if report.workflow_schema not in WORKFLOW_SCHEMAS:
        report.manifest_integrity = False
        _finding(
            report,
            "unsupported_workflow_schema",
            f"schema {report.workflow_schema!r} is not supported",
        )
        return report

    base = workflow_path.parent
    trust_entry = workflow.get("trust_bundle")
    receipt_entries = workflow.get("receipt_set")
    if not isinstance(trust_entry, dict) or not isinstance(receipt_entries, list):
        report.manifest_integrity = False
        _finding(
            report,
            "workflow_shape_invalid",
            "workflow requires object trust_bundle and array receipt_set",
        )
        return report

    try:
        trust_path = _safe_relative(base, trust_entry.get("path"))
        expected_trust_hash = trust_entry.get("sha256")
        if not trust_path.is_file():
            raise ValueError(f"trust bundle not found: {trust_path}")
        if _sha256(trust_path) != expected_trust_hash:
            raise ValueError("trust bundle SHA-256 does not match workflow index")
        keyring = _load_json(trust_path)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        report.manifest_integrity = False
        _finding(report, "trust_bundle_integrity_failed", str(exc))
        return report

    from .verifier import verify_receipt

    receipts: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    seen_ids: set[str] = set()
    profile = workflow.get("profile") or PROFILE_DEFAULT

    for index, entry in enumerate(receipt_entries):
        if not isinstance(entry, dict):
            report.manifest_integrity = False
            _finding(report, "receipt_entry_invalid", f"entry {index} is not an object")
            continue
        raw_path = entry.get("path")
        try:
            path = _safe_relative(base, raw_path)
            if str(raw_path) in seen_paths:
                raise ValueError(f"duplicate receipt path: {raw_path}")
            seen_paths.add(str(raw_path))
            if not path.is_file():
                raise ValueError(f"receipt not found: {path}")
            if _sha256(path) != entry.get("sha256"):
                raise ValueError(f"receipt SHA-256 mismatch: {raw_path}")
            receipt = _load_json(path)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            report.manifest_integrity = False
            _finding(report, "receipt_integrity_failed", str(exc))
            continue

        receipt_id = receipt.get("receipt_id")
        if not isinstance(receipt_id, str) or not receipt_id:
            report.manifest_integrity = False
            _finding(report, "receipt_id_missing", f"receipt {raw_path!r} has no receipt_id")
            continue
        if receipt_id in seen_ids:
            report.manifest_integrity = False
            _finding(report, "duplicate_receipt_id", receipt_id)
            continue
        seen_ids.add(receipt_id)

        verification = verify_receipt(
            receipt,
            keyring,
            schema_path=_schema_for_receipt(receipt),
            selected_profile=profile,
        )
        report.receipt_reports.append(
            {
                "path": str(raw_path),
                "sha256": entry.get("sha256"),
                "receipt_id": receipt_id,
                "receipt_kind": receipt.get("receipt_kind"),
                "requested_tool_name": receipt.get("requested_tool_name"),
                "subject_ref_origin_disclosed": receipt.get(
                    "subject_ref_origin", "not_declared"
                ),
                "report": verification.to_dict(),
            }
        )
        receipts.append(receipt)

    by_id = {
        item.get("receipt_id"): item
        for item in receipts
        if isinstance(item.get("receipt_id"), str)
    }
    for receipt in receipts:
        if receipt.get("receipt_kind") != "outcome":
            continue
        parent_ref = receipt.get("admission_receipt_ref")
        admission = by_id.get(parent_ref)
        if not isinstance(admission, dict) or admission.get("receipt_kind") != "admission":
            report.receipt_linkage_valid = False
            _finding(
                report,
                "admission_receipt_unresolved",
                f"outcome {receipt.get('receipt_id')!r} references {parent_ref!r}",
            )
            continue
        # ``requested_tool_name`` belongs to the admission receipt. Outcome
        # receipts link back through ``admission_receipt_ref`` and preserve the
        # neutral ``logical_call_id``; they do not repeat the requested tool.
        if receipt.get("logical_call_id") != admission.get("logical_call_id"):
            report.receipt_linkage_valid = False
            _finding(
                report,
                "admission_outcome_linkage_mismatch",
                (
                    "logical_call_id differs for outcome "
                    f"{receipt.get('receipt_id')!r}"
                ),
            )

    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="arcs-verify receipt-set",
        description="Verify every DAGR receipt enumerated by a workflow index.",
    )
    parser.add_argument("workflow", type=Path)
    parser.add_argument("--json", action="store_true", dest="as_json")
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as exc:
        return int(exc.code)

    report = verify_receipt_set(args.workflow)
    data = report.to_dict()
    if args.as_json:
        json.dump(data, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        print(f"workflow_schema: {data['workflow_schema']}")
        print(f"service_mode: {data['service_mode']}")
        print(f"manifest_integrity: {'PASS' if data['manifest_integrity'] else 'FAIL'}")
        print(f"receipt_linkage_valid: {'PASS' if data['receipt_linkage_valid'] else 'FAIL'}")
        for item in data["receipt_reports"]:
            state = "PASS" if item["report"]["passed"] else "FAIL"
            print(
                f"receipt: {item['path']} {state} "
                f"origin={item['subject_ref_origin_disclosed']}"
            )
        for finding in data["findings"]:
            print(f"finding: {finding['code']}: {finding['detail']}")
        print(f"passed: {str(data['passed']).lower()}")
    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
