"""DAGR SRS verification execution/report contract (frozen v0.1).

This module builds the deterministic verification report and the
verification execution record defined by
``arcs_verify/contracts/dagr-srs-verification-report-v0-1/``. It does not reimplement
receipt verification: every Boolean verdict and the ``chain_status`` value
come from :func:`arcs_verify.verifier.verify_receipt`, the existing governed
verification path. This module only computes the contract's hash/digest
semantics and assembles the two frozen documents around that verdict.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import rfc8785
from jsonschema import Draft202012Validator

from .verifier import (
    FROZEN_SCHEMA_SHA256,
    MCP_PROFILE,
    PROFILE_IDENTITIES,
    RECEIPT_VERSION,
    VerificationReport,
    verify_receipt,
)

REPORT_VERSION = "v0.1"
REPORT_CONTRACT_ID = "srs.dagr_verification_report.v0.1"
EXECUTION_RECORD_VERSION = "v0.1"
EXECUTION_CONTRACT_ID = "srs.dagr_verification_execution.v0.1"

VERIFIER_REPOSITORY = "https://github.com/thelaplage/arcs-verify"
VERIFIER_ENTRYPOINT = "arcs_verify.cli:main"

# The DAGR MCP receipt-emitter/runtime binding only ever emits admission and
# outcome receipts under srs.mcp.sdk_enforcement.v0.1. Other profiles (for
# example srs.connection.lifecycle.v0.1) are out of scope for this contract.
SUPPORTED_RECEIPT_KINDS = ("admission", "outcome")

VERDICT_FIELDS = (
    "schema_digest",
    "envelope",
    "profile",
    "raw_content_exclusion",
    "signature_valid",
    "issuer_key_resolved",
    "issuer_key_trusted",
    "attestation_limits_present",
)

AUTHENTICATION_SCOPE_STATEMENT = (
    "This execution record binds an asserted invocation to exact input and "
    "output artifacts. Standing alone, it does not authenticate who executed "
    "the verifier or authorize an export."
)

_CONTRACT_ROOT = (
    Path(__file__).resolve().parent
    / "contracts"
    / "dagr-srs-verification-report-v0-1"
)
_REPORT_SCHEMA_PATH = _CONTRACT_ROOT / "verification-report.schema.json"
_EXECUTION_RECORD_SCHEMA_PATH = (
    _CONTRACT_ROOT / "verification-execution-record.schema.json"
)


def _rfc8785_sha256_hex(value: Any) -> str:
    return hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def receipt_artifact_hash(receipt: dict[str, Any]) -> str:
    """sha256(RFC8785-JCS(receipt)), including receipt_signature."""

    return _rfc8785_sha256_hex(receipt)


def trust_bundle_digest(trust_bundle: dict[str, Any]) -> str:
    """sha256(RFC8785-JCS(trust_bundle)), the complete trust artifact."""

    return _rfc8785_sha256_hex(trust_bundle)


def verifier_configuration_digest(
    *,
    selected_profile: str,
    envelope_schema_sha256: str = FROZEN_SCHEMA_SHA256,
) -> str:
    """sha256(RFC8785-JCS) over the pinned schema digest, receipt version,

    and selected profile that governed this invocation.

    ``envelope_schema_sha256`` defaults to the retained v0.2.0 pin, so every
    pre-existing caller and every historical v0.2.0-era input produces the
    identical digest it always has. A caller that verified against a different
    pinned envelope schema passes that schema's digest so the recorded
    configuration names the artifact actually used.
    """

    return _rfc8785_sha256_hex(
        {
            "envelope_schema_sha256": envelope_schema_sha256,
            "receipt_version": RECEIPT_VERSION,
            "selected_profile": selected_profile,
        }
    )


def verification_report_digest(report: dict[str, Any]) -> str:
    """sha256(RFC8785-JCS(report)) for the complete deterministic report."""

    return _rfc8785_sha256_hex(report)


def build_verification_report(
    receipt: dict[str, Any],
    verification: VerificationReport,
    *,
    selected_profile: str,
    trust_bundle: dict[str, Any],
    verifier_commit: str,
    envelope_schema_sha256: str = FROZEN_SCHEMA_SHA256,
) -> dict[str, Any]:
    """Assemble the frozen v0.1 deterministic verification report.

    Raises ValueError (refusal) if the selected profile or the receipt's
    declared kind is outside this contract's scope, rather than silently
    reporting a value for an unsupported combination.
    """

    if selected_profile != MCP_PROFILE:
        raise ValueError(
            "DAGR verification report contract v0.1 supports only "
            f"{MCP_PROFILE!r}, not {selected_profile!r}"
        )

    identity = PROFILE_IDENTITIES[selected_profile]
    receipt_kind = receipt.get("receipt_kind")

    if receipt_kind not in SUPPORTED_RECEIPT_KINDS:
        raise ValueError(
            "DAGR verification report contract v0.1 supports only "
            f"receipt_kind in {SUPPORTED_RECEIPT_KINDS!r}, not "
            f"{receipt_kind!r}"
        )

    return {
        "report_version": REPORT_VERSION,
        "report_contract_id": REPORT_CONTRACT_ID,
        "receipt_id": receipt.get("receipt_id"),
        "receipt_kind": receipt_kind,
        "receipt_artifact_hash": receipt_artifact_hash(receipt),
        "receipt_artifact_hash_algorithm": "sha256",
        "receipt_artifact_canonicalization": "RFC8785-JCS",
        "supported_receipt_contract_id": identity[0],
        "supported_receipt_contract_version": identity[1],
        "verifier_repository": VERIFIER_REPOSITORY,
        "verifier_commit": verifier_commit,
        "verifier_entrypoint": VERIFIER_ENTRYPOINT,
        "verifier_configuration_digest": verifier_configuration_digest(
            selected_profile=selected_profile,
            envelope_schema_sha256=envelope_schema_sha256,
        ),
        "trust_bundle_digest": trust_bundle_digest(trust_bundle),
        "verdicts": {
            name: bool(getattr(verification, name)) for name in VERDICT_FIELDS
        },
        "chain_status": verification.chain_status,
        "failure_codes": list(verification.failure_codes),
    }


def build_verification_execution_record(
    report: dict[str, Any],
    *,
    execution_id: str,
    executed_at: str,
    verifier_commit: str,
) -> dict[str, Any]:
    """Assemble the frozen v0.1 verification execution record for `report`."""

    return {
        "execution_record_version": EXECUTION_RECORD_VERSION,
        "execution_contract_id": EXECUTION_CONTRACT_ID,
        "execution_id": execution_id,
        "executed_at": executed_at,
        "verifier_repository": VERIFIER_REPOSITORY,
        "verifier_commit": verifier_commit,
        "verifier_entrypoint": VERIFIER_ENTRYPOINT,
        "verifier_configuration_digest": report["verifier_configuration_digest"],
        "receipt_id": report["receipt_id"],
        "receipt_artifact_hash": report["receipt_artifact_hash"],
        "trust_bundle_digest": report["trust_bundle_digest"],
        "verification_report_digest": verification_report_digest(report),
        "verification_report_digest_algorithm": "sha256",
        "verification_report_canonicalization": "RFC8785-JCS",
        "authentication_scope_statement": AUTHENTICATION_SCOPE_STATEMENT,
    }


def check_report_matches_receipt(
    report: dict[str, Any],
    receipt: dict[str, Any],
) -> list[str]:
    """Binding checks between a report and the receipt it claims to cover."""

    mismatches: list[str] = []

    if report.get("receipt_id") != receipt.get("receipt_id"):
        mismatches.append(
            "receipt_id mismatch: report="
            f"{report.get('receipt_id')!r} receipt={receipt.get('receipt_id')!r}"
        )

    recomputed = receipt_artifact_hash(receipt)
    if report.get("receipt_artifact_hash") != recomputed:
        mismatches.append(
            "receipt_artifact_hash mismatch: report="
            f"{report.get('receipt_artifact_hash')!r} recomputed={recomputed!r}"
        )

    return mismatches


def check_execution_record_matches_report(
    record: dict[str, Any],
    report: dict[str, Any],
) -> list[str]:
    """Binding checks between an execution record and its paired report."""

    mismatches: list[str] = []

    for key in (
        "receipt_id",
        "receipt_artifact_hash",
        "trust_bundle_digest",
        "verifier_commit",
        "verifier_repository",
        "verifier_entrypoint",
        "verifier_configuration_digest",
    ):
        if record.get(key) != report.get(key):
            mismatches.append(
                f"{key} mismatch: execution_record={record.get(key)!r} "
                f"report={report.get(key)!r}"
            )

    recomputed = verification_report_digest(report)
    if record.get("verification_report_digest") != recomputed:
        mismatches.append(
            "verification_report_digest mismatch: execution_record="
            f"{record.get('verification_report_digest')!r} "
            f"recomputed={recomputed!r}"
        )

    return mismatches


def _load_schema(path: Path) -> Draft202012Validator:
    return Draft202012Validator(json.loads(path.read_text(encoding="utf-8")))


def validate_verification_report(report: dict[str, Any]) -> list[str]:
    validator = _load_schema(_REPORT_SCHEMA_PATH)
    return [error.message for error in validator.iter_errors(report)]


def validate_verification_execution_record(record: dict[str, Any]) -> list[str]:
    validator = _load_schema(_EXECUTION_RECORD_SCHEMA_PATH)
    return [error.message for error in validator.iter_errors(record)]


def _default_schema() -> Path:
    return (
        Path(__file__).resolve().parent
        / "data"
        / "srs-envelope-v0.2.0.schema.json"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="arcs-verify dagr-report",
        description=(
            "Emit the frozen v0.1 DAGR SRS verification report and "
            "execution record for a signed receipt, using the existing "
            "eight-Boolean verification path."
        ),
    )
    parser.add_argument("receipt", type=Path)
    parser.add_argument("--keyring", required=True, type=Path)
    parser.add_argument("--profile", default=MCP_PROFILE)
    parser.add_argument("--schema", type=Path, default=_default_schema())
    parser.add_argument(
        "--verifier-commit",
        required=True,
        help=(
            "Full 40-hex git commit SHA of the arcs-verify checkout that "
            "performed this invocation. Not computed automatically: supply "
            "the exact commit from your build/release metadata."
        ),
    )
    parser.add_argument("--execution-id", required=True)
    parser.add_argument("--executed-at", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        receipt = json.loads(args.receipt.read_text(encoding="utf-8"))
        trust_bundle = json.loads(args.keyring.read_text(encoding="utf-8"))
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"error: malformed JSON: {exc}", file=sys.stderr)
        return 2

    verification = verify_receipt(
        receipt,
        trust_bundle,
        schema_path=args.schema,
        selected_profile=args.profile,
    )

    try:
        report = build_verification_report(
            receipt,
            verification,
            selected_profile=args.profile,
            trust_bundle=trust_bundle,
            verifier_commit=args.verifier_commit,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    record = build_verification_execution_record(
        report,
        execution_id=args.execution_id,
        executed_at=args.executed_at,
        verifier_commit=args.verifier_commit,
    )

    print(
        json.dumps(
            {
                "verification_report": report,
                "verification_execution_record": record,
            },
            indent=2,
            sort_keys=True,
        )
    )

    return 0 if verification.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
