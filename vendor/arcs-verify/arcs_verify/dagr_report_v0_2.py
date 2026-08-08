"""DAGR SRS verification report contract v0.2 (origin disclosure).

v0.2 is v0.1 plus exactly one field. It adds ``subject_ref_origin_disclosed``,
which discloses how the emitter said it obtained ``subject_ref``, and it
changes nothing else:

* the same eight Boolean verdicts, produced by the same
  :func:`arcs_verify.verifier.verify_receipt` call;
* the same ``chain_status``, still reported beside the verdicts and still not
  a ninth Boolean;
* the same receipt/trust/configuration hash semantics.

Parity is structural, not merely tested: :func:`build_verification_report`
below delegates to the frozen v0.1 builder and then rewrites the two version
identifiers and inserts the one new field. There is no second verdict path, so
no origin value can upgrade, downgrade, override, excuse, or replace any
verification result. The disclosure is a disclosure. It is never a verdict.

The v0.1 contract directory and the v0.1 execution-record contract are frozen
and are not touched by this module.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from .dagr_report import (
    build_verification_report as _build_verification_report_v0_1,
)
from .dagr_report import (
    receipt_artifact_hash,
    trust_bundle_digest,
    verification_report_digest,
    verifier_configuration_digest,
)
from .subject_ref_origin import (
    DECLARED_ORIGINS,
    NOT_DECLARED,
    ORIGIN_DISCLOSURE_VALUES,
    MalformedSubjectRefOrigin,
    read_subject_ref_origin,
)
from .verifier import MCP_PROFILE, VerificationReport, verify_receipt

REPORT_VERSION = "v0.2"
REPORT_CONTRACT_ID = "srs.dagr_verification_report.v0.2"

#: The one field v0.2 adds over v0.1.
ORIGIN_DISCLOSURE_FIELD = "subject_ref_origin_disclosed"

#: Fields whose values v0.2 deliberately restates. Every other field in a v0.2
#: report is byte-identical to the v0.1 report for the same input.
VERSION_FIELDS = ("report_version", "report_contract_id")

_CONTRACT_ROOT = (
    Path(__file__).resolve().parent
    / "contracts"
    / "dagr-srs-verification-report-v0-2"
)
_REPORT_SCHEMA_PATH = _CONTRACT_ROOT / "verification-report.schema.json"

__all__ = [
    "DECLARED_ORIGINS",
    "NOT_DECLARED",
    "ORIGIN_DISCLOSURE_FIELD",
    "ORIGIN_DISCLOSURE_VALUES",
    "REPORT_CONTRACT_ID",
    "REPORT_VERSION",
    "VERSION_FIELDS",
    "build_verification_report",
    "envelope_schema_sha256_for_path",
    "main",
    "receipt_artifact_hash",
    "trust_bundle_digest",
    "validate_verification_report",
    "verification_report_digest",
    "verifier_configuration_digest",
]


def envelope_schema_sha256_for_path(schema_path: Path) -> str:
    """sha256 of the envelope schema file actually used for a verification."""

    return hashlib.sha256(schema_path.read_bytes()).hexdigest()


def build_verification_report(
    receipt: dict[str, Any],
    verification: VerificationReport,
    *,
    selected_profile: str,
    trust_bundle: dict[str, Any],
    verifier_commit: str,
    envelope_schema_sha256: str,
) -> dict[str, Any]:
    """Assemble the v0.2 deterministic verification report.

    Delegates verbatim to the frozen v0.1 builder, then restates the two
    version identifiers and adds the origin disclosure. Every verdict, the
    ``chain_status``, the failure codes, and all hash fields come back from the
    v0.1 builder untouched.

    Raises :class:`~arcs_verify.subject_ref_origin.MalformedSubjectRefOrigin`
    when the receipt carries a present but out-of-vocabulary
    ``subject_ref_origin``. Such input is invalid and is never reported as
    ``not_declared``.
    """

    report = _build_verification_report_v0_1(
        receipt,
        verification,
        selected_profile=selected_profile,
        trust_bundle=trust_bundle,
        verifier_commit=verifier_commit,
        envelope_schema_sha256=envelope_schema_sha256,
    )

    report["report_version"] = REPORT_VERSION
    report["report_contract_id"] = REPORT_CONTRACT_ID
    report[ORIGIN_DISCLOSURE_FIELD] = read_subject_ref_origin(receipt)

    return report


def validate_verification_report(report: dict[str, Any]) -> list[str]:
    validator = Draft202012Validator(
        json.loads(_REPORT_SCHEMA_PATH.read_text(encoding="utf-8"))
    )
    return [error.message for error in validator.iter_errors(report)]


def _default_schema() -> Path:
    return (
        Path(__file__).resolve().parent
        / "data"
        / "srs-envelope-v0.2.1.schema.json"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="arcs-verify dagr-report-v0-2",
        description=(
            "Emit the v0.2 DAGR SRS verification report for a signed "
            "receipt: the same eight Booleans and the same chain_status as "
            "v0.1, plus the subject-reference origin disclosure."
        ),
    )
    parser.add_argument("receipt", type=Path)
    parser.add_argument("--keyring", required=True, type=Path)
    parser.add_argument("--profile", default=MCP_PROFILE)
    parser.add_argument(
        "--schema",
        type=Path,
        default=_default_schema(),
        help=(
            "Envelope schema to verify against. Defaults to the v0.2.1 pin, "
            "which enforces the closed subject_ref_origin vocabulary. The "
            "retained v0.2.0 pin remains accepted for historical receipts."
        ),
    )
    parser.add_argument(
        "--verifier-commit",
        required=True,
        help=(
            "Full 40-hex git commit SHA of the arcs-verify checkout that "
            "performed this invocation. Not computed automatically: supply "
            "the exact commit from your build/release metadata."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        receipt = json.loads(args.receipt.read_text(encoding="utf-8"))
        trust_bundle = json.loads(args.keyring.read_text(encoding="utf-8"))
        schema_sha256 = envelope_schema_sha256_for_path(args.schema)
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
            envelope_schema_sha256=schema_sha256,
        )
    except MalformedSubjectRefOrigin as exc:
        print(f"error: invalid receipt: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(report, indent=2, sort_keys=True))

    return 0 if verification.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
