# DAGR SRS verification execution/report contract (frozen v0.1)

This directory is the single, frozen v0.1 contract for what ARCS Verify
executes over a signed DAGR SRS receipt, what it hashes, and what it reports.
It is scoped to the DAGR MCP receipt-emitter/runtime binding's supported
profile, `srs.mcp.sdk_enforcement.v0.1`, and its `admission` and `outcome`
receipt kinds. `srs.connection.lifecycle.v0.1` is out of scope.

It exists so a later, separate, authenticated DAGR exporter can bind an exact
ARCS execution and report **without inventing any field or hash meaning**.
This lane adds no exporter, no DAGR runtime change, and no authentication —
see [Boundary guards](#boundary-guards).

## What ARCS Verify executes

- **Verifier repository:** `https://github.com/thelaplage/arcs-verify`
- **Pinned entrypoint:** `arcs_verify.cli:main`, the console-script target
  declared in `[project.scripts]` of `pyproject.toml` and exposed as the
  `arcs-verify` command. This is the same entrypoint that already performs
  the eight-Boolean verification (`arcs_verify.verifier.verify_receipt`); this
  contract's report and execution record wrap that existing path, they do not
  reimplement it.
- **New report-emission surface:** `arcs-verify dagr-report RECEIPT --keyring
  TRUST_BUNDLE --profile srs.mcp.sdk_enforcement.v0.1 --verifier-commit
  <full-40-hex-sha> --execution-id <opaque-id> --executed-at
  <RFC3339-timestamp>` — see `execution-contract.json`.
- Full identity pin, including package version and deterministic environment
  assumptions: `execution-contract.json`.

## Files

| File | Purpose |
|---|---|
| `execution-contract.json` | Pins the exact execution surface: repository, commit discipline, entrypoint, configuration-digest recipe, environment assumptions. |
| `receipt-hash-contract.json` | Defines the receipt artifact hash, the distinct signature-verification input, the trust-bundle digest, the verifier-configuration digest, and the verification-report digest. |
| `supported-receipt-contract.json` | Pins the receipt/profile identity this contract supports (`srs.mcp.sdk_enforcement.v0.1`, `admission`/`outcome` only) and documents the existing envelope-schema `additionalProperties: true` behavior. |
| `verification-report.schema.json` | JSON Schema (draft 2020-12) for the deterministic verification report. `additionalProperties: false`; unknown fields fail closed. |
| `verification-execution-record.schema.json` | JSON Schema for the execution record binding one invocation's receipt, trust bundle, verifier build, configuration, and report. `additionalProperties: false`. |
| `golden/` | Byte-identical copies of real, already-passing DAGR fixtures (see below), plus their generated deterministic reports, execution records, and pinned hash `expectations.json`. |

Implementation: `arcs_verify/dagr_report.py`. It imports and calls
`arcs_verify.verifier.verify_receipt` — it does not define a second verifier.

## Authoritative receipt-hash semantics

```text
algorithm:        sha256
canonicalization:  RFC8785-JCS
encoding:          UTF-8
input:             the complete accepted receipt JSON object, including receipt_signature
output:            lowercase hexadecimal SHA-256, no prefix
```

This is the **receipt artifact hash**
(`arcs_verify.dagr_report.receipt_artifact_hash`). No previously ratified,
contradictory meaning exists for it: the only pre-existing hash-like values
for this receipt family are `receipt_file_sha256` (raw file bytes, not
canonicalized) and `canonical_preimage_sha256` (the *signing* preimage with
`receipt_signature.signature` removed) in
`vendor/arcs-srs/vectors/signed-receipt-v0.1/manifest.json` — neither is "hash
of the complete receipt object including `receipt_signature`," so this
contract does not silently override or contradict either.

**Signature verification is distinct.** It uses the existing, frozen DAGR SRS
signed-input semantics from `arcs_verify.verifier.verify_receipt`: Ed25519
over RFC8785-JCS bytes of the receipt with `receipt_signature.signature`
(only) deleted. The report exposes these as clearly separate concepts:

- `receipt_artifact_hash`, `receipt_artifact_hash_algorithm`,
  `receipt_artifact_canonicalization` — the complete-object hash.
- `verdicts.signature_valid` (in the report) — the result of Ed25519
  signature verification over the distinct, smaller preimage. See
  `receipt-hash-contract.json` for the full input contract of each.

The `rfc8785` dependency is pinned exactly (`rfc8785==0.1.4`) and implements
RFC 8785 JCS, not merely recursively sorted JSON; `tests/test_dagr_srs_report_contract.py`
proves this against the official RFC 8785 §3.2.2 vector already vendored at
`vendor/arcs-srs/vectors/rfc8785/`.

## Deterministic verification report

`verification-report.schema.json` defines the report. It contains the eight
existing Boolean ARCS verdict fields, unchanged in name and meaning, inside a
`verdicts` object — and nothing else there. `chain_status` is reported
alongside `verdicts`, never inside it: it is not a ninth Boolean.

The report contains no wall-clock time, random identifiers, hostnames, or
temporary paths. `failure_codes` is included beyond the objective's minimum
field list because it is fully deterministic (fixed string codes, never raw
receipt content); the underlying schema-validator `details` list is
deliberately **excluded**, because it can carry raw instance-value text from
JSON Schema error messages and is not appropriate for a frozen, shareable
contract artifact.

## Verification execution record

`verification-execution-record.schema.json` defines the execution record. It
binds a particular invocation's receipt, trust bundle, verifier build,
configuration, and report via `verification_report_digest` — sha256 over
RFC8785-JCS UTF-8 bytes of the complete deterministic report object.

Every execution record carries this fixed statement verbatim
(`authentication_scope_statement`):

> This execution record binds an asserted invocation to exact input and
> output artifacts. Standing alone, it does not authenticate who executed
> the verifier or authorize an export.

`execution_id` and `executed_at` are execution metadata (asserted, not
deterministically re-derivable) and are deliberately absent from the
deterministic report.

## Trust-bundle digest

```text
sha256(RFC8785-JCS(complete trust-bundle JSON object))
```

The report records which exact trust artifact was used
(`trust_bundle_digest`). Recording it is not the same as authorizing it: a
trust bundle supplied beside a receipt is not treated as authoritative merely
because it is structurally valid. Whether a given trust bundle was *authorized*
for use is established by later exporter and consumer contracts, not by this
one.

## Golden fixtures

`golden/admission-receipt.json`, `golden/outcome-receipt.json`, and
`golden/trust-bundle.json` are byte-identical copies of
`packs/srs.mcp.sdk_enforcement/v0.1/implementation/dagr-mcp-fastmcp-demo/{admission-admitted.json,
outcome-result-returned.json, issuer-keys.json}` — real, already-governed
DAGR FastMCP fixtures with a closed, tested `expectations.json` of their own
(`packs/srs.mcp.sdk_enforcement/v0.1/PROVISIONAL_FIXTURES.md`). They are never
rewritten here.

`golden/admission-report.json`, `golden/outcome-report.json`,
`golden/admission-execution-record.json`, and
`golden/outcome-execution-record.json` are generated by calling the actual
`verify_receipt` path and the builder functions in `arcs_verify/dagr_report.py`
— not hand-authored. `golden/expectations.json` pins the exact hash values so
regressions are caught byte-for-byte.

`golden_regeneration_note` (see `execution-contract.json`): the `verifier_commit`
recorded in these fixtures is the feature-branch commit at authoring time. Per
`docs/VERSIONING.md` precedent, it must be regenerated and reconciled to the
squash-merge commit before this contract is treated as merged-authoritative.

## Boundary guards

This contract, and `arcs_verify/dagr_report.py`, add none of the following:
an authenticated exporter; a DAGR runtime change; Countervail code; storage;
API routes; UI; live session fixtures; production signing keys; LEP
conversion; a new admission decision; or new package dependencies (only
`rfc8785`, `cryptography`, and `jsonschema`, already required by the existing
verifier, are used).
