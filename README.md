# dagr-quickstart

**The smallest governed action, end to end — in one command.**

A caller invokes two MCP tools through the real `dagr-mcp` runtime boundary.
One tool is `read`-classed and **admitted**; one is `write`-classed and
**refused**. Both emit **signed, metadata-only SRS receipts**. Each receipt is
then independently recomputed by **`arcs-verify`** running in a separate
interpreter with no producer packages.

```
caller
  → ping (read)       ─┐
  → write_note (write) ─┤ governed by dagr-mcp (DAGRMiddleware + SignedReceiptEmitter)
                        ├─ ping        → admitted → signed admission + outcome receipts
                        └─ write_note  → refused  → signed refused-admission receipt (body never runs)
  → arcs-verify recomputes every receipt (separate process, bytes only)
```

Nothing here mints a verdict. Dispositions and receipt facts are reported
exactly as DAGR produces them; `arcs-verify` reports exactly what it
recomputes. A receipt verifying is **not** a claim that any real-world effect
occurred.

---

## Quickstart (copy-paste, stranger path)

Requirements: [`uv`](https://docs.astral.sh/uv/) and Python 3.12. No access
to any private repository is needed — `dagr-mcp` and `arcs-verify` are
vendored at their exact pinned commits in `vendor/` (see
[`VENDOR_PROVENANCE.md`](VENDOR_PROVENANCE.md)). Public PyPI packages are
fetched from PyPI as normal.

```bash
git clone https://github.com/thelaplage/dagr-quickstart
cd dagr-quickstart
./bootstrap.sh
.venv/bin/dagr-quickstart
```

`bootstrap.sh` builds two separate environments — one for the producer
(`dagr-mcp`) and one for the verifier (`arcs-verify`) — asserts their
reciprocal isolation, and exits. `dagr-quickstart` then runs the governed
action and prints a checklist.

Expected output:

```
dagr-quickstart — the minimal governed action
caller → ping/write_note → governed by dagr-mcp → signed SRS receipt → arcs-verify

  ✓ Read tool admitted by DAGR (ping)
  ✓ Signed receipts emitted (3 total: 2 admission, 1 outcome, 1 refused-admission)
  ✓ Verifier environment isolated (producer packages dagr_mcp / dagr_mcp_service undiscoverable)
  ✓ Receipts independently verified by arcs-verify, separate interpreter (3/3 genuine PASS, 3/3 mutations rejected)

  ✗ write_note — REFUSED (write-classed; policy_refused) [1 refused-admission receipt, body_ran=False]

RESULT: OK
```

---

## Setup detail

`bootstrap.sh` builds two environments to preserve reciprocal
producer/verifier separation (see [`ENV_POSTURE.md`](ENV_POSTURE.md) — this
is the separation the ecosystem proved it needs in `dagr-pack-filesystem@edad883`):

| Env | Contains | Must NOT contain |
|---|---|---|
| `.venv` (producer) | `dagr-quickstart`, `dagr-mcp` (pinned, non-editable, from `vendor/`) | `arcs_verify` |
| `.venv-verifier` | `arcs-verify` (non-editable, from `vendor/`) | `dagr_mcp` |

Both packages are installed from `vendor/` — byte-identical copies of their
pinned upstream commits. See [`VENDOR_PROVENANCE.md`](VENDOR_PROVENANCE.md)
for the full pin record (source repo, commit, sha256 of each archive).

Derived from
[`arcs-ecosystem-kit/RELEASE_MANIFEST_CANDIDATE_v0-1.yaml`](../arcs-ecosystem-kit/RELEASE_MANIFEST_CANDIDATE_v0-1.yaml)
(manifest_id: `arcs-ecosystem.release-manifest-candidate.v0.1`, status:
candidate). See [`UPSTREAM_PIN.yaml`](UPSTREAM_PIN.yaml) for the full pin
record and commit reconciliation notes.

## Test

```bash
.venv/bin/python -m pytest -v
```

- `test_vendor_integrity.py` — 13 tests that pass from a clean checkout with
  no private repo access. They verify the vendor trees are present and properly
  constituted; the import tests additionally require bootstrap to have been run.
- `test_governed_action.py` — 1 test that runs the full end-to-end governed
  action under reciprocal producer/verifier separation. Requires bootstrap.

Before this change (P0): 1 test (skipped without bootstrap).
After this change (P1 / W1): 14 tests (13 pass from clean checkout; 1
requires bootstrap + isolated verifier).

## Make it your integration

This repo is a **template**, not a product. To govern your own tool calls,
change three things in
[`dagr_quickstart/governed_action.py`](dagr_quickstart/governed_action.py)
and nothing else:

1. **The two tool bodies** (`ping`, `write_note`) — call your real system.
2. **`TOOL_CLASSES` and `_policy_resolver`** — declare which tools are
   `read`/`write` and your admission policy (admit / refuse / defer).
3. **The identity + boundary IDs** — name your issuer, runtime, and boundary.

Everything else — signing, receipt emission, and independent verification —
is the real ecosystem machinery and stays exactly as is.

## What is real vs demo-only

- **Real**: the FastMCP transport, `DAGRMiddleware`, `SignedReceiptEmitter`,
  the Ed25519 signing, the admission/outcome/refused-admission receipts, and
  the `arcs-verify` subprocess recomputation are all the actual ecosystem
  packages — nothing about the governance or verification is stubbed.
- **Demo-only**: the Ed25519 signing seed is a fixed, public, non-production
  value with no production validity, and the two tools are trivial
  placeholders.

## Layout

```
dagr_quickstart/
  governed_action.py   the whole wiring: middleware + emitter + one read + one write
  verify.py            the independent arcs-verify subprocess contract
  cli.py               the dagr-quickstart entrypoint (checklist + timer)
vendor/
  dagr-mcp/            dagr-mcp source at commit 2aebf54 (pinned, non-editable)
  arcs-verify/         arcs-verify source at commit e6d6eaca (pinned, non-editable)
VENDOR_PROVENANCE.md   source repo + commit + sha256 for each vendor tree
UPSTREAM_PIN.yaml      full pin record and commit reconciliation notes
tests/
bootstrap.sh
```
