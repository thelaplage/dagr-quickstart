# dagr-quickstart

Derived from [`arcs-ecosystem-kit/RELEASE_MANIFEST_CANDIDATE_v0-1.yaml`](../arcs-ecosystem-kit/RELEASE_MANIFEST_CANDIDATE_v0-1.yaml)
(manifest_id: `arcs-ecosystem.release-manifest-candidate.v0.1`, status: candidate).
Both producer and verifier are installed from their exact pinned git commits per
the manifest; see [`UPSTREAM_PIN.yaml`](UPSTREAM_PIN.yaml) for the full pin record.

**The smallest governed action, end to end — in one command.**

A caller invokes two MCP tools. One is `read`-classed and **admitted**; one is
`write`-classed and **refused**. Both cross the real `dagr-mcp` runtime boundary,
which emits **signed, metadata-only SRS receipts**. Each receipt is then
recomputed by **`arcs-verify`** running as an independent subprocess.

```
caller
  → ping (read)  ─┐
  → write_note (write) ─┤ governed by dagr-mcp (DAGRMiddleware + SignedReceiptEmitter)
                        ├─ ping        → admitted → signed admission + outcome receipts
                        └─ write_note  → refused  → signed refused-admission receipt (body never runs)
  → arcs-verify recomputes every receipt (separate process, bytes only)
```

Nothing here mints a verdict. Dispositions and receipt facts are reported exactly
as DAGR produces them; `arcs-verify` reports exactly what it recomputes. A receipt
verifying is **not** a claim that any real-world effect occurred.

## Setup (once)

Requires [`uv`](https://docs.astral.sh/uv/) and Python 3.12. Two **separate**
environments are built to keep the producer and verifier apart (see
[`ENV_POSTURE.md`](ENV_POSTURE.md) — this is the reciprocal separation the
ecosystem proved it needs in `dagr-pack-filesystem@edad883`):

| Env | Contains | Must NOT contain |
|---|---|---|
| `.venv` (producer) | `dagr-quickstart`, `dagr-mcp` (pinned, non-editable) | `arcs_verify` |
| `.venv-verifier` | `arcs-verify` (non-editable) | `dagr_mcp` |

`dagr-mcp` (commit `2aebf54`, PR#30) and `arcs-verify` (commit `e6d6eaca`, PR#14)
are both installed from their exact pinned git commits per the release manifest. See
[`UPSTREAM_PIN.yaml`](UPSTREAM_PIN.yaml) for the full pin record and commit reconciliation notes.

```bash
cd dagr-quickstart
./bootstrap.sh
```

`bootstrap.sh` builds both environments and **asserts the reciprocal exclusion**
(producer without `arcs_verify`, verifier without `dagr_mcp`) before you can run.

## Run

```bash
F1_VERIFIER_PYTHON=$PWD/.venv-verifier/bin/python .venv/bin/dagr-quickstart
```

(`F1_VERIFIER_PYTHON` defaults to `.venv-verifier` if unset.) You'll see a
checklist: the read admitted, the verifier environment confirmed isolated, every
receipt independently verified in a separate interpreter (genuine passes +
mutations rejected), then the enforced refusal of the write tool — plus elapsed
time.

## Test

```bash
.venv/bin/python -m pytest -q
```

The test SKIPS (rather than silently passing) if no isolated verifier
environment is present — the separation is the point.

## Make it your integration

This repo is a **template**, not a product. To govern your own tool calls, change
three things in [`dagr_quickstart/governed_action.py`](dagr_quickstart/governed_action.py)
and nothing else:

1. **The two tool bodies** (`ping`, `write_note`) — call your real system.
2. **`TOOL_CLASSES` and `_policy_resolver`** — declare which tools are
   `read`/`write` and your admission policy (admit / refuse / defer).
3. **The identity + boundary IDs** — name your issuer, runtime, and boundary.

Everything else — signing, receipt emission, and independent verification — is
the real ecosystem machinery and stays exactly as is.

## What is real vs demo-only

- **Real**: the FastMCP transport, `DAGRMiddleware`, `SignedReceiptEmitter`, the
  Ed25519 signing, the admission/outcome/refused-admission receipts, and the
  `arcs-verify` subprocess recomputation are all the actual ecosystem packages —
  nothing about the governance or verification is stubbed.
- **Demo-only**: the Ed25519 signing seed is a fixed, public, non-production
  value with no production validity, and the two tools are trivial placeholders.

## Layout

```
dagr_quickstart/
  governed_action.py   the whole wiring: middleware + emitter + one read + one write
  verify.py            the independent arcs-verify subprocess contract
  cli.py               the dagr-quickstart entrypoint (checklist + timer)
tests/
bootstrap.sh
```
