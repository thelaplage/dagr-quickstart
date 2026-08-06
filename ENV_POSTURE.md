# ENV_POSTURE.md — dagr-quickstart reciprocal separation

This quickstart deliberately runs the **producer/emitter** and the **verifier**
in two separate installed environments. This is the property the ecosystem
proved it needs in `dagr-pack-filesystem@edad883`: a subprocess call to the
verifier is *not* independence if the verifier package sits in the producer's
own environment, or if the producer's tests can import it.

## Two environments

| Env | Path | Contains | Must NOT contain |
|---|---|---|---|
| Producer | `.venv` | `dagr-quickstart`, `dagr-mcp` (pinned, non-editable) | `arcs_verify` |
| Verifier | `.venv-verifier` | `arcs-verify` (non-editable) | `dagr_mcp`, `dagr_mcp_service` |

`bootstrap.sh` builds both and asserts each exclusion before you can run.

## How verification crosses the boundary

The producer never imports `arcs_verify`. Instead
[`dagr_quickstart/verify.py`](dagr_quickstart/verify.py) runs
[`scripts/verify_receipts.py`](scripts/verify_receipts.py) under the verifier
interpreter named by `F1_VERIFIER_PYTHON` (default: `.venv-verifier/bin/python`).
Only serialized artifacts cross the boundary — the emitted receipt files and the
trust bundle. Nothing else.

The producer-side helper fails **closed**: if the verifier interpreter is
missing, not executable, cannot import `arcs_verify` from its *own*
site-packages, or still has a producer package discoverable, verification raises
rather than reporting success.

`scripts/verify_receipts.py`, running inside the verifier interpreter,
independently re-checks that no producer module is discoverable or loaded before
it imports `arcs_verify`, and records that fact in its machine report.

## What this establishes — and what it does not

- **Establishes:** the producer environment does not carry the verifier; the
  verifier environment does not carry the producer; verification runs under a
  distinct interpreter over serialized bytes only; a single-field mutation to any
  receipt is rejected.
- **Does not establish:** a real third-party transport integration, persistence
  or restart behavior, containment of a real upstream server, a public
  Counterpedia projection, or that any real-world event occurred. Those are the
  jobs of a real integration proof pack, not of this harness.
