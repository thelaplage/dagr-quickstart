#!/usr/bin/env bash
# dagr-quickstart bootstrap — builds TWO isolated environments and proves their
# reciprocal separation, then leaves you a one-command demo.
#
#   .venv           PRODUCER: dagr-quickstart + dagr-mcp (pinned, non-editable).
#                   MUST NOT contain arcs-verify.
#   .venv-verifier  VERIFIER: arcs-verify (non-editable). MUST NOT contain dagr-mcp.
#
# This layout is the reciprocal producer/verifier separation the ecosystem
# proved in dagr-pack-filesystem@edad883. A subprocess call alone is NOT
# independence when both sides share one installed environment.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Pinned upstream bytes — see UPSTREAM_PIN.yaml.
# Both packages are installed from their exact pinned git commits per
# arcs-ecosystem-kit/RELEASE_MANIFEST_CANDIDATE_v0-1.yaml.
# dagr-mcp HEAD has since moved (it dropped the stdio connector); install ONLY
# from this pinned commit. arcs-verify is pinned at the canonical PR#14 review
# commit (see arcs-ecosystem-kit/docs/ARCS_VERIFY_PIN_REVIEW.yaml).
DAGR_MCP_PIN_URL="git+https://github.com/thelaplage/dagr-mcp.git@2aebf54bd4bc5609074de8fa12205c74378483e4"
ARCS_VERIFY_PIN_URL="git+https://github.com/thelaplage/arcs-verify.git@e6d6eaca68b85428c1a8b7674a8cf4d6269952d6"

command -v uv >/dev/null 2>&1 || { echo "ERROR: 'uv' required (https://docs.astral.sh/uv/)." >&2; exit 1; }

echo "==> [1/4] producer .venv: dagr-quickstart + dagr-mcp (pinned, NON-editable), no arcs-verify"
uv venv --python 3.12 "$HERE/.venv"
uv pip install --python "$HERE/.venv/bin/python" "$DAGR_MCP_PIN_URL" -e "$HERE[dev]"

echo "==> [2/4] assert producer isolation (arcs_verify NOT discoverable in .venv)"
"$HERE/.venv/bin/python" - <<'PY'
import importlib.util as u, sys
import dagr_mcp  # must import
assert u.find_spec("arcs_verify") is None, "FAIL: arcs_verify is discoverable in the producer venv"
print("  ok: dagr_mcp present, arcs_verify absent")
PY

echo "==> [3/4] verifier .venv-verifier: arcs-verify (NON-editable), no dagr-mcp"
uv venv --python 3.12 "$HERE/.venv-verifier"
uv pip install --python "$HERE/.venv-verifier/bin/python" "$ARCS_VERIFY_PIN_URL"

echo "==> [4/4] assert verifier isolation (dagr_mcp NOT discoverable; arcs_verify under own site-packages)"
"$HERE/.venv-verifier/bin/python" - <<'PY'
import importlib.util as u, os, sysconfig, arcs_verify
for n in ("dagr_mcp", "dagr_mcp_service"):
    assert u.find_spec(n) is None, f"FAIL: producer package {n} discoverable in verifier venv"
sp = os.path.realpath(sysconfig.get_paths()["purelib"])
f = os.path.realpath(arcs_verify.__file__)
assert os.path.commonpath([f, sp]) == sp, f"FAIL: arcs_verify not under own site-packages: {f}"
print("  ok: arcs_verify present + non-editable, dagr_mcp / dagr_mcp_service absent")
PY

echo
echo "Done. Reciprocal separation holds. Run the governed action:"
echo "  F1_VERIFIER_PYTHON=$HERE/.venv-verifier/bin/python $HERE/.venv/bin/dagr-quickstart"
echo "(F1_VERIFIER_PYTHON defaults to .venv-verifier if unset.)"
