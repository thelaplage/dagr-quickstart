"""Producer-side helper to invoke the SEPARATE verifier interpreter.

Reciprocal producer/verifier separation (mirrors dagr-pack-filesystem F1): the
producer process must NOT import ``arcs_verify`` in-process, and the producer
environment must not even make it discoverable. Independent verification is
performed by running ``scripts/verify_receipts.py`` under a distinct interpreter
named by ``F1_VERIFIER_PYTHON`` (falling back to this repo's ``.venv-verifier``).

These helpers fail CLOSED: if the verifier interpreter is missing, not
executable, cannot import ``arcs_verify`` from its OWN site-packages, or still
has the producer packages discoverable, verification raises rather than passing.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_VERIFY_RECEIPTS = _REPO_ROOT / "scripts" / "verify_receipts.py"
_DEFAULT_VERIFIER = _REPO_ROOT / ".venv-verifier" / "bin" / "python"

PRODUCER_PACKAGES = ("dagr_mcp", "dagr_mcp_service")


def verifier_python() -> str:
    """Return the validated, isolated verifier interpreter path, or fail closed."""
    p = (os.environ.get("F1_VERIFIER_PYTHON", "").strip()
         or (str(_DEFAULT_VERIFIER) if _DEFAULT_VERIFIER.exists() else ""))
    if not p:
        raise AssertionError(
            "No verifier interpreter. Set F1_VERIFIER_PYTHON to a separate venv's "
            "python, or run ./bootstrap.sh to build .venv-verifier. Independent "
            "verification requires an interpreter that is NOT the producer's."
        )
    if not (os.path.isfile(p) and os.access(p, os.X_OK)):
        raise AssertionError(f"F1_VERIFIER_PYTHON is not an executable interpreter: {p!r}")

    # arcs_verify must resolve under the verifier's OWN site-packages (not an
    # editable source checkout, worktree, or the producer environment).
    probe = (
        "import json, os, sysconfig, arcs_verify\n"
        "sp = os.path.realpath(sysconfig.get_paths()['purelib'])\n"
        "f = os.path.realpath(arcs_verify.__file__)\n"
        "print(json.dumps({'under': os.path.commonpath([f, sp]) == sp, 'file': f}))\n"
    )
    out = subprocess.run([p, "-c", probe], capture_output=True, text=True)
    if out.returncode != 0:
        raise AssertionError(f"verifier interpreter {p!r} cannot import arcs_verify: {out.stderr.strip()}")
    info = json.loads(out.stdout)
    if not info["under"]:
        raise AssertionError(f"verifier arcs_verify is not under its own site-packages: {info}")
    return p


def assert_producers_absent_in_verifier() -> dict:
    """Fail unless both producer packages are undiscoverable in the verifier."""
    p = verifier_python()
    probe = (
        "import importlib.util as u, json\n"
        f"print(json.dumps({{n: (u.find_spec(n) is not None) for n in {PRODUCER_PACKAGES!r}}}))\n"
    )
    out = subprocess.run([p, "-c", probe], capture_output=True, text=True)
    if out.returncode != 0:
        raise AssertionError(out.stderr)
    discoverable = json.loads(out.stdout)
    if any(discoverable.values()):
        raise AssertionError(f"producer packages discoverable in verifier environment: {discoverable}")
    return discoverable


def run_verifier(receipts_dir: Path, bundle_path: Path, report_path: Path) -> dict:
    """Run ``scripts/verify_receipts.py`` under the separate verifier interpreter."""
    p = verifier_python()
    cmd = [
        p, str(_VERIFY_RECEIPTS), str(receipts_dir),
        "--bundle", str(bundle_path), "--report", str(report_path),
    ]
    out = subprocess.run(cmd, capture_output=True, text=True)
    if not out.stdout.strip():
        raise RuntimeError(
            f"verifier produced no output (exit {out.returncode}): {out.stderr.strip()}"
        )
    report = json.loads(out.stdout)
    report["exit_code"] = out.returncode
    return report
