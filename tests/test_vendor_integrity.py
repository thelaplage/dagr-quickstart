"""Vendor integrity tests — runnable from a clean checkout, no private repo access needed.

These tests verify that the vendor/ trees committed to the repo are properly
constituted and that bootstrap.sh can satisfy its two install targets from them.
No network to any private repository is required for any test in this file.

The end-to-end governed-action test (test_governed_action.py) requires that
bootstrap.sh has already been run; these tests do not.
"""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
VENDOR_DAGR_MCP = REPO_ROOT / "vendor" / "dagr-mcp"
VENDOR_ARCS_VERIFY = REPO_ROOT / "vendor" / "arcs-verify"

DAGR_MCP_COMMIT = "2aebf54bd4bc5609074de8fa12205c74378483e4"
ARCS_VERIFY_COMMIT = "e6d6eaca68b85428c1a8b7674a8cf4d6269952d6"


# ---------------------------------------------------------------------------
# Vendor tree existence — these pass on any clean checkout of this repo.
# ---------------------------------------------------------------------------

def test_vendor_dagr_mcp_tree_exists():
    assert VENDOR_DAGR_MCP.is_dir(), (
        f"vendor/dagr-mcp missing — was the repo cloned completely? "
        f"Expected: {VENDOR_DAGR_MCP}"
    )


def test_vendor_arcs_verify_tree_exists():
    assert VENDOR_ARCS_VERIFY.is_dir(), (
        f"vendor/arcs-verify missing — was the repo cloned completely? "
        f"Expected: {VENDOR_ARCS_VERIFY}"
    )


def test_vendor_dagr_mcp_installable():
    """pyproject.toml must be present for pip/uv to install from the vendor tree."""
    assert (VENDOR_DAGR_MCP / "pyproject.toml").is_file()


def test_vendor_arcs_verify_installable():
    """pyproject.toml must be present for pip/uv to install from the vendor tree."""
    assert (VENDOR_ARCS_VERIFY / "pyproject.toml").is_file()


def test_vendor_dagr_mcp_consumed_surface():
    """The two modules the quickstart imports must be in the vendor tree."""
    assert (VENDOR_DAGR_MCP / "dagr_mcp" / "fastmcp_binding.py").is_file()
    assert (VENDOR_DAGR_MCP / "dagr_mcp" / "srs_receipts.py").is_file()


def test_vendor_arcs_verify_cli():
    """The verifier CLI entry point must be in the vendor tree."""
    assert (VENDOR_ARCS_VERIFY / "arcs_verify" / "cli.py").is_file()


def test_vendor_dagr_mcp_package_data():
    """SRS schema vendor files must be present (required at import time)."""
    srs_dir = VENDOR_DAGR_MCP / "dagr_mcp" / "vendor" / "srs"
    assert srs_dir.is_dir()
    schemas = list(srs_dir.glob("*.json"))
    assert schemas, "no .json schema files in vendor/dagr-mcp/dagr_mcp/vendor/srs/"


def test_vendor_provenance_doc_exists():
    assert (REPO_ROOT / "VENDOR_PROVENANCE.md").is_file()


def test_vendor_provenance_records_both_commits():
    text = (REPO_ROOT / "VENDOR_PROVENANCE.md").read_text(encoding="utf-8")
    assert DAGR_MCP_COMMIT in text, "VENDOR_PROVENANCE.md missing dagr-mcp commit"
    assert ARCS_VERIFY_COMMIT in text, "VENDOR_PROVENANCE.md missing arcs-verify commit"


# ---------------------------------------------------------------------------
# Runtime importability — these require bootstrap.sh to have been run but
# still require NO private repo network access.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("module", ["dagr_mcp", "dagr_mcp.fastmcp_binding", "dagr_mcp.srs_receipts"])
def test_dagr_mcp_importable(module):
    """dagr_mcp must be importable in the producer environment after bootstrap."""
    try:
        importlib.import_module(module)
    except ImportError as exc:
        pytest.skip(f"dagr_mcp not installed (bootstrap.sh not yet run?): {exc}")


def test_dagr_mcp_not_from_network():
    """Imported dagr_mcp must resolve from a local path, not a git+https cache."""
    try:
        import dagr_mcp
    except ImportError as exc:
        pytest.skip(f"dagr_mcp not installed: {exc}")
    pkg_file = Path(dagr_mcp.__file__).resolve()
    # Must NOT be under a uv/pip VCS cache (those contain the commit hash in the path)
    assert "github.com" not in str(pkg_file), (
        f"dagr_mcp appears to be installed from a git+https cache: {pkg_file}. "
        "Expected a local vendor or site-packages installation."
    )
