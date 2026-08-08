# VENDOR_PROVENANCE.md — dagr-quickstart

Byte-identical source trees vendored from their exact pinned commits, enabling
`git clone dagr-quickstart && ./bootstrap.sh` to succeed with no access to any
private repository. Public PyPI dependencies (fastmcp, cryptography, etc.) are
fetched from PyPI as normal during bootstrap.

Provenance records source repo, commit, and sha256 of the `git archive` stream
used to populate each vendor directory. The vendor directories are the install
source for `bootstrap.sh`; the sha256s bind the installed bytes to the upstream
commit identity recorded in `UPSTREAM_PIN.yaml`.

---

## vendor/dagr-mcp

| Field | Value |
|---|---|
| Source repo | `dagr-mcp` |
| Remote | `https://github.com/thelaplage/dagr-mcp` |
| Pinned commit | `2aebf54bd4bc5609074de8fa12205c74378483e4` |
| Merged PR | #30 |
| Pin authority | `UPSTREAM_PIN.yaml#producer` |
| Archive sha256 | `5c75e6e8e810baacaeb7ddddec5298fcd5b2f896e4ecd47f77a349b93d735f3e` |

Archive scope: `pyproject.toml LICENSE MANIFEST.in dagr_mcp dagr_mcp_lifecycle dagr_mcp_sdk_binding dagr_mcp_service dagr_mcp_continuation`

The archived sha256 covers these paths only (excludes tests/, docs/, examples/, tools/, packages/).
The installed package behavior is identical to `pip install "git+https://github.com/thelaplage/dagr-mcp.git@2aebf54"`.

Consumed surface (from `UPSTREAM_PIN.yaml`):
- `dagr_mcp.fastmcp_binding`: `DAGRMiddleware`, `DAGRMiddlewareConfig`, `BindingPolicy`, `ActorResolution`
- `dagr_mcp.srs_receipts`: `SignedReceiptEmitter`, `SigningIdentity`, `RawEnvelopeFileSink`

---

## vendor/arcs-verify

| Field | Value |
|---|---|
| Source repo | `arcs-verify` |
| Remote | `https://github.com/thelaplage/arcs-verify` |
| Pinned commit | `e6d6eaca68b85428c1a8b7674a8cf4d6269952d6` |
| Merged PR | #14 |
| Pin authority | `UPSTREAM_PIN.yaml#verifier` |
| Archive sha256 | `fd02d0c10b20786643a0fedb114f6bc786e0bdad3d6b01dd454c8c2388d7a97c` |

Archive scope: `pyproject.toml LICENSE arcs_verify`

The archived sha256 covers these paths only (excludes tests/, docs/, packs/, tools/, vendor/).
The installed package behavior is identical to `pip install "git+https://github.com/thelaplage/arcs-verify.git@e6d6eaca"`.

---

## Verification

To recompute and verify the archive sha256 for either package (requires local
access to the source repos):

```bash
# dagr-mcp
cd /path/to/dagr-mcp
git archive 2aebf54bd4bc5609074de8fa12205c74378483e4 \
  pyproject.toml LICENSE MANIFEST.in \
  dagr_mcp dagr_mcp_lifecycle dagr_mcp_sdk_binding dagr_mcp_service dagr_mcp_continuation \
  | shasum -a 256

# arcs-verify
cd /path/to/arcs-verify
git archive e6d6eaca68b85428c1a8b7674a8cf4d6269952d6 \
  pyproject.toml LICENSE arcs_verify \
  | shasum -a 256
```

Expected outputs match the sha256 values above. `git archive` is deterministic
for the same tree, so the digest is reproducible from any clone that has the
named commit.
