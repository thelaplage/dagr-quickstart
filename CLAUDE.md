# CLAUDE.md
> Status: agent guidance only; non-normative. Repository contracts, cited authorities, and admitted artifacts control where they differ.

## Repository lifecycle
ACTIVE

## Ecosystem rule
One authority per contract family. If another repository owns a contract, profile, schema, verifier, semantic rule, or custody invariant, consume or pin that authority. Do not recreate a convenient local dialect.

## Cross-repository evidence rule
A green local test suite does not prove interoperability. Where this repository consumes another repository's artifact, tests should use literal output from the real producer at a pinned commit whenever practical, preserving original bytes and provenance.

## Repository role
dagr-quickstart is a clean-stranger acceptance surface: it demonstrates a governed-action integration installable from vendored, exactly-pinned producer/verifier artifacts. It proves integration; it is not contract authority.

## Authority boundary
AUTHORITATIVE FOR:
- Its own install/acceptance demonstration
NOT AUTHORITATIVE FOR:
- Any contract, profile, verifier, or custody semantic (their owner repos)

## Critical invariants
- vendored producer/verifier pins stay EXACT
- producer and verifier remain in ISOLATED environments/processes (reciprocal import absence asserted)
- clean-stranger install is the acceptance test; drift from pins is an error

## Repository-specific red lines
- Do NOT become another authority; it demonstrates SUPPORTED artifacts only.
- Do NOT relax producer/verifier isolation to simplify the demo.
- Import firewall/public-safety gates; do not weaken them.

## Required validation
- clean-environment install + acceptance run green ; isolation assertions green

## Related repositories
- arcs-srs / arcs-verify / dagr-mcp — the pinned producers/verifier it vendors
- garp-ops / garp-corpus-firewall — public-safety gating
