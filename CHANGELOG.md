# Changelog

All notable changes to the CCS SDK are documented in this file.

## [4.1.0] - 2026-07-20

### Added
- **GuardrailProvider module** — Framework-agnostic runtime security layer for AI Agent tool calls
  - `GuardrailDecisionV1` — Content-addressed authorization decision with SHA-256 integrity verification
  - `ActionEnvelopeV1` — Separated action envelope for clean decision/action decoupling
  - `ToolCallContext` — Framework-agnostic tool call context (replaces framework-specific types)
  - `AllowAllGuardrailProvider` / `DenyAllGuardrailProvider` — Basic allow/deny policies
  - `ToolListGuardrailProvider` — Whitelist/blacklist tool authorization
  - `CKGGuardrailProvider` — Constrained Knowledge Graph authorization with 6 built-in predicates
  - `EnvProtectionProvider` — Runtime .env file access protection (CVE-2026-12957)
  - `CompositeGuardrailProvider` — AND/OR composition of multiple security providers
  - `AuditTrail` — Cryptographic audit chain for all authorization decisions
  - `make_guardrail_hook()` — One-line integration helper for any framework
  - `detect_missing_guardrail()` — Detect tools without guardrail coverage
  - `MCPSecurityValidator` — Pre-flight MCP config security scanning (CVE-2026-42271/12957/25536)
- Go SDK: `guardrail.go` — Full GuardrailProvider implementation
- TypeScript SDK: `guardrail.ts` — Full GuardrailProvider implementation

### Changed
- Python SDK: Added guardrail module exports to `ccs/__init__.py`
- Bumped version to v4.1.0 across all SDKs (Python, Go, TypeScript)

$CURRENT_CHANGELOG
