# Changelog

All notable changes to the CCS SDK are documented in this file.

## [4.0.0] - 2026-07-12

### Added
- `async_govern` decorator for async framework governance (LangGraph, AutoGen async)
- `generator_govern` decorator for streaming generator governance (token-level intercept)
- Go SDK reference implementation (`go/ccs/`)
- TypeScript SDK reference implementation (`ts/`)
- MCP Server with 4 tools: `ccs_govern`, `ccs_status`, `ccs_register_deny_rule`, `ccs_audit_log`
- Framework adapters: CrewAI, AutoGen, LangGraph

### Changed
- Unified version numbering to 4.0.0 across all SDKs: Python, Go, TypeScript, npm
- License unified to MIT across all components
- Removed node_modules from git tracking (150+ files)
- Updated .gitignore rules

### Fixed
- License inconsistency between LICENSE file (MIT) and pyproject.toml (CC BY 4.0)
- CHANGELOG version references aligned to 4.0.0

## [3.0.0] - 2026-07-09

### Added
- Performance benchmark documentation (P50=22us, P99=99us verified)
- `strict_9test.py` — 9-point acceptance verification suite
- `test_async_generator.py` — async + generator governance tests
- OpenTimestamps proof for CCS standard paper (Bitcoin blockchain)

### Changed
- Package renamed to `correctover-ccs` on PyPI (ccs was occupied)
- npm package published as `correctover-ccs`

## [1.0.0] - 2026-07-07

### Added
- Initial CCS v1.0 SDK release
- `govern` synchronous decorator with fail-closed guarantee
- `CCSConfig` for timeout, audit logging, policy configuration
- `CCSPolicy` base class for custom governance rules
- `GovernanceTrace` immutable audit trail
- Default policy with structural deny rules
- Framework adapter pattern for CrewAI, AutoGen, LangGraph
- DOI: 10.5281/zenodo.21271910
