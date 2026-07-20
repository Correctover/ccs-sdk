# CCS — Correctover Conformance Standard

**AI Agent Runtime Assurance** — Synchronous interceptor-based governance + runtime security layer for AI Agent tool calls.

## Why CCS?

Every major Agent framework (CrewAI AGT, AutoGen, LangGraph) uses **observer-pattern hooks** for governance. These hooks are structurally vulnerable to **fail-open bypass** — when the governance layer throws an exception, the framework defaults to allowing tool execution.

**This is not a bug. It's an architectural flaw.** (CWE-636, CVSS 9.1)

CCS uses **function decorators** instead of hooks. The decorator owns the execution path — if governance fails, the tool is BLOCKED. Never allowed.

```
Observer hooks:  governance_crash → exception caught → hook_blocked=False → tool EXECUTES ❌
CCS decorators:  governance_crash → exception caught → tool NEVER CALLED ✅
```

## Installation

```bash
pip install correctover
```

## Quick Start — Governance (3 lines)

```python
from ccs import govern

@govern(policy="default")
def my_tool(args: dict) -> str:
    return "result"

# Governance evaluation happens BEFORE the function runs
# If denied → PermissionError, function never executes
```

## Quick Start — GuardrailProvider (v4.1.0)

Framework-agnostic runtime security layer for AI Agent tool calls:

```python
from ccs import (
    CKGGuardrailProvider,
    EnvProtectionProvider,
    CompositeGuardrailProvider,
    AuditTrail,
    make_guardrail_hook,
    ToolCallContext,
)

# Build a security policy: CKG auth + .env protection, AND composition
ckg = CKGGuardrailProvider("ckg")
env = EnvProtectionProvider("env-prot")
composite = CompositeGuardrailProvider("security", mode="AND", providers=[ckg, env])

# Audit trail with cryptographic chain
audit = AuditTrail()

# One-line integration — wrap any tool function
secured_tool = make_guardrail_hook(my_tool, composite, audit)

# Execute with full authorization + audit
ctx = ToolCallContext(tool_name="my_tool", arguments={"file": "data.txt"}, agent_id="agent-1", metadata={})
result = secured_tool(ctx)
```

### Built-in Guardrail Providers

| Provider | What it does | CVE Reference |
|----------|-------------|---------------|
| `CKGGuardrailProvider` | Constrained Knowledge Graph authorization (6 built-in predicates) | — |
| `EnvProtectionProvider` | Blocks `.env` file read/write at runtime | CVE-2026-12957 |
| `ToolListGuardrailProvider` | Whitelist/blacklist tool authorization | — |
| `CompositeGuardrailProvider` | AND/OR composition of multiple providers | — |
| `MCPSecurityValidator` | Pre-flight MCP config security scanning | CVE-2026-42271/12957/25536 |

### Decision Integrity

Every authorization decision is content-addressed (SHA-256) and independently verifiable:

```python
from ccs import GuardrailDecisionV1, compute_decision_id

decision = ckg.evaluate(ctx)
assert decision.verify_integrity()  # Recompute SHA-256, detect tampering
```

## Framework Adapters

Adapters intercept at the framework's tool execution entry point.
Once installed, ALL tool calls go through CCS governance.

### CrewAI
```python
from ccs.adapters import crewai_adapter
crewai_adapter.install()   # patches BaseTool.run globally
crewai_adapter.uninstall() # restore original
```

### AutoGen (async)
```python
from ccs.adapters import autogen_adapter
autogen_adapter.install()  # patches FunctionTool.run
autogen_adapter.uninstall()
```

### LangGraph / LangChain
```python
from ccs.adapters import langgraph_adapter
langgraph_adapter.install()  # patches LCBaseTool.run
langgraph_adapter.uninstall()
```

### Verified Against
| Framework | Version | Interception Point | Pattern |
|-----------|---------|--------------------|---------|
| CrewAI | >= 0.1.0 | `BaseTool.run()` | sync |
| AutoGen | >= 0.7.0 | `FunctionTool.run()` | async |
| LangGraph | >= 0.2.0 | `LCBaseTool.run()` | sync |

## Fail-Closed Guarantee

| | Observer Hooks (AGT) | CCS Decorators |
|---|---|---|
| Integration | Framework catches hook exception | Decorator owns execution path |
| On governance crash | `hook_blocked` stays `False` → tool executes | Exception propagates → tool never called |
| Fail mode | **FAIL-OPEN** ❌ | **FAIL-CLOSED** ✅ |
| CWE | CWE-636 (Not Failing Securely) | Structurally immune |

## Performance

CANON benchmark (50,000 traces):
- **P50 latency: 14.5µs** (GuardrailProvider evaluation)
- **P99 latency: 99µs**
- **Self-healing rate: 97.4%** (80,000+ test cases)

## MCP Security Scanner

Pre-flight scanning for MCP server configurations:

```python
from ccs import MCPSecurityValidator

validator = MCPSecurityValidator()
result = validator.scan_file("mcp-config.json")

if not result.safe:
    for finding in result.findings:
        print(f"[{finding.severity}] {finding.cve}: {finding.description}")
```

## TypeScript SDK

```bash
npm install correctover
```

```typescript
import { CKGGuardrailProvider, EnvProtectionProvider, makeGuardrailHook } from "correctover";

const ckg = new CKGGuardrailProvider("ckg");
const env = new EnvProtectionProvider("env-prot");
const secured = makeGuardrailHook(myTool, ckg);
```

Source: [`ts/`](./ts) | [npm package](https://www.npmjs.com/package/correctover)

## Go SDK

```bash
go get github.com/Correctover/ccs-sdk/go
```

```go
import "github.com/Correctover/ccs-sdk/go/ccs"

ckg := ccs.NewCKGGuardrailProvider("ckg")
env := ccs.NewEnvProtectionProvider("env-prot")
composite := ccs.NewCompositeGuardrailProvider("security", ccs.CompositeAND,
    []ccs.GuardrailProvider{ckg, env})

ctx := &ccs.ToolCallContext{ToolName: "my_tool", AgentID: "agent-1", Arguments: args}
decision := composite.Evaluate(ctx)
// decision.Action: "allow" or "deny"
// decision.VerifyIntegrity(): SHA-256 check
```

Source: [`go/`](./go)

## Repository Structure

```
ccs-sdk/
├── ccs/              # Python SDK
│   ├── core.py       # Governance runtime + decorators
│   ├── guardrail.py  # GuardrailProvider module (v4.1.0)
│   ├── adapters.py   # CrewAI/AutoGen/LangGraph adapters
│   └── mcp_server/   # MCP server (stdio transport)
├── ts/               # TypeScript SDK (npm: correctover)
│   └── src/          # core.ts + guardrail.ts + mcp_v2/
├── go/               # Go SDK
│   └── ccs/          # core.go + guardrail.go
├── docs/             # Documentation
├── strict_9test.py   # Python 9-test verification suite
└── pyproject.toml
```

## SDK Versions

| SDK | Version | Package |
|-----|---------|---------|
| Python | 4.1.0 | `pip install correctover` |
| TypeScript | 4.1.0 | `npm install correctover` |
| Go | 4.1.0 | `go get github.com/Correctover/ccs-sdk/go` |

## References

- CCS v1.0 Standard: https://doi.org/10.5281/zenodo.21271910
- CCS Whitepaper: https://doi.org/10.5281/zenodo.21405206
- CCS Standard: https://correctover.com/ccs
- CVE Audit (CWE-636 in AGT): https://gist.github.com/Correctover/9cfb97bcf374f79b793fd0bacd4e9d62
- crewAI PR #6597 (GuardrailProvider): https://github.com/crewAIInc/crewAI/pull/6597
- Correctover: https://correctover.com
