# CCS — Correctover Conformance Standard v1.0

Synchronous interceptor-based governance for AI Agent frameworks.

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
pip install ccs
```

## Quick Start (3 lines)

```python
from ccs import govern

@govern(policy="default")
def my_tool(args: dict) -> str:
    return "result"

# Governance evaluation happens BEFORE the function runs
# If denied → PermissionError, function never executes
```

## Framework Adapters

Adapters intercept at the framework's tool execution entry point.
Once installed, ALL tool calls go through CCS governance.

### CrewAI
```python
from ccs.adapters import crewai_adapter
crewai_adapter.install()   # patches BaseTool.run globally
# All CrewAI tool calls now governed by CCS
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

## Custom Policies

```python
from ccs import CCSPolicy, GovernanceResult, govern

class CompliancePolicy(CCSPolicy):
    def evaluate(self, tool_name: str, tool_input: dict) -> GovernanceResult:
        if "delete" in tool_name.lower():
            return GovernanceResult.DENY
        return GovernanceResult.ALLOW

from ccs.core import get_runtime
runtime = get_runtime()
runtime.register_policy("compliance", CompliancePolicy())

@govern(policy="compliance")
def delete_user(user_id: str):
    ...  # This will never execute — policy denies it
```

## Fail-Closed Guarantee

The fundamental difference from observer-pattern hooks:

| | Observer Hooks (AGT) | CCS Decorators |
|---|---|---|
| Integration | Framework catches hook exception | Decorator owns execution path |
| On governance crash | `hook_blocked` stays `False` → tool executes | Exception propagates → tool never called |
| Fail mode | **FAIL-OPEN** ❌ | **FAIL-CLOSED** ✅ |
| CWE | CWE-636 (Not Failing Securely) | Structurally immune |

## Performance

CANON benchmark (50,000 traces):
- **P50 latency: 22µs**
- **P99 latency: 99µs**

## Test Results

Verified on 2026-07-09 with real framework installations:

```
CrewAI Adapter:   BaseTool.run intercepted → fail-closed ✅
AutoGen Adapter:  FunctionTool.run intercepted → fail-closed ✅
LangGraph Adapter: LCBaseTool.run intercepted → fail-closed ✅
All adapters support install/uninstall lifecycle ✅
```

Performance (10,000 iterations, decorator + policy evaluation):
```
P50:  6.2µs
P99:  15.0µs
P999: 53.0µs
```

## MCP Server

CCS is available as a [Model Context Protocol](https://modelcontextprotocol.io) server, enabling any MCP-compatible agent (Claude Desktop, Cursor, Cline) to validate tool calls against CCS governance.

```bash
pip install ccs[mcp]
python -m ccs.mcp_server
```

Configure in Claude Desktop:
```json
{
  "mcpServers": {
    "ccs": {
      "command": "python",
      "args": ["-m", "ccs.mcp_server"]
    }
  }
}
```

### MCP Tools
| Tool | Description |
|------|-------------|
| `ccs_govern` | Evaluate a tool call against a policy → allow/deny |
| `ccs_status` | Runtime stats, policies, latency metrics |
| `ccs_register_deny_rule` | Register custom deny rules by tool name/pattern |
| `ccs_audit_log` | Recent governance audit traces |

## TypeScript SDK

```bash
npm install correctover-ccs
```

```typescript
import { govern, GovernanceResult, CCSPolicy } from "correctover-ccs";

const governedSearch = govern(searchWeb, { policy: "default" });
governedSearch({ query: "test" }); // Throws PermissionError if denied
```

Source: [`ts/`](./ts) | [npm package](https://www.npmjs.com/package/correctover-ccs)

## Go SDK

```bash
go get github.com/Correctover/ccs-sdk/go
```

```go
rt := ccs.NewRuntime()
governed := ccs.Govern(searchFn, "default", rt)
result, err := governed(ccs.ToolInput{"query": "CCS standard"})
// err = *PermissionError if denied — fn NEVER called
```

Source: [`go/`](./go)

## Repository Structure

```
ccs-sdk/
├── ccs/              # Python SDK (core + adapters + MCP server)
│   ├── core.py       # Governance runtime
│   ├── adapters.py   # CrewAI/AutoGen/LangGraph adapters
│   └── mcp_server/   # MCP server (stdio transport)
├── ts/               # TypeScript SDK (npm: correctover-ccs)
│   ├── src/          # Source
│   └── dist/         # Built output
├── go/               # Go SDK
│   └── ccs/          # Core package
├── strict_9test.py   # Python 9-test verification suite
└── pyproject.toml
```

## SDK Versions

| SDK | Version | Package |
|-----|---------|---------|
| Python | 1.0.0 | `pip install ccs` |
| TypeScript | 1.0.0 | `npm install correctover-ccs` |
| Go | 1.0.0 | `go get github.com/Correctover/ccs-sdk/go` |

## References

- CCS v1.0 Standard: https://doi.org/10.5281/zenodo.21271910
- CVE Audit (CWE-636 in AGT): https://gist.github.com/Correctover/9cfb97bcf374f79b793fd0bacd4e9d62
- Correctover: https://correctover.com
