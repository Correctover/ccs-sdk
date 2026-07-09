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

### CrewAI
```python
from ccs.adapters import crewai_adapter
crewai_adapter.install(agent)
```

### AutoGen
```python
from ccs.adapters import autogen_adapter
autogen_adapter.install(conversable_agent)
```

### LangGraph
```python
from ccs.adapters import langgraph_adapter
langgraph_adapter.install(tool_node)
```

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

## References

- CCS v1.0 Standard: https://doi.org/10.5281/zenodo.21271910
- CVE Audit (CWE-636 in AGT): https://gist.github.com/Correctover/9cfb97bcf374f79b793fd0bacd4e9d62
- Correctover: https://correctover.com
