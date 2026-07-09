# @correctover/ccs

**CCS v1.0 — Synchronous interceptor governance for AI Agent frameworks**

TypeScript implementation of the [Correctover Conformance Standard](https://correctover.com) (CCS) v1.0.

Provides structural **fail-closed** guarantee: if governance evaluation fails, the tool function is **NEVER** invoked. This eliminates the CWE-636 fail-open vulnerability inherent to observer-pattern hooks.

## Install

```bash
npm install @correctover/ccs
```

## Quick Start

```typescript
import { govern, GovernanceResult, getRuntime, CCSPolicy } from "@correctover/ccs";

// Wrap any function with governance
const searchWeb = (query: string) => fetch(`...`).then(r => r.text());
const governedSearch = govern(searchWeb, { policy: "default" });

governedSearch("test query"); // ✅ Allowed by default policy

// Custom policy
class BlockDeletePolicy implements CCSPolicy {
  evaluate(toolName: string, toolInput: Record<string, unknown>): GovernanceResult {
    if (toolName.includes("delete") || toolName.includes("rm")) {
      return GovernanceResult.DENY;
    }
    return GovernanceResult.ALLOW;
  }
}

const runtime = getRuntime();
runtime.registerPolicy("block_delete", new BlockDeletePolicy());

const governedDelete = govern(deleteFile, { policy: "block_delete" });
governedDelete("/etc/passwd"); // ❌ Throws PermissionError
```

## Fail-Closed Guarantee

```typescript
// If policy engine crashes, tool is STILL blocked
class CrashPolicy implements CCSPolicy {
  evaluate(): GovernanceResult {
    throw new Error("Policy engine failure!");
  }
}

runtime.registerPolicy("crash", new CrashPolicy());
const governed = govern(myTool, { policy: "crash" });

governed(args); // ❌ PermissionError — tool NEVER executes
```

This is the fundamental difference from observer-pattern hooks (which fail-open when the observer crashes).

## API

### `govern(fn, options?)`
Wraps a function with CCS governance. Returns a new function that evaluates governance before calling the original.

### `getRuntime(config?)`
Returns the global CCS runtime singleton.

### `CCSRuntime`
- `evaluate(toolName, toolInput, policyName?)` → `{ result, latencyUs }`
- `registerPolicy(name, policy)` → void
- `getStats()` → performance statistics

### `GovernanceResult`
Enum: `ALLOW` | `DENY` | `ERROR`

### `CCSPolicy` (interface)
```typescript
interface CCSPolicy {
  evaluate(toolName: string, toolInput: ToolInput): GovernanceResult;
}
```

## Performance

Benchmarked on Node.js v22 (10,000 evaluations):
- P50: ~75µs
- P99: ~150µs

Python SDK is faster (~6µs P50) due to lower decorator overhead.

## Standard Reference

- **Standard**: [CCS v1.0](https://github.com/Correctover/standards)
- **Paper**: DOI: [10.5281/zenodo.21271910](https://doi.org/10.5281/zenodo.21271910)
- **Python SDK**: [ccs-sdk](https://github.com/Correctover/ccs-sdk)

## License

CC BY 4.0 — © Correctover Standards
