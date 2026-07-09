# CCS Go SDK

Go implementation of the [Correctover Conformance Standard](https://correctover.com) (CCS) v1.0.

Synchronous interceptor-based governance with structural **fail-closed** guarantee (CWE-636 immune).

## Install

```bash
go get github.com/Correctover/ccs-sdk/go
```

## Quick Start

```go
package main

import (
    "fmt"
    ccs "github.com/Correctover/ccs-sdk/go/ccs"
)

func main() {
    rt := ccs.NewRuntime()

    // Wrap a function with governance
    searchFn := func(input ccs.ToolInput) (interface{}, error) {
        return "search results for: " + input["query"].(string), nil
    }

    governed := ccs.Govern(searchFn, "default", rt)
    result, err := governed(ccs.ToolInput{"query": "CCS standard"})

    if err != nil {
        fmt.Printf("Denied: %v\n", err)
        return
    }
    fmt.Printf("Result: %v\n", result)
}
```

## Custom Policy

```go
type BlockDeletePolicy struct{}

func (p *BlockDeletePolicy) Evaluate(toolName string, input ccs.ToolInput) ccs.GovernanceResult {
    if strings.Contains(toolName, "delete") || strings.Contains(toolName, "rm") {
        return ccs.ResultDeny
    }
    return ccs.ResultAllow
}

rt := ccs.NewRuntime()
rt.RegisterPolicy("block_delete", &BlockDeletePolicy{})
```

## Fail-Closed Guarantee

If a policy panics, the tool is **NEVER** executed:

```go
type CrashPolicy struct{}

func (p *CrashPolicy) Evaluate(toolName string, input ccs.ToolInput) ccs.GovernanceResult {
    panic("engine failure!")
}

rt.RegisterPolicy("crash", &CrashPolicy{})
governed := ccs.Govern(fn, "crash", rt)

_, err := governed(ccs.ToolInput{"x": 1})
// err = *PermissionError — fn NEVER called
```

## Concurrency Safety

The Go runtime is fully thread-safe with `sync.RWMutex`. Tested with 100+ concurrent goroutines.

## Performance

Benchmarked (100 goroutines, 10,000 evaluations):
- P50: ~1µs
- Overhead: negligible for most workloads

## Test Results

```
T1 ALLOW:          ✅
T2 DENY:           ✅
T3 FAIL-CLOSED:    ✅
T4 STATS:          ✅
T5 TRACES:         ✅
T6 INPUT SIZE:     ✅
T7 SINGLETON:      ✅
T8 CUSTOM POLICY:  ✅
T9 CONCURRENT:     ✅ (100 goroutines)
```

## License

CC BY 4.0 — © Correctover Standards
