package ccs

import (
	"fmt"
	"strings"
	"testing"
)

// ============================================================
// T1: Default policy allows valid input
// ============================================================
func TestAllow(t *testing.T) {
	ResetGlobalRuntime()
	rt := NewRuntime()

	callCount := 0
	fn := func(input ToolInput) (interface{}, error) {
		callCount++
		return "result", nil
	}

	governed := Govern(fn, "default", rt)
	result, err := governed(ToolInput{"query": "hello"})

	if err != nil {
		t.Fatalf("T1 FAIL: unexpected error: %v", err)
	}
	if result != "result" {
		t.Fatalf("T1 FAIL: expected 'result', got %v", result)
	}
	if callCount != 1 {
		t.Fatalf("T1 FAIL: expected callCount=1, got %d", callCount)
	}
	t.Log("T1 ALLOW: ✅")
}

// ============================================================
// T2: Deny policy blocks execution
// ============================================================
func TestDeny(t *testing.T) {
	ResetGlobalRuntime()
	rt := NewRuntime()

	denyPolicy := &alwaysDenyPolicy{}
	rt.RegisterPolicy("deny_all", denyPolicy)

	callCount := 0
	fn := func(input ToolInput) (interface{}, error) {
		callCount++
		return "should_not_reach", nil
	}

	governed := Govern(fn, "deny_all", rt)
	_, err := governed(ToolInput{"query": "test"})

	if err == nil {
		t.Fatal("T2 FAIL: expected PermissionError, got nil")
	}
	permErr, ok := err.(*PermissionError)
	if !ok {
		t.Fatalf("T2 FAIL: expected *PermissionError, got %T", err)
	}
	if callCount != 0 {
		t.Fatalf("T2 FAIL: tool executed when it should have been denied! callCount=%d", callCount)
	}
	if !strings.Contains(permErr.Error(), "DENIED") {
		t.Fatalf("T2 FAIL: error message doesn't contain DENIED: %s", permErr.Error())
	}
	t.Log("T2 DENY: ✅")
}

// ============================================================
// T3: Fail-closed — policy panics → tool NEVER called
// ============================================================
func TestFailClosed(t *testing.T) {
	ResetGlobalRuntime()
	rt := NewRuntime()

	crashPolicy := &crashPolicy{}
	rt.RegisterPolicy("crash", crashPolicy)

	callCount := 0
	fn := func(input ToolInput) (interface{}, error) {
		callCount++
		return "should_not_reach", nil
	}

	governed := Govern(fn, "crash", rt)
	_, err := governed(ToolInput{"query": "test"})

	if err == nil {
		t.Fatal("T3 FAIL: expected PermissionError after policy crash, got nil")
	}
	_, ok := err.(*PermissionError)
	if !ok {
		t.Fatalf("T3 FAIL: expected *PermissionError, got %T: %v", err, err)
	}
	if callCount != 0 {
		t.Fatalf("T3 FAIL: tool executed after policy crash! NOT fail-closed! callCount=%d", callCount)
	}
	t.Log("T3 FAIL-CLOSED: ✅")
}

// ============================================================
// T4: Runtime stats
// ============================================================
func TestStats(t *testing.T) {
	ResetGlobalRuntime()
	rt := NewRuntime()

	// Run some evaluations
	rt.Evaluate("tool_a", ToolInput{"x": 1})
	rt.Evaluate("tool_b", ToolInput{"y": 2})
	rt.Evaluate("tool_c", ToolInput{"z": 3})

	stats := rt.GetStats()

	if stats.TotalEvaluations != 3 {
		t.Fatalf("T4 FAIL: expected 3 evaluations, got %d", stats.TotalEvaluations)
	}
	if stats.TotalAllowed != 3 {
		t.Fatalf("T4 FAIL: expected 3 allowed, got %d", stats.TotalAllowed)
	}
	if stats.TotalDenied != 0 {
		t.Fatalf("T4 FAIL: expected 0 denied, got %d", stats.TotalDenied)
	}
	if stats.LatencyP50Us <= 0 {
		t.Fatalf("T4 FAIL: P50 should be > 0, got %f", stats.LatencyP50Us)
	}
	t.Logf("T4 STATS: ✅ (evals=%d, allowed=%d, p50=%.1fµs)",
		stats.TotalEvaluations, stats.TotalAllowed, stats.LatencyP50Us)
}

// ============================================================
// T5: Traces audit log
// ============================================================
func TestTraces(t *testing.T) {
	ResetGlobalRuntime()
	rt := NewRuntime()

	rt.Evaluate("tool_x", ToolInput{"a": "b"})
	rt.Evaluate("tool_y", ToolInput{"c": "d"})

	traces := rt.Traces()
	if len(traces) != 2 {
		t.Fatalf("T5 FAIL: expected 2 traces, got %d", len(traces))
	}
	if traces[0].ToolName != "tool_x" {
		t.Fatalf("T5 FAIL: expected first trace tool_x, got %s", traces[0].ToolName)
	}
	if traces[1].ToolName != "tool_y" {
		t.Fatalf("T5 FAIL: expected second trace tool_y, got %s", traces[1].ToolName)
	}
	t.Log("T5 TRACES: ✅")
}

// ============================================================
// T6: Input size limit enforcement
// ============================================================
func TestInputSizeLimit(t *testing.T) {
	ResetGlobalRuntime()
	cfg := DefaultConfig()
	cfg.MaxInputSize = 100 // Very small limit
	rt := NewRuntime(cfg)

	bigInput := ToolInput{"data": strings.Repeat("x", 200)}
	result := rt.Evaluate("big_tool", bigInput)

	if result.Result != ResultDeny {
		t.Fatalf("T6 FAIL: expected DENY for oversized input, got %s", result.Result)
	}
	t.Log("T6 INPUT SIZE LIMIT: ✅")
}

// ============================================================
// T7: Global runtime singleton
// ============================================================
func TestGlobalRuntime(t *testing.T) {
	ResetGlobalRuntime()

	rt1 := GetGlobalRuntime()
	rt2 := GetGlobalRuntime()

	if rt1 != rt2 {
		t.Fatal("T7 FAIL: global runtime is not a singleton")
	}
	t.Log("T7 GLOBAL SINGLETON: ✅")
}

// ============================================================
// T8: Custom policy with pattern matching
// ============================================================
func TestCustomPolicy(t *testing.T) {
	ResetGlobalRuntime()
	rt := NewRuntime()

	blockPolicy := &blockPatternPolicy{patterns: []string{"delete", "rm", "destroy"}}
	rt.RegisterPolicy("block_dangerous", blockPolicy)

	// Should allow safe tool
	r1 := rt.Evaluate("search_web", ToolInput{"query": "hello"}, "block_dangerous")
	if r1.Result != ResultAllow {
		t.Fatalf("T8 FAIL: expected ALLOW for safe tool, got %s", r1.Result)
	}

	// Should block dangerous tool
	r2 := rt.Evaluate("delete_file", ToolInput{"path": "/etc/passwd"}, "block_dangerous")
	if r2.Result != ResultDeny {
		t.Fatalf("T8 FAIL: expected DENY for delete_file, got %s", r2.Result)
	}

	// Should block tool with dangerous input
	r3 := rt.Evaluate("run_command", ToolInput{"cmd": "rm -rf /"}, "block_dangerous")
	if r3.Result != ResultDeny {
		t.Fatalf("T8 FAIL: expected DENY for rm input, got %s", r3.Result)
	}

	t.Log("T8 CUSTOM POLICY: ✅")
}

// ============================================================
// T9: Concurrent evaluation safety
// ============================================================
func TestConcurrentSafety(t *testing.T) {
	ResetGlobalRuntime()
	rt := NewRuntime()

	done := make(chan bool, 100)
	for i := 0; i < 100; i++ {
		go func(n int) {
			toolName := fmt.Sprintf("tool_%d", n)
			rt.Evaluate(toolName, ToolInput{"n": n})
			done <- true
		}(i)
	}

	for i := 0; i < 100; i++ {
		<-done
	}

	stats := rt.GetStats()
	if stats.TotalEvaluations != 100 {
		t.Fatalf("T9 FAIL: expected 100 evaluations, got %d", stats.TotalEvaluations)
	}
	t.Logf("T9 CONCURRENT: ✅ (100 goroutines, %d evaluations)", stats.TotalEvaluations)
}

// ============================================================
// Test helpers
// ============================================================

type alwaysDenyPolicy struct{}

func (p *alwaysDenyPolicy) Evaluate(toolName string, toolInput ToolInput) GovernanceResult {
	return ResultDeny
}

type crashPolicy struct{}

func (p *crashPolicy) Evaluate(toolName string, toolInput ToolInput) GovernanceResult {
	panic("policy engine crashed!")
}

type blockPatternPolicy struct {
	patterns []string
}

func (p *blockPatternPolicy) Evaluate(toolName string, toolInput ToolInput) GovernanceResult {
	for _, pattern := range p.patterns {
		if strings.Contains(strings.ToLower(toolName), pattern) {
			return ResultDeny
		}
		// Also check input values
		for _, v := range toolInput {
			if s, ok := v.(string); ok {
				if strings.Contains(strings.ToLower(s), pattern) {
					return ResultDeny
				}
			}
		}
	}
	return ResultAllow
}
