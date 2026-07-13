// Package ccs implements the Correctover Conformance Standard (CCS) v1.0
// for Go. It provides synchronous interceptor-based governance with
// structural fail-closed guarantee.
//
// Reference: CCS v1.0 Standard, Section 3 — Formal Framework
//
//	DOI: 10.5281/zenodo.21271910
package ccs

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Version constants
const (
	Version  = "4.0.1"
	Standard = "CCS v1.0"
	DOI      = "10.5281/zenodo.21271910"
)

// GovernanceResult represents the outcome of a governance evaluation.
type GovernanceResult int

const (
	ResultAllow GovernanceResult = iota
	ResultDeny
	ResultError
)

func (r GovernanceResult) String() string {
	switch r {
	case ResultAllow:
		return "allow"
	case ResultDeny:
		return "deny"
	case ResultError:
		return "error"
	default:
		return "unknown"
	}
}

// Config holds CCS runtime configuration.
type Config struct {
	PolicyName     string
	MaxInputSize   int           // bytes, default 1MB
	Timeout        time.Duration // governance evaluation timeout
	AuditLog       bool
	TargetP50Us    float64
	TargetP99Us    float64
}

// DefaultConfig returns the default CCS configuration.
func DefaultConfig() Config {
	return Config{
		PolicyName:   "default",
		MaxInputSize: 1_000_000,
		Timeout:      50 * time.Millisecond,
		AuditLog:     true,
		TargetP50Us:  22.0,
		TargetP99Us:  99.0,
	}
}

// ToolInput represents the input to a tool call.
type ToolInput = map[string]interface{}

// Policy defines the interface for CCS governance policies.
type Policy interface {
	Evaluate(toolName string, toolInput ToolInput) GovernanceResult
}

// GovernanceTrace is an immutable audit record for a single governance decision.
type GovernanceTrace struct {
	Timestamp     time.Time
	ToolName      string
	InputHash     string
	Result        GovernanceResult
	LatencyUs     float64
	PolicyName    string
	RuleEvaluated string
	Detail        string
}

// EvaluateResult holds the outcome of a governance evaluation.
type EvaluateResult struct {
	Result    GovernanceResult
	LatencyUs float64
}

// DefaultPolicy validates input structure and size.
type DefaultPolicy struct {
	config Config
}

func NewDefaultPolicy(config Config) *DefaultPolicy {
	return &DefaultPolicy{config: config}
}

func (p *DefaultPolicy) Evaluate(toolName string, toolInput ToolInput) GovernanceResult {
	// Size check
	serialized, err := json.Marshal(toolInput)
	if err != nil {
		return ResultDeny
	}
	if len(serialized) > p.config.MaxInputSize {
		return ResultDeny
	}

	// Type check (must be a map)
	if toolInput == nil {
		return ResultDeny
	}

	return ResultAllow
}

// Runtime is the CCS governance engine.
type Runtime struct {
	mu       sync.RWMutex
	config   Config
	policies map[string]Policy
	traces   []GovernanceTrace
	latencies []float64
}

// NewRuntime creates a new CCS runtime with the given configuration.
func NewRuntime(config ...Config) *Runtime {
	cfg := DefaultConfig()
	if len(config) > 0 {
		cfg = config[0]
	}

	r := &Runtime{
		config:    cfg,
		policies:  make(map[string]Policy),
		traces:    make([]GovernanceTrace, 0),
		latencies: make([]float64, 0),
	}
	r.policies["default"] = NewDefaultPolicy(cfg)
	return r
}

// RegisterPolicy registers a named governance policy.
func (r *Runtime) RegisterPolicy(name string, policy Policy) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.policies[name] = policy
}

// Evaluate synchronously evaluates a tool call against the named policy.
// This method NEVER panics — any exception is caught and converted to ResultDeny.
func (r *Runtime) Evaluate(toolName string, toolInput ToolInput, policyName ...string) EvaluateResult {
	pName := "default"
	if len(policyName) > 0 && policyName[0] != "" {
		pName = policyName[0]
	}

	start := time.Now()
	var result GovernanceResult
	var detail string

	func() {
		defer func() {
			if rec := recover(); rec != nil {
				result = ResultDeny
				detail = fmt.Sprintf("Panic caught, fail-closed: %v", rec)
			}
		}()

		r.mu.RLock()
		policy, ok := r.policies[pName]
		r.mu.RUnlock()

		if !ok {
			result = ResultDeny
			detail = fmt.Sprintf("Unknown policy: %s", pName)
			return
		}

		result = policy.Evaluate(toolName, toolInput)
		detail = fmt.Sprintf("Policy '%s' evaluated", pName)
	}()

	latencyUs := float64(time.Since(start).Microseconds())
	r.mu.Lock()
	r.latencies = append(r.latencies, latencyUs)

	// Compute input hash
	inputHash := computeHash(toolInput)

	if r.config.AuditLog {
		r.traces = append(r.traces, GovernanceTrace{
			Timestamp:     time.Now(),
			ToolName:      toolName,
			InputHash:     inputHash,
			Result:        result,
			LatencyUs:     latencyUs,
			PolicyName:    pName,
			RuleEvaluated: pName,
			Detail:        detail,
		})
	}
	r.mu.Unlock()

	return EvaluateResult{Result: result, LatencyUs: latencyUs}
}

// Traces returns all governance audit traces.
func (r *Runtime) Traces() []GovernanceTrace {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]GovernanceTrace, len(r.traces))
	copy(out, r.traces)
	return out
}

// Stats holds runtime performance statistics.
type Stats struct {
	TotalEvaluations int      `json:"total_evaluations"`
	TotalDenied      int      `json:"total_denied"`
	TotalAllowed     int      `json:"total_allowed"`
	LatencyP50Us     float64  `json:"latency_p50_us"`
	LatencyP99Us     float64  `json:"latency_p99_us"`
	LatencyMaxUs     float64  `json:"latency_max_us"`
	RegisteredPolicies []string `json:"registered_policies"`
}

// GetStats returns runtime performance statistics.
func (r *Runtime) GetStats() Stats {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if len(r.latencies) == 0 {
		policies := make([]string, 0, len(r.policies))
		for k := range r.policies {
			policies = append(policies, k)
		}
		return Stats{RegisteredPolicies: policies}
	}

	sorted := make([]float64, len(r.latencies))
	copy(sorted, r.latencies)
	sort.Float64s(sorted)
	n := len(sorted)

	denied := 0
	allowed := 0
	for _, t := range r.traces {
		switch t.Result {
		case ResultDeny:
			denied++
		case ResultAllow:
			allowed++
		}
	}

	policies := make([]string, 0, len(r.policies))
	for k := range r.policies {
		policies = append(policies, k)
	}

	return Stats{
		TotalEvaluations:   n,
		TotalDenied:        denied,
		TotalAllowed:       allowed,
		LatencyP50Us:       sorted[n/2],
		LatencyP99Us:       sorted[int(float64(n)*0.99)],
		LatencyMaxUs:       sorted[n-1],
		RegisteredPolicies: policies,
	}
}

// Govern wraps a function with CCS governance.
// The returned function evaluates governance before calling fn.
// If governance denies, it returns a PermissionError and fn is NEVER called.
func Govern(fn func(args ToolInput) (interface{}, error), policyName string, runtime *Runtime) func(ToolInput) (interface{}, error) {
	if runtime == nil {
		runtime = globalRuntime()
	}
	if policyName == "" {
		policyName = "default"
	}

	return func(input ToolInput) (interface{}, error) {
		result := runtime.Evaluate("function", input, policyName)
		if result.Result != ResultAllow {
			return nil, &PermissionError{
				ToolName:   "function",
				PolicyName: policyName,
				LatencyUs:  result.LatencyUs,
			}
		}
		return fn(input)
	}
}

// PermissionError is returned when CCS governance denies a tool call.
type PermissionError struct {
	ToolName   string
	PolicyName string
	LatencyUs  float64
}

func (e *PermissionError) Error() string {
	return fmt.Sprintf("CCS governance DENIED tool '%s' (policy=%s, latency=%.2fµs)",
		e.ToolName, e.PolicyName, e.LatencyUs)
}

// Global runtime singleton
var (
	globalOnce   sync.Once
	globalRt     *Runtime
)

func globalRuntime() *Runtime {
	globalOnce.Do(func() {
		globalRt = NewRuntime()
	})
	return globalRt
}

// GetGlobalRuntime returns the global CCS runtime singleton.
func GetGlobalRuntime() *Runtime {
	return globalRuntime()
}

// ResetGlobalRuntime resets the global runtime (for testing).
func ResetGlobalRuntime() {
	globalOnce = sync.Once{}
	globalRt = nil
}

func computeHash(input ToolInput) string {
	keys := make([]string, 0, len(input))
	for k := range input {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", k, input[k]))
	}
	data := strings.Join(parts, "&")

	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash[:8])
}
