// Package ccs - GuardrailProvider Module
// Framework-agnostic runtime security layer for AI Agent tool calls.
// CCS v4.1.0 — AI Agent Runtime Assurance
//
// DOI: 10.5281/zenodo.21271910
// Standard: https://correctover.com/ccs
package ccs

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ============================================================
// GuardrailDecisionV1 — Content-addressed authorization decision
// ============================================================

// GuardrailDecisionV1 is an immutable, content-addressed authorization decision.
// The decision_id is SHA-256(canonical_json(claims ∪ expires_at)).
type GuardrailDecisionV1 struct {
	DecisionID  string                 `json:"decision_id"`
	Action      string                 `json:"action"` // "allow" or "deny"
	Claims      map[string]interface{} `json:"claims"`
	ExpiresAt   time.Time              `json:"expires_at"`
	Reason      string                 `json:"reason,omitempty"`
	ProviderID  string                 `json:"provider_id"`
	Timestamp   time.Time              `json:"timestamp"`
}

// CanonicalJSON produces a deterministic JSON serialization for hashing.
func CanonicalJSON(claims map[string]interface{}, expiresAt time.Time) []byte {
	merged := make(map[string]interface{})
	for k, v := range claims {
		merged[k] = v
	}
	merged["expires_at"] = expiresAt.UTC().Format(time.RFC3339Nano)

	keys := make([]string, 0, len(merged))
	for k := range merged {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		v, _ := json.Marshal(merged[k])
		parts = append(parts, fmt.Sprintf("%q:%s", k, string(v)))
	}
	return []byte("{" + strings.Join(parts, ",") + "}")
}

// ComputeDecisionID computes SHA-256 of canonical JSON.
func ComputeDecisionID(claims map[string]interface{}, expiresAt time.Time) string {
	data := CanonicalJSON(claims, expiresAt)
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash[:])
}

// VerifyIntegrity independently recomputes the decision_id and returns true if it matches.
func (d *GuardrailDecisionV1) VerifyIntegrity() bool {
	expected := ComputeDecisionID(d.Claims, d.ExpiresAt)
	return d.DecisionID == expected
}

// IsExpired returns true if the decision has expired.
func (d *GuardrailDecisionV1) IsExpired() bool {
	return time.Now().After(d.ExpiresAt)
}

// ============================================================
// ActionEnvelopeV1 — Separated action envelope
// ============================================================

// ActionEnvelopeV1 wraps the action to be taken, separate from the decision.
type ActionEnvelopeV1 struct {
	ToolName   string                 `json:"tool_name"`
	Arguments  map[string]interface{} `json:"arguments"`
	AgentID    string                 `json:"agent_id,omitempty"`
	Metadata   map[string]string      `json:"metadata,omitempty"`
}

// ============================================================
// ToolCallContext — Framework-agnostic context
// ============================================================

// ToolCallContext represents a tool call to be evaluated.
type ToolCallContext struct {
	ToolName  string
	Arguments map[string]interface{}
	AgentID   string
	Metadata  map[string]string
}

// ============================================================
// GuardrailProvider — Abstract authorization protocol
// ============================================================

// GuardrailProvider is the interface for all guardrail providers.
type GuardrailProvider interface {
	// ProviderID returns the unique identifier for this provider.
	ProviderID() string
	// Evaluate evaluates a tool call context and returns a decision.
	Evaluate(ctx *ToolCallContext) *GuardrailDecisionV1
}

// ============================================================
// AllowAllGuardrailProvider
// ============================================================

type AllowAllGuardrailProvider struct{}

func NewAllowAllGuardrailProvider() *AllowAllGuardrailProvider {
	return &AllowAllGuardrailProvider{}
}

func (p *AllowAllGuardrailProvider) ProviderID() string { return "allow_all" }

func (p *AllowAllGuardrailProvider) Evaluate(ctx *ToolCallContext) *GuardrailDecisionV1 {
	expiresAt := time.Now().Add(1 * time.Hour)
	claims := map[string]interface{}{
		"provider":  p.ProviderID(),
		"tool_name": ctx.ToolName,
		"agent_id":  ctx.AgentID,
	}
	return &GuardrailDecisionV1{
		DecisionID: ComputeDecisionID(claims, expiresAt),
		Action:     "allow",
		Claims:     claims,
		ExpiresAt:  expiresAt,
		Reason:     "AllowAll: no restrictions",
		ProviderID: p.ProviderID(),
		Timestamp:  time.Now(),
	}
}

// ============================================================
// DenyAllGuardrailProvider
// ============================================================

type DenyAllGuardrailProvider struct{}

func NewDenyAllGuardrailProvider() *DenyAllGuardrailProvider {
	return &DenyAllGuardrailProvider{}
}

func (p *DenyAllGuardrailProvider) ProviderID() string { return "deny_all" }

func (p *DenyAllGuardrailProvider) Evaluate(ctx *ToolCallContext) *GuardrailDecisionV1 {
	expiresAt := time.Now().Add(1 * time.Hour)
	claims := map[string]interface{}{
		"provider":  p.ProviderID(),
		"tool_name": ctx.ToolName,
		"agent_id":  ctx.AgentID,
	}
	return &GuardrailDecisionV1{
		DecisionID: ComputeDecisionID(claims, expiresAt),
		Action:     "deny",
		Claims:     claims,
		ExpiresAt:  expiresAt,
		Reason:     "DenyAll: all tool calls denied",
		ProviderID: p.ProviderID(),
		Timestamp:  time.Now(),
	}
}

// ============================================================
// ToolListGuardrailProvider — Whitelist/blacklist
// ============================================================

// ToolListMode determines whitelist or blacklist behavior.
type ToolListMode int

const (
	ToolListWhitelist ToolListMode = iota
	ToolListBlacklist
)

type ToolListGuardrailProvider struct {
	id    string
	mode  ToolListMode
	tools map[string]bool
}

func NewToolListGuardrailProvider(id string, mode ToolListMode, tools []string) *ToolListGuardrailProvider {
	m := make(map[string]bool)
	for _, t := range tools {
		m[t] = true
	}
	return &ToolListGuardrailProvider{id: id, mode: mode, tools: m}
}

func (p *ToolListGuardrailProvider) ProviderID() string { return p.id }

func (p *ToolListGuardrailProvider) Evaluate(ctx *ToolCallContext) *GuardrailDecisionV1 {
	expiresAt := time.Now().Add(1 * time.Hour)
	claims := map[string]interface{}{
		"provider":  p.ProviderID(),
		"tool_name": ctx.ToolName,
		"agent_id":  ctx.AgentID,
	}

	inList := p.tools[ctx.ToolName]
	var action, reason string

	switch p.mode {
	case ToolListWhitelist:
		if inList {
			action, reason = "allow", fmt.Sprintf("Whitelist: %s is allowed", ctx.ToolName)
		} else {
			action, reason = "deny", fmt.Sprintf("Whitelist: %s is not in allowed list", ctx.ToolName)
		}
	case ToolListBlacklist:
		if inList {
			action, reason = "deny", fmt.Sprintf("Blacklist: %s is denied", ctx.ToolName)
		} else {
			action, reason = "allow", fmt.Sprintf("Blacklist: %s is not denied", ctx.ToolName)
		}
	}

	return &GuardrailDecisionV1{
		DecisionID: ComputeDecisionID(claims, expiresAt),
		Action:     action,
		Claims:     claims,
		ExpiresAt:  expiresAt,
		Reason:     reason,
		ProviderID: p.ProviderID(),
		Timestamp:  time.Now(),
	}
}

// ============================================================
// CKGGuardrailProvider — Constrained Knowledge Graph authorization
// ============================================================

// CKGPredicate defines a predicate for CKG-based authorization.
type CKGPredicate func(ctx *ToolCallContext) bool

type CKGGuardrailProvider struct {
	id         string
	predicates map[string]CKGPredicate
}

func NewCKGGuardrailProvider(id string) *CKGGuardrailProvider {
	p := &CKGGuardrailProvider{id: id, predicates: make(map[string]CKGPredicate)}
	p.registerDefaults()
	return p
}

func (p *CKGGuardrailProvider) ProviderID() string { return p.id }

func (p *CKGGuardrailProvider) registerDefaults() {
	// 6 built-in predicates
	p.predicates["is_safe_tool"] = func(ctx *ToolCallContext) bool {
		dangerous := []string{"execute_command", "run_shell", "delete_file", "rm", "format_disk"}
		for _, d := range dangerous {
			if ctx.ToolName == d {
				return false
			}
		}
		return true
	}

	p.predicates["no_sensitive_args"] = func(ctx *ToolCallContext) bool {
		sensitive := []string{"password", "secret", "token", "api_key", "private_key"}
		for k := range ctx.Arguments {
			for _, s := range sensitive {
				if strings.Contains(strings.ToLower(k), s) {
					return false
				}
			}
		}
		return true
	}

	p.predicates["known_agent"] = func(ctx *ToolCallContext) bool {
		return ctx.AgentID != ""
	}

	p.predicates["not_filesystem_root"] = func(ctx *ToolCallContext) bool {
		if path, ok := ctx.Arguments["path"].(string); ok {
			abs := filepath.Clean(path)
			return abs != "/" && abs != "\\"
		}
		return true
	}

	p.predicates["rate_limit_ok"] = func(ctx *ToolCallContext) bool {
		// Always passes — placeholder for rate limiting integration
		return true
	}

	p.predicates["has_valid_metadata"] = func(ctx *ToolCallContext) bool {
		return len(ctx.Metadata) > 0 || ctx.AgentID != ""
	}
}

// AddPredicate adds a custom predicate.
func (p *CKGGuardrailProvider) AddPredicate(name string, pred CKGPredicate) {
	p.predicates[name] = pred
}

func (p *CKGGuardrailProvider) Evaluate(ctx *ToolCallContext) *GuardrailDecisionV1 {
	expiresAt := time.Now().Add(1 * time.Hour)
	claims := map[string]interface{}{
		"provider":  p.ProviderID(),
		"tool_name": ctx.ToolName,
		"agent_id":  ctx.AgentID,
	}

	failedPredicates := []string{}
	for name, pred := range p.predicates {
		if !pred(ctx) {
			failedPredicates = append(failedPredicates, name)
		}
	}

	sort.Strings(failedPredicates)

	var action, reason string
	if len(failedPredicates) == 0 {
		action = "allow"
		reason = "CKG: all predicates satisfied"
	} else {
		action = "deny"
		reason = fmt.Sprintf("CKG: failed predicates: %s", strings.Join(failedPredicates, ", "))
	}

	return &GuardrailDecisionV1{
		DecisionID: ComputeDecisionID(claims, expiresAt),
		Action:     action,
		Claims:     claims,
		ExpiresAt:  expiresAt,
		Reason:     reason,
		ProviderID: p.ProviderID(),
		Timestamp:  time.Now(),
	}
}

// ============================================================
// EnvProtectionProvider — .env file access protection (CVE-2026-12957)
// ============================================================

type EnvProtectionProvider struct {
	id             string
	protectedFiles []string
}

func NewEnvProtectionProvider(id string) *EnvProtectionProvider {
	return &EnvProtectionProvider{
		id: id,
		protectedFiles: []string{
			".env", ".env.local", ".env.production", ".env.development",
			".env.staging", ".env.test", ".env.example",
		},
	}
}

func (p *EnvProtectionProvider) ProviderID() string { return p.id }

func (p *EnvProtectionProvider) Evaluate(ctx *ToolCallContext) *GuardrailDecisionV1 {
	expiresAt := time.Now().Add(1 * time.Hour)
	claims := map[string]interface{}{
		"provider":  p.ProviderID(),
		"tool_name": ctx.ToolName,
		"agent_id":  ctx.AgentID,
	}

	// Check if tool accesses protected env files
	for _, key := range []string{"path", "file", "filename", "filepath"} {
		if val, ok := ctx.Arguments[key].(string); ok {
			base := filepath.Base(filepath.Clean(val))
			for _, pf := range p.protectedFiles {
				if base == pf || strings.HasPrefix(base, ".env.") {
					return &GuardrailDecisionV1{
						DecisionID: ComputeDecisionID(claims, expiresAt),
						Action:     "deny",
						Claims:     claims,
						ExpiresAt:  expiresAt,
						Reason:     fmt.Sprintf("EnvProtection: blocked access to sensitive file '%s' (CVE-2026-12957)", val),
						ProviderID: p.ProviderID(),
						Timestamp:  time.Now(),
					}
				}
			}
		}
	}

	// Check for environment variable read patterns in command-like tools
	if ctx.ToolName == "execute_command" || ctx.ToolName == "run_shell" {
		if cmd, ok := ctx.Arguments["command"].(string); ok {
			envPatterns := []*regexp.Regexp{
				regexp.MustCompile(`\$\{?\w*(KEY|SECRET|TOKEN|PASSWORD)\w*\}?`),
				regexp.MustCompile(`cat\s+\.env`),
				regexp.MustCompile(`os\.environ`),
				regexp.MustCompile(`process\.env`),
			}
			for _, pat := range envPatterns {
				if pat.MatchString(cmd) {
					return &GuardrailDecisionV1{
						DecisionID: ComputeDecisionID(claims, expiresAt),
						Action:     "deny",
						Claims:     claims,
						ExpiresAt:  expiresAt,
						Reason:     fmt.Sprintf("EnvProtection: command references sensitive env vars (CVE-2026-12957)"),
						ProviderID: p.ProviderID(),
						Timestamp:  time.Now(),
					}
				}
			}
		}
	}

	return &GuardrailDecisionV1{
		DecisionID: ComputeDecisionID(claims, expiresAt),
		Action:     "allow",
		Claims:     claims,
		ExpiresAt:  expiresAt,
		Reason:     "EnvProtection: no sensitive file or env access detected",
		ProviderID: p.ProviderID(),
		Timestamp:  time.Now(),
	}
}

// ============================================================
// CompositeGuardrailProvider — AND/OR composition
// ============================================================

// CompositeMode defines how multiple providers are combined.
type CompositeMode int

const (
	CompositeAND CompositeMode = iota // All must allow
	CompositeOR                       // Any must allow
)

type CompositeGuardrailProvider struct {
	id        string
	mode      CompositeMode
	providers []GuardrailProvider
}

func NewCompositeGuardrailProvider(id string, mode CompositeMode, providers []GuardrailProvider) *CompositeGuardrailProvider {
	return &CompositeGuardrailProvider{id: id, mode: mode, providers: providers}
}

func (p *CompositeGuardrailProvider) ProviderID() string { return p.id }

func (p *CompositeGuardrailProvider) Evaluate(ctx *ToolCallContext) *GuardrailDecisionV1 {
	expiresAt := time.Now().Add(1 * time.Hour)
	claims := map[string]interface{}{
		"provider":  p.ProviderID(),
		"tool_name": ctx.ToolName,
		"agent_id":  ctx.AgentID,
	}

	decisions := make([]*GuardrailDecisionV1, 0, len(p.providers))
	for _, provider := range p.providers {
		d := provider.Evaluate(ctx)
		decisions = append(decisions, d)
	}

	var action, reason string
	switch p.mode {
	case CompositeAND:
		allAllow := true
		denyReasons := []string{}
		for _, d := range decisions {
			if d.Action != "allow" {
				allAllow = false
				denyReasons = append(denyReasons, d.Reason)
			}
		}
		if allAllow {
			action = "allow"
			reason = "CompositeAND: all providers allow"
		} else {
			action = "deny"
			reason = fmt.Sprintf("CompositeAND: denied — %s", strings.Join(denyReasons, "; "))
		}
	case CompositeOR:
		anyAllow := false
		allowReasons := []string{}
		for _, d := range decisions {
			if d.Action == "allow" {
				anyAllow = true
				allowReasons = append(allowReasons, d.Reason)
			}
		}
		if anyAllow {
			action = "allow"
			reason = fmt.Sprintf("CompositeOR: allowed by — %s", strings.Join(allowReasons, "; "))
		} else {
			action = "deny"
			reason = "CompositeOR: no provider allowed"
		}
	}

	return &GuardrailDecisionV1{
		DecisionID: ComputeDecisionID(claims, expiresAt),
		Action:     action,
		Claims:     claims,
		ExpiresAt:  expiresAt,
		Reason:     reason,
		ProviderID: p.ProviderID(),
		Timestamp:  time.Now(),
	}
}

// ============================================================
// AuditTrail — Cryptographic audit chain
// ============================================================

type AuditEntry struct {
	Decision      *GuardrailDecisionV1 `json:"decision"`
	PreviousHash  string               `json:"previous_hash"`
	ChainHash     string               `json:"chain_hash"`
}

type AuditTrail struct {
	entries []AuditEntry
}

func NewAuditTrail() *AuditTrail {
	return &AuditTrail{entries: make([]AuditEntry, 0)}
}

func (a *AuditTrail) Record(decision *GuardrailDecisionV1) {
	prevHash := "genesis"
	if len(a.entries) > 0 {
		prevHash = a.entries[len(a.entries)-1].ChainHash
	}

	payload := fmt.Sprintf("%s|%s|%s|%s",
		decision.DecisionID, prevHash, decision.Timestamp.Format(time.RFC3339Nano), decision.Action)
	hash := sha256.Sum256([]byte(payload))

	a.entries = append(a.entries, AuditEntry{
		Decision:     decision,
		PreviousHash: prevHash,
		ChainHash:    fmt.Sprintf("%x", hash[:]),
	})
}

// Verify verifies the integrity of the entire audit chain.
func (a *AuditTrail) Verify() bool {
	prevHash := "genesis"
	for _, entry := range a.entries {
		if entry.PreviousHash != prevHash {
			return false
		}
		payload := fmt.Sprintf("%s|%s|%s|%s",
			entry.Decision.DecisionID, entry.PreviousHash,
			entry.Decision.Timestamp.Format(time.RFC3339Nano), entry.Decision.Action)
		hash := sha256.Sum256([]byte(payload))
		expected := fmt.Sprintf("%x", hash[:])
		if entry.ChainHash != expected {
			return false
		}
		prevHash = entry.ChainHash
	}
	return true
}

// Entries returns all audit entries.
func (a *AuditTrail) Entries() []AuditEntry {
	out := make([]AuditEntry, len(a.entries))
	copy(out, a.entries)
	return out
}

// ============================================================
// MCPSecurityValidator — MCP config security scanning
// ============================================================

// Severity levels for MCP security findings.
type Severity int

const (
	SeverityLow    Severity = 1
	SeverityMedium Severity = 2
	SeverityHigh   Severity = 3
	SeverityCrit   Severity = 4
)

func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	case SeverityCrit:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// MCPFinding represents a security finding in an MCP configuration.
type MCPFinding struct {
	CVE         string   `json:"cve,omitempty"`
	Severity    Severity `json:"severity"`
	Category    string   `json:"category"`
	Description string   `json:"description"`
	Evidence    string   `json:"evidence"`
}

// MCPScanResult is the result of scanning an MCP configuration.
type MCPScanResult struct {
	Safe     bool         `json:"safe"`
	Findings []MCPFinding `json:"findings"`
	ScannedAt time.Time   `json:"scanned_at"`
}

// MCPSecurityValidator scans MCP configurations for known vulnerabilities.
type MCPSecurityValidator struct {
	rules []mcpRule
}

type mcpRule struct {
	id       string
	cve      string
	severity Severity
	category string
	check    func(config string) []MCPFinding
}

func NewMCPSecurityValidator() *MCPSecurityValidator {
	v := &MCPSecurityValidator{rules: make([]mcpRule, 0)}
	v.registerDefaultRules()
	return v
}

func (v *MCPSecurityValidator) registerDefaultRules() {
	// CVE-2026-42271: Command injection via MCP config
	v.rules = append(v.rules, mcpRule{
		id: "cmd_injection", cve: "CVE-2026-42271", severity: SeverityCrit,
		category: "command_injection",
		check: func(config string) []MCPFinding {
			dangerous := []string{"&&", "||", ";", "|", "`", "$(", "${"}
			var findings []MCPFinding
			for _, d := range dangerous {
				if strings.Contains(config, d) {
					findings = append(findings, MCPFinding{
						CVE: "CVE-2026-42271", Severity: SeverityCrit,
						Category:    "command_injection",
						Description: "MCP config contains shell metacharacters that may allow command injection",
						Evidence:    fmt.Sprintf("Found dangerous pattern: %s", d),
					})
				}
			}
			return findings
		},
	})

	// CVE-2026-12957: .env file leakage
	v.rules = append(v.rules, mcpRule{
		id: "env_leakage", cve: "CVE-2026-12957", severity: SeverityHigh,
		category: "env_leakage",
		check: func(config string) []MCPFinding {
			patterns := []string{".env", "process.env", "os.environ", "API_KEY", "SECRET_KEY"}
			var findings []MCPFinding
			for _, p := range patterns {
				if strings.Contains(config, p) {
					findings = append(findings, MCPFinding{
						CVE: "CVE-2026-12957", Severity: SeverityHigh,
						Category:    "env_leakage",
						Description: "MCP config may expose environment variables or credentials",
						Evidence:    fmt.Sprintf("Found sensitive pattern: %s", p),
					})
				}
			}
			return findings
		},
	})

	// CVE-2026-25536: Cross-client data leakage
	v.rules = append(v.rules, mcpRule{
		id: "cross_client", cve: "CVE-2026-25536", severity: SeverityHigh,
		category: "cross_client_leakage",
		check: func(config string) []MCPFinding {
			patterns := []string{"shared_state", "global_cache", "cross_session", "broadcast"}
			var findings []MCPFinding
			for _, p := range patterns {
				if strings.Contains(strings.ToLower(config), p) {
					findings = append(findings, MCPFinding{
						CVE: "CVE-2026-25536", Severity: SeverityHigh,
						Category:    "cross_client_leakage",
						Description: "MCP config may allow cross-client data leakage via shared state",
						Evidence:    fmt.Sprintf("Found shared state pattern: %s", p),
					})
				}
			}
			return findings
		},
	})
}

// Scan validates an MCP configuration against known vulnerability patterns.
func (v *MCPSecurityValidator) Scan(config string) MCPScanResult {
	findings := make([]MCPFinding, 0)
	for _, rule := range v.rules {
		findings = append(findings, rule.check(config)...)
	}
	return MCPScanResult{
		Safe:      len(findings) == 0,
		Findings:  findings,
		ScannedAt: time.Now(),
	}
}

// ScanFile reads and validates an MCP configuration file.
func (v *MCPSecurityValidator) ScanFile(path string) (MCPScanResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return MCPScanResult{}, fmt.Errorf("failed to read config: %w", err)
	}
	return v.Scan(string(data)), nil
}

// ============================================================
// MakeGuardrailHook — One-line integration helper
// ============================================================

// MakeGuardrailHook wraps a tool function with guardrail authorization.
// Returns a new function that checks authorization before executing the tool.
func MakeGuardrailHook(
	fn func(args map[string]interface{}) (interface{}, error),
	provider GuardrailProvider,
	audit *AuditTrail,
) func(*ToolCallContext) (interface{}, error) {
	return func(ctx *ToolCallContext) (interface{}, error) {
		decision := provider.Evaluate(ctx)
		if audit != nil {
			audit.Record(decision)
		}
		if decision.Action != "allow" {
			return nil, fmt.Errorf("guardrail DENIED: %s (provider=%s, decision=%s)",
				decision.Reason, decision.ProviderID, decision.DecisionID[:16])
		}
		return fn(ctx.Arguments)
	}
}

// ============================================================
// DetectMissingGuardrail — Detection utility
// ============================================================

// DetectMissingGuardrail checks if a list of tool names have corresponding
// guardrail providers configured. Returns tools without guardrail coverage.
func DetectMissingGuardrail(toolNames []string, providers []GuardrailProvider) []string {
	if len(providers) == 0 {
		return toolNames
	}
	// For now, if any providers exist, all tools are considered covered
	// In production, this would check per-tool coverage
	return nil
}
