/**
 * Correctover Conformance Standard (CCS) v4.1 — GuardrailProvider Module
 * Framework-agnostic runtime security layer for AI Agent tool calls.
 *
 * DOI: 10.5281/zenodo.21271910
 * Standard: https://correctover.com/ccs
 */

import * as crypto from "crypto";
import * as path from "path";

// ============================================================
// GuardrailDecisionV1 — Content-addressed authorization decision
// ============================================================

export interface GuardrailDecisionV1 {
  decisionId: string;
  action: "allow" | "deny";
  claims: Record<string, unknown>;
  expiresAt: Date;
  reason?: string;
  providerId: string;
  timestamp: Date;
}

export function canonicalJson(
  claims: Record<string, unknown>,
  expiresAt: Date
): string {
  const merged: Record<string, unknown> = { ...claims };
  merged["expires_at"] = expiresAt.toISOString();

  const keys = Object.keys(merged).sort();
  const parts = keys.map((k) => `${JSON.stringify(k)}:${JSON.stringify(merged[k])}`);
  return "{" + parts.join(",") + "}";
}

export function computeDecisionId(
  claims: Record<string, unknown>,
  expiresAt: Date
): string {
  const data = canonicalJson(claims, expiresAt);
  return crypto.createHash("sha256").update(data).digest("hex");
}

export function verifyDecisionIntegrity(decision: GuardrailDecisionV1): boolean {
  const expected = computeDecisionId(decision.claims, decision.expiresAt);
  return decision.decisionId === expected;
}

export function isDecisionExpired(decision: GuardrailDecisionV1): boolean {
  return new Date() > decision.expiresAt;
}

// ============================================================
// ActionEnvelopeV1
// ============================================================

export interface ActionEnvelopeV1 {
  toolName: string;
  arguments: Record<string, unknown>;
  agentId?: string;
  metadata?: Record<string, string>;
}

// ============================================================
// ToolCallContext
// ============================================================

export interface ToolCallContext {
  toolName: string;
  arguments: Record<string, unknown>;
  agentId: string;
  metadata: Record<string, string>;
}

// ============================================================
// GuardrailProvider — Abstract protocol
// ============================================================

export interface GuardrailProvider {
  providerId(): string;
  evaluate(ctx: ToolCallContext): GuardrailDecisionV1;
}

// ============================================================
// AllowAllGuardrailProvider
// ============================================================

export class AllowAllGuardrailProvider implements GuardrailProvider {
  providerId(): string {
    return "allow_all";
  }

  evaluate(ctx: ToolCallContext): GuardrailDecisionV1 {
    const expiresAt = new Date(Date.now() + 3600000);
    const claims = { provider: this.providerId(), tool_name: ctx.toolName, agent_id: ctx.agentId };
    return {
      decisionId: computeDecisionId(claims, expiresAt),
      action: "allow",
      claims,
      expiresAt,
      reason: "AllowAll: no restrictions",
      providerId: this.providerId(),
      timestamp: new Date(),
    };
  }
}

// ============================================================
// DenyAllGuardrailProvider
// ============================================================

export class DenyAllGuardrailProvider implements GuardrailProvider {
  providerId(): string {
    return "deny_all";
  }

  evaluate(ctx: ToolCallContext): GuardrailDecisionV1 {
    const expiresAt = new Date(Date.now() + 3600000);
    const claims = { provider: this.providerId(), tool_name: ctx.toolName, agent_id: ctx.agentId };
    return {
      decisionId: computeDecisionId(claims, expiresAt),
      action: "deny",
      claims,
      expiresAt,
      reason: "DenyAll: all tool calls denied",
      providerId: this.providerId(),
      timestamp: new Date(),
    };
  }
}

// ============================================================
// ToolListGuardrailProvider — Whitelist/blacklist
// ============================================================

export type ToolListMode = "whitelist" | "blacklist";

export class ToolListGuardrailProvider implements GuardrailProvider {
  private id: string;
  private mode: ToolListMode;
  private tools: Set<string>;

  constructor(id: string, mode: ToolListMode, tools: string[]) {
    this.id = id;
    this.mode = mode;
    this.tools = new Set(tools);
  }

  providerId(): string {
    return this.id;
  }

  evaluate(ctx: ToolCallContext): GuardrailDecisionV1 {
    const expiresAt = new Date(Date.now() + 3600000);
    const claims = { provider: this.providerId(), tool_name: ctx.toolName, agent_id: ctx.agentId };
    const inList = this.tools.has(ctx.toolName);

    let action: "allow" | "deny";
    let reason: string;

    if (this.mode === "whitelist") {
      if (inList) {
        action = "allow";
        reason = `Whitelist: ${ctx.toolName} is allowed`;
      } else {
        action = "deny";
        reason = `Whitelist: ${ctx.toolName} is not in allowed list`;
      }
    } else {
      if (inList) {
        action = "deny";
        reason = `Blacklist: ${ctx.toolName} is denied`;
      } else {
        action = "allow";
        reason = `Blacklist: ${ctx.toolName} is not denied`;
      }
    }

    return {
      decisionId: computeDecisionId(claims, expiresAt),
      action,
      claims,
      expiresAt,
      reason,
      providerId: this.providerId(),
      timestamp: new Date(),
    };
  }
}

// ============================================================
// CKGGuardrailProvider — Constrained Knowledge Graph authorization
// ============================================================

export type CKGPredicate = (ctx: ToolCallContext) => boolean;

export class CKGGuardrailProvider implements GuardrailProvider {
  private id: string;
  private predicates: Map<string, CKGPredicate>;

  constructor(id: string) {
    this.id = id;
    this.predicates = new Map();
    this.registerDefaults();
  }

  providerId(): string {
    return this.id;
  }

  private registerDefaults(): void {
    const dangerous = ["execute_command", "run_shell", "delete_file", "rm", "format_disk"];
    this.predicates.set("is_safe_tool", (ctx) => !dangerous.includes(ctx.toolName));

    const sensitiveKeys = ["password", "secret", "token", "api_key", "private_key"];
    this.predicates.set("no_sensitive_args", (ctx) => {
      return !Object.keys(ctx.arguments).some((k) =>
        sensitiveKeys.some((s) => k.toLowerCase().includes(s))
      );
    });

    this.predicates.set("known_agent", (ctx) => ctx.agentId !== "");

    this.predicates.set("not_filesystem_root", (ctx) => {
      const p = ctx.arguments["path"];
      if (typeof p !== "string") return true;
      const abs = path.normalize(p);
      return abs !== "/" && abs !== "\\";
    });

    this.predicates.set("rate_limit_ok", () => true);

    this.predicates.set("has_valid_metadata", (ctx) =>
      Object.keys(ctx.metadata).length > 0 || ctx.agentId !== ""
    );
  }

  addPredicate(name: string, pred: CKGPredicate): void {
    this.predicates.set(name, pred);
  }

  evaluate(ctx: ToolCallContext): GuardrailDecisionV1 {
    const expiresAt = new Date(Date.now() + 3600000);
    const claims = { provider: this.providerId(), tool_name: ctx.toolName, agent_id: ctx.agentId };

    const failed: string[] = [];
    for (const [name, pred] of this.predicates) {
      if (!pred(ctx)) failed.push(name);
    }
    failed.sort();

    let action: "allow" | "deny";
    let reason: string;

    if (failed.length === 0) {
      action = "allow";
      reason = "CKG: all predicates satisfied";
    } else {
      action = "deny";
      reason = `CKG: failed predicates: ${failed.join(", ")}`;
    }

    return {
      decisionId: computeDecisionId(claims, expiresAt),
      action,
      claims,
      expiresAt,
      reason,
      providerId: this.providerId(),
      timestamp: new Date(),
    };
  }
}

// ============================================================
// EnvProtectionProvider — .env file access protection (CVE-2026-12957)
// ============================================================

export class EnvProtectionProvider implements GuardrailProvider {
  private id: string;
  private protectedFiles = [
    ".env", ".env.local", ".env.production", ".env.development",
    ".env.staging", ".env.test", ".env.example",
  ];

  constructor(id: string) {
    this.id = id;
  }

  providerId(): string {
    return this.id;
  }

  evaluate(ctx: ToolCallContext): GuardrailDecisionV1 {
    const expiresAt = new Date(Date.now() + 3600000);
    const claims = { provider: this.providerId(), tool_name: ctx.toolName, agent_id: ctx.agentId };

    // Check file path arguments
    for (const key of ["path", "file", "filename", "filepath"]) {
      const val = ctx.arguments[key];
      if (typeof val === "string") {
        const base = path.basename(path.normalize(val));
        for (const pf of this.protectedFiles) {
          if (base === pf || base.startsWith(".env.")) {
            return {
              decisionId: computeDecisionId(claims, expiresAt),
              action: "deny",
              claims,
              expiresAt,
              reason: `EnvProtection: blocked access to sensitive file '${val}' (CVE-2026-12957)`,
              providerId: this.providerId(),
              timestamp: new Date(),
            };
          }
        }
      }
    }

    // Check command patterns
    if (ctx.toolName === "execute_command" || ctx.toolName === "run_shell") {
      const cmd = ctx.arguments["command"];
      if (typeof cmd === "string") {
        const envPatterns = [
          /\$\{?\w*(KEY|SECRET|TOKEN|PASSWORD)\w*\}?/,
          /cat\s+\.env/,
          /os\.environ/,
          /process\.env/,
        ];
        for (const pat of envPatterns) {
          if (pat.test(cmd)) {
            return {
              decisionId: computeDecisionId(claims, expiresAt),
              action: "deny",
              claims,
              expiresAt,
              reason: "EnvProtection: command references sensitive env vars (CVE-2026-12957)",
              providerId: this.providerId(),
              timestamp: new Date(),
            };
          }
        }
      }
    }

    return {
      decisionId: computeDecisionId(claims, expiresAt),
      action: "allow",
      claims,
      expiresAt,
      reason: "EnvProtection: no sensitive file or env access detected",
      providerId: this.providerId(),
      timestamp: new Date(),
    };
  }
}

// ============================================================
// CompositeGuardrailProvider — AND/OR composition
// ============================================================

export type CompositeMode = "AND" | "OR";

export class CompositeGuardrailProvider implements GuardrailProvider {
  private id: string;
  private mode: CompositeMode;
  private providers: GuardrailProvider[];

  constructor(id: string, mode: CompositeMode, providers: GuardrailProvider[]) {
    this.id = id;
    this.mode = mode;
    this.providers = providers;
  }

  providerId(): string {
    return this.id;
  }

  evaluate(ctx: ToolCallContext): GuardrailDecisionV1 {
    const expiresAt = new Date(Date.now() + 3600000);
    const claims = { provider: this.providerId(), tool_name: ctx.toolName, agent_id: ctx.agentId };

    const decisions = this.providers.map((p) => p.evaluate(ctx));

    let action: "allow" | "deny";
    let reason: string;

    if (this.mode === "AND") {
      const denied = decisions.filter((d) => d.action !== "allow");
      if (denied.length === 0) {
        action = "allow";
        reason = "CompositeAND: all providers allow";
      } else {
        action = "deny";
        reason = `CompositeAND: denied — ${denied.map((d) => d.reason).join("; ")}`;
      }
    } else {
      const allowed = decisions.filter((d) => d.action === "allow");
      if (allowed.length > 0) {
        action = "allow";
        reason = `CompositeOR: allowed by — ${allowed.map((d) => d.reason).join("; ")}`;
      } else {
        action = "deny";
        reason = "CompositeOR: no provider allow";
      }
    }

    return {
      decisionId: computeDecisionId(claims, expiresAt),
      action,
      claims,
      expiresAt,
      reason,
      providerId: this.providerId(),
      timestamp: new Date(),
    };
  }
}

// ============================================================
// AuditTrail — Cryptographic audit chain
// ============================================================

export interface AuditEntry {
  decision: GuardrailDecisionV1;
  previousHash: string;
  chainHash: string;
}

export class AuditTrail {
  private entries: AuditEntry[] = [];

  record(decision: GuardrailDecisionV1): void {
    const prevHash = this.entries.length > 0 ? this.entries[this.entries.length - 1].chainHash : "genesis";
    const payload = `${decision.decisionId}|${prevHash}|${decision.timestamp.toISOString()}|${decision.action}`;
    const chainHash = crypto.createHash("sha256").update(payload).digest("hex");

    this.entries.push({ decision, previousHash: prevHash, chainHash });
  }

  verify(): boolean {
    let prevHash = "genesis";
    for (const entry of this.entries) {
      if (entry.previousHash !== prevHash) return false;
      const payload = `${entry.decision.decisionId}|${entry.previousHash}|${entry.decision.timestamp.toISOString()}|${entry.decision.action}`;
      const expected = crypto.createHash("sha256").update(payload).digest("hex");
      if (entry.chainHash !== expected) return false;
      prevHash = entry.chainHash;
    }
    return true;
  }

  getEntries(): AuditEntry[] {
    return [...this.entries];
  }
}

// ============================================================
// MCPSecurityValidator — MCP config security scanning
// ============================================================

export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface MCPFinding {
  cve?: string;
  severity: Severity;
  category: string;
  description: string;
  evidence: string;
}

export interface MCPScanResult {
  safe: boolean;
  findings: MCPFinding[];
  scannedAt: Date;
}

export class MCPSecurityValidator {
  private rules: Array<{
    id: string;
    cve: string;
    severity: Severity;
    check: (config: string) => MCPFinding[];
  }>;

  constructor() {
    this.rules = [];
    this.registerDefaultRules();
  }

  private registerDefaultRules(): void {
    // CVE-2026-42271: Command injection
    this.rules.push({
      id: "cmd_injection",
      cve: "CVE-2026-42271",
      severity: "CRITICAL",
      check: (config: string) => {
        const dangerous = ["&&", "||", ";", "|", "`", "$(", "${"];
        return dangerous
          .filter((d) => config.includes(d))
          .map((d) => ({
            cve: "CVE-2026-42271",
            severity: "CRITICAL" as Severity,
            category: "command_injection",
            description: "MCP config contains shell metacharacters that may allow command injection",
            evidence: `Found dangerous pattern: ${d}`,
          }));
      },
    });

    // CVE-2026-12957: .env leakage
    this.rules.push({
      id: "env_leakage",
      cve: "CVE-2026-12957",
      severity: "HIGH",
      check: (config: string) => {
        const patterns = [".env", "process.env", "os.environ", "API_KEY", "SECRET_KEY"];
        return patterns
          .filter((p) => config.includes(p))
          .map((p) => ({
            cve: "CVE-2026-12957",
            severity: "HIGH" as Severity,
            category: "env_leakage",
            description: "MCP config may expose environment variables or credentials",
            evidence: `Found sensitive pattern: ${p}`,
          }));
      },
    });

    // CVE-2026-25536: Cross-client data leakage
    this.rules.push({
      id: "cross_client",
      cve: "CVE-2026-25536",
      severity: "HIGH",
      check: (config: string) => {
        const patterns = ["shared_state", "global_cache", "cross_session", "broadcast"];
        return patterns
          .filter((p) => config.toLowerCase().includes(p))
          .map((p) => ({
            cve: "CVE-2026-25536",
            severity: "HIGH" as Severity,
            category: "cross_client_leakage",
            description: "MCP config may allow cross-client data leakage via shared state",
            evidence: `Found shared state pattern: ${p}`,
          }));
      },
    });
  }

  scan(config: string): MCPScanResult {
    const findings: MCPFinding[] = [];
    for (const rule of this.rules) {
      findings.push(...rule.check(config));
    }
    return { safe: findings.length === 0, findings, scannedAt: new Date() };
  }
}

// ============================================================
// makeGuardrailHook — One-line integration helper
// ============================================================

export function makeGuardrailHook(
  fn: (args: Record<string, unknown>) => unknown,
  provider: GuardrailProvider,
  audit?: AuditTrail
): (ctx: ToolCallContext) => unknown {
  return (ctx: ToolCallContext) => {
    const decision = provider.evaluate(ctx);
    if (audit) audit.record(decision);
    if (decision.action !== "allow") {
      throw new Error(
        `guardrail DENIED: ${decision.reason} (provider=${decision.providerId}, decision=${decision.decisionId.substring(0, 16)})`
      );
    }
    return fn(ctx.arguments);
  };
}

// ============================================================
// detectMissingGuardrail — Detection utility
// ============================================================

export function detectMissingGuardrail(
  toolNames: string[],
  providers: GuardrailProvider[]
): string[] {
  if (providers.length === 0) return toolNames;
  return [];
}

// ============================================================
// Version
// ============================================================

export const GUARDRAIL_VERSION = "4.1.0";
