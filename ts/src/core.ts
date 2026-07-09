/**
 * CCS Core: Synchronous Interceptor Governance Runtime
 * 
 * TypeScript implementation of CCS v1.0 Standard.
 * Provides structural fail-closed guarantee: if governance evaluation
 * throws, the tool function is NEVER invoked.
 * 
 * Reference: CCS v1.0 Standard, Section 3 — Formal Framework
 *            DOI: 10.5281/zenodo.21271910
 */

// ============================================================
// Types
// ============================================================

export enum GovernanceResult {
  ALLOW = "allow",
  DENY = "deny",
  ERROR = "error",
}

export interface CCSConfig {
  policyName: string;
  maxToolInputSize: number;  // bytes, default 1MB
  timeoutMs: number;         // governance evaluation timeout
  failMode: "closed";        // Only "closed" is valid
  auditLog: boolean;
  targetP50Us: number;
  targetP99Us: number;
}

export interface GovernanceTrace {
  timestamp: number;
  toolName: string;
  inputHash: string;
  result: GovernanceResult;
  latencyUs: number;
  policyName: string;
  ruleEvaluated: string;
  detail: string;
}

export type ToolInput = Record<string, unknown>;

// ============================================================
// Default Config
// ============================================================

export const DEFAULT_CONFIG: CCSConfig = {
  policyName: "default",
  maxToolInputSize: 1_000_000,
  timeoutMs: 50,
  failMode: "closed",
  auditLog: true,
  targetP50Us: 22.0,
  targetP99Us: 99.0,
};

// ============================================================
// Policy Interface
// ============================================================

export interface CCSPolicy {
  evaluate(toolName: string, toolInput: ToolInput): GovernanceResult;
}

/**
 * Default policy: validates input structure and size.
 */
export class DefaultPolicy implements CCSPolicy {
  constructor(private config: CCSConfig = DEFAULT_CONFIG) {}

  evaluate(toolName: string, toolInput: ToolInput): GovernanceResult {
    try {
      const serialized = JSON.stringify(toolInput);
      if (serialized.length > this.config.maxToolInputSize) {
        return GovernanceResult.DENY;
      }
    } catch {
      return GovernanceResult.DENY;
    }

    if (typeof toolInput !== "object" || toolInput === null || Array.isArray(toolInput)) {
      return GovernanceResult.DENY;
    }

    return GovernanceResult.ALLOW;
  }
}

// ============================================================
// Runtime
// ============================================================

export class CCSRuntime {
  private policies: Map<string, CCSPolicy> = new Map();
  private _traces: GovernanceTrace[] = [];
  private _latencies: number[] = [];
  public config: CCSConfig;

  constructor(config?: Partial<CCSConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.policies.set("default", new DefaultPolicy(this.config));
  }

  registerPolicy(name: string, policy: CCSPolicy): void {
    this.policies.set(name, policy);
  }

  evaluate(
    toolName: string,
    toolInput: ToolInput,
    policyName: string = "default"
  ): { result: GovernanceResult; latencyUs: number } {
    const start = performance.now();

    let result: GovernanceResult;
    let detail: string;

    try {
      const policy = this.policies.get(policyName);
      if (!policy) {
        result = GovernanceResult.DENY;
        detail = `Unknown policy: ${policyName}`;
      } else {
        result = policy.evaluate(toolName, toolInput);
        detail = `Policy '${policyName}' evaluated`;
      }
    } catch (e) {
      // FAIL-CLOSED: Any exception → DENY
      result = GovernanceResult.DENY;
      detail = `Exception caught, fail-closed: ${e instanceof Error ? e.message : String(e)}`;
    }

    const latencyUs = (performance.now() - start) * 1000;
    this._latencies.push(latencyUs);

    // Compute input hash
    let inputHash: string;
    try {
      const inputStr = JSON.stringify(toolInput, Object.keys(toolInput).sort());
      inputHash = simpleHash(inputStr).substring(0, 16);
    } catch {
      inputHash = "unhashable";
    }

    if (this.config.auditLog) {
      this._traces.push({
        timestamp: Date.now(),
        toolName,
        inputHash,
        result,
        latencyUs: Math.round(latencyUs * 100) / 100,
        policyName,
        ruleEvaluated: policyName,
        detail,
      });
    }

    return { result, latencyUs: Math.round(latencyUs * 100) / 100 };
  }

  get traces(): ReadonlyArray<GovernanceTrace> {
    return this._traces;
  }

  getStats(): Record<string, unknown> {
    if (this._latencies.length === 0) {
      return { totalEvaluations: 0 };
    }

    const sorted = [...this._latencies].sort((a, b) => a - b);
    const n = sorted.length;

    return {
      totalEvaluations: n,
      totalDenied: this._traces.filter((t) => t.result === GovernanceResult.DENY).length,
      totalAllowed: this._traces.filter((t) => t.result === GovernanceResult.ALLOW).length,
      latencyP50Us: Math.round(sorted[Math.floor(n / 2)] * 100) / 100,
      latencyP99Us: n >= 100
        ? Math.round(sorted[Math.floor(n * 0.99)] * 100) / 100
        : Math.round(sorted[n - 1] * 100) / 100,
      latencyMaxUs: Math.round(sorted[n - 1] * 100) / 100,
    };
  }
}

// ============================================================
// Global Runtime Singleton
// ============================================================

let globalRuntime: CCSRuntime | null = null;

export function getRuntime(config?: Partial<CCSConfig>): CCSRuntime {
  if (!globalRuntime) {
    globalRuntime = new CCSRuntime(config);
  }
  return globalRuntime;
}

export function resetRuntime(): void {
  globalRuntime = null;
}

// ============================================================
// Govern Decorator (Higher-Order Function)
// ============================================================

/**
 * CCS governance wrapper — the core of the interceptor pattern.
 * 
 * Wraps a function so that governance evaluation happens BEFORE
 * the function executes. If governance denies or throws, the
 * wrapped function is NEVER called (fail-closed).
 * 
 * Usage:
 *   const governedSearch = govern(searchWeb, { policy: "compliance" });
 *   governedSearch({ query: "..." }); // Throws PermissionError if denied
 */
export function govern<T extends (...args: any[]) => any>(
  fn: T,
  options: { policy?: string; config?: Partial<CCSConfig> } = {}
): T {
  const { policy = "default", config } = options;

  const wrapper = function (this: unknown, ...args: unknown[]) {
    const runtime = getRuntime(config);
    const toolInput: ToolInput = { args, kwargs: {} };

    const { result, latencyUs } = runtime.evaluate(
      fn.name || "anonymous",
      toolInput,
      policy
    );

    if (result !== GovernanceResult.ALLOW) {
      throw new PermissionError(
        `CCS governance DENIED tool '${fn.name || "anonymous"}' ` +
        `(policy=${policy}, latency=${latencyUs}µs)`
      );
    }

    return fn.apply(this, args);
  } as unknown as T & {
    __ccs_governed__: boolean;
    __ccs_policy__: string;
  };

  (wrapper as any).__ccs_governed__ = true;
  (wrapper as any).__ccs_policy__ = policy;

  return wrapper;
}

// ============================================================
// PermissionError
// ============================================================

export class PermissionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PermissionError";
  }
}

// ============================================================
// Utility: Simple hash function
// ============================================================

function simpleHash(str: string): string {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash + char) | 0;
  }
  return Math.abs(hash).toString(16).padStart(8, "0");
}
