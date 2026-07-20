/**
 * Correctover Conformance Standard (CCS) v4.1 — TypeScript SDK
 * 
 * Synchronous interceptor-based governance for AI Agent frameworks.
 * Eliminates architectural fail-open bypasses inherent to observer-pattern hooks.
 * 
 * Usage:
 *   import { govern, GovernanceResult, CCSRuntime, MCPv2Detector } from "correctover-ccs";
 *   import { EnvProtectionProvider, MCPSecurityValidator, CompositeGuardrailProvider } from "correctover-ccs";
 *   
 *   const governedFn = govern(myToolFunction, { policy: "default" });
 *   governedFn(args); // Throws PermissionError if governance denies
 *   
 *   const detector = new MCPv2Detector("/path/to/mcp-server");
 *   const result = detector.scan();
 *   console.log(`MCP v2 compatible: ${result.compatible}`);
 * 
 * Standard: https://github.com/Correctover/standards
 * DOI: 10.5281/zenodo.21271910
 */

export {
  // Core types
  GovernanceResult,
  CCSConfig,
  GovernanceTrace,
  ToolInput,
  CCSPolicy,
  DEFAULT_CONFIG,
  
  // Runtime
  CCSRuntime,
  getRuntime,
  resetRuntime,
  DefaultPolicy,
  
  // Decorator
  govern,
  
  // Error
  PermissionError,
} from "./core";

export { MCPv2Detector, Severity } from "./mcp_v2";
export type { Finding, DetectionResult, DetectionSummary, RuleDefinition } from "./mcp_v2";

// Guardrail module (v4.1.0)
export {
  // Decision & Envelope
  canonicalJson,
  computeDecisionId,
  verifyDecisionIntegrity,
  isDecisionExpired,
  type GuardrailDecisionV1,
  type ActionEnvelopeV1,
  type ToolCallContext,
  
  // Provider interface
  type GuardrailProvider,
  
  // Built-in providers
  AllowAllGuardrailProvider,
  DenyAllGuardrailProvider,
  ToolListGuardrailProvider,
  type ToolListMode,
  CKGGuardrailProvider,
  type CKGPredicate,
  EnvProtectionProvider,
  CompositeGuardrailProvider,
  type CompositeMode,
  
  // Audit
  AuditTrail,
  type AuditEntry,
  
  // MCP Security
  MCPSecurityValidator,
  type MCPFinding,
  type MCPScanResult,
  
  // Integration helpers
  makeGuardrailHook,
  detectMissingGuardrail,
} from "./guardrail";

export const VERSION = "4.1.0";
export const STANDARD = "CCS v4.1";
export const DOI = "10.5281/zenodo.21271910";
