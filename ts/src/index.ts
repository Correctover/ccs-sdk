/**
 * Correctover Conformance Standard (CCS) v4.0 — TypeScript SDK
 * 
 * Synchronous interceptor-based governance for AI Agent frameworks.
 * Eliminates architectural fail-open bypasses inherent to observer-pattern hooks.
 * 
 * Usage:
 *   import { govern, GovernanceResult, CCSRuntime, MCPv2Detector } from "correctover-ccs";
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

export const VERSION = "4.0.1";
export const STANDARD = "CCS v4.0";
export const DOI = "10.5281/zenodo.21271910";
