/**
 * Correctover Conformance Standard (CCS) v1.0 — TypeScript SDK
 * 
 * Synchronous interceptor-based governance for AI Agent frameworks.
 * Eliminates architectural fail-open bypasses inherent to observer-pattern hooks.
 * 
 * Usage:
 *   import { govern, GovernanceResult, CCSRuntime } from "@correctover/ccs";
 *   
 *   const governedFn = govern(myToolFunction, { policy: "default" });
 *   governedFn(args); // Throws PermissionError if governance denies
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

export const VERSION = "1.0.0";
export const STANDARD = "CCS v1.0";
export const DOI = "10.5281/zenodo.21271910";
