/**
 * CCS MCP v2 Migration Detector — TypeScript SDK
 * 
 * Detects protocol incompatibility with the 2026-07-28 MCP specification.
 * 10 rules: MV2-001 ~ MV2-010
 * 
 * Usage:
 *   import { MCPv2Detector } from "correctover-ccs/mcp_v2";
 *   
 *   const detector = new MCPv2Detector("/path/to/mcp-server");
 *   const result = detector.scan("my-server");
 *   console.log(`Compatible: ${result.compatible}`);
 *   console.log(`Findings: ${result.findings.length}`);
 */

export { MCPv2Detector } from "./detector";
export { Severity } from "./types";
export type {
  Finding,
  DetectionResult,
  DetectionSummary,
  RuleDefinition,
} from "./types";
