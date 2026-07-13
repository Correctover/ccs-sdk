/**
 * MCP v2 Migration Detector — Type Definitions
 * Detects protocol incompatibility with the 2026-07-28 MCP specification.
 */

export enum Severity {
  CRITICAL = "critical",
  HIGH = "high",
  MEDIUM = "medium",
  INFO = "info",
}

export interface Finding {
  rule_id: string;
  severity: Severity;
  title: string;
  description: string;
  file_path: string;
  line_number: number;
  migration_path: string;
  deadline: string;
}

export interface DetectionSummary {
  critical: number;
  high: number;
  medium: number;
  info: number;
}

export interface DetectionResult {
  server_name: string;
  mcp_sdk_version: string | null;
  sdk_language: string | null;
  findings: Finding[];
  compatible: boolean;
  scan_timestamp: string;
  summary: DetectionSummary;
}

export interface RuleDefinition {
  severity: Severity;
  title: string;
  patterns: RegExp[];
  migration: string;
  file_types: string[];
  negative?: boolean;
}
