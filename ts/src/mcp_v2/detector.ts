/**
 * MCP v2 Compatibility Detector — TypeScript Implementation
 * Scans MCP Server codebases for incompatibilities with the 2026-07-28 specification.
 */

import * as fs from "fs";
import * as path from "path";
import {
  Severity,
  Finding,
  DetectionResult,
  DetectionSummary,
  RuleDefinition,
} from "./types";

const SKIP_DIRS = new Set([
  "node_modules", ".git", "__pycache__", "dist", "build",
  ".venv", "venv", "mcp_v2", ".next", ".nuxt",
]);

const DEADLINE = "2026-07-28";

function nowISO(): string {
  return new Date().toISOString();
}

/** All 10 detection rules, ported from Python implementation */
const RULES: Record<string, RuleDefinition> = {
  "MV2-001": {
    severity: Severity.CRITICAL,
    title: "V1 SDK package: @modelcontextprotocol/sdk",
    patterns: [
      /@modelcontextprotocol\/sdk/,
      /from\s+["']@modelcontextprotocol\/sdk/,
      /require\(["']@modelcontextprotocol\/sdk/,
    ],
    migration: "Migrate to @modelcontextprotocol/server and @modelcontextprotocol/client (v2 split packages)",
    file_types: [".ts", ".js", ".json", ".mjs"],
  },
  "MV2-002": {
    severity: Severity.CRITICAL,
    title: "Stateful session: Mcp-Session-Id or initialize handshake",
    patterns: [
      /Mcp-Session-Id/,
      /mcp-session-id/,
      /mcpSessionId/,
      /\.initialize\(\)/,
      /initialize.*initialized/,
    ],
    migration: "Remove session management; protocol is now stateless. Use server/discover for capabilities.",
    file_types: [".ts", ".js", ".py", ".go", ".cs"],
  },
  "MV2-003": {
    severity: Severity.HIGH,
    title: "Deprecated: Roots API",
    patterns: [/listRoots/, /roots\/list/, /\.roots\b/, /RootsCapability/],
    migration: "Replace with tool parameters, resource URIs, or server configuration.",
    file_types: [".ts", ".js", ".py", ".go"],
  },
  "MV2-004": {
    severity: Severity.HIGH,
    title: "Deprecated: Sampling API (createMessage)",
    patterns: [/createMessage/, /sampling\/createMessage/, /SamplingCapability/, /server\.sampling/],
    migration: "Replace with direct LLM provider API calls or InputRequiredResult pattern.",
    file_types: [".ts", ".js", ".py", ".go"],
  },
  "MV2-005": {
    severity: Severity.HIGH,
    title: "Deprecated: Protocol Logging API",
    patterns: [
      /logging\/setLevel/,
      /setLevel.*log/,
      /LoggingCapability/,
      /server\.logging/,
      /\.log\(".*",\s*LoggingLevel/,
    ],
    migration: "Replace with stderr (stdio transports) or OpenTelemetry (structured observability).",
    file_types: [".ts", ".js", ".py", ".go"],
  },
  "MV2-006": {
    severity: Severity.CRITICAL,
    title: "Hardcoded error code -32002 (changed to -32602)",
    patterns: [/-32002/, /32002/],
    migration: "Replace -32002 with standard JSON-RPC -32602 (Invalid Params) for resource-not-found errors.",
    file_types: [".ts", ".js", ".py", ".go", ".cs"],
  },
  "MV2-007": {
    severity: Severity.CRITICAL,
    title: "SSE transport removed (use Streamable HTTP)",
    patterns: [
      /SSEServerTransport/,
      /SSEClientTransport/,
      /text\/event-stream/,
      /sse.*transport/i,
      /SSE.*Transport/,
    ],
    migration: "Replace SSE transport with Streamable HTTP transport. Single endpoint, stateless.",
    file_types: [".ts", ".js", ".py", ".go"],
  },
  "MV2-008": {
    severity: Severity.MEDIUM,
    title: "Sticky session / session affinity assumptions",
    patterns: [/sticky/i, /session.*affin/i, /affinity.*cookie/i, /session.*store/i, /sessionStore/],
    migration: "Remove session affinity. Stateless protocol allows round-robin load balancing.",
    file_types: [".ts", ".js", ".py", ".go", ".yaml", ".yml", ".json"],
  },
  "MV2-009": {
    severity: Severity.CRITICAL,
    title: "Python mcp v1 dependency (needs 2.0 upgrade)",
    patterns: [
      /["']mcp[<>=~!]/,
      /mcp==1\./,
      /mcp>=1\./,
      /mcp~=1\./,
      /"mcp":\s*"1\./,
      /mcp\[.*\]==1\./,
    ],
    migration: "Upgrade to mcp>=2.0.0. FastMCP→MCPServer rename. Pin: mcp==2.0.0b1 for beta.",
    file_types: [".py", ".toml", ".txt", ".cfg", ".lock"],
  },
  "MV2-010": {
    severity: Severity.MEDIUM,
    title: "Missing _meta propagation for stateless requests",
    patterns: [/_meta/],
    migration: "Ensure _meta fields propagate clientInfo, trace context in every request/response.",
    file_types: [".ts", ".js", ".py", ".go"],
    negative: true,
  },
};

export class MCPv2Detector {
  private targetPath: string;
  private findings: Finding[] = [];

  constructor(targetPath: string) {
    this.targetPath = targetPath;
  }

  scan(serverName = "unknown"): DetectionResult {
    this.findings = [];

    const mcpSdkVersion = this.detectSdkVersion();
    const sdkLanguage = this.detectLanguage();

    for (const [ruleId, rule] of Object.entries(RULES)) {
      this.scanRule(ruleId, rule);
    }

    const summary: DetectionSummary = { critical: 0, high: 0, medium: 0, info: 0 };
    for (const f of this.findings) {
      const key = f.severity as keyof DetectionSummary;
      summary[key]++;
    }

    const compatible = !this.findings.some((f) => f.severity === Severity.CRITICAL);

    return {
      server_name: serverName,
      mcp_sdk_version: mcpSdkVersion,
      sdk_language: sdkLanguage,
      findings: this.findings,
      compatible,
      scan_timestamp: nowISO(),
      summary,
    };
  }

  private scanRule(ruleId: string, rule: RuleDefinition): void {
    const files = this.findFiles(rule.file_types);
    const isNegative = rule.negative ?? false;

    if (isNegative) {
      let foundAnywhere = false;
      for (const fpath of files) {
        try {
          const content = fs.readFileSync(fpath, "utf-8");
          for (const pat of rule.patterns) {
            if (pat.test(content)) {
              foundAnywhere = true;
              break;
            }
          }
          if (foundAnywhere) break;
        } catch {
          continue;
        }
      }
      if (!foundAnywhere) {
        this.findings.push({
          rule_id: ruleId,
          severity: rule.severity,
          title: rule.title,
          description: "Pattern not found in any source file. This may indicate missing stateless request handling.",
          file_path: "(none)",
          line_number: 0,
          migration_path: rule.migration,
          deadline: DEADLINE,
        });
      }
    } else {
      for (const fpath of files) {
        try {
          const lines = fs.readFileSync(fpath, "utf-8").split("\n");
          const relPath = path.relative(this.targetPath, fpath);
          for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            for (const pat of rule.patterns) {
              if (pat.test(line)) {
                this.findings.push({
                  rule_id: ruleId,
                  severity: rule.severity,
                  title: rule.title,
                  description: `Match: ${line.trim().slice(0, 120)}`,
                  file_path: relPath,
                  line_number: i + 1,
                  migration_path: rule.migration,
                  deadline: DEADLINE,
                });
                break;
              }
            }
          }
        } catch {
          continue;
        }
      }
    }
  }

  private findFiles(extensions: string[]): string[] {
    const result: string[] = [];
    const walk = (dir: string) => {
      let entries: fs.Dirent[];
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
      } catch {
        return;
      }
      for (const entry of entries) {
        if (SKIP_DIRS.has(entry.name)) continue;
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          walk(fullPath);
        } else if (entry.isFile()) {
          if (extensions.some((ext) => entry.name.endsWith(ext))) {
            result.push(fullPath);
          }
        }
      }
    };
    walk(this.targetPath);
    return result;
  }

  private detectSdkVersion(): string | null {
    const pkgJson = path.join(this.targetPath, "package.json");
    if (fs.existsSync(pkgJson)) {
      try {
        const data = JSON.parse(fs.readFileSync(pkgJson, "utf-8"));
        const deps = { ...data.dependencies, ...data.devDependencies };
        if (deps["@modelcontextprotocol/sdk"]) {
          return `ts-v1:${deps["@modelcontextprotocol/sdk"]}`;
        }
        if (deps["@modelcontextprotocol/server"]) {
          return `ts-v2:${deps["@modelcontextprotocol/server"]}`;
        }
      } catch {}
    }

    for (const manifest of ["pyproject.toml", "requirements.txt", "setup.py", "setup.cfg"]) {
      const fpath = path.join(this.targetPath, manifest);
      if (fs.existsSync(fpath)) {
        try {
          const content = fs.readFileSync(fpath, "utf-8");
          const m = /mcp[>=<~]*([0-9]+\.[0-9]+[^"\s,\]]*)/.exec(content);
          if (m) {
            const ver = m[1];
            return ver.startsWith("2") ? `py-v2:${ver}` : `py-v1:${ver}`;
          }
        } catch {}
      }
    }
    return null;
  }

  private detectLanguage(): string | null {
    const indicators: Record<string, string[]> = {
      typescript: ["tsconfig.json", "package.json"],
      python: ["pyproject.toml", "setup.py", "requirements.txt"],
      go: ["go.mod"],
      csharp: [".csproj"],
    };
    for (const [lang, files] of Object.entries(indicators)) {
      for (const f of files) {
        if (fs.existsSync(path.join(this.targetPath, f))) {
          return lang;
        }
      }
    }
    return null;
  }
}
