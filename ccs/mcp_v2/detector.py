"""
MCP v2 Compatibility Detector

Scans MCP Server codebases for incompatibilities with the 2026-07-28 specification.
Returns structured detection results with severity, migration path, and deadline.
"""

import os
import re
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any
from pathlib import Path


class Severity(Enum):
    CRITICAL = "critical"    # Will break on 7/28
    HIGH = "high"            # Deprecated, 12-month window
    MEDIUM = "medium"        # Needs attention, functional but suboptimal
    INFO = "info"            # Advisory


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    title: str
    description: str
    file_path: str
    line_number: int
    migration_path: str
    deadline: str  # ISO date or "2026-07-28"


@dataclass
class DetectionResult:
    server_name: str
    mcp_sdk_version: Optional[str] = None
    sdk_language: Optional[str] = None
    findings: List[Finding] = field(default_factory=list)
    compatible: bool = True
    scan_timestamp: str = ""

    def summary(self) -> Dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "info": 0}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "server_name": self.server_name,
            "mcp_sdk_version": self.mcp_sdk_version,
            "sdk_language": self.sdk_language,
            "compatible": self.compatible,
            "summary": self.summary(),
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity.value,
                    "title": f.title,
                    "description": f.description,
                    "file": f.file_path,
                    "line": f.line_number,
                    "migration": f.migration_path,
                    "deadline": f.deadline,
                }
                for f in self.findings
            ],
        }


class MCPv2Detector:
    """
    Scans an MCP Server codebase for 2026-07-28 spec incompatibilities.

    Detection rules:
    - MV2-001: Uses @modelcontextprotocol/sdk (v1 monolithic package)
    - MV2-002: Depends on Mcp-Session-Id / initialize handshake
    - MV2-003: Uses deprecated Roots API
    - MV2-004: Uses deprecated Sampling API (createMessage)
    - MV2-005: Uses deprecated Logging API (logging/setLevel)
    - MV2-006: Hardcodes error code -32002 (now -32602)
    - MV2-007: SSE transport (removed in v2, use Streamable HTTP)
    - MV2-008: Sticky session assumptions
    - MV2-009: Python mcp==1.x without v2 upgrade path
    - MV2-010: Missing _meta propagation for stateless requests
    """

    DEADLINE = "2026-07-28"

    # Rule definitions
    RULES = {
        "MV2-001": {
            "severity": Severity.CRITICAL,
            "title": "V1 SDK package: @modelcontextprotocol/sdk",
            "patterns": [
                r'@modelcontextprotocol/sdk',
                r'from\s+"@modelcontextprotocol/sdk',
                r'require\(["\']@modelcontextprotocol/sdk',
            ],
            "migration": "Migrate to @modelcontextprotocol/server and @modelcontextprotocol/client (v2 split packages)",
            "file_types": [".ts", ".js", ".json", ".mjs"],
        },
        "MV2-002": {
            "severity": Severity.CRITICAL,
            "title": "Stateful session: Mcp-Session-Id or initialize handshake",
            "patterns": [
                r'Mcp-Session-Id',
                r'mcp-session-id',
                r'mcpSessionId',
                r'\.initialize\(\)',
                r'initialize.*initialized',
            ],
            "migration": "Remove session management; protocol is now stateless. Use server/discover for capabilities.",
            "file_types": [".ts", ".js", ".py", ".go", ".cs"],
        },
        "MV2-003": {
            "severity": Severity.HIGH,
            "title": "Deprecated: Roots API",
            "patterns": [
                r'listRoots',
                r'roots/list',
                r'\.roots\b',
                r'RootsCapability',
            ],
            "migration": "Replace with tool parameters, resource URIs, or server configuration.",
            "file_types": [".ts", ".js", ".py", ".go"],
        },
        "MV2-004": {
            "severity": Severity.HIGH,
            "title": "Deprecated: Sampling API (createMessage)",
            "patterns": [
                r'createMessage',
                r'sampling/createMessage',
                r'SamplingCapability',
                r'server\.sampling',
            ],
            "migration": "Replace with direct LLM provider API calls or InputRequiredResult pattern.",
            "file_types": [".ts", ".js", ".py", ".go"],
        },
        "MV2-005": {
            "severity": Severity.HIGH,
            "title": "Deprecated: Protocol Logging API",
            "patterns": [
                r'logging/setLevel',
                r'setLevel.*log',
                r'LoggingCapability',
                r'server\.logging',
                r'\.log\(".*",\s*LoggingLevel',
            ],
            "migration": "Replace with stderr (stdio transports) or OpenTelemetry (structured observability).",
            "file_types": [".ts", ".js", ".py", ".go"],
        },
        "MV2-006": {
            "severity": Severity.CRITICAL,
            "title": "Hardcoded error code -32002 (changed to -32602)",
            "patterns": [
                r'-32002',
                r'32002',
            ],
            "migration": "Replace -32002 with standard JSON-RPC -32602 (Invalid Params) for resource-not-found errors.",
            "file_types": [".ts", ".js", ".py", ".go", ".cs"],
        },
        "MV2-007": {
            "severity": Severity.CRITICAL,
            "title": "SSE transport removed (use Streamable HTTP)",
            "patterns": [
                r'SSEServerTransport',
                r'SSEClientTransport',
                r'text/event-stream',
                r'sse.*transport',
                r'SSE.*Transport',
            ],
            "migration": "Replace SSE transport with Streamable HTTP transport. Single endpoint, stateless.",
            "file_types": [".ts", ".js", ".py", ".go"],
        },
        "MV2-008": {
            "severity": Severity.MEDIUM,
            "title": "Sticky session / session affinity assumptions",
            "patterns": [
                r'sticky',
                r'session.*affin',
                r'affinity.*cookie',
                r'session.*store',
                r'sessionStore',
            ],
            "migration": "Remove session affinity. Stateless protocol allows round-robin load balancing.",
            "file_types": [".ts", ".js", ".py", ".go", ".yaml", ".yml", ".json"],
        },
        "MV2-009": {
            "severity": Severity.CRITICAL,
            "title": "Python mcp v1 dependency (needs 2.0 upgrade)",
            "patterns": [
                r'"mcp[<>=~!]',
                r"mcp==1\.",
                r"mcp>=1\.",
                r"mcp~=1\.",
                r'"mcp":\s*"1\.',
                r'mcp\[.*\]==1\.',
            ],
            "migration": "Upgrade to mcp>=2.0.0. FastMCP→MCPServer rename. Pin: mcp==2.0.0b1 for beta.",
            "file_types": [".py", ".toml", ".txt", ".cfg", ".lock"],
        },
        "MV2-010": {
            "severity": Severity.MEDIUM,
            "title": "Missing _meta propagation for stateless requests",
            "patterns": [
                r'_meta',
            ],
            "migration": "Ensure _meta fields propagate clientInfo, trace context in every request/response.",
            "file_types": [".ts", ".js", ".py", ".go"],
            "negative": True,  # Flag if NOT found
        },
    }

    def __init__(self, target_path: str, exclude_dirs: list = None):
        self.target_path = Path(target_path)
        self.results: List[Finding] = []

    def scan(self, server_name: str = "unknown") -> DetectionResult:
        """Scan target directory for MCP v2 incompatibilities."""
        result = DetectionResult(
            server_name=server_name,
            scan_timestamp=_now_iso(),
        )

        # Detect SDK version from package files
        result.mcp_sdk_version = self._detect_sdk_version()
        result.sdk_language = self._detect_language()

        # Run each detection rule
        for rule_id, rule in self.RULES.items():
            self._scan_rule(rule_id, rule)

        result.findings = self.results
        result.compatible = not any(
            f.severity == Severity.CRITICAL for f in self.results
        )
        return result

    def _scan_rule(self, rule_id: str, rule: Dict[str, Any]) -> None:
        """Scan all matching files for a single rule."""
        severity = rule["severity"]
        patterns = rule["patterns"]
        file_types = rule["file_types"]
        migration = rule["migration"]
        title = rule["title"]
        is_negative = rule.get("negative", False)

        matching_files = self._find_files(file_types)

        if is_negative:
            # Flag if pattern is NOT found anywhere
            found_anywhere = False
            for fpath in matching_files:
                try:
                    content = fpath.read_text(errors="replace")
                    for pat in patterns:
                        if re.search(pat, content):
                            found_anywhere = True
                            break
                    if found_anywhere:
                        break
                except Exception:
                    continue
            if not found_anywhere:
                self.results.append(Finding(
                    rule_id=rule_id,
                    severity=severity,
                    title=title,
                    description=f"Pattern not found in any source file. "
                                f"This may indicate missing stateless request handling.",
                    file_path="(none)",
                    line_number=0,
                    migration_path=migration,
                    deadline=self.DEADLINE,
                ))
        else:
            # Flag each occurrence
            for fpath in matching_files:
                try:
                    lines = fpath.read_text(errors="replace").splitlines()
                except Exception:
                    continue
                for lineno, line in enumerate(lines, 1):
                    for pat in patterns:
                        if re.search(pat, line, re.IGNORECASE):
                            self.results.append(Finding(
                                rule_id=rule_id,
                                severity=severity,
                                title=title,
                                description=f"Match: {line.strip()[:120]}",
                                file_path=str(fpath.relative_to(self.target_path)),
                                line_number=lineno,
                                migration_path=migration,
                                deadline=self.DEADLINE,
                            ))
                            break  # One match per line per rule

    def _find_files(self, extensions: List[str]) -> List[Path]:
        """Find all files with matching extensions, skipping common non-source dirs."""
        skip = {"node_modules", ".git", "__pycache__", "dist", "build", ".venv", "venv", "mcp_v2"}  # mcp_v2 excluded to avoid self-detection
        result = []
        for root, dirs, files in os.walk(self.target_path):
            dirs[:] = [d for d in dirs if d not in skip]
            for fname in files:
                if any(fname.endswith(ext) for ext in extensions):
                    result.append(Path(root) / fname)
        return result

    def _detect_sdk_version(self) -> Optional[str]:
        """Try to detect MCP SDK version from package manifests."""
        # Check package.json for TypeScript
        pkg_json = self.target_path / "package.json"
        if pkg_json.exists():
            try:
                data = json.loads(pkg_json.read_text())
                deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                # v1 monolithic
                if "@modelcontextprotocol/sdk" in deps:
                    return f"ts-v1:{deps['@modelcontextprotocol/sdk']}"
                # v2 split
                if "@modelcontextprotocol/server" in deps:
                    return f"ts-v2:{deps['@modelcontextprotocol/server']}"
            except Exception:
                pass

        # Check pyproject.toml / requirements for Python
        for manifest in ["pyproject.toml", "requirements.txt", "setup.py", "setup.cfg"]:
            fpath = self.target_path / manifest
            if fpath.exists():
                try:
                    content = fpath.read_text()
                    m = re.search(r'mcp[>=<~]*([0-9]+\.[0-9]+[^"\s,\]]*)', content)
                    if m:
                        ver = m.group(1)
                        if ver.startswith("2"):
                            return f"py-v2:{ver}"
                        return f"py-v1:{ver}"
                except Exception:
                    pass
        return None

    def _detect_language(self) -> Optional[str]:
        """Detect primary language of the MCP server."""
        indicators = {
            "typescript": ["tsconfig.json", "package.json"],
            "python": ["pyproject.toml", "setup.py", "requirements.txt"],
            "go": ["go.mod"],
            "csharp": [".csproj"],
        }
        for lang, files in indicators.items():
            for f in files:
                if (self.target_path / f).exists():
                    return lang
        return None


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
