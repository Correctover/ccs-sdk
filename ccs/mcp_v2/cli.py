"""
CLI for MCP v2 migration detection.

Usage:
    python -m ccs.mcp_v2.cli /path/to/mcp-server [--json] [--name my-server]
"""

import sys
import json
import argparse
from .detector import MCPv2Detector


def main():
    parser = argparse.ArgumentParser(description="CCS MCP v2 Migration Detector")
    parser.add_argument("path", help="Path to MCP Server codebase")
    parser.add_argument("--name", default="unknown", help="Server name for report")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()

    detector = MCPv2Detector(args.path)
    result = detector.scan(server_name=args.name)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(f"=== MCP v2 Migration Scan: {result.server_name} ===")
        print(f"SDK: {result.mcp_sdk_version or 'not detected'}")
        print(f"Language: {result.sdk_language or 'not detected'}")
        print(f"Compatible: {'YES' if result.compatible else 'NO'}")
        print()
        summary = result.summary()
        print(f"Findings: {summary['critical']} critical, {summary['high']} high, "
              f"{summary['medium']} medium, {summary['info']} info")
        print()
        if result.findings:
            for f in result.findings:
                icon = {"critical": "🔴", "high": "🟡", "medium": "🟠", "info": "ℹ️"}
                print(f"  {icon[f.severity.value]} {f.rule_id}: {f.title}")
                print(f"     {f.file_path}:{f.line_number}")
                print(f"     → {f.migration_path}")
                print()
        else:
            print("  ✅ No MCP v2 incompatibilities detected.")


if __name__ == "__main__":
    main()
