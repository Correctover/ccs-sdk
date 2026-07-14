"""
CCS MCP Server — Model Context Protocol governance for AI Agents.

Exposes CCS governance as an MCP tool, allowing any MCP-compatible
agent (Claude Desktop, Cursor, Cline, etc.) to validate tool calls
against CCS policies before execution.

Transport: stdio (default for MCP)

Usage:
    python -m ccs_sdk.mcp_server.server

Or configure in Claude Desktop:
    {
        "mcpServers": {
            "ccs": {
                "command": "python",
                "args": ["-m", "ccs_sdk.mcp_server.server"]
            }
        }
    }
"""

from mcp.server.fastmcp import FastMCP
from ccs.core import (
    CCSConfig, CCSPolicy, GovernanceResult,
    get_runtime,
)
from ccs import __version__

# ============================================================
# MCP Server
# ============================================================
mcp = FastMCP(
    "CCS Governance",
    instructions="Correctover Conformance Standard (CCS) v1.0 — "
                 "Synchronous interceptor governance for AI Agent tool calls. "
                 "Validates tool invocations against governance policies with "
                 "structural fail-closed guarantee (CWE-636). "
                 "DOI: 10.5281/zenodo.21271910"
)


@mcp.tool()
def ccs_govern(
    tool_name: str,
    tool_input: dict,
    policy_name: str = "default",
) -> dict:
    """
    Evaluate a tool call against CCS governance policy.

    Returns ALLOW or DENY with latency metrics. If the policy engine
    crashes, returns DENY (fail-closed guarantee).

    Args:
        tool_name: Name of the tool being called (e.g., "search_web")
        tool_input: Arguments dict for the tool (e.g., {"query": "..."})
        policy_name: CCS policy to evaluate against (default: "default")

    Returns:
        dict with:
          - result: "allow" | "deny" | "error"
          - latency_us: governance evaluation latency in microseconds
          - tool_name: echo of the tool name
          - policy_name: echo of the policy used
          - fail_closed: True if denied due to error (not policy logic)
    """
    runtime = get_runtime()
    result, latency_us = runtime.evaluate(
        tool_name=tool_name,
        tool_input=tool_input,
        policy_name=policy_name,
    )

    is_error = result == GovernanceResult.ERROR
    return {
        "result": result.value,
        "latency_us": latency_us,
        "tool_name": tool_name,
        "policy_name": policy_name,
        "fail_closed": is_error,
    }


@mcp.tool()
def ccs_status() -> dict:
    """
    Get CCS governance runtime status and performance metrics.

    Returns total evaluations, deny/allow counts, and latency
    percentiles (P50, P99, max).
    """
    runtime = get_runtime()
    stats = runtime.get_stats()

    # Add registered policies info
    stats["registered_policies"] = list(runtime.policies.keys())
    stats["total_traces"] = len(runtime.traces)
    stats["version"] = __version__
    stats["standard"] = "CCS v1.0"
    stats["doi"] = "10.5281/zenodo.21271910"

    return stats


@mcp.tool()
def ccs_register_deny_rule(
    rule_name: str,
    denied_tools: list[str] | None = None,
    denied_patterns: list[str] | None = None,
) -> dict:
    """
    Register a custom deny policy. Tools matching the denied list
    or patterns will be blocked; all others pass through.

    Args:
        rule_name: Name for this policy (e.g., "block_dangerous_tools")
        denied_tools: Exact tool names to deny (e.g., ["rm", "delete_file"])
        denied_patterns: Substring patterns to deny (e.g., ["delete", "destroy"])

    Returns:
        dict confirming registration with rule details
    """
    denied_tools = denied_tools or []
    denied_patterns = denied_patterns or []

    class DenyRulePolicy(CCSPolicy):
        def __init__(self, tools, patterns):
            self.tools = set(tools)
            self.patterns = patterns

        def evaluate(self, tool_name, tool_input):
            # Exact match
            if tool_name in self.tools:
                return GovernanceResult.DENY
            # Pattern match
            for pattern in self.patterns:
                if pattern.lower() in tool_name.lower():
                    return GovernanceResult.DENY
                # Also check tool input values
                for v in tool_input.values():
                    if isinstance(v, str) and pattern.lower() in v.lower():
                        return GovernanceResult.DENY
            return GovernanceResult.ALLOW

    runtime = get_runtime()
    runtime.register_policy(
        rule_name,
        DenyRulePolicy(denied_tools, denied_patterns)
    )

    return {
        "status": "registered",
        "rule_name": rule_name,
        "denied_tools": denied_tools,
        "denied_patterns": denied_patterns,
        "available_policies": list(runtime.policies.keys()),
    }


@mcp.tool()
def ccs_audit_log(limit: int = 20) -> list[dict]:
    """
    Retrieve recent CCS governance audit traces.

    Each trace includes: timestamp, tool_name, result, latency_us,
    policy_name, input_hash, and detail.

    Args:
        limit: Maximum number of recent traces to return (default: 20)

    Returns:
        List of audit trace dicts, most recent first
    """
    runtime = get_runtime()
    traces = runtime.traces[-limit:] if runtime.traces else []

    return [
        {
            "timestamp": t.timestamp,
            "tool_name": t.tool_name,
            "result": t.result.value,
            "latency_us": t.latency_us,
            "policy_name": t.policy_name,
            "input_hash": t.input_hash,
            "detail": t.detail,
        }
        for t in reversed(traces)
    ]


# ============================================================
# Entry point
# ============================================================
if __name__ == "__main__":
    mcp.run()
