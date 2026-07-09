#!/usr/bin/env python3
"""
CCS Demo: Fail-Open (AGT) vs Fail-Closed (CCS) — Side-by-Side Comparison

This script demonstrates the fundamental architectural difference between
observer-pattern hooks (used by CrewAI AGT, AutoGen, LangGraph) and
interceptor-pattern decorators (used by CCS).

CVE Reference: CWE-636, CVSS 9.1
https://gist.github.com/Correctover/9cfb97bcf374f79b793fd0bacd4e9d62
"""

import sys
sys.path.insert(0, '.')

print("=" * 70)
print("CCS Demo: Observer Hooks vs Interceptor Decorators")
print("=" * 70)

# =============================================================================
# PART 1: Observer-pattern hooks (AGT/CrewAI model) — FAIL-OPEN
# =============================================================================
print("\n--- PART 1: Observer-Pattern Hooks (AGT/CrewAI) ---")
print("Model: Governance observes events, framework decides.\n")

class FakeHookDispatcher:
    """Simulates CrewAI's crew_agent_executor.py:963-977"""
    
    def execute_with_hooks(self, before_hook, tool_func, tool_input):
        hook_blocked = False  # DEFAULT: not blocked
        
        try:
            result = before_hook(tool_input)
            if result is False:
                hook_blocked = True
        except Exception as e:
            # BUG: Only prints error, does NOT set hook_blocked = True
            print(f"  [Hook Dispatcher] Exception caught: {e}")
            print(f"  [Hook Dispatcher] hook_blocked = {hook_blocked} (still False!)")
        
        if hook_blocked:
            return "BLOCKED"
        else:
            return tool_func(tool_input)  # BYPASS!


def crashing_governance(tool_input):
    """Governance that crashes due to bad input"""
    raise ValueError("SnapshotBuilder: non-serializable argument")


def sensitive_tool(tool_input):
    return f"EXECUTED: {tool_input}"


dispatcher = FakeHookDispatcher()
result = dispatcher.execute_with_hooks(
    crashing_governance,
    sensitive_tool,
    {"action": "delete_all_records"}
)
print(f"  Result: {result}")
print(f"  ❌ FAIL-OPEN: Governance crashed, tool still EXECUTED")


# =============================================================================
# PART 2: Interceptor-pattern decorators (CCS) — FAIL-CLOSED
# =============================================================================
print("\n--- PART 2: Interceptor-Pattern Decorators (CCS) ---")
print("Model: CCS decorator owns execution path.\n")

from ccs import govern, CCSPolicy, GovernanceResult, get_runtime

class CrashingPolicy(CCSPolicy):
    """Same crash scenario as Part 1"""
    def evaluate(self, tool_name, tool_input):
        raise ValueError("SnapshotBuilder: non-serializable argument")


runtime = get_runtime()
runtime.register_policy("crash", CrashingPolicy())


@govern(policy="crash")
def ccs_governed_tool(action: str):
    return f"EXECUTED: {action}"


try:
    result = ccs_governed_tool("delete_all_records")
    print(f"  Result: {result}")
    print(f"  ❌ FAIL: Tool should have been blocked!")
except PermissionError as e:
    print(f"  [CCS Runtime] Exception caught in governance evaluation")
    print(f"  [CCS Runtime] Fail-closed: tool NEVER called")
    print(f"  ✅ FAIL-CLOSED: Governance crashed, tool BLOCKED")


# =============================================================================
# SUMMARY
# =============================================================================
print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print("""
  Observer Hooks (AGT/CrewAI):
    governance_crash → exception caught → hook_blocked=False → TOOL EXECUTES ❌
    
  CCS Decorators:
    governance_crash → exception caught → decorator stops → TOOL BLOCKED ✅

  This is NOT a code bug. It's an ARCHITECTURAL property:
  - Hooks observe events but don't control execution → default-allow on failure
  - Decorators own execution path → default-deny on failure

  CVE-2026-XXXX (CWE-636, CVSS 9.1): 100% reproducible, deterministic.
  
  Fix: Replace observer hooks with interceptor decorators (CCS v1.0).
""")
