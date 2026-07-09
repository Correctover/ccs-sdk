#!/usr/bin/env python3
"""
CCS SDK — 9-Test Strict Verification Suite
===========================================
3 frameworks × 3 scenarios = 9 tests
Each test: install → verify interception → uninstall → verify restoration

Test Matrix:
  T1: CrewAI  — ALLOW (policy permits → tool executes normally)
  T2: CrewAI  — DENY   (policy blocks → PermissionError, tool NEVER runs)
  T3: CrewAI  — FAIL-CLOSED (policy raises → PermissionError, tool NEVER runs)
  T4: AutoGen — ALLOW
  T5: AutoGen — DENY
  T6: AutoGen — FAIL-CLOSED
  T7: LangGraph — ALLOW
  T8: LangGraph — DENY
  T9: LangGraph — FAIL-CLOSED

Each test also verifies:
  - install() patches the correct method
  - uninstall() restores original behavior
  - No state leakage between tests
"""

import sys
import asyncio
import traceback

# ============================================================
# Reset CCS global state between tests
# ============================================================
def reset_ccs_runtime():
    """Reset the global CCS runtime singleton to avoid state leakage."""
    import ccs.core as core
    core._runtime = None

# ============================================================
# Test Tool Tracking
# ============================================================
class TestTracker:
    """Track whether tool functions actually executed."""
    def __init__(self):
        self.call_count = 0
        self.last_args = None
    
    def reset(self):
        self.call_count = 0
        self.last_args = None

tracker = TestTracker()

# ============================================================
# RESULT REPORTING
# ============================================================
results = []

def report(test_num, name, passed, detail=""):
    status = "✅ PASS" if passed else "❌ FAIL"
    results.append((test_num, name, passed, detail))
    print(f"\n{'='*60}")
    print(f"  T{test_num}: {name} → {status}")
    if detail:
        print(f"  Detail: {detail}")
    print(f"{'='*60}")


# ============================================================
# CREWAI TESTS (T1, T2, T3)
# ============================================================
def run_crewai_tests():
    from crewai.tools.base_tool import BaseTool
    from ccs.core import CCSPolicy, GovernanceResult, get_runtime
    
    # --- T1: CrewAI ALLOW ---
    tracker.reset()
    reset_ccs_runtime()
    
    class AllowAllPolicy(CCSPolicy):
        def evaluate(self, tool_name, tool_input):
            return GovernanceResult.ALLOW
    
    runtime = get_runtime()
    runtime.register_policy("allow_all", AllowAllPolicy())
    
    class TestCrewTool(BaseTool):
        name: str = "test_tool"
        description: str = "A test tool"
        
        def _run(self, *args, **kwargs):
            tracker.call_count += 1
            tracker.last_args = args
            return "crewai_result"
    
    from ccs.adapters import crewai_adapter
    crewai_adapter.install(policy="allow_all")
    
    tool = TestCrewTool()
    try:
        result = tool.run("hello", "world")
        t1_pass = (tracker.call_count == 1 and result == "crewai_result")
        report(1, "CrewAI ALLOW", t1_pass, 
               f"call_count={tracker.call_count}, result={result}")
    except Exception as e:
        report(1, "CrewAI ALLOW", False, f"Unexpected exception: {e}")
    
    # Verify uninstall restores
    crewai_adapter.uninstall()
    tracker.reset()
    tool2 = TestCrewTool()
    try:
        result2 = tool2.run("after_uninstall")
        uninstall_ok = (tracker.call_count == 1 and result2 == "crewai_result")
    except:
        uninstall_ok = False
    if not uninstall_ok:
        report(1, "CrewAI ALLOW (uninstall check)", False, "Uninstall failed to restore")
    
    # --- T2: CrewAI DENY ---
    tracker.reset()
    reset_ccs_runtime()
    
    class DenyAllPolicy(CCSPolicy):
        def evaluate(self, tool_name, tool_input):
            return GovernanceResult.DENY
    
    runtime = get_runtime()
    runtime.register_policy("deny_all", DenyAllPolicy())
    
    from ccs.adapters import crewai_adapter as ca2
    ca2.install(policy="deny_all")
    
    tool = TestCrewTool()
    denied = False
    try:
        tool.run("should_be_blocked")
    except PermissionError as e:
        denied = True
    except Exception as e:
        report(2, "CrewAI DENY", False, f"Wrong exception type: {type(e).__name__}: {e}")
        ca2.uninstall()
        return
    
    t2_pass = (denied and tracker.call_count == 0)
    report(2, "CrewAI DENY", t2_pass,
           f"denied={denied}, tool_executed={tracker.call_count > 0}")
    ca2.uninstall()
    
    # --- T3: CrewAI FAIL-CLOSED ---
    tracker.reset()
    reset_ccs_runtime()
    
    class CrashPolicy(CCSPolicy):
        def evaluate(self, tool_name, tool_input):
            raise RuntimeError("Policy engine crashed!")
    
    runtime = get_runtime()
    runtime.register_policy("crash", CrashPolicy())
    
    from ccs.adapters import crewai_adapter as ca3
    ca3.install(policy="crash")
    
    tool = TestCrewTool()
    blocked = False
    try:
        tool.run("should_be_blocked_by_crash")
    except PermissionError as e:
        blocked = True
    except RuntimeError:
        # This would mean the crash leaked through — NOT fail-closed
        report(3, "CrewAI FAIL-CLOSED", False, 
               "RuntimeError leaked — policy exception NOT caught by runtime!")
        ca3.uninstall()
        return
    except Exception as e:
        report(3, "CrewAI FAIL-CLOSED", False, 
               f"Wrong exception: {type(e).__name__}: {e}")
        ca3.uninstall()
        return
    
    t3_pass = (blocked and tracker.call_count == 0)
    report(3, "CrewAI FAIL-CLOSED", t3_pass,
           f"blocked={blocked}, tool_executed={tracker.call_count > 0}")
    ca3.uninstall()


# ============================================================
# AUTOGEN TESTS (T4, T5, T6)
# ============================================================
async def run_autogen_tests():
    from autogen_core.tools import FunctionTool
    from autogen_core import CancellationToken
    from ccs.core import CCSPolicy, GovernanceResult, get_runtime
    from pydantic import BaseModel
    
    class ToolArgs(BaseModel):
        query: str = "test"
    
    def sample_function(query: str = "default") -> str:
        tracker.call_count += 1
        tracker.last_args = query
        return "autogen_result"
    
    # --- T4: AutoGen ALLOW ---
    tracker.reset()
    reset_ccs_runtime()
    
    class AllowAllPolicy(CCSPolicy):
        def evaluate(self, tool_name, tool_input):
            return GovernanceResult.ALLOW
    
    runtime = get_runtime()
    runtime.register_policy("allow_all", AllowAllPolicy())
    
    from ccs.adapters import autogen_adapter
    autogen_adapter.install(policy="allow_all")
    
    token = CancellationToken()
    tool = FunctionTool(
        func=sample_function,
        description="A test function",
        name="test_autogen_tool",
    )
    
    try:
        result = await tool.run(ToolArgs(query="hello"), token)
        t4_pass = (tracker.call_count == 1 and result == "autogen_result")
        report(4, "AutoGen ALLOW", t4_pass,
               f"call_count={tracker.call_count}, result={result}")
    except Exception as e:
        report(4, "AutoGen ALLOW", False, f"Unexpected exception: {type(e).__name__}: {e}")
    
    # Verify uninstall
    autogen_adapter.uninstall()
    tracker.reset()
    tool2 = FunctionTool(
        func=sample_function,
        description="A test function",
        name="test_autogen_tool_2",
    )
    try:
        result2 = await tool2.run(ToolArgs(query="after_uninstall"), token)
        uninstall_ok = (tracker.call_count == 1 and result2 == "autogen_result")
    except:
        uninstall_ok = False
    if not uninstall_ok:
        report(4, "AutoGen ALLOW (uninstall check)", False, "Uninstall failed")
    
    # --- T5: AutoGen DENY ---
    tracker.reset()
    reset_ccs_runtime()
    
    class DenyAllPolicy(CCSPolicy):
        def evaluate(self, tool_name, tool_input):
            return GovernanceResult.DENY
    
    runtime = get_runtime()
    runtime.register_policy("deny_all", DenyAllPolicy())
    
    from ccs.adapters import autogen_adapter as ag2
    ag2.install(policy="deny_all")
    
    tool = FunctionTool(
        func=sample_function,
        description="A test function",
        name="test_autogen_deny",
    )
    
    denied = False
    try:
        await tool.run(ToolArgs(), token)
    except PermissionError:
        denied = True
    except Exception as e:
        report(5, "AutoGen DENY", False, f"Wrong exception: {type(e).__name__}: {e}")
        ag2.uninstall()
        return
    
    t5_pass = (denied and tracker.call_count == 0)
    report(5, "AutoGen DENY", t5_pass,
           f"denied={denied}, tool_executed={tracker.call_count > 0}")
    ag2.uninstall()
    
    # --- T6: AutoGen FAIL-CLOSED ---
    tracker.reset()
    reset_ccs_runtime()
    
    class CrashPolicy(CCSPolicy):
        def evaluate(self, tool_name, tool_input):
            raise RuntimeError("AutoGen policy engine crashed!")
    
    runtime = get_runtime()
    runtime.register_policy("crash", CrashPolicy())
    
    from ccs.adapters import autogen_adapter as ag3
    ag3.install(policy="crash")
    
    tool = FunctionTool(
        func=sample_function,
        description="A test function",
        name="test_autogen_crash",
    )
    
    blocked = False
    try:
        await tool.run(ToolArgs(), token)
    except PermissionError:
        blocked = True
    except RuntimeError:
        report(6, "AutoGen FAIL-CLOSED", False,
               "RuntimeError leaked — NOT fail-closed!")
        ag3.uninstall()
        return
    except Exception as e:
        report(6, "AutoGen FAIL-CLOSED", False,
               f"Wrong exception: {type(e).__name__}: {e}")
        ag3.uninstall()
        return
    
    t6_pass = (blocked and tracker.call_count == 0)
    report(6, "AutoGen FAIL-CLOSED", t6_pass,
           f"blocked={blocked}, tool_executed={tracker.call_count > 0}")
    ag3.uninstall()


# ============================================================
# LANGGRAPH TESTS (T7, T8, T9)
# ============================================================
def run_langgraph_tests():
    from langchain_core.tools import BaseTool as LCBaseTool
    from ccs.core import CCSPolicy, GovernanceResult, get_runtime
    from typing import Type
    from pydantic import BaseModel, Field
    
    class TestInput(BaseModel):
        query: str = Field(default="test")
    
    class TestLCTool(LCBaseTool):
        name: str = "test_lc_tool"
        description: str = "A test LangChain tool"
        args_schema: Type[BaseModel] = TestInput
        
        def _run(self, query: str = "test", *args, **kwargs):
            tracker.call_count += 1
            tracker.last_args = query
            return "langgraph_result"
    
    # --- T7: LangGraph ALLOW ---
    tracker.reset()
    reset_ccs_runtime()
    
    class AllowAllPolicy(CCSPolicy):
        def evaluate(self, tool_name, tool_input):
            return GovernanceResult.ALLOW
    
    runtime = get_runtime()
    runtime.register_policy("allow_all", AllowAllPolicy())
    
    from ccs.adapters import langgraph_adapter
    langgraph_adapter.install(policy="allow_all")
    
    tool = TestLCTool()
    try:
        result = tool.run({"query": "hello"})
        t7_pass = (tracker.call_count == 1 and result == "langgraph_result")
        report(7, "LangGraph ALLOW", t7_pass,
               f"call_count={tracker.call_count}, result={result}")
    except Exception as e:
        report(7, "LangGraph ALLOW", False, f"Unexpected exception: {type(e).__name__}: {e}")
    
    # Verify uninstall
    langgraph_adapter.uninstall()
    tracker.reset()
    tool2 = TestLCTool()
    try:
        result2 = tool2.run({"query": "after_uninstall"})
        uninstall_ok = (tracker.call_count == 1 and result2 == "langgraph_result")
    except:
        uninstall_ok = False
    if not uninstall_ok:
        report(7, "LangGraph ALLOW (uninstall check)", False, "Uninstall failed")
    
    # --- T8: LangGraph DENY ---
    tracker.reset()
    reset_ccs_runtime()
    
    class DenyAllPolicy(CCSPolicy):
        def evaluate(self, tool_name, tool_input):
            return GovernanceResult.DENY
    
    runtime = get_runtime()
    runtime.register_policy("deny_all", DenyAllPolicy())
    
    from ccs.adapters import langgraph_adapter as lg2
    lg2.install(policy="deny_all")
    
    tool = TestLCTool()
    denied = False
    try:
        tool.run({"query": "should_block"})
    except PermissionError:
        denied = True
    except Exception as e:
        report(8, "LangGraph DENY", False, f"Wrong exception: {type(e).__name__}: {e}")
        lg2.uninstall()
        return
    
    t8_pass = (denied and tracker.call_count == 0)
    report(8, "LangGraph DENY", t8_pass,
           f"denied={denied}, tool_executed={tracker.call_count > 0}")
    lg2.uninstall()
    
    # --- T9: LangGraph FAIL-CLOSED ---
    tracker.reset()
    reset_ccs_runtime()
    
    class CrashPolicy(CCSPolicy):
        def evaluate(self, tool_name, tool_input):
            raise RuntimeError("LangGraph policy engine crashed!")
    
    runtime = get_runtime()
    runtime.register_policy("crash", CrashPolicy())
    
    from ccs.adapters import langgraph_adapter as lg3
    lg3.install(policy="crash")
    
    tool = TestLCTool()
    blocked = False
    try:
        tool.run({"query": "should_block_by_crash"})
    except PermissionError:
        blocked = True
    except RuntimeError:
        report(9, "LangGraph FAIL-CLOSED", False,
               "RuntimeError leaked — NOT fail-closed!")
        lg3.uninstall()
        return
    except Exception as e:
        report(9, "LangGraph FAIL-CLOSED", False,
               f"Wrong exception: {type(e).__name__}: {e}")
        lg3.uninstall()
        return
    
    t9_pass = (blocked and tracker.call_count == 0)
    report(9, "LangGraph FAIL-CLOSED", t9_pass,
           f"blocked={blocked}, tool_executed={tracker.call_count > 0}")
    lg3.uninstall()


# ============================================================
# MAIN
# ============================================================
def main():
    print("=" * 60)
    print("  CCS SDK — 9-Test Strict Verification Suite")
    print("  3 frameworks × 3 scenarios = 9 tests")
    print("=" * 60)
    
    # CrewAI (sync)
    print("\n--- CrewAI Tests (T1-T3) ---")
    run_crewai_tests()
    
    # AutoGen (async)
    print("\n--- AutoGen Tests (T4-T6) ---")
    asyncio.run(run_autogen_tests())
    
    # LangGraph (sync)
    print("\n--- LangGraph Tests (T7-T9) ---")
    run_langgraph_tests()
    
    # ============================================================
    # FINAL SUMMARY
    # ============================================================
    print("\n" + "=" * 60)
    print("  FINAL SUMMARY")
    print("=" * 60)
    
    total = len(results)
    passed = sum(1 for _, _, p, _ in results if p)
    failed = total - passed
    
    for num, name, p, detail in results:
        status = "✅" if p else "❌"
        print(f"  T{num}: {name:30s} {status}")
    
    print(f"\n  Total: {total} | Passed: {passed} | Failed: {failed}")
    print("=" * 60)
    
    if failed > 0:
        print("\n  ⚠️  SOME TESTS FAILED")
        sys.exit(1)
    else:
        print("\n  🎯 ALL 9 TESTS PASSED")
        sys.exit(0)


if __name__ == "__main__":
    main()
