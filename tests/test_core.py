"""
CCS Core Unit Tests — unittest + mock

Tests the synchronous interceptor architecture:
  - CCSRuntime.evaluate() ALLOW/DENY/fail-closed
  - CCSConfig defaults and customization
  - Audit trace recording
  - govern / async_govern / generator_govern decorators
  - get_stats() latency percentiles

These tests require NO framework dependencies (no CrewAI, no AutoGen, no LangGraph).
"""
import unittest
import time
from unittest.mock import patch, MagicMock
from collections import deque

from ccs.core import (
    CCSConfig,
    CCSPolicy,
    CCSRuntime,
    DefaultPolicy,
    GovernanceResult,
    GovernanceTrace,
    get_runtime,
    govern,
    async_govern,
    generator_govern,
)


class TestCCSConfig(unittest.TestCase):
    """CCSConfig defaults and customization."""

    def test_default_config(self):
        config = CCSConfig()
        self.assertEqual(config.policy_name, "default")
        self.assertEqual(config.max_tool_input_size, 1_000_000)
        self.assertEqual(config.timeout_ms, 50)
        self.assertEqual(config.fail_mode, "closed")
        self.assertTrue(config.audit_log)
        self.assertEqual(config.target_p50_us, 22.0)
        self.assertEqual(config.target_p99_us, 99.0)

    def test_custom_config(self):
        config = CCSConfig(policy_name="strict", max_tool_input_size=500, timeout_ms=100)
        self.assertEqual(config.policy_name, "strict")
        self.assertEqual(config.max_tool_input_size, 500)
        self.assertEqual(config.timeout_ms, 100)


class TestCCSRuntimeInit(unittest.TestCase):
    """CCSRuntime initialization."""

    def test_init_defaults(self):
        runtime = CCSRuntime()
        self.assertIsNotNone(runtime.config)
        self.assertEqual(runtime.config.policy_name, "default")
        self.assertIn("default", runtime.policies)
        self.assertIsInstance(runtime.policies["default"], DefaultPolicy)
        self.assertIsInstance(runtime.traces, deque)
        self.assertEqual(runtime.traces.maxlen, 100_000)
        self.assertIsInstance(runtime._latencies, deque)
        self.assertEqual(runtime._latencies.maxlen, 100_000)

    def test_init_with_config(self):
        config = CCSConfig(policy_name="strict")
        runtime = CCSRuntime(config)
        self.assertIs(runtime.config, config)

    def test_get_stats_empty(self):
        runtime = CCSRuntime()
        stats = runtime.get_stats()
        self.assertEqual(stats["total_evaluations"], 0)


class TestCCSRuntimeEvaluate(unittest.TestCase):
    """CCSRuntime.evaluate() — the core governance engine."""

    def setUp(self):
        self.runtime = CCSRuntime()

    # --- ALLOW ---

    def test_evaluate_allow_default_policy(self):
        result, latency = self.runtime.evaluate("search_web", {"query": "hello"})
        self.assertEqual(result, GovernanceResult.ALLOW)
        self.assertGreater(latency, 0)
        stats = self.runtime.get_stats()
        self.assertEqual(stats["total_evaluations"], 1)
        self.assertEqual(stats["total_allowed"], 1)
        self.assertEqual(stats["total_denied"], 0)

    def test_evaluate_allow_with_large_valid_input(self):
        """Large but within-size input should ALLOW."""
        big_input = {"data": "x" * 900_000}
        result, _ = self.runtime.evaluate("store_data", big_input)
        self.assertEqual(result, GovernanceResult.ALLOW)

    # --- DENY ---

    def test_evaluate_deny_custom_policy(self):
        class DenyPolicy(CCSPolicy):
            def evaluate(self, tool_name, tool_input):
                return GovernanceResult.DENY

        self.runtime.register_policy("deny_all", DenyPolicy())
        result, _ = self.runtime.evaluate("delete_file", {"path": "/etc"}, policy_name="deny_all")
        self.assertEqual(result, GovernanceResult.DENY)

    def test_evaluate_deny_unknown_policy(self):
        """Unknown policy name → DENY (safe default)."""
        result, _ = self.runtime.evaluate("some_tool", {}, policy_name="nonexistent")
        self.assertEqual(result, GovernanceResult.DENY)

    def test_evaluate_deny_non_dict_input(self):
        """Non-dict input → DefaultPolicy denies."""
        result, _ = self.runtime.evaluate("some_tool", "not_a_dict")
        self.assertEqual(result, GovernanceResult.DENY)

    def test_evaluate_deny_oversized_input(self):
        """Input exceeding max_tool_input_size → DENY."""
        oversized = {"data": "x" * (self.runtime.config.max_tool_input_size + 1)}
        result, _ = self.runtime.evaluate("upload", oversized)
        self.assertEqual(result, GovernanceResult.DENY)

    def test_evaluate_deny_on_serialization_error(self):
        """Input that cannot be JSON-serialized → DENY (fail-closed)."""
        class Unserializable:
            def __str__(self):
                raise ValueError("cannot serialize")

        result, _ = self.runtime.evaluate("bad_tool", {"obj": Unserializable()})
        self.assertEqual(result, GovernanceResult.DENY)

    # --- FAIL-CLOSED (critical guarantee) ---

    def test_fail_closed_when_policy_crashes(self):
        """Policy exception → DENY (fail-closed), tool NEVER executes."""

        class CrashPolicy(CCSPolicy):
            def evaluate(self, tool_name, tool_input):
                raise RuntimeError("Policy engine crashed!")

        self.runtime.register_policy("crash", CrashPolicy())
        result, _ = self.runtime.evaluate("dangerous_tool", {"cmd": "rm -rf /"}, policy_name="crash")
        self.assertEqual(result, GovernanceResult.DENY)

    def test_fail_closed_is_deny_not_error(self):
        """Crash returns DENY, not ERROR (runtime never raises)."""
        class CrashPolicy(CCSPolicy):
            def evaluate(self, tool_name, tool_input):
                raise RuntimeError("boom")

        self.runtime.register_policy("crash", CrashPolicy())
        result, _ = self.runtime.evaluate("x", {}, policy_name="crash")
        # The key guarantee: DENY not ERROR
        self.assertEqual(result, GovernanceResult.DENY)

    # --- Audit Traces ---

    def test_trace_recorded_when_audit_log_on(self):
        config = CCSConfig(audit_log=True)
        runtime = CCSRuntime(config)
        runtime.evaluate("search", {"q": "test"})
        self.assertEqual(len(runtime.traces), 1)
        trace = runtime.traces[0]
        self.assertEqual(trace.tool_name, "search")
        self.assertEqual(trace.result, GovernanceResult.ALLOW)
        self.assertIsInstance(trace.timestamp, float)
        self.assertIsInstance(trace.input_hash, str)
        self.assertEqual(len(trace.input_hash), 16)  # SHA-256[:16]
        self.assertIsInstance(trace.latency_us, float)

    def test_trace_not_recorded_when_audit_log_off(self):
        config = CCSConfig(audit_log=False)
        runtime = CCSRuntime(config)
        runtime.evaluate("search", {"q": "test"})
        self.assertEqual(len(runtime.traces), 0)

    def test_trace_deny_detail(self):
        class DenyPolicy(CCSPolicy):
            def evaluate(self, tool_name, tool_input):
                return GovernanceResult.DENY

        runtime = CCSRuntime()
        runtime.register_policy("blocker", DenyPolicy())
        runtime.evaluate("rm_tool", {"path": "/"}, policy_name="blocker")
        self.assertEqual(len(runtime.traces), 1)
        trace = runtime.traces[0]
        self.assertEqual(trace.result, GovernanceResult.DENY)
        self.assertIn("Policy", trace.detail)

    # --- Latency Recording ---

    def test_latency_recorded(self):
        runtime = CCSRuntime()
        runtime.evaluate("fast_tool", {"x": 1})
        runtime.evaluate("fast_tool", {"x": 2})
        runtime.evaluate("fast_tool", {"x": 3})
        self.assertEqual(len(runtime._latencies), 3)
        stats = runtime.get_stats()
        self.assertEqual(stats["total_evaluations"], 3)

    def test_bounded_deque_no_unbounded_growth(self):
        """maxlen=100_000 prevents OOM in long-running processes."""
        runtime = CCSRuntime()
        for i in range(100_500):
            runtime.evaluate(f"tool_{i}", {"idx": i})
        # Should not exceed 100_000
        self.assertLessEqual(len(runtime.traces), 100_000)
        self.assertLessEqual(len(runtime._latencies), 100_000)

    # --- Policy Registration ---

    def test_register_and_use_multiple_policies(self):
        class AllowPolicy(CCSPolicy):
            def evaluate(self, tool_name, tool_input):
                return GovernanceResult.ALLOW

        class DenyPolicy(CCSPolicy):
            def evaluate(self, tool_name, tool_input):
                return GovernanceResult.DENY

        runtime = CCSRuntime()
        runtime.register_policy("allow_it", AllowPolicy())
        runtime.register_policy("deny_it", DenyPolicy())

        self.assertEqual(runtime.evaluate("t", {}, "allow_it")[0], GovernanceResult.ALLOW)
        self.assertEqual(runtime.evaluate("t", {}, "deny_it")[0], GovernanceResult.DENY)
        self.assertEqual(runtime.evaluate("t", {}, "default")[0], GovernanceResult.ALLOW)


class TestGetStats(unittest.TestCase):
    """Runtime performance statistics."""

    def test_stats_with_varied_latencies(self):
        runtime = CCSRuntime()
        # Simulate a range of latencies
        with patch.object(time, 'perf_counter', side_effect=[0.0, 0.000_010, 0.0, 0.000_050, 0.0, 0.000_100]):
            runtime.evaluate("fast", {"x": 1})
            runtime.evaluate("medium", {"x": 2})
            runtime.evaluate("slow", {"x": 3})

        stats = runtime.get_stats()
        self.assertEqual(stats["total_evaluations"], 3)

    def test_stats_deny_count(self):
        class DenyPolicy(CCSPolicy):
            def evaluate(self, tool_name, tool_input):
                return GovernanceResult.DENY

        runtime = CCSRuntime()
        runtime.register_policy("deny", DenyPolicy())
        runtime.evaluate("a", {}, "default")  # ALLOW
        runtime.evaluate("b", {}, "deny")      # DENY
        runtime.evaluate("c", {}, "deny")      # DENY

        stats = runtime.get_stats()
        self.assertEqual(stats["total_allowed"], 1)
        self.assertEqual(stats["total_denied"], 2)


class TestGovernDecorator(unittest.TestCase):
    """@govern decorator — synchronous interception."""

    def test_govern_allow(self):
        runtime = CCSRuntime()
        call_count = 0

        @govern(policy="default", config=CCSConfig(audit_log=False))
        def my_tool(query: str) -> str:
            nonlocal call_count
            call_count += 1
            return f"result:{query}"

        result = my_tool("hello")
        self.assertEqual(result, "result:hello")
        self.assertEqual(call_count, 1)

    def test_govern_deny_raises_permission_error(self):
        class DenyPolicy(CCSPolicy):
            def evaluate(self, tool_name, tool_input):
                return GovernanceResult.DENY

        runtime = get_runtime()
        runtime.register_policy("deny_all", DenyPolicy())
        call_count = 0

        @govern(policy="deny_all")
        def dangerous_tool():
            nonlocal call_count
            call_count += 1
            return "should not reach"

        with self.assertRaises(PermissionError) as ctx:
            dangerous_tool()
        self.assertIn("DENIED", str(ctx.exception))
        self.assertEqual(call_count, 0, "Tool function MUST NOT execute when denied")

    def test_govern_fail_closed_on_crash(self):
        class CrashPolicy(CCSPolicy):
            def evaluate(self, tool_name, tool_input):
                raise RuntimeError("crash!")

        runtime = get_runtime()
        runtime.register_policy("crash", CrashPolicy())
        call_count = 0

        @govern(policy="crash")
        def risky_tool():
            nonlocal call_count
            call_count += 1
            return "should not reach"

        with self.assertRaises(PermissionError):
            risky_tool()
        self.assertEqual(call_count, 0, "Tool MUST NOT execute when governance crashes")

    def test_govern_metadata_attached(self):
        @govern(policy="my_policy")
        def some_tool():
            pass

        self.assertTrue(getattr(some_tool, "__ccs_governed__", False))
        self.assertEqual(getattr(some_tool, "__ccs_policy__"), "my_policy")
        self.assertIsNotNone(getattr(some_tool, "__ccs_runtime__", None))


class TestAsyncGovernDecorator(unittest.TestCase):
    """@async_govern decorator — async interception."""

    def test_async_govern_allow(self):
        import asyncio
        call_count = 0

        @async_govern(policy="default")
        async def fetch_data(url: str) -> str:
            nonlocal call_count
            call_count += 1
            return f"data_from_{url}"

        result = asyncio.run(fetch_data("https://example.com"))
        self.assertEqual(result, "data_from_https://example.com")
        self.assertEqual(call_count, 1)

    def test_async_govern_deny(self):
        import asyncio

        class DenyPolicy(CCSPolicy):
            def evaluate(self, tool_name, tool_input):
                return GovernanceResult.DENY

        runtime = get_runtime()
        runtime.register_policy("deny_async", DenyPolicy())
        call_count = 0

        @async_govern(policy="deny_async")
        async def blocked():
            nonlocal call_count
            call_count += 1
            return "never"

        with self.assertRaises(PermissionError):
            asyncio.run(blocked())
        self.assertEqual(call_count, 0)

    def test_async_govern_metadata(self):
        @async_govern(policy="a")
        async def f():
            pass

        self.assertTrue(f.__ccs_governed__)
        self.assertEqual(f.__ccs_policy__, "a")
        self.assertTrue(f.__ccs_async__)


class TestGeneratorGovernDecorator(unittest.TestCase):
    """@generator_govern decorator — generator interception."""

    def test_generator_govern_allow(self):
        @generator_govern(policy="default")
        def stream_data(n: int):
            for i in range(n):
                yield i

        results = list(stream_data(3))
        self.assertEqual(results, [0, 1, 2])

    def test_generator_govern_deny(self):
        class DenyPolicy(CCSPolicy):
            def evaluate(self, tool_name, tool_input):
                return GovernanceResult.DENY

        runtime = get_runtime()
        runtime.register_policy("deny_gen", DenyPolicy())
        call_count = 0

        @generator_govern(policy="deny_gen")
        def blocked_gen():
            nonlocal call_count
            call_count += 1
            yield "never"

        with self.assertRaises(PermissionError):
            next(blocked_gen())
        self.assertEqual(call_count, 0)

    def test_generator_govern_metadata(self):
        @generator_govern(policy="g")
        def g():
            yield 1
            yield 2

        self.assertTrue(g.__ccs_governed__)
        self.assertEqual(g.__ccs_policy__, "g")
        self.assertTrue(g.__ccs_generator__)


class TestGetRuntime(unittest.TestCase):
    """Global singleton accessor."""

    def test_get_runtime_singleton(self):
        r1 = get_runtime()
        r2 = get_runtime()
        self.assertIs(r1, r2)
        self.assertIsInstance(r1, CCSRuntime)

    def test_get_runtime_with_config_first_call(self):
        """get_runtime with config works on first call (no prior singleton)."""
        import ccs.core as core
        core._runtime = None  # Reset singleton
        config = CCSConfig(policy_name="strict")
        r = get_runtime(config=config)
        self.assertEqual(r.config.policy_name, "strict")


class TestDefaultPolicy(unittest.TestCase):
    """DefaultPolicy edge cases."""

    def test_default_policy_allow_dict(self):
        policy = DefaultPolicy(CCSConfig())
        result = policy.evaluate("t", {"k": "v"})
        self.assertEqual(result, GovernanceResult.ALLOW)

    def test_default_policy_deny_non_dict(self):
        policy = DefaultPolicy(CCSConfig())
        result = policy.evaluate("t", [1, 2, 3])
        self.assertEqual(result, GovernanceResult.DENY)

    def test_default_policy_deny_oversized(self):
        config = CCSConfig(max_tool_input_size=10)
        policy = DefaultPolicy(config)
        result = policy.evaluate("t", {"data": "x" * 100})
        self.assertEqual(result, GovernanceResult.DENY)


class TestGovernanceResult(unittest.TestCase):
    """Enum values."""

    def test_values(self):
        self.assertEqual(GovernanceResult.ALLOW.value, "allow")
        self.assertEqual(GovernanceResult.DENY.value, "deny")
        self.assertEqual(GovernanceResult.ERROR.value, "error")


class TestGovernanceTrace(unittest.TestCase):
    """Trace dataclass."""

    def test_trace_creation(self):
        trace = GovernanceTrace(
            timestamp=1000.0,
            tool_name="test_tool",
            input_hash="abc123",
            result=GovernanceResult.ALLOW,
            latency_us=15.0,
            policy_name="default",
            rule_evaluated="default",
            detail="Policy evaluated",
        )
        self.assertEqual(trace.tool_name, "test_tool")
        self.assertEqual(trace.latency_us, 15.0)
        self.assertEqual(trace.detail, "Policy evaluated")


if __name__ == "__main__":
    unittest.main(verbosity=2)
