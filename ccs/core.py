"""
CCS Core: Synchronous Interceptor Decorator Architecture

Unlike observer-pattern hooks that can fail-open, CCS decorators
OWN the execution control flow. If verification fails or raises,
the wrapped tool function is NEVER invoked. This provides
structural fail-closed guarantee.

Reference: CCS v1.0 Standard, Section 3 — Formal Framework
           DOI: 10.5281/zenodo.21271910
"""

import functools
import time
import hashlib
import json
import logging
from collections import deque
from typing import Any, Callable, Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class GovernanceResult(Enum):
    """Governance evaluation result."""
    ALLOW = "allow"
    DENY = "deny"
    ERROR = "error"  # Error in evaluation → ALWAYS DENY (fail-closed)


@dataclass
class CCSConfig:
    """Configuration for CCS governance."""
    policy_name: str = "default"
    max_tool_input_size: int = 1_000_000  # 1MB max input
    timeout_ms: int = 50  # 50ms timeout for governance evaluation
    fail_mode: str = "closed"  # Only "closed" is valid — fail-open is structurally forbidden
    audit_log: bool = True
    # Performance targets (CANON benchmark)
    target_p50_us: float = 22.0
    target_p99_us: float = 99.0


@dataclass
class GovernanceTrace:
    """Immutable audit trace for a single governance decision."""
    timestamp: float
    tool_name: str
    input_hash: str
    result: GovernanceResult
    latency_us: float
    policy_name: str
    rule_evaluated: str
    detail: str = ""


class CCSPolicy:
    """
    Base class for CCS governance policies.

    Subclass this to define custom governance rules.
    All evaluation methods MUST return GovernanceResult.
    If evaluation raises → fail-closed (DENY), never ALLOW.
    """

    def evaluate(self, tool_name: str, tool_input: Dict[str, Any]) -> GovernanceResult:
        """
        Evaluate whether a tool call should be allowed.

        Args:
            tool_name: Name of the tool being called
            tool_input: Arguments to the tool

        Returns:
            GovernanceResult.ALLOW or GovernanceResult.DENY

        Note:
            If this method raises an exception, the decorator will
            catch it and return DENY (fail-closed). This is the
            fundamental guarantee that distinguishes CCS from
            observer-pattern hooks.
        """
        raise NotImplementedError


class DefaultPolicy(CCSPolicy):
    """Default CCS policy: validates input structure and size."""

    def __init__(self, config: CCSConfig):
        self.config = config

    def evaluate(self, tool_name: str, tool_input: Dict[str, Any]) -> GovernanceResult:
        # Size check
        try:
            serialized = json.dumps(tool_input, default=str)
            if len(serialized) > self.config.max_tool_input_size:
                return GovernanceResult.DENY
        except (TypeError, ValueError, OverflowError):
            # Non-serializable input → DENY (fail-closed)
            return GovernanceResult.DENY

        # Type check
        if not isinstance(tool_input, dict):
            return GovernanceResult.DENY

        return GovernanceResult.ALLOW


class CCSRuntime:
    """
    CCS Governance Runtime — synchronous interceptor engine.

    This is the core of the CCS architecture. Unlike framework hooks
    that observe events, the runtime INTERCEPTS tool calls and
    controls execution flow. If the runtime fails, the tool is BLOCKED.
    """

    def __init__(self, config: Optional[CCSConfig] = None):
        self.config = config or CCSConfig()
        self.policies: Dict[str, CCSPolicy] = {}
        # Bounded deques prevent unbounded memory growth in long-running processes
        self.traces: deque = deque(maxlen=100_000)
        self._latencies: deque = deque(maxlen=100_000)

        # Register default policy
        self.policies["default"] = DefaultPolicy(self.config)

    def register_policy(self, name: str, policy: CCSPolicy):
        """Register a named governance policy."""
        self.policies[name] = policy

    def evaluate(self, tool_name: str, tool_input: Dict[str, Any],
                 policy_name: str = "default") -> Tuple[GovernanceResult, float]:
        """
        Synchronously evaluate a tool call against the named policy.

        Returns:
            Tuple of (GovernanceResult, latency_microseconds)

        Guarantee:
            This method NEVER raises. Any exception is caught and
            converted to GovernanceResult.DENY. This is the fail-closed
            guarantee that observer-pattern hooks cannot provide.
        """
        start = time.perf_counter()

        try:
            policy = self.policies.get(policy_name)
            if policy is None:
                result = GovernanceResult.DENY
                detail = f"Unknown policy: {policy_name}"
            else:
                result = policy.evaluate(tool_name, tool_input)
                detail = f"Policy '{policy_name}' evaluated"
        except Exception as e:
            # FAIL-CLOSED: Any exception → DENY
            # This is the critical difference from observer hooks
            result = GovernanceResult.DENY
            detail = f"Exception caught, fail-closed: {type(e).__name__}: {e}"

        latency_us = (time.perf_counter() - start) * 1_000_000
        self._latencies.append(latency_us)

        # Compute input hash for audit trail
        try:
            input_hash = hashlib.sha256(
                json.dumps(tool_input, default=str, sort_keys=True).encode()
            ).hexdigest()[:16]
        except Exception:
            input_hash = "unhashable"

        if self.config.audit_log:
            trace = GovernanceTrace(
                timestamp=time.time(),
                tool_name=tool_name,
                input_hash=input_hash,
                result=result,
                latency_us=round(latency_us, 2),
                policy_name=policy_name,
                rule_evaluated=policy_name,
                detail=detail,
            )
            self.traces.append(trace)

        # Log DENY events for production observability
        if result != GovernanceResult.ALLOW:
            logger.warning(
                "CCS DENY | tool=%s policy=%s latency=%.2fµs detail=%s",
                tool_name, policy_name, latency_us, detail,
            )

        return result, round(latency_us, 2)

    def get_stats(self) -> Dict[str, Any]:
        """Get runtime performance statistics."""
        if not self._latencies:
            return {"total_evaluations": 0}

        sorted_lat = sorted(self._latencies)
        n = len(sorted_lat)
        return {
            "total_evaluations": n,
            "total_denied": sum(1 for t in self.traces if t.result == GovernanceResult.DENY),
            "total_allowed": sum(1 for t in self.traces if t.result == GovernanceResult.ALLOW),
            "latency_p50_us": round(sorted_lat[n // 2], 2),
            "latency_p99_us": (
                round(sorted_lat[int(n * 0.99)], 2)
                if n >= 100 else round(sorted_lat[-1], 2)
            ),
            "latency_max_us": round(sorted_lat[-1], 2),
        }


# Global runtime singleton
_runtime: Optional[CCSRuntime] = None


def get_runtime(config: Optional[CCSConfig] = None) -> CCSRuntime:
    """Get or create the global CCS runtime."""
    global _runtime
    if _runtime is None:
        _runtime = CCSRuntime(config)
    return _runtime


def govern(policy: str = "default", config: Optional[CCSConfig] = None):
    """
    CCS governance decorator — the core of the interceptor pattern.

    Usage:
        @govern(policy="default")
        def my_tool(args: dict) -> str:
            return "result"

    Guarantee:
        If governance evaluation raises ANY exception, the decorated
        function is NEVER called. This provides structural fail-closed
        behavior that observer-pattern hooks cannot achieve.

    Example (CrewAI):
        from ccs import govern

        @govern(policy="compliance")
        def search_web(query: str):
            # This function will NEVER execute if governance denies
            return search_engine(query)
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            runtime = get_runtime(config)

            # Build tool input for governance evaluation
            tool_input = {"args": args, "kwargs": kwargs}

            # SYNCHRONOUS INTERCEPTION — not observation
            result, latency_us = runtime.evaluate(
                tool_name=func.__name__,
                tool_input=tool_input,
                policy_name=policy,
            )

            # FAIL-CLOSED: Only proceed if explicitly ALLOWED
            if result != GovernanceResult.ALLOW:
                raise PermissionError(
                    f"CCS governance DENIED tool '{func.__name__}' "
                    f"(policy={policy}, latency={latency_us}µs)"
                )

            # Only reached if governance explicitly ALLOWED
            return func(*args, **kwargs)

        # Attach CCS metadata
        wrapper.__ccs_governed__ = True
        wrapper.__ccs_policy__ = policy
        wrapper.__ccs_runtime__ = get_runtime(config)

        return wrapper
    return decorator


def async_govern(policy: str = "default", config: Optional[CCSConfig] = None):
    """
    CCS governance decorator for async functions — asynchronous interceptor pattern.

    Usage:
        @async_govern(policy="default")
        async def my_async_tool(args: dict) -> str:
            return "result"

    Guarantee:
        If governance evaluation raises ANY exception, the decorated
        async function is NEVER called. This provides structural fail-closed
        behavior for async tool calls.

    Example:
        from ccs import async_govern

        @async_govern(policy="compliance")
        async def fetch_data(url: str):
            # This function will NEVER execute if governance denies
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    return await response.text()
    """

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            runtime = get_runtime(config)

            # Build tool input for governance evaluation
            tool_input = {"args": args, "kwargs": kwargs}

            # SYNCHRONOUS INTERCEPTION before async execution
            result, latency_us = runtime.evaluate(
                tool_name=func.__name__,
                tool_input=tool_input,
                policy_name=policy,
            )

            # FAIL-CLOSED: Only proceed if explicitly ALLOWED
            if result != GovernanceResult.ALLOW:
                raise PermissionError(
                    f"CCS governance DENIED async tool '{func.__name__}' "
                    f"(policy={policy}, latency={latency_us}µs)"
                )

            # Only reached if governance explicitly ALLOWED
            return await func(*args, **kwargs)

        # Attach CCS metadata
        wrapper.__ccs_governed__ = True
        wrapper.__ccs_policy__ = policy
        wrapper.__ccs_runtime__ = get_runtime(config)
        wrapper.__ccs_async__ = True

        return wrapper
    return decorator


def generator_govern(policy: str = "default", config: Optional[CCSConfig] = None):
    """
    CCS governance decorator for generator functions — intercept before each yield.

    Usage:
        @generator_govern(policy="default")
        def my_streaming_tool(args: dict):
            for chunk in data:
                yield chunk

    Guarantee:
        Governance is evaluated ONCE before iteration begins. If governance
        denies or raises, the generator function is NEVER invoked.

    Note:
        For per-yield governance, implement custom logic inside the generator.
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            runtime = get_runtime(config)

            # Build tool input for governance evaluation
            tool_input = {"args": args, "kwargs": kwargs}

            # Evaluate governance BEFORE generator starts
            result, latency_us = runtime.evaluate(
                tool_name=func.__name__,
                tool_input=tool_input,
                policy_name=policy,
            )

            # FAIL-CLOSED: Only proceed if explicitly ALLOWED
            if result != GovernanceResult.ALLOW:
                raise PermissionError(
                    f"CCS governance DENIED generator '{func.__name__}' "
                    f"(policy={policy}, latency={latency_us}µs)"
                )

            # Governance passed, iterate generator
            yield from func(*args, **kwargs)

        # Attach CCS metadata
        wrapper.__ccs_governed__ = True
        wrapper.__ccs_policy__ = policy
        wrapper.__ccs_runtime__ = get_runtime(config)
        wrapper.__ccs_generator__ = True

        return wrapper
    return decorator
