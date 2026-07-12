"""
CCS (Correctover Conformance Standard) v3.1
Synchronous and asynchronous interceptor governance for AI Agent frameworks.
Fail-closed by design.
"""

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

__version__ = "3.1.0"
__all__ = [
    "CCSConfig",
    "CCSPolicy", 
    "CCSRuntime",
    "DefaultPolicy",
    "GovernanceResult",
    "GovernanceTrace",
    "get_runtime",
    "govern",
    "async_govern",
    "generator_govern",
]
