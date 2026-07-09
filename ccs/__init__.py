"""
Correctover Conformance Standard (CCS) v1.0 — Python SDK

Synchronous interceptor-based governance for AI Agent frameworks.
Eliminates architectural fail-open bypasses inherent to observer-pattern hooks.

Usage:
    from ccs import govern
    
    @govern(policy="default")
    def my_tool(args):
        ...
"""

__version__ = "1.0.0"
__author__ = "Correctover Standards"

from ccs.core import govern, GovernanceResult, CCSConfig, CCSPolicy, CCSRuntime, get_runtime
from ccs.adapters import crewai_adapter, autogen_adapter, langgraph_adapter

__all__ = [
    "govern",
    "GovernanceResult", 
    "CCSConfig",
    "CCSPolicy",
    "CCSRuntime",
    "get_runtime",
    "crewai_adapter",
    "autogen_adapter", 
    "langgraph_adapter",
]
