"""
CCS Framework Adapters — Verified interception for CrewAI, AutoGen, LangGraph.

Each adapter replaces the framework's observer-pattern hooks with CCS
synchronous interceptor decorators, eliminating CWE-636 fail-open vulnerabilities.

Verified against:
  - CrewAI >= 0.1.0 (BaseTool.run sync interception)
  - AutoGen >= 0.7.0 (FunctionTool.run async interception)
  - LangGraph >= 0.2.0 (LCBaseTool.run sync interception)

Reference: CCS v1.0 Standard, Section 3 — Formal Framework
           DOI: 10.5281/zenodo.21271910
"""


class CrewAIAdapter:
    """
    CCS adapter for CrewAI.

    Intercepts crewai.tools.base_tool.BaseTool.run() — the single
    entry point for ALL CrewAI tool executions. If CCS governance
    denies or crashes, the tool is NEVER invoked (fail-closed).

    Usage:
        from ccs.adapters import crewai_adapter
        crewai_adapter.install()   # patches BaseTool.run globally
        crewai_adapter.uninstall() # restores original
    """

    _original_run = None
    _installed = False

    @staticmethod
    def install(policy: str = "default"):
        """Install CCS governance on CrewAI's BaseTool.run."""
        from crewai.tools.base_tool import BaseTool
        from ccs.core import get_runtime, GovernanceResult

        if CrewAIAdapter._installed:
            return  # Already installed

        runtime = get_runtime()
        CrewAIAdapter._original_run = BaseTool.run

        def ccs_governed_run(self, *args, **kwargs):
            tool_input = {"args": args, "kwargs": kwargs}
            result, latency = runtime.evaluate(
                tool_name=getattr(self, "name", type(self).__name__),
                tool_input=tool_input,
                policy_name=policy,
            )
            if result != GovernanceResult.ALLOW:
                raise PermissionError(
                    f"CCS DENIED: {getattr(self, 'name', 'unknown')} "
                    f"(policy={policy}, latency={latency}µs)"
                )
            return CrewAIAdapter._original_run(self, *args, **kwargs)

        BaseTool.run = ccs_governed_run
        CrewAIAdapter._installed = True

    @staticmethod
    def uninstall():
        """Restore original CrewAI BaseTool.run."""
        if not CrewAIAdapter._installed:
            return
        from crewai.tools.base_tool import BaseTool
        BaseTool.run = CrewAIAdapter._original_run
        CrewAIAdapter._installed = False
        CrewAIAdapter._original_run = None


class AutoGenAdapter:
    """
    CCS adapter for Microsoft AutoGen.

    Intercepts autogen_core.tools.FunctionTool.run() — the async
    entry point for all AutoGen function tool executions.

    Note: AutoGen 0.7+ uses async run(args, cancellation_token).
    The adapter preserves this async signature.

    Usage:
        from ccs.adapters import autogen_adapter
        autogen_adapter.install()
        autogen_adapter.uninstall()
    """

    _original_run = None
    _installed = False

    @staticmethod
    def install(policy: str = "default"):
        """Install CCS governance on AutoGen's FunctionTool.run."""
        from autogen_core.tools import FunctionTool
        from ccs.core import get_runtime, GovernanceResult

        if AutoGenAdapter._installed:
            return

        runtime = get_runtime()
        AutoGenAdapter._original_run = FunctionTool.run

        async def ccs_governed_run(self, args, cancellation_token):
            tool_input = {"args": str(args), "tool": self.name}
            result, latency = runtime.evaluate(
                tool_name=self.name,
                tool_input=tool_input,
                policy_name=policy,
            )
            if result != GovernanceResult.ALLOW:
                raise PermissionError(
                    f"CCS DENIED: {self.name} "
                    f"(policy={policy}, latency={latency}µs)"
                )
            return await AutoGenAdapter._original_run(self, args, cancellation_token)

        FunctionTool.run = ccs_governed_run
        AutoGenAdapter._installed = True

    @staticmethod
    def uninstall():
        """Restore original AutoGen FunctionTool.run."""
        if not AutoGenAdapter._installed:
            return
        from autogen_core.tools import FunctionTool
        FunctionTool.run = AutoGenAdapter._original_run
        AutoGenAdapter._installed = False
        AutoGenAdapter._original_run = None


class LangGraphAdapter:
    """
    CCS adapter for LangGraph / LangChain.

    Intercepts langchain_core.tools.BaseTool.run() — the sync
    entry point for all LangChain/LangGraph tool executions.
    Also covers invoke() since it delegates to run().

    Usage:
        from ccs.adapters import langgraph_adapter
        langgraph_adapter.install()
        langgraph_adapter.uninstall()
    """

    _original_run = None
    _installed = False

    @staticmethod
    def install(policy: str = "default"):
        """Install CCS governance on LangChain's BaseTool.run."""
        from langchain_core.tools import BaseTool as LCBaseTool
        from ccs.core import get_runtime, GovernanceResult

        if LangGraphAdapter._installed:
            return

        runtime = get_runtime()
        LangGraphAdapter._original_run = LCBaseTool.run

        def ccs_governed_run(self, tool_input, *args, **kwargs):
            governance_input = {"tool_input": tool_input, "kwargs": kwargs}
            result, latency = runtime.evaluate(
                tool_name=getattr(self, "name", type(self).__name__),
                tool_input=governance_input,
                policy_name=policy,
            )
            if result != GovernanceResult.ALLOW:
                raise PermissionError(
                    f"CCS DENIED: {getattr(self, 'name', 'unknown')} "
                    f"(policy={policy}, latency={latency}µs)"
                )
            return LangGraphAdapter._original_run(self, tool_input, *args, **kwargs)

        LCBaseTool.run = ccs_governed_run
        LangGraphAdapter._installed = True

    @staticmethod
    def uninstall():
        """Restore original LangChain BaseTool.run."""
        if not LangGraphAdapter._installed:
            return
        from langchain_core.tools import BaseTool as LCBaseTool
        LCBaseTool.run = LangGraphAdapter._original_run
        LangGraphAdapter._installed = False
        LangGraphAdapter._original_run = None


# Convenience instances
crewai_adapter = CrewAIAdapter()
autogen_adapter = AutoGenAdapter()
langgraph_adapter = LangGraphAdapter()
