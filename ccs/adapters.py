"""
CCS Framework Adapters — 3-line integration for major Agent frameworks.

Each adapter wraps the framework's tool calling mechanism with CCS
synchronous interceptor governance, replacing or augmenting the
framework's native observer-pattern hooks.
"""

from typing import Any, Callable, Dict, Optional


class CrewAIAdapter:
    """
    CCS adapter for CrewAI.
    
    Replaces AGT's observer-pattern hooks with CCS interceptor decorators.
    Eliminates the CWE-636 fail-open vulnerability by owning execution control.
    
    Usage (3 lines):
        from ccs.adapters import crewai_adapter
        
        crewai_adapter.install(agent)
        # All tool calls are now governed by CCS
    """
    
    @staticmethod
    def install(agent, policy: str = "default"):
        """
        Install CCS governance on a CrewAI agent.
        
        Args:
            agent: CrewAI Agent instance
            policy: CCS policy name to use
        """
        from ccs.core import get_runtime, GovernanceResult
        
        runtime = get_runtime()
        
        # Wrap the agent's tool execution method
        original_execute = getattr(agent, 'execute_tool', None)
        if original_execute is None:
            raise ValueError("Cannot find execute_tool method on agent")
        
        def ccs_governed_execute(tool_name: str, tool_input: Dict, **kwargs):
            result, latency = runtime.evaluate(tool_name, tool_input, policy)
            if result != GovernanceResult.ALLOW:
                raise PermissionError(
                    f"CCS DENIED: {tool_name} (policy={policy})"
                )
            return original_execute(tool_name, tool_input, **kwargs)
        
        agent.execute_tool = ccs_governed_execute
        agent.__ccs_installed__ = True
        return agent


class AutoGenAdapter:
    """
    CCS adapter for Microsoft AutoGen.
    
    Usage (3 lines):
        from ccs.adapters import autogen_adapter
        
        autogen_adapter.install(conversable_agent)
    """
    
    @staticmethod
    def install(agent, policy: str = "default"):
        """Install CCS governance on an AutoGen ConversableAgent."""
        from ccs.core import get_runtime, GovernanceResult
        
        runtime = get_runtime()
        
        # AutoGen uses tool registration — wrap the tool executor
        original_run = getattr(agent, 'run_function', None)
        
        if original_run is not None:
            def ccs_governed_run(func_name: str, **kwargs):
                tool_input = {"function": func_name, "args": kwargs}
                result, latency = runtime.evaluate(func_name, tool_input, policy)
                if result != GovernanceResult.ALLOW:
                    raise PermissionError(f"CCS DENIED: {func_name}")
                return original_run(func_name, **kwargs)
            
            agent.run_function = ccs_governed_run
            agent.__ccs_installed__ = True
        else:
            # Fallback: register as a hook
            def ccs_hook(tool_call):
                result, _ = runtime.evaluate(
                    tool_call.get('name', 'unknown'),
                    tool_call.get('arguments', {}),
                    policy
                )
                from ccs.core import GovernanceResult
                return result == GovernanceResult.ALLOW
            
            if hasattr(agent, 'register_hook'):
                agent.register_hook('before_tool_call', ccs_hook)
                agent.__ccs_installed__ = True


class LangGraphAdapter:
    """
    CCS adapter for LangGraph.
    
    Usage (3 lines):
        from ccs.adapters import langgraph_adapter
        
        langgraph_adapter.install(graph_node)
    """
    
    @staticmethod
    def install(tool_node, policy: str = "default"):
        """Install CCS governance on a LangGraph ToolNode."""
        from ccs.core import get_runtime, GovernanceResult
        
        runtime = get_runtime()
        
        # LangGraph ToolNode dispatches tool calls
        original_invoke = getattr(tool_node, 'invoke', None)
        
        if original_invoke is not None:
            def ccs_governed_invoke(input_data, **kwargs):
                # Extract tool calls from input
                tool_calls = input_data.get('tool_calls', []) if isinstance(input_data, dict) else []
                
                for tc in tool_calls:
                    result, _ = runtime.evaluate(
                        tc.get('name', 'unknown'),
                        tc.get('args', {}),
                        policy
                    )
                    if result != GovernanceResult.ALLOW:
                        # Remove denied tool call
                        tool_calls.remove(tc)
                
                return original_invoke(input_data, **kwargs)
            
            tool_node.invoke = ccs_governed_invoke
            tool_node.__ccs_installed__ = True


# Convenience instances
crewai_adapter = CrewAIAdapter()
autogen_adapter = AutoGenAdapter()
langgraph_adapter = LangGraphAdapter()
