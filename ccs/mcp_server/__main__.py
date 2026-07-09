"""CCS MCP Server — Model Context Protocol governance for AI Agents."""
from ccs.mcp_server.server import mcp

__all__ = ["mcp"]

if __name__ == "__main__":
    mcp.run()
