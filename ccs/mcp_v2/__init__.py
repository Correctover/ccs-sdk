"""
CCS MCP v2 Migration Detector
Detects protocol incompatibility with the 2026-07-28 MCP specification.

Timeline:
- Release candidate: 2026-05-21 (locked)
- Beta SDKs: 2026-06-29 (Python mcp 2.0.0b1, TypeScript @modelcontextprotocol/server 2.0.0-beta.x)
- Final spec: 2026-07-28

Breaking changes detected:
1. Stateless protocol (no initialize handshake, no Mcp-Session-Id)
2. Package name changes (TypeScript SDK split)
3. Deprecated features: Roots, Sampling, Logging
4. Error code change: -32002 → -32602
5. Auth hardening: OAuth 2.0 / OpenID Connect
6. New headers: Mcp-Method, Mcp-Name
7. MRTR: InputRequiredResult replaces Sampling callbacks
"""

from .detector import MCPv2Detector, DetectionResult

__all__ = ["MCPv2Detector", "DetectionResult"]
__version__ = "4.0.1"
