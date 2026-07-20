"""
CCS (Correctover Conformance Standard) v4.1
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

from ccs.guardrail import (
    canonical_json,
    compute_decision_id,
    GuardrailDecisionV1,
    ActionEnvelopeV1,
    ToolCallContext,
    GuardrailProvider,
    AllowAllGuardrailProvider,
    DenyAllGuardrailProvider,
    ToolListGuardrailProvider,
    CKGGuardrailProvider,
    EnvProtectionProvider,
    CompositeGuardrailProvider,
    AuditTrail,
    GuardrailContext,
    make_guardrail_hook,
    detect_missing_guardrail,
    MCPSecurityValidator,
)

__version__ = "4.1.0"
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
    "canonical_json",
    "compute_decision_id",
    "GuardrailDecisionV1",
    "ActionEnvelopeV1",
    "ToolCallContext",
    "GuardrailProvider",
    "AllowAllGuardrailProvider",
    "DenyAllGuardrailProvider",
    "ToolListGuardrailProvider",
    "CKGGuardrailProvider",
    "EnvProtectionProvider",
    "CompositeGuardrailProvider",
    "AuditTrail",
    "GuardrailContext",
    "make_guardrail_hook",
    "detect_missing_guardrail",
    "MCPSecurityValidator",
]

