"""
correctover.guardrail - Framework-agnostic runtime security guardrail system.
CCS reference implementation.
"""

import hashlib
import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def compute_decision_id(claims, expires_at=None):
    preimage = claims.copy()
    if expires_at is not None:
        preimage["_expires_at"] = expires_at
    return hashlib.sha256(canonical_json(preimage).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class GuardrailDecisionV1:
    decision_id: str
    authorized: bool
    claims: Dict[str, Any]
    expires_at: Optional[float] = None

    def is_expired(self):
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at

    def verify_integrity(self):
        return self.decision_id == compute_decision_id(self.claims, self.expires_at)

    def to_dict(self):
        return {
            "decision_id": self.decision_id,
            "authorized": self.authorized,
            "claims": self.claims,
            "expires_at": self.expires_at,
        }


@dataclass(frozen=True)
class ActionEnvelopeV1:
    decision_id: str
    tool_result_digest: str
    executed_at: float
    duration_ms: float

    @staticmethod
    def digest_result(result):
        raw = canonical_json(result) if result is not None else ""
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def to_dict(self):
        return {
            "decision_id": self.decision_id,
            "tool_result_digest": self.tool_result_digest,
            "executed_at": self.executed_at,
            "duration_ms": self.duration_ms,
        }


@dataclass
class ToolCallContext:
    tool_name: str
    tool_args: Dict[str, Any] = field(default_factory=dict)
    agent_id: str = "unknown"
    metadata: Dict[str, Any] = field(default_factory=dict)


class GuardrailProvider(ABC):
    @abstractmethod
    def authorize(self, context: ToolCallContext) -> GuardrailDecisionV1: ...


class AllowAllGuardrailProvider(GuardrailProvider):
    def authorize(self, context):
        claims = {
            "provider": "AllowAllGuardrailProvider",
            "tool_name": context.tool_name,
            "agent_id": context.agent_id,
        }
        return GuardrailDecisionV1(
            decision_id=compute_decision_id(claims), authorized=True, claims=claims
        )


class DenyAllGuardrailProvider(GuardrailProvider):
    def authorize(self, context):
        claims = {
            "provider": "DenyAllGuardrailProvider",
            "tool_name": context.tool_name,
            "reason": "deny-all safety lock active",
        }
        return GuardrailDecisionV1(
            decision_id=compute_decision_id(claims), authorized=False, claims=claims
        )


class ToolListGuardrailProvider(GuardrailProvider):
    def __init__(self, allowed_tools=None, denied_tools=None):
        self.allowed_tools = allowed_tools
        self.denied_tools = denied_tools or set()

    def authorize(self, context):
        claims = {
            "provider": "ToolListGuardrailProvider",
            "tool_name": context.tool_name,
            "agent_id": context.agent_id,
        }
        if self.allowed_tools is not None:
            authorized = context.tool_name in self.allowed_tools
            claims["policy"] = "allowlist"
            claims["allowed_tools"] = sorted(self.allowed_tools)
        elif context.tool_name in self.denied_tools:
            authorized = False
            claims["policy"] = "denylist"
            claims["denied_tools"] = sorted(self.denied_tools)
        else:
            authorized = True
            claims["policy"] = "default-allow"
        return GuardrailDecisionV1(
            decision_id=compute_decision_id(claims), authorized=authorized, claims=claims
        )


class CKGGuardrailProvider(GuardrailProvider):
    def __init__(self):
        self._constraints = []

    def add_constraint(self, predicate, **kwargs):
        self._constraints.append({"predicate": predicate, **kwargs})
        return self

    def authorize(self, context):
        claims = {
            "provider": "CKGGuardrailProvider",
            "tool_name": context.tool_name,
            "agent_id": context.agent_id,
        }
        satisfied, failed_predicate = True, None
        for c in self._constraints:
            p = c["predicate"]
            if p == "tool_name_in" and context.tool_name not in c["tools"]:
                satisfied, failed_predicate = False, p
            elif p == "tool_name_not_in" and context.tool_name in c["tools"]:
                satisfied, failed_predicate = False, p
            elif p == "agent_id_in" and context.agent_id not in c["agents"]:
                satisfied, failed_predicate = False, p
            elif p == "param_matches" and context.tool_args.get(c["name"]) != c["value"]:
                satisfied, failed_predicate = False, p
            elif p == "has_param" and c["name"] not in context.tool_args:
                satisfied, failed_predicate = False, p
            elif p == "no_param" and c["name"] in context.tool_args:
                satisfied, failed_predicate = False, p
        if not satisfied:
            claims["failed_predicate"] = failed_predicate
        claims["constraints_count"] = len(self._constraints)
        return GuardrailDecisionV1(
            decision_id=compute_decision_id(claims), authorized=satisfied, claims=claims
        )


class EnvProtectionProvider(GuardrailProvider):
    DANGEROUS_PATTERNS = {
        "env_vars": [
            "API_KEY",
            "API_SECRET",
            "SECRET_KEY",
            "PRIVATE_KEY",
            "ACCESS_TOKEN",
            "AUTH_TOKEN",
            "DB_PASSWORD",
            "DATABASE_URL",
            "AWS_SECRET",
            "AWS_ACCESS_KEY",
            "GITHUB_TOKEN",
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
        ],
        "env_commands": ["os.environ", "process.env", "getenv", "env ", "printenv", "echo $", "${"],
        "file_paths": [
            ".env",
            ".env.local",
            ".env.production",
            "credentials.json",
            "service-account.json",
        ],
    }

    def __init__(self, extra_patterns=None):
        self.extra_patterns = extra_patterns or []

    def authorize(self, context):
        claims = {
            "provider": "EnvProtectionProvider",
            "tool_name": context.tool_name,
            "agent_id": context.agent_id,
        }
        args_str = canonical_json(context.tool_args).lower()
        matched = [
            f"{cat}:{p}"
            for cat, pats in self.DANGEROUS_PATTERNS.items()
            for p in pats
            if p.lower() in args_str
        ]
        matched += [f"custom:{p}" for p in self.extra_patterns if p.lower() in args_str]
        if matched:
            claims["matched_patterns"] = matched
            claims["reason"] = "Environment variable access attempt detected"
            return GuardrailDecisionV1(
                decision_id=compute_decision_id(claims), authorized=False, claims=claims
            )
        claims["reason"] = "No environment variable access detected"
        return GuardrailDecisionV1(
            decision_id=compute_decision_id(claims), authorized=True, claims=claims
        )


class CompositeGuardrailProvider(GuardrailProvider):
    def __init__(self, providers, mode="AND"):
        if mode not in ("AND", "OR"):
            raise ValueError(f"mode must be AND or OR, got {mode}")
        self.providers = providers
        self.mode = mode

    def authorize(self, context):
        results = [p.authorize(context) for p in self.providers]
        authorized = (
            all(d.authorized for d in results)
            if self.mode == "AND"
            else any(d.authorized for d in results)
        )
        claims = {
            "provider": "CompositeGuardrailProvider",
            "mode": self.mode,
            "tool_name": context.tool_name,
            "agent_id": context.agent_id,
            "sub_decisions": [d.decision_id for d in results],
            "sub_providers": [d.claims.get("provider", "unknown") for d in results],
        }
        return GuardrailDecisionV1(
            decision_id=compute_decision_id(claims), authorized=authorized, claims=claims
        )


class AuditTrail:
    def __init__(self):
        self._decisions = {}
        self._envelopes = {}

    def record_decision(self, decision):
        self._decisions[decision.decision_id] = decision

    def record_envelope(self, envelope):
        self._envelopes[envelope.decision_id] = envelope

    def get_decision(self, did):
        return self._decisions.get(did)

    def get_envelope(self, did):
        return self._envelopes.get(did)

    def get_all_decisions(self):
        return list(self._decisions.values())

    def get_all_envelopes(self):
        return list(self._envelopes.values())

    def clear(self):
        self._decisions.clear()
        self._envelopes.clear()

    @property
    def decision_count(self):
        return len(self._decisions)

    @property
    def envelope_count(self):
        return len(self._envelopes)

    def verify_all(self):
        return all(d.verify_integrity() for d in self._decisions.values())

    def export(self):
        return {
            "decisions": [d.to_dict() for d in self._decisions.values()],
            "envelopes": [e.to_dict() for e in self._envelopes.values()],
            "verified": self.verify_all(),
        }


class GuardrailContext:
    def __init__(self, provider, trail=None, on_deny=None):
        self.provider = provider
        self.trail = trail or AuditTrail()
        self.on_deny = on_deny

    def authorize(self, context):
        decision = self.provider.authorize(context)
        self.trail.record_decision(decision)
        if not decision.authorized and self.on_deny:
            self.on_deny(decision)
        return decision

    def after_tool_call(self, decision, result, start_time):
        duration_ms = (time.time() - start_time) * 1000
        envelope = ActionEnvelopeV1(
            decision_id=decision.decision_id,
            tool_result_digest=ActionEnvelopeV1.digest_result(result),
            executed_at=time.time(),
            duration_ms=duration_ms,
        )
        self.trail.record_envelope(envelope)
        return envelope


def make_guardrail_hook(provider, trail=None, on_deny=None):
    ctx = GuardrailContext(provider=provider, trail=trail, on_deny=on_deny)

    def _hook(tool_name, tool_args=None, agent_id="unknown", **kwargs):
        context = ToolCallContext(
            tool_name=tool_name, tool_args=tool_args or {}, agent_id=agent_id, metadata=kwargs
        )
        decision = ctx.authorize(context)
        if not decision.authorized:
            return False
        return None

    _hook._guardrail_context = ctx
    return _hook


def detect_missing_guardrail(agents):
    findings = []
    for agent in agents:
        agent_name = getattr(agent, "role", getattr(agent, "name", getattr(agent, "id", "unknown")))
        has_hooks = (
            getattr(agent, "_before_tool_call_hooks", None)
            or getattr(agent, "before_tool_call", None)
            or getattr(agent, "_guardrails", None)
            or getattr(agent, "guardrail_provider", None)
        )
        if not has_hooks:
            findings.append(
                {
                    "severity": "CRITICAL",
                    "pattern": "AS-GUARDRAIL-MISS-001",
                    "agent": agent_name,
                    "message": f"Agent '{agent_name}' has no registered GuardrailProvider",
                    "remediation": "Register a GuardrailProvider via make_guardrail_hook()",
                    "ccs_ref": "https://correctover.com/ccs",
                }
            )
    return findings


class MCPSecurityValidator:
    DANGEROUS_COMMANDS = [
        "rm -rf",
        "curl | sh",
        "wget | bash",
        "eval(",
        "exec(",
        "os.system",
        "subprocess.call",
    ]
    SENSITIVE_ENV_PATTERNS = [
        "API_KEY",
        "SECRET",
        "TOKEN",
        "PASSWORD",
        "PRIVATE_KEY",
        "CREDENTIALS",
        "AUTH",
    ]

    @staticmethod
    def validate_tool_definition(tool_def):
        issues = []
        impl = str(tool_def.get("implementation", ""))
        for cmd in MCPSecurityValidator.DANGEROUS_COMMANDS:
            if cmd in impl:
                issues.append(
                    {
                        "severity": "CRITICAL",
                        "type": "command_injection",
                        "pattern": cmd,
                        "cve_ref": "CVE-2026-42271",
                    }
                )
        env_section = str(tool_def.get("env", {}))
        for pattern in MCPSecurityValidator.SENSITIVE_ENV_PATTERNS:
            if pattern.upper() in env_section.upper():
                issues.append(
                    {
                        "severity": "HIGH",
                        "type": "env_exposure",
                        "pattern": pattern,
                        "cve_ref": "CVE-2026-12957",
                    }
                )
        return {
            "safe": len(issues) == 0,
            "issues": issues,
            "tool_name": tool_def.get("name", "unknown"),
        }

    @staticmethod
    def validate_mcp_config(config):
        issues = []
        transport = config.get("transport", "stdio")
        if transport == "stdio":
            env = config.get("env", {})
            if env:
                issues.append(
                    {
                        "severity": "HIGH",
                        "type": "stdio_env_exposure",
                        "message": "stdio transport with env variables",
                        "cve_ref": "CVE-2026-12957",
                        "remediation": "Use env_isolation or switch to sse/http transport",
                    }
                )
        for tool in config.get("tools", []):
            issues.extend(MCPSecurityValidator.validate_tool_definition(tool)["issues"])
        return {
            "safe": len(issues) == 0,
            "issues": issues,
            "config_name": config.get("name", "unknown"),
        }
