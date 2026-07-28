from dataclasses import dataclass
from typing import Callable

from fastapi import HTTPException

from .models import Finding, PolicyConfig
from .schema import Operation

Rule = Callable[[dict, list[Operation]], list[Finding]]
SEVERITY_RANK = {"note": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _no_security_schemes(document: dict, _: list[Operation]) -> list[Finding]:
    if document.get("components", {}).get("securitySchemes", {}):
        return []
    return [Finding(severity="high", code="NO_SECURITY_SCHEMES", location="#/components", message="No security scheme is declared.")]


def _unauthenticated(_: dict, operations: list[Operation]) -> list[Finding]:
    return [Finding(severity="high", code="UNAUTHENTICATED_OPERATION", location=f"{op.method} {op.path}", message="Operation has no effective security requirement.") for op in operations if not op.has_auth]


def _no_429(document: dict, operations: list[Operation]) -> list[Finding]:
    return [Finding(severity="medium", code="NO_RATE_LIMIT_CONTRACT", location=f"{op.method} {op.path}", message="No 429 response is documented for machine-speed clients.") for op in operations if "429" not in document["paths"][op.path][op.method.lower()].get("responses", {})]


def _no_error(document: dict, operations: list[Operation]) -> list[Finding]:
    findings = []
    for op in operations:
        responses = document["paths"][op.path][op.method.lower()].get("responses", {})
        if not any(str(code).startswith(("4", "5")) for code in responses):
            findings.append(Finding(severity="medium", code="NO_ERROR_CONTRACT", location=f"{op.method} {op.path}", message="No error response schema is documented."))
    return findings


def _missing_operation_id(document: dict, operations: list[Operation]) -> list[Finding]:
    return [Finding(severity="low", code="MISSING_OPERATION_ID", location=f"{op.method} {op.path}", message="Explicit operationId is required for stable agent tool naming.") for op in operations if not document["paths"][op.path][op.method.lower()].get("operationId")]


def _insecure_server(document: dict, _: list[Operation]) -> list[Finding]:
    return [Finding(severity="high", code="INSECURE_SERVER_URL", location=f"#/servers/{index}/url", message="Non-TLS server URL is declared.") for index, server in enumerate(document.get("servers", [])) if isinstance(server, dict) and str(server.get("url", "")).startswith("http://")]


RULES: dict[str, Rule] = {
    "require_security_schemes": _no_security_schemes,
    "require_operation_security": _unauthenticated,
    "require_429_response": _no_429,
    "require_error_response": _no_error,
    "require_operation_id": _missing_operation_id,
    "require_https_servers": _insecure_server,
}


@dataclass(frozen=True)
class PolicyResult:
    findings: list[Finding]
    failed: bool


def evaluate_policy(document: dict, operations: list[Operation], policy: PolicyConfig) -> PolicyResult:
    selected = policy.enabled_rules if policy.enabled_rules is not None else list(RULES)
    unknown = (set(selected) | set(policy.disabled_rules) | set(policy.severity_overrides)) - set(RULES)
    if unknown:
        raise HTTPException(422, f"unknown policy rule(s): {', '.join(sorted(unknown))}")
    enabled = [name for name in selected if name not in policy.disabled_rules]
    findings: list[Finding] = []
    for name in enabled:
        for finding in RULES[name](document, operations):
            override = policy.severity_overrides.get(name)
            findings.append(finding.model_copy(update={"severity": override}) if override else finding)
            if len(findings) >= policy.max_findings:
                break
        if len(findings) >= policy.max_findings:
            break
    findings.sort(key=lambda item: (-SEVERITY_RANK[item.severity], item.code, item.location))
    threshold = SEVERITY_RANK.get(policy.fail_on, 99)
    return PolicyResult(findings=findings, failed=any(SEVERITY_RANK[item.severity] >= threshold for item in findings))

