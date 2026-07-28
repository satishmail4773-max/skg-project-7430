from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class Target(StrEnum):
    POSTMAN = "postman"
    PYTEST = "pytest"
    PLAYWRIGHT = "playwright"


class GenerateRequest(BaseModel):
    schema_document: dict[str, Any]
    targets: list[Target] = Field(default_factory=lambda: list(Target), min_length=1)
    base_url: str | None = Field(default=None, max_length=2_048)
    include_agent_security: bool = True
    policy: "PolicyConfig" = Field(default_factory=lambda: PolicyConfig())

    @field_validator("targets")
    @classmethod
    def unique_targets(cls, value: list[Target]) -> list[Target]:
        return list(dict.fromkeys(value))


class Finding(BaseModel):
    severity: str
    code: str
    location: str
    message: str


class PolicyConfig(BaseModel):
    enabled_rules: list[str] | None = None
    disabled_rules: list[str] = Field(default_factory=list, max_length=32)
    severity_overrides: dict[str, str] = Field(default_factory=dict)
    fail_on: str | None = None
    max_findings: int = Field(default=500, ge=1, le=2_000)

    @field_validator("disabled_rules")
    @classmethod
    def unique_disabled_rules(cls, value: list[str]) -> list[str]:
        return list(dict.fromkeys(value))

    @field_validator("severity_overrides")
    @classmethod
    def valid_severities(cls, value: dict[str, str]) -> dict[str, str]:
        allowed = {"note", "low", "medium", "high", "critical"}
        if any(severity not in allowed for severity in value.values()):
            raise ValueError("severity overrides must be note, low, medium, high, or critical")
        return value

    @field_validator("fail_on")
    @classmethod
    def valid_fail_on(cls, value: str | None) -> str | None:
        if value is not None and value not in {"low", "medium", "high", "critical"}:
            raise ValueError("fail_on must be low, medium, high, or critical")
        return value


class DiffRequest(BaseModel):
    previous_schema: dict[str, Any]
    current_schema: dict[str, Any]


class DiffChange(BaseModel):
    kind: str
    severity: str
    location: str
    message: str
    points: int


class DiffResponse(BaseModel):
    request_id: str
    previous_fingerprint: str
    current_fingerprint: str
    risk_score: int
    risk_level: str
    changes: list[DiffChange]


class Artifact(BaseModel):
    filename: str
    media_type: str
    content: str


class GenerateResponse(BaseModel):
    request_id: str
    schema_fingerprint: str
    operation_count: int
    findings: list[Finding]
    policy_failed: bool = False
    artifacts: list[Artifact]
    privacy: str = "Processed in memory; request and generated artifacts are not persisted."
