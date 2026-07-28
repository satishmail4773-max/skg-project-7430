import copy

import pytest
from fastapi import HTTPException

from specsentinel.models import PolicyConfig
from specsentinel.policy import evaluate_policy
from specsentinel.schema import validate_openapi


def test_policy_overrides_severity_and_fails_threshold(openapi_schema):
    document = copy.deepcopy(openapi_schema)
    document["paths"]["/orders/{orderId}"]["get"]["responses"].pop("429")
    operations = validate_openapi(document, 10)
    policy = PolicyConfig(enabled_rules=["require_429_response"], severity_overrides={"require_429_response": "critical"}, fail_on="high")
    result = evaluate_policy(document, operations, policy)
    assert result.failed is True
    assert result.findings[0].severity == "critical"


def test_policy_can_disable_rule(openapi_schema):
    operations = validate_openapi(openapi_schema, 10)
    policy = PolicyConfig(disabled_rules=["require_operation_id", "require_https_servers"])
    assert evaluate_policy(openapi_schema, operations, policy).findings == []


def test_unknown_rule_fails_closed(openapi_schema):
    operations = validate_openapi(openapi_schema, 10)
    with pytest.raises(HTTPException, match="unknown policy"):
        evaluate_policy(openapi_schema, operations, PolicyConfig(enabled_rules=["run_python"]))


def test_findings_are_bounded(openapi_schema):
    document = copy.deepcopy(openapi_schema)
    document.pop("security")
    operations = validate_openapi(document, 10)
    result = evaluate_policy(document, operations, PolicyConfig(max_findings=1))
    assert len(result.findings) <= 1

