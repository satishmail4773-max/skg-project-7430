import copy

from specsentinel.diff import compare_schemas


def test_unchanged_schema_has_low_zero_risk(openapi_schema):
    score, level, changes = compare_schemas(openapi_schema, copy.deepcopy(openapi_schema))
    assert (score, level, changes) == (0, "low", [])


def test_removed_operation_and_auth_are_high_risk(openapi_schema):
    current = copy.deepcopy(openapi_schema)
    current["paths"] = {}
    score, level, changes = compare_schemas(openapi_schema, current)
    assert score == 30
    assert level == "critical"
    assert changes[0].kind == "operation_removed"


def test_diff_score_is_capped_and_order_is_deterministic(openapi_schema):
    previous = copy.deepcopy(openapi_schema)
    current = copy.deepcopy(openapi_schema)
    for index in range(10):
        previous["paths"][f"/legacy/{index}"] = {"get": {"responses": {"200": {"description": "OK"}}}}
    first = compare_schemas(previous, current)
    second = compare_schemas(previous, current)
    assert first == second
    assert first[0] == 100
    assert first[1] == "critical"


def test_required_parameter_and_removed_success_add_risk(openapi_schema):
    current = copy.deepcopy(openapi_schema)
    operation = current["paths"]["/orders/{orderId}"]["get"]
    operation["parameters"].append({"name": "tenant", "in": "header", "required": True, "schema": {"type": "string"}})
    operation["responses"].pop("200")
    score, _, changes = compare_schemas(openapi_schema, current)
    assert score == 25
    assert {change.kind for change in changes} == {"required_parameter_added", "success_response_removed"}
