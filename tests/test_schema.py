import copy

from specsentinel.schema import canonical_fingerprint, resolve_base_url, validate_openapi


def test_fingerprint_is_order_independent(openapi_schema):
    reordered = copy.deepcopy(openapi_schema)
    reordered["info"] = {"version": "1.0.0", "title": "Orders"}
    assert canonical_fingerprint(openapi_schema) == canonical_fingerprint(reordered)


def test_path_and_operation_parameters_are_combined(openapi_schema):
    operation = validate_openapi(openapi_schema, 10)[0]
    assert {p["name"] for p in operation.parameters} == {"orderId", "expand"}


def test_supplied_base_url_wins(openapi_schema):
    assert resolve_base_url(openapi_schema, "https://staging.example.test/") == "https://staging.example.test"

