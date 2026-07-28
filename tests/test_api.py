from fastapi.testclient import TestClient

from specsentinel.config import Settings, get_settings
from specsentinel.main import app

client = TestClient(app)


def test_health_has_no_store_header():
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.headers["cache-control"].startswith("no-store")
    assert response.headers["x-content-type-options"] == "nosniff"


def test_generate_all_targets(openapi_schema):
    response = client.post("/v1/generate", json={"schema_document": openapi_schema})
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["operation_count"] == 1
    assert len(result["schema_fingerprint"]) == 64
    assert {item["filename"] for item in result["artifacts"]} == {
        "postman/specsentinel.collection.json",
        "pytest/test_specsentinel_contract.py",
        "playwright/specsentinel.spec.ts",
        "reports/specsentinel.sarif.json",
    }
    assert result["findings"] == []
    assert "42" in result["artifacts"][0]["content"]


def test_rejects_non_openapi_document():
    response = client.post("/v1/generate", json={"schema_document": {"paths": {}}})
    assert response.status_code == 422
    assert "OpenAPI 3.x" in response.json()["detail"]


def test_rejects_empty_operations(openapi_schema):
    openapi_schema["paths"] = {}
    response = client.post("/v1/generate", json={"schema_document": openapi_schema})
    assert response.status_code == 422


def test_rejects_invalid_target(openapi_schema):
    response = client.post("/v1/generate", json={"schema_document": openapi_schema, "targets": ["junit"]})
    assert response.status_code == 422


def test_detects_agent_readiness_gaps(openapi_schema):
    openapi_schema["components"].pop("securitySchemes")
    openapi_schema.pop("security")
    openapi_schema["paths"]["/orders/{orderId}"]["get"]["responses"].pop("429")
    result = client.post("/v1/generate", json={"schema_document": openapi_schema}).json()
    assert {finding["code"] for finding in result["findings"]} >= {
        "NO_SECURITY_SCHEMES", "UNAUTHENTICATED_OPERATION", "NO_RATE_LIMIT_CONTRACT"
    }


def test_base_url_must_be_absolute(openapi_schema):
    response = client.post("/v1/generate", json={"schema_document": openapi_schema, "base_url": "file:///etc/passwd"})
    assert response.status_code == 422


def test_invalid_json_returns_400():
    response = client.post("/v1/generate", content=b"{", headers={"content-type": "application/json"})
    assert response.status_code == 400


def test_excessively_nested_json_returns_422():
    body = b'{"schema_document":' + (b'{"x":' * 1500) + b"0" + (b"}" * 1500) + b"}"
    response = client.post("/v1/generate", content=body, headers={"content-type": "application/json"})
    assert response.status_code == 422
    assert "nesting" in response.json()["detail"]


def test_malformed_openapi_container_types_fail_closed(openapi_schema):
    openapi_schema["components"] = "not-an-object"
    response = client.post("/v1/generate", json={"schema_document": openapi_schema})
    assert response.status_code == 422
    assert "components" in response.json()["detail"]


def test_unsafe_request_id_is_not_reflected():
    response = client.get("/healthz", headers={"x-request-id": "unsafe value"})
    assert response.status_code == 200
    assert response.headers["x-request-id"] != "unsafe value"


def test_rejects_wrong_content_type():
    response = client.post("/v1/generate", content=b"{}", headers={"content-type": "text/plain"})
    assert response.status_code == 415


def test_diff_endpoint(openapi_schema):
    current = {**openapi_schema, "paths": {}}
    response = client.post("/v1/diff", json={"previous_schema": openapi_schema, "current_schema": current})
    assert response.status_code == 422  # empty contracts fail closed

    current = {**openapi_schema, "security": []}
    response = client.post("/v1/diff", json={"previous_schema": openapi_schema, "current_schema": current})
    assert response.status_code == 200
    assert response.json()["risk_score"] == 35


def test_bundle_endpoint_streams_signed_zip(openapi_schema):
    app.dependency_overrides[get_settings] = lambda: Settings(bundle_signing_key="integration-secret", bundle_signing_key_id="test-key")
    try:
        response = client.post("/v1/bundle", json={"schema_document": openapi_schema})
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/zip"
    assert response.headers["x-specsentinel-key-id"] == "test-key"
    assert response.content.startswith(b"PK")


def test_metrics_contains_only_bounded_route_labels():
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "specsentinel_requests_total" in response.text
    assert "schema" not in response.text.lower()
