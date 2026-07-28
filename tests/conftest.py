import pytest


@pytest.fixture
def openapi_schema():
    return {
        "openapi": "3.1.0",
        "info": {"title": "Orders", "version": "1.0.0"},
        "servers": [{"url": "https://api.example.test"}],
        "components": {
            "securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}},
            "schemas": {"Order": {"type": "object"}},
        },
        "security": [{"bearerAuth": []}],
        "paths": {
            "/orders/{orderId}": {
                "parameters": [{"name": "orderId", "in": "path", "required": True, "schema": {"type": "integer", "example": 42}}],
                "get": {
                    "operationId": "getOrder",
                    "parameters": [{"name": "expand", "in": "query", "required": True, "schema": {"type": "string", "enum": ["items"]}}],
                    "responses": {"200": {"description": "OK"}, "401": {"description": "Unauthorized"}, "429": {"description": "Limited"}},
                },
            }
        },
    }

