import json

from specsentinel.models import Finding
from specsentinel.sarif import sarif_artifact


def test_sarif_is_valid_shape_and_deterministic():
    findings = [Finding(severity="high", code="AUTH", location="GET /orders", message="Auth required")]
    first = sarif_artifact(findings)
    second = sarif_artifact(findings)
    assert first.content == second.content
    data = json.loads(first.content)
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["results"][0]["level"] == "error"

