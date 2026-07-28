import json

from .models import Artifact, Finding


def sarif_artifact(findings: list[Finding]) -> Artifact:
    rules = {}
    for finding in findings:
        rules[finding.code] = {
            "id": finding.code,
            "shortDescription": {"text": finding.message},
            "properties": {"security-severity": finding.severity},
        }
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "note": "note"}
    results = [{
        "ruleId": finding.code,
        "level": level[finding.severity],
        "message": {"text": finding.message},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "openapi.json"}, "region": {"snippet": {"text": finding.location}}}}],
    } for finding in findings]
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "SpecSentinel", "informationUri": "https://example.invalid/specsentinel", "rules": [rules[key] for key in sorted(rules)]}}, "results": results}],
    }
    return Artifact(filename="reports/specsentinel.sarif.json", media_type="application/sarif+json", content=json.dumps(document, sort_keys=True, indent=2))

