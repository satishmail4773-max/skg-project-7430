from typing import Any

from .models import DiffChange
from .schema import HTTP_METHODS


def _operations(document: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    result = {}
    for path, item in document.get("paths", {}).items():
        if not isinstance(item, dict):
            continue
        for method in HTTP_METHODS:
            if isinstance(item.get(method), dict):
                result[(method.upper(), path)] = item[method]
    return result


def _effective_security(document: dict, operation: dict) -> bool:
    return bool(operation.get("security", document.get("security", [])))


def _parameters(operation: dict) -> dict[tuple[str, str], dict]:
    return {(str(p.get("in")), str(p.get("name"))): p for p in operation.get("parameters", []) if isinstance(p, dict)}


def _success_codes(operation: dict) -> set[str]:
    return {str(code) for code in operation.get("responses", {}) if str(code).isdigit() and 200 <= int(code) < 300}


def _change(kind: str, severity: str, location: str, message: str, points: int) -> DiffChange:
    return DiffChange(kind=kind, severity=severity, location=location, message=message, points=points)


def compare_schemas(previous: dict[str, Any], current: dict[str, Any]) -> tuple[int, str, list[DiffChange]]:
    old_ops, new_ops = _operations(previous), _operations(current)
    changes: list[DiffChange] = []
    for key in sorted(old_ops.keys() - new_ops.keys()):
        changes.append(_change("operation_removed", "critical", f"{key[0]} {key[1]}", "Operation was removed.", 30))
    for key in sorted(new_ops.keys() - old_ops.keys()):
        changes.append(_change("operation_added", "note", f"{key[0]} {key[1]}", "Operation was added.", 0))
    for key in sorted(old_ops.keys() & new_ops.keys()):
        location = f"{key[0]} {key[1]}"
        old, new = old_ops[key], new_ops[key]
        if _effective_security(previous, old) and not _effective_security(current, new):
            changes.append(_change("security_removed", "critical", location, "Effective authentication requirement was removed.", 35))
        old_params, new_params = _parameters(old), _parameters(new)
        for param in sorted(new_params.keys() - old_params.keys()):
            if new_params[param].get("required"):
                changes.append(_change("required_parameter_added", "high", location, f"Required {param[0]} parameter '{param[1]}' was added.", 15))
        for param in sorted(old_params.keys() & new_params.keys()):
            if not old_params[param].get("required") and new_params[param].get("required"):
                changes.append(_change("parameter_became_required", "high", location, f"Parameter '{param[1]}' became required.", 15))
        removed_success = sorted(_success_codes(old) - _success_codes(new))
        for status in removed_success:
            changes.append(_change("success_response_removed", "medium", location, f"Success response {status} was removed.", 10))
    old_schemas = previous.get("components", {}).get("schemas", {})
    new_schemas = current.get("components", {}).get("schemas", {})
    if isinstance(old_schemas, dict) and isinstance(new_schemas, dict):
        for name in sorted(old_schemas.keys() - new_schemas.keys()):
            changes.append(_change("component_schema_removed", "high", f"#/components/schemas/{name}", "Component schema was removed.", 20))
        for name in sorted(old_schemas.keys() & new_schemas.keys()):
            old_required = set(old_schemas[name].get("required", [])) if isinstance(old_schemas[name], dict) else set()
            new_required = set(new_schemas[name].get("required", [])) if isinstance(new_schemas[name], dict) else set()
            for prop in sorted(new_required - old_required):
                changes.append(_change("schema_property_became_required", "high", f"#/components/schemas/{name}/required", f"Property '{prop}' became required.", 15))
    changes.sort(key=lambda item: (item.location, item.kind, item.message))
    score = min(100, sum(change.points for change in changes))
    ranked = {"note": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    score_level = "critical" if score >= 70 else "high" if score >= 40 else "medium" if score >= 15 else "low"
    level = max([score_level, *(change.severity for change in changes)], key=ranked.__getitem__)
    return score, level, changes
