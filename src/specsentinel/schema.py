import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Iterator
from urllib.parse import urlparse

from fastapi import HTTPException

from .models import Finding

HTTP_METHODS = ("get", "post", "put", "patch", "delete", "options", "head", "trace")
SECRET_RE = re.compile(r"(password|passwd|secret|token|api[-_]?key|authorization)", re.I)


@dataclass(frozen=True)
class Operation:
    method: str
    path: str
    operation_id: str
    success_status: int
    has_auth: bool
    parameters: tuple[dict[str, Any], ...]


def canonical_fingerprint(document: dict[str, Any]) -> str:
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def validate_openapi(document: dict[str, Any], max_operations: int) -> list[Operation]:
    version = document.get("openapi")
    if not isinstance(version, str) or not version.startswith("3."):
        raise HTTPException(422, "schema_document must be an OpenAPI 3.x document")
    paths = document.get("paths")
    if not isinstance(paths, dict):
        raise HTTPException(422, "OpenAPI document must contain an object-valued 'paths'")
    components = document.get("components", {})
    if not isinstance(components, dict):
        raise HTTPException(422, "OpenAPI 'components' must be an object")
    for name in ("securitySchemes", "schemas"):
        if name in components and not isinstance(components[name], dict):
            raise HTTPException(422, f"OpenAPI components.{name} must be an object")
    if not isinstance(document.get("servers", []), list):
        raise HTTPException(422, "OpenAPI 'servers' must be an array")
    if not isinstance(document.get("security", []), list):
        raise HTTPException(422, "OpenAPI 'security' must be an array")
    for path, path_item in paths.items():
        if not isinstance(path, str) or not isinstance(path_item, dict):
            raise HTTPException(422, "every OpenAPI path item must be an object")
        if "parameters" in path_item and not isinstance(path_item["parameters"], list):
            raise HTTPException(422, f"parameters for path {path} must be an array")
        for method in HTTP_METHODS:
            operation = path_item.get(method)
            if operation is None:
                continue
            if not isinstance(operation, dict):
                raise HTTPException(422, f"operation {method.upper()} {path} must be an object")
            if not isinstance(operation.get("responses", {}), dict):
                raise HTTPException(422, f"responses for {method.upper()} {path} must be an object")
            if "parameters" in operation and not isinstance(operation["parameters"], list):
                raise HTTPException(422, f"parameters for {method.upper()} {path} must be an array")
            if "security" in operation and not isinstance(operation["security"], list):
                raise HTTPException(422, f"security for {method.upper()} {path} must be an array")
    operations = list(iter_operations(document))
    if not operations:
        raise HTTPException(422, "OpenAPI document contains no operations")
    if len(operations) > max_operations:
        raise HTTPException(413, f"schema contains {len(operations)} operations; limit is {max_operations}")
    return operations


def iter_operations(document: dict[str, Any]) -> Iterator[Operation]:
    global_security = document.get("security", [])
    for path, path_item in document.get("paths", {}).items():
        if not isinstance(path, str) or not isinstance(path_item, dict):
            continue
        shared = path_item.get("parameters", [])
        for method in HTTP_METHODS:
            raw = path_item.get(method)
            if not isinstance(raw, dict):
                continue
            responses = raw.get("responses", {})
            success = next(
                (int(code) for code in responses if str(code).isdigit() and 200 <= int(code) < 300),
                200,
            )
            security = raw.get("security", global_security)
            params = tuple(p for p in [*shared, *raw.get("parameters", [])] if isinstance(p, dict))
            yield Operation(
                method=method.upper(),
                path=path,
                operation_id=str(raw.get("operationId") or f"{method}_{path}").strip(),
                success_status=success,
                has_auth=bool(security),
                parameters=params,
            )


def resolve_base_url(document: dict[str, Any], supplied: str | None) -> str:
    candidate = supplied or next(
        (server.get("url") for server in document.get("servers", []) if isinstance(server, dict)),
        "http://localhost:8000",
    )
    if not isinstance(candidate, str) or len(candidate) > 2_048:
        raise HTTPException(422, "base URL is invalid")
    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(422, "base URL must be an absolute http(s) URL")
    return candidate.rstrip("/")


def analyze(document: dict[str, Any], operations: list[Operation]) -> list[Finding]:
    findings: list[Finding] = []
    schemes = document.get("components", {}).get("securitySchemes", {})
    if not schemes:
        findings.append(Finding(severity="high", code="NO_SECURITY_SCHEMES", location="#/components", message="No security scheme is declared."))
    for op in operations:
        location = f"{op.method} {op.path}"
        if not op.has_auth:
            findings.append(Finding(severity="high", code="UNAUTHENTICATED_OPERATION", location=location, message="Operation has no effective security requirement."))
        raw = document["paths"][op.path][op.method.lower()]
        responses = raw.get("responses", {})
        if "429" not in responses:
            findings.append(Finding(severity="medium", code="NO_RATE_LIMIT_CONTRACT", location=location, message="No 429 response is documented for machine-speed clients."))
        if not any(str(code).startswith(("4", "5")) for code in responses):
            findings.append(Finding(severity="medium", code="NO_ERROR_CONTRACT", location=location, message="No error response schema is documented."))
    for name in document.get("components", {}).get("schemas", {}):
        if SECRET_RE.search(str(name)):
            findings.append(Finding(severity="low", code="SENSITIVE_SCHEMA_NAME", location=f"#/components/schemas/{name}", message="Potential secret-bearing schema; verify response redaction."))
    return findings
