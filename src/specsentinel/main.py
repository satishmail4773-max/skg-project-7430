import hmac
import json
import re
import time
import uuid

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse
from pydantic import ValidationError

from . import __version__
from .config import Settings, get_settings
from .bundle import build_signed_bundle, chunks
from .diff import compare_schemas
from .generators import generate_artifacts
from .models import DiffRequest, DiffResponse, GenerateRequest, GenerateResponse
from .observability import metrics
from .policy import PolicyResult, evaluate_policy
from .sarif import sarif_artifact
from .schema import canonical_fingerprint, resolve_base_url, validate_openapi

app = FastAPI(title="SpecSentinel", version=__version__, docs_url="/docs", redoc_url=None)
settings = get_settings()
if settings.origin_list:
    app.add_middleware(CORSMiddleware, allow_origins=settings.origin_list, allow_methods=["POST", "GET"], allow_headers=["Authorization", "Content-Type"])


@app.middleware("http")
async def privacy_and_security_headers(request: Request, call_next):
    started = time.perf_counter()
    supplied_request_id = request.headers.get("x-request-id", "")
    request_id = supplied_request_id if re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", supplied_request_id) else str(uuid.uuid4())
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers.update({
        "Cache-Control": "no-store, max-age=0",
        "Pragma": "no-cache",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "X-Request-ID": request_id,
    })
    metrics.record(request.method, request.url.path, response.status_code, started)
    return response


def authorize(request: Request, config: Settings = Depends(get_settings)) -> None:
    if not config.api_key_set:
        return
    header = request.headers.get("authorization", "")
    candidate = header[7:] if header.lower().startswith("bearer ") else ""
    if not any(hmac.compare_digest(candidate, key) for key in config.api_key_set):
        raise HTTPException(401, "invalid or missing bearer token", headers={"WWW-Authenticate": "Bearer"})


@app.get("/healthz", include_in_schema=False)
async def healthz() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@app.get("/metrics", response_class=PlainTextResponse, dependencies=[Depends(authorize)], include_in_schema=False)
async def prometheus_metrics() -> str:
    return metrics.render()


async def parse_bounded_json(request: Request, model_type, config: Settings):
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        raise HTTPException(415, "content-type must be application/json")
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > config.max_schema_bytes:
        raise HTTPException(413, "request body exceeds configured limit")
    body = await request.body()
    if len(body) > config.max_schema_bytes:
        raise HTTPException(413, "request body exceeds configured limit")
    try:
        value = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
        raise HTTPException(400, "request body must be valid UTF-8 JSON") from None
    if exceeds_nesting_limit(value):
        raise HTTPException(422, "JSON nesting exceeds limit of 100 levels")
    try:
        return model_type.model_validate(value)
    except ValidationError as exc:
        raise RequestValidationError(exc.errors()) from None


def exceeds_nesting_limit(value, limit: int = 100) -> bool:
    stack = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > limit:
            return True
        if isinstance(current, dict):
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
    return False


def compile_request(payload: GenerateRequest, config: Settings) -> tuple[GenerateResponse, list]:
    document = payload.schema_document
    operations = validate_openapi(document, config.max_operations)
    base_url = resolve_base_url(document, payload.base_url)
    policy_result = evaluate_policy(document, operations, payload.policy) if payload.include_agent_security else PolicyResult([], False)
    artifacts = generate_artifacts(payload.targets, operations, base_url)
    artifacts.append(sarif_artifact(policy_result.findings))
    response = GenerateResponse(
        request_id="",
        schema_fingerprint=canonical_fingerprint(document),
        operation_count=len(operations),
        findings=policy_result.findings,
        policy_failed=policy_result.failed,
        artifacts=artifacts,
    )
    return response, artifacts


@app.post("/v1/generate", response_model=GenerateResponse, dependencies=[Depends(authorize)])
async def generate(request: Request, config: Settings = Depends(get_settings)) -> GenerateResponse:
    payload = await parse_bounded_json(request, GenerateRequest, config)
    response, _ = compile_request(payload, config)
    return response.model_copy(update={"request_id": request.state.request_id})


@app.post("/v1/diff", response_model=DiffResponse, dependencies=[Depends(authorize)])
async def diff(request: Request, config: Settings = Depends(get_settings)) -> DiffResponse:
    payload = await parse_bounded_json(request, DiffRequest, config)
    validate_openapi(payload.previous_schema, config.max_operations)
    validate_openapi(payload.current_schema, config.max_operations)
    score, level, changes = compare_schemas(payload.previous_schema, payload.current_schema)
    return DiffResponse(request_id=request.state.request_id, previous_fingerprint=canonical_fingerprint(payload.previous_schema), current_fingerprint=canonical_fingerprint(payload.current_schema), risk_score=score, risk_level=level, changes=changes)


@app.post("/v1/bundle", dependencies=[Depends(authorize)])
async def bundle(request: Request, config: Settings = Depends(get_settings)) -> StreamingResponse:
    payload = await parse_bounded_json(request, GenerateRequest, config)
    response, artifacts = compile_request(payload, config)
    data = build_signed_bundle(artifacts, response.schema_fingerprint, config.bundle_signing_key, config.bundle_signing_key_id, config.max_bundle_bytes)
    headers = {"Content-Disposition": 'attachment; filename="specsentinel.zip"', "X-SpecSentinel-Signature": "HMAC-SHA256", "X-SpecSentinel-Key-ID": config.bundle_signing_key_id}
    return StreamingResponse(chunks(data), media_type="application/zip", headers=headers)


@app.exception_handler(RequestValidationError)
async def validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(status_code=422, content={"detail": exc.errors()})
