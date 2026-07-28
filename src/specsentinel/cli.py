import argparse
import json
import sys
from pathlib import Path

from fastapi import HTTPException

from .bundle import build_signed_bundle
from .config import Settings
from .diff import compare_schemas
from .main import compile_request
from .models import GenerateRequest
from .schema import canonical_fingerprint, validate_openapi


def _load(path: str, limit: int) -> dict:
    source = Path(path)
    if not source.is_file() or source.stat().st_size > limit:
        raise ValueError(f"input must be a file no larger than {limit} bytes")
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read valid UTF-8 JSON from {path}: {exc}") from None
    if not isinstance(value, dict):
        raise ValueError("input document must be a JSON object")
    return value


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="specsentinel", description="Stateless OpenAPI agent-readiness compiler")
    sub = root.add_subparsers(dest="command", required=True)
    generate = sub.add_parser("generate", help="generate artifacts as JSON on stdout")
    generate.add_argument("schema")
    generate.add_argument("--base-url")
    generate.add_argument("--targets", nargs="+", default=["postman", "pytest", "playwright"])
    generate.add_argument("--policy", help="JSON policy file")
    bundle = sub.add_parser("bundle", help="write a signed ZIP bundle")
    bundle.add_argument("schema")
    bundle.add_argument("output")
    bundle.add_argument("--base-url")
    bundle.add_argument("--policy")
    diff = sub.add_parser("diff", help="score risk between two schemas")
    diff.add_argument("previous")
    diff.add_argument("current")
    return root


def _request(args, config: Settings) -> GenerateRequest:
    payload = {"schema_document": _load(args.schema, config.max_schema_bytes), "base_url": args.base_url}
    if hasattr(args, "targets"):
        payload["targets"] = args.targets
    if args.policy:
        payload["policy"] = _load(args.policy, 64_000)
    return GenerateRequest.model_validate(payload)


def run(args: argparse.Namespace, config: Settings) -> int:
    if args.command == "diff":
        previous, current = _load(args.previous, config.max_schema_bytes), _load(args.current, config.max_schema_bytes)
        validate_openapi(previous, config.max_operations)
        validate_openapi(current, config.max_operations)
        score, level, changes = compare_schemas(previous, current)
        print(json.dumps({"previous_fingerprint": canonical_fingerprint(previous), "current_fingerprint": canonical_fingerprint(current), "risk_score": score, "risk_level": level, "changes": [item.model_dump() for item in changes]}, indent=2))
        return 2 if level in {"high", "critical"} else 0
    response, artifacts = compile_request(_request(args, config), config)
    if args.command == "generate":
        print(response.model_dump_json(indent=2))
        return 2 if response.policy_failed else 0
    data = build_signed_bundle(artifacts, response.schema_fingerprint, config.bundle_signing_key, config.bundle_signing_key_id, config.max_bundle_bytes)
    output = Path(args.output)
    if output.exists():
        raise ValueError("refusing to overwrite existing output")
    output.write_bytes(data)
    print(json.dumps({"output": str(output), "bytes": len(data), "schema_fingerprint": response.schema_fingerprint}))
    return 0


def main() -> None:
    try:
        raise SystemExit(run(parser().parse_args(), Settings()))
    except (ValueError, HTTPException) as exc:
        detail = exc.detail if isinstance(exc, HTTPException) else str(exc)
        print(f"error: {detail}", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
