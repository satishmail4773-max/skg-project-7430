# SpecSentinel

SpecSentinel is a stateless “AI-agent API readiness compiler.” It converts a proprietary OpenAPI 3.x contract into runnable Postman/Newman, PyTest, and TypeScript/Playwright contract packs, while flagging authentication, rate-limit, and error-contract gaps that become dangerous when autonomous agents call APIs at machine speed. Version 0.2 adds deterministic schema-diff risk scoring, bounded policy-as-code, SARIF, a local CLI, signed ZIP streaming, and metadata-only Prometheus metrics.

It is an opinionated, production-deployable MVP: deterministic generation is the default and no model receives the customer schema. The service has no database, queue, analytics SDK, request-body logging, or filesystem writes.

## Why this is the opportunity

Postman's 2025 survey reports that 89% of developers use generative AI, only 24% actively design APIs for agents, and contract testing is used by just 17%. It also reports that 51% worry about unauthorized or excessive agent API calls. That creates a specific buyer problem: platform teams need evidence that proprietary APIs are safe for non-human consumers, in test runners they already use.

This is adjacent to—not a claim of having built—artificial superintelligence. The near-term commercial trend is infrastructure that makes increasingly autonomous systems observable, least-privileged, contract-bound, and testable. See [docs/PRODUCT.md](docs/PRODUCT.md) for positioning and revenue math.

## Quick start

Python 3.11+:

```bash
python -m venv .venv
.venv/Scripts/pip install -e ".[dev]"
.venv/Scripts/uvicorn specsentinel.main:app --reload --no-access-log
```

Or Docker:

```bash
docker build -t specsentinel .
docker run --read-only --tmpfs /tmp --cap-drop ALL -p 8080:8080 \
  -e SPECSENTINEL_API_KEYS=replace-with-a-long-random-key specsentinel
```

Generate a pack:

```bash
curl -sS http://localhost:8080/v1/generate \
  -H "Authorization: Bearer replace-with-a-long-random-key" \
  -H "Content-Type: application/json" \
  --data @request.json > generated.json
```

`request.json`:

```json
{
  "schema_document": {"openapi":"3.1.0","info":{"title":"Orders","version":"1"},"servers":[{"url":"https://api.example.com"}],"paths":{"/health":{"get":{"responses":{"200":{"description":"OK"}}}}}},
  "targets": ["postman", "pytest", "playwright"],
  "include_agent_security": true
}
```

The JSON response contains a SHA-256 schema fingerprint, policy result, findings, SARIF, and in-memory text artifacts. A client extracts each `artifacts[].content` to its `filename`.

## CLI

The CLI performs the same compilation locally. `generate` writes JSON to stdout. `bundle` writes only to the explicit path and refuses to overwrite an existing file.

```bash
specsentinel generate openapi.json --targets pytest playwright > result.json
specsentinel diff previous.json current.json
SPECSENTINEL_BUNDLE_SIGNING_KEY=... specsentinel bundle openapi.json specsentinel.zip
```

Diff exits `2` when the result is high or critical. Generation exits `2` when configured `policy.fail_on` is met, making both suitable for CI gates.

## Policy-as-code

Policy is declarative JSON inside `policy`; it cannot import or execute code. Available rule IDs are `require_security_schemes`, `require_operation_security`, `require_429_response`, `require_error_response`, `require_operation_id`, and `require_https_servers`.

```json
{
  "enabled_rules": ["require_operation_security", "require_429_response"],
  "severity_overrides": {"require_429_response": "high"},
  "fail_on": "high",
  "max_findings": 200
}
```

Unknown rule IDs, invalid severities, oversized policies, and invalid schemas fail closed.

## Running generated artifacts

- Newman: `newman run postman/specsentinel.collection.json --env-var apiToken=$API_TOKEN`
- PyTest: `API_BASE_URL=https://staging.example.com API_TOKEN=... pytest pytest/`
- Playwright: `API_BASE_URL=https://staging.example.com API_TOKEN=... npx playwright test playwright/`

Generated authenticated tests skip when `API_TOKEN` is absent, never embed credentials, use 15-second timeouts, reject redirects, and cap failure-body output at 1,000 characters.

## API and configuration

`POST /v1/generate` returns JSON artifacts. `POST /v1/diff` compares complete previous/current schemas. `POST /v1/bundle` streams a signed ZIP and fails with `503` unless signing is configured. `GET /metrics` exposes bounded route/status/count/duration metadata. `GET /healthz` is suitable for probes. POST endpoints accept `application/json` only. Interactive API docs are at `/docs`.

| Variable | Default | Purpose |
|---|---:|---|
| `SPECSENTINEL_API_KEYS` | empty | Comma-separated bearer keys; empty disables auth for local development |
| `SPECSENTINEL_MAX_SCHEMA_BYTES` | `2000000` | Maximum complete request size |
| `SPECSENTINEL_MAX_OPERATIONS` | `500` | Defends against pathological contracts |
| `SPECSENTINEL_ALLOWED_ORIGINS` | empty | Explicit comma-separated CORS allowlist |
| `SPECSENTINEL_BUNDLE_SIGNING_KEY` | empty | HMAC secret; empty disables bundle generation |
| `SPECSENTINEL_BUNDLE_SIGNING_KEY_ID` | `default` | Non-secret key rotation identifier |
| `SPECSENTINEL_MAX_BUNDLE_BYTES` | `8000000` | Maximum in-memory ZIP response |

For production, require authentication at both the service and gateway, enforce TLS, keep the container read-only, rate-limit per tenant, disable infrastructure body logging, and use ephemeral compute. The application sets `Cache-Control: no-store`, emits only an opaque request ID, and starts Uvicorn with access logs disabled.

## Privacy boundary

“Stateless” means this application does not persist the request or response. It cannot by itself guarantee that a reverse proxy, service mesh, APM agent, cloud load balancer, crash dump, or client does not retain them. The deployment owner must disable body capture in those systems. See [docs/SECURITY.md](docs/SECURITY.md).

No external LLM is called in this version. This is intentional: setting an API option such as `store=false` is not equivalent to contractual zero data retention. If semantic LLM enrichment is later added, require a customer-approved ZDR endpoint or an in-VPC model and make it opt-in per request. Application controls can request non-storage and prevent local persistence; provider retention guarantees remain contractual and deployment-specific.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
```

Tests cover invalid documents, policies, diff risk, SARIF, signature verification, deterministic bundle bytes, CLI/API integration, randomized invariants, URL safety, privacy headers, and all artifact targets.

## Current limitations

- OpenAPI 3.x JSON is supported; YAML should be converted client-side to keep content-type handling unambiguous.
- `$ref` values are preserved, not dereferenced. This avoids SSRF and local-file disclosure. Bundled schemas are recommended.
- Request bodies are not synthesized yet; the MVP focuses on safe read/contract checks and auth-negative tests. Mutating calls should require an explicit sandbox tenant and cleanup policy before automated execution.
- Findings are guardrails, not a penetration test or compliance certification.
- Diffing is intentionally conservative but not a full OpenAPI semantic-compatibility proof; it currently scores operation removal, authentication removal, new required parameters/properties, removed success responses, and removed component schemas.
- HMAC proves integrity/authenticity to parties sharing the secret. It does not provide asymmetric identity or non-repudiation. Rotate keys using `key_id` and distribute them outside SpecSentinel.
- In-process metrics reset on restart and intentionally omit tenant, fingerprint, path parameters, filenames, sizes, and schema content.

Detailed operational guidance is in [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md), the abuse analysis is in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), and release gates are in [docs/ACCEPTANCE_CRITERIA.md](docs/ACCEPTANCE_CRITERIA.md).
