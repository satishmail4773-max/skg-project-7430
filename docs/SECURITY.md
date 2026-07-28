# Security and stateless-processing model

## Data flow

`client -> TLS gateway -> ephemeral SpecSentinel process memory -> client`

The application parses one bounded JSON body, validates it, creates artifacts in memory, returns JSON, and releases references after the request. There is no persistence component. Schema fingerprints are returned to the caller but not recorded by the application.

## Controls implemented

- Constant-time bearer-key comparison when API keys are configured
- Two request-size checks (declared and actual bytes) and an operation-count limit
- No remote or local `$ref` resolution, preventing schema-driven SSRF/file access
- Absolute HTTP(S) base URL validation
- Explicit CORS allowlist only
- `no-store`, clickjacking, MIME-sniffing, and referrer security headers
- Opaque request IDs; no schema content in errors
- Non-root Docker user and no access logs
- No outbound model or telemetry calls
- Deterministic ZIP manifests signed with HMAC-SHA256; bundle creation is disabled without a key
- Metadata-only in-memory metrics with fixed route labels

## Deployment requirements

1. Terminate TLS at a trusted gateway and cap request size there too.
2. Disable request/response body capture in ingress, WAF, APM, tracing, error reporting, and cloud diagnostics.
3. Run with a read-only filesystem, dropped Linux capabilities, ephemeral instances, and no swap where policy requires it.
4. Store API keys in a secrets manager; rotate them and prefer gateway-issued short-lived JWTs in a mature deployment.
5. Apply per-tenant rate limits and concurrency limits at the gateway.
6. Restrict egress. This version needs no outbound network access.
7. Run generated tests only against a sandbox tenant with scoped, synthetic credentials.
8. Perform threat modeling, SAST/dependency scans, container signing, and an independent penetration test before handling regulated data.
9. Keep signing keys outside environment dumps where the platform supports mounted secret files; this MVP accepts environment configuration and should be integrated with the target secrets manager before production.

## Threats intentionally avoided

External `$ref` expansion, arbitrary templates, code execution, archive extraction, user-controlled filenames, callbacks/webhooks, and direct execution of generated tests are excluded. They are common paths for SSRF, traversal, injection, exfiltration, and destructive API calls.

## Optional LLM enrichment policy

Do not claim “zero retention” merely because training is disabled. A future provider adapter must be off by default, allow only organization-approved endpoints, set non-storage flags, avoid background/batch features, validate structured output, and document the provider's contractual retention. For strict customers, run the model in their VPC and prohibit network egress.
