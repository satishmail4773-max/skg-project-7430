# Acceptance criteria and release gates

## Functional

- Valid OpenAPI 3.x produces deterministic Postman, PyTest, Playwright, and SARIF content.
- Diff results are deterministic, capped at 100, and identify the supported breaking/security changes.
- Policies select only known built-in rules, cap findings, override valid severities, and expose a CI failure decision.
- Signed bundles contain every artifact, canonical manifest, per-file SHA-256, HMAC-SHA256 signature, and key ID.
- CLI and HTTP produce equivalent compilation results; CLI refuses output overwrite.

## Security and privacy

- No database, queue, analytics SDK, model call, remote `$ref`, callback, generated-code execution, or body logging.
- Invalid JSON, content type, schema, target, URL, policy, size, and operation count fail closed.
- Application works with no egress and a read-only filesystem as a non-root user.
- Observability contains only fixed route, method, status, aggregate count, and duration labels.
- A deployment review confirms proxy/APM/body logging is disabled; this cannot be proven by application tests.

## Quality gates

- Unit, endpoint integration, CLI integration, randomized property/invariant, lint, and warnings-as-errors compilation pass.
- Container builds and health check passes in CI; vulnerability and license policy are organization-defined release gates.
- Independent threat-model review and penetration test are required before regulated production data.

## Commercial acceptance

- Five design partners can generate a useful CI pack in under 15 minutes without sending a schema to a model.
- At least 80% of generated non-mutating tests run without manual syntax repair.
- Buyers validate the private deployment/data-flow statement and accept the documented diff coverage.
- Pricing is tested with paid pilots; revenue outcomes remain targets, never guarantees.
