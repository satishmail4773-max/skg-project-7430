# Threat model and misuse cases

## Scope and assets

Assets are proprietary API schemas, generated tests, runtime API tokens used later by customer test runners, bundle-signing secrets, service availability, and the trustworthiness of findings. The trust boundary starts at the TLS gateway and ends when the response leaves the application process. Gateways, sidecars, kernels, orchestrators, and clients are deployment-owner responsibilities.

## Threat actors

- An unauthenticated internet client seeking schema access or resource exhaustion
- A valid tenant attempting cross-tenant disclosure or denial of service
- A malicious schema author attempting SSRF, file reads, code execution, output injection, or ZIP traversal
- A compromised operator or observability agent capturing bodies or secrets
- A supply-chain attacker modifying dependencies, images, policies, or generated artifacts

## STRIDE analysis and controls

| Threat | Example | Current control | Residual risk/action |
|---|---|---|---|
| Spoofing | Reuse a static service key | Constant-time bearer comparison; gateway auth expected | Add short-lived JWT validation and tenant identity at gateway |
| Tampering | Modify generated tests in transit/storage | TLS deployment requirement; HMAC manifest and per-file SHA-256 | Shared-key holders can forge; add customer-managed asymmetric signing later |
| Repudiation | Dispute which schema produced a pack | Returned schema fingerprint and signed manifest | No durable audit log by design; customer stores evidence |
| Information disclosure | Body captured by APM or error log | No application body logging; bounded generic errors; no analytics/model calls | Infrastructure can still capture; deployment review is mandatory |
| Denial of service | Huge schema, operation explosion, compression pressure | Body, operation, finding, concurrency, and bundle bounds | Gateway rate/concurrency limits and memory limits remain required |
| Elevation/execution | `$ref` points to metadata service; policy contains code | No `$ref` resolution; declarative allowlisted rules; service never executes tests | Generated tests must run only in customer sandbox |

## Misuse cases

1. **Production mutation:** a user generates tests for POST/DELETE and runs them with privileged production credentials. Mitigation: this release does not synthesize request bodies and documentation requires scoped sandbox credentials; future mutation support must be explicit and disabled by default.
2. **Secret embedded as an OpenAPI example:** generated values could reproduce it. Mitigation: do not put real secrets in contracts; deploy DLP before submission. A future redactor should detect examples without silently changing contract semantics.
3. **Schema exfiltration through metrics:** attacker attempts unique paths/IDs. Mitigation: metrics have a fixed route allowlist and never label fingerprints, operations, tenants, sizes, or request IDs.
4. **Policy bypass:** attacker supplies an empty enabled-rule list. Mitigation: policy is caller-controlled by design; CI owners must pin reviewed policy files and protect branch rules.
5. **ZIP bomb/path traversal:** malicious paths enter archive. Mitigation: all filenames are internal constants, bundle size is bounded, and the service never extracts archives.
6. **Signature confusion:** a caller treats HMAC as public code signing. Mitigation: manifest states `HMAC-SHA256` and key ID; documentation explicitly limits its assurance.
7. **Retention misrepresentation:** deployment claims no retention while a proxy records bodies. Mitigation: product language distinguishes application behavior from infrastructure and contractual provider controls.

## LLM boundary

There is no LLM adapter in this release. A future adapter requires a separate review: disabled by default, explicit request consent, structured-output validation, timeout/size bounds, non-storage flags, allowlisted in-VPC or contractually approved ZDR endpoints, and no background/batch state. “Not trained on” must never be presented as “not retained.”
