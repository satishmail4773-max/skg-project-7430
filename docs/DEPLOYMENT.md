# Production deployment

## Container runtime

Build and run behind a TLS ingress. The application is non-root and has no required write path or egress.

```bash
docker build --pull -t registry.example.com/specsentinel:0.2.0 .
docker run --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop ALL --security-opt no-new-privileges \
  --memory 512m --cpus 1 --pids-limit 128 \
  -e SPECSENTINEL_API_KEYS=... \
  -e SPECSENTINEL_BUNDLE_SIGNING_KEY=... \
  -p 127.0.0.1:8080:8080 registry.example.com/specsentinel:0.2.0
```

Use an immutable image digest after CI scanning/signing. Pinning the base-image digest is environment-specific and must be done in the customer's dependency update process rather than copied as a stale example.

## Gateway and platform checklist

- TLS 1.2+, service authentication, per-tenant rate/concurrency limits, and a 2 MB body cap
- Disable body capture in ingress, WAF, service mesh, traces, APM, crash reporting, and support tooling
- No egress NetworkPolicy; restricted Pod Security; read-only root filesystem; seccomp RuntimeDefault
- Memory/CPU limits, autoscaling on concurrency, disruption budget, and ephemeral nodes as policy requires
- Secrets manager injection and rotation; never put signing keys in image layers or CI logs
- Scrape `/metrics` through an authenticated internal path; export only aggregate fixed-label metrics
- Alert on 401/413/422/429/5xx rates, saturation, latency, restarts, and memory—not schema characteristics
- Store generated packs and audit evidence only in customer-controlled systems with their retention policy

## Key rotation

Configure a new signing secret and increment `SPECSENTINEL_BUNDLE_SIGNING_KEY_ID`. During rotation, deploy separate old/new instances or verify old packs with the archived old secret. SpecSentinel never stores keys or a key history.

## Failure behavior

Invalid input/policy returns 4xx without partial artifacts. Missing signing configuration returns 503. Oversized input/output returns 413. The process holds complete bounded request and ZIP bytes in memory, so size and concurrency limits must be calibrated together. Health is `/healthz`; readiness should additionally verify gateway policy and secret injection externally.

## CI/CD

The included GitHub Actions workflow runs Ruff, warnings-as-errors compilation, all tests, and a Docker build with read-only repository permissions. Add dependency review, SAST, SBOM generation, vulnerability policy, image signing, provenance, and environment approval using the organization's approved tools.
