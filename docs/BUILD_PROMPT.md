# Improved build prompt

Use this prompt for the next product iteration:

> Act as a principal AI platform engineer, AppSec architect, and B2B SaaS product lead. Extend SpecSentinel, a stateless API-agent readiness compiler for enterprise OpenAPI 3.x schemas. Its primary users run Postman/Newman, PyTest, or TypeScript/Playwright. Preserve these non-negotiable constraints: schema and generated content remain in memory only; no request/response body logs, analytics, database, queue, or model training; no external `$ref` resolution; no generated test execution by the service; bounded input, time, and operation counts; fail closed on invalid input; deterministic artifacts; secrets supplied only at test runtime. Add schema-diff risk scoring, SARIF output, a CLI, signed ZIP streaming, and policy-as-code. If LLM enrichment is proposed, keep it disabled by default, support an in-VPC provider, require explicit per-request consent for any hosted ZDR provider, set non-storage options, validate structured output, and state which retention guarantees are contractual versus application-enforced. Include threat modeling, misuse cases, unit/integration/property tests, container hardening, CI, observability using metadata only, deployment instructions, pricing assumptions, acceptance criteria, and clearly documented limitations. Never claim ASI, compliance certification, zero retention across infrastructure, or guaranteed revenue without evidence.

## Product discovery questions

1. Which first vertical should dictate policies and sales language: fintech, healthcare, insurance, or general B2B SaaS?
2. Must the first paid release be hosted SaaS, a customer-VPC private runner, or both?
3. May any schema subset reach a contractually approved Zero Data Retention provider, or must all semantic inference run inside the customer's network?
4. Is OpenAPI sufficient for the first release, or are GraphQL, AsyncAPI, protobuf, and MCP tool schemas required?
5. Which identity system and CI providers matter first (for example, Okta plus GitHub Enterprise)?

