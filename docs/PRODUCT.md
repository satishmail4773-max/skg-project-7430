# Product thesis and go-to-market

## Product

**SpecSentinel: private API readiness gates for autonomous agents.** The wedge is a CLI/API that turns an enterprise contract into native tests for the customer's existing CI. The expansion product adds GitHub/GitLab checks, schema-diff risk scoring, policy-as-code, private runners, SSO/RBAC, audit evidence, and an in-VPC semantic test generator.

The practical “next ASI” work is not predicting a date for superintelligence. It is engineering controllability around systems with increasing agency: agent identity, least privilege, tool-contract enforcement, prompt/goal hijack tests, trace-based evaluations, memory poisoning defenses, and kill switches. SpecSentinel enters through API contracts—the boundary agents actually invoke.

## Ideal customers and buyer

- 200–5,000 person fintech, healthtech, insurance, and B2B SaaS companies
- Platform engineering, API governance, AppSec, and developer-experience teams
- Organizations already standardized on Newman, PyTest, or Playwright
- Trigger events: launching agents, MCP tools, partner APIs, regulatory review, or a breaking API incident

## Revenue model (target, not a guarantee)

No product can credibly guarantee $100,000 quarter-over-quarter revenue. A testable route to **$100k quarterly recurring revenue** is:

| Plan | Price | Quarterly customers | Quarterly revenue |
|---|---:|---:|---:|
| Team | $499/month | 20 | $29,940 |
| Business | $1,500/month | 10 | $45,000 |
| Enterprise private runner | $25,000/year | 4 | $25,000 recognized/quarter |
| Total | | 34 | $99,940 |

The first milestone is five paid design partners, not feature volume. Sell an “agent API readiness assessment” that produces CI evidence in one week; convert it to annual platform contracts. Track time-to-first-generated-test, tests accepted without edits, prevented breaking changes, expansion seats, and gross retention.

## Differentiation

Generic AI test generators often copy proprietary specifications to a hosted model and return framework-specific code with uncertain repeatability. SpecSentinel's core compiler is deterministic, multi-runner, schema-fingerprinted, and model-free. Private semantic enrichment is an optional deployment tier, not an invisible data path.

## Build sequence

1. MVP (this repository): stateless OpenAPI compiler, three runners, basic agent-readiness findings.
2. Design-partner release: CLI, signed ZIP bundles, Spectral-compatible policies, schema diff, SARIF, tenant rate limits.
3. Business tier: Git providers, SSO, audit events containing hashes only, customer-managed object storage.
4. Enterprise: Helm chart/private runner, customer-managed keys, in-VPC LLM, policy approval workflow.

## Current evidence

- [Postman 2025 State of the API](https://www.postman.com/state-of-api/2025/) reports the agent/API adoption and testing gap used in this thesis.
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) frames current risks including goal hijacking, tool misuse, identity/privilege abuse, supply chain weaknesses, and unexpected code execution.
- [OpenAI API data controls](https://platform.openai.com/docs/models/default-usage-policies-by-endpoint) distinguish default abuse-monitoring retention from approved Zero Data Retention and show why “not used for training” alone is insufficient.

