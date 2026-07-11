# Remediation and Capability Status

This document records the current code-backed controls and the limits that remain deployment or architecture decisions. It is not a certification or a substitute for an environment-specific threat model.

## Implemented in the Repository

- Role-based API access for viewer, analyst, and admin operations, with bearer and `x-api-token` support.
- Production fail-closed behavior unless role tokens, a trusted authentication proxy, or the explicit unsafe override is configured.
- Request rate limits, JSON body limits, CORS allow-listing, audit events, and non-sensitive configuration reporting.
- Per-source validation, timeouts, retry behavior, minimum refresh intervals, and source health/history reporting.
- Durable SQLite persistence for IOC/CVE data, source observations, investigations, cases, rules, jobs, audit, STIX objects/versions, and detection artifacts.
- Leased background jobs with deduplication, retries, exponential backoff, and dead-letter state.
- STIX 2.1 bundle export, read-only TAXII 2.1 collections, TLP-aware role filtering, relationship cleanup, and relationship-neighborhood queries.
- SHA-256 response digests for export content and optional HMAC-SHA256 signing with a non-secret key identifier.
- Provider-level enrichment circuit breaking and caching of successful enrichment results only.
- Deterministic IOC extraction/refanging from analyst-provided text.
- MISP read-only paged incremental import, including review-only Sigma, YARA, and Snort artifacts.
- Bilingual, responsive operator workspaces for monitoring, hunting, cases, rules, quality, investigation, modeling, and exchange operations.

## Deliberate Safety Boundaries

- Imported detection artifacts are stored and displayed but never executed automatically.
- The platform does not automatically block, quarantine, or modify external infrastructure.
- The platform does not invent source attribution; models and recommendations must trace to project evidence or deterministic logic.
- Third-party geolocation is disabled by default; an explicit HTTPS `GEO_LOOKUP_URL` template is required to transmit an IP for lookup.
- Browser bundles must not contain production API tokens or authentication-proxy secrets.

## Deployment Decisions Still Required

- Choose and operate the production identity provider and same-origin OIDC/SAML/SSO proxy.
- Provision TLS termination, secret storage, key rotation, backup, retention, and disaster recovery.
- Decide which external feeds are legally and operationally approved for the deployment.
- Define alert routing, escalation, case ownership, and human approval for downstream response actions.
- Establish monitoring, capacity targets, database lifecycle management, and high-availability requirements.
- Validate TLP handling, retention, and export policy against organizational data-governance requirements.

## Verification Commands

```bash
npm run typecheck
npm run lint
npm test
npm run build
```

The CI workflow runs the same static checks, tests, and production build. Environment-specific integration tests still require their corresponding credentials and endpoints.
