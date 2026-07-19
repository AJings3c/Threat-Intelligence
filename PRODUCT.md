# Product

## Register

product

## Users

Security operators, threat-intelligence analysts, incident responders, and red/blue-team researchers use this tool while triaging public indicators, checking source health, and preparing follow-up actions. They work under time pressure and need dense evidence, clear provenance, and fast pivots across IPs, domains, URLs, hashes, and CVEs.

## Product Purpose

The product aggregates public and configured threat-intelligence feeds into one evidence command workbench. It supports the operational path from source health and IOC extraction through hunting, enrichment, correlation, case work, rule automation, quality review, STIX exchange, and threat modeling. Success means an analyst can verify provenance, understand corroborating evidence, record follow-up work, and export a defensible result without leaving the dashboard.

## Core Workflows

- Monitor current posture, feed freshness, source health, and configuration readiness.
- Hunt single or batch IOCs and retain query history for repeatable investigations.
- Enrich and correlate IPs, domains, URLs, hashes, CIDRs, and CVEs against local evidence and configured providers.
- Track cases with indicators and comments, and inspect rule execution history.
- Review intelligence quality, time decay, false positives, geographic distribution, network relationships, and event timelines.
- Build evidence-backed STRIDE/DREAD and architecture threat models with assets, boundaries, flows, controls, and attack paths.
- Exchange STIX 2.1 data, expose read-only TAXII 2.1 collections, inspect STIX relationship neighborhoods, and review imported detection artifacts.
- Search threat actors, intrusion sets, campaigns, malware, tools, ATT&CK techniques, infrastructure, vulnerabilities, and indicators as an evidence-backed knowledge graph.
- Extract and refang IOCs deterministically from email, ticket, or news text while showing local matches.

## Product Surface

The application contains 14 bilingual workspaces: Overview, Threat Knowledge, Hunt, Cases, Rules, Quality, Network, Timeline, Heatmap, Sources, IOC Summary, Modeling, Intel Feed, and Operations. The interface supports dark/light themes, comfortable/compact density, keyboard access, responsive layouts, and explicit loading, empty, error, and disabled states.

## Trust Boundary

The platform supports defensive analysis and research. It does not execute imported Sigma, YARA, or Snort content; automatically block infrastructure; or invent source attribution. Scores, graphs, recommendations, and models must remain traceable to local evidence, configured integrations, or deterministic project logic. Production deployments fail closed unless role tokens or a trusted authentication proxy are configured.

## Brand Personality

Calm, exacting, operational. The interface should feel like a reliable security console: sober, fast to scan, and evidence-led rather than theatrical.

## Anti-references

Avoid marketing landing-page patterns, decorative cyberpunk visuals, oversized hero sections, vague AI-security copy, and dashboards that hide evidence behind summaries. Do not make configuration or threat scores look successful when data is missing.

## Design Principles

- Evidence before interpretation: show source, confidence, timestamps, and references near every conclusion.
- Investigation is a workflow: search, enrich, correlate, model, and export should be one continuous path.
- Configuration must be observable: every optional integration needs a visible configured/unconfigured/testable state.
- Dense but readable: prioritize structured tables, compact panels, and predictable scanning over decorative layouts.
- Fail loudly but safely: distinguish missing credentials, upstream errors, stale data, and empty successful results.
- Preserve distribution controls: apply role-aware TLP filtering to STIX/TAXII output and remove relationships made invalid by filtering.

## Accessibility & Inclusion

Target WCAG 2.1 AA for text contrast and keyboard access. Use color as a secondary signal only; keep badges, labels, and status text explicit. Motion should be minimal and respect reduced-motion preferences.
