# Capability Comparison & Threat-Intel Ecosystem Research

This document (1) compares our platform with the reference project
[koala73/worldmonitor](https://github.com/koala73/worldmonitor), (2) surveys how leading
open-source threat-intelligence projects are built, and (3) distills a roadmap of ideas worth
borrowing.

---

## 1. Our platform vs. worldmonitor

worldmonitor is a **general global situational-awareness** dashboard (geopolitics, news,
finance, disasters) with AI synthesis. Our project is a **focused cyber threat-intelligence**
aggregator. We borrow worldmonitor's "map + live feed + situational awareness" UX pattern but
specialize the domain.

| Dimension | worldmonitor | This platform |
|-----------|--------------|---------------|
| **Domain** | Broad: news, geopolitics, finance, infrastructure, OSINT | Narrow: cyber threat intel (IOCs, CVEs, C2, malware URLs) |
| **Data sources** | 500+ curated news/RSS feeds across 15 categories | Structured CTI feeds across CVE, URL, IP, hash, phishing, CIDR, social, and optional TAXII/API-key sources |
| **Map** | Dual engine: 3D globe (globe.gl) + WebGL flat (deck.gl), 45 layers | Single SVG world map (react-simple-maps), geolocated IOC dots |
| **Intelligence** | AI synthesis (Ollama/local LLM), cross-stream correlation, risk index | Rule-based normalization, cross-feed dedupe, confidence/reliability/TLP metadata, EPSS |
| **Alerting** | In-app signals | **Scheduled DingTalk + Telegram push digests** (new) |
| **Persistence** | DB-backed (PLpgSQL present) | In-memory cache with optional SQLite first/last-seen, trend, geo, push, and source-health history |
| **Packaging** | Web + native desktop (Tauri 2), 5 site variants, 21 languages | Single web app (monorepo: Express API + React dashboard) |
| **Scale/Maturity** | 54k★, 80 contributors, 43 releases | Fresh MVP |
| **Stack** | TypeScript + JS, Rust (Tauri), Astro, Python | TypeScript end-to-end (Node/Express + Vite/React/Tailwind) |

**Key capability gaps (worldmonitor has, we don't yet):** 3D globe & rich map layers, AI
synthesis, desktop app, i18n, alerting beyond chat push, and a far larger source catalog.

**Where we are intentionally different/better for the CTI use case:** structured IOC schema
with severity, IP geolocation of indicators, per-source health monitoring, a clean REST API
designed for integration, and **out-of-the-box DingTalk/Telegram alerting** — which
worldmonitor does not focus on.

---

## 2. How the ecosystem does it (GitHub survey)

Searched with: `threat intelligence`, `threat-intel`, `CTI`, `OSINT`, `IOC`, `threat-feed`,
`MISP`, `STIX/TAXII`.

### Full platforms (heavyweight, DB-backed)
- **[MISP/MISP](https://github.com/MISP/MISP)** — the de-facto standard for sharing. Events &
  attributes model, **STIX/TAXII** import/export, correlation engine, feeds, sharing groups,
  warninglists, taxonomies/galaxies, PyMISP API, and **push/pull synchronization** between
  instances.
- **[OpenCTI](https://github.com/OpenCTI-Platform/opencti)** — knowledge-graph model built on
  **STIX2**, connectors framework (ingest/enrich/export), relationships between entities
  (threat actors → malware → IOCs → TTPs), MITRE ATT&CK navigator integration.
- **[IntelOwl](https://github.com/intelowlproject/IntelOwl)** — "manage threat intel at scale":
  pluggable **analyzers/connectors** to enrich an observable (IP/domain/hash/URL) across many
  services in parallel, with a job queue (Celery) and REST API.

### Feed aggregators / curated lists (lightweight, like us)
- **[hslatman/awesome-threat-intelligence](https://github.com/hslatman/awesome-threat-intelligence)**
  (10k★) — canonical catalog of sources, formats, frameworks, tools.
- **[Bert-JanP/Open-Source-Threat-Intel-Feeds](https://github.com/Bert-JanP/Open-Source-Threat-Intel-Feeds)**
  — free, no-auth feeds grouped by type (IP / URL / CVE / Hash); refreshed via GitHub Actions.
- **[kraloveckey/threat-intelligence-feeds](https://github.com/kraloveckey/threat-intelligence-feeds)**
  — 300+ feeds, **auto-validated & status-checked daily via GitHub Actions** (active/offline
  badges) — a great pattern for source-health automation.

### Recurring design patterns worth borrowing
1. **Normalize to a standard model.** Everyone serious speaks **STIX 2.1** (indicators, observed-data,
   relationships) and ships over **TAXII**. Adopting even a STIX-export endpoint makes us
   interoperable with MISP/OpenCTI/SIEMs.
2. **Enrichment pipeline.** IntelOwl's model: an observable fans out to many analyzers
   (geo, ASN/whois, reputation, VT/AbuseIPDB/Shodan). We already do geo — this generalizes it.
3. **Deduplication & correlation.** MISP correlates attributes across events; we currently
   dedupe by indicator ID. Correlating the same IP/URL/hash across feeds adds confidence scoring.
4. **Confidence / scoring & TLP.** Mature feeds attach confidence, source reliability, and TLP
   (traffic-light protocol) labels — useful for filtering noise.
5. **Automated source health.** kraloveckey validates every feed daily and renders status
   badges — we have live health monitoring; a scheduled validation + history would match this.
6. **Outbound integrations.** Push to chat/SIEM is standard. We now have **DingTalk + Telegram**;
   natural next steps: Slack, generic webhook, email, and SIEM export (CEF/LEEF, ECS).
7. **Persistence + history.** Trends ("new C2s this week", first-seen/last-seen) require a store
   (SQLite/Postgres). worldmonitor and the platforms all persist.

---

## 3. Suggested roadmap (prioritized)

**Now (done this iteration)**
- ✅ Scheduled **DingTalk + Telegram** alert digests (new high-severity threats, dedup by ID,
  severity/source filters, signed DingTalk, test endpoint).

**Next (high value, low effort)**
- ✅ More feeds (no key): ThreatFox recent IOCs, MalwareBazaar recent SHA256 hashes,
  OpenPhish phishing URLs, and FIRST EPSS CVE enrichment.
- ✅ CIDR network feeds: Spamhaus DROP and SANS ISC/DShield block list.
- ✅ Optional credentialed phishing feed: PhishTank verified online URLs.
- ✅ Source-specific refresh intervals for slow-moving feeds.
- ✅ Source-health history and stale-source warnings.
- ✅ Hash drill-down view and malware-family aggregation.
- ✅ Optional credentialed IP source: AbuseIPDB high-confidence blacklist.
- ✅ Read-only TAXII 2.1 export over the existing STIX bundle.
- ✅ Optional AlienVault OTX subscribed-pulse import and external TAXII collection import.
- ✅ On-demand VirusTotal, Shodan, and Censys enrichment endpoint.
- The old abuse.ch SSLBL Botnet C2 CSV is deprecated and should stay out of the
  default source set.
- Generic **webhook + Slack + email** channels (reuse the notifier abstraction).
- SIEM export formats (CEF/LEEF, ECS) for operational integrations.

**Later (differentiation)**
- Enrichment fan-out (ASN/whois/reputation) à la IntelOwl.
- Richer map (globe.gl/deck.gl), MITRE ATT&CK mapping, relationships, and AI summarization of CVE clusters.

---

### Source links
- worldmonitor — https://github.com/koala73/worldmonitor
- MISP — https://github.com/MISP/MISP
- OpenCTI — https://github.com/OpenCTI-Platform/opencti
- IntelOwl — https://github.com/intelowlproject/IntelOwl
- awesome-threat-intelligence — https://github.com/hslatman/awesome-threat-intelligence
- Open-Source-Threat-Intel-Feeds — https://github.com/Bert-JanP/Open-Source-Threat-Intel-Feeds
- threat-intelligence-feeds — https://github.com/kraloveckey/threat-intelligence-feeds
