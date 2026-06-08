# Threat Feed Expansion TODO

This project now ingests CISA KEV, Feodo Tracker, URLhaus, ThreatFox, MalwareBazaar,
OpenPhish, Spamhaus DROP, SANS ISC/DShield, NVD/FIRST EPSS, X, Facebook, optional
PhishTank, AbuseIPDB, AlienVault OTX, and external TAXII collections. It also exposes
on-demand VirusTotal, Shodan, and Censys enrichment. Future expansion should prioritize
current, structured feeds that fit the existing indicator model and avoid stale/deprecated
sources.

## Phase 1 - Implemented

- [x] Verify candidate feeds before implementation.
- [x] Skip abuse.ch SSLBL Botnet C2 CSV because the public CSV is marked deprecated.
- [x] Add OpenPhish Community Feed for phishing URLs.
- [x] Add ThreatFox recent IOC JSON for C2, domains, URLs, and hashes.
- [x] Add MalwareBazaar recent SHA256 feed for malicious sample hashes.
- [x] Add FIRST EPSS enrichment to NVD CVEs.
- [x] Extend frontend/backend types for `hash` indicators and new feed labels.
- [x] Update STIX export so hash indicators are exportable.
- [x] Add parser/unit tests and store resilience tests for the new sources.

## Phase 2 - Implemented

- [x] Add `cidr` indicator support.
- [x] Add Spamhaus DROP after introducing `cidr` indicator support.
- [x] Add SANS ISC/DShield block list after introducing `cidr` indicator support.
- [x] Add PhishTank as an optional phishing source when an app key is configured.
- [x] Add source-specific refresh intervals so slow-moving feeds are not over-fetched.
- [x] Add per-source confidence weights and TLP/reliability metadata.

## Phase 3 - Later

- [x] Add API-key source: AbuseIPDB blacklist.
- [x] Add API-key source: AlienVault OTX subscribed pulses.
- [x] Add API-key enrichers: VirusTotal, Shodan, and Censys.
- [x] Add read-only TAXII 2.1 export option for MISP/OpenCTI/SIEM pull.
- [x] Add MISP/OpenCTI TAXII import option via external collection objects URL.
- [x] Add hash drill-down views and malware-family aggregation.
- [x] Add source catalog health history and stale-source warnings.
- [x] Add deprecated-source warnings.

## Implementation Notes

- Keep one module per feed under `backend/src/sources`.
- Keep fetch failures isolated; a failed source must retain last-good data in `ThreatStore`.
- Prefer feed parsers that can be unit-tested without network I/O.
- Avoid adding feeds whose official endpoint is stale or deprecated unless they are clearly
  marked as optional/legacy.
