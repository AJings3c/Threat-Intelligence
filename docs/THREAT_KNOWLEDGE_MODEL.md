# Threat Knowledge Model

This document defines the product semantics for the threat-knowledge layer. The
raw STIX store remains the source archive; the knowledge tables are a queryable
projection used by the API and UI.

## Scope

The model connects operational observables to durable threat knowledge:

```text
indicator -> sighting -> campaign -> intrusion-set -> threat-actor
                                |              |
                                v              v
                         malware / tool   attack-pattern
```

The first supported entity types are:

- `threat-actor`
- `intrusion-set`
- `campaign`
- `malware`
- `tool`
- `attack-pattern`
- `identity`
- `vulnerability`
- `infrastructure`
- `indicator` (imported STIX graph nodes only)

Indicators remain in the existing IOC store. A sighting or an explicit STIX
relationship connects an indicator to the knowledge graph.

## Semantic Invariants

1. An intrusion set is observed activity. A threat actor is an assessed person
   or organization. They are not interchangeable.
2. Sponsorship and attribution are relationships, never scalar properties on an
   entity. `attributed-to` and `sponsored-by` require evidence and confidence.
3. An alias alone never merges entities. Stable STIX IDs and external IDs take
   precedence; ambiguous aliases remain visible as conflicts.
4. IOC tags, malware-family names, geography, and shared infrastructure may
   create candidate relationships, but never confirmed attribution.
5. Every relationship retains its source, confidence, TLP marking, validity
   window, and evidence references.
6. Analyst assessments are stored separately from source-authored facts. An
   assessment may confirm, dispute, reject, or supersede a candidate claim
   without rewriting imported source data.
7. Raw imported STIX versions are immutable under schema v6. The first
   canonical payload for an object ID/version is never overwritten, and the
   first payload from each connector is retained separately. A later payload
   variant for that ID/version is recorded with its SHA-256 in the conflict
   quarantine and is not projected. Projection updates may replace the current
   query view, but must not delete or rewrite archived source payloads.
8. TLP access control applies to entities, relationships, sightings, evidence,
   assessments, graph traversal, and exports.

## Relationship Policy

The initial source-authored relationship allowlist is:

| Source type | Relationship | Target type |
| --- | --- | --- |
| `campaign` | `attributed-to` | `intrusion-set`, `threat-actor` |
| `intrusion-set` | `attributed-to` | `threat-actor` |
| `threat-actor` | `sponsored-by` | `identity` |
| `campaign`, `intrusion-set`, `threat-actor` | `uses` | `malware`, `tool`, `attack-pattern` |
| `campaign`, `intrusion-set`, `threat-actor` | `targets` | `identity`, `vulnerability` |
| `indicator` | `indicates` | `campaign`, `intrusion-set`, `malware`, `tool`, `threat-actor` |
| any supported entity | `related-to` | any supported entity |

`related-to` is intentionally weak and must not be presented as attribution.
Unsupported relationships remain in the raw STIX archive and are reported as
projection skips instead of being silently reinterpreted.

## Evidence And Confidence

Knowledge confidence uses the STIX 0-100 scale. Missing confidence remains
unknown and is not coerced to zero. Evidence may be an imported STIX object, an
external reference, a local IOC sighting, or an analyst-authored note.

An attribution or sponsorship relationship is publishable only when it has all of:

- at least one evidence reference;
- a named source or connector;
- an explicit confidence value;
- a valid source and target type pair.

The UI must distinguish source-authored facts, candidates, and analyst
assessments. It must use language such as "associated with" for weak relations
and reserve "attributed to" for relationships that satisfy this policy.

## Canonicalization

Names and aliases are normalized only for search and conflict detection. The
original spelling is preserved for display and evidence. Normalization performs
Unicode-compatible case folding, trims whitespace, collapses internal spacing,
and removes unsafe invisible controls. It preserves punctuation, meaningful
digits, and vendor prefixes so that automatic matching remains conservative.

Automatic entity merge is allowed only when at least one stable identifier
matches:

- identical STIX object ID;
- identical MITRE ATT&CK external ID;
- another identical namespaced external ID from the same authority.

All other potential matches require analyst review.

## Read API Contract

The initial API is read-only and requires at least the `viewer` role:

| Endpoint | Purpose | Persistence |
| --- | --- | --- |
| `GET /api/knowledge/types` | Return supported entity type identifiers. | Not required |
| `GET /api/knowledge/entities` | Search and paginate visible current entities. | Required |
| `GET /api/knowledge/entities/:id` | Read one entity by its original STIX ID. | Required |
| `GET /api/knowledge/entities/:id/graph` | Traverse visible relationships and sightings around one entity. | Required |

Entity list parameters are `types` (comma-separated exact type identifiers),
`q` (name, alias, or external-ID substring; at most 200 characters), `limit`
(default 100, maximum 1000), and `offset` (default 0). The response contains
`entities`, `total`, `limit`, and `offset`. The type catalog takes no query
parameters and returns `entityTypes`; entity detail also takes no query
parameters. Entity IDs must contain `--` and are limited to 200 characters.

Graph `depth` defaults to 1 and is bounded to 0-3. Its response contains
`rootId`, `depth`, `entities`, `relationships`, and `sightings`. Role filtering
is applied during traversal: viewer sees CLEAR/GREEN, analyst additionally sees
AMBER, and admin additionally sees RED and `unknown`. Hidden nodes, relations,
and sightings are removed, including relationships made dangling by filtering.
Entity detail and graph endpoints intentionally return the same 404 for a
missing root and a root hidden by TLP policy.

The three data endpoints return 503 until `DATA_DIR` is configured and the
service is restarted. On initialization, SQLite installs Threat Knowledge
schema v6 and backfills retained raw STIX versions and connector provenance;
later STIX/TAXII imports are projected incrementally. The canonical archive
keeps the first payload for each ID/version, `imported_stix_payloads` keeps the
first connector-specific payload, and differing later variants are recorded in
`imported_stix_conflicts` rather than projected. Relationships and sightings
whose supported endpoint entities have not arrived yet remain in
`knowledge_pending_facts` and are retried after later entity imports. Schema v6
also migrates analyst-assessment confidence to nullable storage so an unknown
value is never coerced to zero. `/api/knowledge/types` does not depend on
SQLite.

## Rollout Compatibility

- Existing IOC, CVE, case, rule, STIX, and TAXII APIs remain compatible.
- Persistence remains optional. Knowledge entity and graph endpoints return the
  persistence-required response when `DATA_DIR` is not configured; the type
  catalog remains available without persistence.
- Existing imported STIX objects and connector provenance are migrated into the
  v6 archive tables and backfilled into the projection after the knowledge
  schema is installed.
- The first release exposes read-only knowledge queries. Analyst assessments
  are added only after their audit and authorization tests are in place.
