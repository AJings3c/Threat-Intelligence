import { describe, expect, it } from 'vitest';
import {
  canonicalizeKnowledgeName,
  externalReferenceKey,
  normalizeKnowledgeAliases,
  normalizeKnowledgeName,
} from '../src/knowledge/canonicalize.js';
import {
  isAllowedKnowledgeRelationship,
  validateAnalystAssessment,
  validateKnowledgeRelationship,
  type KnowledgeRelationshipPolicySubject,
} from '../src/knowledge/relationshipPolicy.js';
import type {
  AnalystAssessment,
  KnowledgeEntity,
  KnowledgeEvidence,
  KnowledgeRelationshipFact,
  KnowledgeSource,
} from '../src/knowledge/types.js';

const timestamp = '2026-07-18T00:00:00.000Z';

function source(name = 'MITRE ATT&CK'): KnowledgeSource {
  return { name, kind: 'stix', url: `https://example.test/${encodeURIComponent(name)}`, collectedAt: timestamp };
}

function evidence(
  sourceName = 'MITRE ATT&CK',
  kind: KnowledgeEvidence['kind'] = 'source-assertion',
): KnowledgeEvidence {
  return {
    id: `evidence--${sourceName}`,
    kind,
    source: source(sourceName),
    summary: `${sourceName} assertion`,
    reference: `https://example.test/reports/${encodeURIComponent(sourceName)}`,
    objectRefs: ['report--source-object'],
    collectedAt: timestamp,
    tlp: 'clear',
  };
}

function relationship(
  overrides: Partial<KnowledgeRelationshipPolicySubject> = {},
): KnowledgeRelationshipPolicySubject {
  return {
    relationshipType: 'uses',
    sourceRef: 'intrusion-set--one',
    targetRef: 'malware--one',
    sources: [source()],
    confidence: 80,
    evidence: [evidence()],
    validFrom: timestamp,
    ...overrides,
  };
}

function assessment(evidenceItems: KnowledgeEvidence[], confidence: number | undefined = 75): AnalystAssessment {
  return {
    id: 'assessment--one',
    subjectType: 'relationship',
    subjectRef: 'relationship--one',
    verdict: 'supported',
    rationale: 'Two independent reports support this attribution.',
    analystId: 'analyst@example.test',
    confidence,
    tlp: 'amber',
    evidence: evidenceItems,
    createdAt: timestamp,
    modifiedAt: timestamp,
  };
}

describe('knowledge name canonicalization', () => {
  it('normalizes compatibility characters and neutralizes invisible controls', () => {
    expect(normalizeKnowledgeName('  \uff21\uff30\uff34\u202e  \uff12\uff19\u200b ')).toBe('APT 29');
    expect(canonicalizeKnowledgeName('  Midnight   Blizzard ')).toBe('midnight blizzard');
  });

  it('deduplicates aliases conservatively without discarding punctuation', () => {
    expect(normalizeKnowledgeAliases('APT 29', [' apt 29 ', 'APT\u200b29', 'APT-29', 'APT29', ''])).toEqual([
      'APT-29',
      'APT29',
    ]);
  });

  it('creates stable external-reference keys and rejects unsafe URL schemes', () => {
    expect(
      externalReferenceKey({ sourceName: ' MITRE ATT&CK ', externalId: ' G0016 ', url: 'https://ignored.test' }),
    ).toBe('external-id:mitre%20att%26ck:g0016');

    const urlKey = externalReferenceKey({
      sourceName: 'Vendor',
      url: 'https://user:secret@EXAMPLE.com/report?b=2&a=1#fragment',
    });
    expect(urlKey).toBe('external-url:vendor:https%3A%2F%2Fexample.com%2Freport%3Fa%3D1%26b%3D2');
    expect(urlKey).not.toContain('secret');
    expect(externalReferenceKey({ sourceName: 'Vendor', url: 'javascript:alert(1)' })).toBeNull();
  });
});

describe('knowledge relationship policy', () => {
  it('allows only explicit source/relationship/target triples', () => {
    expect(isAllowedKnowledgeRelationship('intrusion-set', 'uses', 'malware')).toBe(true);
    expect(isAllowedKnowledgeRelationship('threat-actor', 'sponsored-by', 'identity')).toBe(true);
    expect(isAllowedKnowledgeRelationship('threat-actor', 'attributed-to', 'identity')).toBe(false);
    expect(isAllowedKnowledgeRelationship('campaign', 'owns', 'malware')).toBe(false);
    expect(isAllowedKnowledgeRelationship('threat-actor', 'uses', 'infrastructure')).toBe(false);
    expect(isAllowedKnowledgeRelationship('malware', 'controls', 'infrastructure')).toBe(false);
    expect(isAllowedKnowledgeRelationship('indicator', 'indicates', 'vulnerability')).toBe(false);
    expect(isAllowedKnowledgeRelationship('vulnerability', 'related-to', 'campaign')).toBe(true);

    const result = validateKnowledgeRelationship(relationship(), 'campaign', 'identity');
    expect(result.allowed).toBe(false);
    expect(result.violations.map((violation) => violation.code)).toContain('relationship-not-allowed');
  });

  it('rejects attribution based only on a sighting or single IOC', () => {
    const result = validateKnowledgeRelationship(
      relationship({ relationshipType: 'attributed-to', evidence: [evidence('IOC feed', 'sighting')] }),
      'intrusion-set',
      'threat-actor',
    );

    expect(result.allowed).toBe(false);
    expect(result.violations.map((violation) => violation.code)).toContain('attribution-evidence-too-weak');
  });

  it('requires an explicit confidence for attribution but preserves unknown elsewhere', () => {
    const attribution = validateKnowledgeRelationship(
      relationship({ relationshipType: 'attributed-to', confidence: undefined }),
      'intrusion-set',
      'threat-actor',
    );
    const nonAttribution = validateKnowledgeRelationship(relationship({ confidence: undefined }), 'intrusion-set', 'malware');

    expect(attribution.violations.map((violation) => violation.code)).toContain('missing-confidence');
    expect(nonAttribution.allowed).toBe(true);
  });

  it('applies the same evidence threshold to sponsorship claims', () => {
    const result = validateKnowledgeRelationship(
      relationship({ relationshipType: 'sponsored-by', confidence: undefined }),
      'threat-actor',
      'identity',
    );
    expect(result.violations.map((violation) => violation.code)).toContain('missing-confidence');
  });

  it('accepts a citable sourced attribution fact', () => {
    const result = validateKnowledgeRelationship(
      relationship({ relationshipType: 'attributed-to' }),
      'intrusion-set',
      'threat-actor',
    );
    expect(result).toEqual({ allowed: true, violations: [] });
  });

  it('requires two named evidence sources before an analyst supports attribution', () => {
    const oneSource = validateAnalystAssessment(assessment([evidence('Source A')]), 'attributed-to');
    const twoSources = validateAnalystAssessment(
      assessment([evidence('Source A'), evidence('Source B', 'report')]),
      'attributed-to',
    );

    expect(oneSource.violations.map((violation) => violation.code)).toContain(
      'attribution-independent-sources-required',
    );
    expect(twoSources).toEqual({ allowed: true, violations: [] });
  });
});

describe('knowledge model boundaries', () => {
  it('keeps sourced relationship facts separate from analyst assessments', () => {
    const entity: KnowledgeEntity = {
      id: 'intrusion-set--one',
      type: 'intrusion-set',
      name: 'Example Cluster',
      aliases: [],
      externalReferences: [],
      sources: [source()],
      tlp: 'unknown',
      evidence: [evidence()],
      stixVersion: timestamp,
      objectMarkingRefs: [],
      createdAt: timestamp,
      modifiedAt: timestamp,
    };
    const fact: KnowledgeRelationshipFact = {
      id: 'relationship--one',
      relationshipType: 'attributed-to',
      sourceRef: entity.id,
      targetRef: 'threat-actor--one',
      sources: [source()],
      confidence: 70,
      tlp: 'amber',
      externalReferences: [],
      evidence: [evidence()],
      stixVersion: timestamp,
      objectMarkingRefs: [],
      createdAt: timestamp,
      modifiedAt: timestamp,
    };
    const analystJudgement = assessment([evidence('Source A'), evidence('Source B')]);

    expect(entity.confidence).toBeUndefined();
    expect(fact).not.toHaveProperty('verdict');
    expect(analystJudgement).toMatchObject({ subjectRef: fact.id, verdict: 'supported' });
  });
});
