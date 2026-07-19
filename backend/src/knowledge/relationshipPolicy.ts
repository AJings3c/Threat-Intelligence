import { canonicalizeKnowledgeName } from './canonicalize.js';
import type {
  AnalystAssessment,
  KnowledgeEntityType,
  KnowledgeEvidence,
  KnowledgeRelationshipFact,
  KnowledgeRelationshipType,
  KnowledgeValidity,
} from './types.js';

export interface KnowledgeRelationshipRule {
  sourceType: KnowledgeEntityType;
  relationshipType: KnowledgeRelationshipType;
  targetTypes: readonly KnowledgeEntityType[];
}

const ALL_ENTITY_TYPES: readonly KnowledgeEntityType[] = [
  'threat-actor',
  'intrusion-set',
  'campaign',
  'malware',
  'tool',
  'attack-pattern',
  'identity',
  'vulnerability',
  'infrastructure',
  'indicator',
];

const RELATED_TO_RULES: readonly KnowledgeRelationshipRule[] = ALL_ENTITY_TYPES.map((sourceType) => ({
  sourceType,
  relationshipType: 'related-to',
  targetTypes: ALL_ENTITY_TYPES,
}));

export const ALLOWED_RELATIONSHIP_RULES: readonly KnowledgeRelationshipRule[] = [
  { sourceType: 'threat-actor', relationshipType: 'sponsored-by', targetTypes: ['identity'] },
  {
    sourceType: 'threat-actor',
    relationshipType: 'uses',
    targetTypes: ['malware', 'tool', 'attack-pattern'],
  },
  { sourceType: 'threat-actor', relationshipType: 'targets', targetTypes: ['identity', 'vulnerability'] },
  { sourceType: 'intrusion-set', relationshipType: 'attributed-to', targetTypes: ['threat-actor'] },
  {
    sourceType: 'intrusion-set',
    relationshipType: 'uses',
    targetTypes: ['malware', 'tool', 'attack-pattern'],
  },
  { sourceType: 'intrusion-set', relationshipType: 'targets', targetTypes: ['identity', 'vulnerability'] },
  {
    sourceType: 'campaign',
    relationshipType: 'attributed-to',
    targetTypes: ['intrusion-set', 'threat-actor'],
  },
  {
    sourceType: 'campaign',
    relationshipType: 'uses',
    targetTypes: ['malware', 'tool', 'attack-pattern'],
  },
  { sourceType: 'campaign', relationshipType: 'targets', targetTypes: ['identity', 'vulnerability'] },
  {
    sourceType: 'indicator',
    relationshipType: 'indicates',
    targetTypes: ['threat-actor', 'intrusion-set', 'campaign', 'malware', 'tool'],
  },
  ...RELATED_TO_RULES,
];

export type RelationshipPolicyViolationCode =
  | 'relationship-not-allowed'
  | 'self-relationship'
  | 'missing-source'
  | 'missing-evidence'
  | 'invalid-evidence'
  | 'missing-confidence'
  | 'invalid-confidence'
  | 'invalid-validity'
  | 'attribution-not-citable'
  | 'attribution-evidence-too-weak'
  | 'attribution-independent-sources-required'
  | 'missing-rationale'
  | 'missing-analyst';

export interface RelationshipPolicyViolation {
  code: RelationshipPolicyViolationCode;
  message: string;
}

export interface RelationshipPolicyResult {
  allowed: boolean;
  violations: RelationshipPolicyViolation[];
}

export type KnowledgeRelationshipPolicySubject = Pick<
  KnowledgeRelationshipFact,
  | 'relationshipType'
  | 'sourceRef'
  | 'targetRef'
  | 'sources'
  | 'confidence'
  | 'evidence'
  | 'validFrom'
  | 'validUntil'
>;

export function isAllowedKnowledgeRelationship(
  sourceType: KnowledgeEntityType,
  relationshipType: KnowledgeRelationshipType,
  targetType: KnowledgeEntityType,
): boolean {
  return ALLOWED_RELATIONSHIP_RULES.some(
    (rule) =>
      rule.sourceType === sourceType &&
      rule.relationshipType === relationshipType &&
      rule.targetTypes.includes(targetType),
  );
}

export function requiresAttributionEvidence(relationshipType: KnowledgeRelationshipType): boolean {
  return relationshipType === 'attributed-to' || relationshipType === 'sponsored-by';
}

function hasValidConfidence(confidence: number): boolean {
  return Number.isFinite(confidence) && confidence >= 0 && confidence <= 100;
}

function isValidDate(value: string): boolean {
  return Number.isFinite(Date.parse(value));
}

function validateValidity(validity: KnowledgeValidity, violations: RelationshipPolicyViolation[]): void {
  if (validity.validFrom && !isValidDate(validity.validFrom)) {
    violations.push({ code: 'invalid-validity', message: 'validFrom must be a valid date-time.' });
  }
  if (validity.validUntil && !isValidDate(validity.validUntil)) {
    violations.push({ code: 'invalid-validity', message: 'validUntil must be a valid date-time.' });
  }
  if (
    validity.validFrom &&
    validity.validUntil &&
    isValidDate(validity.validFrom) &&
    isValidDate(validity.validUntil) &&
    Date.parse(validity.validFrom) > Date.parse(validity.validUntil)
  ) {
    violations.push({ code: 'invalid-validity', message: 'validFrom must not be later than validUntil.' });
  }
}

function hasCitation(evidence: KnowledgeEvidence): boolean {
  return Boolean(
    evidence.reference?.trim() ||
      evidence.objectRefs.length > 0 ||
      evidence.source.url?.trim() ||
      evidence.source.externalId?.trim(),
  );
}

function isAttributionEvidence(evidence: KnowledgeEvidence): boolean {
  return evidence.kind === 'source-assertion' || evidence.kind === 'report';
}

function validateEvidence(evidence: readonly KnowledgeEvidence[], violations: RelationshipPolicyViolation[]): void {
  if (evidence.length === 0) {
    violations.push({ code: 'missing-evidence', message: 'A relationship fact must retain its evidence.' });
    return;
  }
  if (
    evidence.some(
      (item) =>
        !item.id.trim() ||
        !item.summary.trim() ||
        !canonicalizeKnowledgeName(item.source.name) ||
        !isValidDate(item.collectedAt),
    )
  ) {
    violations.push({ code: 'invalid-evidence', message: 'Evidence must be identifiable, sourced, and dated.' });
  }
}

export function validateKnowledgeRelationship(
  relationship: KnowledgeRelationshipPolicySubject,
  sourceType: KnowledgeEntityType,
  targetType: KnowledgeEntityType,
): RelationshipPolicyResult {
  const violations: RelationshipPolicyViolation[] = [];

  if (!isAllowedKnowledgeRelationship(sourceType, relationship.relationshipType, targetType)) {
    violations.push({
      code: 'relationship-not-allowed',
      message: `${sourceType} ${relationship.relationshipType} ${targetType} is not an allowed knowledge relationship.`,
    });
  }
  if (relationship.sourceRef === relationship.targetRef) {
    violations.push({ code: 'self-relationship', message: 'A relationship cannot point to the same object.' });
  }
  if (
    relationship.sources.length === 0 ||
    relationship.sources.some((source) => !canonicalizeKnowledgeName(source.name))
  ) {
    violations.push({ code: 'missing-source', message: 'A relationship fact must retain a named source.' });
  }
  if (relationship.confidence !== undefined && !hasValidConfidence(relationship.confidence)) {
    violations.push({ code: 'invalid-confidence', message: 'Confidence must be between 0 and 100.' });
  }
  validateValidity(relationship, violations);
  validateEvidence(relationship.evidence, violations);

  if (requiresAttributionEvidence(relationship.relationshipType)) {
    if (relationship.confidence === undefined) {
      violations.push({
        code: 'missing-confidence',
        message: 'Attribution requires an explicit confidence; missing confidence must remain unknown.',
      });
    }
    if (relationship.evidence.length > 0) {
      const attributionEvidence = relationship.evidence.filter(isAttributionEvidence);
      if (attributionEvidence.length === 0) {
        violations.push({
          code: 'attribution-evidence-too-weak',
          message: 'Attribution cannot be established only from sightings, telemetry, tags, aliases, or a single IOC.',
        });
      } else if (!attributionEvidence.some(hasCitation)) {
        violations.push({
          code: 'attribution-not-citable',
          message: 'Attribution evidence must cite a report, external source, or retained source object.',
        });
      }
    }
  }

  return { allowed: violations.length === 0, violations };
}

export function validateAnalystAssessment(
  assessment: AnalystAssessment,
  assessedRelationshipType?: KnowledgeRelationshipType,
): RelationshipPolicyResult {
  const violations: RelationshipPolicyViolation[] = [];
  if (!assessment.analystId.trim()) {
    violations.push({ code: 'missing-analyst', message: 'An assessment must identify its analyst.' });
  }
  if (!assessment.rationale.trim()) {
    violations.push({ code: 'missing-rationale', message: 'An assessment must include a rationale.' });
  }
  if (assessment.confidence !== undefined && !hasValidConfidence(assessment.confidence)) {
    violations.push({ code: 'invalid-confidence', message: 'Confidence must be between 0 and 100.' });
  }
  validateValidity(assessment, violations);
  validateEvidence(assessment.evidence, violations);

  if (
    (assessedRelationshipType === 'attributed-to' || assessedRelationshipType === 'sponsored-by') &&
    assessment.verdict === 'supported' &&
    assessment.evidence.length > 0
  ) {
    if (assessment.confidence === undefined) {
      violations.push({
        code: 'missing-confidence',
        message: 'A supported attribution assessment requires an explicit confidence.',
      });
    }
    const independentSources = new Set(
      assessment.evidence
        .filter((evidence) => (isAttributionEvidence(evidence) || evidence.kind === 'analysis') && hasCitation(evidence))
        .map((evidence) => canonicalizeKnowledgeName(evidence.source.name))
        .filter(Boolean),
    );
    if (independentSources.size < 2) {
      violations.push({
        code: 'attribution-independent-sources-required',
        message: 'A supported attribution assessment requires citable evidence from at least two named sources.',
      });
    }
  }

  return { allowed: violations.length === 0, violations };
}
