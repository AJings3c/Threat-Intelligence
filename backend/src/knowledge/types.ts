import type { SourceReliability, Tlp } from '../types.js';

export type { SourceReliability, Tlp };

export type KnowledgeTlp = Tlp | 'unknown';

export type KnowledgeEntityType =
  | 'threat-actor'
  | 'intrusion-set'
  | 'campaign'
  | 'malware'
  | 'tool'
  | 'attack-pattern'
  | 'identity'
  | 'vulnerability'
  | 'infrastructure'
  | 'indicator';

export type KnowledgeRelationshipType =
  | 'attributed-to'
  | 'sponsored-by'
  | 'uses'
  | 'targets'
  | 'exploits'
  | 'indicates'
  | 'impersonates'
  | 'compromises'
  | 'owns'
  | 'hosts'
  | 'controls'
  | 'delivers'
  | 'downloads'
  | 'drops'
  | 'communicates-with'
  | 'consists-of'
  | 'related-to';

export type KnowledgeSourceKind = 'stix' | 'taxii' | 'misp' | 'feed' | 'manual' | 'internal';

export interface KnowledgeSource {
  name: string;
  kind: KnowledgeSourceKind;
  externalId?: string;
  url?: string;
  reliability?: SourceReliability;
  collectedAt?: string;
}

export interface KnowledgeExternalReference {
  sourceName: string;
  externalId?: string;
  url?: string;
  description?: string;
}

export type KnowledgeEvidenceKind = 'source-assertion' | 'sighting' | 'report' | 'analysis' | 'telemetry';

/** A citable observation. Analyst conclusions belong in AnalystAssessment instead. */
export interface KnowledgeEvidence {
  id: string;
  kind: KnowledgeEvidenceKind;
  source: KnowledgeSource;
  summary: string;
  reference?: string;
  objectRefs: string[];
  observedAt?: string;
  collectedAt: string;
  confidence?: number;
  tlp?: KnowledgeTlp;
}

export interface KnowledgeValidity {
  validFrom?: string;
  validUntil?: string;
}

export interface KnowledgeEntity extends KnowledgeValidity {
  id: string;
  type: KnowledgeEntityType;
  name: string;
  description?: string;
  aliases: string[];
  externalReferences: KnowledgeExternalReference[];
  sources: KnowledgeSource[];
  confidence?: number;
  tlp: KnowledgeTlp;
  evidence: KnowledgeEvidence[];
  stixVersion: string;
  objectMarkingRefs: string[];
  createdAt: string;
  modifiedAt: string;
  revoked?: boolean;
}

/**
 * A sourced relationship assertion. It deliberately contains no analyst
 * verdict, so imported facts remain intact when analysts disagree with them.
 */
export interface KnowledgeRelationshipFact extends KnowledgeValidity {
  id: string;
  relationshipType: KnowledgeRelationshipType;
  sourceRef: string;
  targetRef: string;
  description?: string;
  sources: KnowledgeSource[];
  confidence?: number;
  tlp: KnowledgeTlp;
  externalReferences: KnowledgeExternalReference[];
  evidence: KnowledgeEvidence[];
  stixVersion: string;
  objectMarkingRefs: string[];
  createdAt: string;
  modifiedAt: string;
  revoked?: boolean;
}

export type AnalystAssessmentVerdict = 'supported' | 'disputed' | 'rejected' | 'inconclusive';
export type AnalystAssessmentSubjectType = 'entity' | 'relationship';

/** An analyst-authored judgement about, but never a mutation of, a sourced fact. */
export interface AnalystAssessment extends KnowledgeValidity {
  id: string;
  subjectType: AnalystAssessmentSubjectType;
  subjectRef: string;
  verdict: AnalystAssessmentVerdict;
  rationale: string;
  analystId: string;
  analystName?: string;
  confidence?: number;
  tlp: KnowledgeTlp;
  evidence: KnowledgeEvidence[];
  createdAt: string;
  modifiedAt: string;
}

export interface KnowledgeSighting {
  id: string;
  entityRef: string;
  indicatorRef?: string;
  firstSeen: string;
  lastSeen: string;
  count: number;
  sources: KnowledgeSource[];
  confidence?: number;
  tlp: KnowledgeTlp;
  externalReferences: KnowledgeExternalReference[];
  evidence: KnowledgeEvidence[];
  stixVersion: string;
  objectMarkingRefs: string[];
  createdAt: string;
  modifiedAt: string;
}

export type KnowledgeProjectionWarningCode =
  | 'unsupported-type'
  | 'invalid-object'
  | 'unsupported-relationship'
  | 'unresolved-reference';

export interface KnowledgeProjectionWarning {
  code: KnowledgeProjectionWarningCode;
  message: string;
  objectId?: string;
}

export interface KnowledgeProjection {
  projectedAt: string;
  entities: KnowledgeEntity[];
  relationships: KnowledgeRelationshipFact[];
  sightings: KnowledgeSighting[];
  warnings: KnowledgeProjectionWarning[];
}
