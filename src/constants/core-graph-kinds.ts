/**
 * Core Graph Extension Knowledge Types
 *
 * Knowledge types that extend the core graph structure:
 * - entity: Flexible entity storage with dynamic schemas
 * - relation: Entity relationships with metadata
 * - observation: Fine-grained fact storage with append-only pattern
 *
 * @version 1.0.0
 */

import { z } from 'zod';

import { EntitySchema, ObservationSchema,RelationSchema } from '../schemas/knowledge-types.js';
/**
 * Knowledge type categories for logical grouping
 */
export type KnowledgeCategory =
  | 'core-graph-extension'
  | 'core-document-types'
  | 'development-lifecycle'
  | 'eight-log-system';

/**
 * Validation features supported by each knowledge type
 */
export interface ValidationFeatures {
  hasSchemaValidation: boolean;
  supportsDeduplication: boolean;
  hasImmutabilityConstraints: boolean;
  supportsScopeIsolation: boolean;
  hasTTLPolicies: boolean;
}

/**
 * Business rules and constraints for knowledge types
 */
export interface BusinessRules {
  rules: string[];
  constraints: string[];
  requiredFields: string[];
  optionalFields: string[];
}

/**
 * Comprehensive metadata for knowledge types
 */
export interface KnowledgeTypeMetadata {
  kind: string;
  displayName: string;
  category: KnowledgeCategory;
  description: string;
  useCases: string[];
  validationFeatures: ValidationFeatures;
  businessRules: BusinessRules;
  schemaType: any;
  typescriptType: string;
  tableName: string;
  isImplemented: boolean;
  introducedIn: string;
  relatedTypes: string[];
  tags: string[];
}

/**
 * Core Graph Extension knowledge type metadata
 */
export const CORE_GRAPH_EXTENSION_METADATA: Record<string, KnowledgeTypeMetadata> = {
  entity: {
    kind: 'entity',
    displayName: 'Entity',
    category: 'core-graph-extension' as KnowledgeCategory,
    description:
      'Flexible entity storage with dynamic schemas for representing core concepts like users, organizations, goals, and preferences',
    useCases: [
      'User profile management',
      'Organization structure tracking',
      'Goal and preference storage',
      'Component and service definitions',
      'Stakeholder management',
    ],
    validationFeatures: {
      hasSchemaValidation: true,
      supportsDeduplication: true,
      hasImmutabilityConstraints: false,
      supportsScopeIsolation: true,
      hasTTLPolicies: true,
    },
    businessRules: {
      rules: [
        'Content-hash based deduplication prevents duplicates',
        'Soft delete pattern for data retention',
        'Scope-based isolation for multi-tenancy',
        'Flexible JSONB schema with no validation constraints',
      ],
      constraints: [
        'entity_type must be 1-100 characters',
        'name must be unique within entity_type',
        'name must be 1-500 characters',
      ],
      requiredFields: ['entity_type', 'name'],
      optionalFields: ['data'],
    },
    schemaType: EntitySchema,
    typescriptType: 'EntityItem',
    tableName: 'knowledgeEntity',
    isImplemented: true,
    introducedIn: '1.0.0',
    relatedTypes: ['relation', 'observation'],
    tags: ['graph', 'flexible', 'core-extension', 'storage'],
  },

  relation: {
    kind: 'relation',
    displayName: 'Relation',
    category: 'core-graph-extension' as KnowledgeCategory,
    description:
      'Entity relationships that define connections between knowledge items with metadata for weight, confidence, and temporal aspects',
    useCases: [
      'Connecting decisions to issues they resolve',
      'Linking components to their specifications',
      'Building dependency graphs',
      'Tracking stakeholder relationships',
      'Modeling system architectures',
    ],
    validationFeatures: {
      hasSchemaValidation: true,
      supportsDeduplication: true,
      hasImmutabilityConstraints: false,
      supportsScopeIsolation: true,
      hasTTLPolicies: true,
    },
    businessRules: {
      rules: [
        'Both from_entity_id and to_entity_id must be valid UUIDs',
        'Relations can have optional metadata for weighting and confidence',
        'Supports various relation types like resolves, supersedes, references',
      ],
      constraints: [
        'from_entity_type and to_entity_type must be 1-100 characters',
        'relation_type must be 1-100 characters',
        'entity IDs must be valid UUIDs',
      ],
      requiredFields: [
        'from_entity_type',
        'from_entity_id',
        'to_entity_type',
        'to_entity_id',
        'relation_type',
      ],
      optionalFields: ['metadata'],
    },
    schemaType: RelationSchema,
    typescriptType: 'RelationItem',
    tableName: 'knowledgeRelation',
    isImplemented: true,
    introducedIn: '1.0.0',
    relatedTypes: ['entity', 'observation'],
    tags: ['graph', 'relationships', 'core-extension', 'connections'],
  },

  observation: {
    kind: 'observation',
    displayName: 'Observation',
    category: 'core-graph-extension' as KnowledgeCategory,
    description:
      'Fine-grained fact storage with append-only pattern for tracking detailed information about entities',
    useCases: [
      'Status updates and progress tracking',
      'Metric and measurement logging',
      'Audit trail and activity feeds',
      'Fine-grained fact tracking',
      'Historical record keeping',
    ],
    validationFeatures: {
      hasSchemaValidation: true,
      supportsDeduplication: true,
      hasImmutabilityConstraints: true,
      supportsScopeIsolation: true,
      hasTTLPolicies: true,
    },
    businessRules: {
      rules: [
        'Append-only pattern prevents modification of historical observations',
        'Content-hash based deduplication prevents duplicate observations',
        'Link to entity_id for fact association',
        'Observation type categorizes the kind of fact being recorded',
      ],
      constraints: [
        'entity_type must be 1-100 characters',
        'entity_id must be a valid UUID',
        'observation_type must be 1-100 characters',
      ],
      requiredFields: ['entity_type', 'entity_id', 'observation_type'],
      optionalFields: ['data'],
    },
    schemaType: ObservationSchema,
    typescriptType: 'ObservationItem',
    tableName: 'knowledgeObservation',
    isImplemented: true,
    introducedIn: '1.0.0',
    relatedTypes: ['entity', 'relation'],
    tags: ['graph', 'facts', 'core-extension', 'audit'],
  },
};

/**
 * Core Graph Extension knowledge types array
 */
export const CORE_GRAPH_EXTENSION_TYPES = ['entity', 'relation', 'observation'] as const;
