/**
 * Core Document Knowledge Types
 *
 * Knowledge types for document management:
 * - section: Document sections and content organization
 *
 * @version 1.0.0
 */

import { z } from 'zod';

import { SectionSchema } from '../schemas/knowledge-types.js';
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
  schemaType: unknown;
  typescriptType: string;
  tableName: string;
  isImplemented: boolean;
  introducedIn: string;
  relatedTypes: string[];
  tags: string[];
}

/**
 * Core Document knowledge type metadata
 */
export const DOCUMENT_METADATA: Record<string, KnowledgeTypeMetadata> = {
  section: {
    kind: 'section',
    displayName: 'Section',
    category: 'core-document-types' as KnowledgeCategory,
    description:
      'Document sections for organizing content within larger documents or knowledge bases',
    useCases: [
      'Document structure organization',
      'Knowledge base sectioning',
      'Technical documentation chapters',
      'Policy and procedure sections',
      'Meeting minutes organization',
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
        'Sections can be nested for hierarchical organization',
        'Content-hash based deduplication prevents duplicate sections',
        'Section titles must be unique within parent context',
        'Supports rich text and markdown content',
      ],
      constraints: [
        'section_type must be 1-100 characters',
        'title must be 1-500 characters',
        'parent_section_id must be valid UUID if provided',
      ],
      requiredFields: ['section_type', 'title'],
      optionalFields: ['content', 'parent_section_id', 'metadata'],
    },
    schemaType: SectionSchema,
    typescriptType: 'SectionItem',
    tableName: 'knowledgeSection',
    isImplemented: true,
    introducedIn: '1.0.0',
    relatedTypes: ['entity', 'observation'],
    tags: ['document', 'content', 'organization', 'structure'],
  },
};

/**
 * Core Document knowledge types array
 */
export const CORE_DOCUMENT_TYPES = ['section'] as const;
