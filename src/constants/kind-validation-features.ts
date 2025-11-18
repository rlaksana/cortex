/**
 * Cortex Memory MCP - Knowledge Type Validation Features
 *
 * Utility functions, type guards, and derived constants for knowledge type validation.
 * This module provides the functional interface for working with knowledge type metadata.
 *
 * Key features:
 * - Type-safe metadata retrieval
 * - Category-based filtering
 * - Validation feature checking
 * - Derived constants for common use cases
 * - Comprehensive type guards
 *
 * @version 1.0.0 - Knowledge type validation utilities
 */

import {
  type KnowledgeCategory,
  type KnowledgeTypeMetadata,
  type SupportedKnowledgeKind,
  type ValidationFeatures,
} from './supported-kinds.js';
import { KNOWLEDGE_TYPE_METADATA, SUPPORTED_KINDS } from './supported-kinds.js';

// ============================================================================
// Helper Functions and Utilities
// ============================================================================

/**
 * Get metadata for a specific knowledge type
 */
export function getKnowledgeTypeMetadata(
  kind: (typeof SUPPORTED_KINDS)[number]
): KnowledgeTypeMetadata {
  const metadata = KNOWLEDGE_TYPE_METADATA[kind];
  if (!metadata) {
    throw new Error(`Unknown knowledge type: ${kind}`);
  }
  return metadata;
}

/**
 * Get all knowledge types in a specific category
 */
export function getKnowledgeTypesByCategory(category: KnowledgeCategory): string[] {
  return Object.values(KNOWLEDGE_TYPE_METADATA)
    .filter((metadata) => metadata.category === category)
    .map((metadata) => metadata.kind);
}

/**
 * Get knowledge types with specific validation features
 */
export function getKnowledgeTypesByValidationFeature(feature: keyof ValidationFeatures): string[] {
  return Object.entries(KNOWLEDGE_TYPE_METADATA)
    .filter(([, metadata]) => metadata.validationFeatures[feature])
    .map(([kind]) => kind);
}

/**
 * Get knowledge types with specific tags
 */
export function getKnowledgeTypesByTag(tag: string): string[] {
  return Object.entries(KNOWLEDGE_TYPE_METADATA)
    .filter(([, metadata]) => metadata.tags.includes(tag))
    .map(([kind]) => kind);
}

/**
 * Get related knowledge types for a given type
 */
export function getRelatedKnowledgeTypes(kind: (typeof SUPPORTED_KINDS)[number]): string[] {
  const metadata = getKnowledgeTypeMetadata(kind);
  return metadata.relatedTypes;
}

/**
 * Check if a knowledge type supports specific validation features
 */
export function supportsValidationFeature(
  kind: (typeof SUPPORTED_KINDS)[number],
  feature: keyof ValidationFeatures
): boolean {
  const metadata = getKnowledgeTypeMetadata(kind);
  return metadata.validationFeatures[feature];
}

/**
 * Validate if a knowledge type is in the expected category
 */
export function validateKnowledgeTypeCategory(
  kind: (typeof SUPPORTED_KINDS)[number],
  expectedCategory: KnowledgeCategory
): boolean {
  const metadata = getKnowledgeTypeMetadata(kind);
  return metadata.category === expectedCategory;
}

// ============================================================================
// Type Guards and Validation
// ============================================================================

/**
 * Type guard for KnowledgeCategory
 */
export function isKnowledgeCategory(value: string): value is KnowledgeCategory {
  return [
    'core-graph-extension',
    'core-document-types',
    'development-lifecycle',
    'eight-log-system',
  ].includes(value);
}

/**
 * Type guard to check if a string is a supported knowledge kind
 */
export function isSupportedKind(kind: string): kind is (typeof SUPPORTED_KINDS)[number] {
  return SUPPORTED_KINDS.includes(kind as (typeof SUPPORTED_KINDS)[number]);
}

/**
 * Validate knowledge type metadata integrity
 */
export function validateKnowledgeTypeMetadata(): {
  isValid: boolean;
  issues: string[];
} {
  const issues: string[] = [];

  // Check all supported kinds have metadata
  for (const kind of SUPPORTED_KINDS) {
    if (!KNOWLEDGE_TYPE_METADATA[kind]) {
      issues.push(`Missing metadata for knowledge type: ${kind}`);
    }
  }

  // Check metadata consistency
  Object.entries(KNOWLEDGE_TYPE_METADATA).forEach(([kind, metadata]) => {
    if (!SUPPORTED_KINDS.includes(kind as (typeof SUPPORTED_KINDS)[number])) {
      issues.push(`Metadata for unknown knowledge type: ${kind}`);
    }

    if (metadata.kind !== kind) {
      issues.push(`Kind mismatch in metadata for ${kind}: expected ${kind}, got ${metadata.kind}`);
    }

    if (!metadata.tableName) {
      issues.push(`Missing table name for knowledge type: ${kind}`);
    }
  });

  return {
    isValid: issues.length === 0,
    issues,
  };
}

// ============================================================================
// Derived Constants - Commonly Used Combinations
// ============================================================================

// Note: Derived constants are now defined at the end of the file to avoid circular dependencies

// ============================================================================
// Additional Utility Types and Exports
// ============================================================================

/**
 * Type for supported knowledge kinds (re-exported for convenience)
 */
// Note: SupportedKnowledgeKind is now imported from supported-kinds.ts to avoid circular dependencies

/**
 * Type for validation feature keys (re-exported for convenience)
 */
export type ValidationFeatureKey = keyof ValidationFeatures;

/**
 * Get all available knowledge categories
 */
export const KNOWLEDGE_CATEGORIES: KnowledgeCategory[] = [
  'core-graph-extension',
  'core-document-types',
  'development-lifecycle',
  'eight-log-system',
] as const;

/**
 * Get all available validation features
 */
export const VALIDATION_FEATURES: (keyof ValidationFeatures)[] = [
  'hasSchemaValidation',
  'supportsDeduplication',
  'hasImmutabilityConstraints',
  'supportsScopeIsolation',
  'hasTTLPolicies',
] as const;

// ============================================================================
// Advanced Query Functions
// ============================================================================

/**
 * Get knowledge types by multiple criteria (AND logic)
 */
export function getKnowledgeTypesByCriteria(criteria: {
  category?: KnowledgeCategory;
  hasValidationFeature?: keyof ValidationFeatures;
  hasTag?: string;
  isImplemented?: boolean;
}): string[] {
  return Object.entries(KNOWLEDGE_TYPE_METADATA)
    .filter(([, metadata]) => {
      if (criteria.category && metadata.category !== criteria.category) {
        return false;
      }
      if (
        criteria.hasValidationFeature &&
        !metadata.validationFeatures[criteria.hasValidationFeature]
      ) {
        return false;
      }
      if (criteria.hasTag && !metadata.tags.includes(criteria.hasTag)) {
        return false;
      }
      if (
        criteria.isImplemented !== undefined &&
        metadata.isImplemented !== criteria.isImplemented
      ) {
        return false;
      }
      return true;
    })
    .map(([kind]) => kind);
}

/**
 * Get metadata summary for all knowledge types in a category
 */
export function getCategoryMetadataSummary(category: KnowledgeCategory): {
  category: KnowledgeCategory;
  types: string[];
  count: number;
  hasAllValidationFeatures: boolean;
  implementedTypes: string[];
} {
  const types = getKnowledgeTypesByCategory(category);
  const metadata = types.map((kind) =>
    getKnowledgeTypeMetadata(kind as (typeof SUPPORTED_KINDS)[number])
  );

  return {
    category,
    types,
    count: types.length,
    hasAllValidationFeatures: metadata.every((m) =>
      Object.values(m.validationFeatures).every((feature) => feature)
    ),
    implementedTypes: metadata.filter((m) => m.isImplemented).map((m) => m.kind),
  };
}

/**
 * Check if two knowledge types are related (directly or indirectly)
 */
export function areKnowledgeTypesRelated(
  kind1: SupportedKnowledgeKind,
  kind2: SupportedKnowledgeKind
): boolean {
  const related1 = getRelatedKnowledgeTypes(kind1);
  const related2 = getRelatedKnowledgeTypes(kind2);

  return related1.includes(kind2) || related2.includes(kind1);
}

/**
 * Get validation statistics for all knowledge types
 */
export function getValidationStatistics(): {
  totalTypes: number;
  typesWithSchemaValidation: number;
  typesWithDeduplication: number;
  typesWithImmutability: number;
  typesWithScopeIsolation: number;
  typesWithTTL: number;
  implementedTypes: number;
} {
  const totalTypes = SUPPORTED_KINDS.length;

  return {
    totalTypes,
    typesWithSchemaValidation: IMMUTABLE_TYPES.length,
    typesWithDeduplication: SUPPORTED_KINDS.length, // All types support deduplication
    typesWithImmutability: IMMUTABLE_TYPES.length,
    typesWithScopeIsolation: SUPPORTED_KINDS.length, // All types support scope isolation
    typesWithTTL: TTL_SUPPORTED_TYPES.length,
    implementedTypes: Object.values(KNOWLEDGE_TYPE_METADATA).filter((m) => m.isImplemented).length,
  };
}

// ============================================================================
// Re-exports from supported-kinds
// ============================================================================

// Export core constants from supported-kinds for convenience
export { KNOWLEDGE_TYPE_METADATA, SUPPORTED_KINDS } from './supported-kinds.js';

// Export derived constants (computed lazily to avoid circular dependencies)
export const CORE_GRAPH_EXTENSION_TYPES = ['entity', 'relation', 'observation'];
export const CORE_DOCUMENT_TYPES = ['section'];
export const DEVELOPMENT_LIFECYCLE_TYPES = [
  'runbook',
  'change',
  'issue',
  'decision',
  'todo',
  'release_note',
  'ddl',
  'pr_context',
];
export const EIGHT_LOG_SYSTEM_TYPES = ['incident', 'release', 'risk', 'assumption'];
export const IMMUTABLE_TYPES = ['incident', 'release'];
export const DEDUPLICATED_TYPES = SUPPORTED_KINDS; // All types support deduplication
export const SCOPE_ISOLATED_TYPES = SUPPORTED_KINDS; // All types support scope isolation
export const TTL_SUPPORTED_TYPES = ['todo', 'issue', 'decision', 'risk', 'assumption'];
