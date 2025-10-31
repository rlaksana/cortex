/**
 * Constants Module Index
 *
 * Central export point for all constant definitions in the Cortex Memory system.
 * This file provides a clean import interface for consuming modules.
 */

// Re-export all supported kinds functionality
export {
  // Core exports
  SUPPORTED_KINDS,
  KNOWLEDGE_TYPE_METADATA,

  // Type definitions
  type KnowledgeCategory,
  type ValidationFeatures,
  type BusinessRules,
  type KnowledgeTypeMetadata,

  // Utility functions
  getKnowledgeTypeMetadata,
  getKnowledgeTypesByCategory,
  getKnowledgeTypesByValidationFeature,
  getKnowledgeTypesByTag,
  getRelatedKnowledgeTypes,
  supportsValidationFeature,
  validateKnowledgeTypeMetadata,

  // Type guards
  isSupportedKind,
  isKnowledgeCategory,

  // Pre-defined groupings
  CORE_GRAPH_EXTENSION_TYPES,
  CORE_DOCUMENT_TYPES,
  DEVELOPMENT_LIFECYCLE_TYPES,
  EIGHT_LOG_SYSTEM_TYPES,
  IMMUTABLE_TYPES,
  DEDUPLICATED_TYPES,
  SCOPE_ISOLATED_TYPES,
  TTL_SUPPORTED_TYPES,
} from './supported-kinds.js';

// Future constants can be exported here as they are added
// export { OTHER_CONSTANT } from './other-constants.js';
