/**
 * Constants Module Index
 *
 * Central export point for all constant definitions in the Cortex Memory system.
 * This file provides a clean import interface for consuming modules.
 */

// Re-export all supported kinds functionality
export {
  type BusinessRules,
  CORE_DOCUMENT_TYPES,
  // Pre-defined groupings
  CORE_GRAPH_EXTENSION_TYPES,
  DEDUPLICATED_TYPES,
  DEVELOPMENT_LIFECYCLE_TYPES,
  EIGHT_LOG_SYSTEM_TYPES,
  // Utility functions
  getKnowledgeTypeMetadata,
  getKnowledgeTypesByCategory,
  getKnowledgeTypesByTag,
  getKnowledgeTypesByValidationFeature,
  getRelatedKnowledgeTypes,
  IMMUTABLE_TYPES,
  isKnowledgeCategory,
  // Type guards
  isSupportedKind,
  KNOWLEDGE_TYPE_METADATA,
  // Type definitions
  type KnowledgeCategory,
  type KnowledgeTypeMetadata,
  SCOPE_ISOLATED_TYPES,
  // Core exports
  SUPPORTED_KINDS,
  supportsValidationFeature,
  TTL_SUPPORTED_TYPES,
  validateKnowledgeTypeMetadata,
  type ValidationFeatures,
} from './supported-kinds.js';

// Future constants can be exported here as they are added
// export { OTHER_CONSTANT } from './other-constants.js';
