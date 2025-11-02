/**
 * Example usage of the SUPPORTED_KINDS module
 * Demonstrates how to use the comprehensive knowledge type registry
 */

import {
  SUPPORTED_KINDS,
  KNOWLEDGE_TYPE_METADATA,
  getKnowledgeTypeMetadata,
  getKnowledgeTypesByCategory,
  getKnowledgeTypesByValidationFeature,
  getRelatedKnowledgeTypes,
  supportsValidationFeature,
  CORE_GRAPH_EXTENSION_TYPES,
  DEVELOPMENT_LIFECYCLE_TYPES,
  EIGHT_LOG_SYSTEM_TYPES,
  IMMUTABLE_TYPES,
  KnowledgeCategory,
} from '../src/constants/supported-kinds';

console.log('=== Cortex Memory SUPPORTED_KINDS Module Demo ===\n');

// 1. Basic enumeration of supported types
console.log('1. All Supported Knowledge Types:');
console.log(SUPPORTED_KINDS);
console.log(`Total: ${SUPPORTED_KINDS.length} types\n`);

// 2. Metadata inspection
console.log('2. Entity Type Metadata:');
const entityMetadata = getKnowledgeTypeMetadata('entity');
console.log(`- Display Name: ${entityMetadata.displayName}`);
console.log(`- Category: ${entityMetadata.category}`);
console.log(`- Description: ${entityMetadata.description}`);
console.log(`- Table Name: ${entityMetadata.tableName}`);
console.log(`- Is Implemented: ${entityMetadata.isImplemented}`);
console.log(`- Required Fields: ${entityMetadata.businessRules.requiredFields.join(', ')}`);
console.log(`- Tags: ${entityMetadata.tags.join(', ')}\n`);

// 3. Category-based grouping
console.log('3. Knowledge Types by Category:');
const categories: KnowledgeCategory[] = [
  'core-graph-extension',
  'core-document-types',
  'development-lifecycle',
  'eight-log-system',
];

categories.forEach((category) => {
  const types = getKnowledgeTypesByCategory(category);
  console.log(`- ${category}: ${types.join(', ')}`);
});
console.log();

// 4. Validation feature filtering
console.log('4. Types with Immutability Constraints:');
console.log(IMMUTABLE_TYPES.join(', '));
console.log();

// 5. Related types exploration
console.log('5. Related Types for Decision:');
const decisionRelated = getRelatedKnowledgeTypes('decision');
console.log(decisionRelated.join(', '));
console.log();

// 6. Validation feature checking
console.log('6. Validation Feature Examples:');
const features = [
  { kind: 'decision' as const, feature: 'hasImmutabilityConstraints' as const },
  { kind: 'entity' as const, feature: 'supportsDeduplication' as const },
  { kind: 'observation' as const, feature: 'hasImmutabilityConstraints' as const },
];

features.forEach(({ kind, feature }) => {
  const supported = supportsValidationFeature(kind, feature);
  console.log(`- ${kind} supports ${feature}: ${supported}`);
});
console.log();

// 7. Pre-defined groupings
console.log('7. Pre-defined Type Groupings:');
console.log(`- Core Graph Extension: ${CORE_GRAPH_EXTENSION_TYPES.join(', ')}`);
console.log(`- Development Lifecycle: ${DEVELOPMENT_LIFECYCLE_TYPES.join(', ')}`);
console.log(`- 8-LOG System: ${EIGHT_LOG_SYSTEM_TYPES.join(', ')}`);
console.log();

// 8. Use cases example
console.log('8. Use Cases for Runbook Type:');
const runbookMetadata = getKnowledgeTypeMetadata('runbook');
console.log(runbookMetadata.useCases.map((useCase) => `  - ${useCase}`).join('\n'));
console.log();

// 9. Business rules example
console.log('9. Business Rules for Decision Type:');
const decisionMetadata = getKnowledgeTypeMetadata('decision');
console.log('Rules:');
decisionMetadata.businessRules.rules.forEach((rule) => console.log(`  - ${rule}`));
console.log('Constraints:');
decisionMetadata.businessRules.constraints.forEach((constraint) =>
  console.log(`  - ${constraint}`)
);
console.log();

console.log('=== Demo Complete ===');
