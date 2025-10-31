# SUPPORTED_KINDS Module Guide

## Overview

The `SUPPORTED_KINDS` module provides a comprehensive, single source of truth for all 16 knowledge types supported by the Cortex Memory system. This module replaces scattered knowledge type definitions throughout the codebase with a centralized, type-safe registry.

## Location

```
src/constants/supported-kinds.ts
```

## Quick Start

```typescript
import {
  SUPPORTED_KINDS,
  getKnowledgeTypeMetadata,
  getKnowledgeTypesByCategory
} from './constants/supported-kinds';

// Basic usage
console.log(SUPPORTED_KINDS); // All 16 types
const entityMeta = getKnowledgeTypeMetadata('entity');
const devTypes = getKnowledgeTypesByCategory('development-lifecycle');
```

## Knowledge Type Categories

### Core Graph Extension (3 types)
- **entity**: Flexible entity storage with dynamic schemas
- **relation**: Entity relationships with metadata
- **observation**: Fine-grained fact storage (append-only)

### Core Document Types (1 type)
- **section**: Document sections with markdown/text content

### Development Lifecycle (8 types)
- **runbook**: Operational procedures with step-by-step instructions
- **change**: Change tracking for features, bugfixes, refactoring
- **issue**: Issue tracking with external system integration
- **decision**: Architecture Decision Records (ADR) with immutability
- **todo**: Task management with status tracking
- **release_note**: Release documentation and communication
- **ddl**: Database schema migration tracking
- **pr_context**: Pull request context (30-day TTL)

### 8-LOG SYSTEM (4 types)
- **incident**: Comprehensive incident management
- **release**: Release management with deployment strategies
- **risk**: Risk management with probability assessment
- **assumption**: Assumption management with validation tracking

## Core Exports

### Basic Arrays
```typescript
import { SUPPORTED_KINDS } from './constants/supported-kinds';
// ['entity', 'relation', 'observation', 'section', 'runbook', ...]
```

### Type Definitions
```typescript
import type {
  KnowledgeCategory,
  ValidationFeatures,
  BusinessRules,
  KnowledgeTypeMetadata
} from './constants/supported-kinds';
```

### Pre-defined Groupings
```typescript
import {
  CORE_GRAPH_EXTENSION_TYPES,      // ['entity', 'relation', 'observation']
  DEVELOPMENT_LIFECYCLE_TYPES,      // 8 development types
  EIGHT_LOG_SYSTEM_TYPES,           // ['incident', 'release', 'risk', 'assumption']
  IMMUTABLE_TYPES,                  // Types with immutability constraints
  DEDUPLICATED_TYPES,               // All types (all support deduplication)
  SCOPE_ISOLATED_TYPES,             // All types (all support scope isolation)
  TTL_SUPPORTED_TYPES,              // All types (all support TTL policies)
} from './constants/supported-kinds';
```

## Utility Functions

### Get Metadata for a Specific Type
```typescript
import { getKnowledgeTypeMetadata } from './constants/supported-kinds';

const entityMeta = getKnowledgeTypeMetadata('entity');
console.log(entityMeta.displayName);        // "Entity"
console.log(entityMeta.category);          // "core-graph-extension"
console.log(entityMeta.description);       // Full description
console.log(entityMeta.tableName);         // "knowledgeEntity"
console.log(entityMeta.businessRules);     // Rules and constraints
```

### Get Types by Category
```typescript
import { getKnowledgeTypesByCategory } from './constants/supported-kinds';

const coreGraphTypes = getKnowledgeTypesByCategory('core-graph-extension');
// Returns: ['entity', 'relation', 'observation']
```

### Get Types by Validation Feature
```typescript
import { getKnowledgeTypesByValidationFeature } from './constants/supported-kinds';

const immutableTypes = getKnowledgeTypesByValidationFeature('hasImmutabilityConstraints');
// Returns: ['decision', 'section', 'observation']
```

### Get Related Types
```typescript
import { getRelatedKnowledgeTypes } from './constants/supported-kinds';

const decisionRelated = getRelatedKnowledgeTypes('decision');
// Returns: ['issue', 'section', 'change']
```

### Check Validation Features
```typescript
import { supportsValidationFeature } from './constants/supported-kinds';

const hasImmutability = supportsValidationFeature('decision', 'hasImmutabilityConstraints');
// Returns: true
```

## Metadata Structure

Each knowledge type has comprehensive metadata:

```typescript
interface KnowledgeTypeMetadata {
  kind: string;                    // Unique identifier
  displayName: string;             // Human-readable name
  category: KnowledgeCategory;     // Logical grouping
  description: string;             // Purpose and use cases
  useCases: string[];             // Example scenarios
  validationFeatures: {           // Capabilities
    hasSchemaValidation: boolean;
    supportsDeduplication: boolean;
    hasImmutabilityConstraints: boolean;
    supportsScopeIsolation: boolean;
    hasTTLPolicies: boolean;
  };
  businessRules: {                // Rules and constraints
    rules: string[];
    constraints: string[];
    validTransitions?: string[];
    requiredFields: string[];
    optionalFields: string[];
  };
  schemaType: z.ZodType;          // Zod schema reference
  typescriptType: string;         // TypeScript type name
  tableName: string;              // Database table name
  isImplemented: boolean;         // Implementation status
  introducedIn: string;           // Version introduced
  relatedTypes: string[];         // Related knowledge types
  tags: string[];                 // Search/filter tags
}
```

## Type Guards

```typescript
import { isSupportedKind, isKnowledgeCategory } from './constants/supported-kinds';

if (isSupportedKind(input)) {
  // input is now typed as typeof SUPPORTED_KINDS[number]
}

if (isKnowledgeCategory(category)) {
  // category is now typed as KnowledgeCategory
}
```

## Integration with Existing Code

### Replacing Hardcoded Arrays
**Before:**
```typescript
const VALID_TYPES = ['entity', 'relation', 'observation', 'section', 'runbook', /* ... */];
```

**After:**
```typescript
import { SUPPORTED_KINDS } from './constants/supported-kinds';
const VALID_TYPES = SUPPORTED_KINDS;
```

### Table Name Mapping
**Before:**
```typescript
const kindToTableMap = {
  section: 'section',
  decision: 'adrDecision',
  issue: 'issueLog',
  // ... scattered across code
};
```

**After:**
```typescript
import { getKnowledgeTypeMetadata } from './constants/supported-kinds';

function getTableName(kind: string): string {
  return getKnowledgeTypeMetadata(kind).tableName;
}
```

### Validation Logic
**Before:**
```typescript
const immutableTypes = ['decision', 'section', 'observation'];
const isImmutable = immutableTypes.includes(kind);
```

**After:**
```typescript
import { supportsValidationFeature } from './constants/supported-kinds';
const isImmutable = supportsValidationFeature(kind, 'hasImmutabilityConstraints');
```

## Schema Integration

The module integrates with existing Zod schemas:

```typescript
import { getKnowledgeTypeMetadata } from './constants/supported-kinds';

const entityMeta = getKnowledgeTypeMetadata('entity');
const schema = entityMeta.schemaType; // Actual EntitySchema Zod object

// Use for validation
const validationResult = schema.parse(inputData);
```

## Best Practices

1. **Always import from the constants module** - Don't hardcode knowledge type strings
2. **Use type guards** - Validate user input with `isSupportedKind()`
3. **Leverage metadata** - Access business rules and validation features programmatically
4. **Use category groupings** - Filter types by logical groups instead of individual checks
5. **Check validation features** - Use feature flags instead of hard-coded type lists

## Migration Guide

### Step 1: Update Imports
```typescript
// Old
import { SOME_TYPES } from '../some-file';

// New
import {
  SUPPORTED_KINDS,
  getKnowledgeTypesByCategory
} from '../constants/supported-kinds';
```

### Step 2: Replace Hardcoded Arrays
```typescript
// Old
if (['entity', 'relation', 'observation'].includes(type)) { ... }

// New
import { CORE_GRAPH_EXTENSION_TYPES } from '../constants/supported-kinds';
if (CORE_GRAPH_EXTENSION_TYPES.includes(type)) { ... }
```

### Step 3: Use Metadata for Business Logic
```typescript
// Old
if (type === 'decision' && status === 'accepted') { /* immutability check */ }

// New
import { supportsValidationFeature } from '../constants/supported-kinds';
if (supportsValidationFeature(type, 'hasImmutabilityConstraints')) {
  /* generic immutability check */
}
```

## Testing

The module includes comprehensive tests covering:
- Type safety and metadata structure
- Function behavior and edge cases
- Integration with Zod schemas
- Table name consistency
- Business rules validation

Run tests with:
```bash
npm test -- tests/unit/constants/supported-kinds.test.ts
```

## Benefits

1. **Single Source of Truth** - All knowledge type definitions in one place
2. **Type Safety** - Full TypeScript support with type guards
3. **Metadata-Driven** - Business logic driven by structured metadata
4. **Easy Discovery** - Clear categorization and relationships
5. **Validation Integration** - Direct links to Zod schemas
6. **Extensibility** - Easy to add new knowledge types with full metadata
7. **Maintainability** - Centralized maintenance reduces duplication

## Future Enhancements

- Dynamic schema generation from metadata
- Runtime validation features
- Enhanced type relationship mapping
- Performance optimization utilities
- GraphQL schema generation
- OpenAPI specification generation