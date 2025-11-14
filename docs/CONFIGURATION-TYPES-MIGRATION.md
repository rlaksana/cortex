# Configuration Types Migration Guide

This guide explains how to migrate from `any` usage to properly typed configuration constants and helpers.

## Overview

The migration eliminates `any` usage throughout the configuration system by introducing:
- Type-safe constant definitions
- Runtime validation utilities
- Comprehensive type guards
- Branded types for configuration keys
- Union types for variant configurations

## Migration Steps

### 1. Replace `any` Type Assertions

#### Before:
```typescript
const config = configData as any;
const result = (someValue as any).property;
```

#### After:
```typescript
import { validateConfig, isQdrantConfig } from '@/utils/configuration-validators.js';

const result = validateConfig(configData, isQdrantConfig, 'Qdrant configuration');
if (!result.success) {
  throw new Error(result.error);
}
const config = result.data;
```

### 2. Use Typed Constants

#### Before:
```typescript
const defaultConfig = {
  host: 'localhost',
  port: 6333,
  timeout: 30000
};
```

#### After:
```typescript
import { DEFAULT_QDRANT_CONFIG } from '@/constants/configuration-constants.js';

const config = { ...DEFAULT_QDRANT_CONFIG };
```

### 3. Implement Type Guards

#### Before:
```typescript
function isConfig(value: unknown): boolean {
  return typeof value === 'object' && value !== null;
}
```

#### After:
```typescript
import { isQdrantConfig, isMigrationConfig } from '@/utils/configuration-validators.js';

// Use built-in type guards
if (isQdrantConfig(value)) {
  // value is now properly typed as QdrantConfig
}
```

### 4. Use Configuration Builders

#### Before:
```typescript
const config = {
  host: someHost,
  port: somePort,
  apiKey: someApiKey
};
```

#### After:
```typescript
import { QdrantConfigBuilder } from '@/utils/configuration-validators.js';

const config = new QdrantConfigBuilder()
  .withHost(someHost)
  .withPort(somePort)
  .withApiKey(someApiKey)
  .build();
```

### 5. Replace Validation Rules

#### Before:
```typescript
const validationRule: ValidationRule = {
  name: 'check-config',
  validator: (_config: any) => {
    // validation logic
    return errors;
  }
};
```

#### After:
```typescript
import type { CompleteDatabaseConfig } from '@/types/config.js';

const validationRule: ValidationRule = {
  name: 'check-config',
  validator: (config: CompleteDatabaseConfig) => {
    // validation logic with proper typing
    return errors;
  }
};
```

## Available Type Guards

### Database Configuration
- `isQdrantConfig(value: unknown)` - Validates Qdrant configuration objects
- `isDatabaseConnectionConfig(value: unknown)` - Validates database connection configurations
- `isMigrationConfig(value: unknown)` - Validates migration configuration objects

### Transformation Rules
- `isTransformationRule(value: unknown)` - Validates transformation rule objects
- `isFilterValue(value: unknown)` - Validates filter rule values

### Validation Results
- `isValidationResult(value: unknown)` - Validates validation result objects

### Environment Configuration
- `isEnvironmentConfig(value: unknown)` - Validates environment-specific configurations
- `isProductionConfig(value: unknown)` - Validates production configurations

## Runtime Validation Utilities

### validateConfig
```typescript
const result = validateConfig(value, isQdrantConfig, 'Qdrant config');
if (result.success) {
  const config = result.data; // Properly typed
} else {
  console.error(result.error);
}
```

### safeParseConfig
```typescript
const config = safeParseConfig(value, isQdrantConfig, DEFAULT_QDRANT_CONFIG);
```

### assertType
```typescript
assertType(value, isQdrantConfig, 'Expected Qdrant configuration');
// Now value is properly typed as QdrantConfig
```

## Configuration Constants

### Database Constants
```typescript
import {
  DEFAULT_QDRANT_CONFIG,
  SUPPORTED_DATABASE_TYPES,
  type DatabaseType
} from '@/constants/configuration-constants.js';
```

### Migration Constants
```typescript
import {
  DEFAULT_MIGRATION_CONFIG,
  MIGRATION_STRATEGIES,
  type MigrationMode
} from '@/constants/configuration-constants.js';
```

### Security Constants
```typescript
import {
  DEFAULT_SECURITY_CONFIG,
  PASSWORD_VALIDATION_PATTERNS,
  API_KEY_VALIDATION
} from '@/constants/configuration-constants.js';
```

### Environment Constants
```typescript
import {
  ENVIRONMENT_SETTINGS,
  SUPPORTED_ENVIRONMENTS,
  type Environment
} from '@/constants/configuration-constants.js';
```

## Error Handling

### Before:
```typescript
try {
  const config = JSON.parse(jsonString);
} catch (error) {
  // Error handling with any types
}
```

### After:
```typescript
import { validateConfig, isJSONObject } from '@/utils/configuration-validators.js';

const result = validateConfig(jsonString, isJSONObject, 'JSON configuration');
if (!result.success) {
  // Properly typed error handling
  throw new Error(`Invalid configuration: ${result.error}`);
}
```

## Configuration Merging

### Before:
```typescript
const merged = { ...baseConfig, ...updates } as any;
```

### After:
```typescript
import { mergeConfigs, deepMergeConfigs } from '@/utils/configuration-validators.js';

const merged = mergeConfigs(baseConfig, updates);
const deepMerged = deepMergeConfigs(baseConfig, updates);
```

## Environment Variable Configuration

### Before:
```typescript
const config = {
  qdrantUrl: process.env.QDRANT_URL,
  apiKey: process.env.API_KEY,
  // Types are unknown
};
```

### After:
```typescript
import { createConfigFromEnvironment } from '@/constants/configuration-constants.js';

const config = createConfigFromEnvironment(process.env);
// Returns properly typed Dict<JSONValue>
```

## Best Practices

1. **Always use type guards** when working with unknown configuration data
2. **Import from constants** instead of defining inline configuration objects
3. **Use configuration builders** for complex object creation
4. **Validate at runtime** even with TypeScript types
5. **Provide fallback values** using `safeParseConfig`
6. **Use branded types** for configuration keys when applicable

## Migration Checklist

- [ ] Replace all `any` type assertions with proper type guards
- [ ] Import constants from `/constants/configuration-constants.js`
- [ ] Use `validateConfig` or `safeParseConfig` for unknown data
- [ ] Replace manual configuration merging with utility functions
- [ ] Add runtime validation for all configuration inputs
- [ ] Update type definitions to use proper union types
- [ ] Add comprehensive error handling
- [ ] Write tests for configuration validation

## Example: Complete Migration

### Before:
```typescript
// Old implementation with any
export function processConfig(configData: unknown): any {
  const config = configData as any;
  const merged = {
    ...DEFAULT_CONFIG,
    ...config
  };
  return merged;
}
```

### After:
```typescript
// New implementation with proper typing
import { validateConfig, isMigrationConfig } from '@/utils/configuration-validators.js';
import { DEFAULT_MIGRATION_CONFIG } from '@/constants/configuration-constants.js';
import type { MigrationConfig } from '@/types/config.js';

export function processConfig(configData: unknown): MigrationConfig {
  const result = validateConfig(configData, isMigrationConfig, 'Migration configuration');

  if (!result.success) {
    throw new Error(`Invalid migration configuration: ${result.error}`);
  }

  return {
    ...DEFAULT_MIGRATION_CONFIG,
    ...result.data
  };
}
```

## Testing

Test your migration by:

1. **Running type checking**: `npx tsc --noEmit`
2. **Testing runtime validation**: Verify all configuration inputs are properly validated
3. **Checking error handling**: Ensure invalid configurations are properly rejected
4. **Verifying functionality**: Confirm all existing functionality still works

## Support

If you encounter issues during migration:

1. Check the type guard definitions in `/src/utils/configuration-validators.ts`
2. Review available constants in `/src/constants/configuration-constants.ts`
3. Look at usage examples in existing code
4. Run the TypeScript compiler to identify remaining type issues

Remember: The goal is to eliminate all `any` usage while maintaining backward compatibility and improving type safety.