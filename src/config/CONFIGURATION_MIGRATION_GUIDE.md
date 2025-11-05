# Configuration Migration Guide

This guide covers the migration of configuration property naming inconsistencies in the MCP-Cortex system to ensure consistency and maintain backward compatibility.

## Overview

The MCP-Cortex system has been updated to use consistent property naming conventions across all configuration objects. This migration system ensures:

- **Consistent naming**: All time-related properties use "Ms" suffix (e.g., `timeoutMs`, `retryDelayMs`)
- **Backward compatibility**: Legacy property names are still supported with migration warnings
- **Type safety**: Comprehensive validation prevents property mismatches
- **Builder patterns**: Safe construction of configuration objects

## Property Name Changes

### Health Check Configuration

| Legacy Property | Standard Property | Description                           |
| --------------- | ----------------- | ------------------------------------- |
| `timeout`       | `timeoutMs`       | Timeout in milliseconds               |
| `retries`       | `retryAttempts`   | Number of retry attempts              |
| `retryDelay`    | `retryDelayMs`    | Delay between retries in milliseconds |

### HTTP Client Configuration

| Legacy Property | Standard Property | Description                           |
| --------------- | ----------------- | ------------------------------------- |
| `timeout`       | `timeoutMs`       | Timeout in milliseconds               |
| `retries`       | `retryAttempts`   | Number of retry attempts              |
| `retryDelay`    | `retryDelayMs`    | Delay between retries in milliseconds |

## Migration Examples

### 1. Automatic Migration

The migration system automatically handles legacy property names:

```typescript
import { ProductionHealthChecker } from './monitoring/production-health-checker.js';

// Legacy configuration (still works)
const legacyConfig = {
  timeout: 10000,
  retries: 3,
  retryDelay: 1000,
  enableDetailedChecks: true,
  skipOptionalChecks: false,
};

// Automatically migrates to standard format
const healthChecker = new ProductionHealthChecker(legacyConfig);
```

### 2. Using Builder Pattern

Recommended approach for new code:

```typescript
import { ProductionHealthChecker } from './monitoring/production-health-checker.js';

const healthChecker = ProductionHealthChecker.builder()
  .timeoutMs(10000) // Standard property
  .retryAttempts(3) // Standard property
  .retryDelayMs(1000) // Standard property
  .enableDetailedChecks(true)
  .skipOptionalChecks(false)
  .build();
```

### 3. Mixed Legacy and Standard Properties

Both legacy and standard properties are supported:

```typescript
import { HttpClient } from './http-client/index.js';

const httpClient = new HttpClient({
  timeout: 5000, // Legacy property
  retryAttempts: 2, // Standard property
  retryDelay: 500, // Legacy property
  headers: {
    'User-Agent': 'MyApp/1.0',
  },
});
```

### 4. Configuration Validation

Validate configurations before use:

```typescript
import { validateHealthCheckConfiguration } from './config/configuration-validator.js';

const config = {
  timeoutMs: 10000,
  retryAttempts: 3,
  retryDelayMs: 1000,
};

const validation = validateHealthCheckConfiguration(config);

if (!validation.valid) {
  console.error('Configuration errors:', validation.errors);
}

if (validation.warnings.length > 0) {
  console.warn('Configuration warnings:', validation.warnings);
}
```

## API Reference

### Configuration Migration Functions

```typescript
import {
  migrateHealthCheckConfig,
  migrateHttpClientConfig,
  migrateConfiguration,
  healthCheckConfig,
  httpClientConfig,
} from './config/configuration-migration.js';
```

### Configuration Validation

```typescript
import {
  validateConfiguration,
  validateConfigurationStrict,
  validateConfigurationPermissive,
  isValidConfiguration,
  createConfigurationValidator,
} from './config/configuration-validator.js';
```

### Builder Patterns

```typescript
import { HealthCheckConfigBuilder, HttpClientBuilder } from './config/configuration-migration.js';
```

## Migration Best Practices

### 1. Use Standard Properties for New Code

```typescript
// ✅ Good - Use standard properties
const config = {
  timeoutMs: 10000,
  retryAttempts: 3,
  retryDelayMs: 1000,
};

// ❌ Avoid - Use legacy properties
const legacyConfig = {
  timeout: 10000,
  retries: 3,
  retryDelay: 1000,
};
```

### 2. Use Builder Patterns for Complex Configurations

```typescript
// ✅ Good - Use builder pattern
const httpClient = HttpClient.builder()
  .timeoutMs(10000)
  .retryAttempts(3)
  .retryDelayMs(1000)
  .header('Authorization', 'Bearer token')
  .build();

// ❌ Avoid - Direct object construction for complex configs
const httpClient = new HttpClient({
  timeoutMs: 10000,
  retryAttempts: 3,
  retryDelayMs: 1000,
  headers: {
    Authorization: 'Bearer token',
  },
});
```

### 3. Validate Configurations

```typescript
// ✅ Good - Validate before use
const config = { timeoutMs: 10000, retryAttempts: 3 };
if (isValidConfiguration(config, 'http-client')) {
  const client = new HttpClient(config);
}

// ❌ Avoid - Use without validation
const client = new HttpClient(config); // May fail at runtime
```

### 4. Handle Validation Errors Gracefully

```typescript
const validation = validateConfigurationStrict(config, 'health-check');

if (!validation.valid) {
  // Handle errors appropriately
  validation.errors.forEach((error) => {
    console.error(`Configuration error: ${error.message}`);
  });

  // Provide helpful error messages
  throw new Error(`Invalid configuration: ${validation.errors.map((e) => e.message).join(', ')}`);
}
```

## Environment Variables

The migration system also handles environment variable name standardization:

| Legacy Env Var             | Standard Env Var              | Description                    |
| -------------------------- | ----------------------------- | ------------------------------ |
| `HEALTH_CHECK_TIMEOUT`     | `HEALTH_CHECK_TIMEOUT_MS`     | Health check timeout in ms     |
| `HEALTH_CHECK_RETRIES`     | `HEALTH_CHECK_RETRY_ATTEMPTS` | Health check retry attempts    |
| `HEALTH_CHECK_RETRY_DELAY` | `HEALTH_CHECK_RETRY_DELAY_MS` | Health check retry delay in ms |

## Deprecation Timeline

- **Phase 1 (Current)**: Legacy properties supported with warnings
- **Phase 2 (Future)**: Legacy properties deprecated, warnings become errors
- **Phase 3 (Future)**: Legacy properties removed

## Troubleshooting

### Common Issues

1. **Type Errors**: Ensure you're using the correct import paths for the new configuration types
2. **Validation Failures**: Check that required properties are present and have valid values
3. **Migration Warnings**: Update to standard property names to eliminate warnings

### Debugging

Enable debug logging to see migration details:

```typescript
const validator = createConfigurationValidator({
  strict: false,
  allowDeprecated: true,
  validateTypes: true,
});

const result = validator.validateConfiguration(config);
console.log('Migration metadata:', result.metadata);
```

## Examples Repository

See the `/examples` directory for complete migration examples:

- `health-check-migration.ts` - Health check configuration migration
- `http-client-migration.ts` - HTTP client configuration migration
- `validation-examples.ts` - Configuration validation examples
- `builder-pattern-examples.ts` - Builder pattern usage examples

## Support

For questions or issues with the configuration migration:

1. Check this guide first
2. Review the API documentation
3. Look at the example files
4. Check validation error messages for specific guidance
