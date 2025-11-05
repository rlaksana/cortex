# Unified Knowledge Type Validator System

## Overview

The Unified Knowledge Type Validator System provides comprehensive validation for all 16 knowledge types in the Cortex Memory MCP system. This system ensures consistent validation across all MCP tools while providing enhanced error handling, performance monitoring, and business rule validation.

## Features

### 🔍 Comprehensive Validation
- **Schema Validation**: Runtime type checking with Zod schemas for all knowledge types
- **Business Rule Validation**: Context-aware validation with detailed error messages
- **Performance Constraint Validation**: Checks for large items and deep nesting
- **Cross-Tool Consistency**: Uniform validation across all MCP tools

### 📊 Enhanced Error Handling
- **Structured Error Messages**: Categorized errors with detailed context and suggestions
- **Error Severity Levels**: Error, Warning, and Info classifications
- **Recovery Suggestions**: Actionable advice for fixing validation issues
- **Internationalization Support**: Prepared for multi-language error messages

### ⚡ Performance Optimizations
- **Schema Compilation Caching**: Pre-compiled validation schemas for faster execution
- **Lazy Validation**: Optional validation for expensive operations
- **Batch Processing**: Efficient validation for multiple items
- **Memory Efficiency**: Optimized for large datasets

### 📈 Monitoring & Analytics
- **Performance Metrics**: Validation time tracking and bottleneck identification
- **Error Analytics**: Pattern analysis for common validation issues
- **Health Monitoring**: Real-time validation system health checks

## Supported Knowledge Types

| Type | Description | Key Validation Rules |
|------|-------------|---------------------|
| `section` | Document containers | Requires title or content, checks content length |
| `decision` | Architecture Decision Records | Rationale validation for accepted decisions |
| `issue` | Bug tracking | Critical issue requirements, tracker consistency |
| `todo` | Task tracking | Critical task assignment requirements |
| `runbook` | Operational procedures | Step validation, verification status |
| `change` | Code change tracking | Author attribution for feature changes |
| `release_note` | Release documentation | Breaking change notification requirements |
| `ddl` | Database migrations | DDL operation validation, migration ID format |
| `pr_context` | Pull request context | Branch validation, merge status consistency |
| `entity` | Graph nodes | Entity type validation, data complexity checks |
| `relation` | Graph edges | Self-reference detection, UUID validation |
| `observation` | Fine-grained data | Content length validation |
| `incident` | Incident management | RCA requirements for critical incidents |
| `release` | Release tracking | Rollback plan requirements |
| `risk` | Risk assessment | Risk level vs probability consistency |
| `assumption` | Assumption management | Expiration date validation |

## Validation Modes

### Strict Mode (Default)
- Full schema validation + business rules
- All errors and warnings reported
- Recommended for production environments

### Lenient Mode
- Schema validation only
- Business rules generate warnings, not errors
- Useful for development and testing

### Business Rules Only Mode
- Skip schema validation
- Only apply business rule validation
- Useful for data migration scenarios

### Schema Only Mode
- Skip business rules
- Only validate schema compliance
- Fastest validation mode

## Usage Examples

### Basic Knowledge Item Validation

```typescript
import { validateKnowledgeItem, ValidationMode } from './src/schemas/unified-knowledge-validator.js';

// Validate a decision item
const decision = {
  kind: 'decision',
  scope: { project: 'my-app', branch: 'main' },
  data: {
    component: 'auth-service',
    status: 'accepted',
    title: 'Use OAuth 2.0 for Authentication',
    rationale: 'OAuth 2.0 provides industry-standard security with token-based authentication.',
  },
};

const result = await validateKnowledgeItem(decision, {
  mode: ValidationMode.STRICT,
  includeWarnings: true,
});

if (!result.valid) {
  console.error('Validation errors:', result.errors);
}
if (result.warnings.length > 0) {
  console.warn('Validation warnings:', result.warnings);
}
```

### Memory Store Request Validation

```typescript
import { validateMemoryStoreRequest } from './src/schemas/unified-knowledge-validator.js';

const request = {
  items: [
    {
      kind: 'section',
      scope: { project: 'docs', branch: 'main' },
      data: { title: 'API Documentation', body_md: '# API Documentation\n\n...' },
    },
    {
      kind: 'decision',
      scope: { project: 'docs', branch: 'main' },
      data: {
        component: 'api',
        status: 'accepted',
        title: 'RESTful API Design',
        rationale: 'REST provides standard HTTP-based API patterns.',
      },
    },
  ],
};

const result = await validateMemoryStoreRequest(request);
console.log('Validation result:', result);
```

### MCP Tool Integration

```typescript
import {
  validateMemoryStoreInput,
  validateAndFormatMCPResponse
} from './src/schemas/mcp-validation-integration.js';

// Validate MCP tool input
const input = { items: [...] };
const validationResult = await validateMemoryStoreInput(input);

if (!validationResult.success) {
  throw new Error(`Validation failed: ${validationResult.error?.message}`);
}

// Process with business logic...

// Validate and format response
const response = { success: true, stored: 2, total: 2 };
const formattedResponse = validateAndFormatMCPResponse('memory_store', response);
```

## Error Handling

### Error Categories

1. **SCHEMA**: Data structure and type validation errors
2. **BUSINESS_RULE**: Domain-specific validation rules
3. **SYSTEM**: Validation system errors
4. **PERFORMANCE**: Performance-related warnings

### Error Severity Levels

- **ERROR**: Validation failure that must be addressed
- **WARNING**: Potential issue that should be reviewed
- **INFO**: Informational message

### Error Structure

```typescript
interface ValidationErrorDetail {
  code: string;           // Unique error identifier
  message: string;        // Human-readable error message
  field?: string;         // Field path where error occurred
  category: ErrorCategory; // Error category
  severity: ErrorSeverity; // Error severity
  suggestion?: string;    // Actionable advice
  context?: Record<string, any>; // Additional context
}
```

## Performance Monitoring

### Getting Validation Metrics

```typescript
import { validationService } from './src/services/validation/enhanced-validation-service.js';

const metrics = validationService.getPerformanceMetrics();
console.log('Validation metrics:', {
  totalValidations: metrics.totalValidations,
  successRate: (metrics.successfulValidations / metrics.totalValidations) * 100,
  averageTime: metrics.averageValidationTime,
  errorsByType: metrics.errorsByType,
});
```

### Metrics Structure

```typescript
interface ValidationMetrics {
  totalValidations: number;        // Total validation count
  successfulValidations: number;    // Successful validations
  failedValidations: number;        // Failed validations
  averageValidationTime: number;    // Average time in ms
  slowestValidation: number;        // Slowest validation time
  fastestValidation: number;        // Fastest validation time
  errorsByType: Record<string, number>; // Error counts by type
  warningsByType: Record<string, number>; // Warning counts by type
}
```

## Migration Guide

### From Legacy Validation

1. **Replace import statements**:
   ```typescript
   // Old
   import { validationService } from './src/services/validation/validation-service.js';

   // New
   import { validationService } from './src/services/validation/enhanced-validation-service.js';
   ```

2. **Update validation calls**:
   ```typescript
   // Old
   const result = await validationService.validateStoreInput(items);

   // New (enhanced version provides more features)
   const result = await validationService.validateStoreInput(items);

   // Or use detailed validation for more information
   const detailedResult = await validationService.getDetailedValidationResult(item);
   ```

3. **Handle new error format**:
   ```typescript
   // New error format provides more context
   if (!result.valid) {
     result.errors.forEach(error => {
       console.log(`${error.category}: ${error.message}`);
       if (error.suggestion) {
         console.log(`Suggestion: ${error.suggestion}`);
       }
     });
   }
   ```

### MCP Tool Integration

For MCP tools, use the integration layer:

```typescript
import {
  validateMemoryStoreInput,
  validateMemoryFindInput,
  validateSystemStatusInput,
  validateAndFormatMCPResponse
} from './src/schemas/mcp-validation-integration.js';

// In your MCP tool handler
async function handleMemoryStore(args: any) {
  // Validate input
  const validation = await validateMemoryStoreInput(args);
  if (!validation.success) {
    throw new Error(validation.error?.message);
  }

  // Process with business logic...
  const result = await processMemoryStore(validation.data);

  // Validate and format response
  return validateAndFormatMCPResponse('memory_store', result);
}
```

## Configuration

### Validation Options

```typescript
interface ValidationOptions {
  mode?: ValidationMode;           // Validation mode (STRICT, LENIENT, etc.)
  includeWarnings?: boolean;        // Include warnings in results
  maxErrors?: number;              // Maximum errors to collect
  timeout?: number;                // Validation timeout in ms
  enablePerformanceChecks?: boolean; // Enable performance constraint validation
  customRules?: CustomValidationRule[]; // Custom validation rules
}
```

### Custom Validation Rules

```typescript
const customRules = [
  {
    name: 'custom_business_rule',
    validator: (data: any) => {
      const errors: ValidationErrorDetail[] = [];

      // Custom validation logic
      if (data.customField && data.customField.length > 100) {
        errors.push({
          code: 'CUSTOM_FIELD_TOO_LONG',
          message: 'Custom field is too long',
          field: 'customField',
          category: ValidationErrorCategory.BUSINESS_RULE,
          severity: ValidationErrorSeverity.WARNING,
          suggestion: 'Consider shortening the custom field',
        });
      }

      return errors;
    },
    priority: 1,
  },
];

const result = await validateKnowledgeItem(item, { customRules });
```

## Testing

### Running Tests

```bash
# Run all validation tests
npm test -- validation

# Run specific test file
npm test src/schemas/__tests__/unified-knowledge-validator.test.ts

# Run tests with coverage
npm test -- --coverage src/schemas
```

### Test Coverage Areas

- ✅ Schema validation for all 16 knowledge types
- ✅ Business rule validation
- ✅ Performance constraint validation
- ✅ Error handling and edge cases
- ✅ MCP tool integration
- ✅ Batch validation
- ✅ Custom validation rules
- ✅ Migration utilities

## Troubleshooting

### Common Issues

1. **Validation takes too long**
   - Check if performance constraints are enabled
   - Consider using lenient mode for development
   - Review custom validation rules for performance issues

2. **Too many validation errors**
   - Review data structure against schemas
   - Check for missing required fields
   - Validate data types and formats

3. **Memory issues with large datasets**
   - Use batch validation for multiple items
   - Consider disabling performance checks
   - Monitor memory usage during validation

### Debug Mode

Enable debug logging for detailed validation information:

```typescript
import { logger } from './src/utils/logger.js';

// Set log level to debug
process.env.LOG_LEVEL = 'debug';

// Validation will now output detailed debug information
const result = await validateKnowledgeItem(item);
```

## Best Practices

1. **Use appropriate validation modes**:
   - Production: STRICT mode
   - Development: LENIENT mode
   - Data migration: BUSINESS_RULES_ONLY mode

2. **Handle warnings appropriately**:
   - Log warnings for review
   - Consider user preferences for warning levels
   - Provide clear feedback on warning resolution

3. **Monitor validation performance**:
   - Track validation metrics
   - Set up alerts for high error rates
   - Optimize slow validation rules

4. **Custom validation rules**:
   - Keep custom rules focused and performant
   - Provide clear error messages and suggestions
   - Test custom rules thoroughly

## API Reference

### Core Functions

- `validateKnowledgeItem(item, options?)` - Validate single knowledge item
- `validateMemoryStoreRequest(request, options?)` - Validate store request
- `validateMemoryFindRequest(request, options?)` - Validate find request
- `validateDeleteRequest(request, options?)` - Validate delete request

### MCP Integration Functions

- `validateMemoryStoreInput(input)` - Validate MCP memory store input
- `validateMemoryFindInput(input)` - Validate MCP memory find input
- `validateSystemStatusInput(input)` - Validate MCP system status input
- `validateAndFormatMCPResponse(tool, response)` - Validate and format MCP response

### Utility Functions

- `validateAndTransformItemsEnhanced(items)` - Enhanced MCP item validation
- `validationMonitor.recordValidation(tool, result)` - Record validation metrics
- `validationMonitor.getMetrics(tool?)` - Get validation metrics

## Support and Contributing

For issues, questions, or contributions related to the Unified Validation System:

1. Check existing issues in the project repository
2. Review test files for usage examples
3. Consult the API reference above
4. Create detailed bug reports with reproduction steps

## Version History

- **v2.0.0** (T20 Implementation) - Complete unified validation system
  - All 16 knowledge types supported
  - Business rule validation
  - Performance monitoring
  - MCP tool integration
  - Comprehensive test coverage

- **v1.x.x** - Legacy validation system (deprecated)