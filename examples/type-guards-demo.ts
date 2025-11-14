/**
 * Type Guards Demo - Simple demonstration
 *
 * This file demonstrates the comprehensive type guards system
 * and can be run directly with Node.js to verify functionality.
 */

import {
  // Basic Guards
  isString,
  isNumber,
  isBoolean,
  isNonEmptyString,
  isValidUUID,
  isValidISODate,

  // API Response Guards
  isSuccessResponse,
  isErrorResponse,
  isStandardApiResponse,
  isMCPToolResponse,

  // Knowledge Item Guards
  isKnowledgeItem,
  isSearchQuery,
  isSearchResult,
  isKnowledgeScope,

  // Configuration Guards
  isDatabaseConfig,
  isServiceConfig,
  isQdrantConfig,
  isAuthConfig,

  // Error Guards
  isValidationError,
  isSystemError,
  isDatabaseError,
  isNetworkError,

  // Composition utilities
  and,
  or,
  optional,
  arrayOf,
  hasProperty,
  hasProperties,
  exactShape,
  partialShape,
  discriminatedUnion,
  oneOfValues,
  numberRange,
  stringPattern,
  stringLength,

  // Schema-based guards
  nestedObject,
  collectionSchema,

  // Performance utilities
  memoized,
  fastFail,
  GuardPerformance,
} from '../src/utils/type-guards.js';

// =============================================================================
// Demo Functions
// =============================================================================

function demoBasicGuards() {
  console.log('=== Basic Type Guards Demo ===');

  // Test strings
  console.log('isString("hello"):', isString('hello'));
  console.log('isNonEmptyString("world"):', isNonEmptyString('world'));
  console.log('isNonEmptyString(""):', isNonEmptyString(''));

  // Test numbers
  console.log('isNumber(42):', isNumber(42));
  console.log('isNumber(NaN):', isNumber(NaN));

  // Test UUID and date
  console.log('isValidUUID("123e4567-e89b-12d3-a456-426614174000"):', isValidUUID('123e4567-e89b-12d3-a456-426614174000'));
  console.log('isValidISODate("2024-01-01T00:00:00.000Z"):', isValidISODate('2024-01-01T00:00:00.000Z'));
  console.log();
}

function demoApiResponses() {
  console.log('=== API Response Guards Demo ===');

  const successResponse = {
    success: true,
    data: 'Operation completed successfully',
    message: 'Success'
  };

  const errorResponse = {
    success: false,
    error: {
      code: 'VALIDATION_ERROR',
      message: 'Invalid input data',
      details: { field: 'email', value: 'invalid-email' }
    }
  };

  const mcpResponse = {
    content: [{ type: 'text', text: 'Hello, World!' }],
    isError: false,
    _meta: { version: '1.0' }
  };

  console.log('isSuccessResponse(success):', isSuccessResponse(successResponse));
  console.log('isErrorResponse(error):', isErrorResponse(errorResponse));
  console.log('isStandardApiResponse(success):', isStandardApiResponse(successResponse));
  console.log('isMCPToolResponse(mcp):', isMCPToolResponse(mcpResponse));
  console.log();
}

function demoKnowledgeItems() {
  console.log('=== Knowledge Item Guards Demo ===');

  const validItem = {
    id: 'item-123',
    kind: 'decision',
    content: 'This is a decision record',
    scope: { project: 'my-project', branch: 'main' },
    data: { decision: 'Use TypeScript', rationale: 'Type safety' },
    metadata: { version: '1.0' },
    created_at: '2024-01-01T00:00:00.000Z'
  };

  const validQuery = {
    query: 'TypeScript best practices',
    scope: { project: 'my-project' },
    types: ['decision', 'issue'],
    mode: 'deep' as const,
    limit: 10
  };

  const validResult = {
    id: 'result-123',
    kind: 'decision',
    scope: { project: 'my-project' },
    data: { decision: 'Use TypeScript' },
    created_at: '2024-01-01T00:00:00.000Z',
    confidence_score: 0.95,
    match_type: 'semantic' as const,
    highlight: ['TypeScript', 'best practices']
  };

  console.log('isKnowledgeItem(item):', isKnowledgeItem(validItem));
  console.log('isSearchQuery(query):', isSearchQuery(validQuery));
  console.log('isSearchResult(result):', isSearchResult(validResult));
  console.log();
}

function demoConfigurations() {
  console.log('=== Configuration Guards Demo ===');

  const validQdrantConfig = {
    host: 'localhost',
    port: 6333,
    timeout: 5000,
    maxRetries: 3,
    retryDelay: 1000,
    useHttps: false,
    enableHealthChecks: true,
    connectionPoolSize: 10,
    requestTimeout: 30000,
    connectTimeout: 5000
  };

  const validDatabaseConfig = {
    qdrant: validQdrantConfig,
    fallbackEnabled: true,
    backupEnabled: false,
    migrationEnabled: true
  };

  const validServiceConfig = {
    timeout: 5000,
    retries: 3,
    enableLogging: true
  };

  console.log('isQdrantConfig(qdrant):', isQdrantConfig(validQdrantConfig));
  console.log('isDatabaseConfig(database):', isDatabaseConfig(validDatabaseConfig));
  console.log('isServiceConfig(service):', isServiceConfig(validServiceConfig));
  console.log();
}

function demoErrors() {
  console.log('=== Error Type Guards Demo ===');

  const validationError = {
    code: 'INVALID_EMAIL',
    message: 'Email format is invalid',
    path: 'user.email',
    value: 'invalid-email'
  };

  const systemError = {
    code: 'DATABASE_CONNECTION_FAILED',
    message: 'Could not connect to database',
    category: 'database' as const,
    severity: 'high' as const,
    timestamp: '2024-01-01T00:00:00.000Z',
    retryable: true,
    details: { host: 'localhost', port: 5432 }
  };

  const databaseError = {
    code: 'QUERY_FAILED',
    message: 'Query execution failed',
    database: 'mydb',
    table: 'users',
    operation: 'SELECT',
    query: 'SELECT * FROM users',
    retryable: true,
    timeout: false,
    connectionLost: false
  };

  console.log('isValidationError(validation):', isValidationError(validationError));
  console.log('isSystemError(system):', isSystemError(systemError));
  console.log('isDatabaseError(database):', isDatabaseError(databaseError));
  console.log();
}

function demoComposition() {
  console.log('=== Guard Composition Demo ===');

  // Create a specialized guard for user objects
  const isUser = exactShape({
    id: isString,
    name: isString,
    email: (value: unknown): value is string =>
      typeof value === 'string' && value.includes('@'),
    age: (value: unknown): value is number =>
      typeof value === 'number' && value >= 0 && value <= 150,
    isActive: optional(isBoolean)
  });

  const validUser = {
    id: 'user-123',
    name: 'John Doe',
    email: 'john@example.com',
    age: 30,
    isActive: true
  };

  console.log('isUser(valid user):', isUser(validUser));
  console.log('isUser(invalid user):', isUser({ id: '1', name: 'John', email: 'invalid', age: -5 }));

  // Test composition utilities
  const isStringOrNumber = or(isString, isNumber);
  console.log('isStringOrNumber("hello"):', isStringOrNumber('hello'));
  console.log('isStringOrNumber(42):', isStringOrNumber(42));
  console.log('isStringOrNumber(true):', isStringOrNumber(true));

  const isPositiveNumber = and(isNumber, (n): n is number => n > 0);
  console.log('isPositiveNumber(5):', isPositiveNumber(5));
  console.log('isPositiveNumber(-5):', isPositiveNumber(-5));

  const stringArray = arrayOf(isString, { minLength: 1, maxLength: 3 });
  console.log('stringArray(["a", "b"]):', stringArray(['a', 'b']));
  console.log('stringArray([]):', stringArray([]));
  console.log('stringArray(["a", "b", "c", "d"]):', stringArray(['a', 'b', 'c', 'd']));

  const isEmail = stringPattern(/^[^\s@]+@[^\s@]+\.[^\s@]+$/);
  console.log('isEmail("test@example.com"):', isEmail('test@example.com'));
  console.log('isEmail("invalid"):', isEmail('invalid'));

  const isAge = numberRange(0, 120, { integer: true });
  console.log('isAge(25):', isAge(25));
  console.log('isAge(-1):', isAge(-1));
  console.log('isAge(25.5):', isAge(25.5));

  console.log();
}

function demoSchemas() {
  console.log('=== Schema-Based Guards Demo ===');

  // Create a complex nested schema
  const userSchema = nestedObject({
    id: { validate: isString, required: true },
    profile: {
      validate: nestedObject({
        name: { validate: stringLength(1, 100), required: true },
        bio: { validate: optional(stringLength(0, 500)), required: false },
        avatar: { validate: optional(isValidURL), required: false },
      }),
      required: true,
    },
    preferences: {
      validate: nestedObject({
        theme: { validate: oneOfValues(['light', 'dark', 'auto']), required: true },
        notifications: { validate: isBoolean, required: true },
        language: { validate: optional(stringPattern(/^[a-z]{2}-[A-Z]{2}$/)), required: false },
      }),
      required: false,
    },
    roles: {
      validate: collectionSchema(
        { validate: oneOfValues(['admin', 'user', 'guest']) },
        { minLength: 1, maxLength: 5 }
      ),
      required: true,
    },
  }, { strict: true });

  const validUser = {
    id: 'user-123',
    profile: {
      name: 'John Doe',
      bio: 'Software developer',
      avatar: 'https://example.com/avatar.jpg'
    },
    preferences: {
      theme: 'dark',
      notifications: true,
      language: 'en-US'
    },
    roles: ['user', 'admin']
  };

  console.log('userSchema(valid user):', userSchema(validUser));
  console.log('userSchema(invalid user - missing roles):', userSchema({ ...validUser, roles: [] }));
  console.log('userSchema(invalid user - extra field):', userSchema({ ...validUser, extra: 'field' }));
  console.log();
}

function demoPerformance() {
  console.log('=== Performance Utilities Demo ===');

  // Create an expensive guard
  const expensiveGuard = (value: unknown): value is string => {
    // Simulate expensive operation
    const start = Date.now();
    while (Date.now() - start < 1) {
      // Busy wait to simulate work
    }
    return typeof value === 'string' && value.length > 5;
  };

  // Test memoization
  const memoizedGuard = memoized(expensiveGuard);

  console.log('Testing memoized guard:');
  console.log('First call ("test-string"):', memoizedGuard('test-string'));
  console.log('Second call (same string - should use cache):', memoizedGuard('test-string'));
  console.log('Different call ("short"):', memoizedGuard('short'));

  // Test performance monitoring
  const monitoredGuard = GuardPerformance.wrap('demo-guard', isString);

  // Execute guard multiple times
  monitoredGuard('hello');
  monitoredGuard(123);
  monitoredGuard('world');
  monitoredGuard(true);

  const metrics = GuardPerformance.getMetrics('demo-guard');
  console.log('Performance metrics:', {
    calls: metrics?.calls,
    totalTime: `${metrics?.totalTime?.toFixed(2)}ms`,
    averageTime: `${metrics?.averageTime?.toFixed(2)}ms`,
    errors: metrics?.errors
  });

  GuardPerformance.resetMetrics('demo-guard');
  console.log();
}

// =============================================================================
// Main Demo Function
// =============================================================================

function runAllDemos() {
  console.log('🎯 Type Guards System Demo');
  console.log('=============================\n');

  demoBasicGuards();
  demoApiResponses();
  demoKnowledgeItems();
  demoConfigurations();
  demoErrors();
  demoComposition();
  demoSchemas();
  demoPerformance();

  console.log('✅ All demos completed successfully!');
  console.log('\nThis comprehensive type guards system provides:');
  console.log('• Runtime type safety to replace `any` usage');
  console.log('• Composable guard utilities for complex validation');
  console.log('• Schema-based validation for nested structures');
  console.log('• Performance optimization features');
  console.log('• Comprehensive error handling');
  console.log('• Support for discriminated unions and conditional validation');
}

// Run the demo if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runAllDemos();
}

export {
  runAllDemos,
  demoBasicGuards,
  demoApiResponses,
  demoKnowledgeItems,
  demoConfigurations,
  demoErrors,
  demoComposition,
  demoSchemas,
  demoPerformance,
};