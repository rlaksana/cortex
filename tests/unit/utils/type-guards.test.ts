/**
 * Type Guards Test Suite
 *
 * Tests for the comprehensive type guards system
 */

import {
  // Basic guards
  isString,
  isNumber,
  isBoolean,
  isNonEmptyString,
  isValidUUID,
  isValidISODate,

  // API Response guards
  isSuccessResponse,
  isErrorResponse,
  isStandardApiResponse,
  isMCPToolResponse,

  // Knowledge Item guards
  isKnowledgeItem,
  isSearchQuery,
  isSearchResult,
  isKnowledgeScope,

  // Configuration guards
  isDatabaseConfig,
  isServiceConfig,
  isQdrantConfig,
  isAuthConfig,

  // Error guards
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
} from '../../../src/utils/type-guards.js';

describe('Type Guards', () => {
  // =============================================================================
  // Basic Type Guards Tests
  // =============================================================================

  describe('Basic Type Guards', () => {
    test('isString', () => {
      expect(isString('hello')).toBe(true);
      expect(isString('')).toBe(true);
      expect(isString(123)).toBe(false);
      expect(isString(null)).toBe(false);
      expect(isString(undefined)).toBe(false);
    });

    test('isNumber', () => {
      expect(isNumber(123)).toBe(true);
      expect(isNumber(0)).toBe(true);
      expect(isNumber(-1)).toBe(true);
      expect(isNumber(3.14)).toBe(true);
      expect(isNumber(NaN)).toBe(false);
      expect(isNumber(Infinity)).toBe(false);
      expect(isNumber('123')).toBe(false);
    });

    test('isNonEmptyString', () => {
      expect(isNonEmptyString('hello')).toBe(true);
      expect(isNonEmptyString('   ')).toBe(true);
      expect(isNonEmptyString('')).toBe(false);
      expect(isNonEmptyString(123)).toBe(false);
    });

    test('isValidUUID', () => {
      expect(isValidUUID('123e4567-e89b-12d3-a456-426614174000')).toBe(true);
      expect(isValidUUID('invalid-uuid')).toBe(false);
      expect(isValidUUID(123)).toBe(false);
    });

    test('isValidISODate', () => {
      expect(isValidISODate('2024-01-01T00:00:00.000Z')).toBe(true);
      expect(isValidISODate('2024-01-01')).toBe(false);
      expect(isValidISODate('invalid-date')).toBe(false);
    });
  });

  // =============================================================================
  // API Response Type Guards Tests
  // =============================================================================

  describe('API Response Type Guards', () => {
    test('isSuccessResponse', () => {
      const successResponse = {
        success: true,
        data: 'Operation completed',
        message: 'Success'
      };
      expect(isSuccessResponse(successResponse)).toBe(true);
      expect(isSuccessResponse({ success: true, data: null })).toBe(false);
      expect(isSuccessResponse({ success: false, error: 'Error' })).toBe(false);
    });

    test('isErrorResponse', () => {
      const errorResponse = {
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Invalid input',
          details: { field: 'email' }
        }
      };
      expect(isErrorResponse(errorResponse)).toBe(true);
      expect(isErrorResponse({ success: true, data: 'success' })).toBe(false);
    });

    test('isStandardApiResponse', () => {
      const success = { success: true, data: 'data' };
      const error = { success: false, error: { code: 'ERR', message: 'msg' } };
      expect(isStandardApiResponse(success)).toBe(true);
      expect(isStandardApiResponse(error)).toBe(true);
      expect(isStandardApiResponse({ invalid: 'response' })).toBe(false);
    });

    test('isMCPToolResponse', () => {
      const mcpResponse = {
        content: [{ type: 'text', text: 'Hello' }],
        isError: false,
        _meta: { version: '1.0' }
      };
      expect(isMCPToolResponse(mcpResponse)).toBe(true);
      expect(isMCPToolResponse({ content: [] })).toBe(true);
      expect(isMCPToolResponse({ invalid: 'response' })).toBe(false);
    });
  });

  // =============================================================================
  // Knowledge Item Type Guards Tests
  // =============================================================================

  describe('Knowledge Item Type Guards', () => {
    test('isKnowledgeScope', () => {
      const validScope = { project: 'my-project', branch: 'main' };
      expect(isKnowledgeScope(validScope)).toBe(true);
      expect(isKnowledgeScope({})).toBe(true);
      expect(isKnowledgeScope(null)).toBe(false);
      expect(isKnowledgeScope('invalid')).toBe(false);
    });

    test('isKnowledgeItem', () => {
      const validItem = {
        id: 'item-123',
        kind: 'decision',
        content: 'This is a decision',
        scope: { project: 'my-project' },
        data: { decision: 'Use TypeScript' },
        metadata: { version: '1.0' },
        created_at: '2024-01-01T00:00:00.000Z'
      };
      expect(isKnowledgeItem(validItem)).toBe(true);

      const invalidItem = { kind: 'decision' }; // missing required scope and data
      expect(isKnowledgeItem(invalidItem)).toBe(false);
    });

    test('isSearchQuery', () => {
      const validQuery = {
        query: 'TypeScript best practices',
        scope: { project: 'my-project' },
        types: ['decision', 'issue'],
        mode: 'deep',
        limit: 10
      };
      expect(isSearchQuery(validQuery)).toBe(true);

      const invalidQuery = { query: 123 }; // invalid query type
      expect(isSearchQuery(invalidQuery)).toBe(false);
    });

    test('isSearchResult', () => {
      const validResult = {
        id: 'result-123',
        kind: 'decision',
        scope: { project: 'my-project' },
        data: { decision: 'Use TypeScript' },
        created_at: '2024-01-01T00:00:00.000Z',
        confidence_score: 0.95,
        match_type: 'semantic',
        highlight: ['TypeScript', 'best practices']
      };
      expect(isSearchResult(validResult)).toBe(true);

      const invalidResult = { id: 'result-123' }; // missing required fields
      expect(isSearchResult(invalidResult)).toBe(false);
    });
  });

  // =============================================================================
  // Configuration Type Guards Tests
  // =============================================================================

  describe('Configuration Type Guards', () => {
    test('isQdrantConfig', () => {
      const validConfig = {
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
      expect(isQdrantConfig(validConfig)).toBe(true);

      const invalidConfig = { host: 'localhost' }; // missing required fields
      expect(isQdrantConfig(invalidConfig)).toBe(false);
    });

    test('isDatabaseConfig', () => {
      const validConfig = {
        qdrant: {
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
        },
        fallbackEnabled: true,
        backupEnabled: false,
        migrationEnabled: true
      };
      expect(isDatabaseConfig(validConfig)).toBe(true);
    });

    test('isServiceConfig', () => {
      const validConfig = {
        timeout: 5000,
        retries: 3,
        enableLogging: true
      };
      expect(isServiceConfig(validConfig)).toBe(true);
      expect(isServiceConfig({})).toBe(true); // all fields optional
      expect(isServiceConfig({ timeout: -1 })).toBe(false); // invalid timeout
    });
  });

  // =============================================================================
  // Error Type Guards Tests
  // =============================================================================

  describe('Error Type Guards', () => {
    test('isValidationError', () => {
      const validError = {
        code: 'INVALID_EMAIL',
        message: 'Email format is invalid',
        path: 'user.email',
        value: 'invalid-email'
      };
      expect(isValidationError(validError)).toBe(true);

      const minimalError = {
        code: 'ERROR',
        message: 'Something went wrong'
      };
      expect(isValidationError(minimalError)).toBe(true);

      const invalidError = { message: 'Missing code' };
      expect(isValidationError(invalidError)).toBe(false);
    });

    test('isSystemError', () => {
      const validError = {
        code: 'DATABASE_CONNECTION_FAILED',
        message: 'Could not connect to database',
        category: 'database',
        severity: 'high',
        timestamp: '2024-01-01T00:00:00.000Z',
        retryable: true,
        details: { host: 'localhost', port: 5432 }
      };
      expect(isSystemError(validError)).toBe(true);

      const invalidError = {
        code: 'ERROR',
        message: 'Error',
        category: 'invalid-category', // invalid category
        severity: 'high',
        retryable: false
      };
      expect(isSystemError(invalidError)).toBe(false);
    });

    test('isDatabaseError', () => {
      const validError = {
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
      expect(isDatabaseError(validError)).toBe(true);
    });

    test('isNetworkError', () => {
      const validError = {
        code: 'HTTP_404',
        message: 'Resource not found',
        url: 'https://api.example.com/resource',
        method: 'GET',
        statusCode: 404,
        timeout: false,
        retryable: false,
        headers: { 'content-type': 'application/json' }
      };
      expect(isNetworkError(validError)).toBe(true);
    });
  });

  // =============================================================================
  // Guard Composition Utilities Tests
  // =============================================================================

  describe('Guard Composition Utilities', () => {
    test('and - combines guards with AND logic', () => {
      const isStringAndNotEmpty = and(isString, (s): s is string => s.length > 0);
      expect(isStringAndNotEmpty('hello')).toBe(true);
      expect(isStringAndNotEmpty('')).toBe(false);
      expect(isStringAndNotEmpty(123)).toBe(false);
    });

    test('or - combines guards with OR logic', () => {
      const isStringOrNumber = or(isString, isNumber);
      expect(isStringOrNumber('hello')).toBe(true);
      expect(isStringOrNumber(123)).toBe(true);
      expect(isStringOrNumber(true)).toBe(false);
    });

    test('optional - allows null/undefined', () => {
      const optionalString = optional(isString);
      expect(optionalString('hello')).toBe(true);
      expect(optionalString(null)).toBe(true);
      expect(optionalString(undefined)).toBe(true);
      expect(optionalString(123)).toBe(false);
    });

    test('arrayOf - validates arrays', () => {
      const stringArray = arrayOf(isString, { minLength: 1, maxLength: 5 });
      expect(stringArray(['a', 'b', 'c'])).toBe(true);
      expect(stringArray([])).toBe(false); // minLength: 1
      expect(stringArray(['a', 'b', 'c', 'd', 'e', 'f'])).toBe(false); // maxLength: 5
      expect(stringArray([1, 2, 3])).toBe(false); // not strings
    });

    test('hasProperty - validates specific property', () => {
      const hasId = hasProperty('id', isString);
      expect(hasId({ id: '123', name: 'test' })).toBe(true);
      expect(hasId({ id: 123, name: 'test' })).toBe(false); // id is not string
      expect(hasId({ name: 'test' })).toBe(false); // missing id
    });

    test('exactShape - validates complete object shape', () => {
      const userShape = exactShape({
        id: isString,
        name: isString,
        age: (n): n is number => typeof n === 'number' && n >= 0
      });

      expect(userShape({ id: '1', name: 'John', age: 30 })).toBe(true);
      expect(userShape({ id: '1', name: 'John' })).toBe(false); // missing age
      expect(userShape({ id: '1', name: 'John', age: -5 })).toBe(false); // invalid age
      expect(userShape({ id: '1', name: 'John', age: 30, extra: 'field' })).toBe(false); // extra field
    });

    test('partialShape - validates partial object shape', () => {
      const userPartial = partialShape({
        id: isString,
        name: isString,
        email: optional(isString)
      });

      expect(userPartial({ id: '1' })).toBe(true);
      expect(userPartial({ name: 'John' })).toBe(true);
      expect(userPartial({ id: '1', name: 'John' })).toBe(true);
      expect(userPartial({ id: 1 })).toBe(false); // invalid id type
    });

    test('discriminatedUnion - validates discriminated unions', () => {
      const isTextContent = discriminatedUnion('type', 'text',
        hasProperties({ content: isString })
      );

      expect(isTextContent({ type: 'text', content: 'Hello' })).toBe(true);
      expect(isTextContent({ type: 'image', url: 'image.jpg' })).toBe(false);
      expect(isTextContent({ type: 'text' })).toBe(false); // missing content
    });

    test('oneOfValues - validates against allowed values', () => {
      const isStatus = oneOfValues(['active', 'inactive', 'pending'] as const);
      expect(isStatus('active')).toBe(true);
      expect(isStatus('invalid')).toBe(false);
      expect(isStatus(null)).toBe(false);
    });

    test('numberRange - validates number ranges', () => {
      const isAge = numberRange(0, 120, { integer: true });
      expect(isAge(25)).toBe(true);
      expect(isAge(-1)).toBe(false);
      expect(isAge(25.5)).toBe(false); // not integer
      expect(isAge(150)).toBe(false);
    });

    test('stringPattern - validates string patterns', () => {
      const isEmail = stringPattern(/^[^\s@]+@[^\s@]+\.[^\s@]+$/);
      expect(isEmail('test@example.com')).toBe(true);
      expect(isEmail('invalid-email')).toBe(false);
    });

    test('stringLength - validates string length', () => {
      const isPassword = stringLength(8, 128);
      expect(isPassword('password123')).toBe(true);
      expect(isPassword('short')).toBe(false);
      expect(isPassword('a'.repeat(200))).toBe(false); // too long
    });
  });

  // =============================================================================
  // Schema-Based Guards Tests
  // =============================================================================

  describe('Schema-Based Guards', () => {
    test('nestedObject - validates nested structures', () => {
      const userSchema = nestedObject({
        id: { validate: isString, required: true },
        profile: {
          validate: nestedObject({
            name: { validate: isString, required: true },
            bio: { validate: optional(isString), required: false }
          }),
          required: true
        },
        settings: {
          validate: nestedObject({
            theme: { validate: oneOfValues(['light', 'dark']), required: true }
          }),
          required: false
        }
      }, { strict: true });

      const validUser = {
        id: 'user-123',
        profile: {
          name: 'John Doe',
          bio: 'Developer'
        },
        settings: {
          theme: 'dark'
        }
      };

      expect(userSchema(validUser)).toBe(true);

      const invalidUser = {
        id: 'user-123',
        profile: {
          name: 'John Doe'
        },
        extraField: 'not allowed' // strict mode should reject
      };

      expect(userSchema(invalidUser)).toBe(false);
    });

    test('collectionSchema - validates collections', () => {
      const userCollection = collectionSchema(
        { validate: exactShape({ id: isString, name: isString }) },
        { minLength: 1, maxLength: 10 }
      );

      const validUsers = [
        { id: '1', name: 'John' },
        { id: '2', name: 'Jane' }
      ];

      expect(userCollection(validUsers)).toBe(true);
      expect(userCollection([])).toBe(false); // minLength: 1
      expect(userCollection([{ id: 1, name: 'John' }])).toBe(false); // invalid id type
    });
  });

  // =============================================================================
  // Performance Utilities Tests
  // =============================================================================

  describe('Performance Utilities', () => {
    test('memoized - caches guard results', () => {
      const expensiveGuard = (value: unknown): value is string => {
        // Simulate expensive operation
        return typeof value === 'string' && value.length > 5;
      };

      const memoizedGuard = memoized(expensiveGuard);

      const testString = 'test-string';
      expect(memoizedGuard(testString)).toBe(true);
      expect(memoizedGuard(testString)).toBe(true); // Should use cache
      expect(memoizedGuard('short')).toBe(false);
    });

    test('fastFail - quickly rejects common invalid types', () => {
      const isUserObject = fastFail(
        exactShape({ name: isString, age: isNumber }),
        ['string', 'number', 'boolean']
      );

      expect(isUserObject({ name: 'John', age: 30 })).toBe(true);
      expect(isUserObject('invalid-string')).toBe(false); // Fast fail
      expect(isUserObject(123)).toBe(false); // Fast fail
    });

    test('GuardPerformance - measures performance', () => {
      const testGuard = GuardPerformance.wrap('test-guard', isString);

      // Execute guard multiple times
      testGuard('hello');
      testGuard(123);
      testGuard('world');

      const metrics = GuardPerformance.getMetrics('test-guard');
      expect(metrics).toBeDefined();
      expect(metrics!.calls).toBe(3);
      expect(metrics!.totalTime).toBeGreaterThan(0);

      GuardPerformance.resetMetrics('test-guard');
      expect(GuardPerformance.getMetrics('test-guard')).toBeUndefined();
    });
  });
});