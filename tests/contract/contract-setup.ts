/**
 * Contract Test Setup - T22 Implementation
 *
 * Setup configuration for API contract testing including:
 * - Global test utilities
 * - Mock data factories
 * - Validation helpers
 * - Response format validators
 *
 * @version 2.0.1
 */

import { beforeEach, afterEach, expect } from 'vitest';
import { z } from 'zod';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';

// ============================================================================
// Global Setup
// ============================================================================

// Initialize AJV for JSON Schema validation
export const ajv = new Ajv({ allErrors: true });
addFormats(ajv);

// Global test utilities
export const TestUtils = {
  // Validation helpers
  validateSchema: (schema: any, data: any) => {
    const validate = ajv.compile(schema);
    const valid = validate(data);
    return {
      valid,
      errors: validate.errors || [],
    };
  },

  // Response format validation
  validateResponseStructure: (response: any, expectedType: 'success' | 'error' = 'success') => {
    expect(response).toHaveProperty('content');
    expect(response).toHaveProperty('_meta');
    expect(response).toHaveProperty('isError');

    expect(Array.isArray(response.content)).toBe(true);
    expect(typeof response['_meta']).toBe('object');
    expect(typeof response.isError).toBe('boolean');

    if (expectedType === 'success') {
      expect(response.isError).toBe(false);
    } else if (expectedType === 'error') {
      expect(response.isError).toBe(true);
      expect(response['_']meta).toHaveProperty('error');
    }

    // Verify content items
    response.content.forEach((item: any) => {
      expect(item).toHaveProperty('type');
      expect(item).toHaveProperty('text');
      expect(typeof item.type).toBe('string');
      expect(typeof item.text).toBe('string');
    });

    // Verify metadata
    expect(response['_']meta).toHaveProperty('requestId');
    expect(response['_']meta).toHaveProperty('timestamp');
    expect(response['_']meta).toHaveProperty('operation');
    expect(response['_']meta).toHaveProperty('duration');
    expect(response['_']meta).toHaveProperty('version');

    return true;
  },

  // Metadata validation
  validateMetadata: (meta: any) => {
    expect(typeof meta.requestId).toBe('string');
    expect(meta.requestId).toMatch(/^[a-f0-9-]{36}$/); // UUID format

    expect(typeof meta.timestamp).toBe('string');
    expect(new Date(meta.timestamp).toISOString()).toBe(meta.timestamp); // Valid ISO date

    expect(typeof meta.operation).toBe('string');
    expect(meta.operation).toMatch(/^(memory_store|memory_find)$/);

    expect(typeof meta.duration).toBe('number');
    expect(meta.duration).toBeGreaterThan(0);

    expect(typeof meta.version).toBe('string');
    expect(meta.version).toMatch(/^\d+\.\d+\.\d+$/); // Semantic version

    return true;
  },

  // Error validation
  validateError: (error: any) => {
    expect(error).toHaveProperty('code');
    expect(error).toHaveProperty('message');
    expect(error).toHaveProperty('type');
    expect(error).toHaveProperty('details');

    expect(typeof error.code).toBe('string');
    expect(error.code).toMatch(/^[A-Z_]+$/);

    expect(typeof error.message).toBe('string');
    expect(error.message.length).toBeGreaterThan(0);
    expect(error.message.length).toBeLessThan(1000);

    expect(['validation', 'operational', 'system']).toContain(error.type);

    expect(typeof error.details).toBe('object');
    expect(error.details).not.toBeNull();

    return true;
  },
};

// Global test data generators
export const TestDataGenerator = {
  // Generate valid UUID
  generateUUID: () => {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = (Math.random() * 16) | 0;
      const v = c === 'x' ? r : (r & 0x3) | 0x8;
      return v.toString(16);
    });
  },

  // Generate timestamp
  generateTimestamp: (offsetHours: number = 0) => {
    const date = new Date();
    date.setHours(date.getHours() + offsetHours);
    return date.toISOString();
  },

  // Generate test entity
  generateEntity: (overrides: any = {}) => ({
    kind: 'entity',
    content: `Test entity content ${TestDataGenerator.generateUUID()}`,
    data: {
      name: `TestEntity_${Date.now()}`,
      type: 'component',
      description: 'Auto-generated test entity',
      ...overrides.data,
    },
    ...overrides,
  }),

  // Generate test decision
  generateDecision: (overrides: any = {}) => ({
    kind: 'decision',
    content: `Test decision content ${TestDataGenerator.generateUUID()}`,
    data: {
      title: `Test Decision ${Date.now()}`,
      rationale: 'Auto-generated test decision for contract validation',
      alternatives: ['Option A', 'Option B', 'Option C'],
      impact: 'medium',
      ...overrides.data,
    },
    ...overrides,
  }),

  // Generate test query
  generateQuery: (length: number = 20) => {
    const words = ['test', 'query', 'search', 'find', 'lookup', 'entity', 'decision', 'component'];
    const query = [];
    for (let i = 0; i < length; i++) {
      query.push(words[Math.floor(Math.random() * words.length)]);
    }
    return query.join(' ');
  },

  // Generate test scope
  generateScope: (overrides: any = {}) => ({
    project: `test-project-${Date.now()}`,
    branch: 'test-branch',
    org: 'test-org',
    ...overrides,
  }),
};

// Global mock configurations
export const MockConfigs = {
  // Mock memory store input
  memoryStoreInput: {
    items: [TestDataGenerator.generateEntity(), TestDataGenerator.generateDecision()],
    deduplication: {
      enabled: true,
      merge_strategy: 'intelligent',
      similarity_threshold: 0.85,
      check_within_scope_only: true,
      max_history_hours: 168,
      dedupe_window_days: 30,
      allow_newer_versions: true,
      enable_audit_logging: true,
    },
    global_ttl: {
      policy: 'default',
      auto_extend: false,
      extend_threshold_days: 7,
      max_extensions: 3,
    },
    global_truncation: {
      enabled: true,
      max_chars: 50000,
      truncate_strategy: 'smart',
      preserve_structure: true,
    },
    scope: TestDataGenerator.generateScope(),
    insights: {
      generate: false,
      include_similarity: true,
      include_connections: true,
    },
  },

  // Mock memory find input
  memoryFindInput: {
    query: TestDataGenerator.generateQuery(),
    scope: TestDataGenerator.generateScope(),
    search_strategy: 'auto',
    result_format: 'detailed',
    limit: 50,
    ttl_filter: {
      active_only: true,
      include_expired: false,
    },
    kinds: ['entity', 'decision'],
    confidence_threshold: 0.7,
    include_metadata: true,
    expand_relations: true,
    max_expansion_depth: 2,
  },

  // Mock response metadata
  responseMeta: {
    requestId: TestDataGenerator.generateUUID(),
    timestamp: TestDataGenerator.generateTimestamp(),
    operation: 'memory_store',
    duration: 500,
    version: '2.0.1',
    apiVersion: '2.0.1',
    minCompatibleVersion: '2.0.0',
  },
};

// Global assertion helpers
export const CustomAssertions = {
  // Assert valid UUID
  assertUUID: (uuid: string) => {
    expect(uuid).toMatch(/^[a-f0-9-]{36}$/);
  },

  // Assert valid ISO timestamp
  assertTimestamp: (timestamp: string) => {
    const date = new Date(timestamp);
    expect(date.toISOString()).toBe(timestamp);
  },

  // Assert semantic version
  assertSemanticVersion: (version: string) => {
    expect(version).toMatch(/^\d+\.\d+\.\d+$/);
    const [major, minor, patch] = version.split('.').map(Number);
    expect([major, minor, patch]).toEqual([
      expect.any(Number),
      expect.any(Number),
      expect.any(Number),
    ]);
  },

  // Assert error code format
  assertErrorCode: (code: string) => {
    expect(code).toMatch(/^[A-Z_]+$/);
  },

  // Assert operation name
  assertOperation: (operation: string) => {
    expect(operation).toMatch(/^(memory_store|memory_find)$/);
  },

  // Assert knowledge kind
  assertKnowledgeKind: (kind: string) => {
    const validKinds = [
      'entity',
      'relation',
      'observation',
      'section',
      'runbook',
      'change',
      'issue',
      'decision',
      'todo',
      'release_note',
      'ddl',
      'pr_context',
      'incident',
      'release',
      'risk',
      'assumption',
    ];
    expect(validKinds).toContain(kind);
  },

  // Assert merge strategy
  assertMergeStrategy: (strategy: string) => {
    const validStrategies = ['skip', 'prefer_existing', 'prefer_newer', 'combine', 'intelligent'];
    expect(validStrategies).toContain(strategy);
  },

  // Assert TTL policy
  assertTTLPolicy: (policy: string) => {
    const validPolicies = ['default', 'short', 'long', 'permanent'];
    expect(validPolicies).toContain(policy);
  },

  // Assert search strategy
  assertSearchStrategy: (strategy: string) => {
    const validStrategies = ['fast', 'auto', 'deep'];
    expect(validStrategies).toContain(strategy);
  },

  // Assert result format
  assertResultFormat: (format: string) => {
    const validFormats = ['detailed', 'summary', 'compact'];
    expect(validFormats).toContain(format);
  },
};

// Global setup and teardown hooks
beforeEach(() => {
  // Setup test environment
  process.env['NODE_ENV'] = 'test';
  process.env['CONTRACT_TESTING'] = 'true';
  process.env['API_VERSION'] = '2.0.1';
});

afterEach(() => {
  // Cleanup test environment
  delete process.env['CONTRACT_TESTING'];
});

// Export global utilities for use in test files
export { expect };

// Make utilities available globally
declare global {
  namespace Vi {
    interface TestContext {
      utils: typeof TestUtils;
      data: typeof TestDataGenerator;
      mocks: typeof MockConfigs;
      assertions: typeof CustomAssertions;
      ajv: Ajv;
    }
  }
}

// Attach utilities to test context
beforeEach(() => {
  // Adding utilities to test context
  (globalThis as any).TestUtils = TestUtils;
  (globalThis as any).TestDataGenerator = TestDataGenerator;
  (globalThis as any).MockConfigs = MockConfigs;
  (globalThis as any).CustomAssertions = CustomAssertions;
  (globalThis as any).ajv = ajv;
});
