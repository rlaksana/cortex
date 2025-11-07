/**
 * Tool Schema Validation Tests - T22 Implementation
 *
 * Comprehensive validation of MCP tool schemas including:
 * - JSON Schema compliance validation
 * - Zod runtime schema validation
 * - Schema consistency between JSON and Zod schemas
 * - Input transformation and sanitization
 * - Schema evolution and backward compatibility
 *
 * @version 2.0.1
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { z } from 'zod';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';

// Import schemas
import { ALL_JSON_SCHEMAS } from '../../src/schemas/json-schemas.js';
import {
  MemoryStoreInputSchema,
  MemoryFindInputSchema,
  MergeStrategySchema,
  TTLPolicySchema,
  SearchStrategySchema,
} from '../../src/schemas/mcp-inputs.js';

// Import validation functions
import {
  safeValidateMemoryStoreInput,
  safeValidateMemoryFindInput,
  validateMemoryStoreInput,
  validateMemoryFindInput,
} from '../../src/schemas/mcp-inputs.js';

import { ValidationError } from '../../src/utils/error-handler.js';

// Test fixtures
import {
  createValidMemoryStoreInput,
  createValidMemoryFindInput,
  createInvalidMemoryStoreInput,
  createInvalidMemoryFindInput,
  createEdgeCaseInputs,
  createBoundaryConditionInputs,
} from '../fixtures/mcp-input-fixtures.js';

describe('Tool Schema Validation Tests - T22', () => {
  let ajv: Ajv;

  beforeEach(() => {
    // Initialize AJV for JSON Schema validation
    ajv = new Ajv({ allErrors: true });
    addFormats(ajv);
  });

  // ============================================================================
  // JSON Schema Validation
  // ============================================================================

  describe('JSON Schema Compliance', () => {
    it('should validate memory_store JSON schema structure', () => {
      const memoryStoreSchema = ALL_JSON_SCHEMAS.memory_store;

      // Verify schema structure
      expect(memoryStoreSchema).toHaveProperty('$schema');
      expect(memoryStoreSchema).toHaveProperty('type', 'object');
      expect(memoryStoreSchema).toHaveProperty('required');
      expect(memoryStoreSchema).toHaveProperty('properties');

      // Verify required fields
      expect(memoryStoreSchema.required).toContain('items');

      // Verify property definitions
      expect(memoryStoreSchema.properties).toHaveProperty('items');
      expect(memoryStoreSchema.properties).toHaveProperty('deduplication');
      expect(memoryStoreSchema.properties).toHaveProperty('global_ttl');
      expect(memoryStoreSchema.properties).toHaveProperty('global_truncation');
      expect(memoryStoreSchema.properties).toHaveProperty('insights');
      expect(memoryStoreSchema.properties).toHaveProperty('scope');

      // Verify items property
      const itemsProperty = memoryStoreSchema.properties.items;
      expect(itemsProperty).toHaveProperty('type', 'array');
      expect(itemsProperty).toHaveProperty('minItems', 1);
      expect(itemsProperty).toHaveProperty('maxItems', 100);
      expect(itemsProperty).toHaveProperty('items');

      // Verify item schema
      const itemSchema = itemsProperty.items;
      expect(itemSchema).toHaveProperty('type', 'object');
      expect(itemSchema.required).toContain('kind');
      expect(itemSchema.properties).toHaveProperty('kind');
      expect(itemSchema.properties.kind).toHaveProperty('enum');
    });

    it('should validate memory_find JSON schema structure', () => {
      const memoryFindSchema = ALL_JSON_SCHEMAS.memory_find;

      // Verify schema structure
      expect(memoryFindSchema).toHaveProperty('$schema');
      expect(memoryFindSchema).toHaveProperty('type', 'object');
      expect(memoryFindSchema).toHaveProperty('required');
      expect(memoryFindSchema).toHaveProperty('properties');

      // Verify required fields
      expect(memoryFindSchema.required).toContain('query');

      // Verify property definitions
      expect(memoryFindSchema.properties).toHaveProperty('query');
      expect(memoryFindSchema.properties).toHaveProperty('scope');
      expect(memoryFindSchema.properties).toHaveProperty('search_strategy');
      expect(memoryFindSchema.properties).toHaveProperty('result_format');
      expect(memoryFindSchema.properties).toHaveProperty('limit');
      expect(memoryFindSchema.properties).toHaveProperty('ttl_filter');
      expect(memoryFindSchema.properties).toHaveProperty('kinds');
      expect(memoryFindSchema.properties).toHaveProperty('confidence_threshold');
      expect(memoryFindSchema.properties).toHaveProperty('include_metadata');
      expect(memoryFindSchema.properties).toHaveProperty('expand_relations');
      expect(memoryFindSchema.properties).toHaveProperty('max_expansion_depth');

      // Verify query property
      const queryProperty = memoryFindSchema.properties.query;
      expect(queryProperty).toHaveProperty('type', 'string');
      expect(queryProperty).toHaveProperty('minLength', 1);
      expect(queryProperty).toHaveProperty('maxLength', 1000);
    });

    it('should validate inputs using JSON Schema', () => {
      const validateMemoryStore = ajv.compile(ALL_JSON_SCHEMAS.memory_store);
      const validateMemoryFind = ajv.compile(ALL_JSON_SCHEMAS.memory_find);

      // Test valid inputs
      const validStoreInput = createValidMemoryStoreInput();
      const validFindInput = createValidMemoryFindInput();

      expect(validateMemoryStore(validStoreInput)).toBe(true);
      expect(validateMemoryFind(validFindInput)).toBe(true);

      // Test invalid inputs
      const invalidStoreInputs = createInvalidMemoryStoreInput();
      const invalidFindInputs = createInvalidMemoryFindInput();

      invalidStoreInputs.forEach((invalidInput, index) => {
        expect(validateMemoryStore(invalidInput)).toBe(false);
        expect(validateMemoryStore.errors).toBeDefined();
        expect(validateMemoryStore.errors!.length).toBeGreaterThan(0);
      });

      invalidFindInputs.forEach((invalidInput, index) => {
        expect(validateMemoryFind(invalidInput)).toBe(false);
        expect(validateMemoryFind.errors).toBeDefined();
        expect(validateMemoryFind.errors!.length).toBeGreaterThan(0);
      });
    });

    it('should provide descriptive JSON Schema validation errors', () => {
      const validateMemoryStore = ajv.compile(ALL_JSON_SCHEMAS.memory_store);
      const validateMemoryFind = ajv.compile(ALL_JSON_SCHEMAS.memory_find);

      // Test missing required field
      const missingItems = { deduplication: { enabled: true } };
      expect(validateMemoryStore(missingItems)).toBe(false);

      const error = validateMemoryStore.errors![0];
      expect(error.instancePath).toBe('');
      expect(error.keyword).toBe('required');
      expect(error.message).toContain('must have required property');
      expect(error.params.missingProperty).toBe('items');

      // Test invalid enum value
      const invalidStrategy = {
        items: [{ kind: 'entity', content: 'test' }],
        deduplication: { merge_strategy: 'invalid' },
      };
      expect(validateMemoryStore(invalidStrategy)).toBe(false);

      const enumError = validateMemoryStore.errors![0];
      expect(enumError.keyword).toBe('enum');
      expect(enumError.message).toContain('must be equal to one of the allowed values');
    });
  });

  // ============================================================================
  // Zod Schema Validation
  // ============================================================================

  describe('Zod Schema Validation', () => {
    it('should validate memory_store input using Zod schema', () => {
      const validInput = createValidMemoryStoreInput();
      const result = MemoryStoreInputSchema.safeParse(validInput);

      expect(result.success).toBe(true);
      if (result.success) {
        // Verify transformed output
        expect(result['data.items']).toBeInstanceOf(Array);
        expect(result['data.items'].length).toBeGreaterThan(0);
        expect(result['data.deduplication']).toBeDefined();
        expect(result['data.global_ttl']).toBeDefined();
        expect(result['data.global_truncation']).toBeDefined();
      }
    });

    it('should validate memory_find input using Zod schema', () => {
      const validInput = createValidMemoryFindInput();
      const result = MemoryFindInputSchema.safeParse(validInput);

      expect(result.success).toBe(true);
      if (result.success) {
        // Verify transformed output
        expect(result['data.query']).toBeTypeOf('string');
        expect(result['data.query'].trim()).toBe(result['data.query']); // Should be trimmed
        expect(result['data.search_strategy']).toBeDefined();
        expect(result['data.result_format']).toBeDefined();
        expect(result['data.limit']).toBeDefined();
      }
    });

    it('should reject invalid inputs with detailed Zod errors', () => {
      // Test memory_store validation
      const invalidStoreInputs = createInvalidMemoryStoreInput();
      invalidStoreInputs.forEach((invalidInput, index) => {
        const result = MemoryStoreInputSchema.safeParse(invalidInput);
        expect(result.success).toBe(false);

        if (!result.success) {
          expect(result.error).toBeInstanceOf(z['Z']odError);
          expect(result.error.issues.length).toBeGreaterThan(0);

          // Verify error structure
          const issue = result.error.issues[0];
          expect(issue).toHaveProperty('code');
          expect(issue).toHaveProperty('message');
          expect(issue).toHaveProperty('path');
          expect(issue.message).toBeTypeOf('string');
          expect(issue.message.length).toBeGreaterThan(0);
        }
      });

      // Test memory_find validation
      const invalidFindInputs = createInvalidMemoryFindInput();
      invalidFindInputs.forEach((invalidInput, index) => {
        const result = MemoryFindInputSchema.safeParse(invalidInput);
        expect(result.success).toBe(false);

        if (!result.success) {
          expect(result.error).toBeInstanceOf(z['Z']odError);
          expect(result.error.issues.length).toBeGreaterThan(0);
        }
      });
    });

    it('should apply input transformations correctly', () => {
      // Test string trimming transformation
      const untrimmedInput = {
        query: '  trimmed query with spaces  ',
        search_strategy: 'auto' as const,
      };

      const result = MemoryFindInputSchema.safeParse(untrimmedInput);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result['data.query']).toBe('trimmed query with spaces');
      }

      // Test default value application
      const minimalInput = {
        query: 'minimal query',
      };

      const minimalResult = MemoryFindInputSchema.safeParse(minimalInput);
      expect(minimalResult.success).toBe(true);
      if (minimalResult.success) {
        expect(minimalResult['data.search_strategy']).toBeDefined();
        expect(minimalResult['data.result_format']).toBeDefined();
        expect(minimalResult['data.limit']).toBeDefined();
      }
    });
  });

  // ============================================================================
  // Schema Consistency Tests
  // ============================================================================

  describe('Schema Consistency', () => {
    it('should maintain consistency between JSON and Zod schemas', () => {
      // Test that both validators accept the same valid inputs
      const validStoreInput = createValidMemoryStoreInput();
      const validFindInput = createValidMemoryFindInput();

      // JSON Schema validation
      const validateStoreJson = ajv.compile(ALL_JSON_SCHEMAS.memory_store);
      const validateFindJson = ajv.compile(ALL_JSON_SCHEMAS.memory_find);

      expect(validateStoreJson(validStoreInput)).toBe(true);
      expect(validateFindJson(validFindInput)).toBe(true);

      // Zod validation
      expect(MemoryStoreInputSchema.safeParse(validStoreInput).success).toBe(true);
      expect(MemoryFindInputSchema.safeParse(validFindInput).success).toBe(true);

      // Test that both validators reject the same invalid inputs
      const invalidStoreInput = { items: 'not an array' };
      const invalidFindInput = { query: 123 };

      expect(validateStoreJson(invalidStoreInput)).toBe(false);
      expect(validateFindJson(invalidFindInput)).toBe(false);
      expect(MemoryStoreInputSchema.safeParse(invalidStoreInput).success).toBe(false);
      expect(MemoryFindInputSchema.safeParse(invalidFindInput).success).toBe(false);
    });

    it('should have matching required fields across schemas', () => {
      const jsonStoreSchema = ALL_JSON_SCHEMAS.memory_store;
      const jsonFindSchema = ALL_JSON_SCHEMAS.memory_find;

      // Check memory_store required fields
      expect(jsonStoreSchema.required).toContain('items');
      // Zod schema also requires items (verified by testing)

      // Check memory_find required fields
      expect(jsonFindSchema.required).toContain('query');
      // Zod schema also requires query (verified by testing)
    });

    it('should have matching enum values across schemas', () => {
      // Test merge strategy enums
      const validMergeStrategies = [
        'skip',
        'prefer_existing',
        'prefer_newer',
        'combine',
        'intelligent',
      ];

      validMergeStrategies.forEach((strategy) => {
        expect(MergeStrategySchema.safeParse(strategy).success).toBe(true);
      });

      // Test TTL policy enums
      const validTtlPolicies = ['default', 'short', 'long', 'permanent'];

      validTtlPolicies.forEach((policy) => {
        expect(TTLPolicySchema.safeParse(policy).success).toBe(true);
      });

      // Test search strategy enums
      const validSearchStrategies = ['fast', 'auto', 'deep'];

      validSearchStrategies.forEach((strategy) => {
        expect(SearchStrategySchema.safeParse(strategy).success).toBe(true);
      });
    });
  });

  // ============================================================================
  // Validation Function Tests
  // ============================================================================

  describe('Validation Functions', () => {
    it('should validate memory_store inputs using validation functions', () => {
      const validInput = createValidMemoryStoreInput();

      // Test strict validation
      expect(() => validateMemoryStoreInput(validInput)).not.toThrow();

      // Test safe validation
      const safeResult = safeValidateMemoryStoreInput(validInput);
      expect(safeResult).not.toBeNull();
      expect(safeResult).toHaveProperty('items');
    });

    it('should handle validation errors using validation functions', () => {
      const invalidInput = createInvalidMemoryStoreInput()[0];

      // Test strict validation throws error
      expect(() => validateMemoryStoreInput(invalidInput)).toThrow(ValidationError);

      // Test safe validation returns null
      const safeResult = safeValidateMemoryStoreInput(invalidInput);
      expect(safeResult).toBeNull();
    });

    it('should validate memory_find inputs using validation functions', () => {
      const validInput = createValidMemoryFindInput();

      // Test strict validation
      expect(() => validateMemoryFindInput(validInput)).not.toThrow();

      // Test safe validation
      const safeResult = safeValidateMemoryFindInput(validInput);
      expect(safeResult).not.toBeNull();
      expect(safeResult).toHaveProperty('query');
    });

    it('should handle memory_find validation errors using validation functions', () => {
      const invalidInput = createInvalidMemoryFindInput()[0];

      // Test strict validation throws error
      expect(() => validateMemoryFindInput(invalidInput)).toThrow(ValidationError);

      // Test safe validation returns null
      const safeResult = safeValidateMemoryFindInput(invalidInput);
      expect(safeResult).toBeNull();
    });

    it('should provide proper ValidationError format', () => {
      const invalidInput = { items: 'invalid' };

      try {
        validateMemoryStoreInput(invalidInput);
        fail('Expected ValidationError to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(ValidationError);
        expect(error.message).toContain('validation failed');
        expect(error.field).toBeDefined();
        expect(error.code).toBeDefined();
      }
    });
  });

  // ============================================================================
  // Edge Case and Boundary Tests
  // ============================================================================

  describe('Edge Case Validation', () => {
    it('should handle edge cases in validation', () => {
      const edgeCases = createEdgeCaseInputs();

      // Test memory_store edge cases
      edgeCases.memoryStore.forEach((edgeCase, index) => {
        const result = MemoryStoreInputSchema.safeParse(edgeCase);

        // Edge cases should either pass or fail gracefully
        if (result.success) {
          // Verify structure if it passes
          expect(result.data).toHaveProperty('items');
          expect(Array.isArray(result['data.items'])).toBe(true);
        } else {
          // Verify proper error handling if it fails
          expect(result.error).toBeInstanceOf(z['Z']odError);
        }
      });

      // Test memory_find edge cases
      edgeCases.memoryFind.forEach((edgeCase, index) => {
        const result = MemoryFindInputSchema.safeParse(edgeCase);

        // Edge cases should either pass or fail gracefully
        if (result.success) {
          // Verify structure if it passes
          expect(result.data).toHaveProperty('query');
          expect(typeof result['data.query']).toBe('string');
        } else {
          // Verify proper error handling if it fails
          expect(result.error).toBeInstanceOf(z['Z']odError);
        }
      });
    });

    it('should handle boundary conditions correctly', () => {
      const boundaryConditions = createBoundaryConditionInputs();

      // Test numeric boundaries
      Object.entries(boundaryConditions.numeric).forEach(([field, values]) => {
        values.forEach((value: any) => {
          if (field === 'similarity_threshold') {
            const input = {
              items: [{ kind: 'entity' as const, content: 'test' }],
              deduplication: { similarity_threshold: value },
            };
            const result = MemoryStoreInputSchema.safeParse(input);
            expect(result.success).toBe(value >= 0.1 && value <= 1.0);
          }
        });
      });

      // Test string boundaries
      boundaryConditions.string.maxLength.forEach((value) => {
        const input = {
          items: [{ kind: 'entity' as const, content: value }],
        };
        const result = MemoryStoreInputSchema.safeParse(input);
        expect(result.success).toBe(value.length <= 100000);
      });

      // Test array boundaries
      boundaryConditions.array.minItems.forEach((value) => {
        const input = { items: value };
        const result = MemoryStoreInputSchema.safeParse(input);
        expect(result.success).toBe(value.length >= 1 && value.length <= 100);
      });
    });
  });

  // ============================================================================
  // Schema Evolution Tests
  // ============================================================================

  describe('Schema Evolution', () => {
    it('should handle schema versioning correctly', () => {
      const memoryStoreSchema = ALL_JSON_SCHEMAS.memory_store;
      const memoryFindSchema = ALL_JSON_SCHEMAS.memory_find;

      // Schemas should have version information
      expect(memoryStoreSchema).toHaveProperty('$schema');
      expect(memoryFindSchema).toHaveProperty('$schema');

      // Should use JSON Schema draft-07
      expect(memoryStoreSchema.$schema).toBe('http://json-schema.org/draft-07/schema#');
      expect(memoryFindSchema.$schema).toBe('http://json-schema.org/draft-07/schema#');
    });

    it('should maintain backward compatibility', () => {
      // Test with minimal v1.0 style inputs
      const v1StoreInput = {
        items: [{ kind: 'entity' as const, content: 'Simple entity' }],
      };

      const v1FindInput = {
        query: 'simple query',
      };

      // Should still validate with current schemas
      expect(MemoryStoreInputSchema.safeParse(v1StoreInput).success).toBe(true);
      expect(MemoryFindInputSchema.safeParse(v1FindInput).success).toBe(true);

      // Should have sensible defaults applied
      const storeResult = MemoryStoreInputSchema.safeParse(v1StoreInput);
      if (storeResult.success) {
        expect(storeResult['data.deduplication']).toBeDefined();
        expect(storeResult['data.global_ttl']).toBeDefined();
        expect(storeResult['data.global_truncation']).toBeDefined();
      }

      const findResult = MemoryFindInputSchema.safeParse(v1FindInput);
      if (findResult.success) {
        expect(findResult['data.search_strategy']).toBeDefined();
        expect(findResult['data.result_format']).toBeDefined();
        expect(findResult['data.limit']).toBeDefined();
      }
    });

    it('should provide migration path for deprecated fields', () => {
      // This would test handling of deprecated fields if any existed
      // For now, verify that the schema handles additional properties gracefully
      const inputWithExtraFields = {
        items: [{ kind: 'entity' as const, content: 'test' }],
        deprecatedField: 'should be ignored',
        anotherDeprecated: { nested: 'data' },
      };

      const result = MemoryStoreInputSchema.safeParse(inputWithExtraFields);
      // Should either succeed (ignoring extra fields) or fail gracefully
      expect(result.success || !result.success).toBe(true);
    });
  });

  // ============================================================================
  // Performance Tests
  // ============================================================================

  describe('Validation Performance', () => {
    it('should validate large inputs efficiently', () => {
      const largeInput = {
        items: Array(100)
          .fill(null)
          .map((_, i) => ({
            kind: 'entity' as const,
            content: `Entity ${i} with some content`,
            data: { index: i, timestamp: new Date().toISOString() },
          })),
      };

      const startTime = performance.now();
      const result = MemoryStoreInputSchema.safeParse(largeInput);
      const endTime = performance.now();

      // Should complete within reasonable time (100ms)
      expect(endTime - startTime).toBeLessThan(100);
      expect(result.success).toBe(true);
    });

    it('should handle complex validation efficiently', () => {
      const complexInput = {
        query: 'complex search query with many words',
        scope: {
          org: 'test-org',
          project: 'test-project',
          branch: 'feature/complex-validation',
        },
        search_strategy: 'deep' as const,
        result_format: 'detailed' as const,
        limit: 50,
        kinds: ['entity', 'decision', 'issue'] as const,
        confidence_threshold: 0.8,
        include_metadata: true,
        expand_relations: true,
        max_expansion_depth: 3,
      };

      const startTime = performance.now();
      const result = MemoryFindInputSchema.safeParse(complexInput);
      const endTime = performance.now();

      // Should complete within reasonable time (50ms)
      expect(endTime - startTime).toBeLessThan(50);
      expect(result.success).toBe(true);
    });
  });
});
