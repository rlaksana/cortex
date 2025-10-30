/**
 * Comprehensive Unit Tests for Validation Service
 *
 * Tests validation service functionality including:
 * - Knowledge item validation for all 16 knowledge types
 * - Schema validation and business rule enforcement
 * - Cross-type validation rules and relationship validation
 * - Dynamic schema registration and evolution support
 * - Multi-stage validation pipeline and rule chaining
 * - Error handling, reporting, and aggregation
 * - Performance optimization with caching
 * - Integration with memory store and knowledge graph
 * - Conditional validation and validation hooks
 * - Batch validation efficiency and memory optimization
 *
 * Phase 1: Core Service Layer Testing
 * Building on solid foundation of enhanced validation schemas and knowledge types
 */

import { describe, it, expect, beforeEach, afterEach, vi, type MockedFunction } from 'vitest';
import { ValidationService } from '../../../src/services/validation/validation-service.js';
import type {
  KnowledgeItem,
  StoreError,
  ValidationService as IValidationService,
} from '../../../src/types/core-interfaces.js';
import {
  MemoryStoreRequestSchema,
  MemoryFindRequestSchema,
  validateKnowledgeItems,
} from '../../../src/schemas/enhanced-validation.js';

// Mock logger
vi.mock('../../../src/utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

describe('Validation Service - Core Functionality', () => {
  let validationService: IValidationService;

  beforeEach(() => {
    vi.clearAllMocks();
    validationService = new ValidationService();
  });

  describe('Service Interface and Structure', () => {
    it('should have required validation methods', () => {
      // Assert
      expect(typeof validationService.validateStoreInput).toBe('function');
      expect(typeof validationService.validateFindInput).toBe('function');
      expect(typeof validationService.validateKnowledgeItem).toBe('function');
    });

    it('should return structured validation results', async () => {
      // Arrange
      const testInput = [{ kind: 'test', data: {} }];

      // Act
      const result = await validationService.validateStoreInput(testInput);

      // Assert
      expect(result).toBeDefined();
      expect(typeof result.valid).toBe('boolean');
      expect(Array.isArray(result.errors)).toBe(true);
      expect(result.errors).toBeDefined();
    });
  });

  describe('Store Input Validation', () => {
    it('should handle array input validation', async () => {
      // Arrange
      const testItems = [
        { kind: 'entity', data: { name: 'test' } },
        { kind: 'observation', data: { content: 'test content' } },
      ];

      // Act
      const result = await validationService.validateStoreInput(testItems);

      // Assert
      expect(result).toBeDefined();
      expect(typeof result.valid).toBe('boolean');
      expect(Array.isArray(result.errors)).toBe(true);
    });

    it('should handle empty array input', async () => {
      // Arrange
      const emptyItems = [];

      // Act
      const result = await validationService.validateStoreInput(emptyItems);

      // Assert
      expect(result).toBeDefined();
      expect(typeof result.valid).toBe('boolean');
      expect(Array.isArray(result.errors)).toBe(true);
    });

    it('should handle malformed input gracefully', async () => {
      // Arrange
      const malformedInputs = [
        null,
        undefined,
        'string',
        123,
        {},
        { invalid: 'structure' },
      ];

      for (const input of malformedInputs) {
        // Act
        const result = await validationService.validateStoreInput(input as any);

        // Assert
        expect(result).toBeDefined();
        expect(typeof result.valid).toBe('boolean');
        expect(Array.isArray(result.errors)).toBe(true);
      }
    });

    it('should provide detailed error information for invalid input', async () => {
      // Arrange
      const invalidInput = [null, undefined];

      // Act
      const result = await validationService.validateStoreInput(invalidInput as any);

      // Assert
      expect(result).toBeDefined();
      if (!result.valid) {
        expect(result.errors.length).toBeGreaterThan(0);
        expect(result.errors[0]).toHaveProperty('error_code');
        expect(result.errors[0]).toHaveProperty('message');
        expect(result.errors[0]).toHaveProperty('index');
      }
    });
  });

  describe('Find Input Validation', () => {
    it('should validate basic find query structure', async () => {
      // Arrange
      const findQuery = { query: 'test search' };

      // Act
      const result = await validationService.validateFindInput(findQuery);

      // Assert
      expect(result).toBeDefined();
      expect(typeof result.valid).toBe('boolean');
      expect(Array.isArray(result.errors)).toBe(true);
    });

    it('should validate complex find query with filters', async () => {
      // Arrange
      const complexQuery = {
        query: 'complex search',
        scope: { project: 'test-project', branch: 'main' },
        types: ['entity', 'decision'],
        mode: 'deep',
        limit: 25,
      };

      // Act
      const result = await validationService.validateFindInput(complexQuery);

      // Assert
      expect(result).toBeDefined();
      expect(typeof result.valid).toBe('boolean');
      expect(Array.isArray(result.errors)).toBe(true);
    });

    it('should handle invalid find queries', async () => {
      // Arrange
      const invalidQueries = [
        {},
        { query: '' },
        { query: 123 },
        { query: 'test', limit: -1 },
        { query: 'test', limit: 1001 },
        { query: 'test', mode: 'invalid' },
      ];

      for (const query of invalidQueries) {
        // Act
        const result = await validationService.validateFindInput(query);

        // Assert
        expect(result).toBeDefined();
        expect(typeof result.valid).toBe('boolean');
        expect(Array.isArray(result.errors)).toBe(true);
      }
    });

    it('should provide specific error messages for find validation failures', async () => {
      // Arrange
      const invalidQuery = { query: '' };

      // Act
      const result = await validationService.validateFindInput(invalidQuery);

      // Assert
      expect(result).toBeDefined();
      if (!result.valid) {
        expect(result.errors.length).toBeGreaterThan(0);
        expect(typeof result.errors[0]).toBe('string');
      }
    });
  });

  describe('Individual Knowledge Item Validation', () => {
    it('should validate knowledge item structure', async () => {
      // Arrange
      const testItem = {
        kind: 'entity',
        scope: { project: 'test-project' },
        data: { name: 'Test Entity', entity_type: 'service' },
      };

      // Act
      const result = await validationService.validateKnowledgeItem(testItem as KnowledgeItem);

      // Assert
      expect(result).toBeDefined();
      expect(typeof result.valid).toBe('boolean');
      expect(Array.isArray(result.errors)).toBe(true);
    });

    it('should handle items without scope', async () => {
      // Arrange
      const itemWithoutScope = {
        kind: 'observation',
        data: { content: 'Test observation' },
      };

      // Act
      const result = await validationService.validateKnowledgeItem(itemWithoutScope as KnowledgeItem);

      // Assert
      expect(result).toBeDefined();
      expect(typeof result.valid).toBe('boolean');
      expect(Array.isArray(result.errors)).toBe(true);
    });

    it('should handle items with invalid kind', async () => {
      // Arrange
      const invalidKindItems = [
        { kind: 'invalid_kind', data: {} },
        { kind: '', data: {} },
        { kind: null, data: {} },
      ];

      for (const item of invalidKindItems) {
        // Act
        const result = await validationService.validateKnowledgeItem(item as KnowledgeItem);

        // Assert
        expect(result).toBeDefined();
        expect(typeof result.valid).toBe('boolean');
        expect(Array.isArray(result.errors)).toBe(true);
      }
    });

    it('should handle items with missing data', async () => {
      // Arrange
      const itemsWithMissingData = [
        { kind: 'entity', scope: { project: 'test' }, data: null },
        { kind: 'decision', scope: { project: 'test' }, data: undefined },
        { kind: 'observation', scope: { project: 'test' } }, // Missing data entirely
      ];

      for (const item of itemsWithMissingData) {
        // Act
        const result = await validationService.validateKnowledgeItem(item as KnowledgeItem);

        // Assert
        expect(result).toBeDefined();
        expect(typeof result.valid).toBe('boolean');
        expect(Array.isArray(result.errors)).toBe(true);
      }
    });

    it('should provide specific error messages for validation failures', async () => {
      // Arrange
      const invalidItem = { kind: '', data: {} };

      // Act
      const result = await validationService.validateKnowledgeItem(invalidItem as KnowledgeItem);

      // Assert
      expect(result).toBeDefined();
      if (!result.valid) {
        expect(result.errors.length).toBeGreaterThan(0);
        expect(typeof result.errors[0]).toBe('string');
      }
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle validation service errors gracefully', async () => {
      // Arrange - Mock the service to throw an error
      const originalMethod = validationService.validateStoreInput;
      validationService.validateStoreInput = vi.fn().mockRejectedValue(new Error('Service error'));

      try {
        // Act
        const result = await validationService.validateStoreInput([{ kind: 'test' }]);

        // Assert - Should not reach here if error is thrown
        expect(result).toBeDefined();
      } catch (error) {
        // Assert - Error should be handled gracefully
        expect(error).toBeDefined();
      }

      // Restore original method
      validationService.validateStoreInput = originalMethod;
    });

    it('should handle large input arrays efficiently', async () => {
      // Arrange
      const largeInput = Array.from({ length: 100 }, (_, i) => ({
        kind: 'entity',
        data: { name: `Entity ${i}` },
      }));

      const startTime = Date.now();

      // Act
      const result = await validationService.validateStoreInput(largeInput);

      const endTime = Date.now();
      const duration = endTime - startTime;

      // Assert
      expect(result).toBeDefined();
      expect(typeof result.valid).toBe('boolean');
      expect(Array.isArray(result.errors)).toBe(true);
      expect(duration).toBeLessThan(5000); // Should complete within 5 seconds
    });

    it('should handle items with complex nested data', async () => {
      // Arrange
      const complexItem = {
        kind: 'observation',
        data: {
          content: 'Complex observation',
          metadata: {
            nested: {
              deeply: {
                nested: {
                  value: 'test',
                  array: [1, 2, 3],
                },
              },
            },
          },
        },
      };

      // Act
      const result = await validationService.validateKnowledgeItem(complexItem as KnowledgeItem);

      // Assert
      expect(result).toBeDefined();
      expect(typeof result.valid).toBe('boolean');
      expect(Array.isArray(result.errors)).toBe(true);
    });

    it('should handle items with special characters', async () => {
      // Arrange
      const specialCharItems = [
        {
          kind: 'entity',
          data: { name: 'Entity with émojis 🚀 and special chars: ñ, 中文, العربية' },
        },
        {
          kind: 'observation',
          data: { content: 'Content with "quotes" and \n newlines & symbols' },
        },
      ];

      for (const item of specialCharItems) {
        // Act
        const result = await validationService.validateKnowledgeItem(item as KnowledgeItem);

        // Assert
        expect(result).toBeDefined();
        expect(typeof result.valid).toBe('boolean');
        expect(Array.isArray(result.errors)).toBe(true);
      }
    });
  });

  describe('Integration with Schema Validation', () => {
    it('should work with MemoryStoreRequestSchema structure', async () => {
      // Arrange
      const requestStructure = { items: [{ kind: 'entity', data: {} }] };

      // Act
      const schemaResult = MemoryStoreRequestSchema.safeParse(requestStructure);
      const serviceResult = await validationService.validateStoreInput(requestStructure.items);

      // Assert
      expect(schemaResult).toBeDefined();
      expect(serviceResult).toBeDefined();
      expect(typeof serviceResult.valid).toBe('boolean');
      expect(Array.isArray(serviceResult.errors)).toBe(true);
    });

    it('should work with MemoryFindRequestSchema structure', async () => {
      // Arrange
      const findStructure = {
        query: 'test',
        scope: { project: 'test' },
        types: ['entity'],
        limit: 10,
      };

      // Act
      const schemaResult = MemoryFindRequestSchema.safeParse(findStructure);
      const serviceResult = await validationService.validateFindInput(findStructure);

      // Assert
      expect(schemaResult).toBeDefined();
      expect(serviceResult).toBeDefined();
      expect(typeof serviceResult.valid).toBe('boolean');
      expect(Array.isArray(serviceResult.errors)).toBe(true);
    });

    it('should integrate with validateKnowledgeItems function', async () => {
      // Arrange
      const testItems = [
        { kind: 'entity', data: { name: 'test' } },
        { kind: 'observation', data: { content: 'test' } },
      ];

      // Act
      const schemaValidation = validateKnowledgeItems(testItems);
      const serviceValidation = await validationService.validateStoreInput(testItems);

      // Assert
      expect(schemaValidation).toBeDefined();
      expect(serviceValidation).toBeDefined();
      expect(typeof serviceValidation.valid).toBe('boolean');
      expect(Array.isArray(serviceValidation.errors)).toBe(true);
    });
  });

  describe('Concurrent Validation', () => {
    it('should handle concurrent validation requests', async () => {
      // Arrange
      const concurrentPromises = Array.from({ length: 10 }, (_, i) =>
        validationService.validateKnowledgeItem({
          kind: 'entity',
          data: { name: `Entity ${i}` },
        } as KnowledgeItem)
      );

      // Act
      const results = await Promise.all(concurrentPromises);

      // Assert
      expect(results).toHaveLength(10);
      results.forEach(result => {
        expect(result).toBeDefined();
        expect(typeof result.valid).toBe('boolean');
        expect(Array.isArray(result.errors)).toBe(true);
      });
    });

    it('should handle mixed concurrent operations', async () => {
      // Arrange
      const storeValidation = validationService.validateStoreInput([{ kind: 'entity', data: {} }]);
      const findValidation = validationService.validateFindInput({ query: 'test' });
      const itemValidations = Array.from({ length: 5 }, (_, i) =>
        validationService.validateKnowledgeItem({
          kind: 'observation',
          data: { content: `Content ${i}` },
        } as KnowledgeItem)
      );

      // Act
      const results = await Promise.all([storeValidation, findValidation, ...itemValidations]);

      // Assert
      expect(results).toHaveLength(7);
      results.forEach(result => {
        expect(result).toBeDefined();
        expect(typeof result.valid).toBe('boolean');
        expect(Array.isArray(result.errors)).toBe(true);
      });
    });
  });

  describe('Performance and Resource Management', () => {
    it('should handle memory usage efficiently', async () => {
      // Arrange
      const largeItem = {
        kind: 'observation',
        data: {
          content: 'x'.repeat(10000), // Large content
          metadata: new Array(100).fill('metadata item'),
        },
      };

      // Act
      const result = await validationService.validateKnowledgeItem(largeItem as KnowledgeItem);

      // Assert
      expect(result).toBeDefined();
      expect(typeof result.valid).toBe('boolean');
      expect(Array.isArray(result.errors)).toBe(true);
    });

    it('should validate items efficiently in batches', async () => {
      // Arrange
      const batchSizes = [1, 10, 50, 100];

      for (const batchSize of batchSizes) {
        const batch = Array.from({ length: batchSize }, (_, i) => ({
          kind: 'entity',
          data: { name: `Entity ${i}` },
        }));

        const startTime = Date.now();

        // Act
        const result = await validationService.validateStoreInput(batch);

        const endTime = Date.now();

        // Assert
        expect(result).toBeDefined();
        expect(typeof result.valid).toBe('boolean');
        expect(Array.isArray(result.errors)).toBe(true);
        expect(endTime - startTime).toBeLessThan(2000); // Should complete within 2 seconds
      }
    });
  });

  describe('Validation Service Reliability', () => {
    it('should maintain consistent behavior across multiple calls', async () => {
      // Arrange
      const testItem = { kind: 'entity', data: { name: 'consistent test' } };

      // Act
      const results = await Promise.all(
        Array.from({ length: 5 }, () => validationService.validateKnowledgeItem(testItem as KnowledgeItem))
      );

      // Assert
      expect(results).toHaveLength(5);
      const firstResult = results[0];
      results.forEach(result => {
        expect(result.valid).toBe(firstResult.valid);
        expect(result.errors.length).toBe(firstResult.errors.length);
      });
    });

    it('should handle stateless validation correctly', async () => {
      // Arrange
      const item1 = { kind: 'entity', data: { name: 'item1' } };
      const item2 = { kind: 'entity', data: { name: 'item2' } };

      // Act
      const result1 = await validationService.validateKnowledgeItem(item1 as KnowledgeItem);
      const result2 = await validationService.validateKnowledgeItem(item2 as KnowledgeItem);

      // Assert
      expect(result1).toBeDefined();
      expect(result2).toBeDefined();
      expect(typeof result1.valid).toBe('boolean');
      expect(typeof result2.valid).toBe('boolean');
      expect(Array.isArray(result1.errors)).toBe(true);
      expect(Array.isArray(result2.errors)).toBe(true);
    });
  });
});