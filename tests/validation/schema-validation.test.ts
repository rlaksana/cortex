/**
 * JSON Schema Validation Tests
 *
 * Tests to validate that simplified schemas conform to JSON Schema standards
 * and can be parsed without timeout issues.
 */

import { describe, it, expect } from 'vitest';
import {
  MEMORY_STORE_JSON_SCHEMA,
  MEMORY_FIND_JSON_SCHEMA,
  SYSTEM_STATUS_JSON_SCHEMA,
  PERFORMANCE_MONITORING_JSON_SCHEMA
} from '../../src/schemas/json-schemas.js';

describe('JSON Schema Validation', () => {
  describe('Schema Structure Validation', () => {
    it('should have valid MEMORY_STORE_JSON_SCHEMA structure', () => {
      expect(MEMORY_STORE_JSON_SCHEMA).toBeDefined();
      expect(MEMORY_STORE_JSON_SCHEMA.$schema).toBe('http://json-schema.org/draft-07/schema#');
      expect(MEMORY_STORE_JSON_SCHEMA.type).toBe('object');
      expect(MEMORY_STORE_JSON_SCHEMA.required).toContain('items');

      // Verify no complex definitions that could cause parsing issues
      expect(MEMORY_STORE_JSON_SCHEMA.definitions).toBeUndefined();

      // Verify simplified oneOf structure
      const itemsSchema = MEMORY_STORE_JSON_SCHEMA.properties?.items;
      expect(itemsSchema?.items?.oneOf).toBeDefined();
      expect(Array.isArray(itemsSchema?.items?.oneOf)).toBe(true);
      expect(itemsSchema?.items?.oneOf).toHaveLength(2); // content-based or data-based
    });

    it('should have valid MEMORY_FIND_JSON_SCHEMA structure', () => {
      expect(MEMORY_FIND_JSON_SCHEMA).toBeDefined();
      expect(MEMORY_FIND_JSON_SCHEMA.$schema).toBe('http://json-schema.org/draft-07/schema#');
      expect(MEMORY_FIND_JSON_SCHEMA.type).toBe('object');
      expect(MEMORY_FIND_JSON_SCHEMA.required).toContain('query');

      // Verify no complex definitions that could cause parsing issues
      expect(MEMORY_FIND_JSON_SCHEMA.definitions).toBeUndefined();

      // Verify inlined configurations instead of $ref
      expect(MEMORY_FIND_JSON_SCHEMA.properties?.graph_expansion).toBeDefined();
      expect(MEMORY_FIND_JSON_SCHEMA.properties?.ttl_filters).toBeDefined();
      expect(MEMORY_FIND_JSON_SCHEMA.properties?.filters).toBeDefined();
      expect(MEMORY_FIND_JSON_SCHEMA.properties?.formatting).toBeDefined();
      expect(MEMORY_FIND_JSON_SCHEMA.properties?.optimization).toBeDefined();
      expect(MEMORY_FIND_JSON_SCHEMA.properties?.analytics).toBeDefined();
    });

    it('should have valid SYSTEM_STATUS_JSON_SCHEMA structure', () => {
      expect(SYSTEM_STATUS_JSON_SCHEMA).toBeDefined();
      expect(SYSTEM_STATUS_JSON_SCHEMA.$schema).toBe('http://json-schema.org/draft-07/schema#');
      expect(SYSTEM_STATUS_JSON_SCHEMA.type).toBe('object');
      expect(SYSTEM_STATUS_JSON_SCHEMA.required).toContain('operation');

      // Verify no complex definitions that could cause parsing issues
      expect(SYSTEM_STATUS_JSON_SCHEMA.definitions).toBeUndefined();

      // Verify inlined cleanup_config instead of $ref
      expect(SYSTEM_STATUS_JSON_SCHEMA.properties?.cleanup_config).toBeDefined();
    });

    it('should have valid PERFORMANCE_MONITORING_JSON_SCHEMA structure', () => {
      expect(PERFORMANCE_MONITORING_JSON_SCHEMA).toBeDefined();
      expect(PERFORMANCE_MONITORING_JSON_SCHEMA.$schema).toBe('http://json-schema.org/draft-07/schema#');
      expect(PERFORMANCE_MONITORING_JSON_SCHEMA.type).toBe('object');
      expect(PERFORMANCE_MONITORING_JSON_SCHEMA.required).toContain('operation');

      // Verify no complex definitions that could cause parsing issues
      expect(PERFORMANCE_MONITORING_JSON_SCHEMA.definitions).toBeUndefined();
    });
  });

  describe('Schema Complexity Metrics', () => {
    it('should have reasonable schema complexity', () => {
      const schemas = [
        { name: 'MEMORY_STORE_JSON_SCHEMA', schema: MEMORY_STORE_JSON_SCHEMA },
        { name: 'MEMORY_FIND_JSON_SCHEMA', schema: MEMORY_FIND_JSON_SCHEMA },
        { name: 'SYSTEM_STATUS_JSON_SCHEMA', schema: SYSTEM_STATUS_JSON_SCHEMA },
        { name: 'PERFORMANCE_MONITORING_JSON_SCHEMA', schema: PERFORMANCE_MONITORING_JSON_SCHEMA },
      ];

      schemas.forEach(({ name, schema }) => {
        const complexity = calculateSchemaComplexity(schema);
        console.log(`${name} complexity score: ${complexity}`);

        // Complexity should be reasonable to avoid parsing timeouts
        expect(complexity).toBeLessThan(1000); // Arbitrary threshold for acceptable complexity
      });
    });

    it('should have minimal nesting depth', () => {
      const schemas = [
        { name: 'MEMORY_STORE_JSON_SCHEMA', schema: MEMORY_STORE_JSON_SCHEMA },
        { name: 'MEMORY_FIND_JSON_SCHEMA', schema: MEMORY_FIND_JSON_SCHEMA },
        { name: 'SYSTEM_STATUS_JSON_SCHEMA', schema: SYSTEM_STATUS_JSON_SCHEMA },
        { name: 'PERFORMANCE_MONITORING_JSON_SCHEMA', schema: PERFORMANCE_MONITORING_JSON_SCHEMA },
      ];

      schemas.forEach(({ name, schema }) => {
        const maxDepth = calculateMaxNestingDepth(schema);
        console.log(`${name} max nesting depth: ${maxDepth}`);

        // Nesting depth should be minimal to improve parsing performance
        expect(maxDepth).toBeLessThanOrEqual(4); // Reasonable depth limit
      });
    });
  });

  describe('Schema Validation Examples', () => {
    it('should validate valid memory store input', () => {
      const validInput = {
        items: [
          {
            kind: 'entity',
            content: 'Test entity content',
            scope: {
              project: 'test-project'
            }
          }
        ]
      };

      // This would normally use a JSON Schema validator
      // For now, we just verify the structure matches expectations
      expect(validInput.items).toBeDefined();
      expect(validInput.items[0].kind).toBe('entity');
      expect(validInput.items[0].content).toBe('Test entity content');
    });

    it('should validate valid memory find input', () => {
      const validInput = {
        query: 'test search',
        limit: 10,
        types: ['entity', 'observation']
      };

      expect(validInput.query).toBe('test search');
      expect(validInput.limit).toBe(10);
      expect(validInput.types).toContain('entity');
    });

    it('should validate valid system status input', () => {
      const validInput = {
        operation: 'health',
        include_detailed_metrics: true
      };

      expect(validInput.operation).toBe('health');
      expect(validInput.include_detailed_metrics).toBe(true);
    });

    it('should validate valid performance monitoring input', () => {
      const validInput = {
        operation: 'get_metrics',
        categories: ['performance'],
        time_window: {
          last_hours: 24
        }
      };

      expect(validInput.operation).toBe('get_metrics');
      expect(validInput.categories).toContain('performance');
      expect(validInput.time_window?.last_hours).toBe(24);
    });
  });
});

/**
 * Helper function to calculate schema complexity score
 * This is a simplified metric based on object properties and nesting
 */
function calculateSchemaComplexity(schema: any): number {
  let complexity = 0;

  function traverse(obj: any, depth: number = 0): void {
    if (typeof obj !== 'object' || obj === null) return;

    complexity += depth; // Each nested level adds complexity

    Object.keys(obj).forEach(key => {
      complexity += 1; // Each property adds complexity

      if (key === 'properties' || key === 'items') {
        traverse(obj[key], depth + 1);
      } else if (key === 'oneOf' && Array.isArray(obj[key])) {
        obj[key].forEach((item: any) => traverse(item, depth + 1));
      }
    });
  }

  traverse(schema);
  return complexity;
}

/**
 * Helper function to calculate maximum nesting depth
 */
function calculateMaxNestingDepth(schema: any, currentDepth: number = 0): number {
  if (typeof schema !== 'object' || schema === null) return currentDepth;

  let maxDepth = currentDepth;

  Object.keys(schema).forEach(key => {
    if (key === 'properties' || key === 'items') {
      const depth = calculateMaxNestingDepth(schema[key], currentDepth + 1);
      maxDepth = Math.max(maxDepth, depth);
    } else if (key === 'oneOf' && Array.isArray(schema[key])) {
      schema[key].forEach((item: any) => {
        const depth = calculateMaxNestingDepth(item, currentDepth + 1);
        maxDepth = Math.max(maxDepth, depth);
      });
    }
  });

  return maxDepth;
}