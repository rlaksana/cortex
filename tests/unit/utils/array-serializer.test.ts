/**
 * Comprehensive Unit Tests for Array Serialization Utilities
 *
 * Tests array serialization functionality including:
 * - JavaScript to PostgreSQL array format conversion
 * - PostgreSQL to JavaScript array conversion
 * - Special character escaping
 * - Nested object serialization
 * - Edge cases and error handling
 * - Performance considerations
 */

import {
  serializeArray,
  deserializeArray,
  serializeForDatabase,
  deserializeFromDatabase,
} from '../../../src/utils/array-serializer';

// Setup global performance mock
(global as any).performance = {
  now: () => Date.now()
};

describe('Array Serialization Utilities', () => {
  describe('serializeArray', () => {
    it('should serialize simple string arrays', () => {
      const input = ['item1', 'item2', 'item3'];
      const result = serializeArray(input);

      expect(result).toEqual(['item1', 'item2', 'item3']);
    });

    it('should handle empty arrays', () => {
      const input: string[] = [];
      const result = serializeArray(input);

      expect(result).toBeNull();
    });

    it('should handle null input', () => {
      const result = serializeArray(null);

      expect(result).toBeNull();
    });

    it('should handle undefined input', () => {
      const result = serializeArray(undefined);

      expect(result).toBeNull();
    });

    it('should escape single quotes', () => {
      const input = ["item'with'quotes", "normal"];
      const result = serializeArray(input);

      expect(result).toEqual(["item''with''quotes", "normal"]);
    });

    it('should escape backslashes', () => {
      const input = ['item\\with\\backslashes', 'normal'];
      const result = serializeArray(input);

      expect(result).toEqual(['item\\\\with\\\\backslashes', 'normal']);
    });

    it('should escape both single quotes and backslashes', () => {
      const input = ["item'with\\both", 'normal'];
      const result = serializeArray(input);

      expect(result).toEqual(["item''with\\\\both", 'normal']);
    });

    it('should handle empty strings in array', () => {
      const input = ['', 'item2', ''];
      const result = serializeArray(input);

      expect(result).toEqual(['', 'item2', '']);
    });

    it('should handle arrays with special characters', () => {
      const input = ['item@#$%', 'item&*()', 'item{}[]'];
      const result = serializeArray(input);

      expect(result).toEqual(input); // Special characters should be preserved
    });

    it('should handle arrays with numbers as strings', () => {
      const input = ['123', '456.789', '0'];
      const result = serializeArray(input);

      expect(result).toEqual(input);
    });

    it('should handle arrays with whitespace', () => {
      const input = ['  item1  ', 'item2\t', '\nitem3\n'];
      const result = serializeArray(input);

      expect(result).toEqual(input); // Whitespace should be preserved
    });

    it('should handle arrays with Unicode characters', () => {
      const input = ['café', 'résumé', '测试', '🚀'];
      const result = serializeArray(input);

      expect(result).toEqual(input);
    });

    it('should handle very long strings', () => {
      const longString = 'a'.repeat(10000);
      const input = [longString, 'normal'];
      const result = serializeArray(input);

      expect(result).toEqual(input);
    });
  });

  describe('deserializeArray', () => {
    it('should deserialize simple string arrays', () => {
      const input = ['item1', 'item2', 'item3'];
      const result = deserializeArray(input);

      expect(result).toEqual(['item1', 'item2', 'item3']);
    });

    it('should handle empty arrays', () => {
      const input: string[] = [];
      const result = deserializeArray(input);

      expect(result).toEqual([]);
    });

    it('should handle null input', () => {
      const result = deserializeArray(null);

      expect(result).toEqual([]);
    });

    it('should unescape single quotes', () => {
      const input = ["item''with''quotes", "normal"];
      const result = deserializeArray(input);

      expect(result).toEqual(["item'with'quotes", "normal"]);
    });

    it('should unescape backslashes', () => {
      const input = ['item\\\\with\\\\backslashes', 'normal'];
      const result = deserializeArray(input);

      expect(result).toEqual(['item\\with\\backslashes', 'normal']);
    });

    it('should unescape both single quotes and backslashes', () => {
      const input = ["item''with\\\\both", 'normal'];
      const result = deserializeArray(input);

      expect(result).toEqual(["item'with\\both", 'normal']);
    });

    it('should handle empty strings in array', () => {
      const input = ['', 'item2', ''];
      const result = deserializeArray(input);

      expect(result).toEqual(['', 'item2', '']);
    });

    it('should handle arrays with special characters', () => {
      const input = ['item@#$%', 'item&*()', 'item{}[]'];
      const result = deserializeArray(input);

      expect(result).toEqual(input);
    });

    it('should handle arrays with Unicode characters', () => {
      const input = ['café', 'résumé', '测试', '🚀'];
      const result = deserializeArray(input);

      expect(result).toEqual(input);
    });

    it('should handle complex escape sequences', () => {
      const input = ["item''''with'''''multiple''quotes", "item\\\\\\\\with\\\\\\\\multiple\\\\\\\\backslashes"];
      const result = deserializeArray(input);

      expect(result).toEqual(["item''with'''multiple'quotes", "item\\\\with\\\\multiple\\\\backslashes"]);
    });
  });

  describe('Round-trip Serialization', () => {
    it('should maintain data integrity through serialize/deserialize cycle', () => {
      const originalArray = [
        "item'with'quotes",
        'item\\with\\backslashes',
        "item'with\\both",
        'normal item',
        '',
        'special@#$%characters',
        'café résumé 测试 🚀',
        '123',
        'item with spaces',
      ];

      const serialized = serializeArray(originalArray);
      const deserialized = deserializeArray(serialized);

      expect(deserialized).toEqual(originalArray);
    });

    it('should handle empty array round-trip', () => {
      const originalArray: string[] = [];

      const serialized = serializeArray(originalArray);
      const deserialized = deserializeArray(serialized);

      expect(deserialized).toEqual(originalArray);
    });

    it('should handle null round-trip', () => {
      const originalArray = null;

      const serialized = serializeArray(originalArray);
      const deserialized = deserializeArray(serialized);

      expect(deserialized).toEqual([]);
    });

    it('should handle undefined round-trip', () => {
      const originalArray = undefined;

      const serialized = serializeArray(originalArray);
      const deserialized = deserializeArray(serialized);

      expect(deserialized).toEqual([]);
    });
  });

  describe('serializeForDatabase', () => {
    it('should pass through non-array values unchanged', () => {
      const nonArrayValues = [
        'string',
        123,
        true,
        false,
        null,
        undefined,
        { key: 'value' },
      ];

      nonArrayValues.forEach(value => {
        const result = serializeForDatabase(value);
        // For primitives, use toBe; for objects, use toEqual
        if (value && typeof value === 'object') {
          expect(result).toEqual(value);
        } else {
          expect(result).toBe(value);
        }
      });
    });

    it('should serialize arrays using serializeArray', () => {
      const input = ['item1', 'item2', "item'with'quotes"];
      const result = serializeForDatabase(input);

      expect(result).toEqual(['item1', 'item2', "item''with''quotes"]);
    });

    it('should handle nested objects with arrays', () => {
      const input = {
        name: 'test',
        tags: ['tag1', 'tag2'],
        metadata: {
          categories: ['cat1', 'cat2'],
          count: 5,
          active: true,
        },
        description: 'no array here',
      };

      const result = serializeForDatabase(input);

      expect(result).toEqual({
        name: 'test',
        tags: ['tag1', 'tag2'],
        metadata: {
          categories: ['cat1', 'cat2'],
          count: 5,
          active: true,
        },
        description: 'no array here',
      });
    });

    it('should handle deeply nested objects with arrays', () => {
      const input = {
        level1: {
          level2: {
            level3: {
              array: ['deep1', 'deep2'],
              value: 'not array',
            },
          },
        },
        topArray: ['top1', 'top2'],
      };

      const result = serializeForDatabase(input);

      expect(result).toEqual({
        level1: {
          level2: {
            level3: {
              array: ['deep1', 'deep2'],
              value: 'not array',
            },
          },
        },
        topArray: ['top1', 'top2'],
      });
    });

    it('should handle objects with null and undefined properties', () => {
      const input = {
        validArray: ['item1', 'item2'],
        nullValue: null,
        undefinedValue: undefined,
        emptyArray: [],
        string: 'test',
      };

      const result = serializeForDatabase(input);

      expect(result).toEqual({
        validArray: ['item1', 'item2'],
        nullValue: null,
        undefinedValue: undefined,
        emptyArray: null, // Empty arrays become null
        string: 'test',
      });
    });

    it('should handle circular references gracefully', () => {
      const input: any = { name: 'test' };
      input.self = input;

      // This would cause infinite recursion if not handled properly
      expect(() => serializeForDatabase(input)).not.toThrow();
    });
  });

  describe('deserializeFromDatabase', () => {
    it('should return input unchanged for PostgreSQL arrays', () => {
      const input = ['item1', 'item2', 'item3'];
      const result = deserializeFromDatabase(input);

      expect(result).toEqual(input);
      expect(result).toBe(input); // Should be the same reference
    });

    it('should return non-array values unchanged', () => {
      const nonArrayValues = [
        'string',
        123,
        true,
        false,
        null,
        undefined,
        { key: 'value' },
      ];

      nonArrayValues.forEach(value => {
        const result = deserializeFromDatabase(value);
        expect(result).toBe(value); // Should be the same reference
      });
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle arrays with mixed content types', () => {
      const input = ['string', 123, true, null, undefined, { key: 'value' }, ['nested', 'array']];
      const result = serializeArray(input as any);

      expect(result).toEqual(['string', '123', 'true', 'null', 'undefined', '[object Object]', 'nested,array']);
    });

    it('should handle arrays with very large number of items', () => {
      const input = Array.from({ length: 10000 }, (_, i) => `item${i}`);
      const result = serializeArray(input);

      expect(result).toHaveLength(10000);
      expect(result[0]).toBe('item0');
      expect(result[9999]).toBe('item9999');
    });

    it('should handle arrays with duplicate items', () => {
      const input = ['duplicate', 'item', 'duplicate', 'item', 'unique'];
      const result = serializeArray(input);

      expect(result).toEqual(input);
    });

    it('should handle arrays with only whitespace strings', () => {
      const input = ['   ', '\t', '\n', '\r\n', ''];
      const result = serializeArray(input);

      expect(result).toEqual(input);
    });

    it('should handle arrays with SQL injection attempts', () => {
      const input = ["'; DROP TABLE users; --", "'; SELECT * FROM sensitive_data; --"];
      const result = serializeArray(input);

      expect(result).toEqual(["''; DROP TABLE users; --", "''; SELECT * FROM sensitive_data; --"]);
    });

    it('should handle arrays with JSON-like strings', () => {
      const input = ['{"key": "value"}', '[1, 2, 3]', 'true', 'null'];
      const result = serializeArray(input);

      expect(result).toEqual(input);
    });

    it('should handle arrays with newline and tab characters', () => {
      const input = ['line1\nline2', 'tab\there', 'mixed\n\tboth'];
      const result = serializeArray(input);

      expect(result).toEqual(input);
    });
  });

  describe('Performance Considerations', () => {
    it('should handle large arrays efficiently', () => {
      const largeArray = Array.from({ length: 100000 }, (_, i) => `item${i}`);

      const startTime = performance.now();
      const serialized = serializeArray(largeArray);
      const serializeTime = performance.now() - startTime;

      const deserializeStartTime = performance.now();
      const deserialized = deserializeArray(serialized);
      const deserializeTime = performance.now() - deserializeStartTime;

      expect(deserialized).toEqual(largeArray);
      expect(serializeTime).toBeLessThan(1000); // Should serialize in under 1 second
      expect(deserializeTime).toBeLessThan(1000); // Should deserialize in under 1 second
    });

    it('should handle many small arrays efficiently', () => {
      const arrays = Array.from({ length: 10000 }, (_, i) => [`item${i}-1`, `item${i}-2`, `item${i}-3`]);

      const startTime = performance.now();
      const results = arrays.map(array => serializeArray(array));
      const endTime = performance.now();

      expect(results).toHaveLength(10000);
      expect(endTime - startTime).toBeLessThan(1000); // Should process all arrays in under 1 second
    });

    it('should not create memory leaks during serialization', () => {
      const initialMemory = process.memoryUsage().heapUsed;

      // Perform many serializations
      for (let i = 0; i < 1000; i++) {
        const array = [`item${i}-1`, `item${i}-2`, `item${i}-3`];
        serializeArray(array);
      }

      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }

      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = finalMemory - initialMemory;

      // Memory increase should be reasonable (less than 10MB)
      expect(memoryIncrease).toBeLessThan(10 * 1024 * 1024);
    });
  });

  describe('Integration Scenarios', () => {
    it('should handle real-world database tag scenarios', () => {
      const tags = [
        'javascript',
        'node.js',
        "O'Reilly",
        'C++',
        'C#',
        'data\\analysis',
        "user's guide",
        'API/v2',
        'test-case-1',
        'bug#123',
      ];

      const serialized = serializeArray(tags);
      const deserialized = deserializeArray(serialized);

      expect(deserialized).toEqual(tags);
    });

    it('should handle configuration array scenarios', () => {
      const config = [
        'localhost:5432',
        'user="admin"',
        'password=\'secret\'',
        'database="my_app"',
        'sslmode=require',
        'timeout=30',
      ];

      const serialized = serializeArray(config);
      const deserialized = deserializeArray(serialized);

      expect(deserialized).toEqual(config);
    });

    it('should handle user input array scenarios', () => {
      const userInput = [
        "John's feedback",
        'Issue #123: Cannot\\connect',
        'Status: "resolved"',
        "User's email: test@example.com",
        'Path: C:\\Users\\Documents',
        'Note: "This is important"',
      ];

      const serialized = serializeArray(userInput);
      const deserialized = deserializeArray(serialized);

      expect(deserialized).toEqual(userInput);
    });

    it('should handle logging and metadata scenarios', () => {
      const logEntries = [
        '2025-01-01T12:00:00Z',
        '[ERROR] Database\\connection\\failed',
        "User 'admin' logged in",
        'Request: GET /api/users?page=1&limit=10',
        'Response: {"status": "success", "count": 50}',
        'Duration: 125ms',
      ];

      const serialized = serializeArray(logEntries);
      const deserialized = deserializeArray(serialized);

      expect(deserialized).toEqual(logEntries);
    });
  });

  describe('Compatibility and Standards', () => {
    it('should be compatible with PostgreSQL array format expectations', () => {
      // Test that the format matches what PostgreSQL expects
      const testArray = ['item1', "item'with'quotes", 'item\\with\\backslashes'];
      const serialized = serializeArray(testArray);

      // PostgreSQL arrays should be properly escaped
      expect(serialized).toEqual(['item1', "item''with''quotes", 'item\\\\with\\\\backslashes']);
    });

    it('should handle PostgreSQL array literals correctly', () => {
      // Simulate what PostgreSQL might return
      const pgArray = ['item1', "item''with''quotes", 'item\\with\\backslashes'];
      const result = deserializeArray(pgArray);

      expect(result).toEqual(['item1', "item'with'quotes", 'item\\with\\backslashes']);
    });

    it('should maintain compatibility with JSON serialization', () => {
      const testArray = ['item1', 'item2', 'item3'];

      const serialized = serializeForDatabase(testArray);
      const jsonString = JSON.stringify(serialized);
      const parsed = JSON.parse(jsonString);
      const deserialized = deserializeFromDatabase(parsed);

      expect(deserialized).toEqual(testArray);
    });
  });
});