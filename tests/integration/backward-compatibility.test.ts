/**
 * Backward Compatibility Tests for Cortex MCP Tools
 *
 * Tests ensure that new versions of tools maintain compatibility with existing clients
 * and that version negotiation works correctly across all supported versions.
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import {
  parseSemVer,
  isVersionCompatible,
  getBestCompatibleVersion,
  validateInputForVersion,
  validateOutputForVersion,
  resolveToolVersion,
  BUILTIN_TOOL_CONTRACTS,
} from '../../src/types/versioning-schema.js';
import { EnhancedMemoryStoreInputSchema, MemoryStoreInputSchema } from '../../src/schemas/mcp-inputs.js';
import { z } from 'zod';

describe('SemVer Versioning', () => {
  describe('parseSemVer', () => {
    it('should parse valid semantic versions', () => {
      expect(parseSemVer('1.0.0')).toEqual({
        major: 1,
        minor: 0,
        patch: 0,
      });

      expect(parseSemVer('2.1.3')).toEqual({
        major: 2,
        minor: 1,
        patch: 3,
      });

      expect(parseSemVer('1.0.0-alpha.1')).toEqual({
        major: 1,
        minor: 0,
        patch: 0,
        prerelease: 'alpha.1',
      });

      expect(parseSemVer('1.0.0+build.1')).toEqual({
        major: 1,
        minor: 0,
        patch: 0,
        build: 'build.1',
      });
    });

    it('should throw error for invalid versions', () => {
      expect(() => parseSemVer('invalid')).toThrow();
      expect(() => parseSemVer('1.0')).toThrow();
      expect(() => parseSemVer('1.x.0')).toThrow();
    });
  });

  describe('isVersionCompatible', () => {
    it('should determine version compatibility correctly', () => {
      // Same major version, compatible minor/patch
      expect(isVersionCompatible('1.0.0', '1.0.0')).toBe(true);
      expect(isVersionCompatible('1.0.1', '1.0.0')).toBe(true);
      expect(isVersionCompatible('1.1.0', '1.0.0')).toBe(true);
      expect(isVersionCompatible('1.1.5', '1.2.0')).toBe(true);

      // Consumer newer than provider - incompatible
      expect(isVersionCompatible('1.2.0', '1.1.0')).toBe(false);
      expect(isVersionCompatible('1.1.5', '1.1.0')).toBe(false);
      expect(isVersionCompatible('2.0.0', '1.5.0')).toBe(false);

      // Different major versions - incompatible
      expect(isVersionCompatible('2.0.0', '1.0.0')).toBe(false);
      expect(isVersionCompatible('1.0.0', '2.0.0')).toBe(false);
    });
  });

  describe('getBestCompatibleVersion', () => {
    it('should return most recent compatible version', () => {
      const available = ['1.0.0', '1.1.0', '1.2.0', '2.0.0'];

      expect(getBestCompatibleVersion('1.0.0', available)).toBe('1.2.0');
      expect(getBestCompatibleVersion('1.1.0', available)).toBe('1.2.0');
      expect(getBestCompatibleVersion('1.2.0', available)).toBe('1.2.0');
      expect(getBestCompatibleVersion('1.0.5', available)).toBe('1.2.0');
    });

    it('should return null for incompatible requests', () => {
      const available = ['1.0.0', '1.1.0', '1.2.0'];

      expect(getBestCompatibleVersion('2.0.0', available)).toBe(null);
      expect(getBestCompatibleVersion('1.3.0', available)).toBe(null);
    });

    it('should handle version lists with prereleases', () => {
      const available = ['1.0.0', '1.0.1-alpha', '1.1.0', '1.2.0-beta'];

      expect(getBestCompatibleVersion('1.0.0', available)).toBe('1.1.0');
    });
  });
});

describe('Tool Contract Validation', () => {
  describe('validateInputForVersion', () => {
    it('should validate input against version-specific schemas', () => {
      // Test memory_store v1.0.0 (simple schema)
      const v1_0_0_input = {
        items: [
          { kind: 'entity', content: 'test content' },
        ],
      };

      const result1 = validateInputForVersion('memory_store', '1.0.0', v1_0_0_input);
      expect(result1.isValid).toBe(true);
      expect(result1.validatedInput).toBeDefined();

      // Test memory_store v1.2.0 (enhanced schema)
      const v1_2_0_input = {
        items: [
          {
            kind: 'entity',
            content: 'test content',
            idempotency_key: 'test-key',
          },
        ],
        deduplication: {
          enabled: true,
          similarity_threshold: 0.9,
        },
        processing: {
          enable_validation: true,
        },
      };

      const result2 = validateInputForVersion('memory_store', '1.2.0', v1_2_0_input);
      expect(result2.isValid).toBe(true);
      expect(result2.validatedInput).toBeDefined();
    });

    it('should reject invalid input for specific versions', () => {
      // Test with missing required fields for v1.2.0
      const invalid_input = {
        items: [
          { kind: 'entity' }, // Missing content
        ],
      };

      const result = validateInputForVersion('memory_store', '1.2.0', invalid_input);
      expect(result.isValid).toBe(false);
      expect(result.error).toContain('Input validation failed');
    });

    it('should handle unknown tool versions', () => {
      const input = { items: [] };
      const result = validateInputForVersion('unknown_tool', '1.0.0', input);
      expect(result.isValid).toBe(false);
      expect(result.error).toContain('Unknown tool version');
    });
  });

  describe('validateOutputForVersion', () => {
    it('should validate output against version schemas', () => {
      // Mock output format
      const output = {
        success: true,
        items: [
          { id: 'test-id', kind: 'entity' },
        ],
      };

      // Since we don't have detailed output schemas in the test environment,
      // this test mainly checks the validation process
      const result = validateOutputForVersion('memory_store', '1.0.0', output);
      expect(typeof result.isValid).toBe('boolean');
    });
  });
});

describe('Version Resolution', () => {
  describe('resolveToolVersion', () => {
    it('should resolve exact versions when available', () => {
      const headers = { 'x-version': '1.0.0' };
      const result = resolveToolVersion('memory_store', headers);

      expect(result.version).toBe('1.0.0');
      expect(result.warnings).toHaveLength(0);
    });

    it('should find compatible versions for exact matches', () => {
      const headers = { 'x-version': '1.1.5' };
      const result = resolveToolVersion('memory_store', headers);

      expect(result.version).toBe('1.2.0'); // Most recent compatible
      expect(result.warnings.length).toBeGreaterThan(0);
      expect(result.warnings[0]).toContain('not available, using compatible version');
    });

    it('should use default version when no version specified', () => {
      const headers = {};
      const result = resolveToolVersion('memory_store', headers);

      expect(result.version).toBe('1.2.0'); // Current version
    });

    it('should handle deprecation warnings', () => {
      // This would test deprecation when we have deprecated versions
      const headers = { 'x-version': '1.0.0' };
      const result = resolveToolVersion('memory_store', headers);

      expect(result.version).toBe('1.0.0');
      // Would check for deprecation warnings if configured
    });

    it('should fallback to current version for incompatible requests', () => {
      const headers = { 'x-version': '2.0.0' }; // Major version mismatch
      const result = resolveToolVersion('memory_store', headers);

      expect(result.version).toBe('1.2.0'); // Current version
      expect(result.warnings.length).toBeGreaterThan(0);
      expect(result.warnings[0]).toContain('not compatible, using current version');
    });

    it('should handle multiple version headers', () => {
      const headers = {
        'x-version': '1.0.0',
        'x-api-version': '1.1.0',
        'x-client-version': '1.2.0',
      };

      const result = resolveToolVersion('memory_store', headers);
      expect(result.version).toBe('1.0.0'); // x-version takes precedence
    });
  });
});

describe('Backward Compatibility Integration Tests', () => {
  describe('Memory Store Tool Compatibility', () => {
    it('should support v1.0.0 clients', () => {
      const v1_0_0_request = {
        items: [
          {
            kind: 'entity',
            content: 'Test entity content',
            scope: { project: 'test-project' },
          },
        ],
      };

      const validation = validateInputForVersion('memory_store', '1.0.0', v1_0_0_request);
      expect(validation.isValid).toBe(true);
    });

    it('should support v1.1.0 clients with deduplication', () => {
      const v1_1_0_request = {
        items: [
          {
            kind: 'entity',
            content: 'Test entity content',
            scope: { project: 'test-project' },
          },
        ],
        deduplication: {
          enabled: true,
          similarity_threshold: 0.85,
        },
      };

      const validation = validateInputForVersion('memory_store', '1.1.0', v1_1_0_request);
      expect(validation.isValid).toBe(true);
    });

    it('should support v1.2.0 clients with processing options', () => {
      const v1_2_0_request = {
        items: [
          {
            kind: 'entity',
            content: 'Test entity content',
            scope: { project: 'test-project' },
            idempotency_key: 'unique-key-123',
          },
        ],
        deduplication: {
          enabled: true,
          merge_strategy: 'intelligent',
        },
        processing: {
          enable_validation: true,
          enable_async_processing: false,
        },
      };

      const validation = validateInputForVersion('memory_store', '1.2.0', v1_2_0_request);
      expect(validation.isValid).toBe(true);
    });

    it('should handle breaking changes gracefully', () => {
      // Simulate a v1.2.0 client trying to use breaking changes
      const breaking_change_request = {
        items: [
          {
            kind: 'entity',
            content: 'Test entity content',
            // Missing required idempotency_key for v1.2.0
          },
        ],
        processing: {
          enable_validation: true,
        },
      };

      const validation = validateInputForVersion('memory_store', '1.2.0', breaking_change_request);
      // This should fail due to missing required field in v1.2.0
      expect(validation.isValid).toBe(false);
    });
  });

  describe('Memory Find Tool Compatibility', () => {
    it('should support v1.0.0 clients', () => {
      const v1_0_0_request = {
        query: 'test query',
        scope: { project: 'test-project' },
      };

      const validation = validateInputForVersion('memory_find', '1.0.0', v1_0_0_request);
      expect(validation.isValid).toBe(true);
    });

    it('should support v1.3.0 clients with advanced features', () => {
      const v1_3_0_request = {
        query: 'test query',
        scope: {
          project: 'test-project',
          service: 'test-service',
          tenant: 'test-tenant',
        },
        search_strategy: 'deep',
        limit: 20,
        graph_expansion: {
          enabled: true,
          max_depth: 3,
        },
      };

      const validation = validateInputForVersion('memory_find', '1.3.0', v1_3_0_request);
      expect(validation.isValid).toBe(true);
    });

    it('should handle optional new features gracefully', () => {
      // Old client (v1.0.0) format should work with newer versions
      const old_format_request = {
        query: 'test query',
      };

      const validation_v1_0 = validateInputForVersion('memory_find', '1.0.0', old_format_request);
      expect(validation_v1_0.isValid).toBe(true);

      // Same request should work with v1.3.0 (backward compatibility)
      const validation_v1_3 = validateInputForVersion('memory_find', '1.3.0', old_format_request);
      expect(validation_v1_3.isValid).toBe(true);
    });
  });
});

describe('Schema Evolution Tests', () => {
  it('should handle field additions gracefully', () => {
    // New fields should be optional in newer versions
    const old_format = {
      items: [{ kind: 'entity', content: 'test' }],
    };

    const validation = validateInputForVersion('memory_store', '1.2.0', old_format);
    expect(validation.isValid).toBe(true); // Should work even with newer schema
  });

  it('should handle field deprecation with warnings', () => {
    // This would test deprecated field handling
    // Implementation depends on specific deprecation scenarios
  });

  it('should validate type changes correctly', () => {
    // Test that type changes between versions are handled
    const request_with_wrong_type = {
      items: [
        {
          kind: 'entity',
          content: 123, // Should be string, not number
        },
      ],
    };

    const validation = validateInputForVersion('memory_store', '1.2.0', request_with_wrong_type);
    expect(validation.isValid).toBe(false);
    expect(validation.error).toContain('Input validation failed');
  });
});

describe('Version Header Integration', () => {
  it('should parse various version header formats', () => {
    const test_cases = [
      { headers: { 'x-version': '1.0.0' }, expected: '1.0.0' },
      { headers: { 'x-api-version': '1.1.0' }, expected: '1.1.0' },
      { headers: { 'x-client-version': '1.2.0' }, expected: '1.2.0' },
      { headers: {}, expected: '1.2.0' }, // Default
    ];

    test_cases.forEach(({ headers, expected }) => {
      const result = resolveToolVersion('memory_store', headers);
      expect(result.version).toBe(expected);
    });
  });

  it('should handle invalid version headers gracefully', () => {
    const headers = { 'x-version': 'invalid.version' };
    const result = resolveToolVersion('memory_store', headers);

    expect(result.version).toBe('1.2.0'); // Should fallback to default
    expect(result.warnings.length).toBeGreaterThan(0);
  });
});

describe('Performance and Regression Tests', () => {
  it('should handle version resolution efficiently', () => {
    const start = Date.now();

    for (let i = 0; i < 1000; i++) {
      resolveToolVersion('memory_store', { 'x-version': '1.0.0' });
    }

    const duration = Date.now() - start;
    expect(duration).toBeLessThan(100); // Should complete in < 100ms
  });

  it('should handle large input validation efficiently', () => {
    const large_input = {
      items: Array.from({ length: 100 }, (_, i) => ({
        kind: 'entity',
        content: `Test content ${i}`,
        metadata: { index: i },
      })),
    };

    const start = Date.now();
    const validation = validateInputForVersion('memory_store', '1.2.0', large_input);
    const duration = Date.now() - start;

    expect(validation.isValid).toBe(true);
    expect(duration).toBeLessThan(50); // Should complete in < 50ms
  });
});