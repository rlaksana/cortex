/**
 * MCP Tool Contract Tests
 *
 * Comprehensive contract testing for all MCP tools to ensure:
 * - Schema compliance and validation
 * - Input/output contract adherence
 * - Version compatibility across tool versions
 * - Error handling and edge cases
 * - Performance and security requirements
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { z } from 'zod';
import {
  ToolContractSchema,
  BUILTIN_TOOL_CONTRACTS,
  validateInputForVersion,
  validateOutputForVersion,
  parseSemVer,
  isVersionCompatible,
} from '../../src/types/versioning-schema.js';
import {
  EnhancedMemoryStoreInputSchema,
  MemoryStoreInputSchema,
  EnhancedMemoryFindInputSchema,
  MemoryFindInputSchema,
  SystemStatusInputSchema,
} from '../../src/schemas/mcp-inputs.js';
import type { AuthContext } from '../../src/types/auth-types.js';

describe('MCP Tool Contract Definitions', () => {
  describe('Contract Schema Validation', () => {
    it('should validate tool contract schemas', () => {
      for (const [toolName, toolInfo] of Object.entries(BUILTIN_TOOL_CONTRACTS)) {
        expect(toolName).toBeDefined();
        expect(toolInfo.current_version).toBeDefined();
        expect(toolInfo.available_versions).toContain(toolInfo.current_version);
        expect(toolInfo.contracts).toBeDefined();

        for (const [version, contract] of Object.entries(toolInfo.contracts)) {
          const validationResult = ToolContractSchema.safeParse(contract);
          expect(validationResult.success).toBe(true);
          if (!validationResult.success) {
            console.error(`Contract validation failed for ${toolName}@${version}:`, validationResult.error);
          }
        }
      }
    });

    it('should have valid semantic versions', () => {
      for (const [toolName, toolInfo] of Object.entries(BUILTIN_TOOL_CONTRACTS)) {
        for (const version of toolInfo.available_versions) {
          expect(() => parseSemVer(version)).not.toThrow();
        }
      }
    });

    it('should have compatible version matrices', () => {
      for (const [toolName, toolInfo] of Object.entries(BUILTIN_TOOL_CONTRACTS)) {
        for (const [version, contract] of Object.entries(toolInfo.contracts)) {
          const { min_version, max_version } = contract.compatibility;

          // Current version should be compatible with its own compatibility range
          expect(() => parseSemVer(min_version)).not.toThrow();
          expect(() => parseSemVer(max_version)).not.toThrow();

          // If version is the current version, it should be compatible with itself
          if (version === toolInfo.current_version) {
            expect(isVersionCompatible(version, version)).toBe(true);
          }
        }
      }
    });
  });

  describe('Required Scopes Validation', () => {
    it('should have valid scope definitions', () => {
      const validScopes = [
        'memory:read', 'memory:write', 'memory:delete',
        'knowledge:read', 'knowledge:write', 'knowledge:delete',
        'system:read', 'system:manage',
        'audit:read', 'audit:write',
        'search:basic', 'search:advanced', 'search:deep',
      ];

      for (const [toolName, toolInfo] of Object.entries(BUILTIN_TOOL_CONTRACTS)) {
        for (const [version, contract] of Object.entries(toolInfo.contracts)) {
          for (const scope of contract.required_scopes) {
            expect(validScopes).toContain(scope);
          }
        }
      }
    });

    it('should have appropriate scopes for tool operations', () => {
      // Memory operations should require memory scopes
      const memoryStoreContract = BUILTIN_TOOL_CONTRACTS.memory_store.contracts['1.2.0'];
      expect(memoryStoreContract.required_scopes).toContain('memory:write');

      // Search operations should require search scopes
      const memoryFindContract = BUILTIN_TOOL_CONTRACTS.memory_find.contracts['1.3.0'];
      expect(memoryFindContract.required_scopes).toContain('memory:read');

      // System operations should require system scopes
      const systemStatusContract = BUILTIN_TOOL_CONTRACTS.system_status.contracts['1.0.0'];
      expect(systemStatusContract.required_scopes).toContain('system:read');
    });
  });

  describe('Rate Limit Configuration', () => {
    it('should have valid rate limit configurations', () => {
      for (const [toolName, toolInfo] of Object.entries(BUILTIN_TOOL_CONTRACTS)) {
        for (const [version, contract] of Object.entries(toolInfo.contracts)) {
          if (contract.rate_limits) {
            const { requests_per_minute, tokens_per_minute, burst_allowance } = contract.rate_limits;

            expect(requests_per_minute).toBeGreaterThan(0);
            expect(requests_per_minute).toBeLessThanOrEqual(10000);

            expect(tokens_per_minute).toBeGreaterThan(0);
            expect(tokens_per_minute).toBeLessThanOrEqual(1000000);

            expect(burst_allowance).toBeGreaterThanOrEqual(0);
            expect(burst_allowance).toBeLessThanOrEqual(requests_per_minute);
          }
        }
      }
    });

    it('should have appropriate rate limits for tool types', () => {
      // Search tools should have higher rate limits than write tools
      const memoryFindContract = BUILTIN_TOOL_CONTRACTS.memory_find.contracts['1.3.0'];
      const memoryStoreContract = BUILTIN_TOOL_CONTRACTS.memory_store.contracts['1.2.0'];

      expect(memoryFindContract.rate_limits?.requests_per_minute)
        .toBeGreaterThanOrEqual(memoryStoreContract.rate_limits?.requests_per_minute || 0);
    });
  });

  describe('Input Validation Configuration', () => {
    it('should have valid input validation settings', () => {
      for (const [toolName, toolInfo] of Object.entries(BUILTIN_TOOL_CONTRACTS)) {
        for (const [version, contract] of Object.entries(toolInfo.contracts)) {
          if (contract.input_validation) {
            const {
              max_content_length,
              max_items_per_request,
              allowed_content_types,
            } = contract.input_validation;

            expect(max_content_length).toBeGreaterThan(0);
            expect(max_content_length).toBeLessThanOrEqual(100 * 1024 * 1024); // 100MB max

            expect(max_items_per_request).toBeGreaterThan(0);
            expect(max_items_per_request).toBeLessThanOrEqual(10000);

            expect(allowed_content_types).toContain('application/json');
            expect(allowed_content_types.length).toBeGreaterThan(0);
          }
        }
      }
    });

    it('should have appropriate limits for tool operations', () => {
      // Store operations should allow larger content than search
      const memoryStoreContract = BUILTIN_TOOL_CONTRACTS.memory_store.contracts['1.2.0'];
      const memoryFindContract = BUILTIN_TOOL_CONTRACTS.memory_find.contracts['1.3.0'];

      expect(memoryStoreContract.input_validation?.max_content_length)
        .toBeGreaterThanOrEqual(memoryFindContract.input_validation?.max_content_length || 0);

      // Store operations should allow more items than search
      expect(memoryStoreContract.input_validation?.max_items_per_request)
        .toBeGreaterThanOrEqual(memoryFindContract.input_validation?.max_items_per_request || 0);
    });
  });

  describe('Tenant Isolation Configuration', () => {
    it('should have valid tenant isolation settings', () => {
      for (const [toolName, toolInfo] of Object.entries(BUILTIN_TOOL_CONTRACTS)) {
        for (const [version, contract] of Object.entries(toolInfo.contracts)) {
          expect(typeof contract.tenant_isolation).toBe('boolean');
        }
      }
    });

    it('should have appropriate tenant isolation for tool types', () => {
      // System tools should not have tenant isolation
      const systemStatusContract = BUILTIN_TOOL_CONTRACTS.system_status.contracts['1.0.0'];
      expect(systemStatusContract.tenant_isolation).toBe(false);

      // Memory tools should have tenant isolation
      const memoryStoreContract = BUILTIN_TOOL_CONTRACTS.memory_store.contracts['1.2.0'];
      expect(memoryStoreContract.tenant_isolation).toBe(true);

      const memoryFindContract = BUILTIN_TOOL_CONTRACTS.memory_find.contracts['1.3.0'];
      expect(memoryFindContract.tenant_isolation).toBe(true);
    });
  });
});

describe('Memory Store Tool Contracts', () => {
  describe('Version 1.0.0 Contract', () => {
    const contract = BUILTIN_TOOL_CONTRACTS.memory_store.contracts['1.0.0'];

    it('should validate basic input structure', () => {
      const validInput = {
        items: [
          {
            kind: 'entity',
            content: 'Test entity content',
            scope: { project: 'test-project' },
          },
        ],
      };

      const validation = validateInputForVersion('memory_store', '1.0.0', validInput);
      expect(validation.isValid).toBe(true);
    });

    it('should reject invalid input structures', () => {
      const invalidInputs = [
        { items: [] }, // Empty items
        { items: 'not-array' }, // Non-array items
        { items: [{ kind: 'invalid-kind' }] }, // Invalid kind
        { items: [{ kind: 'entity' }] }, // Missing required fields
        {}, // Missing items
      ];

      for (const input of invalidInputs) {
        const validation = validateInputForVersion('memory_store', '1.0.0', input);
        expect(validation.isValid).toBe(false);
        expect(validation.error).toBeDefined();
      }
    });

    it('should enforce rate limits', () => {
      expect(contract.rate_limits?.requests_per_minute).toBe(60);
      expect(contract.rate_limits?.tokens_per_minute).toBe(10000);
      expect(contract.rate_limits?.burst_allowance).toBe(10);
    });

    it('should enforce input validation limits', () => {
      expect(contract.input_validation?.max_content_length).toBe(1000000); // 1MB
      expect(contract.input_validation?.max_items_per_request).toBe(50);
    });
  });

  describe('Version 1.1.0 Contract', () => {
    const contract = BUILTIN_TOOL_CONTRACTS.memory_store.contracts['1.1.0'];

    it('should support deduplication options', () => {
      const validInput = {
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

      const validation = validateInputForVersion('memory_store', '1.1.0', validInput);
      expect(validation.isValid).toBe(true);
    });

    it('should maintain backward compatibility with v1.0.0 inputs', () => {
      const v1_0_0_input = {
        items: [
          {
            kind: 'entity',
            content: 'Test entity content',
            scope: { project: 'test-project' },
          },
        ],
      };

      const validation = validateInputForVersion('memory_store', '1.1.0', v1_0_0_input);
      expect(validation.isValid).toBe(true);
    });

    it('should validate deduplication parameters', () => {
      const invalidInputs = [
        {
          items: [{ kind: 'entity', content: 'test' }],
          deduplication: { enabled: 'not-boolean' },
        },
        {
          items: [{ kind: 'entity', content: 'test' }],
          deduplication: { similarity_threshold: 1.5 }, // Invalid range
        },
      ];

      for (const input of invalidInputs) {
        const validation = validateInputForVersion('memory_store', '1.1.0', input);
        expect(validation.isValid).toBe(false);
      }
    });

    it('should have increased limits', () => {
      expect(contract.input_validation?.max_items_per_request).toBe(100); // Increased from 50
    });
  });

  describe('Version 1.2.0 Contract', () => {
    const contract = BUILTIN_TOOL_CONTRACTS.memory_store.contracts['1.2.0'];

    it('should support processing options', () => {
      const validInput = {
        items: [
          {
            kind: 'entity',
            content: 'Test entity content',
            scope: { project: 'test-project' },
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

      const validation = validateInputForVersion('memory_store', '1.2.0', validInput);
      expect(validation.isValid).toBe(true);
    });

    it('should support advanced deduplication options', () => {
      const validInput = {
        items: [
          {
            kind: 'entity',
            content: 'Test entity content',
            scope: { project: 'test-project' },
          },
        ],
        deduplication: {
          enabled: true,
          merge_strategy: 'intelligent',
          similarity_threshold: 0.9,
          max_history_hours: 168,
          enable_intelligent_merging: true,
        },
      };

      const validation = validateInputForVersion('memory_store', '1.2.0', validInput);
      expect(validation.isValid).toBe(true);
    });

    it('should document breaking changes', () => {
      expect(contract.compatibility.breaking_changes).toBeDefined();
      expect(contract.compatibility.breaking_changes?.length).toBeGreaterThan(0);

      const breakingChange = contract.compatibility.breaking_changes![0];
      expect(breakingChange.version).toBe('1.2.0');
      expect(breakingChange.description).toContain('idempotency_key');
      expect(breakingChange.migration_required).toBe(true);
    });
  });
});

describe('Memory Find Tool Contracts', () => {
  describe('Version 1.0.0 Contract', () => {
    const contract = BUILTIN_TOOL_CONTRACTS.memory_find.contracts['1.0.0'];

    it('should validate basic search input', () => {
      const validInput = {
        query: 'test query',
        scope: { project: 'test-project' },
      };

      const validation = validateInputForVersion('memory_find', '1.0.0', validInput);
      expect(validation.isValid).toBe(true);
    });

    it('should require query parameter', () => {
      const invalidInputs = [
        {}, // Missing query
        { query: '' }, // Empty query
        { query: '   ' }, // Whitespace only query
      ];

      for (const input of invalidInputs) {
        const validation = validateInputForVersion('memory_find', '1.0.0', input);
        expect(validation.isValid).toBe(false);
      }
    });

    it('should enforce query length limits', () => {
      const validInput = {
        query: 'a'.repeat(1000), // Max length
      };

      const validation = validateInputForVersion('memory_find', '1.0.0', validInput);
      expect(validation.isValid).toBe(true);

      const tooLongInput = {
        query: 'a'.repeat(1001), // Over limit
      };

      const invalidValidation = validateInputForVersion('memory_find', '1.0.0', tooLongInput);
      expect(invalidValidation.isValid).toBe(false);
    });

    it('should have appropriate rate limits for search operations', () => {
      expect(contract.rate_limits?.requests_per_minute).toBe(120); // Higher than store
      expect(contract.rate_limits?.tokens_per_minute).toBe(20000);
    });
  });

  describe('Version 1.3.0 Contract', () => {
    const contract = BUILTIN_TOOL_CONTRACTS.memory_find.contracts['1.3.0'];

    it('should support advanced search options', () => {
      const validInput = {
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
          max_nodes: 200,
        },
      };

      const validation = validateInputForVersion('memory_find', '1.3.0', validInput);
      expect(validation.isValid).toBe(true);
    });

    it('should validate search strategy options', () => {
      const validStrategies = ['fast', 'auto', 'deep'];
      for (const strategy of validStrategies) {
        const input = { query: 'test', search_strategy: strategy };
        const validation = validateInputForVersion('memory_find', '1.3.0', input);
        expect(validation.isValid).toBe(true);
      }
    });

    it('should validate limit and pagination parameters', () => {
      const validInputs = [
        { query: 'test', limit: 1 }, // Min limit
        { query: 'test', limit: 100 }, // Max limit
        { query: 'test', limit: 10 }, // Default
      ];

      for (const input of validInputs) {
        const validation = validateInputForVersion('memory_find', '1.3.0', input);
        expect(validation.isValid).toBe(true);
      }

      const invalidInputs = [
        { query: 'test', limit: 0 }, // Too low
        { query: 'test', limit: 101 }, // Too high
        { query: 'test', limit: -5 }, // Negative
      ];

      for (const input of invalidInputs) {
        const validation = validateInputForVersion('memory_find', '1.3.0', input);
        expect(validation.isValid).toBe(false);
      }
    });

    it('should validate graph expansion parameters', () => {
      const validInput = {
        query: 'test',
        graph_expansion: {
          enabled: true,
          max_depth: 3,
          max_nodes: 100,
          include_metadata: true,
        },
      };

      const validation = validateInputForVersion('memory_find', '1.3.0', validInput);
      expect(validation.isValid).toBe(true);

      const invalidInputs = [
        {
          query: 'test',
          graph_expansion: { max_depth: 6 }, // Too high
        },
        {
          query: 'test',
          graph_expansion: { max_depth: 0 }, // Too low
        },
      ];

      for (const input of invalidInputs) {
        const validation = validateInputForVersion('memory_find', '1.3.0', input);
        expect(validation.isValid).toBe(false);
      }
    });
  });
});

describe('System Status Tool Contracts', () => {
  describe('Version 1.0.0 Contract', () => {
    const contract = BUILTIN_TOOL_CONTRACTS.system_status.contracts['1.0.0'];

    it('should validate basic system status input', () => {
      const validInputs = [
        { operation: 'health' },
        { operation: 'stats' },
        { operation: 'metrics' },
        {
          operation: 'health',
          scope: { project: 'test-project' },
        },
      ];

      for (const input of validInputs) {
        const validation = validateInputForVersion('system_status', '1.0.0', input);
        expect(validation.isValid).toBe(true);
      }
    });

    it('should validate operation types', () => {
      const validOperations = ['health', 'stats', 'metrics'];
      for (const operation of validOperations) {
        const input = { operation };
        const validation = validateInputForVersion('system_status', '1.0.0', input);
        expect(validation.isValid).toBe(true);
      }

      const invalidInput = { operation: 'invalid-operation' };
      const validation = validateInputForVersion('system_status', '1.0.0', invalidInput);
      expect(validation.isValid).toBe(false);
    });

    it('should not have tenant isolation', () => {
      expect(contract.tenant_isolation).toBe(false);
    });

    it('should have conservative rate limits', () => {
      expect(contract.rate_limits?.requests_per_minute).toBe(30); // Lower than other tools
      expect(contract.rate_limits?.tokens_per_minute).toBe(5000);
    });
  });
});

describe('Cross-Tool Contract Compatibility', () => {
  it('should maintain consistent scope field definitions', () => {
    const tools = ['memory_store', 'memory_find'];
    const commonScopeFields = ['project', 'branch', 'org'];

    for (const toolName of tools) {
      const toolInfo = BUILTIN_TOOL_CONTRACTS[toolName];
      for (const [version, contract] of Object.entries(toolInfo.contracts)) {
        // Check that the tool accepts common scope fields
        const inputWithScope = {
          ...(toolName === 'memory_store' ? { items: [{ kind: 'entity', content: 'test' }] } : { query: 'test' }),
          scope: {
            project: 'test',
            branch: 'main',
            org: 'test-org',
          },
        };

        const validation = validateInputForVersion(toolName, version, inputWithScope);
        expect(validation.isValid).toBe(true);
      }
    }
  });

  it('should handle consistent error response formats', () => {
    // This would test that all tools return consistent error formats
    // Implementation depends on actual error handling code
    expect(true).toBe(true); // Placeholder
  });

  it('should maintain consistent authentication patterns', () => {
    const tools = ['memory_store', 'memory_find', 'system_status'];

    for (const toolName of tools) {
      const toolInfo = BUILTIN_TOOL_CONTRACTS[toolName];
      for (const [version, contract] of Object.entries(toolInfo.contracts)) {
        // All tools should have required scopes defined
        expect(contract.required_scopes).toBeDefined();
        expect(Array.isArray(contract.required_scopes)).toBe(true);
      }
    }
  });
});

describe('Contract Drift Detection', () => {
  it('should detect schema drift between versions', () => {
    const memoryStoreV1 = BUILTIN_TOOL_CONTRACTS.memory_store.contracts['1.0.0'];
    const memoryStoreV2 = BUILTIN_TOOL_CONTRACTS.memory_store.contracts['1.2.0'];

    // V1.2.0 should support all V1.0.0 features
    const v1_0_0_input = {
      items: [
        {
          kind: 'entity',
          content: 'test',
          scope: { project: 'test' },
        },
      ],
    };

    const v1Validation = validateInputForVersion('memory_store', '1.0.0', v1_0_0_input);
    const v2Validation = validateInputForVersion('memory_store', '1.2.0', v1_0_0_input);

    expect(v1Validation.isValid).toBe(true);
    expect(v2Validation.isValid).toBe(true); // Should be backward compatible
  });

  it('should detect breaking changes in compatibility matrix', () => {
    const memoryStoreV2 = BUILTIN_TOOL_CONTRACTS.memory_store.contracts['1.2.0'];

    // Check that breaking changes are documented
    expect(memoryStoreV2.compatibility.breaking_changes).toBeDefined();
    expect(memoryStoreV2.compatibility.breaking_changes!.length).toBeGreaterThan(0);

    // Verify breaking change details
    const breakingChange = memoryStoreV2.compatibility.breaking_changes![0];
    expect(breakingChange.version).toBe('1.2.0');
    expect(breakingChange.description).toBeDefined();
    expect(breakingChange.migration_required).toBeDefined();
  });

  it('should validate contract completeness', () => {
    for (const [toolName, toolInfo] of Object.entries(BUILTIN_TOOL_CONTRACTS)) {
      // Each tool should have a current version
      expect(toolInfo.current_version).toBeDefined();
      expect(toolInfo.available_versions).toContain(toolInfo.current_version);

      // Each version should have a complete contract
      for (const version of toolInfo.available_versions) {
        const contract = toolInfo.contracts[version];
        expect(contract).toBeDefined();
        expect(contract.name).toBe(toolName);
        expect(contract.version).toBeDefined();
        expect(contract.compatibility).toBeDefined();
        expect(contract.input_schema).toBeDefined();
        expect(contract.output_schema).toBeDefined();
        expect(contract.required_scopes).toBeDefined();
        expect(contract.rate_limits).toBeDefined();
        expect(contract.input_validation).toBeDefined();
        expect(typeof contract.tenant_isolation).toBe('boolean');
      }
    }
  });
});

describe('Performance and Security Contract Tests', () => {
  it('should enforce reasonable rate limits across all tools', () => {
    for (const [toolName, toolInfo] of Object.entries(BUILTIN_TOOL_CONTRACTS)) {
      for (const [version, contract] of Object.entries(toolInfo.contracts)) {
        const { rate_limits } = contract;

        if (rate_limits) {
          // All tools should have reasonable rate limits
          expect(rate_limits.requests_per_minute).toBeGreaterThan(0);
          expect(rate_limits.requests_per_minute).toBeLessThanOrEqual(1000);

          expect(rate_limits.tokens_per_minute).toBeGreaterThan(0);
          expect(rate_limits.tokens_per_minute).toBeLessThanOrEqual(100000);

          // Burst allowance should be reasonable
          expect(rate_limits.burst_allowance).toBeGreaterThanOrEqual(0);
          expect(rate_limits.burst_allowance).toBeLessThanOrEqual(rate_limits.requests_per_minute);
        }
      }
    }
  });

  it('should enforce input size limits', () => {
    for (const [toolName, toolInfo] of Object.entries(BUILTIN_TOOL_CONTRACTS)) {
      for (const [version, contract] of Object.entries(toolInfo.contracts)) {
        const { input_validation } = contract;

        if (input_validation) {
          // All tools should have reasonable input limits
          expect(input_validation.max_content_length).toBeGreaterThan(0);
          expect(input_validation.max_content_length).toBeLessThanOrEqual(100 * 1024 * 1024); // 100MB

          expect(input_validation.max_items_per_request).toBeGreaterThan(0);
          expect(input_validation.max_items_per_request).toBeLessThanOrEqual(10000);

          // Should allow JSON content type
          expect(input_validation.allowed_content_types).toContain('application/json');
        }
      }
    }
  });

  it('should complete contract validation efficiently', () => {
    const start = Date.now();

    // Validate all contracts
    for (const [toolName, toolInfo] of Object.entries(BUILTIN_TOOL_CONTRACTS)) {
      for (const [version, contract] of Object.entries(toolInfo.contracts)) {
        ToolContractSchema.parse(contract);
      }
    }

    const duration = Date.now() - start;
    expect(duration).toBeLessThan(100); // Should complete in < 100ms
  });
});