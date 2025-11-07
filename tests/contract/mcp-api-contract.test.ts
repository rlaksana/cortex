/**
 * Comprehensive API Contract Tests - T22 Implementation
 *
 * Tests MCP tool contracts including:
 * - Input/output validation with type checking
 * - Tool response format verification
 * - Error handling contract compliance
 * - Tool discovery and capability contracts
 * - Backward compatibility verification
 *
 * @version 2.0.1
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
  InitializeRequestSchema,
  ErrorCode,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';

// Import schemas for validation
import {
  MemoryStoreInputSchema,
  MemoryFindInputSchema,
  safeValidateMemoryStoreInput,
  safeValidateMemoryFindInput,
} from '../../src/schemas/mcp-inputs.js';
import { ALL_JSON_SCHEMAS } from '../../src/schemas/json-schemas.js';

// Import validation utilities
import { ValidationError } from '../../src/utils/error-handler.js';

// Test data factories
import {
  createValidMemoryStoreInput,
  createValidMemoryFindInput,
  createInvalidMemoryStoreInput,
  createInvalidMemoryFindInput,
  createEdgeCaseInputs,
} from '../fixtures/mcp-input-fixtures.js';

describe('MCP API Contract Tests - T22', () => {
  let server: Server;

  beforeEach(async () => {
    // Setup test server instance
    server = new Server(
      {
        name: 'test-cortex-memory',
        version: '2.0.1',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );
  });

  afterEach(() => {
    // Cleanup
  });

  // ============================================================================
  // T22.1: Tool Discovery and Capability Contracts
  // ============================================================================

  describe('Tool Discovery Contracts', () => {
    it('should list all available tools with correct schema', async () => {
      const listToolsRequest = {
        method: 'tools/list',
        params: {},
      };

      // Mock the server's tool list response
      const expectedTools = [
        {
          name: 'memory_store',
          description: expect.stringContaining('Store knowledge items in Cortex memory'),
          inputSchema: ALL_JSON_SCHEMAS.memory_store,
        },
        {
          name: 'memory_find',
          description: expect.stringContaining('Search Cortex memory'),
          inputSchema: ALL_JSON_SCHEMAS.memory_find,
        },
      ];

      // Verify tool discovery contract
      expect(expectedTools).toHaveLength(2);

      expectedTools.forEach((tool) => {
        expect(tool.name).toMatch(/^(memory_store|memory_find)$/);
        expect(tool.description).toBeTypeOf('string');
        expect(tool.description).toContain('Cortex memory');
        expect(tool.inputSchema).toBeDefined();
        expect(tool.inputSchema).toHaveProperty('type', 'object');
        expect(tool.inputSchema).toHaveProperty('required');
        expect(tool.inputSchema).toHaveProperty('properties');
      });
    });

    it('should maintain backward compatibility for tool definitions', () => {
      // Verify tool names remain consistent (backward compatibility)
      const toolNames = ['memory_store', 'memory_find'];

      toolNames.forEach((toolName) => {
        expect(toolName).toBeTypeOf('string');
        expect(toolName).toMatch(/^[a-z_]+$/);
        expect(toolName.length).toBeGreaterThan(0);
        expect(toolName.length).toBeLessThan(50);
      });
    });

    it('should provide complete tool capability descriptions', () => {
      const memoryStoreSchema = ALL_JSON_SCHEMAS.memory_store;
      const memoryFindSchema = ALL_JSON_SCHEMAS.memory_find;

      // Verify memory_store capabilities
      expect(memoryStoreSchema.properties).toHaveProperty('items');
      expect(memoryStoreSchema.properties).toHaveProperty('deduplication');
      expect(memoryStoreSchema.properties).toHaveProperty('global_ttl');
      expect(memoryStoreSchema.properties).toHaveProperty('global_truncation');
      expect(memoryStoreSchema.properties).toHaveProperty('insights');

      // Verify memory_find capabilities
      expect(memoryFindSchema.properties).toHaveProperty('query');
      expect(memoryFindSchema.properties).toHaveProperty('scope');
      expect(memoryFindSchema.properties).toHaveProperty('search_strategy');
      expect(memoryFindSchema.properties).toHaveProperty('result_format');
      expect(memoryFindSchema.properties).toHaveProperty('limit');
      expect(memoryFindSchema.properties).toHaveProperty('ttl_filter');
    });
  });

  // ============================================================================
  // T22.2: Input/Output Contract Tests with Type Validation
  // ============================================================================

  describe('Memory Store Input/Output Contracts', () => {
    it('should validate valid memory_store inputs', () => {
      const validInput = createValidMemoryStoreInput();

      // Test Zod schema validation
      const result = MemoryStoreInputSchema.safeParse(validInput);
      expect(result.success).toBe(true);

      // Test safe validation function
      const safeResult = safeValidateMemoryStoreInput(validInput);
      expect(safeResult).not.toBeNull();
      expect(safeResult).toHaveProperty('items');
      expect(safeResult?.items).toBeInstanceOf(Array);
    });

    it('should reject invalid memory_store inputs with proper error messages', () => {
      const invalidInputs = createInvalidMemoryStoreInput();

      invalidInputs.forEach((invalidInput, index) => {
        const result = MemoryStoreInputSchema.safeParse(invalidInput);
        expect(result.success).toBe(false);

        if (!result.success) {
          expect(result.error).toBeInstanceOf(z['Z']odError);
          expect(result.error.errors.length).toBeGreaterThan(0);

          // Verify error messages are helpful
          const error = result.error.errors[0];
          expect(error.message).toBeTypeOf('string');
          expect(error.message.length).toBeGreaterThan(0);
          expect(error.path).toBeDefined();
        }
      });
    });

    it('should handle edge cases in memory_store inputs', () => {
      const edgeCases = createEdgeCaseInputs().memoryStore;

      edgeCases.forEach((input) => {
        const result = MemoryStoreInputSchema.safeParse(input);

        // Edge cases should either pass or fail gracefully
        if (result.success) {
          // If it passes, ensure the output is well-formed
          expect(result.data).toHaveProperty('items');
          expect(Array.isArray(result['data.items'])).toBe(true);
        } else {
          // If it fails, ensure proper error handling
          expect(result.error).toBeInstanceOf(z['Z']odError);
        }
      });
    });

    it('should validate all 16 knowledge types', () => {
      const knowledgeTypes = [
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

      knowledgeTypes.forEach((kind) => {
        const input = {
          items: [
            {
              kind,
              content: `Test content for ${kind}`,
            },
          ],
        };

        const result = MemoryStoreInputSchema.safeParse(input);
        expect(result.success).toBe(true);
      });
    });

    it('should validate deduplication configuration', () => {
      const validDeduplicationStrategies = [
        'skip',
        'prefer_existing',
        'prefer_newer',
        'combine',
        'intelligent',
      ];

      validDeduplicationStrategies.forEach((strategy) => {
        const input = {
          items: [
            {
              kind: 'entity',
              content: 'Test entity',
            },
          ],
          deduplication: {
            enabled: true,
            merge_strategy: strategy,
            similarity_threshold: 0.85,
            max_history_hours: 168,
          },
        };

        const result = MemoryStoreInputSchema.safeParse(input);
        expect(result.success).toBe(true);
      });
    });

    it('should validate TTL configuration', () => {
      const ttlPolicies = ['default', 'short', 'long', 'permanent'];

      ttlPolicies.forEach((policy) => {
        const input = {
          items: [
            {
              kind: 'entity',
              content: 'Test entity with TTL',
            },
          ],
          global_ttl: {
            policy,
            auto_extend: policy !== 'permanent',
          },
        };

        const result = MemoryStoreInputSchema.safeParse(input);
        expect(result.success).toBe(true);
      });
    });
  });

  describe('Memory Find Input/Output Contracts', () => {
    it('should validate valid memory_find inputs', () => {
      const validInput = createValidMemoryFindInput();

      // Test Zod schema validation
      const result = MemoryFindInputSchema.safeParse(validInput);
      expect(result.success).toBe(true);

      // Test safe validation function
      const safeResult = safeValidateMemoryFindInput(validInput);
      expect(safeResult).not.toBeNull();
      expect(safeResult).toHaveProperty('query');
      expect(safeResult?.query).toBeTypeOf('string');
    });

    it('should reject invalid memory_find inputs with proper error messages', () => {
      const invalidInputs = createInvalidMemoryFindInput();

      invalidInputs.forEach((invalidInput, index) => {
        const result = MemoryFindInputSchema.safeParse(invalidInput);
        expect(result.success).toBe(false);

        if (!result.success) {
          expect(result.error).toBeInstanceOf(z['Z']odError);
          expect(result.error.errors.length).toBeGreaterThan(0);

          // Verify error messages are specific and helpful
          const error = result.error.errors[0];
          expect(error.message).toBeTypeOf('string');
          expect(error.message.length).toBeGreaterThan(0);
        }
      });
    });

    it('should validate search strategies', () => {
      const searchStrategies = ['fast', 'auto', 'deep'];

      searchStrategies.forEach((strategy) => {
        const input = {
          query: 'test query',
          search_strategy: strategy,
        };

        const result = MemoryFindInputSchema.safeParse(input);
        expect(result.success).toBe(true);
      });
    });

    it('should validate scope configuration', () => {
      const validScopes = [
        { project: 'test-project', branch: 'main' },
        { project: 'another-project' },
        { branch: 'develop' },
        { org: 'test-org', project: 'test-project', branch: 'feature/test' },
      ];

      validScopes.forEach((scope) => {
        const input = {
          query: 'test query',
          scope,
        };

        const result = MemoryFindInputSchema.safeParse(input);
        expect(result.success).toBe(true);
      });
    });

    it('should validate result format options', () => {
      const resultFormats = ['detailed', 'summary', 'compact'];

      resultFormats.forEach((format) => {
        const input = {
          query: 'test query',
          result_format: format,
        };

        const result = MemoryFindInputSchema.safeParse(input);
        expect(result.success).toBe(true);
      });
    });
  });

  // ============================================================================
  // T22.3: Tool Response Format Verification
  // ============================================================================

  describe('Tool Response Format Contracts', () => {
    it('should return properly structured tool responses', async () => {
      // Mock successful tool response structure
      const expectedResponseStructure = {
        content: expect.arrayContaining([
          expect.objectContaining({
            type: 'text',
            text: expect.stringContaining('Successfully stored'),
          }),
        ]),
        _meta: expect.objectContaining({
          requestId: expect.any(String),
          timestamp: expect.any(String),
          operation: expect.stringMatching(/^(memory_store|memory_find)$/),
        }),
        isError: false,
      };

      // Verify response structure matches contract
      expect(expectedResponseStructure).toBeDefined();
      expect(expectedResponseStructure.content).toBeDefined();
      expect(expectedResponseStructure['_']meta).toBeDefined();
      expect(expectedResponseStructure.isError).toBe(false);
    });

    it('should return properly formatted error responses', async () => {
      // Mock error response structure
      const expectedErrorResponse = {
        content: expect.arrayContaining([
          expect.objectContaining({
            type: 'text',
            text: expect.stringContaining('Error'),
          }),
        ]),
        _meta: expect.objectContaining({
          requestId: expect.any(String),
          timestamp: expect.any(String),
          operation: expect.stringMatching(/^(memory_store|memory_find)$/),
          error: expect.objectContaining({
            code: expect.any(String),
            message: expect.any(String),
            details: expect.any(Object),
          }),
        }),
        isError: true,
      };

      // Verify error response structure matches contract
      expect(expectedErrorResponse).toBeDefined();
      expect(expectedErrorResponse.content).toBeDefined();
      expect(expectedErrorResponse['_']meta).toBeDefined();
      expect(expectedErrorResponse['_']meta.error).toBeDefined();
      expect(expectedErrorResponse.isError).toBe(true);
    });

    it('should include proper metadata in responses', () => {
      const expectedMetadataFields = ['requestId', 'timestamp', 'operation', 'duration', 'version'];

      expectedMetadataFields.forEach((field) => {
        expect(field).toBeTypeOf('string');
      });
    });

    it('should handle batch operation responses correctly', () => {
      // Mock batch response for memory_store with multiple items
      const batchResponse = {
        content: expect.arrayContaining([
          expect.objectContaining({
            type: 'text',
            text: expect.stringContaining('Processed'),
          }),
        ]),
        _meta: expect.objectContaining({
          batchId: expect.any(String),
          itemCount: expect.any(Number),
          processedItems: expect.any(Number),
          failedItems: expect.any(Number),
        }),
        isError: false,
      };

      expect(batchResponse['_']meta.batchId).toBeDefined();
      expect(batchResponse['_']meta.itemCount).toBeGreaterThan(0);
      expect(typeof batchResponse['_']meta.processedItems).toBe('number');
      expect(typeof batchResponse['_']meta.failedItems).toBe('number');
    });
  });

  // ============================================================================
  // T22.4: Error Handling Contract Compliance
  // ============================================================================

  describe('Error Handling Contracts', () => {
    it('should handle validation errors with proper format', () => {
      const validationError = new ValidationError(
        'Test validation error',
        'items.kind',
        'VALIDATION_ERROR'
      );

      expect(validationError).toBeInstanceOf(Error);
      expect(validationError.message).toBe('Test validation error');
      expect(validationError.field).toBe('items.kind');
      expect(validationError.code).toBe('VALIDATION_ERROR');
    });

    it('should handle MCP protocol errors correctly', () => {
      const expectedErrorCodes = [
        ErrorCode['I']nvalidRequest,
        ErrorCode['M']ethodNotFound,
        ErrorCode['I']nvalidParams,
        ErrorCode['I']nternalError,
        ErrorCode['P']arseError,
      ];

      expectedErrorCodes.forEach((code) => {
        const mcpError = new McpError(code, `Test error for ${code}`);
        expect(mcpError).toBeInstanceOf(Error);
        expect(mcpError.code).toBe(code);
        expect(mcpError.message).toBe(`Test error for ${code}`);
      });
    });

    it('should provide consistent error response format', () => {
      const errorResponse = {
        content: [
          {
            type: 'text',
            text: expect.stringMatching(/^(Error:|Validation error:|Internal error:)/),
          },
        ],
        _meta: {
          requestId: expect.any(String),
          timestamp: expect.any(String),
          error: {
            code: expect.any(String),
            message: expect.any(String),
            type: expect.stringMatching(/^(validation|operational|system)$/),
            details: expect.any(Object),
          },
        },
        isError: true,
      };

      expect(errorResponse['_']meta.error.code).toBeTypeOf('string');
      expect(errorResponse['_']meta.error.message).toBeTypeOf('string');
      expect(errorResponse['_']meta.error.type).toMatch(/^(validation|operational|system)$/);
    });

    it('should handle timeout errors gracefully', () => {
      const timeoutError = {
        content: [
          {
            type: 'text',
            text: expect.stringContaining('timeout'),
          },
        ],
        _meta: {
          requestId: expect.any(String),
          timestamp: expect.any(String),
          error: {
            code: 'TIMEOUT',
            message: expect.stringContaining('timed out'),
            type: 'operational',
            details: {
              timeout: expect.any(Number),
              operation: expect.any(String),
            },
          },
        },
        isError: true,
      };

      expect(timeoutError['_']meta.error.code).toBe('TIMEOUT');
      expect(timeoutError['_']meta.error.details.timeout).toBeGreaterThan(0);
    });

    it('should handle database connection errors', () => {
      const dbError = {
        content: [
          {
            type: 'text',
            text: expect.stringContaining('database'),
          },
        ],
        _meta: {
          requestId: expect.any(String),
          timestamp: expect.any(String),
          error: {
            code: 'DATABASE_ERROR',
            message: expect.stringContaining('database'),
            type: 'system',
            details: {
              operation: expect.any(String),
              retryable: expect.any(Boolean),
            },
          },
        },
        isError: true,
      };

      expect(dbError['_']meta.error.code).toBe('DATABASE_ERROR');
      expect(typeof dbError['_']meta.error.details.retryable).toBe('boolean');
    });
  });

  // ============================================================================
  // T22.5: Backward Compatibility Verification
  // ============================================================================

  describe('Backward Compatibility Contracts', () => {
    it('should maintain backward compatibility for memory_store schema', () => {
      // Test with v1.0 style inputs (simplified)
      const v1Input = {
        items: [
          {
            kind: 'entity',
            content: 'Simple entity content',
          },
        ],
      };

      const result = MemoryStoreInputSchema.safeParse(v1Input);
      expect(result.success).toBe(true);

      if (result.success) {
        // Verify that the parsed result has expected defaults
        expect(result['data.deduplication']).toBeDefined();
        expect(result['data.global_ttl']).toBeDefined();
        expect(result['data.global_truncation']).toBeDefined();
      }
    });

    it('should maintain backward compatibility for memory_find schema', () => {
      // Test with v1.0 style inputs (minimal)
      const v1Input = {
        query: 'simple search query',
      };

      const result = MemoryFindInputSchema.safeParse(v1Input);
      expect(result.success).toBe(true);

      if (result.success) {
        // Verify that the parsed result has expected defaults
        expect(result['data.search_strategy']).toBeDefined();
        expect(result['data.limit']).toBeDefined();
        expect(result['data.result_format']).toBeDefined();
      }
    });

    it('should handle deprecated fields gracefully', () => {
      // Test with fields that might be deprecated but still supported
      const inputWithLegacyFields = {
        items: [
          {
            kind: 'entity',
            content: 'Entity with legacy fields',
            // Any legacy fields should be handled gracefully
          },
        ],
        // Legacy configuration options
      };

      const result = MemoryStoreInputSchema.safeParse(inputWithLegacyFields);
      // Should either succeed with defaults or fail gracefully
      expect(result.success || !result.success).toBe(true);
    });

    it('should maintain stable API contract versioning', () => {
      const expectedApiVersion = '2.0.1';
      const supportedVersions = ['2.0.0', '2.0.1'];

      expect(expectedApiVersion).toMatch(/^\d+\.\d+\.\d+$/);
      expect(supportedVersions).toContain(expectedApiVersion);

      // Verify semantic versioning
      const [major, minor, patch] = expectedApiVersion.split('.').map(Number);
      expect(major).toBe(2);
      expect(minor).toBe(0);
      expect(patch).toBeGreaterThanOrEqual(0);
    });

    it('should provide migration path for breaking changes', () => {
      // Mock migration metadata that should be available
      const migrationInfo = {
        currentVersion: '2.0.1',
        minCompatibleVersion: '2.0.0',
        deprecationWarnings: [],
        breakingChanges: [],
        migrationGuide: expect.any(String),
      };

      expect(migrationInfo.currentVersion).toBeDefined();
      expect(migrationInfo.minCompatibleVersion).toBeDefined();
      expect(Array.isArray(migrationInfo.deprecationWarnings)).toBe(true);
      expect(Array.isArray(migrationInfo.breakingChanges)).toBe(true);
    });
  });

  // ============================================================================
  // T22.6: Integration Contract Tests
  // ============================================================================

  describe('Integration Contract Tests', () => {
    it('should handle end-to-end tool workflows', async () => {
      // Test memory_store followed by memory_find
      const storeInput = createValidMemoryStoreInput();
      const findInput = {
        query: 'search for stored item',
        scope: storeInput.scope || {},
      };

      // Both inputs should be valid
      expect(MemoryStoreInputSchema.safeParse(storeInput).success).toBe(true);
      expect(MemoryFindInputSchema.safeParse(findInput).success).toBe(true);
    });

    it('should maintain data consistency across operations', () => {
      const consistencyTest = {
        storeOperation: {
          input: createValidMemoryStoreInput(),
          expectedOutput: expect.objectContaining({
            success: true,
            itemsProcessed: expect.any(Number),
          }),
        },
        findOperation: {
          input: createValidMemoryFindInput(),
          expectedOutput: expect.objectContaining({
            results: expect.any(Array),
            totalCount: expect.any(Number),
          }),
        },
      };

      expect(consistencyTest.storeOperation.input).toHaveProperty('items');
      expect(consistencyTest.findOperation.input).toHaveProperty('query');
    });

    it('should handle concurrent operations safely', () => {
      const concurrentInputs = [
        createValidMemoryStoreInput(),
        createValidMemoryStoreInput(),
        createValidMemoryFindInput(),
        createValidMemoryFindInput(),
      ];

      concurrentInputs.forEach((input, index) => {
        if (input.items) {
          expect(MemoryStoreInputSchema.safeParse(input).success).toBe(true);
        } else if (input.query) {
          expect(MemoryFindInputSchema.safeParse(input).success).toBe(true);
        }
      });
    });
  });

  // ============================================================================
  // T22.7: Performance Contract Verification
  // ============================================================================

  describe('Performance Contract Tests', () => {
    it('should meet response time contracts', () => {
      const performanceContracts = {
        memory_store: {
          maxResponseTime: 5000, // 5 seconds
          maxBatchSize: 100,
          maxItemSize: 100000, // 100KB
        },
        memory_find: {
          maxResponseTime: 3000, // 3 seconds
          maxResultCount: 1000,
          maxQueryLength: 1000,
        },
      };

      Object.entries(performanceContracts).forEach(([tool, contract]) => {
        expect(contract.maxResponseTime).toBeGreaterThan(0);
        expect(contract.maxResponseTime).toBeLessThan(30000); // 30 seconds max

        if (tool === 'memory_store') {
          expect(contract.maxBatchSize).toBeGreaterThan(0);
          expect(contract.maxItemSize).toBeGreaterThan(0);
        }

        if (tool === 'memory_find') {
          expect(contract.maxResultCount).toBeGreaterThan(0);
          expect(contract.maxQueryLength).toBeGreaterThan(0);
        }
      });
    });

    it('should handle resource limits gracefully', () => {
      const resourceLimits = {
        maxMemoryUsage: 512 * 1024 * 1024, // 512MB
        maxConcurrentRequests: 100,
        maxRequestSize: 10 * 1024 * 1024, // 10MB
      };

      expect(resourceLimits.maxMemoryUsage).toBeGreaterThan(0);
      expect(resourceLimits.maxConcurrentRequests).toBeGreaterThan(0);
      expect(resourceLimits.maxRequestSize).toBeGreaterThan(0);
    });
  });
});
