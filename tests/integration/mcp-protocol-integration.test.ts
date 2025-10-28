/**
 * MCP Protocol Integration Tests
 *
 * Tests the complete MCP protocol message flows, including:
 * - Tool registration and discovery
 * - Request/response handling
 * - Error propagation
 * - Message validation
 * - Performance under load
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import { Server } from '@modelcontextprotocol/sdk/server';
import { StdioServerTransport } from ' '@modelcontextprotocol/sdk/server/stdio.js';
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
  JSONRPCMessage,
  ErrorCode,
  McpError,
} from ' '@modelcontextprotocol/sdk/types.js';
import { memoryStore } from ' '../../src/services/memory-store.js';
import { smartMemoryFind } from ' '../../src/services/smart-find.js';
import { dbQdrantClient } from ' '../../src/db/pool.js';
// Prisma client removed - system now uses Qdrant + PostgreSQL architecture';

describe('MCP Protocol Integration Tests', () => {
  let server: Server;
  let testDb: any;

  beforeAll(async () => {
    // Initialize database for testing
    await dbQdrantClient.initialize();

    // Create test server instance
    server = new Server(
      { name: 'cortex-test', version: '1.0.0' },
      { capabilities: { tools: {} } }
    );

    // Register tool handlers
    server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          name: 'memory_store',
          description: 'Store, update, or delete knowledge items',
          inputSchema: {
            type: 'object',
            properties: {
              items: {
                type: 'array',
                items: { type: 'object' },
                description: 'Array of knowledge items to store',
              },
            },
            required: ['items'],
          },
        },
        {
          name: 'memory_find',
          description: 'Search knowledge with confidence scoring',
          inputSchema: {
            type: 'object',
            properties: {
              query: { type: 'string' },
              scope: { type: 'object' },
              types: { type: 'array', items: { type: 'string' } },
              mode: { type: 'string', enum: ['auto', 'fast', 'deep'] },
            },
            required: ['query'],
          },
        },
      ],
    }));

    server.setRequestHandler(CallToolRequestSchema, async (request: any) => {
      const { name, arguments: args } = request.params;

      try {
        switch (name) {
          case 'memory_store':
            const storeResult = await memoryStore(args.items);
            return { content: [{ type: 'text', text: JSON.stringify(storeResult, null, 2) }] };
          case 'memory_find':
            const findResult = await smartMemoryFind(args);
            return { content: [{ type: 'text', text: JSON.stringify(findResult, null, 2) }] };
          default:
            throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
        }
      } catch (error) {
        if (error instanceof McpError) {
          throw error;
        }
        throw new McpError(
          ErrorCode.InternalError,
          error instanceof Error ? error.message : 'Unknown error'
        );
      }
    });
  });

  afterAll(async () => {
    // Cleanup test data using proper table names
    await dbQdrantClient.query(`DELETE FROM section WHERE tags @> '{"test": true}'::jsonb`);
    await dbQdrantClient.query(`DELETE FROM adr_decision WHERE tags @> '{"test": true}'::jsonb`);
    await dbQdrantClient.query(`DELETE FROM issue_log WHERE tags @> '{"test": true}'::jsonb`);
    await dbQdrantClient.query(`DELETE FROM runbook WHERE tags @> '{"test": true}'::jsonb`);
    await dbQdrantClient.query(`DELETE FROM knowledge_entity WHERE tags @> '{"test": true}'::jsonb`);
    await dbQdrantClient.query(`DELETE FROM knowledge_relation WHERE tags @> '{"test": true}'::jsonb`);
  });

  describe('Tool Registration and Discovery', () => {
    it('should list available tools with correct schema', async () => {
      const request = {
        jsonrpc: '2.0' as const,
        id: 'test-1',
        method: 'tools/list' as const,
      };

      const response = await server.request(request, ListToolsRequestSchema);

      expect(response).toBeDefined();
      expect(response.tools).toHaveLength(2);

      const memoryStoreTool = response.tools.find((t: any) => t.name === 'memory_store');
      expect(memoryStoreTool).toBeDefined();
      expect(memoryStoreTool.description).toContain('Store, update, or delete');
      expect(memoryStoreTool.inputSchema.required).toContain('items');

      const memoryFindTool = response.tools.find((t: any) => t.name === 'memory_find');
      expect(memoryFindTool).toBeDefined();
      expect(memoryFindTool.description).toContain('Search knowledge');
      expect(memoryFindTool.inputSchema.required).toContain('query');
    });

    it('should validate tool schema compliance', async () => {
      const request = {
        jsonrpc: '2.0' as const,
        id: 'test-2',
        method: 'tools/list' as const,
      };

      const response = await server.request(request, ListToolsRequestSchema);

      // Validate each tool schema
      for (const tool of response.tools) {
        expect(tool.name).toBeDefined();
        expect(tool.description).toBeDefined();
        expect(tool.inputSchema).toBeDefined();
        expect(tool.inputSchema.type).toBe('object');
        expect(Array.isArray(tool.inputSchema.properties)).toBeFalsy(); // Should be object
      }
    });
  });

  describe('Memory Store Tool Integration', () => {
    it('should handle valid memory store requests', async () => {
      const request = {
        jsonrpc: '2.0' as const,
        id: 'test-3',
        method: 'tools/call' as const,
        params: {
          name: 'memory_store',
          arguments: {
            items: [
              {
                kind: 'section',
                scope: { project: 'test-project', branch: 'main' },
                data: {
                  title: 'Test Section',
                  heading: 'Test Heading',
                  body_text: 'Test content for integration testing',
                },
                tags: { test: true },
              },
            ],
          },
        },
      };

      const response = await server.request(request, CallToolRequestSchema);

      expect(response).toBeDefined();
      expect(response.content).toHaveLength(1);
      expect(response.content[0].type).toBe('text');

      const result = JSON.parse(response.content[0].text);
      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].kind).toBe('section');
      expect(result.stored[0].status).toBe('inserted');
      expect(result.errors).toHaveLength(0);
    });

    it('should handle batch memory store requests', async () => {
      const request = {
        jsonrpc: '2.0' as const,
        id: 'test-4',
        method: 'tools/call' as const,
        params: {
          name: 'memory_store',
          arguments: {
            items: [
              {
                kind: 'decision',
                scope: { project: 'test-project', branch: 'main' },
                data: {
                  title: 'Test Decision 1',
                  status: 'accepted',
                  component: 'integration-test',
                  rationale: 'Test rationale for decision 1',
                },
                tags: { test: true },
              },
              {
                kind: 'decision',
                scope: { project: 'test-project', branch: 'main' },
                data: {
                  title: 'Test Decision 2',
                  status: 'proposed',
                  component: 'integration-test',
                  rationale: 'Test rationale for decision 2',
                },
                tags: { test: true },
              },
            ],
          },
        },
      };

      const response = await server.request(request, CallToolRequestSchema);

      const result = JSON.parse(response.content[0].text);
      expect(result.stored).toHaveLength(2);
      expect(result.errors).toHaveLength(0);
    });

    it('should validate input and return appropriate errors', async () => {
      const request = {
        jsonrpc: '2.0' as const,
        id: 'test-5',
        method: 'tools/call' as const,
        params: {
          name: 'memory_store',
          arguments: {
            items: [
              {
                kind: 'invalid_kind',
                scope: { project: 'test-project' },
                data: {},
              },
            ],
          },
        },
      };

      await expect(server.request(request, CallToolRequestSchema)).rejects.toThrow();
    });
  });

  describe('Memory Find Tool Integration', () => {
    beforeEach(async () => {
      // Insert test data
      await memoryStore([
        {
          kind: 'section',
          scope: { project: 'search-test', branch: 'main' },
          data: {
            title: 'Search Test Section',
            heading: 'Search Integration Testing',
            body_text: 'This content is used for testing search functionality',
          },
          tags: { test: true, search_test: true },
        },
      ]);
    });

    it('should handle basic search requests', async () => {
      const request = {
        jsonrpc: '2.0' as const,
        id: 'test-6',
        method: 'tools/call' as const,
        params: {
          name: 'memory_find',
          arguments: {
            query: 'search integration',
            types: ['section'],
          },
        },
      };

      const response = await server.request(request, CallToolRequestSchema);

      const result = JSON.parse(response.content[0].text);
      expect(result.hits).toBeInstanceOf(Array);
      expect(result.autonomous_metadata).toBeDefined();
      expect(result.autonomous_metadata.strategy_used).toBeDefined();
    });

    it('should handle scoped search requests', async () => {
      const request = {
        jsonrpc: '2.0' as const,
        id: 'test-7',
        method: 'tools/call' as const,
        params: {
          name: 'memory_find',
          arguments: {
            query: 'search',
            scope: { project: 'search-test', branch: 'main' },
            types: ['section'],
          },
        },
      };

      const response = await server.request(request, CallToolRequestSchema);

      const result = JSON.parse(response.content[0].text);
      expect(result.hits.length).toBeGreaterThan(0);
    });

    it('should handle different search modes', async () => {
      const modes = ['auto', 'fast', 'deep'] as const;

      for (const mode of modes) {
        const request = {
          jsonrpc: '2.0' as const,
          id: `test-8-${mode}`,
          method: 'tools/call' as const,
          params: {
            name: 'memory_find',
            arguments: {
              query: 'search',
              mode,
            },
          },
        };

        const response = await server.request(request, CallToolRequestSchema);
        const result = JSON.parse(response.content[0].text);
        expect(result).toBeDefined();
        expect(result.autonomous_metadata.mode_executed).toBeDefined();
      }
    });
  });

  describe('Error Handling and Validation', () => {
    it('should handle invalid tool names', async () => {
      const request = {
        jsonrpc: '2.0' as const,
        id: 'test-9',
        method: 'tools/call' as const,
        params: {
          name: 'invalid_tool',
          arguments: {},
        },
      };

      await expect(server.request(request, CallToolRequestSchema)).rejects.toThrow();
    });

    it('should handle missing required arguments', async () => {
      const request = {
        jsonrpc: '2.0' as const,
        id: 'test-10',
        method: 'tools/call' as const,
        params: {
          name: 'memory_find',
          arguments: {}, // Missing required 'query'
        },
      };

      await expect(server.request(request, CallToolRequestSchema)).rejects.toThrow();
    });

    it('should handle malformed JSON-RPC requests', async () => {
      const invalidRequests = [
        { id: 'test-11', method: 'tools/call' }, // Missing jsonrpc
        { jsonrpc: '2.0', method: 'tools/call' }, // Missing id
        { jsonrpc: '1.0', id: 'test-12', method: 'tools/call' }, // Invalid jsonrpc version
      ];

      for (const invalidRequest of invalidRequests) {
        await expect(
          server.request(invalidRequest as any, CallToolRequestSchema)
        ).rejects.toThrow();
      }
    });
  });

  describe('Performance and Load Testing', () => {
    it('should handle concurrent requests efficiently', async () => {
      const concurrentRequests = 10;
      const requests = Array.from({ length: concurrentRequests }, (_, i) => ({
        jsonrpc: '2.0' as const,
        id: `test-concurrent-${i}`,
        method: 'tools/list' as const,
      }));

      const startTime = Date.now();
      const responses = await Promise.all(
        requests.map(req => server.request(req, ListToolsRequestSchema))
      );
      const duration = Date.now() - startTime;

      expect(responses).toHaveLength(concurrentRequests);
      expect(duration).toBeLessThan(5000); // Should complete within 5 seconds

      // All responses should be identical
      const firstResponse = responses[0];
      for (const response of responses) {
        expect(response.tools).toEqual(firstResponse.tools);
      }
    });

    it('should handle large data sets efficiently', async () => {
      const largeItems = Array.from({ length: 50 }, (_, i) => ({
        kind: 'entity' as const,
        scope: { project: 'performance-test', branch: 'main' },
        data: {
          entity_type: 'test_entity',
          name: `Test Entity ${i}`,
          data: {
            description: `Test description for entity ${i}`,
            content: 'x'.repeat(1000), // 1KB of content per entity
          },
        },
        tags: { test: true, performance_test: true },
      }));

      const request = {
        jsonrpc: '2.0' as const,
        id: 'test-large-data',
        method: 'tools/call' as const,
        params: {
          name: 'memory_store',
          arguments: {
            items: largeItems,
          },
        },
      };

      const startTime = Date.now();
      const response = await server.request(request, CallToolRequestSchema);
      const duration = Date.now() - startTime;

      const result = JSON.parse(response.content[0].text);
      expect(result.stored).toHaveLength(50);
      expect(result.errors).toHaveLength(0);
      expect(duration).toBeLessThan(10000); // Should complete within 10 seconds
    });
  });

  describe('Message Serialization and Deserialization', () => {
    it('should handle complex nested data structures', async () => {
      const complexData = {
        kind: 'entity' as const,
        scope: { project: 'serialization-test', branch: 'main', org: 'test-org' },
        data: {
          entity_type: 'complex_entity',
          name: 'Complex Test Entity',
          data: {
            nested: {
              arrays: [1, 2, 3, { deep: { value: 'test' } }],
              objects: { key1: 'value1', key2: null, key3: undefined },
              primitives: 'string',
            },
          },
        },
        tags: { test: true, complex: true },
      };

      const request = {
        jsonrpc: '2.0' as const,
        id: 'test-serialization',
        method: 'tools/call' as const,
        params: {
          name: 'memory_store',
          arguments: {
            items: [complexData],
          },
        },
      };

      const response = await server.request(request, CallToolRequestSchema);
      const result = JSON.parse(response.content[0].text);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].kind).toBe('entity');
      expect(result.stored[0].status).toBe('inserted');
    });

    it('should preserve data integrity through round-trip', async () => {
      const originalData = {
        kind: 'section' as const,
        scope: { project: 'roundtrip-test', branch: 'main' },
        data: {
          title: 'Round-trip Test',
          heading: 'Data Integrity Test',
          body_text: 'Testing data integrity through storage and retrieval',
        },
        tags: { test: true, roundtrip: true },
      };

      // Store the data
      const storeRequest = {
        jsonrpc: '2.0' as const,
        id: 'test-roundtrip-store',
        method: 'tools/call' as const,
        params: {
          name: 'memory_store',
          arguments: {
            items: [originalData],
          },
        },
      };

      const storeResponse = await server.request(storeRequest, CallToolRequestSchema);
      const storeResult = JSON.parse(storeResponse.content[0].text);
      const storedId = storeResult.stored[0].id;

      // Retrieve the data
      const findRequest = {
        jsonrpc: '2.0' as const,
        id: 'test-roundtrip-find',
        method: 'tools/call' as const,
        params: {
          name: 'memory_find',
          arguments: {
            query: 'roundtrip test',
            scope: { project: 'roundtrip-test', branch: 'main' },
          },
        },
      };

      const findResponse = await server.request(findRequest, CallToolRequestSchema);
      const findResult = JSON.parse(findResponse.content[0].text);

      expect(findResult.hits.length).toBeGreaterThan(0);
      const foundItem = findResult.hits.find((hit: any) => hit.id === storedId);
      expect(foundItem).toBeDefined();
      expect(foundItem.title).toBe(originalData.data.title);
    });
  });
});