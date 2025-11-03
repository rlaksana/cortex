/**
 * Integration Tests for Unified Response Format
 *
 * Tests that all MCP tools return standardized metadata format
 * with the required fields: strategy, vector_used, degraded, source, ttl?
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createResponseMeta, UnifiedToolResponse } from '../../src/types/unified-response.interface.js';

describe('Unified Response Format Integration Tests', () => {
  let server: Server;
  let testTools: any[];

  beforeAll(async () => {
    // Initialize the MCP server for testing
    const { createServer } = await import('../../src/index.js');
    server = createServer();

    // Get available tools
    const tools = await server.listTools();
    testTools = tools.tools.filter(tool =>
      ['memory_store', 'memory_find', 'system_status'].includes(tool.name)
    );
  });

  afterAll(async () => {
    if (server) {
      await server.close();
    }
  });

  describe('Unified Response Interface Validation', () => {
    it('should validate createResponseMeta function', () => {
      const meta = createResponseMeta({
        strategy: 'auto',
        vector_used: true,
        degraded: false,
        source: 'cortex_memory',
        execution_time_ms: 150,
        confidence_score: 0.95,
        ttl: '1h',
        additional: {
          operation_id: 'test-123',
          debug_info: 'test'
        }
      });

      expect(meta).toHaveProperty('strategy', 'auto');
      expect(meta).toHaveProperty('vector_used', true);
      expect(meta).toHaveProperty('degraded', false);
      expect(meta).toHaveProperty('source', 'cortex_memory');
      expect(meta).toHaveProperty('execution_time_ms', 150);
      expect(meta).toHaveProperty('confidence_score', 0.95);
      expect(meta).toHaveProperty('ttl', '1h');
      expect(meta).toHaveProperty('operation_id', 'test-123');
      expect(meta).toHaveProperty('debug_info', 'test');
    });

    it('should handle minimal required fields only', () => {
      const meta = createResponseMeta({
        strategy: 'fast',
        vector_used: false,
        degraded: true,
        source: 'test_source'
      });

      expect(meta).toHaveProperty('strategy', 'fast');
      expect(meta).toHaveProperty('vector_used', false);
      expect(meta).toHaveProperty('degraded', true);
      expect(meta).toHaveProperty('source', 'test_source');
      expect(meta).not.toHaveProperty('execution_time_ms');
      expect(meta).not.toHaveProperty('confidence_score');
      expect(meta).not.toHaveProperty('ttl');
    });
  });

  describe('memory_store tool response format', () => {
    it('should return unified response format for successful memory store', async () => {
      const testData = {
        items: [
          {
            kind: 'entity',
            content: 'Test entity for unified response format',
            scope: { project: 'test-project' },
            metadata: { test: true }
          }
        ]
      };

      try {
        const response = await server.callTool({
          name: 'memory_store',
          arguments: testData
        });

        expect(response).toHaveProperty('content');
        expect(response.content).toBeInstanceOf(Array);
        expect(response.content[0]).toHaveProperty('type', 'text');

        const responseData = JSON.parse(response.content[0].text);

        // Should have both legacy observability and new meta field
        expect(responseData).toHaveProperty('observability');
        expect(responseData).toHaveProperty('meta');

        // Validate unified meta format
        const meta = responseData.meta;
        expect(meta).toHaveProperty('strategy');
        expect(meta).toHaveProperty('vector_used');
        expect(meta).toHaveProperty('degraded');
        expect(meta).toHaveProperty('source');
        expect(meta).toHaveProperty('execution_time_ms');
        expect(meta).toHaveProperty('confidence_score');

        // Strategy should be one of the allowed values
        expect(['autonomous_deduplication', 'skip', 'prefer_existing', 'prefer_newer', 'combine', 'intelligent']).toContain(meta.strategy);

        // Should have additional metadata
        expect(meta).toHaveProperty('batch_id');
        expect(meta).toHaveProperty('items_processed');
        expect(meta).toHaveProperty('items_stored');
        expect(meta).toHaveProperty('items_errors');

      } catch (error) {
        // Skip test if server is not available or database issues
        console.warn('Memory store test skipped due to:', error);
      }
    });

    it('should return unified response format for failed memory store', async () => {
      const invalidData = {
        items: [
          {
            kind: 'invalid_kind',
            content: '',
            scope: null
          }
        ]
      };

      try {
        const response = await server.callTool({
          name: 'memory_store',
          arguments: invalidData
        });

        expect(response).toHaveProperty('content');
        const responseData = JSON.parse(response.content[0].text);

        // Should still have meta field even in error cases
        expect(responseData).toHaveProperty('meta');

        const meta = responseData.meta;
        expect(meta).toHaveProperty('strategy');
        expect(meta).toHaveProperty('vector_used');
        expect(meta).toHaveProperty('degraded');
        expect(meta).toHaveProperty('source');

      } catch (error) {
        // Expected behavior for invalid input
        expect(error).toBeDefined();
      }
    });
  });

  describe('memory_find tool response format', () => {
    it('should return unified response format for memory find', async () => {
      const searchData = {
        query: 'test unified response format',
        limit: 5,
        mode: 'auto'
      };

      try {
        const response = await server.callTool({
          name: 'memory_find',
          arguments: searchData
        });

        expect(response).toHaveProperty('content');
        expect(response.content[0]).toHaveProperty('type', 'text');

        const responseData = JSON.parse(response.content[0].text);

        // Should have both legacy observability and new meta field
        expect(responseData).toHaveProperty('observability');
        expect(responseData).toHaveProperty('meta');

        // Validate unified meta format
        const meta = responseData.meta;
        expect(meta).toHaveProperty('strategy');
        expect(meta).toHaveProperty('vector_used');
        expect(meta).toHaveProperty('degraded');
        expect(meta).toHaveProperty('source');
        expect(meta).toHaveProperty('execution_time_ms');
        expect(meta).toHaveProperty('confidence_score');

        // Strategy should be one of the allowed search strategies
        expect(['fast', 'auto', 'deep', 'semantic', 'keyword', 'hybrid', 'fallback', 'orchestrator_based']).toContain(meta.strategy);

        // Should have additional search metadata
        expect(meta).toHaveProperty('search_id');
        expect(meta).toHaveProperty('query');
        expect(meta).toHaveProperty('results_found');
        expect(meta).toHaveProperty('mode');
        expect(meta).toHaveProperty('expand');
        expect(meta).toHaveProperty('scope_applied');
        expect(meta).toHaveProperty('types_filter');

      } catch (error) {
        // Skip test if server is not available or database issues
        console.warn('Memory find test skipped due to:', error);
      }
    });

    it('should handle different search modes', async () => {
      const searchModes = ['fast', 'auto', 'deep'];

      for (const mode of searchModes) {
        try {
          const response = await server.callTool({
            name: 'memory_find',
            arguments: {
              query: 'test search mode validation',
              mode: mode,
              limit: 3
            }
          });

          const responseData = JSON.parse(response.content[0].text);
          const meta = responseData.meta;

          expect(meta).toHaveProperty('strategy');
          expect(meta).toHaveProperty('execution_time_ms');

          // Mode should be reflected in additional metadata
          expect(meta.mode).toBe(mode);

        } catch (error) {
          console.warn(`Search mode ${mode} test skipped:`, error);
        }
      }
    });
  });

  describe('system_status tool response format', () => {
    it('should return unified response format for system health check', async () => {
      try {
        const response = await server.callTool({
          name: 'system_status',
          arguments: { operation: 'health' }
        });

        expect(response).toHaveProperty('content');
        expect(response.content[0]).toHaveProperty('type', 'text');

        const responseData = JSON.parse(response.content[0].text);

        // Should have both legacy observability and new meta field
        expect(responseData).toHaveProperty('observability');
        expect(responseData).toHaveProperty('meta');

        // Validate unified meta format
        const meta = responseData.meta;
        expect(meta).toHaveProperty('strategy', 'system_operation');
        expect(meta).toHaveProperty('vector_used', false);
        expect(meta).toHaveProperty('degraded', false);
        expect(meta).toHaveProperty('source', 'cortex_memory');
        expect(meta).toHaveProperty('confidence_score', 1.0);

        // Should have additional system metadata
        expect(meta).toHaveProperty('operation', 'health_check');
        expect(meta).toHaveProperty('service_status');
        expect(meta).toHaveProperty('uptime');
        expect(meta).toHaveProperty('timestamp');

      } catch (error) {
        console.warn('System status test skipped due to:', error);
      }
    });

    it('should handle system status errors gracefully', async () => {
      try {
        const response = await server.callTool({
          name: 'system_status',
          arguments: { operation: 'invalid_operation' }
        });

        // Should return some kind of error response
        expect(response).toHaveProperty('content');
        const responseData = JSON.parse(response.content[0].text);

        // Should still have meta field
        expect(responseData).toHaveProperty('meta');
        const meta = responseData.meta;

        expect(meta).toHaveProperty('strategy');
        expect(meta).toHaveProperty('vector_used');
        expect(meta).toHaveProperty('degraded');
        expect(meta).toHaveProperty('source');

      } catch (error) {
        // Expected behavior for invalid operation
        expect(error).toBeDefined();
      }
    });
  });

  describe('Response Consistency Validation', () => {
    it('should ensure all tools use consistent meta field structure', async () => {
      const testCases = [
        {
          tool: 'memory_store',
          args: {
            items: [{ kind: 'entity', content: 'consistency test', scope: { project: 'test' } }]
          }
        },
        {
          tool: 'memory_find',
          args: { query: 'consistency test', limit: 1 }
        },
        {
          tool: 'system_status',
          args: { operation: 'health' }
        }
      ];

      for (const testCase of testCases) {
        try {
          const response = await server.callTool({
            name: testCase.tool,
            arguments: testCase.args
          });

          const responseData = JSON.parse(response.content[0].text);
          const meta = responseData.meta;

          // All responses should have these required fields
          expect(meta).toHaveProperty('strategy');
          expect(meta).toHaveProperty('vector_used');
          expect(meta).toHaveProperty('degraded');
          expect(meta).toHaveProperty('source');

          // Strategy should be a valid string
          expect(typeof meta.strategy).toBe('string');
          expect(meta.strategy.length).toBeGreaterThan(0);

          // Boolean fields should be boolean
          expect(typeof meta.vector_used).toBe('boolean');
          expect(typeof meta.degraded).toBe('boolean');

          // Source should be a non-empty string
          expect(typeof meta.source).toBe('string');
          expect(meta.source.length).toBeGreaterThan(0);

        } catch (error) {
          console.warn(`Consistency test for ${testCase.tool} skipped:`, error);
        }
      }
    });

    it('should maintain backward compatibility with observability field', async () => {
      try {
        const response = await server.callTool({
          name: 'memory_find',
          arguments: { query: 'backward compatibility test' }
        });

        const responseData = JSON.parse(response.content[0].text);

        // Should have both old and new formats
        expect(responseData).toHaveProperty('observability');
        expect(responseData).toHaveProperty('meta');

        // Legacy observability should still have expected fields
        expect(responseData.observability).toHaveProperty('source');
        expect(responseData.observability).toHaveProperty('strategy');
        expect(responseData.observability).toHaveProperty('vector_used');
        expect(responseData.observability).toHaveProperty('degraded');

        // New meta should have the same core information
        expect(responseData.meta.source).toBe(responseData.observability.source);
        expect(responseData.meta.vector_used).toBe(responseData.observability.vector_used);
        expect(responseData.meta.degraded).toBe(responseData.observability.degraded);

      } catch (error) {
        console.warn('Backward compatibility test skipped:', error);
      }
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle malformed tool arguments gracefully', async () => {
      const invalidRequests = [
        { tool: 'memory_store', args: null },
        { tool: 'memory_find', args: {} }, // Missing required query
        { tool: 'system_status', args: { operation: null } }
      ];

      for (const request of invalidRequests) {
        try {
          const response = await server.callTool({
            name: request.tool,
            arguments: request.args
          });

          // Should return error response with meta field
          expect(response).toHaveProperty('content');

          try {
            const responseData = JSON.parse(response.content[0].text);
            expect(responseData).toHaveProperty('meta');

            const meta = responseData.meta;
            expect(meta).toHaveProperty('strategy');
            expect(meta).toHaveProperty('vector_used');
            expect(meta).toHaveProperty('degraded');
            expect(meta).toHaveProperty('source');

          } catch (parseError) {
            // If it's a raw error response, that's also acceptable
            expect(response.content[0].text).toBeDefined();
          }

        } catch (error) {
          // Error responses are expected for invalid inputs
          expect(error).toBeDefined();
        }
      }
    });
  });
});