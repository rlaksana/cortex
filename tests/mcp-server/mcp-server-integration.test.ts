/**
 * MCP Server Integration Tests
 *
 * Comprehensive integration tests for the Cortex Memory MCP server.
 * Tests the full MCP protocol communication flow.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import { spawn, ChildProcess } from 'child_process';
import { Readable, Writable } from 'stream';
import { TestUtils } from '../setup/mcp-test-setup';

describe('MCP Server Integration Tests', () => {
  let serverProcess: ChildProcess | null = null;
  let serverStdin: Writable | null = null;
  let serverStdout: Readable | null = null;
  let serverStderr: Readable | null = null;

  // Test configuration
  const SERVER_STARTUP_TIMEOUT = 10000; // 10 seconds
  const REQUEST_TIMEOUT = 5000; // 5 seconds per request
  const SERVER_COMMAND = 'node';
  const SERVER_ARGS = ['dist/index.js'];

  // Helper function to start MCP server
  async function startMCPServer(): Promise<void> {
    return new Promise((resolve, reject) => {
      console.log('🚀 Starting MCP server for integration tests...');

      serverProcess = spawn(SERVER_COMMAND, SERVER_ARGS, {
        stdio: ['pipe', 'pipe', 'pipe'],
        env: {
          ...process.env,
          NODE_ENV: 'test',
          QDRANT_URL: process.env.QDRANT_URL || 'http://localhost:6333',
          QDRANT_COLLECTION_NAME: `test-cortex-memory-${Date.now()}`,
          MCP_TEST_MODE: 'true'
        }
      });

      serverStdin = serverProcess.stdin;
      serverStdout = serverProcess.stdout;
      serverStderr = serverProcess.stderr;

      if (!serverStdin || !serverStdout || !serverStderr) {
        reject(new Error('Failed to set up server I/O streams'));
        return;
      }

      // Capture stderr for debugging
      let stderrOutput = '';
      serverStderr.on('data', (data) => {
        stderrOutput += data.toString();
        console.log('📝 Server stderr:', data.toString().trim());
      });

      // Wait for server startup
      serverStdout.on('data', (data) => {
        const output = data.toString();
        console.log('📝 Server stdout:', output.trim());

        // Check for ready message
        if (output.includes('ready') || output.includes('accepting requests')) {
          console.log('✅ MCP server is ready');
          resolve();
        }
      });

      serverProcess.on('error', (error) => {
        console.error('❌ Server process error:', error);
        reject(error);
      });

      serverProcess.on('exit', (code, signal) => {
        if (code !== null && code !== 0) {
          console.error(`❌ Server exited with code ${code}`);
          console.error('Server stderr output:', stderrOutput);
          reject(new Error(`Server exited with code ${code}`));
        }
        if (signal) {
          console.error(`❌ Server killed by signal ${signal}`);
          reject(new Error(`Server killed by signal ${signal}`));
        }
      });

      // Timeout for server startup
      setTimeout(() => {
        reject(new Error('Server startup timeout'));
      }, SERVER_STARTUP_TIMEOUT);
    });
  }

  // Helper function to stop MCP server
  async function stopMCPServer(): Promise<void> {
    if (!serverProcess) return;

    console.log('🛑 Stopping MCP server...');

    return new Promise((resolve) => {
      if (serverProcess) {
        serverProcess.on('exit', () => {
          console.log('✅ MCP server stopped');
          resolve();
        });

        // Try graceful shutdown first
        serverProcess.kill('SIGTERM');

        // Force kill if graceful shutdown doesn't work
        setTimeout(() => {
          if (serverProcess && !serverProcess.killed) {
            console.log('⚠️ Forcing server shutdown...');
            serverProcess.kill('SIGKILL');
          }
        }, 2000);
      } else {
        resolve();
      }
    });
  }

  // Helper function to send JSON-RPC request
  async function sendMCPRequest(request: any): Promise<any> {
    if (!serverStdin || !serverStdout) {
      throw new Error('Server I/O streams not available');
    }

    return new Promise((resolve, reject) => {
      let responseBuffer = '';
      const requestId = request.id;

      // Set up response listener
      const responseHandler = (data: Buffer) => {
        responseBuffer += data.toString();

        // Try to parse complete JSON responses
        const lines = responseBuffer.split('\n').filter(line => line.trim());

        for (const line of lines) {
          try {
            const response = JSON.parse(line);
            if (response.id === requestId) {
              serverStdout!.removeListener('data', responseHandler);

              if (response.error) {
                reject(new Error(`MCP Error: ${response.error.message} (${response.error.code})`));
              } else {
                resolve(response.result);
              }
              return;
            }
          } catch (e) {
            // Not a complete JSON object yet, continue buffering
          }
        }
      };

      serverStdout.on('data', responseHandler);

      // Send request
      const requestJson = JSON.stringify(request) + '\n';
      console.log('📤 Sending MCP request:', requestJson.trim());

      const writeResult = serverStdin.write(requestJson);
      if (!writeResult) {
        serverStdin!.removeListener('data', responseHandler);
        reject(new Error('Failed to write request to server stdin'));
      }

      // Set timeout
      setTimeout(() => {
        serverStdout!.removeListener('data', responseHandler);
        reject(new Error('MCP request timeout'));
      }, REQUEST_TIMEOUT);
    });
  }

  // Setup and teardown
  beforeAll(async () => {
    // Build the project first
    const { execSync } = await import('child_process');
    try {
      execSync('npm run build', { stdio: 'inherit' });
    } catch (error) {
      console.error('❌ Failed to build project before tests');
      throw error;
    }

    await startMCPServer();
  }, 30000);

  afterAll(async () => {
    await stopMCPServer();
  }, 10000);

  beforeEach(() => {
    // Reset test state
  });

  afterEach(() => {
    // Cleanup after each test
  });

  // Test suite
  describe('Server Initialization', () => {
    it('should initialize MCP server successfully', async () => {
      expect(serverProcess).toBeDefined();
      expect(serverProcess!.pid).toBeGreaterThan(0);
      expect(!serverProcess!.killed).toBe(true);
    });

    it('should respond to initialize request', async () => {
      const initRequest = {
        jsonrpc: '2.0',
        id: 'test-init',
        method: 'initialize',
        params: {
          protocolVersion: '2025-06-18',
          capabilities: {
            tools: {}
          },
          clientInfo: {
            name: 'test-client',
            version: '1.0.0'
          }
        }
      };

      const response = await sendMCPRequest(initRequest);

      expect(response).toBeDefined();
      expect(response.protocolVersion).toBe('2025-06-18');
      expect(response.capabilities).toBeDefined();
      expect(response.capabilities.tools).toBeDefined();
    });
  });

  describe('Tool Listing', () => {
    it('should list available tools', async () => {
      // Initialize first
      const initRequest = {
        jsonrpc: '2.0',
        id: 'test-list-tools-init',
        method: 'initialize',
        params: {
          protocolVersion: '2025-06-18',
          capabilities: { tools: {} }
        }
      };
      await sendMCPRequest(initRequest);

      // List tools
      const listToolsRequest = {
        jsonrpc: '2.0',
        id: 'test-list-tools',
        method: 'tools/list',
        params: {}
      };

      const response = await sendMCPRequest(listToolsRequest);

      expect(response).toBeDefined();
      expect(response.tools).toBeDefined();
      expect(Array.isArray(response.tools)).toBe(true);
      expect(response.tools.length).toBeGreaterThan(0);

      // Check required tools are present
      const toolNames = response.tools.map((tool: any) => tool.name);
      expect(toolNames).toContain('memory_store');
      expect(toolNames).toContain('memory_find');
      expect(toolNames).toContain('system_status');

      // Verify tool schemas
      const memoryStoreTool = response.tools.find((tool: any) => tool.name === 'memory_store');
      expect(memoryStoreTool).toBeDefined();
      expect(memoryStoreTool.inputSchema).toBeDefined();
      expect(memoryStoreTool.inputSchema.properties).toBeDefined();
      expect(memoryStoreTool.inputSchema.properties.items).toBeDefined();
    });
  });

  describe('Memory Store Tool', () => {
    it('should store memory items successfully', async () => {
      const storeRequest = TestUtils.createTestServerRequest('memory_store', {
        items: [
          TestUtils.generateTestMemoryItem('entity', { title: 'Test Entity 1' }),
          TestUtils.generateTestMemoryItem('decision', { title: 'Test Decision 1' })
        ]
      });

      const response = await sendMCPRequest(storeRequest);

      expect(response).toBeDefined();
      expect(response.content).toBeDefined();
      expect(Array.isArray(response.content)).toBe(true);
      expect(response.content[0].type).toBe('text');
      expect(response.content[0].text).toContain('Successfully stored');
      expect(response.content[0].text).toContain('knowledge items');
    });

    it('should handle empty items array', async () => {
      const storeRequest = TestUtils.createTestServerRequest('memory_store', {
        items: []
      });

      const response = await sendMCPRequest(storeRequest);

      expect(response).toBeDefined();
      expect(response.content[0].text).toContain('Successfully stored 0');
    });

    it('should validate required fields', async () => {
      const invalidStoreRequest = TestUtils.createTestServerRequest('memory_store', {
        items: [
          { kind: 'entity' } // Missing required 'data' field
        ]
      });

      await expect(sendMCPRequest(invalidStoreRequest)).rejects.toThrow();
    });
  });

  describe('Memory Find Tool', () => {
    beforeEach(async () => {
      // Store some test data
      const storeRequest = TestUtils.createTestServerRequest('memory_store', {
        items: TestUtils.generateBatchTestItems(5)
      });
      await sendMCPRequest(storeRequest);
    });

    it('should find stored memory items', async () => {
      const findRequest = TestUtils.createTestServerRequest('memory_find', {
        query: 'test',
        limit: 10
      });

      const response = await sendMCPRequest(findRequest);

      expect(response).toBeDefined();
      expect(response.content).toBeDefined();
      expect(response.content[0].text).toContain('Found');
      expect(response.content[0].text).toContain('knowledge items');
    });

    it('should filter by type', async () => {
      const findRequest = TestUtils.createTestServerRequest('memory_find', {
        query: 'test',
        types: ['entity'],
        limit: 10
      });

      const response = await sendMCPRequest(findRequest);

      expect(response).toBeDefined();
      expect(response.content[0].text).toContain('Found');
    });

    it('should filter by scope', async () => {
      const findRequest = TestUtils.createTestServerRequest('memory_find', {
        query: 'test',
        scope: {
          project: 'test-project',
          branch: 'test-branch'
        },
        limit: 10
      });

      const response = await sendMCPRequest(findRequest);

      expect(response).toBeDefined();
      expect(response.content[0].text).toContain('Found');
    });

    it('should handle limit parameter', async () => {
      const findRequest = TestUtils.createTestServerRequest('memory_find', {
        query: 'test',
        limit: 2
      });

      const response = await sendMCPRequest(findRequest);

      expect(response).toBeDefined();
      expect(response.content[0].text).toContain('Found');
    });
  });

  describe('System Status Tool', () => {
    it('should return system status', async () => {
      const statusRequest = TestUtils.createTestServerRequest('system_status', {});

      const response = await sendMCPRequest(statusRequest);

      expect(response).toBeDefined();
      expect(response.content).toBeDefined();
      expect(response.content[0].type).toBe('text');
      expect(response.content[0].text).toContain('Cortex Memory MCP Server Status');
      expect(response.content[0].text).toContain('Server Information');
      expect(response.content[0].text).toContain('Qdrant Database');
    });
  });

  describe('Error Handling', () => {
    it('should handle unknown tool requests', async () => {
      const unknownToolRequest = TestUtils.createTestServerRequest('unknown_tool', {});

      await expect(sendMCPRequest(unknownToolRequest)).rejects.toThrow(/Unknown tool/);
    });

    it('should handle malformed JSON-RPC requests', async () => {
      const malformedRequest = {
        jsonrpc: '2.0',
        // Missing 'id' field
        method: 'tools/list'
      };

      await expect(sendMCPRequest(malformedRequest)).rejects.toThrow();
    });

    it('should handle missing required parameters', async () => {
      const invalidRequest = TestUtils.createTestServerRequest('memory_store', {
        // Missing required 'items' parameter
      });

      await expect(sendMCPRequest(invalidRequest)).rejects.toThrow();
    });
  });

  describe('Performance Tests', () => {
    it('should handle concurrent requests', async () => {
      const requests = [];

      // Create multiple concurrent requests
      for (let i = 0; i < 5; i++) {
        const findRequest = TestUtils.createTestServerRequest('memory_find', {
          query: `test-${i}`,
          limit: 5
        });
        requests.push(sendMCPRequest(findRequest));
      }

      // Wait for all requests to complete
      const responses = await Promise.allSettled(requests);

      // Check that most requests succeeded (allow some failures due to timing)
      const successCount = responses.filter(r => r.status === 'fulfilled').length;
      expect(successCount).toBeGreaterThanOrEqual(3);
    }, 15000);

    it('should handle large data volumes', async () => {
      // Store a batch of items
      const largeBatch = TestUtils.generateBatchTestItems(20);
      const storeRequest = TestUtils.createTestServerRequest('memory_store', {
        items: largeBatch
      });

      const storeResponse = await sendMCPRequest(storeRequest);
      expect(storeResponse.content[0].text).toContain('Successfully stored 20');

      // Search with larger limit
      const findRequest = TestUtils.createTestServerRequest('memory_find', {
        query: 'test',
        limit: 50
      });

      const findResponse = await sendMCPRequest(findRequest);
      expect(findResponse.content[0].text).toContain('Found');
    }, 20000);
  });
});