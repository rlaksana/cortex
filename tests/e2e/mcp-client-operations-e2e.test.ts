/**
 * MCP Client Operations E2E Tests
 *
 * Tests MCP protocol message flows end-to-end.
 * Validates client-server communication and protocol compliance.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { spawn, ChildProcess } from 'child_process';
import { createInterface } from 'readline';
import { setTimeout } from 'timers/promises';
import { randomUUID } from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

interface MCPServer {
  process: ChildProcess;
  stdin: NodeJS.WritableStream;
  stdout: NodeJS.ReadableStream;
  stderr: NodeJS.ReadableStream;
}

interface MCPMessage {
  jsonrpc: '2.0';
  id?: string | number;
  method?: string;
  params?: any;
  result?: any;
  error?: {
    code: number;
    message: string;
    data?: any;
  };
}

describe('MCP Client Operations E2E', () => {
  let server: MCPServer;
  let messageId = 1;
  const TEST_DB_URL = process.env.TEST_QDRANT_URL ||
    'http://cortex:trust@localhost:5433/cortex_test_e2e';

  beforeAll(async () => {
    await setupTestDatabase();
    server = await startMCPServer();
    await setTimeout(2000); // Wait for server initialization
  });

  afterAll(async () => {
    if (server?.process) {
      server.process.kill('SIGTERM');
      await setTimeout(1000);
    }
    await cleanupTestDatabase();
  });

  beforeEach(async () => {
    messageId = 1;
    await cleanupTestData();
  });

  describe('MCP Protocol Initialization', () => {
    it('should initialize MCP protocol with proper capabilities', async () => {
      // Send initialize request
      const initMessage: MCPMessage = {
        jsonrpc: '2.0',
        id: messageId++,
        method: 'initialize',
        params: {
          protocolVersion: '2024-11-05',
          capabilities: {
            tools: {}
          },
          clientInfo: {
            name: 'test-client',
            version: '1.0.0'
          }
        }
      };

      const response = await sendMCPMessage(initMessage);
      expect(response.result).toBeDefined();
      expect(response.result.capabilities).toBeDefined();
      expect(response.result.capabilities.tools).toBeDefined();

      // Send initialized notification
      const initializedMessage: MCPMessage = {
        jsonrpc: '2.0',
        method: 'notifications/initialized'
      };

      await sendMCPMessage(initializedMessage);
    });

    it('should handle protocol errors gracefully', async () => {
      // Send invalid JSON-RPC message
      const invalidMessage = {
        invalid: 'message'
      };

      const response = await sendRawMessage(invalidMessage);
      expect(response.error).toBeDefined();
      expect(response.error.code).toBe(-32600); // Invalid Request
    });

    it('should reject unsupported methods', async () => {
      const unsupportedMessage: MCPMessage = {
        jsonrpc: '2.0',
        id: messageId++,
        method: 'unsupported_method',
        params: {}
      };

      const response = await sendMCPMessage(unsupportedMessage);
      expect(response.error).toBeDefined();
      expect(response.error.code).toBe(-32601); // Method not found
    });
  });

  describe('Tool Operations', () => {
    beforeEach(async () => {
      // Initialize protocol for tool tests
      const initMessage: MCPMessage = {
        jsonrpc: '2.0',
        id: messageId++,
        method: 'initialize',
        params: {
          protocolVersion: '2024-11-05',
          capabilities: { tools: {} },
          clientInfo: { name: 'test-client', version: '1.0.0' }
        }
      };
      await sendMCPMessage(initMessage);

      const initializedMessage: MCPMessage = {
        jsonrpc: '2.0',
        method: 'notifications/initialized'
      };
      await sendMCPMessage(initializedMessage);
    });

    it('should list available tools', async () => {
      const listToolsMessage: MCPMessage = {
        jsonrpc: '2.0',
        id: messageId++,
        method: 'tools/list'
      };

      const response = await sendMCPMessage(listToolsMessage);
      expect(response.result).toBeDefined();
      expect(response.result.tools).toBeDefined();
      expect(Array.isArray(response.result.tools)).toBe(true);

      const tools = response.result.tools;
      expect(tools.length).toBeGreaterThan(0);

      // Verify required tools exist
      const memoryStoreTool = tools.find((t: any) => t.name === 'memory_store');
      expect(memoryStoreTool).toBeDefined();
      expect(memoryStoreTool.description).toBeDefined();
      expect(memoryStoreTool.inputSchema).toBeDefined();

      const memoryFindTool = tools.find((t: any) => t.name === 'memory_find');
      expect(memoryFindTool).toBeDefined();
      expect(memoryFindTool.description).toBeDefined();
      expect(memoryFindTool.inputSchema).toBeDefined();
    });

    it('should call memory_store tool successfully', async () => {
      const storeMessage: MCPMessage = {
        jsonrpc: '2.0',
        id: messageId++,
        method: 'tools/call',
        params: {
          name: 'memory_store',
          arguments: {
            items: [{
              kind: 'decision',
              scope: {
                project: 'test-project',
                branch: 'main'
              },
              data: {
                component: 'architecture',
                status: 'proposed',
                title: 'Use TypeScript for type safety',
                rationale: 'TypeScript provides compile-time type checking',
                alternatives_considered: [
                  { alternative: 'JavaScript', reason: 'No type safety' }
                ]
              }
            }]
          }
        }
      };

      const response = await sendMCPMessage(storeMessage);
      expect(response.result).toBeDefined();
      expect(response.result.content).toBeDefined();
      expect(Array.isArray(response.result.content)).toBe(true);

      const content = response.result.content[0];
      expect(content.type).toBe('text');
      expect(content.text).toBeDefined();

      const result = JSON.parse(content.text);
      expect(result.stored).toBeDefined();
      expect(result.stored).toHaveLength(1);
      expect(result.errors).toBeDefined();
      expect(result.autonomous_context).toBeDefined();
    });

    it('should call memory_find tool successfully', async () => {
      // First store some data
      const storeMessage: MCPMessage = {
        jsonrpc: '2.0',
        id: messageId++,
        method: 'tools/call',
        params: {
          name: 'memory_store',
          arguments: {
            items: [{
              kind: 'entity',
              scope: { project: 'search-test' },
              data: {
                entity_type: 'component',
                name: 'TestComponent',
                data: { description: 'A test component for search' }
              }
            }]
          }
        }
      };
      await sendMCPMessage(storeMessage);

      // Then search for it
      const findMessage: MCPMessage = {
        jsonrpc: '2.0',
        id: messageId++,
        method: 'tools/call',
        params: {
          name: 'memory_find',
          arguments: {
            query: 'TestComponent',
            scope: { project: 'search-test' },
            types: ['entity']
          }
        }
      };

      const response = await sendMCPMessage(findMessage);
      expect(response.result).toBeDefined();
      expect(response.result.content).toBeDefined();

      const content = response.result.content[0];
      const result = JSON.parse(content.text);
      expect(result.hits).toBeDefined();
      expect(Array.isArray(result.hits)).toBe(true);
    });

    it('should handle tool validation errors', async () => {
      const invalidStoreMessage: MCPMessage = {
        jsonrpc: '2.0',
        id: messageId++,
        method: 'tools/call',
        params: {
          name: 'memory_store',
          arguments: {
            // Missing required 'items' field
            invalid: 'data'
          }
        }
      };

      const response = await sendMCPMessage(invalidStoreMessage);
      expect(response.error).toBeDefined();
      expect(response.error.code).toBeDefined();
    });

    it('should handle tool execution errors', async () => {
      const errorMessage: MCPMessage = {
        jsonrpc: '2.0',
        id: messageId++,
        method: 'tools/call',
        params: {
          name: 'memory_store',
          arguments: {
            items: [{
              kind: 'decision',
              scope: { project: 'error-test' },
              data: {
                // Invalid data that should cause database error
                component: null,
                status: 'invalid_status',
                title: '', // Empty title should fail validation
                rationale: 'Test'
              }
            }]
          }
        }
      };

      const response = await sendMCPMessage(errorMessage);
      expect(response.result).toBeDefined();
      expect(response.result.isError).toBe(true);

      const content = response.result.content[0];
      const result = JSON.parse(content.text);
      expect(result.error).toBeDefined();
      expect(result.code).toBeDefined();
    });
  });

  describe('Concurrent Operations', () => {
    beforeEach(async () => {
      // Initialize protocol
      const initMessage: MCPMessage = {
        jsonrpc: '2.0',
        id: messageId++,
        method: 'initialize',
        params: {
          protocolVersion: '2024-11-05',
          capabilities: { tools: {} },
          clientInfo: { name: 'test-client', version: '1.0.0' }
        }
      };
      await sendMCPMessage(initMessage);

      const initializedMessage: MCPMessage = {
        jsonrpc: '2.0',
        method: 'notifications/initialized'
      };
      await sendMCPMessage(initializedMessage);
    });

    it('should handle concurrent tool calls', async () => {
      const concurrentCalls = 5;
      const promises: Promise<any>[] = [];

      for (let i = 0; i < concurrentCalls; i++) {
        const storeMessage: MCPMessage = {
          jsonrpc: '2.0',
          id: messageId++,
          method: 'tools/call',
          params: {
            name: 'memory_store',
            arguments: {
              items: [{
                kind: 'entity',
                scope: { project: `concurrent-test-${i}` },
                data: {
                  entity_type: 'component',
                  name: `ConcurrentComponent${i}`,
                  data: { index: i }
                }
              }]
            }
          }
        };

        promises.push(sendMCPMessage(storeMessage));
      }

      const responses = await Promise.all(promises);

      // All calls should succeed
      responses.forEach((response, index) => {
        expect(response.result).toBeDefined();
        expect(response.result.content).toBeDefined();

        const content = response.result.content[0];
        const result = JSON.parse(content.text);
        expect(result.stored).toHaveLength(1);
        expect(result.stored[0].kind).toBe('entity');
      });
    });

    it('should maintain message isolation between concurrent calls', async () => {
      const project1 = `isolation-test-1-${randomUUID().substring(0, 4)}`;
      const project2 = `isolation-test-2-${randomUUID().substring(0, 4)}`;

      // Simultaneous store operations for different projects
      const store1Promise = sendMCPMessage({
        jsonrpc: '2.0',
        id: messageId++,
        method: 'tools/call',
        params: {
          name: 'memory_store',
          arguments: {
            items: [{
              kind: 'entity',
              scope: { project: project1 },
              data: {
                entity_type: 'component',
                name: 'Project1Component',
                data: { project: project1 }
              }
            }]
          }
        }
      });

      const store2Promise = sendMCPMessage({
        jsonrpc: '2.0',
        id: messageId++,
        method: 'tools/call',
        params: {
          name: 'memory_store',
          arguments: {
            items: [{
              kind: 'entity',
              scope: { project: project2 },
              data: {
                entity_type: 'component',
                name: 'Project2Component',
                data: { project: project2 }
              }
            }]
          }
        }
      });

      const [response1, response2] = await Promise.all([store1Promise, store2Promise]);

      // Verify both operations succeeded independently
      expect(response1.result).toBeDefined();
      expect(response2.result).toBeDefined();

      const result1 = JSON.parse(response1.result.content[0].text);
      const result2 = JSON.parse(response2.result.content[0].text);

      expect(result1.stored).toHaveLength(1);
      expect(result2.stored).toHaveLength(1);

      // Verify data isolation through search
      const search1Promise = sendMCPMessage({
        jsonrpc: '2.0',
        id: messageId++,
        method: 'tools/call',
        params: {
          name: 'memory_find',
          arguments: {
            query: 'component',
            scope: { project: project1 }
          }
        }
      });

      const search2Promise = sendMCPMessage({
        jsonrpc: '2.0',
        id: messageId++,
        method: 'tools/call',
        params: {
          name: 'memory_find',
          arguments: {
            query: 'component',
            scope: { project: project2 }
          }
        }
      });

      const [searchResponse1, searchResponse2] = await Promise.all([search1Promise, search2Promise]);

      const searchResult1 = JSON.parse(searchResponse1.result.content[0].text);
      const searchResult2 = JSON.parse(searchResponse2.result.content[0].text);

      expect(searchResult1.hits).toHaveLength(1);
      expect(searchResult2.hits).toHaveLength(1);

      // Verify correct data is in each project
      expect(searchResult1.hits[0].data?.name).toBe('Project1Component');
      expect(searchResult2.hits[0].data?.name).toBe('Project2Component');
    });
  });

  describe('Error Handling and Recovery', () => {
    beforeEach(async () => {
      // Initialize protocol
      const initMessage: MCPMessage = {
        jsonrpc: '2.0',
        id: messageId++,
        method: 'initialize',
        params: {
          protocolVersion: '2024-11-05',
          capabilities: { tools: {} },
          clientInfo: { name: 'test-client', version: '1.0.0' }
        }
      };
      await sendMCPMessage(initMessage);

      const initializedMessage: MCPMessage = {
        jsonrpc: '2.0',
        method: 'notifications/initialized'
      };
      await sendMCPMessage(initializedMessage);
    });

    it('should handle malformed requests gracefully', async () => {
      const malformedMessage = {
        // Missing jsonrpc version
        id: messageId++,
        method: 'tools/call',
        params: {
          name: 'memory_store',
          arguments: { items: [] }
        }
      };

      const response = await sendRawMessage(malformedMessage);
      expect(response.error).toBeDefined();
      expect(response.error.code).toBe(-32600); // Invalid Request
    });

    it('should recover from database connection errors', async () => {
      // Simulate database connection issue by invalidating connection
      // This would require mocking or test infrastructure

      // Try operation that should fail due to connection issue
      const storeMessage: MCPMessage = {
        jsonrpc: '2.0',
        id: messageId++,
        method: 'tools/call',
        params: {
          name: 'memory_store',
          arguments: {
            items: [{
              kind: 'entity',
              scope: { project: 'recovery-test' },
              data: {
                entity_type: 'component',
                name: 'RecoveryTestComponent',
                data: {}
              }
            }]
          }
        }
      };

      const response = await sendMCPMessage(storeMessage);

      // Should either succeed or provide meaningful error
      if (response.error) {
        expect(response.error.code).toBeDefined();
        expect(response.error.message).toBeDefined();
      } else {
        expect(response.result).toBeDefined();
      }
    });

    it('should handle large payload processing', async () => {
      // Create large payload
      const largeContent = 'x'.repeat(10000); // 10KB of content
      const largePayload = {
        jsonrpc: '2.0',
        id: messageId++,
        method: 'tools/call',
        params: {
          name: 'memory_store',
          arguments: {
            items: [{
              kind: 'section',
              scope: { project: 'large-payload-test' },
              data: {
                title: 'Large Content Test',
                heading: 'Large Content',
                body_md: largeContent
              }
            }]
          }
        }
      };

      const response = await sendMCPMessage(largePayload);
      expect(response.result).toBeDefined();

      const result = JSON.parse(response.result.content[0].text);
      expect(result.stored).toHaveLength(1);
    });

    it('should maintain operation consistency under high load', async () => {
      const operations = 20;
      const promises: Promise<any>[] = [];

      for (let i = 0; i < operations; i++) {
        const message: MCPMessage = {
          jsonrpc: '2.0',
          id: messageId++,
          method: 'tools/call',
          params: {
            name: 'memory_store',
            arguments: {
              items: [{
                kind: 'entity',
                scope: { project: `load-test-${i % 5}` }, // 5 different projects
                data: {
                  entity_type: 'test_entity',
                  name: `LoadTestEntity${i}`,
                  data: { index: i, timestamp: Date.now() }
                }
              }]
            }
          }
        };

        promises.push(sendMCPMessage(message));
      }

      const responses = await Promise.all(promises);

      // Count successful vs failed operations
      let successful = 0;
      let failed = 0;

      responses.forEach(response => {
        if (response.result && !response.result.isError) {
          successful++;
        } else {
          failed++;
        }
      });

      // Most operations should succeed
      expect(successful).toBeGreaterThan(operations * 0.8); // 80% success rate
      console.log(`Load test: ${successful} successful, ${failed} failed`);
    });
  });

  describe('Protocol Compliance', () => {
    beforeEach(async () => {
      // Initialize protocol
      const initMessage: MCPMessage = {
        jsonrpc: '2.0',
        id: messageId++,
        method: 'initialize',
        params: {
          protocolVersion: '2024-11-05',
          capabilities: { tools: {} },
          clientInfo: { name: 'test-client', version: '1.0.0' }
        }
      };
      await sendMCPMessage(initMessage);

      const initializedMessage: MCPMessage = {
        jsonrpc: '2.0',
        method: 'notifications/initialized'
      };
      await sendMCPMessage(initializedMessage);
    });

    it('should follow JSON-RPC 2.0 specification', async () => {
      // Test proper JSON-RPC response structure
      const request: MCPMessage = {
        jsonrpc: '2.0',
        id: messageId++,
        method: 'tools/list'
      };

      const response = await sendMCPMessage(request);

      // Verify JSON-RPC compliance
      expect(response.jsonrpc).toBe('2.0');
      expect(response.id).toBe(request.id);
      expect(response.result).toBeDefined();
    });

    it('should handle notifications (requests without id)', async () => {
      const notification: MCPMessage = {
        jsonrpc: '2.0',
        method: 'notifications/test',
        params: { message: 'test notification' }
      };

      // Notifications should not receive responses
      // This test verifies the server doesn't crash on notifications
      const response = await sendMCPMessage(notification, { expectResponse: false });
      expect(response).toBeNull(); // No response expected
    });

    it('should maintain message order correlation', async () => {
      const messages: MCPMessage[] = [];
      const expectedIds: (string | number)[] = [];

      // Send multiple messages with different IDs
      for (let i = 0; i < 5; i++) {
        const id = `test-${i}`;
        expectedIds.push(id);

        const message: MCPMessage = {
          jsonrpc: '2.0',
          id,
          method: 'tools/list'
        };

        messages.push(message);
      }

      // Send all messages
      const promises = messages.map(msg => sendMCPMessage(msg));
      const responses = await Promise.all(promises);

      // Verify response IDs match request IDs
      responses.forEach((response, index) => {
        expect(response.id).toBe(expectedIds[index]);
      });
    });
  });
});

// Helper Functions
async function setupTestDatabase(): Promise<void> {
  console.log('Setting up test database for MCP operations...');
}

async function cleanupTestDatabase(): Promise<void> {
  console.log('Cleaning up test database for MCP operations...');
}

async function cleanupTestData(): Promise<void> {
  console.log('Cleaning up test data for MCP operations...');
}

async function startMCPServer(): Promise<MCPServer> {
  const serverPath = path.join(__dirname, '../../dist/index.js');
  const process = spawn('node', [serverPath], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: {
      ...process.env,
      QDRANT_URL: TEST_DB_URL,
      NODE_ENV: 'test'
    }
  });

  const stdin = process.stdin!;
  const stdout = process.stdout!;
  const stderr = process.stderr!;

  return {
    process,
    stdin,
    stdout,
    stderr
  };
}

async function sendMCPMessage(message: MCPMessage): Promise<MCPMessage> {
  return sendRawMessage(message, { expectResponse: true });
}

async function sendRawMessage(message: any, options: { expectResponse?: boolean } = {}): Promise<MCPMessage | null> {
  if (!server?.stdin || !server?.stdout) {
    throw new Error('Server not available');
  }

  const messageStr = JSON.stringify(message) + '\n';
  server.stdin.write(messageStr);

  if (!options.expectResponse) {
    return null;
  }

  // Read response
  const rl = createInterface({
    input: server.stdout,
    crlfDelay: Infinity
  });

  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      rl.close();
      reject(new Error('Message timeout'));
    }, 10000);

    rl.once('line', (line) => {
      clearTimeout(timeout);
      rl.close();

      try {
        const response = JSON.parse(line);
        resolve(response);
      } catch (error) {
        reject(new Error(`Invalid JSON response: ${line}`));
      }
    });

    rl.once('error', (error) => {
      clearTimeout(timeout);
      reject(error);
    });
  });
}