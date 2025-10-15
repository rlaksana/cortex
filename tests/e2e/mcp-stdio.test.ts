import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn, ChildProcess } from 'child_process';
import { EventEmitter } from 'events';

/**
 * T087: MCP STDIO Transport Test
 *
 * Validates:
 * - Server starts successfully with STDIO transport
 * - tools/list request returns memory.find and memory.store
 * - JSON-RPC protocol compliance
 * - Graceful shutdown on SIGTERM
 */
describe('MCP STDIO Transport E2E', () => {
  let serverProcess: ChildProcess;
  let responseEmitter: EventEmitter;
  let stdoutBuffer: string = '';

  beforeAll(async () => {
    // Start MCP server as child process
    serverProcess = spawn('node', ['dist/index.js'], {
      cwd: process.cwd(),
      env: {
        ...process.env,
        DATABASE_URL:
          process.env.DATABASE_URL || 'postgresql://cortex:cortex@localhost:5432/cortex_test',
        NODE_ENV: 'test',
      },
    });

    responseEmitter = new EventEmitter();

    // Capture stdout for JSON-RPC responses
    serverProcess.stdout?.on('data', (data) => {
      stdoutBuffer += data.toString();

      // Try to parse complete JSON-RPC messages
      const lines = stdoutBuffer.split('\n');
      stdoutBuffer = lines.pop() || ''; // Keep incomplete line in buffer

      for (const line of lines) {
        if (line.trim()) {
          try {
            const message = JSON.parse(line);
            responseEmitter.emit('message', message);
          } catch (e) {
            // Ignore parse errors for incomplete messages
          }
        }
      }
    });

    serverProcess.stderr?.on('data', (data) => {
      console.error('Server stderr:', data.toString());
    });

    // Wait for server to be ready
    await new Promise((resolve) => setTimeout(resolve, 1000));
  });

  afterAll(() => {
    if (serverProcess && !serverProcess.killed) {
      serverProcess.kill('SIGTERM');
    }
  });

  it('should respond to tools/list request with memory.find and memory.store', async () => {
    const request = {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/list',
      params: {},
    };

    const responsePromise = new Promise((resolve) => {
      responseEmitter.once('message', resolve);
    });

    // Send request to server via stdin
    serverProcess.stdin?.write(JSON.stringify(request) + '\n');

    const response: any = await responsePromise;

    expect(response).toBeDefined();
    expect(response.jsonrpc).toBe('2.0');
    expect(response.id).toBe(1);
    expect(response.result).toBeDefined();
    expect(response.result.tools).toBeInstanceOf(Array);

    const toolNames = response.result.tools.map((t: any) => t.name);
    expect(toolNames).toContain('memory.find');
    expect(toolNames).toContain('memory.store');
  }, 10000);

  it('should include required tool metadata in tools/list response', async () => {
    const request = {
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/list',
      params: {},
    };

    const responsePromise = new Promise((resolve) => {
      responseEmitter.once('message', resolve);
    });

    serverProcess.stdin?.write(JSON.stringify(request) + '\n');
    const response: any = await responsePromise;

    const memoryFind = response.result.tools.find((t: any) => t.name === 'memory.find');
    expect(memoryFind).toBeDefined();
    expect(memoryFind.description).toBeDefined();
    expect(memoryFind.inputSchema).toBeDefined();
    expect(memoryFind.inputSchema.type).toBe('object');
    expect(memoryFind.inputSchema.required).toContain('query');

    const memoryStore = response.result.tools.find((t: any) => t.name === 'memory.store');
    expect(memoryStore).toBeDefined();
    expect(memoryStore.description).toBeDefined();
    expect(memoryStore.inputSchema).toBeDefined();
    expect(memoryStore.inputSchema.required).toContain('items');
  }, 10000);

  it('should handle invalid JSON-RPC with error response', async () => {
    const invalidRequest = {
      jsonrpc: '2.0',
      id: 3,
      method: 'invalid/method',
      params: {},
    };

    const responsePromise = new Promise((resolve) => {
      responseEmitter.once('message', resolve);
    });

    serverProcess.stdin?.write(JSON.stringify(invalidRequest) + '\n');
    const response: any = await responsePromise;

    expect(response).toBeDefined();
    expect(response.jsonrpc).toBe('2.0');
    expect(response.id).toBe(3);
    expect(response.error).toBeDefined();
  }, 10000);
});
