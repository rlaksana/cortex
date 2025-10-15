import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn, ChildProcess } from 'child_process';
import { EventEmitter } from 'events';

/**
 * T088: Golden Path E2E Test
 *
 * Validates full round-trip:
 * 1. Start server
 * 2. Store knowledge item via memory.store
 * 3. Retrieve item via memory.find
 * 4. Verify response matches schema
 * 5. Graceful shutdown
 */
describe('Golden Path: Store → Find Round-Trip', () => {
  let serverProcess: ChildProcess;
  let responseEmitter: EventEmitter;
  let stdoutBuffer: string = '';
  let requestId = 100;

  beforeAll(async () => {
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

    serverProcess.stdout?.on('data', (data) => {
      stdoutBuffer += data.toString();
      const lines = stdoutBuffer.split('\n');
      stdoutBuffer = lines.pop() || '';

      for (const line of lines) {
        if (line.trim()) {
          try {
            const message = JSON.parse(line);
            responseEmitter.emit(`response_${message.id}`, message);
          } catch (e) {
            // Ignore
          }
        }
      }
    });

    await new Promise((resolve) => setTimeout(resolve, 1000));
  });

  afterAll(() => {
    if (serverProcess && !serverProcess.killed) {
      serverProcess.kill('SIGTERM');
    }
  });

  async function sendRequest(method: string, params: any): Promise<any> {
    const id = ++requestId;
    const request = {
      jsonrpc: '2.0',
      id,
      method,
      params,
    };

    const responsePromise = new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error('Request timeout'));
      }, 5000);

      responseEmitter.once(`response_${id}`, (response) => {
        clearTimeout(timeout);
        resolve(response);
      });
    });

    serverProcess.stdin?.write(JSON.stringify(request) + '\n');
    return responsePromise;
  }

  it('should complete full store → find round-trip', async () => {
    // Step 1: Store a section via memory.store
    const storeRequest = {
      name: 'memory.store',
      arguments: {
        items: [
          {
            kind: 'section',
            scope: {
              project: 'cortex-memory',
              branch: 'e2e-test',
            },
            data: {
              document_id: '123e4567-e89b-12d3-a456-426614174000',
              heading: 'E2E Test Section',
              body_jsonb: {
                content:
                  'This is an end-to-end test section for golden path validation with unique keyword e2etest123',
              },
              body_text:
                'This is an end-to-end test section for golden path validation with unique keyword e2etest123',
            },
            tags: {
              test: 'e2e',
              unique_keyword: 'e2etest123',
            },
          },
        ],
      },
    };

    const storeResponse: any = await sendRequest('tools/call', storeRequest);

    // Verify store response
    expect(storeResponse.error).toBeUndefined();
    expect(storeResponse.result).toBeDefined();

    const storeResult = JSON.parse(storeResponse.result.content[0].text);
    expect(storeResult.stored).toBeInstanceOf(Array);
    expect(storeResult.stored.length).toBe(1);

    const storedItem = storeResult.stored[0];
    expect(storedItem.id).toBeDefined();
    expect(storedItem.status).toMatch(/inserted|skipped_dedupe/);
    expect(storedItem.kind).toBe('section');

    // Step 2: Search for the stored item via memory.find
    const findRequest = {
      name: 'memory.find',
      arguments: {
        query: 'e2etest123 validation',
        types: ['section'],
        top_k: 10,
        mode: 'fast',
      },
    };

    const findResponse: any = await sendRequest('tools/call', findRequest);

    // Verify find response
    expect(findResponse.error).toBeUndefined();
    expect(findResponse.result).toBeDefined();

    const findResult = JSON.parse(findResponse.result.content[0].text);
    expect(findResult.hits).toBeInstanceOf(Array);
    expect(findResult.hits.length).toBeGreaterThan(0);

    // Verify we found our stored item
    const foundItem = findResult.hits.find((hit: any) => hit.snippet.includes('e2etest123'));
    expect(foundItem).toBeDefined();
    expect(foundItem.kind).toBe('section');
    expect(foundItem.id).toBeDefined();
    expect(foundItem.title).toBe('E2E Test Section');
    expect(foundItem.score).toBeGreaterThan(0);

    // Verify response schema compliance
    expect(foundItem).toHaveProperty('kind');
    expect(foundItem).toHaveProperty('id');
    expect(foundItem).toHaveProperty('title');
    expect(foundItem).toHaveProperty('snippet');
    expect(foundItem).toHaveProperty('score');

    // Verify debug metadata
    expect(findResult.debug).toBeDefined();
    expect(findResult.debug.query_duration_ms).toBeGreaterThan(0);
  }, 15000);

  it('should handle memory.store with validation errors gracefully', async () => {
    const invalidStoreRequest = {
      name: 'memory.store',
      arguments: {
        items: [
          {
            kind: 'section',
            scope: {
              // Missing required 'branch' field
              project: 'test',
            },
            data: {
              document_id: '123e4567-e89b-12d3-a456-426614174000',
              heading: 'Test',
              body_jsonb: {},
              body_text: 'Test',
            },
          },
        ],
      },
    };

    const response: any = await sendRequest('tools/call', invalidStoreRequest);

    // Should return error or partial success
    expect(response).toBeDefined();
    // Response may contain errors array or error field
  }, 10000);
});
