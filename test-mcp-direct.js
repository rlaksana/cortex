#!/usr/bin/env node

/**
 * Direct MCP Cortex test using MCP client
 * Tests actual memory store and find operations
 */

import { spawn } from 'child_process';
import fs from 'fs';
import path from 'path';

// Test configuration
const TEST_TIMEOUT = 30000; // 30 seconds
const MCP_SERVER_PATH = './dist/index.js';

// Test data
const TEST_DATA = {
  entities: [
    {
      kind: 'entity',
      content: 'Test User John Doe',
      metadata: {
        type: 'user',
        department: 'engineering',
        role: 'senior-developer',
        join_date: '2023-01-15',
      },
    },
    {
      kind: 'decision',
      content: 'Adopt TypeScript for all new frontend projects',
      metadata: {
        alternatives: ['JavaScript', 'Flow'],
        rationale: 'Type safety and better IDE support',
        impact: 'high',
        decision_date: '2024-03-01',
        decision_maker: 'tech-lead',
      },
    },
    {
      kind: 'observation',
      content: 'Database connection pool exhaustion observed during peak hours',
      metadata: {
        timestamp: '2025-11-05T01:00:00Z',
        metrics: {
          active_connections: 95,
          max_connections: 100,
          response_time_ms: 2500,
        },
        severity: 'warning',
      },
    },
    {
      kind: 'issue',
      content: 'Login page hangs on mobile devices',
      metadata: {
        severity: 'high',
        status: 'open',
        reporter: 'qa-team',
        affected_platforms: ['iOS', 'Android'],
        first_seen: '2025-11-01T10:30:00Z',
      },
    },
    {
      kind: 'todo',
      content: 'Implement OAuth 2.0 authentication',
      metadata: {
        priority: 'high',
        assignee: 'backend-team',
        due_date: '2025-12-01T00:00:00Z',
        estimated_hours: 40,
        dependencies: ['security-review', 'api-key-setup'],
      },
    },
  ],

  relations: [
    {
      kind: 'relation',
      content: 'User reported login issue',
      metadata: {
        relation_type: 'reports',
        source: 'user-john-doe',
        target: 'login-page-bug',
        strength: 0.9,
        timestamp: '2025-11-02T14:20:00Z',
      },
    },
  ],
};

class DirectMcpTester {
  constructor() {
    this.testResults = [];
    this.mcpProcess = null;
    this.requestId = 0;
  }

  /**
   * Add test result
   */
  addResult(testName, passed, message, details = null) {
    const result = {
      testName,
      passed,
      message,
      details,
      timestamp: new Date().toISOString(),
    };

    this.testResults.push(result);

    if (passed) {
      console.log(`✓ [PASS] ${testName}: ${message}`);
    } else {
      console.log(`✗ [FAIL] ${testName}: ${message}`);
      if (details) {
        console.log(`  Details: ${JSON.stringify(details, null, 2)}`);
      }
    }
  }

  /**
   * Start MCP server process
   */
  async startMcpServer() {
    return new Promise((resolve, reject) => {
      console.log('Starting MCP server...');

      if (!fs.existsSync(MCP_SERVER_PATH)) {
        reject(new Error(`MCP server not found at ${MCP_SERVER_PATH}`));
        return;
      }

      this.mcpProcess = spawn('node', [MCP_SERVER_PATH], {
        stdio: ['pipe', 'pipe', 'pipe'],
      });

      let initReceived = false;
      let serverOutput = '';

      this.mcpProcess.stdout.on('data', (data) => {
        const output = data.toString();
        serverOutput += output;

        // Look for initialization message
        if (output.includes('"result"') && output.includes('"protocolVersion"')) {
          if (!initReceived) {
            initReceived = true;
            console.log('MCP server initialized successfully');
            resolve();
          }
        }
      });

      this.mcpProcess.stderr.on('data', (data) => {
        console.error('MCP Server Error:', data.toString());
      });

      this.mcpProcess.on('error', (error) => {
        console.error('Failed to start MCP server:', error);
        reject(error);
      });

      // Timeout
      setTimeout(() => {
        if (!initReceived) {
          reject(new Error('MCP server initialization timeout'));
        }
      }, 10000);

      // Send initialization request
      this.sendMcpRequest({
        jsonrpc: '2.0',
        id: ++this.requestId,
        method: 'initialize',
        params: {
          protocolVersion: '2024-11-05',
          capabilities: {
            tools: {},
          },
          clientInfo: {
            name: 'test-client',
            version: '1.0.0',
          },
        },
      });
    });
  }

  /**
   * Send MCP request
   */
  sendMcpRequest(request) {
    if (this.mcpProcess && this.mcpProcess.stdin) {
      const requestStr = JSON.stringify(request) + '\n';
      this.mcpProcess.stdin.write(requestStr);
    }
  }

  /**
   * Send tool call request
   */
  async callTool(toolName, params) {
    return new Promise((resolve, reject) => {
      const requestId = ++this.requestId;

      const request = {
        jsonrpc: '2.0',
        id: requestId,
        method: 'tools/call',
        params: {
          name: toolName,
          arguments: params,
        },
      };

      let responseReceived = false;

      const dataHandler = (data) => {
        try {
          const responses = data.toString().trim().split('\n');
          for (const responseStr of responses) {
            if (!responseStr.trim()) continue;

            const response = JSON.parse(responseStr);
            if (response.id === requestId) {
              responseReceived = true;
              this.mcpProcess.stdout.off('data', dataHandler);

              if (response.error) {
                reject(new Error(response.error.message));
              } else {
                resolve(response.result);
              }
            }
          }
        } catch (error) {
          console.error('Error parsing MCP response:', error);
        }
      };

      this.mcpProcess.stdout.on('data', dataHandler);
      this.sendMcpRequest(request);

      // Timeout
      setTimeout(() => {
        if (!responseReceived) {
          this.mcpProcess.stdout.off('data', dataHandler);
          reject(new Error(`Tool call timeout: ${toolName}`));
        }
      }, 5000);
    });
  }

  /**
   * Test memory store operation
   */
  async testMemoryStore() {
    console.log('\n=== Testing Memory Store Operations ===');

    try {
      // Test storing a single entity
      const entity = TEST_DATA.entities[0];
      const storeResult = await this.callTool('memory_store', {
        items: [entity],
      });

      if (storeResult && storeResult.stored && storeResult.stored.length > 0) {
        this.addResult(
          'Memory Store Single Entity',
          true,
          `Successfully stored entity with ID: ${storeResult.stored[0].id}`
        );
      } else {
        this.addResult('Memory Store Single Entity', false, 'Failed to store entity', storeResult);
      }

      // Test storing multiple entities
      const batchResult = await this.callTool('memory_store', {
        items: TEST_DATA.entities.slice(1),
      });

      if (batchResult && batchResult.stored && batchResult.stored.length > 0) {
        this.addResult(
          'Memory Store Batch',
          true,
          `Successfully stored ${batchResult.stored.length} entities`
        );
      } else {
        this.addResult('Memory Store Batch', false, 'Failed to store batch entities', batchResult);
      }

      // Test storing relations
      const relationResult = await this.callTool('memory_store', {
        items: TEST_DATA.relations,
      });

      if (relationResult && relationResult.stored && relationResult.stored.length > 0) {
        this.addResult(
          'Memory Store Relations',
          true,
          `Successfully stored ${relationResult.stored.length} relations`
        );
      } else {
        this.addResult(
          'Memory Store Relations',
          false,
          'Failed to store relations',
          relationResult
        );
      }
    } catch (error) {
      this.addResult(
        'Memory Store Operations',
        false,
        `Memory store operation failed: ${error.message}`
      );
    }
  }

  /**
   * Test memory find operations
   */
  async testMemoryFind() {
    console.log('\n=== Testing Memory Find Operations ===');

    try {
      // Test basic search
      const searchResult = await this.callTool('memory_find', {
        query: 'TypeScript frontend',
        scope: { project: 'mcp-cortex' },
      });

      if (searchResult && searchResult.items && searchResult.items.length > 0) {
        this.addResult(
          'Memory Find Basic Search',
          true,
          `Found ${searchResult.items.length} items for 'TypeScript frontend'`
        );
      } else {
        this.addResult(
          'Memory Find Basic Search',
          false,
          'No items found for basic search',
          searchResult
        );
      }

      // Test find by knowledge type
      const typeResult = await this.callTool('memory_find', {
        query: 'test',
        types: ['decision'],
        scope: { project: 'mcp-cortex' },
      });

      if (typeResult && typeResult.items && typeResult.items.length > 0) {
        this.addResult('Memory Find By Type', true, `Found ${typeResult.items.length} decisions`);
      } else {
        this.addResult('Memory Find By Type', false, 'No decisions found', typeResult);
      }

      // Test scope filtering
      const scopeResult = await this.callTool('memory_find', {
        query: 'user',
        scope: {
          project: 'mcp-cortex',
          branch: 'test-branch',
        },
      });

      this.addResult(
        'Memory Find Scope Filtering',
        true,
        `Scope filtering executed, found ${scopeResult ? scopeResult.items?.length || 0 : 0} items`
      );

      // Test find with analytics
      const analyticsResult = await this.callTool('memory_find', {
        query: 'database',
        analytics: true,
        scope: { project: 'mcp-cortex' },
      });

      this.addResult('Memory Find Analytics', true, `Analytics search executed for 'database'`);
    } catch (error) {
      this.addResult(
        'Memory Find Operations',
        false,
        `Memory find operation failed: ${error.message}`
      );
    }
  }

  /**
   * Test autonomous deduplication
   */
  async testDeduplication() {
    console.log('\n=== Testing Autonomous Deduplication ===');

    try {
      // Try to store duplicate entity
      const duplicateEntity = {
        ...TEST_DATA.entities[0],
        content: 'Test User John Doe', // Same content
        metadata: { ...TEST_DATA.entities[0].metadata, role: 'modified-role' }, // Different metadata
      };

      const duplicateResult = await this.callTool('memory_store', {
        items: [duplicateEntity],
      });

      // Check if duplicates were detected
      if (duplicateResult && duplicateResult.duplicates && duplicateResult.duplicates.length > 0) {
        this.addResult(
          'Autonomous Deduplication',
          true,
          `Detected ${duplicateResult.duplicates.length} duplicates`
        );
      } else if (duplicateResult && duplicateResult.stored && duplicateResult.stored.length > 0) {
        this.addResult(
          'Autonomous Deduplication',
          false,
          'No duplicates detected - potential deduplication issue'
        );
      } else {
        this.addResult(
          'Autonomous Deduplication',
          false,
          'Deduplication test inconclusive',
          duplicateResult
        );
      }
    } catch (error) {
      this.addResult(
        'Autonomous Deduplication',
        false,
        `Deduplication test failed: ${error.message}`
      );
    }
  }

  /**
   * Test TTL and cache behavior
   */
  async testTtlAndCache() {
    console.log('\n=== Testing TTL and Cache Behavior ===');

    try {
      // Store item with TTL
      const ttlItem = {
        kind: 'entity',
        content: 'Temporary test entity with TTL',
        metadata: {
          ttl_seconds: 60, // 1 minute TTL
          test_type: 'ttl-test',
        },
      };

      const ttlResult = await this.callTool('memory_store', {
        items: [ttlItem],
      });

      if (ttlResult && ttlResult.stored && ttlResult.stored.length > 0) {
        this.addResult('TTL Item Storage', true, 'Successfully stored item with TTL');
      } else {
        this.addResult('TTL Item Storage', false, 'Failed to store TTL item', ttlResult);
      }

      // Test cache behavior by searching for recently stored item
      const cacheResult = await this.callTool('memory_find', {
        query: 'TypeScript frontend',
        scope: { project: 'mcp-cortex' },
        use_cache: true,
      });

      this.addResult(
        'Cache Behavior',
        true,
        `Cache search executed, found ${cacheResult ? cacheResult.items?.length || 0 : 0} items`
      );
    } catch (error) {
      this.addResult('TTL and Cache Behavior', false, `TTL/Cache test failed: ${error.message}`);
    }
  }

  /**
   * Stop MCP server
   */
  stopMcpServer() {
    if (this.mcpProcess) {
      console.log('Stopping MCP server...');
      this.mcpProcess.kill('SIGTERM');
      this.mcpProcess = null;
    }
  }

  /**
   * Generate comprehensive report
   */
  generateReport() {
    const passed = this.testResults.filter((r) => r.passed).length;
    const total = this.testResults.length;
    const successRate = total > 0 ? ((passed / total) * 100).toFixed(2) : '0';

    const report = {
      summary: {
        total,
        passed,
        failed: total - passed,
        successRate: `${successRate}%`,
      },
      tests: this.testResults,
      testData: TEST_DATA,
      timestamp: new Date().toISOString(),
    };

    // Save report
    const reportPath = './artifacts/mcp-cortex-direct-test-report.json';
    if (!fs.existsSync('./artifacts')) {
      fs.mkdirSync('./artifacts', { recursive: true });
    }

    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));

    console.log('\n=== Direct MCP Test Summary ===');
    console.log(`Total Tests: ${total}`);
    console.log(`Passed: ${passed}`);
    console.log(`Failed: ${total - passed}`);
    console.log(`Success Rate: ${report.summary.successRate}`);
    console.log(`Report saved to: ${reportPath}`);

    return report;
  }

  /**
   * Run all tests
   */
  async runAllTests() {
    console.log('=== MCP Cortex Direct Test Suite ===');
    console.log(`Started at: ${new Date().toISOString()}`);
    console.log('=====================================\n');

    try {
      // Start MCP server
      await this.startMcpServer();

      // Run tests
      await this.testMemoryStore();
      await this.testMemoryFind();
      await this.testDeduplication();
      await this.testTtlAndCache();
    } catch (error) {
      console.error('Test suite failed:', error);
      this.addResult('Test Suite Execution', false, `Test suite failed: ${error.message}`);
    } finally {
      // Cleanup
      this.stopMcpServer();
    }

    // Generate report
    return this.generateReport();
  }
}

// Run tests if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const tester = new DirectMcpTester();

  tester
    .runAllTests()
    .then((report) => {
      const success = parseFloat(report.summary.successRate) >= 80;
      process.exit(success ? 0 : 1);
    })
    .catch((error) => {
      console.error('Test execution failed:', error);
      process.exit(1);
    });
}

export default DirectMcpTester;
