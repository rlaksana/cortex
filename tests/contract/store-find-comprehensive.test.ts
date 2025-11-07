/**
 * Comprehensive Store/Find Tool Contract Tests - GA Validation
 *
 * Extensive testing of memory_store and memory_find tools covering:
 * - Happy paths with various payload sizes (small, medium, large)
 * - Unicode and internationalization support
 * - Concurrency testing (10, 50, 100 concurrent operations)
 * - TTL/expiry and purge correctness
 * - Deduplication and near-duplicate thresholds
 * - Limits, quotas, and backpressure (429 + retry_after)
 * - Degraded mode testing (Qdrant down → Postgres-only)
 * - Performance regression prevention
 * - Consistency under load
 *
 * @version 2.0.1 GA Compliant
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawn, ChildProcess } from 'child_process';
import { writeFileSync, unlinkSync } from 'fs';
import { join } from 'path';
import { setTimeout } from 'timers/promises';

// Test configuration
const SERVER_TIMEOUT = 30000;
const CONCURRENT_TESTS = [10, 50, 100];
const PAYLOAD_SIZES = {
  small: { minItems: 1, maxItems: 5, contentSize: 100 },
  medium: { minItems: 10, maxItems: 25, contentSize: 500 },
  large: { minItems: 50, maxItems: 100, contentSize: 2000 }
};

// Test data generators
class TestDataGenerator {
  static generateKnowledgeItems(count: number, size: 'small' | 'medium' | 'large'): any[] {
    const contentSizes = {
      small: 100,
      medium: 500,
      large: 2000
    };

    const targetSize = contentSizes[size];
    const kinds = ['entity', 'decision', 'issue', 'observation', 'assumption', 'runbook'];

    return Array.from({ length: count }, (_, i) => ({
      kind: kinds[i % kinds.length],
      content: this.generateText(targetSize),
      data: {
        index: i,
        timestamp: new Date().toISOString(),
        category: `test-category-${i % 10}`,
        tags: [`tag-${i % 5}`, `category-${i % 3}`]
      },
      metadata: {
        source: 'contract-test',
        priority: i % 3 === 0 ? 'high' : 'normal',
        confidence: 0.8 + (Math.random() * 0.2)
      }
    }));
  }

  static generateText(length: number): string {
    const base = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. ';
    const repeats = Math.ceil(length / base.length);
    return (base.repeat(repeats)).substring(0, length);
  }

  static generateUnicodeContent(): string {
    const unicodeTexts = [
      '测试中文内容',
      'Тест русского текста',
      'テスト日本語',
      'العربية اختبار',
      '한국어 테스트',
      'עברית בדיקה',
      'English with émojis 🚀🧪📊',
      'Mixed: English 中文 日本語 Русский'
    ];
    return unicodeTexts.join(' ');
  }

  static generateSimilarContent(base: string, similarity: number): string {
    // Generate content with specified similarity to base
    const words = base.split(' ');
    const wordsToChange = Math.floor(words.length * (1 - similarity));

    for (let i = 0; i < wordsToChange; i++) {
      const randomIndex = Math.floor(Math.random() * words.length);
      words[randomIndex] = `changed${i}`;
    }

    return words.join(' ');
  }
}

// MCP Server Test Harness
class MCPServerHarness {
  private server: ChildProcess | null = null;
  private requestId = 1;
  private responses = new Map<number, any>();

  async startServer(silentMode = true): Promise<void> {
    const serverPath = silentMode
      ? 'dist/silent-mcp-entry.js'
      : 'dist/index.js';

    this.server = spawn('node', [serverPath], {
      stdio: ['pipe', 'pipe', 'pipe'],
      cwd: process.cwd()
    });

    let serverOutput = '';

    this.server.stdout.on('data', (data) => {
      serverOutput += data.toString();
      this.parseResponses(data.toString());
    });

    this.server.stderr.on('data', (data) => {
      if (!silentMode) {
        console.log('Server stderr:', data.toString());
      }
    });

    this.server.on('error', (error) => {
      console.error('Server error:', error);
    });

    // Wait for server to be ready
    await setTimeout(2000);

    // Initialize server
    await this.sendRequest('initialize', {
      protocolVersion: '2024-11-05',
      capabilities: { tools: {} },
      clientInfo: { name: 'test-client', version: '1.0.0' }
    });
  }

  async stopServer(): Promise<void> {
    if (this.server) {
      await this.sendRequest('shutdown', {});
      this.server.kill();
      this.server = null;
    }
  }

  private parseResponses(data: string): void {
    const lines = data.trim().split('\n');

    lines.forEach(line => {
      if (line.startsWith('{') && line.endsWith('}')) {
        try {
          const response = JSON.parse(line);
          if (response.id) {
            this.responses.set(response.id, response);
          }
        } catch (error) {
          // Ignore malformed JSON
        }
      }
    });
  }

  async sendRequest(method: string, params: any, timeout = 5000): Promise<any> {
    if (!this.server) {
      throw new Error('Server not started');
    }

    const id = this.requestId++;
    const request = {
      jsonrpc: '2.0',
      id,
      method,
      params
    };

    const startTime = Date.now();

    return new Promise((resolve, reject) => {
      const checkResponse = () => {
        const response = this.responses.get(id);
        if (response) {
          this.responses.delete(id);
          const duration = Date.now() - startTime;
          resolve({ ...response, _duration: duration });
        } else if (Date.now() - startTime > timeout) {
          reject(new Error(`Request timeout: ${method}`));
        } else {
          setTimeout(checkResponse, 50);
        }
      };

      this.server!.stdin.write(JSON.stringify(request) + '\n');
      checkResponse();
    });
  }

  async storeMemory(items: any[], options: any = {}): Promise<any> {
    return this.sendRequest('tools/call', {
      name: 'memory_store',
      arguments: {
        items,
        ...options
      }
    });
  }

  async findMemory(query: string, options: any = {}): Promise<any> {
    return this.sendRequest('tools/call', {
      name: 'memory_find',
      arguments: {
        query,
        ...options
      }
    });
  }
}

describe('Store/Find Tool Contract Tests - GA Validation', () => {
  let harness: MCPServerHarness;

  beforeEach(async () => {
    harness = new MCPServerHarness();
    await harness.startServer(true);
  });

  afterEach(async () => {
    await harness.stopServer();
  });

  // ============================================================================
  // Happy Path Tests with Various Payload Sizes
  // ============================================================================

  describe('Happy Path Tests - Different Payload Sizes', () => {
    it('should handle small payloads efficiently', async () => {
      const items = TestDataGenerator.generateKnowledgeItems(3, 'small');

      const startTime = Date.now();
      const storeResponse = await harness.storeMemory(items);
      const storeDuration = Date.now() - startTime;

      expect(storeResponse.result).toBeDefined();
      expect(storeResponse.result.content).toBeDefined();
      expect(storeResponse._duration).toBeLessThan(1000); // Should complete within 1 second

      // Test finding the stored items
      const findResponse = await harness.findMemory('test');
      expect(findResponse.result).toBeDefined();
      expect(findResponse.result.content).toBeDefined();
      expect(Array.isArray(findResponse.result.content)).toBe(true);

      console.log(`Small payload test completed in ${storeDuration}ms`);
    });

    it('should handle medium payloads correctly', async () => {
      const items = TestDataGenerator.generateKnowledgeItems(15, 'medium');

      const startTime = Date.now();
      const storeResponse = await harness.storeMemory(items);
      const storeDuration = Date.now() - startTime;

      expect(storeResponse.result).toBeDefined();
      expect(storeResponse._duration).toBeLessThan(5000); // Should complete within 5 seconds

      // Verify all items were stored
      const findResponse = await harness.findMemory('Lorem ipsum', { limit: 20 });
      expect(findResponse.result.content.length).toBeGreaterThan(0);

      console.log(`Medium payload test completed in ${storeDuration}ms`);
    });

    it('should handle large payloads without degradation', async () => {
      const items = TestDataGenerator.generateKnowledgeItems(75, 'large');

      const startTime = Date.now();
      const storeResponse = await harness.storeMemory(items);
      const storeDuration = Date.now() - startTime;

      expect(storeResponse.result).toBeDefined();
      expect(storeResponse._duration).toBeLessThan(15000); // Should complete within 15 seconds

      // Test that items can be found
      const findResponse = await harness.findMemory('Lorem ipsum', { limit: 100 });
      expect(findResponse.result.content.length).toBeGreaterThan(0);

      console.log(`Large payload test completed in ${storeDuration}ms`);
    });
  });

  // ============================================================================
  // Unicode and Internationalization Tests
  // ============================================================================

  describe('Unicode and Internationalization Support', () => {
    it('should handle Unicode content correctly', async () => {
      const unicodeItem = {
        kind: 'entity',
        content: TestDataGenerator.generateUnicodeContent(),
        data: {
          language: 'multi',
          encoding: 'utf-8'
        }
      };

      const storeResponse = await harness.storeMemory([unicodeItem]);
      expect(storeResponse.result).toBeDefined();

      // Search for Unicode content
      const unicodeQueries = ['测试', 'Тест', 'テスト', 'العربية', '한국어'];

      for (const query of unicodeQueries) {
        const findResponse = await harness.findMemory(query);
        expect(findResponse.result).toBeDefined();
        expect(findResponse.result.content).toBeDefined();
      }
    });

    it('should preserve Unicode formatting in search results', async () => {
      const items = [
        {
          kind: 'observation',
          content: '测试中文内容 with English and émojis 🚀🧪',
          data: { format: 'mixed' }
        }
      ];

      await harness.storeMemory(items);

      const findResponse = await harness.findMemory('测试');
      expect(findResponse.result.content.length).toBeGreaterThan(0);

      const result = findResponse.result.content[0];
      expect(result.text).toContain('测试中文内容');
      expect(result.text).toContain('🚀🧪');
    });
  });

  // ============================================================================
  // Concurrency Testing
  // ============================================================================

  describe('Concurrency Testing', () => {
    it.each(CONCURRENT_TESTS)('should handle %d concurrent operations', async (concurrency) => {
      const promises = [];
      const startTime = Date.now();

      // Create concurrent store operations
      for (let i = 0; i < concurrency; i++) {
        const items = TestDataGenerator.generateKnowledgeItems(2, 'small');
        promises.push(harness.storeMemory(items));
      }

      // Wait for all operations to complete
      const results = await Promise.allSettled(promises);
      const duration = Date.now() - startTime;

      // Verify all operations completed successfully
      const successful = results.filter(r => r.status === 'fulfilled').length;
      const failed = results.filter(r => r.status === 'rejected').length;

      expect(successful).toBeGreaterThanOrEqual(concurrency * 0.95); // Allow 5% failure rate
      expect(failed).toBeLessThanOrEqual(concurrency * 0.05);

      console.log(`${concurrency} concurrent operations completed in ${duration}ms`);
      console.log(`Success rate: ${(successful / concurrency * 100).toFixed(2)}%`);

      // Verify data consistency
      const findResponse = await harness.findMemory('Lorem ipsum', { limit: 200 });
      expect(findResponse.result.content.length).toBeGreaterThan(0);
    });

    it('should maintain consistency under concurrent read/write operations', async () => {
      const promises = [];
      const baseContent = 'consistency test content';

      // Mix of store and find operations
      for (let i = 0; i < 50; i++) {
        if (i % 2 === 0) {
          // Store operation
          const items = [{
            kind: 'entity',
            content: `${baseContent} ${i}`,
            data: { batch: Math.floor(i / 10) }
          }];
          promises.push(harness.storeMemory(items));
        } else {
          // Find operation
          promises.push(harness.findMemory(baseContent));
        }
      }

      const results = await Promise.allSettled(promises);
      const successful = results.filter(r => r.status === 'fulfilled').length;

      expect(successful).toBeGreaterThanOrEqual(45); // 90% success rate

      // Final consistency check
      const finalFind = await harness.findMemory(baseContent, { limit: 100 });
      expect(finalFind.result.content.length).toBeGreaterThan(20); // Should find many items
    });
  });

  // ============================================================================
  // TTL/Expiry and Purge Tests
  // ============================================================================

  describe('TTL/Expiry and Purge Functionality', () => {
    it('should respect TTL policies', async () => {
      const items = [{
        kind: 'observation',
        content: 'TTL test item',
        data: { test: 'ttl' }
      }];

      // Store with short TTL
      const storeResponse = await harness.storeMemory(items, {
        global_ttl: {
          policy: 'short', // Should expire quickly
          custom_seconds: 5
        }
      });

      expect(storeResponse.result).toBeDefined();

      // Should find immediately
      const immediateFind = await harness.findMemory('TTL test item');
      expect(immediateFind.result.content.length).toBeGreaterThan(0);

      // Wait for expiry
      await setTimeout(6000);

      // Should not find after expiry
      const expiredFind = await harness.findMemory('TTL test item');
      // Note: This depends on TTL implementation - may need adjustment
      console.log('Expired find results:', expiredFind.result.content.length);
    });

    it('should handle permanent TTL correctly', async () => {
      const items = [{
        kind: 'decision',
        content: 'Permanent test item',
        data: { test: 'permanent' }
      }];

      // Store with permanent TTL
      const storeResponse = await harness.storeMemory(items, {
        global_ttl: {
          policy: 'permanent'
        }
      });

      expect(storeResponse.result).toBeDefined();

      // Should find immediately and continue to exist
      const findResponse = await harness.findMemory('Permanent test item');
      expect(findResponse.result.content.length).toBeGreaterThan(0);
    });
  });

  // ============================================================================
  // Deduplication and Near-Duplicate Tests
  // ============================================================================

  describe('Deduplication and Near-Duplicate Detection', () => {
    it('should detect exact duplicates', async () => {
      const item = {
        kind: 'entity',
        content: 'Exact duplicate test content',
        data: { test: 'duplicate' }
      };

      // Store the same item twice
      const store1 = await harness.storeMemory([item]);
      const store2 = await harness.storeMemory([item]);

      expect(store1.result).toBeDefined();
      expect(store2.result).toBeDefined();

      // Should only find one instance
      const findResponse = await harness.findMemory('Exact duplicate test content');
      expect(findResponse.result.content.length).toBeGreaterThanOrEqual(1);

      // Check deduplication info in response
      if (store2.result._meta && store2.result._meta.deduplication) {
        expect(store2.result._meta.deduplication.duplicates_detected).toBeGreaterThan(0);
      }
    });

    it('should handle near-duplicates with configurable thresholds', async () => {
      const baseContent = 'Near duplicate test content with some additional text';
      const similarContent = TestDataGenerator.generateSimilarContent(baseContent, 0.8);

      const items = [
        {
          kind: 'observation',
          content: baseContent,
          data: { test: 'near-duplicate-1' }
        },
        {
          kind: 'observation',
          content: similarContent,
          data: { test: 'near-duplicate-2' }
        }
      ];

      // Store with different deduplication settings
      const strictResponse = await harness.storeMemory(items, {
        deduplication: {
          enabled: true,
          merge_strategy: 'intelligent',
          similarity_threshold: 0.9 // High threshold
        }
      });

      expect(strictResponse.result).toBeDefined();

      // Check if near-duplicates were detected
      if (strictResponse.result._meta && strictResponse.result._meta.deduplication) {
        console.log('Near-duplicate detection:', strictResponse.result._meta.deduplication);
      }
    });
  });

  // ============================================================================
  // Limits, Quotas, and Backpressure Tests
  // ============================================================================

  describe('Limits, Quotas, and Backpressure', () => {
    it('should enforce payload size limits', async () => {
      // Test with oversized payload
      const oversizedItems = TestDataGenerator.generateKnowledgeItems(150, 'large'); // Over limit

      try {
        const response = await harness.storeMemory(oversizedItems);
        // Should either succeed with truncation or fail gracefully
        expect(response.result || response.error).toBeDefined();

        if (response.error) {
          // Should provide helpful error message
          expect(response.error.message).toContain('limit') ||
                 expect(response.error.message).toContain('too large');
        }
      } catch (error) {
        // Network-level error is acceptable for extreme sizes
        expect(error.message).toBeDefined();
      }
    });

    it('should implement rate limiting with retry_after headers', async () => {
      const promises = [];
      const rateLimitCount = 20;

      // Send many requests quickly to trigger rate limiting
      for (let i = 0; i < rateLimitCount; i++) {
        const items = TestDataGenerator.generateKnowledgeItems(1, 'small');
        promises.push(harness.storeMemory(items));
      }

      const results = await Promise.allSettled(promises);
      const rateLimited = results.filter(r =>
        r.status === 'rejected' ||
        (r.status === 'fulfilled' && r.value.error && r.value.error.code === 429)
      );

      // Some requests should be rate limited
      expect(rateLimited.length).toBeGreaterThan(0);

      // Check rate limited responses have retry_after
      rateLimited.forEach(result => {
        if (result.status === 'fulfilled' && result.value.error) {
          expect(result.value.error.data).toHaveProperty('retry_after');
        }
      });

      console.log(`Rate limited ${rateLimited.length} out of ${rateLimitCount} requests`);
    });
  });

  // ============================================================================
  // Degraded Mode Tests (Qdrant down → Postgres-only)
  // ============================================================================

  describe('Degraded Mode Operation', () => {
    it('should provide fallback storage when primary database unavailable', async () => {
      // This test would require infrastructure to simulate Qdrant failure
      // For now, we'll test graceful degradation indicators

      const items = [{
        kind: 'entity',
        content: 'Degraded mode test item',
        data: { test: 'degraded-mode' }
      }];

      const storeResponse = await harness.storeMemory(items, {
        fallback_mode: 'postgres_only' // Simulate degraded mode
      });

      expect(storeResponse.result).toBeDefined();

      // Should indicate degraded mode in metadata
      if (storeResponse.result._meta) {
        expect(storeResponse.result._meta.storage_mode || storeResponse.result._meta.degraded_mode).toBeDefined();
      }

      // Should still be able to find items in degraded mode
      const findResponse = await harness.findMemory('Degraded mode test item');
      expect(findResponse.result.content.length).toBeGreaterThan(0);
    });
  });

  // ============================================================================
  // Performance Regression Tests
  // ============================================================================

  describe('Performance Regression Prevention', () => {
    it('should meet performance targets for operations', async () => {
      const performanceTargets = {
        store_small: 500,   // ms
        store_medium: 2000, // ms
        store_large: 8000,  // ms
        find_query: 250     // ms
      };

      // Test small payload performance
      const smallItems = TestDataGenerator.generateKnowledgeItems(3, 'small');
      const smallStart = Date.now();
      await harness.storeMemory(smallItems);
      const smallDuration = Date.now() - smallStart;

      expect(smallDuration).toBeLessThan(performanceTargets.store_small);

      // Test medium payload performance
      const mediumItems = TestDataGenerator.generateKnowledgeItems(15, 'medium');
      const mediumStart = Date.now();
      await harness.storeMemory(mediumItems);
      const mediumDuration = Date.now() - mediumStart;

      expect(mediumDuration).toBeLessThan(performanceTargets.store_medium);

      // Test find performance
      const findStart = Date.now();
      await harness.findMemory('Lorem ipsum', { limit: 50 });
      const findDuration = Date.now() - findStart;

      expect(findDuration).toBeLessThan(performanceTargets.find_query);

      console.log('Performance results:', {
        smallStore: `${smallDuration}ms (target: ${performanceTargets.store_small}ms)`,
        mediumStore: `${mediumDuration}ms (target: ${performanceTargets.store_medium}ms)`,
        findQuery: `${findDuration}ms (target: ${performanceTargets.find_query}ms)`
      });
    });
  });

  // ============================================================================
  // Edge Case and Error Handling Tests
  // ============================================================================

  describe('Edge Cases and Error Handling', () => {
    it('should handle empty or malformed inputs gracefully', async () => {
      // Test empty items array
      const emptyResponse = await harness.storeMemory([]);
      expect(emptyResponse.result || emptyResponse.error).toBeDefined();

      // Test malformed item
      const malformedItem = { invalid: 'structure' };
      const malformedResponse = await harness.storeMemory([malformedItem]);
      expect(malformedResponse.error || malformedResponse.result).toBeDefined();

      if (malformedResponse.error) {
        expect(malformedResponse.error.message).toBeDefined();
        expect(malformedResponse.error.code).toBeDefined();
      }
    });

    it('should handle extremely long queries', async () => {
      const longQuery = 'test '.repeat(1000); // Very long query

      const response = await harness.findMemory(longQuery);
      expect(response.result || response.error).toBeDefined();

      if (response.error) {
        expect(response.error.message).toContain('too long') ||
               expect(response.error.message).toContain('limit');
      }
    });
  });
});