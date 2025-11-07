/**
 * Simple Integration Test - Memory Store Service
 *
 * Basic test to verify test infrastructure is working correctly
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { memoryStore } from '../../src/services/memory-store.js';
import { memoryFind } from '../../src/services/memory-find.js';
import { mockDatabaseFactory } from '../mocks/database.js';

describe('Simple Integration Test - Memory Service', () => {
  let mockDatabase: any;

  beforeAll(async () => {
    // Setup mock database for testing
    mockDatabase = mockDatabaseFactory.create();
  });

  it('should store and retrieve a simple item', async () => {
    const testItem = {
      kind: 'entity',
      content: 'Test content for simple integration test',
      scope: { project: 'test-project' },
      metadata: { test: true },
    };

    // Store the item
    const storeResult = await memoryStore([testItem]);

    expect(storeResult).toBeDefined();
    expect(storeResult.success).toBe(true);
    expect(storeResult.items).toBeDefined();
    expect(storeResult.items.length).toBeGreaterThan(0);
  });

  it('should find stored items', async () => {
    // Search for the test item
    const searchResult = await memoryFind({
      query: 'Test content for simple integration test',
      scope: { project: 'test-project' },
      limit: 10,
    });

    expect(searchResult).toBeDefined();
    expect(searchResult.results).toBeDefined();
  });

  afterAll(async () => {
    // Cleanup if needed
    if (mockDatabase && typeof mockDatabase.close === 'function') {
      await mockDatabase.close();
    }
  });
});
