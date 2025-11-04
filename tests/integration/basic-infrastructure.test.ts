/**
 * Basic Infrastructure Test
 *
 * Tests that the basic test infrastructure is working correctly
 */

import { describe, it, expect } from 'vitest';
import { mockDatabaseFactory } from '../mocks/database.js';

describe('Basic Infrastructure Test', () => {
  it('should load test dependencies correctly', () => {
    // Test that basic dependencies are available
    expect(mockDatabaseFactory).toBeDefined();
    expect(mockDatabaseFactory.create).toBeDefined();
    expect(typeof mockDatabaseFactory.create).toBe('function');
  });

  it('should create mock database correctly', () => {
    const mockDb = mockDatabaseFactory.create();

    expect(mockDb).toBeDefined();
    expect(mockDb.healthCheck).toBeDefined();
    expect(mockDb.store).toBeDefined();
    expect(mockDb.find).toBeDefined();
    expect(typeof mockDb.healthCheck).toBe('function');
    expect(typeof mockDb.store).toBe('function');
    expect(typeof mockDb.find).toBe('function');
  });

  it('should handle async operations correctly', async () => {
    const mockDb = mockDatabaseFactory.create();

    // Test that async operations work
    const healthCheckResult = await mockDb.healthCheck();
    expect(healthCheckResult).toBeDefined();
    expect(healthCheckResult.status).toBe('healthy');

    // Test store operation
    const storeResult = await mockDb.store([{ test: 'data' }]);
    expect(storeResult).toBeDefined();
    expect(Array.isArray(storeResult)).toBe(true);

    // Test search operation (mock uses 'search' instead of 'find')
    const searchResult = await mockDb.search({ query: 'test' });
    expect(searchResult).toBeDefined();
    expect(searchResult.results).toBeDefined();
  });

  it('should verify vitest test framework is working', () => {
    // Basic sanity checks for vitest
    expect(1 + 1).toBe(2);
    expect('test').toContain('test');
    expect([1, 2, 3]).toHaveLength(3);
  });
});