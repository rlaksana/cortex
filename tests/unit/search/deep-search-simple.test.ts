/**
 * Simple test to verify deep-search imports work
 */

import { describe, it, expect, vi } from 'vitest';

// Now import the module without mocking first
const { deepSearch, calculateSimilarity } = await import('../../../src/services/search/deep-search');

describe('Deep Search Service - Simple Tests', () => {
  it('should import functions correctly', () => {
    expect(deepSearch).toBeDefined();
    expect(calculateSimilarity).toBeDefined();
    expect(typeof deepSearch).toBe('function');
    expect(typeof calculateSimilarity).toBe('function');
  });

  it('should handle empty search types', async () => {
    const result = await deepSearch('test query', []);
    expect(result).toEqual([]);
  });
});