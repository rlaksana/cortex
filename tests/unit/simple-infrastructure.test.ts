/**
 * Simple test to verify testing infrastructure works
 */

import { describe, it, expect } from 'vitest';

describe('Testing Infrastructure', () => {
  it('should run a simple test', () => {
    expect(1 + 1).toBe(2);
  });

  it('should handle async operations', async () => {
    const result = await Promise.resolve(42);
    expect(result).toBe(42);
  });
});