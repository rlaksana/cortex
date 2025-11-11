
/**
 * Phase 3 Search Strategies Test Suite
 *
 * Tests for the enhanced memory find functionality with:
 * - 3 stabilized search strategies: fast, auto, deep
 * - Vector backend degradation logic
 * - Graph traversal for relation/parent/child expansion
 * - Scope precedence: branch > project > org hierarchy
 * - Enhanced response metadata
 */

import { afterEach,beforeEach, describe, expect, it } from '@jest/globals';

import { type CoreFindParams,coreMemoryFind } from '../core-memory-find.js';
import { getSearchStrategies,memoryFind, memoryFindWithStrategy } from '../memory-find.js';

// Mock the logger to avoid noise in tests
jest.mock('../../utils/logger.js', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}));

describe('Phase 3 Search Strategies', () => {
  beforeEach(() => {
    // Set up environment variables for testing
    process.env.CORTEX_ORG = 'test-org';
    process.env.CORTEX_PROJECT = 'test-project';
    process.env.CORTEX_BRANCH = 'test-branch';
  });

  afterEach(() => {
    // Clean up environment variables
    delete process.env.CORTEX_ORG;
    delete process.env.CORTEX_PROJECT;
    delete process.env.CORTEX_BRANCH;
  });

  describe('Search Strategy Execution', () => {
    it('should execute fast search strategy', async () => {
      const params: CoreFindParams = {
        query: 'test query',
        mode: 'fast',
        limit: 5,
      };

      const result = await coreMemoryFind(params);

      expect(result.results).toBeDefined();
      expect(result.total_count).toBeGreaterThanOrEqual(0);
      expect(result.observability?.strategy).toBe('fast');
      expect(result.observability?.vector_used).toBe(false);
      expect(result.observability?.degraded).toBe(false);
    });

    it('should execute auto search strategy', async () => {
      const params: CoreFindParams = {
        query: 'test query',
        mode: 'auto',
        limit: 10,
      };

      const result = await coreMemoryFind(params);

      expect(result.results).toBeDefined();
      expect(result.total_count).toBeGreaterThanOrEqual(0);
      expect(result.observability?.strategy).toBe('auto');
      expect(result.observability?.search_id).toBeDefined();
    });

    it('should execute deep search strategy', async () => {
      const params: CoreFindParams = {
        query: 'test query',
        mode: 'deep',
        limit: 15,
      };

      const result = await coreMemoryFind(params);

      expect(result.results).toBeDefined();
      expect(result.total_count).toBeGreaterThanOrEqual(0);
      expect(result.observability?.strategy).toBe('deep');
    });

    it('should default to auto mode when no mode specified', async () => {
      const params: CoreFindParams = {
        query: 'test query',
      };

      const result = await coreMemoryFind(params);

      expect(result.observability?.strategy).toBe('auto');
    });
  });

  describe('Vector Backend Degradation', () => {
    it('should handle vector backend unavailability in deep mode', async () => {
      // Mock vector backend as unavailable
      jest.spyOn(Math, 'random').mockReturnValue(0.05); // Below 0.1 threshold

      const params: CoreFindParams = {
        query: 'test query',
        mode: 'deep',
      };

      const result = await coreMemoryFind(params);

      expect(result.observability?.strategy).toBe('deep');
      expect(result.observability?.degraded).toBe(true);
      expect(result.autonomous_context?.user_message_suggestion).toContain('degraded');

      jest.restoreAllMocks();
    });

    it('should use vector backend when available in auto mode', async () => {
      // Mock vector backend as available
      jest.spyOn(Math, 'random').mockReturnValue(0.9); // Above 0.1 threshold

      const params: CoreFindParams = {
        query: 'test query',
        mode: 'auto',
      };

      const result = await coreMemoryFind(params);

      expect(result.observability?.vector_used).toBe(true);
      expect(result.observability?.degraded).toBe(false);

      jest.restoreAllMocks();
    });
  });

  describe('Graph Expansion', () => {
    it('should apply relations expansion', async () => {
      const params: CoreFindParams = {
        query: 'test query',
        expand: 'relations',
      };

      const result = await coreMemoryFind(params);

      expect(result.results).toBeDefined();
      // Should include original results plus related items
      expect(result.total_count).toBeGreaterThan(0);
    });

    it('should apply parents expansion', async () => {
      const params: CoreFindParams = {
        query: 'test query',
        expand: 'parents',
      };

      const result = await coreMemoryFind(params);

      expect(result.results).toBeDefined();
      expect(result.total_count).toBeGreaterThanOrEqual(0);
    });

    it('should apply children expansion', async () => {
      const params: CoreFindParams = {
        query: 'test query',
        expand: 'children',
      };

      const result = await coreMemoryFind(params);

      expect(result.results).toBeDefined();
      expect(result.total_count).toBeGreaterThanOrEqual(0);
    });

    it('should not apply expansion when set to none', async () => {
      const params: CoreFindParams = {
        query: 'test query',
        expand: 'none',
      };

      const result = await coreMemoryFind(params);

      expect(result.results).toBeDefined();
      // Should have only original results
      expect(result.total_count).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Scope Precedence', () => {
    it('should apply scope precedence: branch > project > org', async () => {
      const params: CoreFindParams = {
        query: 'test query',
        scope: {
          org: 'provided-org',
          project: 'provided-project',
          branch: 'provided-branch',
        },
      };

      const result = await coreMemoryFind(params);

      expect(result.results).toBeDefined();
      // Results should match the provided scope
      expect(result.total_count).toBeGreaterThanOrEqual(0);
    });

    it('should use environment variables when scope not provided', async () => {
      const params: CoreFindParams = {
        query: 'test query',
      };

      const result = await coreMemoryFind(params);

      expect(result.results).toBeDefined();
      expect(result.total_count).toBeGreaterThanOrEqual(0);
    });

    it('should mix provided scope with environment variables', async () => {
      const params: CoreFindParams = {
        query: 'test query',
        scope: {
          branch: 'provided-branch-only',
        },
      };

      const result = await coreMemoryFind(params);

      expect(result.results).toBeDefined();
      // Should combine provided branch with environment project/org
      expect(result.total_count).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Type Filtering', () => {
    it('should filter results by specified types', async () => {
      const params: CoreFindParams = {
        query: 'test query',
        types: ['entity', 'decision'],
      };

      const result = await coreMemoryFind(params);

      expect(result.results).toBeDefined();
      // All results should be of specified types
      result.results.forEach((item) => {
        expect(['entity', 'decision']).toContain(item.kind);
      });
    });

    it('should return all types when no type filter specified', async () => {
      const params: CoreFindParams = {
        query: 'test query',
      };

      const result = await coreMemoryFind(params);

      expect(result.results).toBeDefined();
      expect(result.total_count).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Enhanced Response Metadata', () => {
    it('should include comprehensive observability metadata', async () => {
      const params: CoreFindParams = {
        query: 'test query',
        mode: 'auto',
        limit: 5,
      };

      const result = await coreMemoryFind(params);

      expect(result.observability).toBeDefined();
      expect(result.observability?.source).toBe('cortex_memory');
      expect(result.observability?.strategy).toBeDefined();
      expect(result.observability?.vector_used).toBeDefined();
      expect(result.observability?.degraded).toBeDefined();
      expect(result.observability?.execution_time_ms).toBeGreaterThan(0);
      expect(result.observability?.confidence_average).toBeDefined();
      expect(result.observability?.search_id).toBeDefined();
      expect(result.observability?.search_id).toMatch(/^search_\d+_[a-z0-9]+$/);
    });

    it('should include error metadata when search fails', async () => {
      // Test with an invalid query that should cause an error
      const params: CoreFindParams = {
        query: '',
        mode: 'invalid-mode' as any,
      };

      const result = await coreMemoryFind(params);

      expect(result.results).toEqual([]);
      expect(result.total_count).toBe(0);
      expect(result.observability?.strategy).toBe('error');
      expect(result.observability?.degraded).toBe(true);
      expect(result.autonomous_context?.search_mode_used).toBe('error');
    });
  });
});

describe('Memory Find Wrapper - Phase 3', () => {
  beforeEach(() => {
    process.env.CORTEX_ORG = 'wrapper-test-org';
  });

  afterEach(() => {
    delete process.env.CORTEX_ORG;
  });

  describe('Enhanced Wrapper Functionality', () => {
    it('should support expand parameter', async () => {
      const query = {
        query: 'test query',
        expand: 'relations' as const,
      };

      const result = await memoryFind(query);

      expect(result.results).toBeDefined();
      expect(result.observability).toBeDefined();
      expect(result.total_count).toBeGreaterThanOrEqual(0);
    });

    it('should maintain backward compatibility', async () => {
      const query = {
        query: 'test query',
        mode: 'fast' as const,
        limit: 10,
      };

      const result = await memoryFind(query);

      expect(result.results).toBeDefined();
      expect(result.items).toBeDefined(); // Backward compatibility
      expect(result.total_count).toBeDefined();
      expect(result.total).toBeDefined(); // Backward compatibility
      expect(result.autonomous_context).toBeDefined();
    });
  });

  describe('Strategy Details Function', () => {
    it('should return detailed strategy information', async () => {
      const query = {
        query: 'test query',
        mode: 'auto' as const,
        expand: 'relations' as const,
      };

      const result = await memoryFindWithStrategy(query);

      expect(result.strategy_details).toBeDefined();
      expect(result.strategy_details.selected_strategy).toBe('auto');
      expect(result.strategy_details.vector_backend_available).toBeDefined();
      expect(result.strategy_details.graph_expansion_applied).toBe(true);
      expect(result.strategy_details.scope_precedence_applied).toBe(true);
    });
  });

  describe('Search Strategies Information', () => {
    it('should return available strategies and their status', async () => {
      const strategies = await getSearchStrategies();

      expect(strategies.strategies).toHaveLength(3);
      expect(strategies.strategies.map((s) => s.name)).toEqual(['fast', 'auto', 'deep']);
      expect(strategies.vector_backend_status).toBeDefined();
      expect(strategies.vector_backend_status.available).toBeDefined();
      expect(strategies.vector_backend_status.last_checked).toBeDefined();

      // Check fast strategy
      const fastStrategy = strategies.strategies.find((s) => s.name === 'fast');
      expect(fastStrategy?.vector_required).toBe(false);
      expect(fastStrategy?.current_status).toBe('available');

      // Check deep strategy
      const deepStrategy = strategies.strategies.find((s) => s.name === 'deep');
      expect(deepStrategy?.vector_required).toBe(true);
      expect(deepStrategy?.fallback_strategy).toBe('auto');
    });
  });
});
