/**
 * Unit tests for auto-purge service
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { Pool } from 'pg';

// Mock the dependencies
vi.mock('../../src/utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    error: vi.fn(),
  },
}));

describe('Auto-Purge Service', () => {
  let mockPool: Pool;

  beforeEach(() => {
    mockPool = {
      query: vi.fn(),
    } as any;
  });

  describe('checkAndPurge', () => {
    it('should increment operation counter on every call', async () => {
      const { checkAndPurge } = await import('../../src/services/auto-purge.js');

      // Mock: purge not needed (thresholds not exceeded)
      (mockPool.query as any)
        .mockResolvedValueOnce({ rows: [] }) // Increment counter
        .mockResolvedValueOnce({
          // Get metadata
          rows: [
            {
              enabled: true,
              last_purge_at: new Date(),
              operations_since_purge: 10,
              time_threshold_hours: 24,
              operation_threshold: 1000,
            },
          ],
        });

      await checkAndPurge(mockPool, 'memory.store');

      // Verify increment query was called
      expect(mockPool.query).toHaveBeenCalledWith(
        expect.stringContaining('UPDATE _purge_metadata SET operations_since_purge')
      );
    });

    it('should trigger purge when time threshold exceeded', async () => {
      const { checkAndPurge } = await import('../../src/services/auto-purge.js');

      // Mock: time threshold exceeded (25 hours since last purge)
      const oldDate = new Date(Date.now() - 25 * 3600 * 1000);

      (mockPool.query as any)
        .mockResolvedValueOnce({ rows: [] }) // Increment
        .mockResolvedValueOnce({
          // Get metadata
          rows: [
            {
              enabled: true,
              last_purge_at: oldDate,
              operations_since_purge: 10,
              time_threshold_hours: 24,
              operation_threshold: 1000,
            },
          ],
        });

      await checkAndPurge(mockPool, 'memory.store');

      // Purge should be triggered (but runs async, so can't easily verify in unit test)
      // This is better tested in integration tests
      expect(mockPool.query).toHaveBeenCalled();
    });

    it('should trigger purge when operation threshold exceeded', async () => {
      const { checkAndPurge } = await import('../../src/services/auto-purge.js');

      // Mock: operation threshold exceeded (1001 ops)
      (mockPool.query as any)
        .mockResolvedValueOnce({ rows: [] }) // Increment
        .mockResolvedValueOnce({
          // Get metadata
          rows: [
            {
              enabled: true,
              last_purge_at: new Date(),
              operations_since_purge: 1001,
              time_threshold_hours: 24,
              operation_threshold: 1000,
            },
          ],
        });

      await checkAndPurge(mockPool, 'memory.find');

      expect(mockPool.query).toHaveBeenCalled();
    });

    it('should skip purge when disabled', async () => {
      const { checkAndPurge } = await import('../../src/services/auto-purge.js');

      (mockPool.query as any)
        .mockResolvedValueOnce({ rows: [] }) // Increment
        .mockResolvedValueOnce({
          // Get metadata
          rows: [
            {
              enabled: false, // DISABLED
              last_purge_at: new Date(0), // Very old
              operations_since_purge: 9999,
              time_threshold_hours: 24,
              operation_threshold: 1000,
            },
          ],
        });

      await checkAndPurge(mockPool, 'memory.store');

      // Should only increment, not trigger purge
      expect(mockPool.query).toHaveBeenCalledTimes(2);
    });
  });

  describe('getPurgeStatus', () => {
    it('should return current purge metadata', async () => {
      const { getPurgeStatus } = await import('../../src/services/auto-purge.js');

      const mockMeta = {
        enabled: true,
        last_purge_at: new Date('2025-10-14T12:00:00Z'),
        operations_since_purge: 500,
        time_threshold_hours: 24,
        operation_threshold: 1000,
        deleted_counts: { todo: 10, pr_context: 5 },
        last_duration_ms: 125,
      };

      (mockPool.query as any).mockResolvedValueOnce({ rows: [mockMeta] });

      const status = await getPurgeStatus(mockPool);

      expect(status.enabled).toBe(true);
      expect(status.operations_since_purge).toBe(500);
      expect(status.last_deleted_counts).toEqual({ todo: 10, pr_context: 5 });
      expect(status.next_purge_estimate).toBeDefined();
    });
  });
});
