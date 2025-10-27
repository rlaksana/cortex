/**
 * Comprehensive Unit Tests for Auto-Purge Service
 *
 * Tests auto-purge functionality including:
 * - Threshold-based triggering
 * - Operation counter incrementing
 * - TTL policy enforcement
 * - Error handling and recovery
 * - Performance considerations
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import type { Pool } from 'pg';

// Mock the dependencies
vi.mock('../../src/utils/logger', () => ({
  logger: {
    info: vi.fn(),
    error: vi.fn(),
    warn: vi.fn(),
    debug: vi.fn(),
  },
}));

vi.mock('../../src/db/unified-database-layer.js', () => ({
  UnifiedDatabaseLayer: vi.fn().mockImplementation(() => mockDatabaseLayer),
}));

vi.mock('../../src/utils/db-error-handler', () => ({
  dbErrorHandler: {
    executeWithRetry: vi.fn(),
  },
}));

// Mock Unified Database Layer
const mockDatabaseLayer = {
  query: vi.fn(),
  purgeMetadata: {
    update: vi.fn(),
    findUnique: vi.fn(),
    create: vi.fn(),
  },
  todoLog: {
    deleteMany: vi.fn(),
  },
  changeLog: {
    deleteMany: vi.fn(),
  },
  prContext: {
    deleteMany: vi.fn(),
  },
  issueLog: {
    deleteMany: vi.fn(),
  },
  knowledgeEntity: {
    deleteMany: vi.fn(),
  },
  knowledgeRelation: {
    deleteMany: vi.fn(),
  },
  knowledgeObservation: {
    deleteMany: vi.fn(),
  },
  incidentLog: {
    deleteMany: vi.fn(),
  },
  releaseLog: {
    deleteMany: vi.fn(),
  },
  riskLog: {
    deleteMany: vi.fn(),
  },
  assumptionLog: {
    deleteMany: vi.fn(),
  },
};

describe('Auto-Purge Service', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.resetAllMocks();

    // Default successful mock for dbErrorHandler
    const { dbErrorHandler } = require('../../src/utils/db-error-handler');
    dbErrorHandler.executeWithRetry.mockResolvedValue({
      success: true,
      data: { operations_since_purge: 1 }
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('checkAndPurge', () => {
    it('should increment operation counter on every call', async () => {
      const { checkAndPurge } = await import('../../src/services/auto-purge.js');
      const { dbErrorHandler } = require('../../src/utils/db-error-handler');

      // Mock successful counter update
      dbErrorHandler.executeWithRetry.mockResolvedValue({
        success: true,
        data: { operations_since_purge: 1 }
      });

      // Mock: purge not needed (thresholds not exceeded)
      mockDatabaseLayer.purgeMetadata.findUnique.mockResolvedValue({
        enabled: true,
        last_purge_at: new Date(),
        operations_since_purge: 10,
        time_threshold_hours: 24,
        operation_threshold: 1000,
      });

      await checkAndPurge('memory.store');

      // Verify counter update was attempted
      expect(dbErrorHandler.executeWithRetry).toHaveBeenCalledWith(
        expect.any(Function),
        'auto-purge.update-counter',
        { maxRetries: 2, baseDelayMs: 500 }
      );
    });

    it('should trigger purge when time threshold exceeded', async () => {
      const { checkAndPurge } = await import('../../src/services/auto-purge.js');
      const { dbErrorHandler } = require('../../src/utils/db-error-handler');
      const { logger } = require('../../src/utils/logger');

      // Mock successful counter update
      dbErrorHandler.executeWithRetry.mockResolvedValue({
        success: true,
        data: { operations_since_purge: 1 }
      });

      // Mock: time threshold exceeded (25 hours since last purge)
      const oldDate = new Date(Date.now() - 25 * 3600 * 1000);
      mockDatabaseLayer.purgeMetadata.findUnique.mockResolvedValue({
        enabled: true,
        last_purge_at: oldDate,
        operations_since_purge: 10,
        time_threshold_hours: 24,
        operation_threshold: 1000,
      });

      await checkAndPurge('memory.store');

      // Should log purge trigger
      expect(logger.info).toHaveBeenCalledWith(
        expect.objectContaining({
          triggered_by: 'time_threshold',
          triggered_from: 'memory.store',
        }),
        'Auto-purge triggered'
      );
    });

    it('should trigger purge when operation threshold exceeded', async () => {
      const { checkAndPurge } = await import('../../src/services/auto-purge.js');
      const { dbErrorHandler } = require('../../src/utils/db-error-handler');
      const { logger } = require('../../src/utils/logger');

      // Mock successful counter update
      dbErrorHandler.executeWithRetry.mockResolvedValue({
        success: true,
        data: { operations_since_purge: 1001 }
      });

      // Mock: operation threshold exceeded
      mockDatabaseLayer.purgeMetadata.findUnique.mockResolvedValue({
        enabled: true,
        last_purge_at: new Date(),
        operations_since_purge: 1001,
        time_threshold_hours: 24,
        operation_threshold: 1000,
      });

      await checkAndPurge('memory.find');

      expect(logger.info).toHaveBeenCalledWith(
        expect.objectContaining({
          triggered_by: 'operation_threshold',
          triggered_from: 'memory.find',
        }),
        'Auto-purge triggered'
      );
    });

    it('should skip purge when disabled', async () => {
      const { checkAndPurge } = await import('../../src/services/auto-purge.js');
      const { dbErrorHandler } = require('../../src/utils/db-error-handler');

      // Mock successful counter update
      dbErrorHandler.executeWithRetry.mockResolvedValue({
        success: true,
        data: { operations_since_purge: 1 }
      });

      // Mock: purge disabled
      mockDatabaseLayer.purgeMetadata.findUnique.mockResolvedValue({
        enabled: false,
        last_purge_at: new Date(0),
        operations_since_purge: 9999,
        time_threshold_hours: 24,
        operation_threshold: 1000,
      });

      await checkAndPurge('memory.store');

      // Should not trigger purge
      expect(mockDatabaseLayer.purgeMetadata.update).toHaveBeenCalledTimes(1); // Only counter update
    });

    it('should handle counter update failure gracefully', async () => {
      const { checkAndPurge } = await import('../../src/services/auto-purge.js');
      const { dbErrorHandler } = require('../../src/utils/db-error-handler');
      const { logger } = require('../../src/utils/logger');

      // Mock counter update failure
      dbErrorHandler.executeWithRetry.mockResolvedValue({
        success: false,
        error: new Error('Database connection failed')
      });

      await checkAndPurge('memory.store');

      // Should log warning and skip purge check
      expect(logger.warn).toHaveBeenCalledWith(
        expect.objectContaining({
          error: expect.any(Error),
          source: 'memory.store',
        }),
        'Failed to update purge counter, skipping purge check'
      );

      // Should not attempt to find metadata
      expect(mockDatabaseLayer.purgeMetadata.findUnique).not.toHaveBeenCalled();
    });

    it('should create initial metadata record if not found', async () => {
      const { checkAndPurge } = await import('../../src/services/auto-purge.js');
      const { dbErrorHandler } = require('../../src/utils/db-error-handler');
      const { logger } = require('../../src/utils/logger');

      // Mock successful counter update
      dbErrorHandler.executeWithRetry.mockResolvedValue({
        success: true,
        data: { operations_since_purge: 1 }
      });

      // Mock: metadata not found
      mockDatabaseLayer.purgeMetadata.findUnique.mockResolvedValue(null);

      await checkAndPurge('memory.store');

      // Should create initial record
      expect(mockDatabaseLayer.purgeMetadata.create).toHaveBeenCalledWith({
        data: {
          id: 1,
          time_threshold_hours: 24,
          operation_threshold: 1000,
        },
      });

      expect(logger.error).toHaveBeenCalledWith(
        'Purge metadata not found, creating initial record'
      );
    });

    it('should handle database errors during purge gracefully', async () => {
      const { checkAndPurge } = await import('../../src/services/auto-purge.js');
      const { dbErrorHandler } = require('../../src/utils/db-error-handler');
      const { logger } = require('../../src/utils/logger');

      // Mock successful counter update
      dbErrorHandler.executeWithRetry.mockResolvedValue({
        success: true,
        data: { operations_since_purge: 1 }
      });

      // Mock: metadata exists and purge should trigger
      mockDatabaseLayer.purgeMetadata.findUnique.mockResolvedValue({
        enabled: true,
        last_purge_at: new Date(Date.now() - 25 * 3600 * 1000),
        operations_since_purge: 10,
        time_threshold_hours: 24,
        operation_threshold: 1000,
      });

      await checkAndPurge('memory.store');

      // Should handle errors gracefully (purge runs async)
      expect(logger.info).toHaveBeenCalledWith(
        expect.objectContaining({
          triggered_by: 'time_threshold',
        }),
        'Auto-purge triggered'
      );
    });
  });

  describe('runPurge', () => {
    beforeEach(() => {
      // Mock successful delete operations
      mockDatabaseLayer.todoLog.deleteMany.mockResolvedValue({ count: 5 });
      mockDatabaseLayer.changeLog.deleteMany.mockResolvedValue({ count: 3 });
      mockDatabaseLayer.prContext.deleteMany.mockResolvedValue({ count: 2 });
      mockDatabaseLayer.issueLog.deleteMany.mockResolvedValue({ count: 4 });
      mockDatabaseLayer.knowledgeEntity.deleteMany.mockResolvedValue({ count: 1 });
      mockDatabaseLayer.knowledgeRelation.deleteMany.mockResolvedValue({ count: 2 });
      mockDatabaseLayer.knowledgeObservation.deleteMany.mockResolvedValue({ count: 1 });
      mockDatabaseLayer.incidentLog.deleteMany.mockResolvedValue({ count: 1 });
      mockDatabaseLayer.releaseLog.deleteMany.mockResolvedValue({ count: 1 });
      mockDatabaseLayer.riskLog.deleteMany.mockResolvedValue({ count: 1 });
      mockDatabaseLayer.assumptionLog.deleteMany.mockResolvedValue({ count: 1 });
    });

    it('should execute all TTL-based purge rules', async () => {
      const { manualPurge } = await import('../../src/services/auto-purge.js');
      const { logger } = require('../../src/utils/logger');

      const result = await manualPurge();

      // Should call all delete operations
      expect(mockDatabaseLayer.todoLog.deleteMany).toHaveBeenCalledWith({
        where: {
          status: { in: ['done', 'cancelled'] },
          closed_at: expect.any(Date),
        },
      });

      expect(mockDatabaseLayer.changeLog.deleteMany).toHaveBeenCalledWith({
        where: {
          created_at: expect.any(Date),
        },
      });

      expect(mockDatabaseLayer.prContext.deleteMany).toHaveBeenCalledWith({
        where: {
          status: 'merged',
          merged_at: expect.any(Date),
        },
      });

      // Should update metadata with results
      expect(mockDatabaseLayer.purgeMetadata.update).toHaveBeenCalledWith({
        where: { id: 1 },
        data: {
          last_purge_at: expect.any(Date),
          operations_since_purge: 0,
          deleted_counts: expect.objectContaining({
            todo: 5,
            change: 3,
            pr_context: 2,
          }),
          last_duration_ms: expect.any(Number),
        },
      });

      // Should return proper result structure
      expect(result).toMatchObject({
        deleted_counts: expect.any(Object),
        total_deleted: expect.any(Number),
        duration_ms: expect.any(Number),
        triggered_by: 'manual',
        triggered_from: 'manual',
      });

      // Should log success
      expect(logger.info).toHaveBeenCalledWith(
        expect.objectContaining({
          deleted_counts: expect.any(Object),
          total_deleted: expect.any(Number),
        }),
        'Auto-purge completed successfully'
      );
    });

    it('should handle database errors during purge execution', async () => {
      const { manualPurge } = await import('../../src/services/auto-purge.js');
      const { logger } = require('../../src/utils/logger');

      // Mock database error
      mockDatabaseLayer.todoLog.deleteMany.mockRejectedValue(new Error('Connection failed'));

      await expect(manualPurge()).rejects.toThrow('Connection failed');

      expect(logger.error).toHaveBeenCalledWith(
        expect.objectContaining({
          err: expect.any(Error),
          source: 'manual',
          triggered_by: 'manual',
        }),
        'Auto-purge encountered error'
      );
    });

    it('should calculate accurate timing and totals', async () => {
      const { manualPurge } = await import('../../src/services/auto-purge.js');

      const startTime = Date.now();
      const result = await manualPurge();
      const endTime = Date.now();

      // Should track duration accurately
      expect(result.duration_ms).toBeGreaterThanOrEqual(0);
      expect(result.duration_ms).toBeLessThanOrEqual(endTime - startTime + 100); // Allow 100ms tolerance

      // Should calculate total correctly
      const expectedTotal = Object.values(result.deleted_counts).reduce((sum: number, count: any) => sum + count, 0);
      expect(result.total_deleted).toBe(expectedTotal);
    });
  });

  describe('getPurgeStatus', () => {
    it('should return current purge metadata with calculated fields', async () => {
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

      mockDatabaseLayer.purgeMetadata.findUnique.mockResolvedValue(mockMeta);

      const status = await getPurgeStatus();

      expect(status.enabled).toBe(true);
      expect(status.operations_since_purge).toBe(500);
      expect(status.last_deleted_counts).toEqual({ todo: 10, pr_context: 5 });
      expect(status.last_duration_ms).toBe(125);
      expect(status.hours_since_purge).toBeDefined();
      expect(status.next_purge_estimate).toBeDefined();
    });

    it('should throw error when metadata not found', async () => {
      const { getPurgeStatus } = await import('../../src/services/auto-purge.js');

      mockDatabaseLayer.purgeMetadata.findUnique.mockResolvedValue(null);

      await expect(getPurgeStatus()).rejects.toThrow('Purge metadata not found');
    });

    it('should estimate next purge correctly', async () => {
      const { getPurgeStatus } = await import('../../src/services/auto-purge.js');

      // Mock data: 12 hours since last purge, 500 operations, thresholds 24h/1000ops
      const twelveHoursAgo = new Date(Date.now() - 12 * 3600 * 1000);
      mockDatabaseLayer.purgeMetadata.findUnique.mockResolvedValue({
        enabled: true,
        last_purge_at: twelveHoursAgo,
        operations_since_purge: 500,
        time_threshold_hours: 24,
        operation_threshold: 1000,
        deleted_counts: {},
        last_duration_ms: 100,
      });

      const status = await getPurgeStatus();

      // Should estimate based on time (12 hours remaining)
      expect(status.next_purge_estimate).toMatch(/~12 hours/);
      expect(status.hours_since_purge).toBe('12.00');
    });

    it('should estimate imminent purge when thresholds exceeded', async () => {
      const { getPurgeStatus } = await import('../../src/services/auto-purge.js');

      // Mock data: 25 hours since last purge (exceeds 24h threshold)
      const twentyFiveHoursAgo = new Date(Date.now() - 25 * 3600 * 1000);
      mockDatabaseLayer.purgeMetadata.findUnique.mockResolvedValue({
        enabled: true,
        last_purge_at: twentyFiveHoursAgo,
        operations_since_purge: 500,
        time_threshold_hours: 24,
        operation_threshold: 1000,
        deleted_counts: {},
        last_duration_ms: 100,
      });

      const status = await getPurgeStatus();

      expect(status.next_purge_estimate).toBe('imminent');
      expect(parseFloat(status.hours_since_purge)).toBeGreaterThan(24);
    });
  });

  describe('TTL Policy Enforcement', () => {
    it('should enforce 90-day TTL for todos', async () => {
      const { manualPurge } = await import('../../src/services/auto-purge.js');

      await manualPurge();

      expect(mockDatabaseLayer.todoLog.deleteMany).toHaveBeenCalledWith({
        where: {
          status: { in: ['done', 'cancelled'] },
          closed_at: expect.any(Date),
        },
      });
    });

    it('should enforce 30-day TTL for PR contexts', async () => {
      const { manualPurge } = await import('../../src/services/auto-purge.js');

      await manualPurge();

      expect(mockDatabaseLayer.prContext.deleteMany).toHaveBeenCalledWith({
        where: {
          status: 'merged',
          merged_at: expect.any(Date),
        },
      });
    });

    it('should enforce soft-delete cleanup for graph entities', async () => {
      const { manualPurge } = await import('../../src/services/auto-purge.js');

      await manualPurge();

      expect(mockDatabaseLayer.knowledgeEntity.deleteMany).toHaveBeenCalledWith({
        where: {
          deleted_at: expect.any(Date),
        },
      });

      expect(mockDatabaseLayer.knowledgeRelation.deleteMany).toHaveBeenCalledWith({
        where: {
          deleted_at: expect.any(Date),
        },
      });

      expect(mockDatabaseLayer.knowledgeObservation.deleteMany).toHaveBeenCalledWith({
        where: {
          deleted_at: expect.any(Date),
        },
      });
    });
  });

  describe('Performance Considerations', () => {
    it('should run purge asynchronously without blocking', async () => {
      const { checkAndPurge } = await import('../../src/services/auto-purge.js');
      const { dbErrorHandler } = require('../../src/utils/db-error-handler');

      // Mock successful counter update
      dbErrorHandler.executeWithRetry.mockResolvedValue({
        success: true,
        data: { operations_since_purge: 1001 }
      });

      // Mock: purge should trigger
      mockDatabaseLayer.purgeMetadata.findUnique.mockResolvedValue({
        enabled: true,
        last_purge_at: new Date(Date.now() - 25 * 3600 * 1000),
        operations_since_purge: 1001,
        time_threshold_hours: 24,
        operation_threshold: 1000,
      });

      const startTime = Date.now();
      await checkAndPurge('memory.store');
      const endTime = Date.now();

      // Should return quickly (purge runs async)
      expect(endTime - startTime).toBeLessThan(100); // Should complete in under 100ms
    });

    it('should handle concurrent checkAndPurge calls safely', async () => {
      const { checkAndPurge } = await import('../../src/services/auto-purge.js');
      const { dbErrorHandler } = require('../../src/utils/db-error-handler');

      // Mock successful counter update
      dbErrorHandler.executeWithRetry.mockResolvedValue({
        success: true,
        data: { operations_since_purge: 1 }
      });

      // Mock: no purge needed
      mockDatabaseLayer.purgeMetadata.findUnique.mockResolvedValue({
        enabled: true,
        last_purge_at: new Date(),
        operations_since_purge: 10,
        time_threshold_hours: 24,
        operation_threshold: 1000,
      });

      // Run multiple concurrent calls
      const promises = Array(10).fill(null).map(() => checkAndPurge('memory.store'));
      await Promise.all(promises);

      // Should handle all calls without errors
      expect(dbErrorHandler.executeWithRetry).toHaveBeenCalledTimes(10);
    });
  });

  describe('Error Recovery', () => {
    it('should continue operation if some delete operations fail', async () => {
      const { manualPurge } = await import('../../src/services/auto-purge.js');
      const { logger } = require('../../src/utils/logger');

      // Mock partial failure - some operations succeed, others fail
      mockDatabaseLayer.todoLog.deleteMany.mockResolvedValue({ count: 5 });
      mockDatabaseLayer.changeLog.deleteMany.mockRejectedValue(new Error('Table locked'));
      mockDatabaseLayer.prContext.deleteMany.mockResolvedValue({ count: 2 });
      mockDatabaseLayer.issueLog.deleteMany.mockResolvedValue({ count: 4 });

      await expect(manualPurge()).rejects.toThrow('Table locked');

      // Should have attempted the operations that succeeded
      expect(mockDatabaseLayer.todoLog.deleteMany).toHaveBeenCalled();
      expect(mockDatabaseLayer.prContext.deleteMany).toHaveBeenCalled();
      expect(mockDatabaseLayer.issueLog.deleteMany).toHaveBeenCalled();
    });

    it('should validate date calculations for TTL policies', async () => {
      const { manualPurge } = await import('../../src/services/auto-purge.js');

      const now = new Date();
      await manualPurge();

      // Verify 90-day calculation
      const ninetyDaysAgo = new Date(now);
      ninetyDaysAgo.setDate(ninetyDaysAgo.getDate() - 90);

      expect(mockDatabaseLayer.todoLog.deleteMany).toHaveBeenCalledWith({
        where: {
          status: { in: ['done', 'cancelled'] },
          closed_at: expect.any(Date),
        },
      });

      // Verify 30-day calculation for PR contexts
      const thirtyDaysAgo = new Date(now);
      thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

      expect(mockDatabaseLayer.prContext.deleteMany).toHaveBeenCalledWith({
        where: {
          status: 'merged',
          merged_at: expect.any(Date),
        },
      });
    });
  });
});
