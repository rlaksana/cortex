/**
 * MCP Cleanup Tools Integration Tests
 *
 * Integration tests for the MCP cleanup tool interface including:
 * - MCP tool invocation and response handling
 * - Parameter validation and type checking
 * - End-to-end cleanup workflows
 * - Error handling at MCP level
 */

import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';

// Mock environment
process.env.NODE_ENV = 'test';
process.env.QDRANT_URL = 'http://localhost:6333';
process.env.QDRANT_COLLECTION_NAME = 'test-cortex-memory';

// Mock cleanup worker and dependencies
vi.mock('../../src/services/cleanup-worker.service.js');
vi.mock('../../src/services/expiry-worker.js');
vi.mock('../../src/services/memory-find.js');
vi.mock('../../src/services/memory-store.js');
vi.mock('../../src/services/metrics/system-metrics.js');

describe('MCP Cleanup Tools Integration', () => {
  let server: Server;
  let mockCleanupWorker: any;

  beforeAll(async () => {
    // Import the server after mocks are set up
    const { getCleanupWorker } = await import('../../src/services/cleanup-worker.service.js');
    mockCleanupWorker = {
      runCleanup: vi.fn(),
      confirmCleanup: vi.fn(),
      getCleanupStatistics: vi.fn(),
      getOperationHistory: vi.fn(),
      getConfig: vi.fn(),
    };

    // Mock the getCleanupWorker function
    (getCleanupWorker as any).mockReturnValue(mockCleanupWorker);

    // Import and start the server
    const serverModule = await import('../../src/index.ts');

    // The server should be auto-started in non-test mode, but we're in test mode
    // so we need to manually initialize it for testing
    // For now, we'll test the handlers directly
  });

  afterAll(() => {
    vi.clearAllMocks();
  });

  describe('run_cleanup Tool', () => {
    it('should handle dry run cleanup operation', async () => {
      // Mock cleanup worker response
      const mockReport = {
        operation_id: 'cleanup_test_123',
        timestamp: new Date().toISOString(),
        mode: 'dry_run',
        operations: [
          { type: 'expired', description: 'Remove expired items', enabled: true, priority: 1 },
        ],
        metrics: {
          cleanup_deleted_total: 0,
          cleanup_dryrun_total: 25,
          cleanup_by_type: { entity: 15, relation: 10 },
          cleanup_duration: { expired: 150 },
          cleanup_errors: [],
          expired_items_deleted: 0,
          orphaned_items_deleted: 0,
          duplicate_items_deleted: 0,
          metrics_items_deleted: 0,
          logs_items_deleted: 0,
          items_per_second: 166.67,
          average_batch_duration_ms: 150,
          total_batches_processed: 1,
        },
        backup_created: undefined,
        safety_confirmations: {
          required: false,
          confirmed: true,
        },
        errors: [],
        warnings: [],
        performance: {
          total_duration_ms: 180,
          items_processed_per_second: 138.89,
          memory_usage_mb: 2.5,
        },
      };

      mockCleanupWorker.runCleanup.mockResolvedValue(mockReport);

      // Import and test the handler directly
      const { handleRunCleanup } = await import('../../src/index.ts');

      const result = await handleRunCleanup({
        dry_run: true,
        cleanup_operations: ['expired'],
        require_confirmation: false,
      });

      expect(result.content).toHaveLength(2);
      expect(result.content[0].type).toBe('cleanup_report');
      expect(result.content[1].type).toBe('text');

      const reportData = result.content[0].report;
      expect(reportData.mode).toBe('dry_run');
      expect(reportData.metrics.cleanup_deleted_total).toBe(0);
      expect(reportData.metrics.cleanup_dryrun_total).toBe(25);
      expect(reportData.safety_confirmations.confirmed).toBe(true);

      expect(mockCleanupWorker.runCleanup).toHaveBeenCalledWith({
        dry_run: true,
        operations: ['expired'],
        require_confirmation: false,
      });
    });

    it('should require confirmation for destructive operations', async () => {
      const mockReport = {
        operation_id: 'cleanup_test_456',
        timestamp: new Date().toISOString(),
        mode: 'dry_run', // Still dry run, but requires confirmation
        operations: [
          { type: 'expired', description: 'Remove expired items', enabled: true, priority: 1 },
        ],
        metrics: {
          cleanup_deleted_total: 0,
          cleanup_dryrun_total: 50,
          cleanup_by_type: { entity: 30, relation: 20 },
          cleanup_duration: { expired: 200 },
          cleanup_errors: [],
          expired_items_deleted: 0,
          orphaned_items_deleted: 0,
          duplicate_items_deleted: 0,
          metrics_items_deleted: 0,
          logs_items_deleted: 0,
          items_per_second: 250,
          average_batch_duration_ms: 200,
          total_batches_processed: 1,
        },
        backup_created: undefined,
        safety_confirmations: {
          required: true,
          confirmed: false,
          confirmation_token: 'cleanup_confirm_test_123456',
        },
        errors: [],
        warnings: ['Large deletion operation: 50 items estimated'],
        performance: {
          total_duration_ms: 250,
          items_processed_per_second: 200,
          memory_usage_mb: 3.2,
        },
      };

      mockCleanupWorker.runCleanup.mockResolvedValue(mockReport);

      const { handleRunCleanup } = await import('../../src/index.ts');

      const result = await handleRunCleanup({
        dry_run: false,
        cleanup_operations: ['expired'],
        require_confirmation: true,
      });

      expect(result.content).toHaveLength(3); // report + text + confirmation_required
      expect(result.content[2].type).toBe('confirmation_required');
      expect(result.content[2].confirmation_token).toBe('cleanup_confirm_test_123456');

      const reportData = result.content[0].report;
      expect(reportData.safety_confirmations.required).toBe(true);
      expect(reportData.safety_confirmations.confirmed).toBe(false);
    });

    it('should handle multiple cleanup operations', async () => {
      const mockReport = {
        operation_id: 'cleanup_multi_789',
        timestamp: new Date().toISOString(),
        mode: 'cleanup',
        operations: [
          { type: 'expired', description: 'Remove expired items', enabled: true, priority: 1 },
          { type: 'orphaned', description: 'Remove orphaned relationships', enabled: true, priority: 2 },
          { type: 'duplicate', description: 'Remove duplicate items', enabled: true, priority: 3 },
        ],
        metrics: {
          cleanup_deleted_total: 45,
          cleanup_dryrun_total: 0,
          cleanup_by_type: { entity: 20, relation: 15, todo: 10 },
          cleanup_duration: { expired: 150, orphaned: 200, duplicate: 300 },
          cleanup_errors: [],
          expired_items_deleted: 25,
          orphaned_items_deleted: 10,
          duplicate_items_deleted: 10,
          metrics_items_deleted: 0,
          logs_items_deleted: 0,
          items_per_second: 90,
          average_batch_duration_ms: 216.67,
          total_batches_processed: 3,
        },
        backup_created: {
          backup_id: 'backup_789',
          items_backed_up: 45,
          backup_size_bytes: 102400,
        },
        safety_confirmations: {
          required: false,
          confirmed: true,
        },
        errors: [],
        warnings: [],
        performance: {
          total_duration_ms: 650,
          items_processed_per_second: 69.23,
          memory_usage_mb: 5.8,
        },
      };

      mockCleanupWorker.runCleanup.mockResolvedValue(mockReport);

      const { handleRunCleanup } = await import('../../src/index.ts');

      const result = await handleRunCleanup({
        dry_run: false,
        cleanup_operations: ['expired', 'orphaned', 'duplicate'],
        require_confirmation: false,
        confirmation_token: 'valid_token',
      });

      const reportData = result.content[0].report;
      expect(reportData.operations).toHaveLength(3);
      expect(reportData.metrics.cleanup_deleted_total).toBe(45);
      expect(reportData.backup_created).toBeDefined();
      expect(reportData.backup_created.backup_id).toBe('backup_789');
    });

    it('should handle cleanup operation errors', async () => {
      mockCleanupWorker.runCleanup.mockRejectedValue(new Error('Database connection failed'));

      const { handleRunCleanup } = await import('../../src/index.ts');

      const result = await handleRunCleanup({
        dry_run: true,
        cleanup_operations: ['expired'],
        require_confirmation: false,
      });

      expect(result.content).toHaveLength(1);
      expect(result.content[0].type).toBe('text');
      expect(result.content[0].text).toContain('Error running cleanup operation');
    });
  });

  describe('confirm_cleanup Tool', () => {
    it('should confirm cleanup operation with valid token', async () => {
      mockCleanupWorker.confirmCleanup.mockReturnValue(true);

      const { handleConfirmCleanup } = await import('../../src/index.ts');

      const result = await handleConfirmCleanup({
        cleanup_token: 'cleanup_confirm_valid_token_123',
      });

      expect(result.content).toHaveLength(2);
      expect(result.content[0].type).toBe('confirmation_result');
      expect(result.content[0].confirmed).toBe(true);

      expect(mockCleanupWorker.confirmCleanup).toHaveBeenCalledWith('cleanup_confirm_valid_token_123');
    });

    it('should reject cleanup operation with invalid token', async () => {
      mockCleanupWorker.confirmCleanup.mockReturnValue(false);

      const { handleConfirmCleanup } = await import('../../src/index.ts');

      const result = await handleConfirmCleanup({
        cleanup_token: 'invalid_token_456',
      });

      expect(result.content[0].confirmed).toBe(false);
      expect(result.content[1].text).toContain('Invalid or expired confirmation token');
    });

    it('should require cleanup_token parameter', async () => {
      const { handleConfirmCleanup } = await import('../../src/index.ts');

      const result = await handleConfirmCleanup({});

      expect(result.content).toHaveLength(1);
      expect(result.content[0].text).toContain('cleanup_token is required');
    });
  });

  describe('get_cleanup_statistics Tool', () => {
    it('should retrieve cleanup statistics', async () => {
      const mockStats = {
        total_operations: 15,
        total_items_deleted: 1250,
        total_items_dryrun: 3200,
        average_duration_ms: 450,
        success_rate: 93.3,
        operations_by_type: {
          expired: 8,
          orphaned: 3,
          duplicate: 2,
          metrics: 1,
          logs: 1,
        },
        errors_by_type: {
          expired: 1,
        },
      };

      mockCleanupWorker.getCleanupStatistics.mockResolvedValue(mockStats);

      const { handleGetCleanupStatistics } = await import('../../src/index.ts');

      const result = await handleGetCleanupStatistics({
        cleanup_stats_days: 30,
      });

      expect(result.content).toHaveLength(2);
      expect(result.content[0].type).toBe('cleanup_statistics');

      const statsData = result.content[0].statistics;
      expect(statsData.total_operations).toBe(15);
      expect(statsData.total_items_deleted).toBe(1250);
      expect(statsData.period_days).toBe(30);
      expect(statsData.calculated_at).toBeDefined();

      expect(mockCleanupWorker.getCleanupStatistics).toHaveBeenCalledWith(30);
    });

    it('should use default period when not specified', async () => {
      const mockStats = {
        total_operations: 0,
        total_items_deleted: 0,
        total_items_dryrun: 0,
        average_duration_ms: 0,
        success_rate: 0,
        operations_by_type: {},
        errors_by_type: {},
      };

      mockCleanupWorker.getCleanupStatistics.mockResolvedValue(mockStats);

      const { handleGetCleanupStatistics } = await import('../../src/index.ts');

      await handleGetCleanupStatistics({});

      expect(mockCleanupWorker.getCleanupStatistics).toHaveBeenCalledWith(30); // Default value
    });
  });

  describe('get_cleanup_history Tool', () => {
    it('should retrieve cleanup operation history', async () => {
      const mockHistory = [
        {
          operation_id: 'cleanup_001',
          timestamp: '2025-01-01T10:00:00Z',
          mode: 'cleanup',
          metrics: {
            cleanup_deleted_total: 25,
            cleanup_dryrun_total: 0,
            cleanup_by_type: { entity: 15, relation: 10 },
            cleanup_duration: {},
            cleanup_errors: [],
            expired_items_deleted: 25,
            orphaned_items_deleted: 0,
            duplicate_items_deleted: 0,
            metrics_items_deleted: 0,
            logs_items_deleted: 0,
            items_per_second: 125,
            average_batch_duration_ms: 200,
            total_batches_processed: 1,
          },
          backup_created: undefined,
          safety_confirmations: { required: false, confirmed: true },
          errors: [],
          warnings: [],
          performance: { total_duration_ms: 200, items_processed_per_second: 125, memory_usage_mb: 2.1 },
          operations: [{ type: 'expired', description: 'Remove expired items', enabled: true, priority: 1, estimated_items: 25 }],
        },
        {
          operation_id: 'cleanup_002',
          timestamp: '2025-01-01T08:00:00Z',
          mode: 'dry_run',
          metrics: {
            cleanup_deleted_total: 0,
            cleanup_dryrun_total: 30,
            cleanup_by_type: { entity: 20, relation: 10 },
            cleanup_duration: {},
            cleanup_errors: [],
            expired_items_deleted: 0,
            orphaned_items_deleted: 0,
            duplicate_items_deleted: 0,
            metrics_items_deleted: 0,
            logs_items_deleted: 0,
            items_per_second: 150,
            average_batch_duration_ms: 100,
            total_batches_processed: 1,
          },
          backup_created: undefined,
          safety_confirmations: { required: false, confirmed: true },
          errors: [],
          warnings: [],
          performance: { total_duration_ms: 150, items_processed_per_second: 200, memory_usage_mb: 1.8 },
          operations: [{ type: 'expired', description: 'Remove expired items', enabled: true, priority: 1, estimated_items: 30 }],
        },
      ];

      mockCleanupWorker.getOperationHistory.mockReturnValue(mockHistory);

      const { handleGetCleanupHistory } = await import('../../src/index.ts');

      const result = await handleGetCleanupHistory({
        cleanup_history_limit: 10,
      });

      expect(result.content).toHaveLength(2);
      expect(result.content[0].type).toBe('cleanup_history');

      const historyData = result.content[0].history;
      expect(historyData).toHaveLength(2);
      expect(historyData[0].operation_id).toBe('cleanup_001');
      expect(historyData[0].mode).toBe('cleanup');
      expect(historyData[1].mode).toBe('dry_run');

      expect(mockCleanupWorker.getOperationHistory).toHaveBeenCalledWith(10);
    });

    it('should limit history results', async () => {
      const mockHistory = Array.from({ length: 20 }, (_, i) => ({
        operation_id: `cleanup_${String(i + 1).padStart(3, '0')}`,
        timestamp: new Date().toISOString(),
        mode: 'dry_run',
        metrics: { cleanup_deleted_total: 0, cleanup_dryrun_total: 10, cleanup_by_type: {}, cleanup_duration: {}, cleanup_errors: [], expired_items_deleted: 0, orphaned_items_deleted: 0, duplicate_items_deleted: 0, metrics_items_deleted: 0, logs_items_deleted: 0, items_per_second: 100, average_batch_duration_ms: 50, total_batches_processed: 1 },
        backup_created: undefined,
        safety_confirmations: { required: false, confirmed: true },
        errors: [],
        warnings: [],
        performance: { total_duration_ms: 100, items_processed_per_second: 100, memory_usage_mb: 1.5 },
        operations: [{ type: 'expired', description: 'Remove expired items', enabled: true, priority: 1, estimated_items: 10 }],
      }));

      mockCleanupWorker.getOperationHistory.mockReturnValue(mockHistory);

      const { handleGetCleanupHistory } = await import('../../src/index.ts');

      const result = await handleGetCleanupHistory({
        cleanup_history_limit: 5,
      });

      expect(result.content[0].count).toBe(5);
      expect(result.content[0].requested_limit).toBe(5);
      expect(result.content[1].text).toContain('5 cleanup operations');
    });
  });

  describe('MCP Tool Schema Validation', () => {
    it('should validate run_cleanup required parameters', async () => {
      // This test would involve actual MCP schema validation
      // For now, we test the handler's parameter handling

      mockCleanupWorker.runCleanup.mockResolvedValue({
        operation_id: 'test',
        timestamp: new Date().toISOString(),
        mode: 'dry_run',
        operations: [],
        metrics: { cleanup_deleted_total: 0, cleanup_dryrun_total: 0, cleanup_by_type: {}, cleanup_duration: {}, cleanup_errors: [], expired_items_deleted: 0, orphaned_items_deleted: 0, duplicate_items_deleted: 0, metrics_items_deleted: 0, logs_items_deleted: 0, items_per_second: 0, average_batch_duration_ms: 0, total_batches_processed: 0 },
        backup_created: undefined,
        safety_confirmations: { required: false, confirmed: true },
        errors: [],
        warnings: [],
        performance: { total_duration_ms: 0, items_processed_per_second: 0, memory_usage_mb: 0 },
      });

      const { handleRunCleanup } = await import('../../src/index.ts');

      // Test with minimal parameters (should work with defaults)
      const result = await handleRunCleanup({});

      expect(result.content).toBeDefined();
      expect(mockCleanupWorker.runCleanup).toHaveBeenCalledWith({
        dry_run: true, // Default
        require_confirmation: true, // Default
      });
    });

    it('should handle invalid cleanup operations', async () => {
      const { handleRunCleanup } = await import('../../src/index.ts');

      // The handler should handle invalid operations gracefully
      const result = await handleRunCleanup({
        cleanup_operations: ['invalid_operation'], // Invalid operation type
      });

      // Should not throw error, but handle gracefully
      expect(result.content).toBeDefined();
    });
  });

  describe('Error Handling Integration', () => {
    it('should handle cleanup worker unavailability', async () => {
      // Mock cleanup worker to throw an error
      mockCleanupWorker.runCleanup.mockImplementation(() => {
        throw new Error('Cleanup worker not available');
      });

      const { handleRunCleanup } = await import('../../src/index.ts');

      const result = await handleRunCleanup({
        dry_run: true,
        cleanup_operations: ['expired'],
      });

      expect(result.content).toHaveLength(1);
      expect(result.content[0].type).toBe('text');
      expect(result.content[0].text).toContain('Error running cleanup operation');
    });

    it('should handle malformed responses from cleanup worker', async () => {
      // Mock cleanup worker to return malformed data
      mockCleanupWorker.runCleanup.mockResolvedValue(null as any);

      const { handleRunCleanup } = await import('../../src/index.ts');

      // Should handle null/undefined responses gracefully
      const result = await handleRunCleanup({
        dry_run: true,
        cleanup_operations: ['expired'],
      });

      expect(result.content).toBeDefined();
    });
  });

  describe('Performance and Load Tests', () => {
    it('should handle concurrent cleanup requests', async () => {
      const mockReport = {
        operation_id: 'concurrent_test',
        timestamp: new Date().toISOString(),
        mode: 'dry_run',
        operations: [{ type: 'expired', description: 'Remove expired items', enabled: true, priority: 1, estimated_items: 10 }],
        metrics: { cleanup_deleted_total: 0, cleanup_dryrun_total: 10, cleanup_by_type: {}, cleanup_duration: {}, cleanup_errors: [], expired_items_deleted: 0, orphaned_items_deleted: 0, duplicate_items_deleted: 0, metrics_items_deleted: 0, logs_items_deleted: 0, items_per_second: 100, average_batch_duration_ms: 100, total_batches_processed: 1 },
        backup_created: undefined,
        safety_confirmations: { required: false, confirmed: true },
        errors: [],
        warnings: [],
        performance: { total_duration_ms: 100, items_processed_per_second: 100, memory_usage_mb: 1.0 },
      };

      mockCleanupWorker.runCleanup.mockResolvedValue(mockReport);

      const { handleRunCleanup } = await import('../../src/index.ts');

      // Run multiple concurrent requests
      const promises = Array.from({ length: 20 }, (_, i) =>
        handleRunCleanup({
          dry_run: true,
          cleanup_operations: ['expired'],
          require_confirmation: false,
        })
      );

      const results = await Promise.all(promises);

      // All requests should complete successfully
      results.forEach(result => {
        expect(result.content).toBeDefined();
        expect(result.content[0].type).toBe('cleanup_report');
      });

      expect(mockCleanupWorker.runCleanup).toHaveBeenCalledTimes(20);
    });
  });
});