import { BaselineTelemetry } from '../../src/services/telemetry/baseline-telemetry';

describe('BaselineTelemetry', () => {
  let telemetry: BaselineTelemetry;

  beforeEach(() => {
    telemetry = new BaselineTelemetry();
  });

  describe('logStoreAttempt', () => {
    it('should track store attempts', () => {
      telemetry.logStoreAttempt(true, 10000, 8000, 'observation', 'test-project');
      telemetry.logStoreAttempt(false, 1000, 1000, 'decision', 'test-project');

      const metrics = telemetry.getStoreMetrics();
      expect(metrics.total_stores).toBe(2);
      expect(metrics.truncated_stores).toBe(1);
      expect(metrics.truncation_ratio).toBe(0.5);
      expect(metrics.avg_truncated_loss).toBe(2000);
    });
  });

  describe('logFindAttempt', () => {
    it('should track find attempts', () => {
      telemetry.logFindAttempt('test query', 'test-project', 5, 0.8, 'auto');
      telemetry.logFindAttempt('another query', 'test-project', 0, 0.0, 'deep');

      const metrics = telemetry.getFindMetrics();
      expect(metrics.total_queries).toBe(2);
      expect(metrics.zero_result_queries).toBe(1);
      expect(metrics.zero_result_ratio).toBe(0.5);
      expect(metrics.avg_returned_count).toBe(2.5);
      expect(metrics.avg_top_score).toBe(0.4);
    });
  });

  describe('getScopeAnalysis', () => {
    it('should analyze by scope', () => {
      // Store attempts
      telemetry.logStoreAttempt(true, 10000, 8000, 'observation', 'project-a');
      telemetry.logStoreAttempt(false, 1000, 1000, 'decision', 'project-b');

      // Find attempts
      telemetry.logFindAttempt('query 1', 'project-a', 3, 0.7, 'auto');
      telemetry.logFindAttempt('query 2', 'project-a', 0, 0.0, 'deep');
      telemetry.logFindAttempt('query 3', 'project-b', 5, 0.9, 'auto');

      const analysis = telemetry.getScopeAnalysis();

      expect(analysis['project-a']).toEqual({
        stores: 1,
        queries: 2,
        zero_results: 1,
        avg_score: 0.35
      });

      expect(analysis['project-b']).toEqual({
        stores: 1,
        queries: 1,
        zero_results: 0,
        avg_score: 0.9
      });
    });
  });

  describe('exportLogs', () => {
    it('should export complete logs with summary', () => {
      telemetry.logStoreAttempt(true, 10000, 8000, 'observation', 'test-project');
      telemetry.logFindAttempt('test query', 'test-project', 3, 0.8, 'auto');

      const exportData = telemetry.exportLogs();

      expect(exportData.store_logs).toHaveLength(1);
      expect(exportData.find_logs).toHaveLength(1);
      expect(exportData.summary.store.total_stores).toBe(1);
      expect(exportData.summary.find.total_queries).toBe(1);
      expect(exportData.summary.scope_analysis['test-project']).toBeDefined();
    });
  });

  describe('reset', () => {
    it('should clear all logs', () => {
      telemetry.logStoreAttempt(true, 10000, 8000, 'observation', 'test-project');
      telemetry.logFindAttempt('test query', 'test-project', 3, 0.8, 'auto');

      telemetry.reset();

      expect(telemetry.getStoreMetrics().total_stores).toBe(0);
      expect(telemetry.getFindMetrics().total_queries).toBe(0);
    });
  });
});