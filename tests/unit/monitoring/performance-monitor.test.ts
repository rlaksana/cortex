/**
 * Performance Monitor Tests
 *
 * Tests for the performance monitoring system including
 * metric collection, baseline creation, and regression detection.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  PerformanceMonitor,
  performanceMonitor,
  monitorPerformance,
  PerformanceMetrics
} from '../../../src/monitoring/performance-monitor.js';

describe('Performance Monitor', () => {
  let monitor: PerformanceMonitor;

  beforeEach(() => {
    monitor = new PerformanceMonitor();
    monitor.clear();
  });

  afterEach(() => {
    monitor.clear();
  });

  describe('Basic Operations', () => {
    it('should start and stop operation timing', () => {
      const finish = monitor.startOperation('test-operation');

      // Simulate some work
      setTimeout(() => {
        const metric = finish();

        expect(metric.operation).toBe('test-operation');
        expect(metric.duration).toBeGreaterThanOrEqual(0);
        expect(metric.timestamp).toBeGreaterThan(0);
        expect(metric.memoryBefore).toBeDefined();
        expect(metric.memoryAfter).toBeDefined();
      }, 10);
    });

    it('should record metrics automatically', () => {
      const finish = monitor.startOperation('auto-test');
      finish();

      const metrics = monitor.getMetrics('auto-test');
      expect(metrics).toHaveLength(1);
      expect(metrics[0].operation).toBe('auto-test');
    });

    it('should handle metadata in operations', () => {
      const metadata = { userId: '123', action: 'search' };
      const finish = monitor.startOperation('test', metadata);
      finish();

      const metrics = monitor.getMetrics('test');
      expect(metrics[0].metadata).toEqual(metadata);
    });
  });

  describe('Threshold Management', () => {
    it('should set and use thresholds', () => {
      monitor.setThresholds('test-op', {
        warning: 100,
        critical: 200,
        absolute: 500,
      });

      const mockEmit = vi.spyOn(monitor, 'emit');

      // Create a metric that exceeds warning threshold
      const finish = monitor.startOperation('test-op');

      // Simulate slow operation by manually creating metric
      setTimeout(() => {
        const metric = finish();

        // Check if alert was emitted (duration depends on test environment)
        if (metric.duration > 100) {
          expect(mockEmit).toHaveBeenCalledWith(
            expect.stringMatching(/alert:(warning|critical|absolute)/),
            expect.any(Object),
            expect.any(Object)
          );
        }
      }, 150);
    });

    it('should calculate default thresholds from metrics', () => {
      // Generate some test metrics
      for (let i = 0; i < 10; i++) {
        const finish = monitor.startOperation('default-test');
        finish();
      }

      const report = monitor.generateReport();
      const threshold = report.operations['default-test'].threshold;

      expect(threshold.warning).toBeGreaterThan(0);
      expect(threshold.critical).toBeGreaterThan(threshold.warning);
      expect(threshold.absolute).toBeGreaterThan(threshold.critical);
    });
  });

  describe('Baseline Management', () => {
    it('should create baseline for operation', () => {
      // Generate test metrics
      for (let i = 0; i < 5; i++) {
        const finish = monitor.startOperation('baseline-test');
        finish();
      }

      monitor.createBaseline('baseline-test');

      const baseline = monitor.getBaseline('baseline-test');
      expect(baseline).toBeDefined();
      expect(baseline?.operation).toBe('baseline-test');
      expect(baseline?.sampleCount).toBe(5);
      expect(baseline?.avgDuration).toBeGreaterThan(0);
    });

    it('should create baselines for all operations', () => {
      // Generate metrics for multiple operations
      ['op1', 'op2', 'op3'].forEach(op => {
        for (let i = 0; i < 3; i++) {
          const finish = monitor.startOperation(op);
          finish();
        }
      });

      monitor.createBaseline();

      expect(monitor.getBaseline('op1')).toBeDefined();
      expect(monitor.getBaseline('op2')).toBeDefined();
      expect(monitor.getBaseline('op3')).toBeDefined();
    });

    it('should detect regressions', () => {
      // Create initial baseline
      for (let i = 0; i < 5; i++) {
        const finish = monitor.startOperation('regression-test');
        finish();
      }
      monitor.createBaseline('regression-test');

      // Generate slower metrics (simulate regression)
      const baseline = monitor.getBaseline('regression-test')!;
      const regressionThreshold = baseline.avgDuration * 2; // Much slower

      // Mock metrics with longer duration
      const mockMetrics: PerformanceMetrics[] = [
        {
          operation: 'regression-test',
          duration: regressionThreshold,
          timestamp: Date.now(),
          memoryBefore: process.memoryUsage(),
          memoryAfter: process.memoryUsage(),
        }
      ];

      // Manually add regression metrics
      for (const metric of mockMetrics) {
        monitor['recordMetric'](metric);
      }

      const regressions = monitor.detectRegressions();
      expect(regressions.length).toBeGreaterThan(0);
      expect(regressions[0].operation).toBe('regression-test');
    });
  });

  describe('Report Generation', () => {
    it('should generate comprehensive report', () => {
      // Generate test data
      ['operation1', 'operation2'].forEach(op => {
        for (let i = 0; i < 5; i++) {
          const finish = monitor.startOperation(op);
          finish();
        }
      });

      monitor.createBaseline();

      const report = monitor.generateReport();

      expect(report.summary.totalOperations).toBe(2);
      expect(report.summary.totalSamples).toBe(10);
      expect(report.summary.avgDuration).toBeGreaterThan(0);
      expect(Object.keys(report.operations)).toHaveLength(2);
      expect(report.generatedAt).toBeGreaterThan(0);

      // Check operation details
      const op1 = report.operations['operation1'];
      expect(op1.current).toHaveLength(5);
      expect(op1.baseline).toBeDefined();
      expect(op1.threshold).toBeDefined();
    });

    it('should track improvements and regressions', () => {
      // Create baseline
      for (let i = 0; i < 5; i++) {
        const finish = monitor.startOperation('improvement-test');
        finish();
      }
      monitor.createBaseline('improvement-test');

      const report = monitor.generateReport();
      const operation = report.operations['improvement-test'];

      expect(operation.regressions).toBeDefined();
      expect(operation.improvements).toBeDefined();
    });
  });

  describe('Memory Management', () => {
    it('should limit metrics history size', () => {
      // Generate more than the limit (1000)
      for (let i = 0; i < 1005; i++) {
        const finish = monitor.startOperation('memory-test');
        finish();
      }

      const metrics = monitor.getMetrics('memory-test');
      expect(metrics.length).toBeLessThanOrEqual(1000);
    });

    it('should clear metrics and optionally baselines', () => {
      // Generate data
      const finish = monitor.startOperation('clear-test');
      finish();
      monitor.createBaseline('clear-test');

      // Clear only metrics
      monitor.clear(false);
      expect(monitor.getMetrics('clear-test')).toHaveLength(0);
      expect(monitor.getBaseline('clear-test')).toBeDefined();

      // Clear both metrics and baselines
      monitor.clear(true);
      expect(monitor.getBaseline('clear-test')).toBeUndefined();
    });
  });

  describe('Event Emission', () => {
    it('should emit events for metric recording', () => {
      const mockEmit = vi.spyOn(monitor, 'emit');

      const finish = monitor.startOperation('event-test');
      finish();

      expect(mockEmit).toHaveBeenCalledWith('metric:recorded', expect.any(Object));
    });

    it('should emit events for baseline updates', () => {
      const mockEmit = vi.spyOn(monitor, 'emit');

      const finish = monitor.startOperation('baseline-event-test');
      finish();

      monitor.createBaseline();

      expect(mockEmit).toHaveBeenCalledWith('baseline:updated');
    });

    it('should emit events for clearing', () => {
      const mockEmit = vi.spyOn(monitor, 'emit');

      monitor.clear();

      expect(mockEmit).toHaveBeenCalledWith('cleared');
    });
  });
});

describe('Performance Monitor Decorator', () => {
  class TestClass {
    @monitorPerformance('decorated-method')
    public decoratedMethod(value: number): number {
      return value * 2;
    }

    @monitorPerformance()
    public async asyncDecoratedMethod(value: number): Promise<number> {
      await new Promise(resolve => setTimeout(resolve, 10));
      return value * 3;
    }

    public regularMethod(value: number): number {
      return value + 1;
    }

    @monitorPerformance('error-method')
    public errorMethod(): never {
      throw new Error('Test error');
    }
  }

  it('should monitor synchronous methods', () => {
    const instance = new TestClass();
    const result = instance.decoratedMethod(5);

    expect(result).toBe(15);

    const metrics = performanceMonitor.getMetrics('decorated-method');
    expect(metrics).toHaveLength(1);
    expect(metrics[0].metadata?.className).toBe('TestClass');
    expect(metrics[0].metadata?.method).toBe('decoratedMethod');
  });

  it('should monitor async methods', async () => {
    const instance = new TestClass();
    const result = await instance.asyncDecoratedMethod(5);

    expect(result).toBe(15);

    const metrics = performanceMonitor.getMetrics('TestClass.asyncDecoratedMethod');
    expect(metrics).toHaveLength(1);
    expect(metrics[0].duration).toBeGreaterThan(0);
  });

  it('should handle errors in monitored methods', () => {
    const instance = new TestClass();

    expect(() => instance.errorMethod()).toThrow('Test error');

    const metrics = performanceMonitor.getMetrics('error-method');
    expect(metrics).toHaveLength(1);
  });

  it('should use default operation name when not specified', () => {
    const instance = new TestClass();
    instance.regularMethod();

    const metrics = performanceMonitor.getMetrics('TestClass.regularMethod');
    expect(metrics).toHaveLength(0); // Should not be monitored
  });
});