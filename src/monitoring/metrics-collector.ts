// EMERGENCY ROLLBACK: Monitoring system type compatibility issues

/**
 * Metrics Collector for MCP Cortex
 * Core responsibility: collect, aggregate, and provide metrics data.
 */

import { type AggregationType } from './alert-management-service.js';

export interface RecordedMetrics {
  key: string; // time bucket derived from timestamp (e.g., 2025-01-01T12:00:00)
  values: number[]; // arbitrary numeric measurements
  timestamp: Date;
  labels?: Record<string, string | number>;
}

export interface MetricsCollectorConfig {
  maxBuckets?: number;
}

/**
 * MetricsCollector
 * Records and aggregates numeric measurements over time windows.
 */
export class MetricsCollector {
  private data: Map<string, RecordedMetrics[]> = new Map();

  constructor(private config: MetricsCollectorConfig = {}) {}

  /**
   * Record a measurement into a temporal bucket and labels.
   */
  record(value: number, timestamp = new Date(), labels?: Record<string, string | number>): void {
    try {
      const key = this.getTimeBucketKey(timestamp);
      if (!this.data.has(key)) {
        this.data.set(key, []);
      }
      this.data.get(key)!.push({
        key,
        values: [value],
        timestamp,
        labels,
      });

      // Keep only last 1000 per bucket
      const arr = this.data.get(key)!;
      if (arr.length > 1000) {
        arr.splice(0, arr.length - 1000);
      }
    } catch (err) {
      // Swallow errors for metrics recording
    }
  }

  /**
   * Query recorded metrics for a time range.
   */
  query(range: { from: Date; to: Date }): RecordedMetrics[] {
    const result: RecordedMetrics[] = [];
    for (const [key, arr] of this.data) {
      const keyDate = this.parseTimeBucketKey(key);
      if (keyDate >= range.from && keyDate <= range.to) {
        result.push(...arr);
      }
    }
    return result.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
  }

  /**
   * Aggregate numeric values over a time window per aggregation type.
   */
  aggregate(values: number[], aggregation: AggregationType): number {
    try {
      switch (aggregation) {
        case 'sum':
          return values.reduce((s, v) => s + v, 0);
        case 'avg':
          return values.length ? values.reduce((s, v) => s + v, 0) / values.length : 0;
        case 'min':
          return values.length ? Math.min.apply(null, values) : 0;
        case 'max':
          return values.length ? Math.max.apply(null, values) : 0;
        case 'count':
          return values.length;
        default:
          return 0;
      }
    } catch {
      return 0;
    }
  }

  private getTimeBucketKey(ts: Date): string {
    // simple minute-level key
    return ts.toISOString().slice(0, 16); // up to minutes
  }

  private parseTimeBucketKey(key: string): Date {
    return new Date(key + ':00');
  }
}
