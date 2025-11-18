// Simple unit test harness for MetricsCollector

import { MetricsCollector } from '../metrics-collector';

// Type assertion for Jest globals
declare const describe: any;
declare const beforeEach: any;
declare const test: any;
declare const expect: any;
declare const beforeAll: any;
declare const afterAll: any;
declare const afterEach: any;
declare const it: any;

describe('MetricsCollector', () => {
  let collector: MetricsCollector;

  beforeEach(() => {
    collector = new MetricsCollector();
  });

  test('records a single measurement', () => {
    collector.record(42);
    const results = collector.query({ from: new Date(Date.now() - 60000), to: new Date() });
    expect(results.length).toBeGreaterThanOrEqual(1);
    expect(results[0]?.values).toContain(42);
  });

  test('aggregates values correctly (avg)', () => {
    collector.record(10);
    collector.record(20);
    collector.record(30);
    const avg = collector.aggregate([10, 20, 30], 'avg');
    expect(avg).toBeCloseTo(20, 5);
  });

  test('aggregates values correctly (sum)', () => {
    const sum = collector.aggregate([1, 2, 3], 'sum');
    expect(sum).toBe(6);
  });

  test('aggregates values correctly (min)', () => {
    const min = collector.aggregate([5, 3, 8], 'min');
    expect(min).toBe(3);
  });

  test('aggregates values correctly (max)', () => {
    const max = collector.aggregate([5, 3, 8], 'max');
    expect(max).toBe(8);
  });

  test('aggregates values correctly (count)', () => {
    const count = collector.aggregate([1, 2, 3, 4], 'count');
    expect(count).toBe(4);
  });
});
