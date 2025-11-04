#!/usr/bin/env node

/**
 * Performance Regression Checker
 *
 * Compares current benchmark results against baseline to detect performance regressions
 */

import { readFileSync, existsSync } from 'fs';
import { join } from 'path';

const BENCHMARK_FILE = './artifacts/bench/benchmark-results.json';
const BASELINE_FILE = './fixtures/bench/baseline-performance.json';

// Regression thresholds
const THRESHOLDS = {
  p95_latency: 0.15,  // 15% increase
  p99_latency: 0.20,  // 20% increase
  throughput: -0.20,  // 20% decrease
  error_rate: 0.50    // 50% increase
};

function loadJSON(filePath) {
  try {
    if (!existsSync(filePath)) {
      console.error(`❌ File not found: ${filePath}`);
      process.exit(1);
    }
    return JSON.parse(readFileSync(filePath, 'utf-8'));
  } catch (error) {
    console.error(`❌ Error reading ${filePath}:`, error.message);
    process.exit(1);
  }
}

function compareMetrics(current, baseline, scenario) {
  const regressions = [];
  const improvements = [];

  // Compare p95 latency
  const p95Change = (current.metrics.latencies.p95 - baseline.p95_ms) / baseline.p95_ms;
  if (p95Change > THRESHOLDS.p95_latency) {
    regressions.push({
      metric: 'p95_latency',
      scenario,
      baseline: baseline.p95_ms,
      current: current.metrics.latencies.p95,
      change: p95Change * 100,
      threshold: THRESHOLDS.p95_latency * 100
    });
  } else if (p95Change < -THRESHOLDS.p95_latency) {
    improvements.push({
      metric: 'p95_latency',
      scenario,
      change: Math.abs(p95Change) * 100
    });
  }

  // Compare throughput
  const throughputChange = (current.metrics.throughput - baseline.throughput_ops_per_sec) / baseline.throughput_ops_per_sec;
  if (throughputChange < THRESHOLDS.throughput) {
    regressions.push({
      metric: 'throughput',
      scenario,
      baseline: baseline.throughput_ops_per_sec,
      current: current.metrics.throughput,
      change: throughputChange * 100,
      threshold: Math.abs(THRESHOLDS.throughput) * 100
    });
  } else if (throughputChange > Math.abs(THRESHOLDS.throughput)) {
    improvements.push({
      metric: 'throughput',
      scenario,
      change: throughputChange * 100
    });
  }

  // Compare error rate
  const errorRateChange = (current.metrics.errorRate - baseline.error_rate_percent) / baseline.error_rate_percent;
  if (errorRateChange > THRESHOLDS.error_rate) {
    regressions.push({
      metric: 'error_rate',
      scenario,
      baseline: baseline.error_rate_percent,
      current: current.metrics.errorRate,
      change: errorRateChange * 100,
      threshold: THRESHOLDS.error_rate * 100
    });
  }

  return { regressions, improvements };
}

function main() {
  console.log('🔍 Checking for performance regressions...\n');

  try {
    const benchmarkData = loadJSON(BENCHMARK_FILE);
    const baselineData = loadJSON(BASELINE_FILE);

    const allRegressions = [];
    const allImprovements = [];

    // Compare each scenario
    for (const result of benchmarkData.results) {
      const scenarioName = result.scenario.toLowerCase().replace(/\s+/g, '_');
      const baselineMetrics = baselineData.baseline_metrics.memory_store[scenarioName] ||
                             baselineData.baseline_metrics.memory_find[scenarioName];

      if (baselineMetrics) {
        const { regressions, improvements } = compareMetrics(result, baselineMetrics, result.scenario);
        allRegressions.push(...regressions);
        allImprovements.push(...improvements);
      } else {
        console.log(`⚠️  No baseline found for scenario: ${result.scenario}`);
      }
    }

    // Report results
    console.log(`📊 Performance Analysis Complete`);
    console.log(`   Regressions detected: ${allRegressions.length}`);
    console.log(`   Improvements detected: ${allImprovements.length}\n`);

    if (allRegressions.length > 0) {
      console.log('🚨 PERFORMANCE REGRESSIONS DETECTED:\n');
      allRegressions.forEach(regression => {
        console.log(`❌ ${regression.scenario} - ${regression.metric}`);
        console.log(`   Baseline: ${regression.baseline.toFixed(2)}`);
        console.log(`   Current:  ${regression.current.toFixed(2)}`);
        console.log(`   Change:   ${regression.change.toFixed(1)}% (threshold: ±${regression.threshold.toFixed(1)}%)\n`);
      });

      console.log('💡 Regression detected! Consider:');
      console.log('   - Reviewing recent changes');
      console.log('   - Running performance profiling');
      console.log('   - Checking for memory leaks');
      console.log('   - Validating test environment');

      process.exit(1);
    } else {
      console.log('✅ No performance regressions detected');

      if (allImprovements.length > 0) {
        console.log('\n🎉 Performance Improvements:\n');
        allImprovements.forEach(improvement => {
          console.log(`✨ ${improvement.scenario} - ${improvement.metric}: ${improvement.change.toFixed(1)}% improvement`);
        });
      }

      console.log('\n🎯 Performance is within acceptable thresholds!');
      process.exit(0);
    }

  } catch (error) {
    console.error('❌ Performance regression check failed:', error.message);
    process.exit(1);
  }
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}

export { main as checkPerformanceRegression };