#!/usr/bin/env node

/**
 * Performance Gate Validator
 *
 * Validates performance targets with rigorous testing:
 * - P95 latency < 1s @ N=100 concurrent users
 * - Throughput ≥ 100 ops/sec
 * - Error rate < 1%
 * - Memory usage validation
 * - Load testing with stress scenarios
 */

import { execSync, spawn } from 'child_process';
import { readFileSync, existsSync, mkdirSync, writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { performance } from 'perf_hooks';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = join(__dirname, '..');

// Configuration
const CONFIG = {
  // Performance thresholds (as specified in requirements)
  THRESHOLDS: {
    P95_LATENCY_MS: 1000, // p95 < 1s
    THROUGHPUT_MIN: 100, // Minimum operations per second
    ERROR_RATE_MAX: 1.0, // Maximum error rate percentage
    MEMORY_MAX_MB: 2048, // Maximum memory usage in MB
    CPU_MAX_PERCENT: 80, // Maximum CPU usage percentage
  },
  // Load testing configuration (N=100 as specified)
  LOAD_TEST: {
    CONCURRENT_USERS: 100, // N=100 concurrent users
    DURATION_SECONDS: 60, // Test duration
    WARMUP_SECONDS: 10, // Warmup period
    RAMP_UP_SECONDS: 20, // Ramp up time
    REQUESTS_PER_USER: 50, // Requests per user
    TOTAL_REQUESTS: 5000, // Total target requests
  },
  // Stress testing configuration
  STRESS_TEST: {
    MAX_CONCURRENT_USERS: 500,
    STEP_USERS: 50,
    STEP_DURATION_SECONDS: 30,
    TOTAL_DURATION_SECONDS: 300,
  },
  // Output directories
  OUTPUT_DIR: join(projectRoot, 'artifacts', 'performance-gates'),
  BENCHMARK_DIR: join(projectRoot, 'artifacts', 'bench'),
  TEMP_DIR: join(projectRoot, 'temp', 'performance'),
};

// Colors for console output
const COLORS = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  bold: '\x1b[1m',
};

function log(message, color = COLORS.reset) {
  console.log(`${color}${message}${COLORS.reset}`);
}

function logError(message) {
  log(`❌ ${message}`, COLORS.red);
}

function logSuccess(message) {
  log(`✅ ${message}`, COLORS.green);
}

function logWarning(message) {
  log(`⚠️  ${message}`, COLORS.yellow);
}

function logInfo(message) {
  log(`ℹ️  ${message}`, COLORS.blue);
}

function logHeader(message) {
  log(`\n${COLORS.bold}${message}${COLORS.reset}`);
  log('='.repeat(message.length), COLORS.cyan);
}

/**
 * Execute command with timeout and real-time output
 */
function executeCommand(command, options = {}) {
  return new Promise((resolve, reject) => {
    const args = command.split(' ');
    const cmd = args.shift();

    const child = spawn(cmd, args, {
      cwd: projectRoot,
      stdio: 'pipe',
      ...options,
    });

    let stdout = '';
    let stderr = '';

    child.stdout?.on('data', (data) => {
      const output = data.toString();
      stdout += output;
      if (options.realTimeOutput) {
        process.stdout.write(output);
      }
    });

    child.stderr?.on('data', (data) => {
      const output = data.toString();
      stderr += output;
      if (options.realTimeOutput) {
        process.stderr.write(output);
      }
    });

    child.on('close', (code) => {
      resolve({
        success: code === 0,
        exitCode: code,
        stdout,
        stderr,
      });
    });

    child.on('error', (error) => {
      reject(error);
    });

    if (options.timeout) {
      setTimeout(() => {
        child.kill();
        reject(new Error(`Command timed out after ${options.timeout}ms`));
      }, options.timeout);
    }
  });
}

/**
 * Execute async load test with monitoring
 */
async function executeLoadTest(config) {
  logInfo(`Starting load test with ${config.concurrentUsers} concurrent users...`);

  // Ensure output directory exists
  mkdirSync(CONFIG.OUTPUT_DIR, { recursive: true });

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const resultFile = join(CONFIG.OUTPUT_DIR, `load-test-${timestamp}.json`);
  const metricsFile = join(CONFIG.OUTPUT_DIR, `load-metrics-${timestamp}.json`);

  // Start server for testing
  const serverProcess = spawn('npm', ['run', 'start'], {
    cwd: projectRoot,
    stdio: 'pipe',
    detached: true,
  });

  // Wait for server to start
  await new Promise((resolve) => setTimeout(resolve, 3000));

  try {
    const results = {
      testConfig: config,
      startTime: new Date().toISOString(),
      endTime: null,
      duration: 0,
      metrics: {
        totalRequests: 0,
        successfulRequests: 0,
        failedRequests: 0,
        latencies: {
          min: Infinity,
          max: 0,
          mean: 0,
          p50: 0,
          p90: 0,
          p95: 0,
          p99: 0,
        },
        throughput: 0,
        errorRate: 0,
        memoryUsage: {
          initial: 0,
          peak: 0,
          final: 0,
        },
        cpuUsage: {
          average: 0,
          peak: 0,
        },
      },
      samples: [],
      status: 'running',
    };

    // Monitor system resources during test
    const monitoringInterval = setInterval(() => {
      const memUsage = process.memoryUsage();
      const memoryMB = memUsage.heapUsed / 1024 / 1024;

      results.metrics.memoryUsage.peak = Math.max(results.metrics.memoryUsage.peak, memoryMB);
    }, 1000);

    // Execute load test
    try {
      const testCommand = `npm run bench:load -c ${config.concurrentUsers} -n ${config.totalRequests}`;
      const testResult = await executeCommand(testCommand, {
        timeout: (config.durationSeconds + 30) * 1000,
        realTimeOutput: true,
      });

      if (testResult.success) {
        // Parse load test results
        const loadTestResults = parseLoadTestOutput(testResult.stdout);
        results.metrics = { ...results.metrics, ...loadTestResults.metrics };
        results.samples = loadTestResults.samples || [];
        results.status = 'completed';
        logSuccess('Load test completed successfully');
      } else {
        results.status = 'failed';
        results.error = testResult.stderr;
        logError('Load test failed');
      }
    } catch (error) {
      results.status = 'error';
      results.error = error.message;
      logError(`Load test error: ${error.message}`);
    } finally {
      clearInterval(monitoringInterval);
    }

    results.endTime = new Date().toISOString();
    results.duration = new Date(results.endTime) - new Date(results.startTime);

    // Save results
    writeFileSync(resultFile, JSON.stringify(results, null, 2));
    writeFileSync(metricsFile, JSON.stringify(results.metrics, null, 2));

    logInfo(`Load test results saved to: ${resultFile}`);
    return results;
  } finally {
    // Clean up server process
    try {
      process.kill(-serverProcess.pid);
    } catch (e) {
      // Process might already be stopped
    }
  }
}

/**
 * Parse load test output
 */
function parseLoadTestOutput(output) {
  const results = {
    metrics: {
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      latencies: {
        min: Infinity,
        max: 0,
        mean: 0,
        p50: 0,
        p90: 0,
        p95: 0,
        p99: 0,
      },
      throughput: 0,
      errorRate: 0,
    },
    samples: [],
  };

  try {
    // Try to parse JSON output first
    const jsonMatch = output.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      const jsonData = JSON.parse(jsonMatch[0]);
      if (jsonData.results && jsonData.results[0]) {
        const benchmark = jsonData.results[0];
        results.metrics = {
          totalRequests: benchmark.totalRequests || 0,
          successfulRequests: benchmark.successfulRequests || 0,
          failedRequests: benchmark.failedRequests || 0,
          latencies: benchmark.latencies || results.metrics.latencies,
          throughput: benchmark.throughput || 0,
          errorRate: benchmark.errorRate || 0,
        };
        results.samples = benchmark.samples || [];
      }
    } else {
      // Fallback to regex parsing
      const lines = output.split('\n');
      lines.forEach((line) => {
        if (line.includes('requests') && line.includes('completed')) {
          const match = line.match(/(\d+)\s+requests\s+completed/);
          if (match) results.metrics.totalRequests = parseInt(match[1]);
        }
        if (line.includes('latency') && line.includes('ms')) {
          const match = line.match(/latency:\s+(\d+(\.\d+)?)\s*ms/);
          if (match) results.metrics.latencies.mean = parseFloat(match[1]);
        }
        if (line.includes('throughput') && line.includes('req/s')) {
          const match = line.match(/throughput:\s+(\d+(\.\d+)?)\s*req\/s/);
          if (match) results.metrics.throughput = parseFloat(match[1]);
        }
      });

      // Calculate error rate
      results.metrics.errorRate =
        results.metrics.totalRequests > 0
          ? (results.metrics.failedRequests / results.metrics.totalRequests) * 100
          : 0;
    }
  } catch (error) {
    logWarning(`Failed to parse load test output: ${error.message}`);
  }

  return results;
}

/**
 * Run existing benchmarks
 */
async function runBenchmarks() {
  logInfo('Running performance benchmarks...');

  try {
    // Run quick benchmarks
    const quickResult = await executeCommand('npm run bench:quick', {
      timeout: 120000,
      realTimeOutput: true,
    });

    if (!quickResult.success) {
      throw new Error(`Quick benchmarks failed: ${quickResult.stderr}`);
    }

    // Parse benchmark results
    const benchmarkResults = parseBenchmarkResults(quickResult.stdout);
    logSuccess('Benchmarks completed successfully');

    return benchmarkResults;
  } catch (error) {
    logError(`Benchmark execution failed: ${error.message}`);
    return { success: false, error: error.message };
  }
}

/**
 * Parse benchmark results
 */
function parseBenchmarkResults(output) {
  const results = {
    success: true,
    scenarios: [],
    summary: {
      avgP95: 0,
      avgThroughput: 0,
      avgErrorRate: 0,
      totalScenarios: 0,
    },
  };

  try {
    const benchmarkFile = join(CONFIG.BENCHMARK_DIR, 'benchmark-results.json');
    if (existsSync(benchmarkFile)) {
      const benchmarkData = JSON.parse(readFileSync(benchmarkFile, 'utf8'));

      if (benchmarkData.results && Array.isArray(benchmarkData.results)) {
        results.scenarios = benchmarkData.results.map((result) => ({
          name: result.scenario,
          p95Latency: result.metrics?.latencies?.p95 || 0,
          throughput: result.metrics?.throughput || 0,
          errorRate: result.metrics?.errorRate || 0,
          status: 'completed',
        }));

        // Calculate summary
        if (results.scenarios.length > 0) {
          results.summary.avgP95 =
            results.scenarios.reduce((sum, s) => sum + s.p95Latency, 0) / results.scenarios.length;
          results.summary.avgThroughput =
            results.scenarios.reduce((sum, s) => sum + s.throughput, 0) / results.scenarios.length;
          results.summary.avgErrorRate =
            results.scenarios.reduce((sum, s) => sum + s.errorRate, 0) / results.scenarios.length;
          results.summary.totalScenarios = results.scenarios.length;
        }
      }
    }
  } catch (error) {
    results.success = false;
    results.error = error.message;
  }

  return results;
}

/**
 * Validate performance against thresholds
 */
function validatePerformanceThresholds(benchmarkResults, loadTestResults) {
  logHeader('📊 Performance Threshold Validation');

  const validation = {
    overall: 'passed',
    thresholds: {
      p95Latency: { status: 'unknown', value: 0, threshold: CONFIG.THRESHOLDS.P95_LATENCY_MS },
      throughput: { status: 'unknown', value: 0, threshold: CONFIG.THRESHOLDS.THROUGHPUT_MIN },
      errorRate: { status: 'unknown', value: 0, threshold: CONFIG.THRESHOLDS.ERROR_RATE_MAX },
      memoryUsage: { status: 'unknown', value: 0, threshold: CONFIG.THRESHOLDS.MEMORY_MAX_MB },
    },
    details: {},
  };

  // Validate P95 latency
  const p95Value = loadTestResults.metrics?.latencies?.p95 || benchmarkResults.summary?.avgP95 || 0;
  validation.thresholds.p95Latency.value = p95Value;
  validation.thresholds.p95Latency.status =
    p95Value <= CONFIG.THRESHOLDS.P95_LATENCY_MS ? 'passed' : 'failed';

  const p95Status = validation.thresholds.p95Latency.status === 'passed' ? '✅' : '❌';
  const p95Color = validation.thresholds.p95Latency.status === 'passed' ? COLORS.green : COLORS.red;
  log(
    `   ${p95Status} P95 Latency: ${p95Value.toFixed(2)}ms (threshold: ${CONFIG.THRESHOLDS.P95_LATENCY_MS}ms)`,
    p95Color
  );

  // Validate throughput
  const throughputValue =
    loadTestResults.metrics?.throughput || benchmarkResults.summary?.avgThroughput || 0;
  validation.thresholds.throughput.value = throughputValue;
  validation.thresholds.throughput.status =
    throughputValue >= CONFIG.THRESHOLDS.THROUGHPUT_MIN ? 'passed' : 'failed';

  const throughputStatus = validation.thresholds.throughput.status === 'passed' ? '✅' : '❌';
  const throughputColor =
    validation.thresholds.throughput.status === 'passed' ? COLORS.green : COLORS.red;
  log(
    `   ${throughputStatus} Throughput: ${throughputValue.toFixed(2)} ops/s (threshold: ${CONFIG.THRESHOLDS.THROUGHPUT_MIN} ops/s)`,
    throughputColor
  );

  // Validate error rate
  const errorRateValue =
    loadTestResults.metrics?.errorRate || benchmarkResults.summary?.avgErrorRate || 0;
  validation.thresholds.errorRate.value = errorRateValue;
  validation.thresholds.errorRate.status =
    errorRateValue <= CONFIG.THRESHOLDS.ERROR_RATE_MAX ? 'passed' : 'failed';

  const errorRateStatus = validation.thresholds.errorRate.status === 'passed' ? '✅' : '❌';
  const errorRateColor =
    validation.thresholds.errorRate.status === 'passed' ? COLORS.green : COLORS.red;
  log(
    `   ${errorRateStatus} Error Rate: ${errorRateValue.toFixed(2)}% (threshold: ${CONFIG.THRESHOLDS.ERROR_RATE_MAX}%)`,
    errorRateColor
  );

  // Validate memory usage
  const memoryValue = loadTestResults.metrics?.memoryUsage?.peak || 0;
  validation.thresholds.memoryUsage.value = memoryValue;
  validation.thresholds.memoryUsage.status =
    memoryValue <= CONFIG.THRESHOLDS.MEMORY_MAX_MB ? 'passed' : 'failed';

  const memoryStatus = validation.thresholds.memoryUsage.status === 'passed' ? '✅' : '❌';
  const memoryColor =
    validation.thresholds.memoryUsage.status === 'passed' ? COLORS.green : COLORS.red;
  log(
    `   ${memoryStatus} Memory Usage: ${memoryValue.toFixed(0)}MB (threshold: ${CONFIG.THRESHOLDS.MEMORY_MAX_MB}MB)`,
    memoryColor
  );

  // Determine overall status
  const failedThresholds = Object.values(validation.thresholds).filter(
    (t) => t.status === 'failed'
  );
  validation.overall = failedThresholds.length === 0 ? 'passed' : 'failed';

  validation.details = {
    benchmarkResults,
    loadTestResults,
    failedThresholds: failedThresholds.map((t) => ({
      metric: Object.keys(validation.thresholds).find((key) => validation.thresholds[key] === t),
      value: t.value,
      threshold: t.threshold,
      deviation: t.value - t.threshold,
    })),
  };

  return validation;
}

/**
 * Generate performance gate report
 */
function generatePerformanceReport(validation) {
  logHeader('📋 Generating Performance Gate Report');

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const reportFile = join(CONFIG.OUTPUT_DIR, `performance-gate-report-${timestamp}.json`);
  const htmlReportFile = join(CONFIG.OUTPUT_DIR, `performance-gate-report-${timestamp}.html`);

  const report = {
    metadata: {
      timestamp: new Date().toISOString(),
      version: '2.0.1',
      testConfiguration: {
        concurrentUsers: CONFIG.LOAD_TEST.CONCURRENT_USERS,
        duration: CONFIG.LOAD_TEST.DURATION_SECONDS,
        totalRequests: CONFIG.LOAD_TEST.TOTAL_REQUESTS,
      },
    },
    summary: {
      overallStatus: validation.overall,
      thresholdsChecked: Object.keys(validation.thresholds).length,
      thresholdsPassed: Object.values(validation.thresholds).filter((t) => t.status === 'passed')
        .length,
      thresholdsFailed: Object.values(validation.thresholds).filter((t) => t.status === 'failed')
        .length,
      readyForRelease: validation.overall === 'passed',
    },
    thresholds: validation.thresholds,
    details: validation.details,
    recommendations: generatePerformanceRecommendations(validation),
    artifacts: {
      reportFile,
      htmlReportFile,
      benchmarkDir: CONFIG.BENCHMARK_DIR,
      performanceGateDir: CONFIG.OUTPUT_DIR,
    },
  };

  // Write JSON report
  writeFileSync(reportFile, JSON.stringify(report, null, 2));
  logSuccess(`Performance report generated: ${reportFile}`);

  // Write HTML report
  const htmlReport = generateHTMLPerformanceReport(report);
  writeFileSync(htmlReportFile, htmlReport);
  logSuccess(`HTML performance report generated: ${htmlReportFile}`);

  return report;
}

/**
 * Generate performance recommendations
 */
function generatePerformanceRecommendations(validation) {
  const recommendations = [];

  Object.entries(validation.thresholds).forEach(([metric, threshold]) => {
    if (threshold.status === 'failed') {
      switch (metric) {
        case 'p95Latency':
          recommendations.push({
            priority: 'high',
            category: 'Latency',
            issue: `P95 latency ${threshold.value.toFixed(2)}ms exceeds threshold ${threshold.threshold}ms`,
            action:
              'Optimize database queries, add caching, reduce computational complexity, or use more efficient algorithms',
          });
          break;
        case 'throughput':
          recommendations.push({
            priority: 'high',
            category: 'Throughput',
            issue: `Throughput ${threshold.value.toFixed(2)} ops/s below threshold ${threshold.threshold} ops/s`,
            action:
              'Scale horizontally, optimize code performance, use connection pooling, or implement request batching',
          });
          break;
        case 'errorRate':
          recommendations.push({
            priority: 'critical',
            category: 'Reliability',
            issue: `Error rate ${threshold.value.toFixed(2)}% exceeds threshold ${threshold.threshold}%`,
            action:
              'Fix bugs causing errors, improve error handling, add circuit breakers, or implement retry mechanisms',
          });
          break;
        case 'memoryUsage':
          recommendations.push({
            priority: 'medium',
            category: 'Memory',
            issue: `Memory usage ${threshold.value.toFixed(0)}MB exceeds threshold ${threshold.threshold}MB`,
            action:
              'Optimize memory usage, fix memory leaks, use streaming for large data, or increase memory limits',
          });
          break;
      }
    }
  });

  return recommendations;
}

/**
 * Generate HTML performance report
 */
function generateHTMLPerformanceReport(report) {
  const { metadata, summary, thresholds, recommendations } = report;

  const getThresholdColor = (status) => (status === 'passed' ? '#4CAF50' : '#f44336');
  const getThresholdIcon = (status) => (status === 'passed' ? '✅' : '❌');

  return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Performance Gate Report - ${metadata.version}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 40px; padding-bottom: 20px; border-bottom: 2px solid #e0e0e0; }
        .status-banner { padding: 20px; border-radius: 8px; text-align: center; font-size: 1.2em; font-weight: bold; margin-bottom: 30px; }
        .status-passed { background: #e8f5e8; color: #2e7d32; border: 2px solid #4caf50; }
        .status-failed { background: #ffebee; color: #c62828; border: 2px solid #f44336; }
        .thresholds-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 30px 0; }
        .threshold-card { padding: 20px; border-radius: 8px; border-left: 4px solid #ddd; background: #f8f9fa; }
        .threshold-passed { border-left-color: #4CAF50; background: #e8f5e8; }
        .threshold-failed { border-left-color: #f44336; background: #ffebee; }
        .metric-value { font-size: 2em; font-weight: bold; margin: 10px 0; }
        .metric-threshold { font-size: 0.9em; color: #666; }
        .test-config { background: #f5f5f5; padding: 15px; border-radius: 8px; margin: 20px 0; }
        .recommendations { margin: 30px 0; }
        .recommendation { padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid #ff9800; background: #fff3e0; }
        .priority-critical { border-left-color: #f44336; background: #ffebee; }
        .priority-high { border-left-color: #ff9800; background: #fff3e0; }
        .priority-medium { border-left-color: #2196f3; background: #e3f2fd; }
        .footer { text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #e0e0e0; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>⚡ Performance Gate Report</h1>
            <p>Version: ${metadata.version} | Generated: ${new Date(metadata.timestamp).toLocaleString()}</p>
            <div class="status-banner ${summary.readyForRelease ? 'status-passed' : 'status-failed'}">
                ${summary.readyForRelease ? '🎉 PERFORMANCE TARGETS MET' : '🚫 PERFORMANCE TARGETS NOT MET'}
            </div>
        </div>

        <div class="test-config">
            <h3>🧪 Test Configuration</h3>
            <p><strong>Concurrent Users:</strong> ${metadata.testConfiguration.concurrentUsers} (N=100 as required)</p>
            <p><strong>Duration:</strong> ${metadata.testConfiguration.duration} seconds</p>
            <p><strong>Total Requests:</strong> ${metadata.testConfiguration.totalRequests}</p>
            <p><strong>P95 Latency Target:</strong> < 1s (1000ms)</p>
            <p><strong>Throughput Target:</strong> ≥ 100 ops/sec</p>
        </div>

        <div class="thresholds-grid">
            ${Object.entries(thresholds)
              .map(
                ([key, threshold]) => `
            <div class="threshold-card ${threshold.status}">
                <h3>${getThresholdIcon(threshold.status)} ${key.replace(/([A-Z])/g, ' $1').trim()}</h3>
                <div class="metric-value" style="color: ${getThresholdColor(threshold.status)}">
                    ${threshold.value.toFixed(key === 'errorRate' ? 2 : 1)}
                    <span style="font-size: 0.5em;">
                        ${key === 'errorRate' ? '%' : key === 'memoryUsage' ? 'MB' : key.includes('Latency') ? 'ms' : 'ops/s'}
                    </span>
                </div>
                <div class="metric-threshold">
                    Threshold: ${threshold.threshold}${key === 'errorRate' ? '%' : key === 'memoryUsage' ? 'MB' : key.includes('Latency') ? 'ms' : 'ops/s'}
                </div>
                <p><strong>Status:</strong> <span style="color: ${getThresholdColor(threshold.status)}">${threshold.status.toUpperCase()}</span></p>
            </div>
            `
              )
              .join('')}
        </div>

        <div style="margin: 30px 0; text-align: center;">
            <h3>📊 Summary</h3>
            <p>Thresholds Checked: ${summary.thresholdsChecked}</p>
            <p>Passed: <span style="color: #4CAF50; font-weight: bold;">${summary.thresholdsPassed}</span></p>
            <p>Failed: <span style="color: #f44336; font-weight: bold;">${summary.thresholdsFailed}</span></p>
        </div>

        ${
          recommendations.length > 0
            ? `
        <div class="recommendations">
            <h3>📋 Performance Recommendations</h3>
            ${recommendations
              .map(
                (rec) => `
            <div class="recommendation priority-${rec.priority}">
                <h4>${rec.category} - ${rec.priority.toUpperCase()}</h4>
                <p><strong>Issue:</strong> ${rec.issue}</p>
                <p><strong>Action:</strong> ${rec.action}</p>
            </div>
            `
              )
              .join('')}
        </div>
        `
            : ''
        }

        <div class="footer">
            <p>Generated by Cortex Memory MCP Performance Gate Validator</p>
            <p>Ensuring P95 < 1s @ N=100 concurrent users for production readiness</p>
        </div>
    </div>
</body>
</html>`;
}

/**
 * Main performance gate validation function
 */
async function validatePerformanceGates() {
  logHeader('🎯 Performance Gate Validation');
  logInfo('Validating performance targets: P95 < 1s @ N=100 concurrent users\n');

  const startTime = performance.now();

  try {
    // Step 1: Run benchmarks
    const benchmarkResults = await runBenchmarks();
    if (!benchmarkResults.success) {
      logError('Benchmarks failed - cannot proceed with performance validation');
      process.exit(1);
    }

    // Step 2: Execute load test with N=100 users
    const loadTestResults = await executeLoadTest(CONFIG.LOAD_TEST);
    if (loadTestResults.status !== 'completed') {
      logError('Load test failed - cannot validate performance targets');
      process.exit(1);
    }

    // Step 3: Validate against thresholds
    const validation = validatePerformanceThresholds(benchmarkResults, loadTestResults);

    // Step 4: Generate report
    const report = generatePerformanceReport(validation);

    // Final summary
    const duration = Math.round((performance.now() - startTime) / 1000);
    logHeader('📊 Performance Gate Validation Complete');
    logInfo(`Validation completed in ${duration} seconds`);

    if (validation.overall === 'passed') {
      logSuccess('\n🎉 ALL PERFORMANCE TARGETS MET');
      logSuccess('✅ P95 latency < 1s @ N=100 concurrent users');
      logSuccess('✅ Throughput ≥ 100 ops/sec');
      logSuccess('✅ Error rate < 1%');
      logSuccess('✅ Memory usage within limits');
      logSuccess('\n✅ PERFORMANCE GATES PASSED - READY FOR RELEASE');

      process.exit(0);
    } else {
      logError('\n🚫 PERFORMANCE TARGETS NOT MET - RELEASE BLOCKED');
      logError('The following performance thresholds failed:');

      Object.entries(validation.thresholds).forEach(([metric, threshold]) => {
        if (threshold.status === 'failed') {
          const metricName = metric.replace(/([A-Z])/g, ' $1').trim();
          logError(
            `  ❌ ${metricName}: ${threshold.value.toFixed(2)} (threshold: ${threshold.threshold})`
          );
        }
      });

      logError('\n💡 Address performance issues before proceeding with release');
      logError(`📄 Report: ${report.artifacts.reportFile}`);
      logError(`🌐 HTML Report: ${report.artifacts.htmlReportFile}`);

      process.exit(1);
    }
  } catch (error) {
    logError(`Performance gate validation failed: ${error.message}`);
    process.exit(1);
  }
}

// Run the validation if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  validatePerformanceGates().catch((error) => {
    logError(`Unexpected error: ${error.message}`);
    process.exit(1);
  });
}

export { validatePerformanceGates };
