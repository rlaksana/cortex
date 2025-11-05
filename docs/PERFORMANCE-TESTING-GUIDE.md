# Performance Testing Guide

## Overview

The Cortex Memory MCP performance testing system provides comprehensive performance monitoring, load testing, and regression detection for the knowledge management system. This guide covers how to use the performance testing framework to ensure optimal system performance.

## Features

- **Performance Targets**: Configurable performance targets with N=100 ops, p95 < 1s, p99 < 2s
- **Load Testing**: Comprehensive load testing for critical operations
- **Regression Detection**: Automated performance regression detection
- **CI Integration**: Performance gates for continuous integration
- **Dashboard**: Web-based performance dashboard with charts and metrics
- **Artifact Storage**: Raw logs, charts, and reports storage
- **Baseline Management**: Automated baseline creation and updates

## Architecture

```
Performance Testing System
├── Performance Targets (src/performance/performance-targets.ts)
├── Performance Harness (src/performance/performance-harness.ts)
├── Artifact Storage (src/performance/artifact-storage.ts)
├── CI Regression Guard (src/performance/ci-regression-guard.ts)
├── Performance Dashboard (src/performance/performance-dashboard.ts)
└── Load Tests (tests/performance/load-testing/)
```

## Performance Targets

### Knowledge Storage Operations
- **p95 Latency**: < 1000ms (target), < 2000ms (max)
- **p99 Latency**: < 2000ms (target), < 5000ms (max)
- **Throughput**: > 100 ops/s (target), > 50 ops/s (min)
- **Error Rate**: < 5% (target), < 5% (max)

### Search and Retrieval Operations
- **p95 Latency**: < 500ms (target), < 1000ms (max)
- **p99 Latency**: < 1000ms (target), < 2000ms (max)
- **Throughput**: > 200 ops/s (target), > 100 ops/s (min)
- **Error Rate**: < 2% (target), < 2% (max)

### Circuit Breaker Operations
- **Response Time**: < 10ms (target), < 50ms (max)
- **Throughput**: > 10,000 ops/s (target), > 5,000 ops/s (min)

### Health Check Operations
- **p95 Latency**: < 100ms (target), < 500ms (max)
- **Throughput**: > 1,000 ops/s (target), > 500 ops/s (min)

## Usage

### Running Performance Tests

#### Run All Performance Tests
```bash
npm run perf:test
```

#### Run Critical Path Tests
```bash
npm run perf:test:critical
```

#### Run Specific Test Suites
```bash
# Knowledge storage tests
npm run perf:test:storage

# Search and retrieval tests
npm run perf:test:search

# Circuit breaker tests
npm run perf:test:circuit-breaker

# Health check tests
npm run perf:test:health-check
```

#### Run with Verbose Output
```bash
npm run perf:test:all
```

### Performance Gates

#### Run Performance Gate (Critical Tests)
```bash
npm run perf:gate
```

#### Run Performance Gate for CI
```bash
npm run perf:gate:ci
```

### Baseline Management

#### Update Baseline
```bash
npm run perf:baseline
```

#### Run with Baseline Update
```bash
node scripts/performance-ci-gate.js --update-baseline
```

### Dashboard and Reporting

#### Generate Performance Dashboard
```bash
npm run perf:dashboard
```

#### Generate Complete Performance Report
```bash
npm run perf:report
```

#### Run Performance Validation
```bash
npm run perf:validate
```

## Configuration

### Performance Configuration File

Create a `performance-config.json` file to customize performance targets and settings:

```json
{
  "performanceTargets": {
    "knowledge_storage": {
      "p95_latency_ms": 1000,
      "p99_latency_ms": 2000,
      "throughput_ops_per_sec": 100,
      "error_rate_percent": 5,
      "memory_usage_mb": 512
    },
    "search_retrieval": {
      "p95_latency_ms": 500,
      "p99_latency_ms": 1000,
      "throughput_ops_per_sec": 200,
      "error_rate_percent": 2,
      "memory_usage_mb": 256
    }
  },
  "testConfigurations": {
    "enableTrendAnalysis": true,
    "autoUpdateBaseline": true,
    "performanceGateEnabled": true,
    "maxRegressionPercentage": 20
  }
}
```

### Environment Variables

- `CI`: Set to `true` for CI environment
- `PERFORMANCE_OUTPUT_DIR`: Custom output directory for artifacts
- `PERFORMANCE_CONFIG_PATH`: Path to custom configuration file

## CI Integration

### GitHub Actions

```yaml
name: Performance Tests

on: [push, pull_request]

jobs:
  performance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '18'

      - name: Install dependencies
        run: npm ci

      - name: Run performance tests
        run: npm run perf:gate:ci

      - name: Upload performance artifacts
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: performance-artifacts
          path: artifacts/performance/ci/
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any

    stages {
        stage('Performance Tests') {
            steps {
                sh 'npm ci'
                sh 'npm run perf:gate:ci'

                publishHTML([
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: 'artifacts/performance/dashboard',
                    reportFiles: 'index.html',
                    reportName: 'Performance Report'
                ])
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'artifacts/performance/ci/**/*', fingerprint: true
        }
    }
}
```

## Test Suites

### Knowledge Storage Tests

- **Entity Storage Performance**: Tests entity storage operations with various sizes
- **Observation Storage Performance**: Tests observation storage with linked entities
- **Decision Storage Performance**: Tests decision storage with complexity levels
- **Task Storage Performance**: Tests task storage with dependencies
- **Mixed Knowledge Storage**: Tests mixed entity types storage
- **Knowledge Storage Stress Test**: Sustained load testing for storage operations

### Search and Retrieval Tests

- **Semantic Search Performance**: Vector-based semantic search testing
- **Keyword Search Performance**: Traditional keyword search testing
- **Hybrid Search Performance**: Combined semantic and keyword search
- **Search Under Load**: Concurrent search operations testing
- **Search Result Ranking**: Performance of large result set ranking
- **Search Memory Efficiency**: Memory usage during search operations

### Circuit Breaker Tests

- **Circuit Breaker Response Time**: Basic circuit breaker performance
- **Circuit State Transitions**: Performance during state changes
- **High-Frequency Circuit Breaker**: Performance under high frequency checks
- **Concurrent Circuit Breaker Operations**: Thread safety and concurrency testing
- **Failure Scenarios**: Performance under various failure conditions
- **Recovery Performance**: Circuit breaker recovery performance

### Health Check Tests

- **Database Health Check**: Database connectivity and query performance
- **Memory Health Check**: Memory usage monitoring performance
- **Circuit Breaker Health Check**: Circuit breaker status monitoring
- **API Health Check**: API endpoint health monitoring
- **Comprehensive Health Check**: All health checks combined
- **Health Check Caching**: Performance with result caching

## Artifacts and Reports

### Artifact Types

1. **Raw Logs**: JSON files with detailed test execution data
2. **Metrics**: Processed performance metrics in JSON format
3. **Charts**: Interactive HTML charts for performance visualization
4. **Reports**: Markdown and HTML performance reports
5. **Comparisons**: Baseline vs current performance comparisons
6. **Regression Reports**: Detailed regression analysis reports

### Artifact Structure

```
artifacts/performance/
├── logs/                 # Raw execution logs
├── metrics/              # Processed metrics
├── charts/               # Performance charts
├── reports/              # Performance reports
├── baseline/             # Performance baselines
├── regression-reports/   # Regression analysis
├── dashboard/            # Web dashboard files
└── ci/                   # CI-specific artifacts
```

## Dashboard

### Accessing the Dashboard

1. Generate the dashboard:
   ```bash
   npm run perf:dashboard
   ```

2. Open the dashboard in your browser:
   ```
   file:///path/to/project/artifacts/performance/dashboard/index.html
   ```

### Dashboard Features

- **Real-time Metrics**: Performance metrics visualization
- **Trend Analysis**: Historical performance trends
- **Interactive Charts**: Clickable charts with detailed information
- **Test Results**: Detailed test results table
- **System Metrics**: Resource usage monitoring
- **Regression Alerts**: Visual regression indicators

## Troubleshooting

### Common Issues

#### Performance Tests Fail

1. **Check System Resources**: Ensure sufficient CPU and memory
2. **Verify Dependencies**: Ensure all required dependencies are installed
3. **Check Database Connection**: Verify database connectivity
4. **Review Configuration**: Check performance configuration settings

#### CI Performance Gate Fails

1. **Review Regression Report**: Check regression-reports directory
2. **Compare with Baseline**: Analyze performance differences
3. **Check Environment**: Ensure consistent CI environment
4. **Update Baseline**: If improvements are genuine, update baseline

#### Dashboard Not Loading

1. **Check File Permissions**: Ensure files are readable
2. **Verify Chart Data**: Check if data files exist in api directory
3. **Browser Console**: Check for JavaScript errors
4. **Clear Cache**: Clear browser cache and reload

### Performance Optimization Tips

#### Memory Usage

- Monitor memory leaks using memory profiling
- Optimize garbage collection frequency
- Use memory-efficient data structures
- Implement proper cleanup procedures

#### Latency Optimization

- Identify bottlenecks through profiling
- Optimize database queries
- Implement caching strategies
- Use connection pooling

#### Throughput Improvement

- Increase concurrency levels
- Optimize batch operations
- Implement parallel processing
- Use efficient algorithms

## Best Practices

### Test Design

1. **Realistic Workloads**: Design tests that mirror real usage patterns
2. **Warm-up Periods**: Include proper warm-up iterations
3. **Multiple Runs**: Run tests multiple times for statistical significance
4. **Environment Consistency**: Maintain consistent test environments

### Baseline Management

1. **Regular Updates**: Update baselines after improvements
2. **Version Control**: Store baselines in version control
3. **Environment Matching**: Match baseline and test environments
4. **Documentation**: Document baseline conditions and parameters

### CI Integration

1. **Early Detection**: Run performance tests early in CI pipeline
2. **Gate Enforcement**: Enforce performance gates for deployments
3. **Notification Setup**: Configure alerts for performance regressions
4. **Artifact Retention**: Maintain performance artifact history

### Monitoring

1. **Trend Analysis**: Monitor performance trends over time
2. **Alert Thresholds**: Set appropriate alert thresholds
3. **Dashboard Usage**: Regularly review performance dashboard
4. **Root Cause Analysis**: Investigate performance anomalies

## API Reference

### Performance Harness

```typescript
import { PerformanceHarness } from './src/performance/performance-harness.js';

const harness = new PerformanceHarness('./artifacts/performance');
const results = await harness.runTestSuite(testConfigs);
```

### Regression Guard

```typescript
import { CIRegressionGuard } from './src/performance/ci-regression-guard.js';

const guard = new CIRegressionGuard();
const reports = await guard.checkRegressions(results);
```

### Dashboard

```typescript
import { PerformanceDashboard } from './src/performance/performance-dashboard.js';

const dashboard = new PerformanceDashboard();
await dashboard.generateDashboard(results);
```

### Artifact Storage

```typescript
import { PerformanceArtifactStorage } from './src/performance/artifact-storage.js';

const storage = new PerformanceArtifactStorage();
await storage.storeTestResults(result);
```

## Contributing

### Adding New Performance Tests

1. Create test configuration in `performance-targets.ts`
2. Implement test scenario in appropriate load test file
3. Add test to benchmark scenarios
4. Update documentation
5. Add to CI configuration

### Extending Performance Targets

1. Add new target definitions to `performance-targets.ts`
2. Update validation logic
3. Add to configuration schema
4. Update dashboard charts
5. Update documentation

### Improving Dashboard

1. Modify dashboard templates in `performance-dashboard.ts`
2. Add new chart types
3. Update CSS styling
4. Add new metrics
5. Test with sample data

## Support

For questions, issues, or contributions:

1. Check existing documentation
2. Review test results and artifacts
3. Consult performance regression reports
4. Open GitHub issues for bugs or feature requests
5. Contact the performance team for guidance

---

**Last Updated**: 2025-11-05
**Version**: 2.0.1
**Maintainer**: Cortex Memory MCP Performance Team