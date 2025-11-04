# Cortex Memory MCP - Benchmark Framework

Comprehensive performance testing and benchmarking suite for Cortex Memory MCP Server.

## Overview

This benchmark framework provides:

- **Load Testing**: Concurrent operations testing with configurable concurrency levels
- **Performance Monitoring**: Detailed latency, throughput, and memory usage metrics
- **SLA Validation**: Automated Service Level Agreement compliance checking
- **Regression Detection**: Performance trend analysis and change detection
- **Report Generation**: Comprehensive reports in multiple formats (JSON, CSV, Markdown)
- **Dataset Generation**: Realistic test data generation for various scenarios

## Installation & Setup

### Prerequisites

- Node.js >= 20.0.0
- TypeScript >= 5.9.3
- Sufficient system resources for testing (8GB+ RAM recommended)

### Build Required

```bash
npm run build
```

## Quick Start

### Run All Benchmarks

```bash
# Full benchmark suite
npm run bench

# Quick benchmark (1 warmup, 3 iterations)
npm run bench:quick

# Comprehensive benchmark (5 warmup, 20 iterations)
npm run bench:full
```

### Run Specific Categories

```bash
# Memory store benchmarks only
npm run bench:store

# Memory find/search benchmarks only
npm run bench:search
```

### Load Testing

```bash
# Load testing with 100 concurrent operations, 1000 total operations
npm run bench:load

# Stress testing with 500 concurrent operations, 5000 total operations
npm run bench:stress
```

## CLI Usage

### Basic Commands

```bash
# Show all available commands
node bench/run-benchmarks.js --help

# List available benchmark scenarios
node bench/run-benchmarks.js list

# Run specific scenarios with custom configuration
node bench/run-benchmarks.js run -w 5 -i 15 -o ./custom-output
```

### Generate Test Data

```bash
# Generate predefined dataset sizes
npm run bench:data:small      # 1,000 items
npm run bench:data:medium     # 10,000 items
npm run bench:data:large      # 100,000 items
npm run bench:data:enterprise # 1,000,000 items

# Generate custom dataset
node bench/run-benchmarks.js generate-data -n 5000 -o ./custom-data
```

### Advanced Usage

```bash
# Store benchmarks with custom concurrency
node bench/run-benchmarks.js store -c 50 -n 2000

# Search benchmarks with custom operations
node bench/run-benchmarks.js search -c 20 -n 500

# Load testing with custom ramp-up time
node bench/run-benchmarks.js load -c 200 -n 5000 -r 10000

# Stress testing configuration
node bench/run-benchmarks.js stress -c 1000 -n 10000 -r 30000
```

## Benchmark Scenarios

### Memory Store Scenarios

1. **Single Item Store**
   - Tests basic single-item storage performance
   - Default: 100 operations, 1KB average item size

2. **Batch Store**
   - Tests batch storage with 100 items per batch
   - Evaluates throughput and memory efficiency

3. **Concurrent Store**
   - Tests multiple concurrent storage operations
   - Configurable concurrency levels (1-500+)

4. **Deduplication**
   - Tests duplicate detection performance
   - 50 unique items with repeated storage

5. **Large Item Store**
   - Tests performance with large payloads (50KB average)
   - Memory usage analysis under stress

6. **TTL Processing**
   - Tests Time-To-Live handling performance
   - Various TTL policies and expiration times

### Memory Find Scenarios

1. **Simple Search**
   - Basic semantic search with simple queries
   - Tests baseline search performance

2. **Complex Search**
   - Advanced search with filters and complex queries
   - Tests filter performance and result accuracy

3. **Concurrent Search**
   - Multiple concurrent search operations
   - Tests search performance under load

4. **Graph Expansion**
   - Search with relationship expansion (depth 1-3)
   - Tests graph traversal performance

5. **Fuzzy Search**
   - Search with typo tolerance and fuzzy matching
   - Tests query correction and matching algorithms

6. **Large Result Set**
   - Searches returning large result sets (100-1000+ items)
   - Tests pagination and large data handling

## Performance Metrics

### Latency Metrics

- **p50**: 50th percentile response time
- **p95**: 95th percentile response time
- **p99**: 99th percentile response time
- **min/max**: Minimum and maximum response times

### Throughput Metrics

- **Operations per second**: Overall throughput
- **Concurrent operations**: Simultaneous operation capacity
- **Batch efficiency**: Items processed per second

### Memory Metrics

- **Peak memory usage**: Maximum memory consumption
- **Average memory usage**: Typical memory consumption
- **Memory delta**: Memory change during operations

### Error Metrics

- **Error rate**: Percentage of failed operations
- **Timeout rate**: Percentage of timed-out operations
- **Success rate**: Percentage of successful operations

## SLA Targets

### Memory Store SLAs

| Operation | p95 Target | p99 Target | Throughput Target | Error Rate Target |
|-----------|------------|------------|-------------------|-------------------|
| Single Item | <200ms | <500ms | >100 ops/s | <1% |
| Batch Store | <800ms | <2000ms | >80 ops/s | <2% |
| Concurrent | <500ms | <1000ms | >70 ops/s | <3% |

### Memory Find SLAs

| Operation | p95 Target | p99 Target | Throughput Target | Error Rate Target |
|-----------|------------|------------|-------------------|-------------------|
| Simple Search | <400ms | <1000ms | >200 ops/s | <1% |
| Complex Search | <1000ms | <2000ms | >80 ops/s | <2% |
| Graph Expansion | <2000ms | <5000ms | >40 ops/s | <2% |

## Results and Reports

### Output Formats

Benchmark results are generated in multiple formats:

1. **JSON**: Complete results with all metrics and metadata
2. **CSV**: Tabular data for analysis in spreadsheets
3. **Markdown**: Human-readable summary reports

### Result Files

Results are saved to `./artifacts/bench/` with timestamped filenames:

```
artifacts/bench/
├── benchmark-2025-11-04T10-30-00-000Z.json
├── benchmark-2025-11-04T10-30-00-000Z.csv
├── benchmark-2025-11-04T10-30-00-000Z.md
├── performance-metrics-2025-11-04T10-30-00-000Z.csv
├── iteration-data-2025-11-04T10-30-00-000Z.csv
└── sla-compliance-2025-11-04T10-30-00-000Z.csv
```

### Report Analysis

#### JSON Structure

```json
{
  "metadata": {
    "name": "Cortex Memory MCP Benchmark Suite",
    "version": "2.0.0",
    "timestamp": "2025-11-04T10:30:00.000Z",
    "environment": { ... }
  },
  "results": [
    {
      "scenario": "Single Item Store",
      "description": "Store individual knowledge items",
      "metrics": {
        "latencies": { "p50": 45.2, "p95": 180.5, "p99": 420.1 },
        "throughput": 120.5,
        "errorRate": 0.3,
        "memoryUsage": { "peak": 45286400, "average": 42188600 }
      }
    }
  ]
}
```

#### CSV Export

The framework exports multiple CSV files for analysis:

1. **Results Summary**: Scenario-level performance metrics
2. **Performance Metrics**: Detailed metric breakdown with SLA compliance
3. **Iteration Data**: Individual iteration results for deep analysis
4. **SLA Compliance**: SLA target vs actual performance comparison

## Baseline Performance

### System Requirements for Baseline

- **CPU**: 4 cores @ 2.5GHz
- **Memory**: 8GB RAM
- **Storage**: SSD 100GB
- **Network**: 1Gbps

### Baseline Metrics

Baseline performance metrics are stored in `fixtures/bench/baseline-performance.json` and include:

- Reference performance values for all scenarios
- SLA targets and compliance thresholds
- Performance tiers (excellent, good, acceptable, poor)
- Scaling factors for different dataset sizes

## Configuration

### Benchmark Configuration

```typescript
interface BenchmarkConfig {
  name: string;                    // Benchmark suite name
  version: string;                 // Version identifier
  outputDir: string;               // Output directory
  warmupIterations: number;        // Warmup iterations
  benchmarkIterations: number;     // Benchmark iterations
  scenarioDelay?: number;          // Delay between scenarios
  enableMemoryProfiling?: boolean; // Memory profiling
  maxDuration?: number;            // Maximum test duration
}
```

### Load Test Configuration

```typescript
interface LoadTestConfig {
  concurrency: number;             // Concurrent operations
  operations: number;              // Total operations
  operationDelay?: number;         // Delay between operations
  rampUpTime?: number;             // Ramp-up time (ms)
  dataConfig?: TestDataConfig;     // Test data configuration
  parameters?: Record<string, any>; // Custom parameters
}
```

## Best Practices

### Running Benchmarks

1. **System Preparation**
   ```bash
   # Close unnecessary applications
   # Ensure sufficient system resources
   # Use consistent system configuration
   ```

2. **Baseline Establishment**
   ```bash
   # Establish baseline for your system
   npm run bench:baseline
   ```

3. **Consistent Environment**
   - Use same hardware and software configuration
   - Run benchmarks at consistent times
   - Document system configuration

4. **Multiple Runs**
   ```bash
   # Run multiple times for statistical significance
   for i in {1..3}; do npm run bench; done
   ```

### Performance Analysis

1. **Compare Against Baseline**
   ```bash
   # Compare current results with baseline
   node bench/run-benchmarks.js compare baseline.json current.json
   ```

2. **Monitor Trends**
   - Track performance over time
   - Identify regression patterns
   - Monitor resource utilization

3. **SLA Compliance**
   - Regular SLA validation
   - Automated compliance checking
   - Performance threshold alerts

## Troubleshooting

### Common Issues

1. **Memory Issues**
   - Reduce batch sizes
   - Increase garbage collection
   - Monitor memory leaks

2. **Timeout Issues**
   - Increase timeout values
   - Check system resources
   - Reduce concurrency levels

3. **Database Issues**
   - Verify database connection
   - Check database performance
   - Monitor query performance

### Debug Mode

```bash
# Run with debug logging
DEBUG=cortex:* npm run bench

# Run with Node.js debugging
node --inspect bench/run-benchmarks.js run
```

## Contributing

### Adding New Scenarios

1. Create scenario file in `bench/scenarios/`
2. Implement `BenchmarkScenario` interface
3. Add to appropriate benchmark suite
4. Update documentation

### Extending Metrics

1. Add new metrics to `types.ts`
2. Update CSV exporter
3. Modify report generation
4. Update SLA targets

## Integration with CI/CD

### GitHub Actions Example

```yaml
- name: Run Benchmarks
  run: |
    npm run build
    npm run bench:quick

- name: Upload Benchmark Results
  uses: actions/upload-artifact@v3
  with:
    name: benchmark-results
    path: artifacts/bench/
```

### Performance Regression Detection

```bash
# Check for performance regressions
node scripts/check-performance-regression.js

# Fail CI on significant regressions
if [ $? -ne 0 ]; then
  echo "Performance regression detected!"
  exit 1
fi
```

## Support

- **Documentation**: See `/docs` directory for detailed documentation
- **Issues**: Report bugs and feature requests on GitHub
- **Discussions**: Join community discussions for questions and support

## License

MIT License - see LICENSE file for details.