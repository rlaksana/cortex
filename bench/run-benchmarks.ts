#!/usr/bin/env node

/**
 * Benchmark CLI Tool
 *
 * Command-line interface for running Cortex Memory MCP benchmarks
 */

import { program } from 'commander';
import { BenchmarkRunner } from './framework/benchmark-runner.js';
import { BenchmarkDataGenerator } from './utils/data-generator.js';
import type { BenchmarkConfig } from './framework/types.js';

// Import benchmark scenarios
import {
  singleItemStoreBenchmark,
  batchStoreBenchmark,
  concurrentStoreBenchmark,
  deduplicationBenchmark,
  largeItemStoreBenchmark,
  ttlProcessingBenchmark,
} from './scenarios/memory-store-benchmark.js';

import {
  simpleSearchBenchmark,
  complexSearchBenchmark,
  concurrentSearchBenchmark,
  graphExpansionBenchmark,
  fuzzySearchBenchmark,
  largeResultSetBenchmark,
} from './scenarios/memory-find-benchmark.js';

const program = require('commander');

// CLI configuration
program.name('cortex-bench').description('Cortex Memory MCP Benchmark Tool').version('2.0.0');

// Run all benchmarks
program
  .command('run')
  .description('Run all benchmark suites')
  .option('-w, --warmup <number>', 'Warmup iterations', '3')
  .option('-i, --iterations <number>', 'Benchmark iterations', '10')
  .option('-o, --output <dir>', 'Output directory', './artifacts/bench')
  .option('-d, --delay <ms>', 'Delay between scenarios (ms)', '1000')
  .option('--no-memory-profiling', 'Disable memory profiling')
  .action(async (options) => {
    const config: BenchmarkConfig = {
      name: 'Cortex Memory MCP Full Benchmark Suite',
      version: '2.0.0',
      outputDir: options.output,
      warmupIterations: parseInt(options.warmup),
      benchmarkIterations: parseInt(options.iterations),
      scenarioDelay: parseInt(options.delay),
      enableMemoryProfiling: options.memoryProfiling,
    };

    const runner = new BenchmarkRunner(config);
    const scenarios = [
      // Memory Store Benchmarks
      singleItemStoreBenchmark,
      batchStoreBenchmark,
      deduplicationBenchmark,
      ttlProcessingBenchmark,

      // Memory Find Benchmarks
      simpleSearchBenchmark,
      complexSearchBenchmark,
      fuzzySearchBenchmark,
    ];

    try {
      const results = await runner.runSuite(scenarios);
      console.log('\n🎉 All benchmarks completed successfully!');
      process.exit(0);
    } catch (error) {
      console.error('❌ Benchmark suite failed:', error);
      process.exit(1);
    }
  });

// Run store benchmarks only
program
  .command('store')
  .description('Run memory store benchmarks')
  .option('-w, --warmup <number>', 'Warmup iterations', '3')
  .option('-i, --iterations <number>', 'Benchmark iterations', '10')
  .option('-o, --output <dir>', 'Output directory', './artifacts/bench')
  .option('-c, --concurrency <number>', 'Concurrent operations', '1')
  .option('-n, --operations <number>', 'Number of operations', '100')
  .action(async (options) => {
    const config: BenchmarkConfig = {
      name: 'Memory Store Benchmarks',
      version: '2.0.0',
      outputDir: options.output,
      warmupIterations: parseInt(options.warmup),
      benchmarkIterations: parseInt(options.iterations),
    };

    // Update scenario configs with CLI options
    const storeScenarios = [
      { ...singleItemStoreBenchmark },
      { ...batchStoreBenchmark },
      {
        ...concurrentStoreBenchmark,
        config: {
          ...concurrentStoreBenchmark.config,
          concurrency: parseInt(options.concurrency),
          operations: parseInt(options.operations),
        },
      },
      { ...deduplicationBenchmark },
      { ...largeItemStoreBenchmark },
      { ...ttlProcessingBenchmark },
    ];

    const runner = new BenchmarkRunner(config);

    try {
      const results = await runner.runSuite(storeScenarios);
      console.log('\n🎉 Store benchmarks completed successfully!');
      process.exit(0);
    } catch (error) {
      console.error('❌ Store benchmarks failed:', error);
      process.exit(1);
    }
  });

// Run search benchmarks only
program
  .command('search')
  .description('Run memory find/search benchmarks')
  .option('-w, --warmup <number>', 'Warmup iterations', '3')
  .option('-i, --iterations <number>', 'Benchmark iterations', '10')
  .option('-o, --output <dir>', 'Output directory', './artifacts/bench')
  .option('-c, --concurrency <number>', 'Concurrent operations', '1')
  .option('-n, --operations <number>', 'Number of operations', '100')
  .action(async (options) => {
    const config: BenchmarkConfig = {
      name: 'Memory Find Benchmarks',
      version: '2.0.0',
      outputDir: options.output,
      warmupIterations: parseInt(options.warmup),
      benchmarkIterations: parseInt(options.iterations),
    };

    // Update scenario configs with CLI options
    const searchScenarios = [
      { ...simpleSearchBenchmark },
      { ...complexSearchBenchmark },
      {
        ...concurrentSearchBenchmark,
        config: {
          ...concurrentSearchBenchmark.config,
          concurrency: parseInt(options.concurrency),
          operations: parseInt(options.operations),
        },
      },
      { ...graphExpansionBenchmark },
      { ...fuzzySearchBenchmark },
      { ...largeResultSetBenchmark },
    ];

    const runner = new BenchmarkRunner(config);

    try {
      const results = await runner.runSuite(searchScenarios);
      console.log('\n🎉 Search benchmarks completed successfully!');
      process.exit(0);
    } catch (error) {
      console.error('❌ Search benchmarks failed:', error);
      process.exit(1);
    }
  });

// Run load testing
program
  .command('load')
  .description('Run load testing scenarios')
  .option('-c, --concurrency <number>', 'Concurrent operations', '100')
  .option('-n, --operations <number>', 'Number of operations', '1000')
  .option('-r, --rampup <ms>', 'Ramp-up time (ms)', '5000')
  .option('-o, --output <dir>', 'Output directory', './artifacts/bench')
  .action(async (options) => {
    const config: BenchmarkConfig = {
      name: 'Load Testing',
      version: '2.0.0',
      outputDir: options.output,
      warmupIterations: 1,
      benchmarkIterations: 1,
    };

    // Configure for load testing
    const loadTestScenarios = [
      {
        ...concurrentStoreBenchmark,
        name: 'High Concurrency Store Load Test',
        config: {
          ...concurrentStoreBenchmark.config,
          concurrency: parseInt(options.concurrency),
          operations: parseInt(options.operations),
          rampUpTime: parseInt(options.rampup),
        },
      },
      {
        ...concurrentSearchBenchmark,
        name: 'High Concurrency Search Load Test',
        config: {
          ...concurrentSearchBenchmark.config,
          concurrency: parseInt(options.concurrency),
          operations: parseInt(options.operations),
          rampUpTime: parseInt(options.rampup),
        },
      },
    ];

    const runner = new BenchmarkRunner(config);

    try {
      const results = await runner.runSuite(loadTestScenarios);
      console.log('\n🎉 Load testing completed successfully!');
      process.exit(0);
    } catch (error) {
      console.error('❌ Load testing failed:', error);
      process.exit(1);
    }
  });

// Run stress testing
program
  .command('stress')
  .description('Run stress testing scenarios')
  .option('-c, --concurrency <number>', 'Concurrent operations', '500')
  .option('-n, --operations <number>', 'Number of operations', '5000')
  .option('-r, --rampup <ms>', 'Ramp-up time (ms)', '10000')
  .option('-o, --output <dir>', 'Output directory', './artifacts/bench')
  .action(async (options) => {
    const config: BenchmarkConfig = {
      name: 'Stress Testing',
      version: '2.0.0',
      outputDir: options.output,
      warmupIterations: 0,
      benchmarkIterations: 1,
    };

    // Configure for stress testing
    const stressTestScenarios = [
      {
        ...concurrentStoreBenchmark,
        name: 'Stress Test - Store Operations',
        config: {
          ...concurrentStoreBenchmark.config,
          concurrency: parseInt(options.concurrency),
          operations: parseInt(options.operations),
          rampUpTime: parseInt(options.rampup),
        },
      },
      {
        ...concurrentSearchBenchmark,
        name: 'Stress Test - Search Operations',
        config: {
          ...concurrentSearchBenchmark.config,
          concurrency: parseInt(options.concurrency),
          operations: parseInt(options.operations),
          rampUpTime: parseInt(options.rampup),
        },
      },
      {
        ...largeItemStoreBenchmark,
        name: 'Stress Test - Large Items',
        config: {
          ...largeItemStoreBenchmark.config,
          operations: 100, // Reduce for stress test
        },
      },
    ];

    const runner = new BenchmarkRunner(config);

    try {
      const results = await runner.runSuite(stressTestScenarios);
      console.log('\n🎉 Stress testing completed successfully!');
      process.exit(0);
    } catch (error) {
      console.error('❌ Stress testing failed:', error);
      process.exit(1);
    }
  });

// Generate test data
program
  .command('generate-data')
  .description('Generate test datasets for benchmarking')
  .option('-t, --type <type>', 'Dataset type (small|medium|large|enterprise)', 'medium')
  .option('-o, --output <dir>', 'Output directory', './fixtures/bench')
  .option('-n, --items <number>', 'Number of items to generate')
  .option('--save', 'Save dataset to file', true)
  .action(async (options) => {
    const generator = new BenchmarkDataGenerator();

    try {
      let dataset;

      if (options.items) {
        // Custom dataset size
        dataset = await generator.generateDataset({
          itemCount: parseInt(options.items),
          itemTypes: ['entity', 'observation', 'decision', 'issue', 'todo', 'incident', 'release'],
          sizeDistribution: { min: 500, max: 5000, average: 2000 },
          relationshipDensity: 0.15,
          embeddingDimensions: 1536,
        });
      } else {
        // Predefined dataset type
        dataset = await generator.generatePredefinedDataset(options.type as any);
      }

      console.log(`✅ Dataset generated:`);
      console.log(`   Items: ${dataset.metadata['itemCount']}`);
      console.log(`   Size: ${(dataset.metadata['totalSize'] / 1024 / 1024).toFixed(2)}MB`);
      console.log(`   Relationships: ${dataset.relationships.length}`);

      if (options.save) {
        await generator.saveDataset(dataset, `${options.output}/${dataset.metadata['name']}.json`);
      }

      process.exit(0);
    } catch (error) {
      console.error('❌ Data generation failed:', error);
      process.exit(1);
    }
  });

// Generate performance report
program
  .command('report')
  .description('Generate performance report from benchmark results')
  .argument('<results-file>', 'Path to benchmark results JSON file')
  .option('-o, --output <dir>', 'Output directory', './artifacts/bench')
  .option('-f, --format <format>', 'Report format (markdown|html|json)', 'markdown')
  .action(async (resultsFile, options) => {
    try {
      const fs = await import('fs');
      const path = await import('path');

      const resultsData = JSON.parse(fs.readFileSync(resultsFile, 'utf-8'));

      // Generate report based on format
      switch (options.format) {
        case 'markdown':
          console.log('📝 Markdown report generation not implemented yet');
          break;
        case 'html':
          console.log('🌐 HTML report generation not implemented yet');
          break;
        case 'json':
          console.log('📄 JSON report generation not implemented yet');
          break;
        default:
          console.error(`❌ Unsupported format: ${options.format}`);
          process.exit(1);
      }

      process.exit(0);
    } catch (error) {
      console.error('❌ Report generation failed:', error);
      process.exit(1);
    }
  });

// Compare benchmark results
program
  .command('compare')
  .description('Compare two benchmark results')
  .argument('<baseline>', 'Baseline results file')
  .argument('<comparison>', 'Comparison results file')
  .option('-o, --output <dir>', 'Output directory', './artifacts/bench')
  .action(async (baseline, comparison, options) => {
    try {
      const fs = await import('fs');

      const baselineData = JSON.parse(fs.readFileSync(baseline, 'utf-8'));
      const comparisonData = JSON.parse(fs.readFileSync(comparison, 'utf-8'));

      console.log('📊 Benchmark comparison:');
      console.log(`   Baseline: ${baseline}`);
      console.log(`   Comparison: ${comparison}`);

      // TODO: Implement detailed comparison logic

      process.exit(0);
    } catch (error) {
      console.error('❌ Comparison failed:', error);
      process.exit(1);
    }
  });

// List available scenarios
program
  .command('list')
  .description('List available benchmark scenarios')
  .action(() => {
    console.log('📋 Available Benchmark Scenarios:\n');

    console.log('Memory Store Scenarios:');
    console.log('  • Single Item Store - Basic single item storage');
    console.log('  • Batch Store - Store multiple items in batches');
    console.log('  • Concurrent Store - Multiple concurrent storage operations');
    console.log('  • Deduplication - Duplicate detection performance');
    console.log('  • Large Item Store - Large payload storage');
    console.log('  • TTL Processing - Time-to-live handling');

    console.log('\nMemory Find Scenarios:');
    console.log('  • Simple Search - Basic semantic search');
    console.log('  • Complex Search - Advanced search with filters');
    console.log('  • Concurrent Search - Multiple concurrent searches');
    console.log('  • Graph Expansion - Relationship-based search');
    console.log('  • Fuzzy Search - Search with typo tolerance');
    console.log('  • Large Result Set - Large result set handling');

    console.log('\nTest Scenarios:');
    console.log('  • Load Testing - High volume operations');
    console.log('  • Stress Testing - Maximum capacity testing');

    console.log('\nUsage Examples:');
    console.log('  cortex-bench run                    # Run all benchmarks');
    console.log('  cortex-bench store                   # Run store benchmarks');
    console.log('  cortex-bench search                  # Run search benchmarks');
    console.log('  cortex-bench load -c 100 -n 1000     # Load testing');
    console.log('  cortex-bench stress -c 500 -n 5000   # Stress testing');
    console.log('  cortex-bench generate-data -t large  # Generate test data');
  });

// Parse command line arguments
program.parse();

// Show help if no command provided
if (!process.argv.slice(2).length) {
  program.outputHelp();
}
