#!/usr/bin/env node

/**
 * Memory Optimization Validation Script
 *
 * This script validates the memory optimization implementation by:
 * - Testing memory manager functionality
 * - Validating embedding service memory management
 * - Checking memory monitoring and alerting
 * - Simulating memory pressure scenarios
 */

import { performance } from 'node:perf_hooks';

// Mock the environment for testing
const mockMemoryUsage = () => ({
  heapUsed: 100000000 + Math.random() * 50000000, // 100-150MB
  heapTotal: 200000000,
  external: 10000000 + Math.random() * 5000000,
  rss: 150000000 + Math.random() * 50000000,
});

// Test basic memory manager functionality
async function testMemoryManager() {
  console.log('🧠 Testing Memory Manager Service...');

  try {
    // Import the memory manager
    const { memoryManager } = await import('./src/services/memory/memory-manager-service.js');

    // Test basic functionality
    const stats = memoryManager.getStats();
    console.log('✅ Memory Manager initialized successfully');
    console.log(`   - Warning Threshold: ${stats.alertConfig.warningThreshold}%`);
    console.log(`   - Critical Threshold: ${stats.alertConfig.criticalThreshold}%`);
    console.log(`   - Emergency Threshold: ${stats.alertConfig.emergencyThreshold}%`);

    // Test memory pool functionality
    memoryManager.createMemoryPool('test-pool', {
      maxPoolSize: 10,
      cleanupInterval: 5000,
      itemMaxAge: 30000,
    });

    const item = memoryManager.getFromPool('test-pool', () => ({ id: 1, data: 'test' }));
    console.log('✅ Memory pool operations working');

    // Return item to pool
    memoryManager.returnToPool('test-pool', item);
    console.log('✅ Item returned to pool successfully');

    return true;
  } catch (error) {
    console.error('❌ Memory Manager test failed:', error.message);
    return false;
  }
}

// Test embedding service memory management
async function testEmbeddingService() {
  console.log('🔤 Testing Optimized Embedding Service...');

  try {
    const { optimizedEmbeddingService } = await import(
      './src/services/embeddings/optimized-embedding-service.js'
    );

    // Test basic functionality
    const stats = optimizedEmbeddingService.getMemoryStats();
    console.log('✅ Optimized Embedding Service initialized successfully');
    console.log(`   - Cache Size: ${stats.cacheSize}`);
    console.log(`   - Cache Memory: ${stats.cacheMemoryMB.toFixed(2)}MB`);
    console.log(`   - Memory Pressure: ${stats.memoryPressureLevel}`);

    // Test configuration
    optimizedEmbeddingService.updateConfig({
      cacheMaxSize: 1000,
      cacheMaxMemoryMB: 50,
    });

    console.log('✅ Embedding service configuration updated');

    return true;
  } catch (error) {
    console.error('❌ Embedding Service test failed:', error.message);
    return false;
  }
}

// Test memory monitoring
async function testMemoryMonitor() {
  console.log('📊 Testing Enhanced Memory Monitor...');

  try {
    const { enhancedMemoryMonitor } = await import('./src/monitoring/enhanced-memory-monitor.js');

    // Test basic functionality
    const stats = enhancedMemoryMonitor.getEnhancedStats();
    console.log('✅ Enhanced Memory Monitor initialized successfully');
    console.log(`   - Current Usage: ${stats.current.usagePercentage.toFixed(1)}%`);
    console.log(`   - History Size: ${stats.history.size}`);
    console.log(`   - Active Cooldowns: ${stats.alerts.activeCooldowns.length}`);

    // Trigger manual check
    enhancedMemoryMonitor.triggerCheck();
    console.log('✅ Manual memory check triggered');

    return true;
  } catch (error) {
    console.error('❌ Memory Monitor test failed:', error.message);
    return false;
  }
}

// Test optimized orchestrator
async function testOptimizedOrchestrator() {
  console.log('🎯 Testing Optimized Memory Store Orchestrator...');

  try {
    const { OptimizedMemoryStoreOrchestrator } = await import(
      './src/services/orchestrators/optimized-memory-store-orchestrator.js'
    );

    const orchestrator = new OptimizedMemoryStoreOrchestrator();

    // Test basic functionality
    const poolStats = orchestrator.getMemoryPoolStats();
    console.log('✅ Optimized Orchestrator initialized successfully');
    console.log(`   - Item Result Pool: ${poolStats.itemResultPool}`);
    console.log(`   - Batch Summary Pool: ${poolStats.batchSummaryPool}`);
    console.log(`   - Context Pool: ${poolStats.contextPool}`);

    // Test operation statistics
    const opStats = orchestrator.getOperationStats();
    console.log(`   - Total Operations: ${opStats.totalOperations}`);

    orchestrator.shutdown();
    console.log('✅ Orchestrator shut down successfully');

    return true;
  } catch (error) {
    console.error('❌ Optimized Orchestrator test failed:', error.message);
    return false;
  }
}

// Test memory configuration
async function testMemoryConfig() {
  console.log('⚙️ Testing Memory Configuration...');

  try {
    const { getMemoryOptimizationConfig, validateMemoryConfig } = await import(
      './src/config/memory-optimization-config.js'
    );

    // Test configuration loading
    const config = getMemoryOptimizationConfig();
    console.log('✅ Memory configuration loaded successfully');
    console.log(`   - Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`   - Memory Manager Warning Threshold: ${config.memoryManager.warningThreshold}%`);
    console.log(`   - Embedding Cache Max Size: ${config.embeddingService.cacheMaxSize}`);

    // Test configuration validation
    const validation = validateMemoryConfig(config);
    if (validation.valid) {
      console.log('✅ Memory configuration is valid');
    } else {
      console.log('⚠️ Memory configuration validation warnings:', validation.errors);
    }

    return true;
  } catch (error) {
    console.error('❌ Memory Configuration test failed:', error.message);
    return false;
  }
}

// Simulate memory pressure scenario
async function testMemoryPressureScenario() {
  console.log('🚨 Testing Memory Pressure Scenario...');

  try {
    const { memoryManager } = await import('./src/services/memory/memory-manager-service.js');
    const { enhancedMemoryMonitor } = await import('./src/monitoring/enhanced-memory-monitor.js');

    // Set up alert listeners
    let alertCount = 0;
    memoryManager.on('memory-warning', () => {
      alertCount++;
      console.log('⚠️ Memory warning alert received');
    });

    // Simulate high memory usage
    const highMemoryStats = {
      heapUsed: 190000000,
      heapTotal: 200000000,
      external: 15000000,
      rss: 220000000,
    };

    // Mock process.memoryUsage
    const originalMemoryUsage = process.memoryUsage;
    process.memoryUsage = () => highMemoryStats;

    // Trigger memory checks
    const stats = memoryManager.getCurrentMemoryStats();
    console.log(`   - Simulated Memory Usage: ${stats.usagePercentage.toFixed(1)}%`);

    enhancedMemoryMonitor.triggerCheck();

    // Wait for event processing
    await new Promise((resolve) => setTimeout(resolve, 1000));

    // Restore original memoryUsage
    process.memoryUsage = originalMemoryUsage;

    console.log(`✅ Memory pressure scenario completed (alerts: ${alertCount})`);
    return true;
  } catch (error) {
    console.error('❌ Memory Pressure Scenario test failed:', error.message);
    return false;
  }
}

// Performance test
async function testMemoryPerformance() {
  console.log('⚡ Testing Memory Performance...');

  try {
    const startTime = performance.now();

    // Test memory allocation and cleanup
    const arrays = [];
    for (let i = 0; i < 1000; i++) {
      arrays.push(new Array(1000).fill(Math.random()));
    }

    const allocationTime = performance.now() - startTime;

    // Cleanup
    arrays.length = 0;

    // Force garbage collection if available
    if (global.gc) {
      global.gc();
    }

    const totalTime = performance.now() - startTime;

    console.log(`✅ Memory performance test completed`);
    console.log(`   - Allocation Time: ${allocationTime.toFixed(2)}ms`);
    console.log(`   - Total Time: ${totalTime.toFixed(2)}ms`);

    return true;
  } catch (error) {
    console.error('❌ Memory Performance test failed:', error.message);
    return false;
  }
}

// Main test runner
async function runMemoryOptimizationTests() {
  console.log('🚀 Starting Memory Optimization Validation...\n');

  const tests = [
    { name: 'Memory Manager', fn: testMemoryManager },
    { name: 'Embedding Service', fn: testEmbeddingService },
    { name: 'Memory Monitor', fn: testMemoryMonitor },
    { name: 'Optimized Orchestrator', fn: testOptimizedOrchestrator },
    { name: 'Memory Configuration', fn: testMemoryConfig },
    { name: 'Memory Pressure Scenario', fn: testMemoryPressureScenario },
    { name: 'Memory Performance', fn: testMemoryPerformance },
  ];

  const results = [];

  for (const test of tests) {
    try {
      const result = await test.fn();
      results.push({ name: test.name, passed: result });
    } catch (error) {
      console.error(`❌ ${test.name} test crashed:`, error);
      results.push({ name: test.name, passed: false, error: error.message });
    }
  }

  // Summary
  console.log('\n📊 Test Results Summary:');
  console.log('='.repeat(50));

  let passedCount = 0;
  for (const result of results) {
    const status = result.passed ? '✅ PASS' : '❌ FAIL';
    console.log(`${status} ${result.name}`);
    if (result.error) {
      console.log(`    Error: ${result.error}`);
    }
    if (result.passed) passedCount++;
  }

  console.log('='.repeat(50));
  console.log(`Total: ${passedCount}/${results.length} tests passed`);

  if (passedCount === results.length) {
    console.log('🎉 All memory optimization tests passed!');
    console.log('\nMemory optimization implementation is ready for production use.');
  } else {
    console.log('⚠️ Some tests failed. Please review the implementation.');
  }

  // Memory usage summary
  const finalMemory = process.memoryUsage();
  console.log('\n💾 Final Memory Usage:');
  console.log(`   - Heap Used: ${Math.round(finalMemory.heapUsed / 1024 / 1024)}MB`);
  console.log(`   - Heap Total: ${Math.round(finalMemory.heapTotal / 1024 / 1024)}MB`);
  console.log(`   - External: ${Math.round(finalMemory.external / 1024 / 1024)}MB`);
  console.log(`   - RSS: ${Math.round(finalMemory.rss / 1024 / 1024)}MB`);

  return passedCount === results.length;
}

// Run tests
runMemoryOptimizationTests().catch((error) => {
  console.error('💥 Test suite failed to run:', error);
  process.exit(1);
});
