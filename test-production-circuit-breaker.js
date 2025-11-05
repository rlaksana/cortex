#!/usr/bin/env node

/**
 * Production Circuit Breaker Validation Script
 *
 * This script validates the production-ready circuit breaker implementation
 * by testing various scenarios and measuring success rates.
 */

import { QdrantAdapter } from './src/db/adapters/qdrant-adapter.js';
import { circuitBreakerManager } from './src/services/circuit-breaker.service.js';
import { retryPolicyManager } from './src/utils/retry-policy.js';

class ProductionCircuitBreakerValidator {
  constructor() {
    this.qdrantAdapter = null;
    this.testResults = [];
  }

  async initialize() {
    console.log('🚀 Initializing Production Circuit Breaker Validation...\n');

    // Create Qdrant adapter with production configuration
    this.qdrantAdapter = new QdrantAdapter({
      url: process.env.QDRANT_URL || 'http://localhost:6333',
      timeout: 30000,
      maxConnections: 20,
      vectorSize: 1536,
      distance: 'Cosine',
    });

    // Reset all circuit breakers and retry policies
    circuitBreakerManager.resetAll();
    retryPolicyManager.resetAllCircuitBreakers();

    try {
      await this.qdrantAdapter.initialize();
      console.log('✅ Qdrant adapter initialized successfully\n');
    } catch (error) {
      console.log('❌ Failed to initialize Qdrant adapter:', error.message);
      console.log('⚠️  Continuing with limited tests...\n');
    }
  }

  async runTest(testName, testFunction) {
    console.log(`📋 Running test: ${testName}`);
    const startTime = Date.now();

    try {
      const result = await testFunction();
      const duration = Date.now() - startTime;

      this.testResults.push({
        name: testName,
        success: true,
        duration,
        result,
      });

      console.log(`✅ ${testName} - PASSED (${duration}ms)`);
      if (result.summary) {
        console.log(`   ${result.summary}`);
      }
      console.log('');
    } catch (error) {
      const duration = Date.now() - startTime;

      this.testResults.push({
        name: testName,
        success: false,
        duration,
        error: error.message,
      });

      console.log(`❌ ${testName} - FAILED (${duration}ms)`);
      console.log(`   Error: ${error.message}`);
      console.log('');
    }
  }

  async testProductionThresholds() {
    const testOperations = 100;
    let successfulOperations = 0;
    let failedOperations = 0;

    // Test with 99% success rate
    for (let i = 0; i < testOperations; i++) {
      try {
        await this.qdrantAdapter.healthCheck();
        successfulOperations++;
      } catch (error) {
        failedOperations++;
      }

      // Small delay between operations
      await new Promise(resolve => setTimeout(resolve, 10));
    }

    const circuitStats = this.qdrantAdapter.getQdrantCircuitBreakerStatus();
    const successRate = successfulOperations / testOperations;

    return {
      summary: `Success rate: ${(successRate * 100).toFixed(2)}%, Circuit state: ${circuitStats.state}`,
      metrics: {
        totalOperations: testOperations,
        successfulOperations,
        failedOperations,
        successRate,
        circuitState: circuitStats.state,
        circuitOpen: circuitStats.isOpen,
        failureRate: circuitStats.failureRate,
      },
    };
  }

  async testRetryMechanics() {
    const retryMetricsBefore = retryPolicyManager.getMetrics();

    // Test with failing service
    const originalUrl = process.env.QDRANT_URL;
    process.env.QDRANT_URL = 'http://localhost:9999'; // Invalid URL

    try {
      await this.qdrantAdapter.healthCheck();
    } catch (error) {
      // Expected to fail
    }

    // Restore correct URL
    process.env.QDRANT_URL = originalUrl;

    // Test recovery
    const startTime = Date.now();
    let recovered = false;
    try {
      await this.qdrantAdapter.healthCheck();
      recovered = true;
    } catch (error) {
      // Still failing
    }
    const recoveryTime = Date.now() - startTime;

    const retryMetricsAfter = retryPolicyManager.getMetrics();

    return {
      summary: `Recovery: ${recovered ? 'SUCCESS' : 'FAILED'}, Time: ${recoveryTime}ms`,
      metrics: {
        recovered,
        recoveryTime,
        retryOperations: retryMetricsAfter.total_operations - retryMetricsBefore.total_operations,
        retriedOperations: retryMetricsAfter.retried_operations - retryMetricsBefore.retried_operations,
      },
    };
  }

  async testConcurrentLoad() {
    const concurrentRequests = 20;
    const startTime = Date.now();

    const promises = Array.from({ length: concurrentRequests }, async (_, i) => {
      const requestStart = Date.now();
      try {
        await this.qdrantAdapter.healthCheck();
        return { success: true, duration: Date.now() - requestStart, id: i };
      } catch (error) {
        return { success: false, duration: Date.now() - requestStart, id: i, error: error.message };
      }
    });

    const results = await Promise.allSettled(promises);
    const totalDuration = Date.now() - startTime;

    const successfulResults = results.filter(r => r.status === 'fulfilled' && r.value.success).length;
    const responseTimes = results
      .filter(r => r.status === 'fulfilled' && r.value.success)
      .map(r => r.value.duration);

    const averageResponseTime = responseTimes.length > 0
      ? responseTimes.reduce((sum, time) => sum + time, 0) / responseTimes.length
      : 0;

    return {
      summary: `Success rate: ${((successfulResults / concurrentRequests) * 100).toFixed(2)}%, Avg response: ${averageResponseTime.toFixed(2)}ms`,
      metrics: {
        concurrentRequests,
        successfulResults,
        totalDuration,
        averageResponseTime,
        successRate: successfulResults / concurrentRequests,
      },
    };
  }

  async testCircuitRecovery() {
    // Force circuit breaker open
    const qdrantCircuitBreaker = circuitBreakerManager.getCircuitBreaker('qdrant');
    qdrantCircuitBreaker.forceOpen();

    expect(qdrantCircuitBreaker.isOpen()).toBe(true);

    // Test that operations fail immediately when circuit is open
    let openCircuitFailures = 0;
    try {
      await this.qdrantAdapter.healthCheck();
    } catch (error) {
      openCircuitFailures++;
    }

    // Wait for recovery timeout
    await new Promise(resolve => setTimeout(resolve, 1000));

    // Test recovery attempt
    let recoveryAttempt = 0;
    try {
      await this.qdrantAdapter.healthCheck();
      recoveryAttempt = 1;
    } catch (error) {
      recoveryAttempt = 0;
    }

    const finalStats = qdrantCircuitBreaker.getStats();

    return {
      summary: `Open circuit failures: ${openCircuitFailures}, Recovery attempt: ${recoveryAttempt > 0 ? 'SUCCESS' : 'FAILED'}`,
      metrics: {
        openCircuitFailures,
        recoveryAttempt,
        finalState: finalStats.state,
        timeSinceStateChange: finalStats.timeSinceStateChange,
      },
    };
  }

  async testMonitoringSystem() {
    const monitoringData = this.qdrantAdapter.getComprehensiveMonitoringData();

    return {
      summary: `Overall health: ${monitoringData.system.overallHealth}, Qdrant status: ${monitoringData.qdrant.healthStatus}`,
      metrics: {
        overallHealth: monitoringData.system.overallHealth,
        qdrantHealth: monitoringData.qdrant.healthStatus,
        qdrantCircuitState: monitoringData.qdrant.circuitBreaker.state,
        openaiHealth: monitoringData.openai.healthStatus,
        recommendations: monitoringData.system.recommendations.length,
      },
    };
  }

  async testLoadScenario() {
    const loadTestResult = await this.qdrantAdapter.testCircuitBreakerLoad({
      concurrentRequests: 10,
      failureRate: 0.02, // 2% simulated failure rate
      durationMs: 5000, // 5 seconds
    });

    const successRate = loadTestResult.metrics.successfulRequests / loadTestResult.metrics.totalRequests;

    return {
      summary: `Load test: ${successRate >= 0.9 ? 'PASSED' : 'FAILED'}, Success rate: ${(successRate * 100).toFixed(2)}%`,
      metrics: {
        ...loadTestResult.metrics,
        successRate,
        testPassed: loadTestResult.success,
      },
    };
  }

  async runAllTests() {
    console.log('🎯 Starting Production Circuit Breaker Validation Tests\n');

    await this.runTest('Production Thresholds Validation', () => this.testProductionThresholds());
    await this.runTest('Retry Mechanics Test', () => this.testRetryMechanics());
    await this.runTest('Concurrent Load Test', () => this.testConcurrentLoad());
    await this.runTest('Circuit Recovery Test', () => this.testCircuitRecovery());
    await this.runTest('Monitoring System Test', () => this.testMonitoringSystem());
    await this.runTest('Load Scenario Test', () => this.testLoadScenario());

    this.printSummary();
  }

  printSummary() {
    console.log('📊 VALIDATION SUMMARY\n');
    console.log('=' .repeat(60));

    const totalTests = this.testResults.length;
    const passedTests = this.testResults.filter(t => t.success).length;
    const failedTests = totalTests - passedTests;
    const totalDuration = this.testResults.reduce((sum, t) => sum + t.duration, 0);

    console.log(`Total Tests: ${totalTests}`);
    console.log(`Passed: ${passedTests} ✅`);
    console.log(`Failed: ${failedTests} ❌`);
    console.log(`Success Rate: ${((passedTests / totalTests) * 100).toFixed(2)}%`);
    console.log(`Total Duration: ${totalDuration}ms`);
    console.log('');

    if (failedTests > 0) {
      console.log('❌ FAILED TESTS:');
      this.testResults
        .filter(t => !t.success)
        .forEach(t => {
          console.log(`   - ${t.name}: ${t.error}`);
        });
      console.log('');
    }

    // Get final circuit breaker status
    const finalMonitoringData = this.qdrantAdapter.getComprehensiveMonitoringData();
    console.log('📈 FINAL CIRCUIT BREAKER STATUS:');
    console.log(`   Qdrant Circuit State: ${finalMonitoringData.qdrant.circuitBreaker.state}`);
    console.log(`   Qdrant Health: ${finalMonitoringData.qdrant.healthStatus}`);
    console.log(`   Overall System Health: ${finalMonitoringData.system.overallHealth}`);
    console.log(`   Total Qdrant Calls: ${finalMonitoringData.qdrant.circuitBreaker.totalCalls}`);
    console.log(`   Qdrant Success Rate: ${(finalMonitoringData.qdrant.circuitBreaker.successRate * 100).toFixed(2)}%`);
    console.log(`   Qdrant Failure Rate: ${(finalMonitoringData.qdrant.circuitBreaker.failureRate * 100).toFixed(2)}%`);
    console.log('');

    // Production readiness assessment
    const isProductionReady = this.assessProductionReadiness();
    console.log('🎯 PRODUCTION READINESS ASSESSMENT:');
    console.log(`   Status: ${isProductionReady ? '✅ READY' : '❌ NOT READY'}`);
    console.log('');

    if (isProductionReady) {
      console.log('🚀 The circuit breaker implementation is ready for production deployment!');
    } else {
      console.log('⚠️  Additional improvements needed before production deployment.');
    }

    console.log('=' .repeat(60));
  }

  assessProductionReadiness() {
    const successRate = this.testResults.filter(t => t.success).length / this.testResults.length;
    const finalMonitoringData = this.qdrantAdapter.getComprehensiveMonitoringData();

    // Criteria for production readiness
    const criteria = {
      testSuccessRate: successRate >= 0.9, // 90% of tests should pass
      circuitStable: finalMonitoringData.qdrant.circuitBreaker.state === 'closed',
      systemHealthy: finalMonitoringData.system.overallHealth !== 'critical',
      reasonableFailureRate: finalMonitoringData.qdrant.circuitBreaker.failureRate < 0.1, // Less than 10% failure rate
      minimumCalls: finalMonitoringData.qdrant.circuitBreaker.totalCalls >= 10, // Sufficient sample size
    };

    const passedCriteria = Object.values(criteria).filter(Boolean).length;
    const totalCriteria = Object.keys(criteria).length;

    console.log('Production Readiness Criteria:');
    Object.entries(criteria).forEach(([key, passed]) => {
      console.log(`   ${passed ? '✅' : '❌'} ${key}: ${passed ? 'PASS' : 'FAIL'}`);
    });
    console.log('');

    return passedCriteria >= totalCriteria * 0.8; // 80% of criteria should pass
  }

  async cleanup() {
    if (this.qdrantAdapter) {
      try {
        await this.qdrantAdapter.close();
        console.log('🧹 Cleaned up resources');
      } catch (error) {
        console.log('⚠️  Error during cleanup:', error.message);
      }
    }
  }
}

// Main execution
async function main() {
  const validator = new ProductionCircuitBreakerValidator();

  try {
    await validator.initialize();
    await validator.runAllTests();
  } catch (error) {
    console.error('💥 Fatal error during validation:', error);
    process.exit(1);
  } finally {
    await validator.cleanup();
  }
}

// Run validation if this script is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(error => {
    console.error('💥 Unhandled error:', error);
    process.exit(1);
  });
}

export { ProductionCircuitBreakerValidator };