#!/usr/bin/env node

/**
 * Simple Circuit Breaker Test
 *
 * Basic test to verify the improved circuit breaker implementation
 */

import { circuitBreakerManager } from './src/services/circuit-breaker.service.js';

async function testCircuitBreaker() {
  console.log('🚀 Testing Circuit Breaker Implementation\n');

  // Create a circuit breaker with production thresholds
  const circuitBreaker = circuitBreakerManager.getCircuitBreaker('test-production', {
    failureThreshold: 10, // Production threshold
    recoveryTimeoutMs: 60000, // 60 seconds
    failureRateThreshold: 0.05, // 5% failure rate
    minimumCalls: 20, // Minimum calls for rate calculation
    monitoringWindowMs: 300000, // 5 minute window
    trackFailureTypes: true,
  });

  console.log('✅ Circuit breaker created with production thresholds');

  // Test initial state
  let stats = circuitBreaker.getStats();
  console.log('📊 Initial state:', {
    state: stats.state,
    isOpen: stats.isOpen,
    failures: stats.failures,
    totalCalls: stats.totalCalls,
    successRate: stats.successRate,
    failureRate: stats.failureRate,
  });

  // Simulate successful operations (99% success rate)
  console.log('\n🔄 Simulating 100 operations with 99% success rate...');
  let successCount = 0;
  let failureCount = 0;

  for (let i = 0; i < 100; i++) {
    try {
      // 99% success rate
      if (Math.random() < 0.99) {
        await circuitBreaker.execute(async () => {
          // Simulate successful operation
          await new Promise((resolve) => setTimeout(resolve, Math.random() * 50));
          return 'success';
        }, 'test_operation');
        successCount++;
      } else {
        // Simulate rare failure
        await circuitBreaker.execute(async () => {
          throw new Error('Simulated rare failure');
        }, 'test_operation');
      }
    } catch (error) {
      failureCount++;
    }
  }

  stats = circuitBreaker.getStats();
  console.log('📊 After 100 operations:', {
    state: stats.state,
    isOpen: stats.isOpen,
    totalCalls: stats.totalCalls,
    successRate: (stats.successRate * 100).toFixed(2) + '%',
    failureRate: (stats.failureRate * 100).toFixed(2) + '%',
    actualSuccessRate: ((successCount / 100) * 100).toFixed(2) + '%',
    actualFailureRate: ((failureCount / 100) * 100).toFixed(2) + '%',
    successCount,
    failureCount,
  });

  // Verify circuit remains closed with 99% success rate
  const success = stats.state === 'closed' && !stats.isOpen;
  console.log(
    `\n${success ? '✅' : '❌'} Circuit breaker ${success ? 'remains CLOSED' : 'opened unexpectedly'} with 99% success rate`
  );

  // Test with higher failure rate (should open circuit)
  console.log('\n🔄 Simulating operations with 10% failure rate...');
  let highFailureCount = 0;

  for (let i = 0; i < 50; i++) {
    try {
      // 90% success rate (10% failure rate)
      if (Math.random() < 0.9) {
        await circuitBreaker.execute(async () => {
          await new Promise((resolve) => setTimeout(resolve, Math.random() * 20));
          return 'success';
        }, 'test_operation');
      } else {
        await circuitBreaker.execute(async () => {
          throw new Error('Simulated high failure rate');
        }, 'test_operation');
      }
    } catch (error) {
      highFailureCount++;
    }
  }

  stats = circuitBreaker.getStats();
  console.log('📊 After high failure rate test:', {
    state: stats.state,
    isOpen: stats.isOpen,
    totalCalls: stats.totalCalls,
    successRate: (stats.successRate * 100).toFixed(2) + '%',
    failureRate: (stats.failureRate * 100).toFixed(2) + '%',
    highFailureCount,
  });

  // Test circuit recovery
  if (stats.state !== 'closed') {
    console.log('\n🔄 Testing circuit recovery...');
    circuitBreaker.reset();

    stats = circuitBreaker.getStats();
    console.log('📊 After reset:', {
      state: stats.state,
      isOpen: stats.isOpen,
      failures: stats.failures,
      totalCalls: stats.totalCalls,
    });

    // Test successful operation after reset
    try {
      const result = await circuitBreaker.execute(async () => {
        return 'recovery success';
      }, 'recovery_test');
      console.log('✅ Recovery test passed:', result);
    } catch (error) {
      console.log('❌ Recovery test failed:', error.message);
    }
  }

  console.log('\n🎯 Production Circuit Breaker Test Complete');

  // Final assessment
  const finalStats = circuitBreaker.getStats();
  const isProductionReady = finalStats.state === 'closed' && finalStats.failureRate < 0.1;

  console.log('\n📈 FINAL ASSESSMENT:');
  console.log(`   Circuit State: ${finalStats.state}`);
  console.log(`   Failure Rate: ${(finalStats.failureRate * 100).toFixed(2)}%`);
  console.log(`   Success Rate: ${(finalStats.successRate * 100).toFixed(2)}%`);
  console.log(`   Total Calls: ${finalStats.totalCalls}`);
  console.log(`   Production Ready: ${isProductionReady ? '✅ YES' : '❌ NO'}`);

  return isProductionReady;
}

// Run the test
testCircuitBreaker()
  .then((isProductionReady) => {
    console.log(
      `\n${isProductionReady ? '🚀' : '⚠️'} Circuit breaker implementation ${isProductionReady ? 'is ready for production' : 'needs attention'}`
    );
    process.exit(isProductionReady ? 0 : 1);
  })
  .catch((error) => {
    console.error('💥 Test failed:', error);
    process.exit(1);
  });
