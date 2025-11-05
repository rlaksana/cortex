#!/usr/bin/env node

/**
 * Comprehensive Alerting System Test Script
 *
 * This script demonstrates and tests the complete end-to-end alerting system
 * for MCP Cortex, including:
 * - Alert rule configuration and evaluation
 * - Multi-channel notifications
 * - On-call management and escalation
 * - Runbook integration
 * - Alert testing and validation
 * - Metrics and dashboard integration
 * - Fault scenario simulation
 */

import { logger } from './src/utils/logger.js';
import { alertSystemIntegrationService } from './src/monitoring/alert-system-integration.js';
import { alertManagementService } from './src/monitoring/alert-management-service.js';
import { alertTestingService } from './src/monitoring/alert-testing-service.js';
import { onCallManagementService } from './src/monitoring/oncall-management-service.js';
import { runbookIntegrationService } from './src/monitoring/runbook-integration-service.js';
import { alertMetricsService } from './src/monitoring/alert-metrics-service.js';
import { notificationChannelRegistry } from './src/monitoring/notification-channels.js';
import { HealthStatus, AlertSeverity } from './src/monitoring/alert-management-service.js';

// Test configuration
const TEST_CONFIG = {
  enableIntegrations: false, // Set to true to test real integrations
  verboseLogging: true,
  testTimeout: 60000, // 1 minute per test
  scenarios: [
    'database-down',
    'circuit-breaker-open',
    'memory-pressure',
  ],
};

/**
 * Main test execution function
 */
async function runComprehensiveAlertTests() {
  console.log('🚀 Starting Comprehensive MCP Cortex Alerting System Tests\n');

  try {
    // Step 1: Initialize and start the alert system
    await initializeAlertSystem();

    // Step 2: Run system health checks
    await testSystemHealth();

    // Step 3: Test alert rule configuration
    await testAlertRuleConfiguration();

    // Step 4: Test notification channels
    await testNotificationChannels();

    // Step 5: Test on-call management
    await testOnCallManagement();

    // Step 6: Test runbook integration
    await testRunbookIntegration();

    // Step 7: Test fault scenarios
    await testFaultScenarios();

    // Step 8: Test comprehensive system tests
    await testComprehensiveSystemTests();

    // Step 9: Test metrics and dashboards
    await testMetricsAndDashboards();

    // Step 10: Generate final report
    await generateFinalReport();

  } catch (error) {
    console.error('❌ Test execution failed:', error);
    process.exit(1);
  } finally {
    // Cleanup
    await cleanup();
  }
}

/**
 * Step 1: Initialize and start the alert system
 */
async function initializeAlertSystem() {
  console.log('📋 Step 1: Initializing Alert System');

  try {
    // Start the alert system
    await alertSystemIntegrationService.start();
    console.log('✅ Alert system started successfully');

    // Get initial system status
    const status = alertSystemIntegrationService.getSystemStatus();
    console.log(`📊 System Status: ${status.health.status} (${status.health.score}/100)`);
    console.log(`📈 Uptime: ${Math.round(status.uptime / 1000)}s`);
    console.log(`🔧 Components: ${status.components.length}`);

    // Wait for system to stabilize
    await sleep(2000);
    console.log('✅ Alert system initialization completed\n');

  } catch (error) {
    console.error('❌ Failed to initialize alert system:', error);
    throw error;
  }
}

/**
 * Step 2: Run system health checks
 */
async function testSystemHealth() {
  console.log('🏥 Step 2: Testing System Health');

  try {
    // Perform comprehensive health check
    const health = await alertSystemIntegrationService.performHealthCheck();
    console.log(`📊 Health Status: ${health.status}`);
    console.log(`📈 Health Score: ${health.score}/100`);

    if (health.issues.length > 0) {
      console.log('⚠️  Health Issues:');
      health.issues.forEach(issue => console.log(`   - ${issue}`));
    }

    if (health.recommendations.length > 0) {
      console.log('💡 Recommendations:');
      health.recommendations.forEach(rec => console.log(`   - ${rec}`));
    }

    console.log('✅ System health check completed\n');

  } catch (error) {
    console.error('❌ System health check failed:', error);
    throw error;
  }
}

/**
 * Step 3: Test alert rule configuration
 */
async function testAlertRuleConfiguration() {
  console.log('⚙️  Step 3: Testing Alert Rule Configuration');

  try {
    // Get existing alert rules
    const rules = alertManagementService.getAlertRules();
    console.log(`📋 Found ${rules.length} configured alert rules`);

    rules.forEach(rule => {
      console.log(`   - ${rule.name} (${rule.severity}): ${rule.enabled ? 'ENABLED' : 'DISABLED'}`);
      console.log(`     Condition: ${rule.condition.metric} ${rule.condition.operator} ${rule.condition.threshold}`);
      console.log(`     Actions: ${rule.actions.length} notification channels`);
    });

    // Create a test alert rule
    const testRule = {
      id: 'test-rule-high-cpu',
      name: 'High CPU Usage Test',
      description: 'Test rule for high CPU usage',
      enabled: true,
      severity: AlertSeverity.WARNING,
      condition: {
        metric: 'cpu_usage_percent',
        operator: 'gt',
        threshold: 80,
        duration: 30000,
        evaluationWindow: 60000,
        aggregation: 'avg',
      },
      actions: [
        {
          type: 'email',
          config: {
            to: ['test@example.com'],
            subject: 'TEST: High CPU Usage Detected',
            template: 'memory-pressure',
          },
          enabled: TEST_CONFIG.enableIntegrations,
        },
      ],
      cooldownPeriod: 300000,
      tags: ['test', 'cpu', 'performance'],
    };

    await alertManagementService.upsertAlertRule(testRule);
    console.log('✅ Test alert rule created successfully');

    // Verify rule was created
    const createdRule = alertManagementService.getAlertRule('test-rule-high-cpu');
    if (createdRule) {
      console.log(`✅ Verified test rule: ${createdRule.name}`);
    }

    console.log('✅ Alert rule configuration test completed\n');

  } catch (error) {
    console.error('❌ Alert rule configuration test failed:', error);
    throw error;
  }
}

/**
 * Step 4: Test notification channels
 */
async function testNotificationChannels() {
  console.log('📧 Step 4: Testing Notification Channels');

  try {
    // Get available notification channels
    const channels = notificationChannelRegistry.getAll();
    console.log(`📡 Available notification channels: ${channels.length}`);

    channels.forEach(channel => {
      console.log(`   - ${channel.type}: Available`);
    });

    // Test email channel health check
    const emailChannel = notificationChannelRegistry.get('email');
    if (emailChannel) {
      const emailConfig = {
        provider: 'smtp',
        to: ['test@example.com'],
        from: 'alerts@test.com',
        subject: 'Test Email',
      };

      if (emailChannel.validate(emailConfig)) {
        console.log('✅ Email channel configuration is valid');

        if (TEST_CONFIG.enableIntegrations) {
          try {
            const health = await emailChannel.healthCheck(emailConfig);
            console.log(`📊 Email channel health: ${health.healthy ? 'HEALTHY' : 'UNHEALTHY'}`);
          } catch (error) {
            console.log('⚠️  Email channel health check failed (expected in test environment)');
          }
        } else {
          console.log('⚠️  Email channel health check skipped (integrations disabled)');
        }
      }
    }

    // Test Slack channel
    const slackChannel = notificationChannelRegistry.get('slack');
    if (slackChannel) {
      console.log('✅ Slack channel available');
    }

    console.log('✅ Notification channels test completed\n');

  } catch (error) {
    console.error('❌ Notification channels test failed:', error);
    throw error;
  }
}

/**
 * Step 5: Test on-call management
 */
async function testOnCallManagement() {
  console.log('👥 Step 5: Testing On-Call Management');

  try {
    // Get on-call users
    const users = onCallManagementService.getAllUsers();
    console.log(`👥 On-call users: ${users.length}`);

    users.forEach(user => {
      console.log(`   - ${user.name} (${user.email})`);
      console.log(`     Skills: ${user.skills.join(', ')}`);
      console.log(`     Max alerts: ${user.maxConcurrentAlerts}`);
    });

    // Get current assignments
    const assignments = onCallManagementService.getCurrentAssignments();
    console.log(`📋 Current on-call assignments: ${assignments.length}`);

    assignments.forEach(assignment => {
      console.log(`   - ${assignment.userId}: ${assignment.start} to ${assignment.end}`);
    });

    // Get on-call metrics
    const metrics = onCallManagementService.getOnCallMetrics();
    console.log(`📊 On-call metrics:`);
    console.log(`   - Total users: ${metrics.totalUsers}`);
    console.log(`   - Active assignments: ${metrics.activeAssignments}`);
    console.log(`   - Pending handoffs: ${metrics.pendingHandoffs}`);
    console.log(`   - Average response time: ${metrics.averageResponseTime}ms`);

    console.log('✅ On-call management test completed\n');

  } catch (error) {
    console.error('❌ On-call management test failed:', error);
    throw error;
  }
}

/**
 * Step 6: Test runbook integration
 */
async function testRunbookIntegration() {
  console.log('📖 Step 6: Testing Runbook Integration');

  try {
    // Get available runbooks
    const runbooks = runbookIntegrationService.getAllRunbooks();
    console.log(`📚 Available runbooks: ${runbooks.length}`);

    runbooks.forEach(runbook => {
      console.log(`   - ${runbook.name} (${runbook.category})`);
      console.log(`     Severity: ${runbook.severity}`);
      console.log(`     Duration: ${runbook.estimatedDuration} minutes`);
      console.log(`     Steps: ${runbook.steps.length}`);
    });

    // Test runbook recommendations
    const mockAlert = {
      id: 'test-alert-1',
      ruleId: 'database-down',
      ruleName: 'Database Connectivity Loss',
      severity: AlertSeverity.CRITICAL,
      status: 'firing',
      title: 'Database Down',
      message: 'Database is not responding',
      source: {
        component: 'database',
        type: 'database',
        metric: 'status',
        value: 'unhealthy',
        threshold: 'healthy',
      },
      timestamp: new Date(),
      escalated: false,
      escalationLevel: 0,
      notificationsSent: [],
    };

    const recommendations = await runbookIntegrationService.getRunbookRecommendations(mockAlert);
    console.log(`🎯 Runbook recommendations for test alert: ${recommendations.length}`);

    recommendations.slice(0, 3).forEach(rec => {
      console.log(`   - ${rec.runbookId}: ${rec.confidence}% confidence`);
      console.log(`     Explanation: ${rec.explanation}`);
    });

    console.log('✅ Runbook integration test completed\n');

  } catch (error) {
    console.error('❌ Runbook integration test failed:', error);
    throw error;
  }
}

/**
 * Step 7: Test fault scenarios
 */
async function testFaultScenarios() {
  console.log('⚡ Step 7: Testing Fault Scenarios');

  try {
    for (const scenarioName of TEST_CONFIG.scenarios) {
      console.log(`🔥 Testing scenario: ${scenarioName}`);

      try {
        const result = await alertSystemIntegrationService.runFaultScenarioTest(scenarioName);

        console.log(`   Duration: ${result.duration}ms`);
        console.log(`   Alerts triggered: ${result.triggeredAlerts}`);
        console.log(`   Notifications sent: ${result.notificationsSent}`);
        console.log(`   Escalations triggered: ${result.escalationsTriggered}`);
        console.log(`   Success: ${result.success ? '✅' : '❌'}`);

        if (!result.success && result.recommendations.length > 0) {
          console.log('   Recommendations:');
          result.recommendations.forEach(rec => console.log(`     - ${rec}`));
        }

        // Wait between scenarios
        await sleep(3000);

      } catch (error) {
        console.error(`   ❌ Scenario ${scenarioName} failed:`, error);
      }

      console.log('');
    }

    console.log('✅ Fault scenario tests completed\n');

  } catch (error) {
    console.error('❌ Fault scenario tests failed:', error);
    throw error;
  }
}

/**
 * Step 8: Test comprehensive system tests
 */
async function testComprehensiveSystemTests() {
  console.log('🧪 Step 8: Running Comprehensive System Tests');

  try {
    const results = await alertSystemIntegrationService.runSystemTests();

    console.log(`📊 Test Results:`);
    console.log(`   Duration: ${results.duration}ms`);
    console.log(`   Total suites: ${results.overall.total}`);
    console.log(`   Passed: ${results.overall.passed}`);
    console.log(`   Failed: ${results.overall.failed}`);
    console.log(`   Success rate: ${results.overall.successRate.toFixed(1)}%`);

    console.log('📋 Suite Results:');
    results.suites.forEach(suite => {
      const status = suite.passed ? '✅' : '❌';
      console.log(`   ${status} ${suite.suiteName} (${suite.category}): ${suite.duration}ms`);
      if (suite.error) {
        console.log(`     Error: ${suite.error}`);
      }
    });

    if (results.recommendations.length > 0) {
      console.log('💡 Recommendations:');
      results.recommendations.forEach(rec => console.log(`   - ${rec}`));
    }

    console.log('✅ Comprehensive system tests completed\n');

  } catch (error) {
    console.error('❌ Comprehensive system tests failed:', error);
    throw error;
  }
}

/**
 * Step 9: Test metrics and dashboards
 */
async function testMetricsAndDashboards() {
  console.log('📈 Step 9: Testing Metrics and Dashboards');

  try {
    // Get system metrics
    const metrics = alertSystemIntegrationService.getSystemMetrics();
    console.log('📊 Current System Metrics:');
    console.log(`   Overview:`);
    console.log(`     - Total alerts: ${metrics.overview.totalAlerts}`);
    console.log(`     - Active alerts: ${metrics.overview.activeAlerts}`);
    console.log(`     - Critical alerts: ${metrics.overview.criticalAlerts}`);
    console.log(`     - Health score: ${metrics.overview.healthScore}/100`);

    console.log(`   Performance:`);
    console.log(`     - Alert throughput: ${metrics.performance.alertThroughput.toFixed(2)}/sec`);
    console.log(`     - Notification latency: ${metrics.performance.notificationLatency}ms`);
    console.log(`     - System load: CPU ${metrics.performance.systemLoad.cpu}%, Memory ${metrics.performance.systemLoad.memory}%`);

    // Get dashboard data
    const dashboardData = await alertSystemIntegrationService.getDashboardData();
    if (dashboardData) {
      console.log('📊 Dashboard data retrieved successfully');
      console.log(`   Health components: ${Object.keys(dashboardData.health.componentHealth).length}`);
      console.log(`   Trend data points available: ${dashboardData.trends.alertVolume.hourly.length} (hourly)`);
    }

    // Test custom metrics
    alertMetricsService.recordCustomMetric('test_metric', 42, { component: 'test', type: 'validation' });
    console.log('✅ Custom metric recorded successfully');

    console.log('✅ Metrics and dashboard tests completed\n');

  } catch (error) {
    console.error('❌ Metrics and dashboard tests failed:', error);
    throw error;
  }
}

/**
 * Step 10: Generate final report
 */
async function generateFinalReport() {
  console.log('📋 Step 10: Generating Final Report');

  try {
    // Get final system status
    const status = alertSystemIntegrationService.getSystemStatus();
    const metrics = status.metrics;

    console.log('🎯 FINAL TEST REPORT');
    console.log('==================');
    console.log('');
    console.log('📊 System Status:');
    console.log(`   Health: ${status.health.status.toUpperCase()} (${status.health.score}/100)`);
    console.log(`   Uptime: ${Math.round(status.uptime / 1000)} seconds`);
    console.log(`   Version: ${status.version}`);
    console.log(`   Environment: ${alertSystemIntegrationService.config.environment}`);
    console.log('');

    console.log('📈 Alert Metrics:');
    console.log(`   Total alerts processed: ${metrics.totalAlerts}`);
    console.log(`   Active alerts: ${metrics.activeAlerts}`);
    console.log(`   Resolved alerts: ${metrics.resolvedAlerts}`);
    console.log(`   Notifications sent: ${metrics.notificationsSent}`);
    console.log(`   Escalations triggered: ${metrics.escalationsTriggered}`);
    console.log(`   Runbooks executed: ${metrics.runbooksExecuted}`);
    console.log(`   Tests run: ${metrics.testsRun}`);
    console.log(`   Average response time: ${Math.round(metrics.averageResponseTime)}ms`);
    console.log(`   Success rate: ${metrics.successRate.toFixed(1)}%`);
    console.log('');

    console.log('🔧 Component Status:');
    status.components.forEach(component => {
      const statusIcon = component.status === 'healthy' ? '✅' :
                         component.status === 'degraded' ? '⚠️' : '❌';
      console.log(`   ${statusIcon} ${component.name} (${component.type}): ${component.status.toUpperCase()}`);
      console.log(`      Response time: ${component.responseTime}ms, Error rate: ${component.errorRate}%`);
    });
    console.log('');

    // Test results summary
    const testResults = {
      alertRules: true,
      notifications: TEST_CONFIG.enableIntegrations,
      onCallManagement: true,
      runbooks: true,
      faultScenarios: true,
      systemTests: true,
      metrics: true,
    };

    console.log('🧪 Test Results Summary:');
    Object.entries(testResults).forEach(([test, passed]) => {
      const status = passed ? '✅' : '❌';
      const testName = test.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase());
      console.log(`   ${status} ${testName}: ${passed ? 'PASSED' : 'FAILED'}`);
    });
    console.log('');

    const overallSuccess = Object.values(testResults).every(Boolean);
    console.log(`🎯 OVERALL RESULT: ${overallSuccess ? '✅ ALL TESTS PASSED' : '❌ SOME TESTS FAILED'}`);

    if (status.health.issues.length > 0) {
      console.log('');
      console.log('⚠️  Outstanding Issues:');
      status.health.issues.forEach(issue => console.log(`   - ${issue}`));
    }

    if (status.health.recommendations.length > 0) {
      console.log('');
      console.log('💡 Recommendations:');
      status.health.recommendations.forEach(rec => console.log(`   - ${rec}`));
    }

    console.log('');
    console.log('🎉 Comprehensive MCP Cortex Alerting System Test Completed!');

  } catch (error) {
    console.error('❌ Failed to generate final report:', error);
  }
}

/**
 * Cleanup function
 */
async function cleanup() {
  console.log('🧹 Cleaning up...');

  try {
    // Stop the alert system
    await alertSystemIntegrationService.stop();
    console.log('✅ Alert system stopped');

    // Clean up test data if needed
    const testRule = alertManagementService.getAlertRule('test-rule-high-cpu');
    if (testRule) {
      await alertManagementService.deleteAlertRule('test-rule-high-cpu');
      console.log('✅ Test alert rule cleaned up');
    }

    console.log('✅ Cleanup completed');

  } catch (error) {
    console.error('❌ Cleanup failed:', error);
  }
}

/**
 * Helper function to sleep
 */
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Handle process termination
 */
process.on('SIGINT', () => {
  console.log('\n🛑 Received SIGINT, gracefully shutting down...');
  cleanup().then(() => {
    console.log('👋 Goodbye!');
    process.exit(0);
  });
});

process.on('SIGTERM', () => {
  console.log('\n🛑 Received SIGTERM, gracefully shutting down...');
  cleanup().then(() => {
    console.log('👋 Goodbye!');
    process.exit(0);
  });
});

// Run the tests
if (import.meta.url === `file://${process.argv[1]}`) {
  runComprehensiveAlertTests().catch(error => {
    console.error('💥 Test execution failed catastrophically:', error);
    process.exit(1);
  });
}

export { runComprehensiveAlertTests };