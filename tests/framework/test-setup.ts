/**
 * Comprehensive Test Framework for Cortex Memory MCP
 *
 * Provides testing utilities, data factories, and setup/teardown functions
 * for all 16 knowledge types and their operations.
 */

// PostgreSQL import removed - now using Qdrant;
import { getQdrantClient } from '../../src/db/pool';
import {
  TestDataFactory,
  DatabaseTestHelper,
  PerformanceTestHelper,
  ValidationTestHelper,
  ErrorTestHelper,
} from './helpers/index';

/**
 * Main test framework class
 */
export class CortexMemoryTestFramework {
  private pool: QdrantClient;
  private testDatabases: string[] = [];

  constructor() {
    this.pool = getQdrantClient();
  }

  /**
   * Initialize the test framework
   */
  async initialize(): Promise<void> {
    await DatabaseTestHelper.setupTestEnvironment(this.pool);
  }

  /**
   * Clean up the test framework
   */
  async cleanup(): Promise<void> {
    for (const dbName of this.testDatabases) {
      await DatabaseTestHelper.cleanupTestDatabase(dbName);
    }
    await this.pool.end();
  }

  /**
   * Create a test database and return its connection
   */
  async createTestDatabase(name?: string): Promise<QdrantClient> {
    const dbName =
      name || `test_cortex_memory_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`;
    this.testDatabases.push(dbName);
    return DatabaseTestHelper.setupTestDatabase(dbName);
  }

  /**
   * Get test data factory
   */
  getDataFactory(): TestDataFactory {
    return new TestDataFactory();
  }

  /**
   * Get performance test helper
   */
  getPerformanceHelper(): PerformanceTestHelper {
    return new PerformanceTestHelper();
  }

  /**
   * Get validation test helper
   */
  getValidationHelper(): ValidationTestHelper {
    return new ValidationTestHelper();
  }

  /**
   * Get error test helper
   */
  getErrorHelper(): ErrorTestHelper {
    return new ErrorTestHelper();
  }
}

/**
 * Test interfaces and types
 */
export interface TestContext {
  framework: CortexMemoryTestFramework;
  testDb: QdrantClient;
  dataFactory: TestDataFactory;
  performanceHelper: PerformanceTestHelper;
  validationHelper: ValidationTestHelper;
  errorHelper: ErrorTestHelper;
}

export interface TestScenario {
  name: string;
  description: string;
  setup?: (context: TestContext) => Promise<void>;
  teardown?: (context: TestContext) => Promise<void>;
  tests: TestCase[];
}

export interface TestCase {
  name: string;
  description: string;
  timeout?: number;
  test: (context: TestContext) => Promise<void>;
}

export interface TestResult {
  scenario: string;
  testCase: string;
  status: 'passed' | 'failed' | 'skipped' | 'timeout';
  duration: number;
  error?: Error;
  performance?: {
    operation: string;
    duration: number;
    memoryUsage: number;
  };
}

/**
 * Test runner for executing test scenarios
 */
export class TestRunner {
  private framework: CortexMemoryTestFramework;
  private results: TestResult[] = [];

  constructor() {
    this.framework = new CortexMemoryTestFramework();
  }

  /**
   * Run a complete test scenario
   */
  async runScenario(scenario: TestScenario): Promise<TestResult[]> {
    const testDb = await this.framework.createTestDatabase();
    const context: TestContext = {
      framework: this.framework,
      testDb,
      dataFactory: this.framework.getDataFactory(),
      performanceHelper: this.framework.getPerformanceHelper(),
      validationHelper: this.framework.getValidationHelper(),
      errorHelper: this.framework.getErrorHelper(),
    };

    try {
      if (scenario.setup) {
        await scenario.setup(context);
      }

      console.log(`\n🧪 Running scenario: ${scenario.name}`);
      console.log(`📝 ${scenario.description}`);

      const scenarioResults: TestResult[] = [];

      for (const testCase of scenario.tests) {
        const result = await this.runTestCase(testCase, context);
        scenarioResults.push(result);
        this.results.push(result);
      }

      if (scenario.teardown) {
        await scenario.teardown(context);
      }

      return scenarioResults;
    } finally {
      await testDb.end();
    }
  }

  /**
   * Run a single test case
   */
  private async runTestCase(testCase: TestCase, context: TestContext): Promise<TestResult> {
    const startTime = Date.now();
    console.log(`  ⚡ ${testCase.name}...`);

    try {
      const timeoutMs = testCase.timeout || 30000; // Default 30s timeout
      await Promise.race([
        testCase.test(context),
        new Promise((_, reject) => setTimeout(() => reject(new Error('Test timeout')), timeoutMs)),
      ]);

      const duration = Date.now() - startTime;
      console.log(`    ✅ ${testCase.name} (${duration}ms)`);

      return {
        scenario: '',
        testCase: testCase.name,
        status: 'passed',
        duration,
      };
    } catch (error) {
      const duration = Date.now() - startTime;
      console.log(`    ❌ ${testCase.name} (${duration}ms)`);
      console.log(`       Error: ${error instanceof Error ? error.message : String(error)}`);

      return {
        scenario: '',
        testCase: testCase.name,
        status: error instanceof Error && error.message === 'Test timeout' ? 'timeout' : 'failed',
        duration,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Get all test results
   */
  getResults(): TestResult[] {
    return this.results;
  }

  /**
   * Get test summary
   */
  getSummary(): {
    total: number;
    passed: number;
    failed: number;
    skipped: number;
    timeout: number;
    totalDuration: number;
    averageDuration: number;
  } {
    const total = this.results.length;
    const passed = this.results.filter((r) => r.status === 'passed').length;
    const failed = this.results.filter((r) => r.status === 'failed').length;
    const timeout = this.results.filter((r) => r.status === 'timeout').length;
    const skipped = this.results.filter((r) => r.status === 'skipped').length;
    const totalDuration = this.results.reduce((sum, r) => sum + r.duration, 0);
    const averageDuration = total > 0 ? totalDuration / total : 0;

    return {
      total,
      passed,
      failed,
      skipped,
      timeout,
      totalDuration,
      averageDuration,
    };
  }

  /**
   * Print test summary
   */
  printSummary(): void {
    const summary = this.getSummary();

    console.log('\n📊 Test Results Summary');
    console.log('='.repeat(50));
    console.log(`Total Tests:     ${summary.total}`);
    console.log(`Passed:          ${summary.passed} ✅`);
    console.log(`Failed:          ${summary.failed} ❌`);
    console.log(`Timeout:         ${summary.timeout} ⏰`);
    console.log(`Skipped:         ${summary.skipped} ⏭️`);
    console.log(`Total Duration:  ${summary.totalDuration}ms`);
    console.log(`Average:         ${Math.round(summary.averageDuration)}ms`);
    console.log(`Success Rate:    ${Math.round((summary.passed / summary.total) * 100)}%`);

    if (summary.failed > 0) {
      console.log('\n❌ Failed Tests:');
      this.results
        .filter((r) => r.status === 'failed')
        .forEach((r) => {
          console.log(`  - ${r.testCase}: ${r.error?.message}`);
        });
    }

    if (summary.timeout > 0) {
      console.log('\n⏰ Timeout Tests:');
      this.results
        .filter((r) => r.status === 'timeout')
        .forEach((r) => {
          console.log(`  - ${r.testCase}`);
        });
    }
  }

  /**
   * Initialize and cleanup the test framework
   */
  async initialize(): Promise<void> {
    await this.framework.initialize();
  }

  async cleanup(): Promise<void> {
    await this.framework.cleanup();
  }
}

/**
 * Global test runner instance
 */
export const testRunner = new TestRunner();

/**
 * Convenience function to run tests
 */
export async function runTests(scenarios: TestScenario[]): Promise<void> {
  await testRunner.initialize();

  try {
    for (const scenario of scenarios) {
      await testRunner.runScenario(scenario);
    }

    testRunner.printSummary();

    const summary = testRunner.getSummary();
    if (summary.failed > 0 || summary.timeout > 0) {
      process.exit(1);
    }
  } finally {
    await testRunner.cleanup();
  }
}

/**
 * Common test assertions
 */
export class TestAssertions {
  static assert<T>(condition: T, message?: string): asserts condition {
    if (!condition) {
      throw new Error(message || 'Assertion failed');
    }
  }

  static assertEquals<T>(actual: T, expected: T, message?: string): void {
    if (actual !== expected) {
      throw new Error(message || `Expected ${expected}, but got ${actual}`);
    }
  }

  static assertNotEquals<T>(actual: T, expected: T, message?: string): void {
    if (actual === expected) {
      throw new Error(message || `Expected ${actual} to not equal ${expected}`);
    }
  }

  static assertArrayEquals<T>(actual: T[], expected: T[], message?: string): void {
    if (actual.length !== expected.length) {
      throw new Error(
        message || `Expected array of length ${expected.length}, but got ${actual.length}`
      );
    }

    for (let i = 0; i < expected.length; i++) {
      if (actual[i] !== expected[i]) {
        throw new Error(
          message ||
            `Array elements differ at index ${i}: expected ${expected[i]}, but got ${actual[i]}`
        );
      }
    }
  }

  static assertContains<T>(array: T[], item: T, message?: string): void {
    if (!array.includes(item)) {
      throw new Error(message || `Expected array to contain ${item}`);
    }
  }

  static assertThrows<T>(fn: () => Promise<T> | T, expectedError?: string): Promise<void> {
    return (async () => {
      try {
        await fn();
        throw new Error('Expected function to throw an error');
      } catch (error) {
        if (expectedError && error instanceof Error && !error.message.includes(expectedError)) {
          throw new Error(
            `Expected error to contain "${expectedError}", but got "${error.message}"`
          );
        }
      }
    })();
  }

  static assertPerformance(duration: number, maxDuration: number, operation: string): void {
    if (duration > maxDuration) {
      throw new Error(
        `Performance assertion failed: ${operation} took ${duration}ms (max: ${maxDuration}ms)`
      );
    }
  }
}

/**
 * Mock data generators
 */
export class MockDataGenerator {
  static generateUUID(): string {
    return `test-uuid-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  static generateText(length: number): string {
    const words = [
      'lorem',
      'ipsum',
      'dolor',
      'sit',
      'amet',
      'consectetur',
      'adipiscing',
      'elit',
      'sed',
      'do',
      'eiusmod',
      'tempor',
      'incididunt',
      'ut',
      'labore',
      'et',
      'dolore',
      'magna',
      'aliqua',
    ];
    const result = [];
    for (let i = 0; i < length; i++) {
      result.push(words[Math.floor(Math.random() * words.length)]);
    }
    return result.join(' ');
  }

  static generateMarkdown(): string {
    const sections = [
      '# Introduction',
      'This is a test markdown document.',
      '## Features',
      '- Feature 1',
      '- Feature 2',
      '## Usage',
      '```typescript\nconst example = "test";\n```',
      '## Conclusion',
      'This concludes the test document.',
    ];
    return sections.join('\n\n');
  }

  static generateTimestamp(offsetDays: number = 0): string {
    const date = new Date();
    date.setDate(date.getDate() + offsetDays);
    return date.toISOString();
  }

  static generateScope(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
      project: 'test-project',
      branch: 'main',
      org: 'test-org',
      ...overrides,
    };
  }
}
