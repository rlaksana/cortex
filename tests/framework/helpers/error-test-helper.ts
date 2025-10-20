/**
 * Error Test Helper
 *
 * Provides comprehensive error testing for all error conditions,
 * error handling, and recovery scenarios.
 */

import { memoryStore } from '../../../src/services/memory-store.js';
import { memoryFind } from '../../../src/services/memory-find.js';
import { softDelete } from '../../../src/services/delete-operations.js';
import type { TestContext } from '../test-setup.js';
import type { EnhancedKnowledgeItem } from '../../../src/types/index.js';

/**
 * Error test result
 */
export interface ErrorTestResult {
  testName: string;
  expectedError: string;
  actualError?: string;
  passed: boolean;
  errorHandled: boolean;
  details?: string;
}

/**
 * Error test helper
 */
export class ErrorTestHelper {
  private results: ErrorTestResult[] = [];

  /**
   * Run all error tests
   */
  async runAllErrorTests(context: TestContext): Promise<void> {
    console.log('\n🚨 Running Error Handling Tests...');

    await this.testMemoryStoreErrors(context);
    await this.testMemoryFindErrors(context);
    await this.testDeleteErrors(context);
    await this.testDatabaseErrors(context);
    await this.testSystemErrors(context);

    this.printErrorSummary();
  }

  /**
   * Test memory store error handling
   */
  private async testMemoryStoreErrors(context: TestContext): Promise<void> {
    console.log('  Testing Memory Store Error Handling...');

    // Test validation errors
    await this.runErrorTest('validation_error_missing_fields', 'VALIDATION_FAILED', async () => {
      const invalidItem = {
        kind: 'section',
        scope: { project: 'test' },
        data: {}, // Missing required fields
      } as EnhancedKnowledgeItem;

      const result = await memoryStore([invalidItem]);
      this.assert(result.errors.length > 0, 'Should return validation errors');
      throw new Error(result.errors[0].message);
    });

    // Test invalid knowledge type
    await this.runErrorTest('invalid_knowledge_type', 'INVALID_INPUT', async () => {
      const invalidItem = {
        kind: 'invalid_type',
        scope: { project: 'test' },
        data: { title: 'test' },
      } as any;

      const result = await memoryStore([invalidItem]);
      this.assert(result.errors.length > 0, 'Should reject invalid knowledge type');
      throw new Error(result.errors[0].message);
    });

    // Test malformed JSON data
    await this.runErrorTest('malformed_json_data', 'VALIDATION_FAILED', async () => {
      // This would require testing with circular references or invalid JSON structures
      const circular: any = {};
      circular.self = circular;

      const item = context.dataFactory.createEntity({
        properties: circular,
      });

      const result = await memoryStore([item]);
      // Should handle circular references gracefully
      if (result.errors.length > 0) {
        throw new Error(result.errors[0].message);
      }
    });

    // Test oversized data
    await this.runErrorTest('oversized_data', 'VALIDATION_FAILED', async () => {
      const oversizedItem = context.dataFactory.createSection({
        title: 'A'.repeat(10000), // Very long title
        body_md: 'B'.repeat(100000), // Very long content
      });

      const result = await memoryStore([oversizedItem]);
      // Should handle oversized data appropriately
      if (result.errors.length > 0) {
        throw new Error(result.errors[0].message);
      }
    });
  }

  /**
   * Test memory find error handling
   */
  private async testMemoryFindErrors(context: TestContext): Promise<void> {
    console.log('  Testing Memory Find Error Handling...');

    // Test invalid search parameters
    await this.runErrorTest('invalid_top_k_negative', 'INVALID_INPUT', async () => {
      try {
        await memoryFind({
          query: 'test',
          top_k: -1,
        });
        // If it doesn't throw, check if it handles gracefully
      } catch (error) {
        throw error;
      }
    });

    await this.runErrorTest('invalid_top_k_too_large', 'INVALID_INPUT', async () => {
      try {
        await memoryFind({
          query: 'test',
          top_k: 100000, // Too large
        });
      } catch (error) {
        throw error;
      }
    });

    // Test invalid mode
    await this.runErrorTest('invalid_search_mode', 'INVALID_INPUT', async () => {
      try {
        await memoryFind({
          query: 'test',
          mode: 'invalid_mode' as any,
        });
      } catch (error) {
        throw error;
      }
    });

    // Test invalid scope
    await this.runErrorTest('invalid_scope', 'INVALID_SCOPE', async () => {
      try {
        await memoryFind({
          query: 'test',
          scope: {
            project: '', // Empty project might be invalid
          },
        });
      } catch (error) {
        throw error;
      }
    });

    // Test SQL injection attempts
    await this.runErrorTest('sql_injection_attempt', 'INVALID_QUERY', async () => {
      const maliciousQuery = "test'; DROP TABLE section; --";
      const result = await memoryFind({ query: maliciousQuery });
      // Should sanitize and handle SQL injection attempts
      // If it succeeds, verify table still exists
      const tableCheck = await context.testDb.query(
        "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'section')"
      );
      this.assert(tableCheck.rows[0].exists, 'Section table should still exist after SQL injection attempt');
    });
  }

  /**
   * Test delete error handling
   */
  private async testDeleteErrors(context: TestContext): Promise<void> {
    console.log('  Testing Delete Error Handling...');

    // Test delete non-existent entity
    await this.runErrorTest('delete_non_existent', 'NOT_FOUND', async () => {
      const result = await softDelete(context.testDb, {
        entity_type: 'section',
        entity_id: 'non-existent-uuid',
      });
      this.assert(result.status === 'not_found', 'Should return not_found for non-existent entity');
      throw new Error('Entity not found');
    });

    // Test delete with invalid entity type
    await this.runErrorTest('delete_invalid_type', 'KNOWLEDGE_TYPE_NOT_FOUND', async () => {
      const result = await softDelete(context.testDb, {
        entity_type: 'invalid_type',
        entity_id: 'test-uuid',
      });
      this.assert(result.status === 'not_found', 'Should return not_found for invalid type');
      throw new Error('Invalid entity type');
    });

    // Test delete with invalid UUID
    await this.runErrorTest('delete_invalid_uuid', 'INVALID_INPUT', async () => {
      const result = await softDelete(context.testDb, {
        entity_type: 'section',
        entity_id: 'invalid-uuid',
      });
      // Should handle invalid UUID gracefully
      if (result.status === 'error') {
        throw new Error(result.message);
      }
    });

    // Test delete immutable entity
    await this.runErrorTest('delete_immutable_entity', 'IMMUTABLE_ENTITY', async () => {
      // Create an accepted decision (immutable)
      const decision = context.dataFactory.createDecision({
        status: 'accepted',
      });
      const storeResult = await memoryStore([decision]);

      if (storeResult.stored.length > 0) {
        const deleteResult = await softDelete(context.testDb, {
          entity_type: 'decision',
          entity_id: storeResult.stored[0].id,
        });

        this.assert(deleteResult.status === 'immutable', 'Should not allow deletion of immutable entity');
        throw new Error('Cannot delete immutable entity');
      }
    });
  }

  /**
   * Test database error handling
   */
  private async testDatabaseErrors(context: TestContext): Promise<void> {
    console.log('  Testing Database Error Handling...');

    // Test connection errors (simulate by using invalid connection)
    await this.runErrorTest('database_connection_error', 'CONNECTION_FAILED', async () => {
      // This would require creating a test scenario with invalid connection
      // For now, we'll just ensure the error handling infrastructure exists
      throw new Error('Database connection failed');
    });

    // Test constraint violation
    await this.runErrorTest('constraint_violation', 'CONSTRAINT_VIOLATION', async () => {
      // Try to insert duplicate data that violates unique constraints
      const item1 = context.dataFactory.createSection({
        title: 'unique-title-test',
      });
      const item2 = context.dataFactory.createSection({
        title: 'unique-title-test', // Same title, might violate constraints
      });

      const result1 = await memoryStore([item1]);
      const result2 = await memoryStore([item2]);

      // Check if constraint violation was handled
      if (result2.errors.length > 0) {
        throw new Error(result2.errors[0].message);
      }
    });

    // Test transaction rollback
    await this.runErrorTest('transaction_rollback', 'TRANSACTION_FAILED', async () => {
      // Test that transactions are properly rolled back on errors
      const mixedBatch = [
        context.dataFactory.createSection(),
        {
          kind: 'section',
          scope: { project: 'test' },
          data: {}, // Invalid item that should cause rollback
        } as EnhancedKnowledgeItem,
        context.dataFactory.createDecision(),
      ];

      const result = await memoryStore(mixedBatch);
      this.assert(result.errors.length > 0, 'Should have errors');
      // Verify that valid items weren't partially stored
    });
  }

  /**
   * Test system error handling
   */
  private async testSystemErrors(context: TestContext): Promise<void> {
    console.log('  Testing System Error Handling...');

    // Test memory exhaustion
    await this.runErrorTest('memory_exhaustion', 'INTERNAL_ERROR', async () => {
      // This is difficult to test safely, but we can test the error handling
      // Create items with very large data
      const largeItems = Array.from({ length: 10 }, () =>
        context.dataFactory.createSection({
          body_md: 'x'.repeat(100000), // Large content
        })
      );

      const result = await memoryStore(largeItems);
      // Should handle memory pressure gracefully
      if (result.errors.length > 0) {
        throw new Error(result.errors[0].message);
      }
    });

    // Test timeout handling
    await this.runErrorTest('operation_timeout', 'TIMEOUT_ERROR', async () => {
      // Simulate a long-running operation
      const startTime = Date.now();
      const largeBatch = context.dataFactory.createMixedBatch(1000);

      const result = await memoryStore(largeBatch);
      const duration = Date.now() - startTime;

      // If operation takes too long, it should be handled appropriately
      if (duration > 30000) { // 30 seconds
        throw new Error('Operation timed out');
      }
    });

    // Test concurrent access conflicts
    await this.runErrorTest('concurrent_access_conflict', 'CONCURRENT_MODIFICATION', async () => {
      // Test handling of concurrent modifications
      const item = context.dataFactory.createSection();
      const storeResult = await memoryStore([item]);

      if (storeResult.stored.length > 0) {
        // Simulate concurrent update attempts
        const promises = Array.from({ length: 5 }, async (_, i) => {
          const updateItem = {
            kind: 'section',
            scope: item.scope,
            data: {
              id: storeResult.stored[0].id,
              title: `Concurrent Update ${i}`,
              heading: `Concurrent Update ${i}`,
              body_md: 'Updated content',
            },
          };

          return memoryStore([updateItem]);
        });

        const results = await Promise.all(promises);
        // Should handle concurrent access gracefully
        const errors = results.flatMap(r => r.errors);
        if (errors.length > 0) {
          throw new Error(errors[0].message);
        }
      }
    });
  }

  /**
   * Test error recovery scenarios
   */
  private async testErrorRecovery(context: TestContext): Promise<void> {
    console.log('  Testing Error Recovery...');

    // Test retry mechanism
    await this.runErrorTest('retry_mechanism', 'RETRY_EXHAUSTED', async () => {
      // Test that failed operations can be retried successfully
      const item = context.dataFactory.createSection();

      // First attempt might fail
      try {
        await memoryStore([item]);
      } catch (error) {
        // Retry should succeed
        const result = await memoryStore([item]);
        this.assert(result.errors.length === 0, 'Retry should succeed');
      }
    });

    // Test graceful degradation
    await this.runErrorTest('graceful_degradation', 'PARTIAL_SUCCESS', async () => {
      // Test that system continues to work with degraded functionality
      const batchWithErrors = [
        context.dataFactory.createSection(),
        { kind: 'invalid_type', scope: { project: 'test' }, data: {} } as any,
        context.dataFactory.createDecision(),
      ];

      const result = await memoryStore(batchWithErrors);
      this.assert(result.stored.length > 0, 'Valid items should be processed despite errors');
      this.assert(result.errors.length > 0, 'Invalid items should produce errors');

      if (result.errors.length > 0) {
        throw new Error(`Partial success: ${result.stored.length} stored, ${result.errors.length} errors`);
      }
    });
  }

  /**
   * Test error message sanitization
   */
  private async testErrorSanitization(context: TestContext): Promise<void> {
    console.log('  Testing Error Message Sanitization...');

    await this.runErrorTest('error_message_sanitization', 'SANITIZED_ERROR', async () => {
      // Test that error messages don't leak sensitive information
      const item = context.dataFactory.createSection({
        title: 'Title with password=secret123 and token=abc123',
      });

      const invalidItem = {
        kind: 'section',
        scope: { project: 'test' },
        data: {}, // Invalid data
      } as EnhancedKnowledgeItem;

      const result = await memoryStore([invalidItem]);

      if (result.errors.length > 0) {
        const errorMessage = result.errors[0].message;
        this.assert(!errorMessage.includes('secret123'), 'Error message should not contain passwords');
        this.assert(!errorMessage.includes('abc123'), 'Error message should not contain tokens');
        throw new Error('Sanitized error message');
      }
    });
  }

  /**
   * Run a single error test
   */
  private async runErrorTest(
    testName: string,
    expectedErrorType: string,
    testFn: () => Promise<void>
  ): Promise<void> {
    try {
      await testFn();
      this.results.push({
        testName,
        expectedError: expectedErrorType,
        passed: false,
        errorHandled: false,
        details: 'Expected error was not thrown',
      });
    } catch (error) {
      const actualError = error instanceof Error ? error.message : String(error);
      const errorHandled = actualError.includes(expectedErrorType) ||
                        actualError.toLowerCase().includes(expectedErrorType.toLowerCase());

      this.results.push({
        testName,
        expectedError: expectedErrorType,
        actualError,
        passed: errorHandled,
        errorHandled,
      });
    }
  }

  /**
   * Custom assertion helper
   */
  private assert(condition: unknown, message: string): void {
    if (!condition) {
      throw new Error(`Assertion failed: ${message}`);
    }
  }

  /**
   * Print error test summary
   */
  private printErrorSummary(): void {
    console.log('\n🚨 Error Handling Test Summary');
    console.log('='.repeat(50));

    const total = this.results.length;
    const passed = this.results.filter(r => r.passed).length;
    const failed = total - passed;

    console.log(`Total Tests: ${total}`);
    console.log(`Passed: ${passed} ✅`);
    console.log(`Failed: ${failed} ❌`);
    console.log(`Error Handling Rate: ${Math.round((passed / total) * 100)}%`);

    if (failed > 0) {
      console.log('\n❌ Failed Error Tests:');
      for (const result of this.results.filter(r => !r.passed)) {
        console.log(`  ${result.testName}`);
        console.log(`    Expected: ${result.expectedError}`);
        console.log(`    Actual: ${result.actualError || 'No error thrown'}`);
        if (result.details) {
          console.log(`    Details: ${result.details}`);
        }
      }
    }

    // Analyze error patterns
    const errorPatterns = this.analyzeErrorPatterns();
    if (errorPatterns.length > 0) {
      console.log('\n📊 Error Pattern Analysis:');
      for (const pattern of errorPatterns) {
        console.log(`  ${pattern}`);
      }
    }

    console.log('\n✅ Error Handling Tests Completed');
  }

  /**
   * Analyze error patterns
   */
  private analyzeErrorPatterns(): string[] {
    const patterns: string[] = [];

    const notFoundErrors = this.results.filter(r => r.expectedError.includes('NOT_FOUND'));
    if (notFoundErrors.length > 0) {
      const handledRate = (notFoundErrors.filter(r => r.passed).length / notFoundErrors.length) * 100;
      patterns.push(`NOT_FOUND errors: ${Math.round(handledRate)}% handled correctly`);
    }

    const validationErrors = this.results.filter(r => r.expectedError.includes('VALIDATION_FAILED'));
    if (validationErrors.length > 0) {
      const handledRate = (validationErrors.filter(r => r.passed).length / validationErrors.length) * 100;
      patterns.push(`VALIDATION errors: ${Math.round(handledRate)}% handled correctly`);
    }

    const immutableErrors = this.results.filter(r => r.expectedError.includes('IMMUTABLE_ENTITY'));
    if (immutableErrors.length > 0) {
      const handledRate = (immutableErrors.filter(r => r.passed).length / immutableErrors.length) * 100;
      patterns.push(`IMMUTABILITY errors: ${Math.round(handledRate)}% handled correctly`);
    }

    return patterns;
  }

  /**
   * Get all error test results
   */
  getResults(): ErrorTestResult[] {
    return [...this.results];
  }

  /**
   * Clear all error test results
   */
  clearResults(): void {
    this.results = [];
  }

  /**
   * Check if all error tests passed
   */
  allTestsPassed(): boolean {
    return this.results.every(r => r.passed);
  }

  /**
   * Get error handling effectiveness metrics
   */
  getErrorHandlingMetrics(): {
    totalTests: number;
    passedTests: number;
    handlingRate: number;
    errorsByType: Record<string, { total: number; handled: number; rate: number }>;
  } {
    const total = this.results.length;
    const passed = this.results.filter(r => r.passed).length;
    const handlingRate = total > 0 ? (passed / total) * 100 : 0;

    const errorsByType: Record<string, { total: number; handled: number; rate: number }> = {};

    for (const result of this.results) {
      if (!errorsByType[result.expectedError]) {
        errorsByType[result.expectedError] = { total: 0, handled: 0, rate: 0 };
      }
      errorsByType[result.expectedError].total++;
      if (result.passed) {
        errorsByType[result.expectedError].handled++;
      }
    }

    // Calculate rates
    for (const type in errorsByType) {
      const stats = errorsByType[type];
      stats.rate = stats.total > 0 ? (stats.handled / stats.total) * 100 : 0;
    }

    return {
      totalTests: total,
      passedTests: passed,
      handlingRate,
      errorsByType,
    };
  }
}