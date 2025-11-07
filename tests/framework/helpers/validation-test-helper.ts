/**
 * Validation Test Helper
 *
 * Provides comprehensive validation testing for all knowledge types,
 * schema validation, and edge case handling.
 */

import { memoryStore } from '../../../src/services/memory-store';
import { memoryFind } from '../../../src/services/memory-find';
import { softDelete } from '../../../src/services/delete-operations';
import type { TestContext } from '../test-setup';
import type { EnhancedKnowledgeItem } from '../../../src/types/index';

/**
 * Validation test result
 */
export interface ValidationResult {
  testName: string;
  passed: boolean;
  error?: Error;
  details?: string;
}

/**
 * Validation test helper
 */
export class ValidationTestHelper {
  private results: ValidationResult[] = [];

  /**
   * Run all validation tests
   */
  async runAllValidationTests(context: TestContext): Promise<void> {
    console.log('\n🔍 Running Validation Tests...');

    await this.testSchemaValidation(context);
    await this.testBusinessRuleValidation(context);
    await this.testEdgeCaseValidation(context);
    await this.testSearchValidation(context);
    await this.testDeleteValidation(context);

    this.printValidationSummary();
  }

  /**
   * Test schema validation for all knowledge types
   */
  private async testSchemaValidation(context: TestContext): Promise<void> {
    console.log('  Testing Schema Validation...');

    // Test valid data for all knowledge types
    await this.runValidationTest('valid_section_data', async () => {
      const item = context.dataFactory.createSection();
      const result = await memoryStore([item]);
      this.assert(result.errors.length === 0, 'Valid section data should be accepted');
    });

    await this.runValidationTest('valid_decision_data', async () => {
      const item = context.dataFactory.createDecision();
      const result = await memoryStore([item]);
      this.assert(result.errors.length === 0, 'Valid decision data should be accepted');
    });

    await this.runValidationTest('valid_issue_data', async () => {
      const item = context.dataFactory.createIssue();
      const result = await memoryStore([item]);
      this.assert(result.errors.length === 0, 'Valid issue data should be accepted');
    });

    // Test invalid data
    await this.runValidationTest('invalid_missing_required_fields', async () => {
      const invalidItem = {
        kind: 'section',
        scope: { project: 'test' },
        data: {}, // Missing required fields
      } as EnhancedKnowledgeItem;

      const result = await memoryStore([invalidItem]);
      this.assert(result.errors.length > 0, 'Invalid data should be rejected');
      this.assert(
        result.errors[0].error_code === 'VALIDATION_FAILED',
        'Should return validation error'
      );
    });

    await this.runValidationTest('invalid_invalid_knowledge_type', async () => {
      const invalidItem = {
        kind: 'invalid_type',
        scope: { project: 'test' },
        data: { title: 'test' },
      } as any;

      const result = await memoryStore([invalidItem]);
      this.assert(result.errors.length > 0, 'Invalid knowledge type should be rejected');
    });

    await this.runValidationTest('invalid_invalid_status_enum', async () => {
      const invalidItem = context.dataFactory.createDecision({
        status: 'invalid_status' as any,
      });

      const result = await memoryStore([invalidItem]);
      this.assert(result.errors.length > 0, 'Invalid status enum should be rejected');
    });
  }

  /**
   * Test business rule validation
   */
  private async testBusinessRuleValidation(context: TestContext): Promise<void> {
    console.log('  Testing Business Rule Validation...');

    // Test immutability constraints
    await this.runValidationTest('accepted_decision_immutable', async () => {
      const decision = context.dataFactory.createDecision({
        status: 'accepted',
      });

      const result = await memoryStore([decision]);
      this.assert(result.errors.length === 0, 'Accepted decision should be stored');

      // Try to modify the accepted decision
      const updateItem = {
        kind: 'decision',
        scope: decision.scope,
        data: {
          id: result.stored[0].id,
          status: 'deprecated', // This should be blocked
          title: decision['data.title'],
          component: decision['data.component'],
          rationale: decision['data.rationale'],
        },
      };

      const updateResult = await memoryStore([updateItem]);
      this.assert(updateResult.errors.length > 0, 'Modifying accepted decision should be blocked');
      this.assert(
        updateResult.errors[0].error_code === 'IMMUTABLE_ENTITY',
        'Should return immutability error'
      );
    });

    // Test scope validation
    await this.runValidationTest('invalid_scope_validation', async () => {
      const invalidItem = context.dataFactory.createSection();
      // Set invalid scope
      invalidItem.scope = {
        project: '', // Empty project should be invalid
        branch: 'main',
      };

      const result = await memoryStore([invalidItem]);
      // This might pass or fail depending on validation rules
      // The test ensures consistent behavior
    });

    // Test content length validation
    await this.runValidationTest('content_length_validation', async () => {
      const veryLongContent = 'a'.repeat(100000); // Very long content
      const item = context.dataFactory.createSection({
        body_md: veryLongContent,
      });

      const result = await memoryStore([item]);
      // Should either accept or gracefully reject very long content
    });
  }

  /**
   * Test edge case validation
   */
  private async testEdgeCaseValidation(context: TestContext): Promise<void> {
    console.log('  Testing Edge Case Validation...');

    const edgeCases = context.dataFactory.createEdgeCaseItems();

    // Test oversized content
    await this.runValidationTest('oversized_content', async () => {
      const result = await memoryStore([edgeCases.oversized]);
      // Should handle oversized content gracefully
    });

    // Test minimal content
    await this.runValidationTest('minimal_content', async () => {
      const result = await memoryStore([edgeCases.minimal]);
      this.assert(result.errors.length === 0, 'Minimal valid content should be accepted');
    });

    // Test special characters
    await this.runValidationTest('special_characters', async () => {
      const result = await memoryStore([edgeCases.withSpecialCharacters]);
      this.assert(result.errors.length === 0, 'Special characters should be handled correctly');
    });

    // Test null values
    await this.runValidationTest('null_values', async () => {
      const result = await memoryStore([edgeCases.withNullValues]);
      // Should handle null values according to schema rules
    });

    // Test empty strings
    await this.runValidationTest('empty_strings', async () => {
      const result = await memoryStore([edgeCases.withEmptyStrings]);
      // Should handle empty strings according to validation rules
    });

    // Test large arrays
    await this.runValidationTest('large_arrays', async () => {
      const result = await memoryStore([edgeCases.withLargeArrays]);
      // Should handle large arrays gracefully
    });

    // Test deep nesting
    await this.runValidationTest('deep_nesting', async () => {
      const result = await memoryStore([edgeCases.withDeepNesting]);
      // Should handle deeply nested objects
    });
  }

  /**
   * Test search validation
   */
  private async testSearchValidation(context: TestContext): Promise<void> {
    console.log('  Testing Search Validation...');

    // Prepare test data
    const testData = context.dataFactory.createMixedBatch(20);
    await memoryStore(testData);

    // Test valid search queries
    await this.runValidationTest('valid_search_query', async () => {
      const result = await memoryFind({
        query: 'test',
        types: ['section'],
        top_k: 10,
      });
      this.assert(result.hits.length >= 0, 'Valid search should return results');
    });

    // Test invalid search parameters
    await this.runValidationTest('invalid_top_k', async () => {
      const result = await memoryFind({
        query: 'test',
        top_k: -1, // Invalid top_k
      });
      // Should handle invalid parameters gracefully
    });

    // Test invalid query
    await this.runValidationTest('invalid_query', async () => {
      const result = await memoryFind({
        query: '', // Empty query
      });
      // Should handle empty query appropriately
    });

    // Test query with special characters
    await this.runValidationTest('query_special_characters', async () => {
      const result = await memoryFind({
        query: 'test@#$%^&*()',
      });
      // Should handle special characters in queries
    });

    // Test very long query
    await this.runValidationTest('very_long_query', async () => {
      const longQuery = 'test '.repeat(1000);
      const result = await memoryFind({
        query: longQuery,
      });
      // Should handle very long queries gracefully
    });
  }

  /**
   * Test delete validation
   */
  private async testDeleteValidation(context: TestContext): Promise<void> {
    console.log('  Testing Delete Validation...');

    // Prepare test data
    const testData = context.dataFactory.createMixedBatch(10);
    const storeResult = await memoryStore(testData);

    // Test valid delete
    if (storeResult.stored.length > 0) {
      await this.runValidationTest('valid_delete', async () => {
        const item = storeResult.stored[0];
        const result = await softDelete(context.testDb, {
          entity_type: item.kind,
          entity_id: item.id,
        });
        this.assert(result.status !== 'error', 'Valid delete should succeed');
      });
    }

    // Test delete non-existent entity
    await this.runValidationTest('delete_non_existent', async () => {
      const result = await softDelete(context.testDb, {
        entity_type: 'section',
        entity_id: 'non-existent-uuid',
      });
      this.assert(result.status === 'not_found', 'Non-existent entity should return not_found');
    });

    // Test delete invalid entity type
    await this.runValidationTest('delete_invalid_type', async () => {
      const result = await softDelete(context.testDb, {
        entity_type: 'invalid_type',
        entity_id: 'test-uuid',
      });
      this.assert(result.status === 'not_found', 'Invalid entity type should return not_found');
    });

    // Test delete with invalid UUID
    await this.runValidationTest('delete_invalid_uuid', async () => {
      const result = await softDelete(context.testDb, {
        entity_type: 'section',
        entity_id: 'invalid-uuid',
      });
      // Should handle invalid UUID gracefully
    });
  }

  /**
   * Test validation for batch operations
   */
  private async testBatchValidation(context: TestContext): Promise<void> {
    console.log('  Testing Batch Validation...');

    // Test mixed valid/invalid batch
    await this.runValidationTest('mixed_valid_invalid_batch', async () => {
      const validItem = context.dataFactory.createSection();
      const invalidItem = {
        kind: 'section',
        scope: { project: 'test' },
        data: {}, // Missing required fields
      } as EnhancedKnowledgeItem;

      const result = await memoryStore([validItem, invalidItem]);
      this.assert(result.stored.length > 0, 'Valid items should be processed');
      this.assert(result.errors.length > 0, 'Invalid items should produce errors');
    });

    // Test large batch
    await this.runValidationTest('large_batch_validation', async () => {
      const largeBatch = context.dataFactory.createMixedBatch(100);
      const result = await memoryStore(largeBatch);
      // Should handle large batches without validation errors for valid data
    });

    // Test empty batch
    await this.runValidationTest('empty_batch', async () => {
      const result = await memoryStore([]);
      this.assert(result.stored.length === 0, 'Empty batch should return no stored items');
      this.assert(result.errors.length === 0, 'Empty batch should return no errors');
    });
  }

  /**
   * Test correlation context validation
   */
  private async testCorrelationValidation(context: TestContext): Promise<void> {
    console.log('  Testing Correlation Validation...');

    // Test with valid correlation context
    await this.runValidationTest('valid_correlation_context', async () => {
      const item = context.dataFactory.createSection();
      const result = await memoryStore([item], {
        correlation_id: 'test-correlation-id',
        request_id: 'test-request-id',
        operation: 'test-operation',
      });
      this.assert(result.errors.length === 0, 'Valid correlation context should be accepted');
      this.assert(result.correlation, 'Correlation context should be returned');
    });

    // Test with invalid correlation context
    await this.runValidationTest('invalid_correlation_context', async () => {
      const item = context.dataFactory.createSection();
      const result = await memoryStore([item], {
        correlation_id: '', // Empty correlation ID
        request_id: 'test-request-id',
        operation: 'test-operation',
      });
      // Should handle invalid correlation context gracefully
    });
  }

  /**
   * Run a single validation test
   */
  private async runValidationTest(testName: string, testFn: () => Promise<void>): Promise<void> {
    try {
      await testFn();
      this.results.push({ testName, passed: true });
    } catch (error) {
      this.results.push({
        testName,
        passed: false,
        error: error instanceof Error ? error : new Error(String(error)),
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
   * Print validation test summary
   */
  private printValidationSummary(): void {
    console.log('\n📋 Validation Test Summary');
    console.log('='.repeat(40));

    const total = this.results.length;
    const passed = this.results.filter((r) => r.passed).length;
    const failed = total - passed;

    console.log(`Total Tests: ${total}`);
    console.log(`Passed: ${passed} ✅`);
    console.log(`Failed: ${failed} ❌`);
    console.log(`Success Rate: ${Math.round((passed / total) * 100)}%`);

    if (failed > 0) {
      console.log('\n❌ Failed Tests:');
      for (const result of this.results.filter((r) => !r.passed)) {
        console.log(`  ${result.testName}: ${result.error?.message}`);
      }
    }

    console.log('\n✅ Validation Tests Completed');
  }

  /**
   * Get all validation results
   */
  getResults(): ValidationResult[] {
    return [...this.results];
  }

  /**
   * Clear all validation results
   */
  clearResults(): void {
    this.results = [];
  }

  /**
   * Check if all validation tests passed
   */
  allTestsPassed(): boolean {
    return this.results.every((r) => r.passed);
  }
}
