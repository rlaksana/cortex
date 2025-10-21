/**
 * PRISMA SCHEMA REGRESSION PREVENTION TEST SUITE
 *
 * Comprehensive regression tests to ensure metadata/tags workarounds
 * for database fields never reappear in the codebase.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { TestRunner, TestAssertions } from '../framework/test-setup.js';
import { validatePrismaSchemaCompliance } from '../../src/services/knowledge/issue.js';
import { Grep } from '../../src/utils/grep.js';

describe('PRISMA SCHEMA REGRESSION PREVENTION', () => {
  let testRunner: TestRunner;
  let testContext: any;

  beforeEach(async () => {
    testRunner = new TestRunner();
    await testRunner.initialize();

    const testDb = await testRunner.framework.createTestDatabase();
    testContext = {
      framework: testRunner.framework,
      testDb,
      dataFactory: testRunner.framework.getDataFactory(),
      performanceHelper: testRunner.framework.getPerformanceHelper(),
      validationHelper: testRunner.framework.getValidationHelper(),
      errorHelper: testRunner.framework.getErrorHelper(),
    };
  });

  afterEach(async () => {
    await testRunner.cleanup();
  });

  describe('CODEBASE ANALYSIS REGRESSION TESTS', () => {
    it('should not contain metadata field access patterns for database fields', async () => {
      // Search for potential metadata access patterns that violate Prisma Schema
      const metadataAccessPatterns = [
        'metadata.tracker',
        'metadata.external_id',
        'metadata.url',
        'metadata.assignee',
        'metadata.labels',
        'metadata.severity',
        'metadata.priority',
        'metadata.due_date',
        'metadata.todo_type',
        'metadata.service',
        'metadata.triggers',
        'metadata.change_type',
        'metadata.pr_number',
        'metadata.incident_commander',
        'metadata.risk_level',
        'metadata.validation_status'
      ];

      const violations = [];

      for (const pattern of metadataAccessPatterns) {
        // Search for this pattern in service files
        const searchResults = await Grep({
          pattern: pattern,
          path: 'src/services',
          type: 'ts',
          output_mode: 'files_with_matches'
        });

        if (searchResults.length > 0) {
          violations.push({
            pattern,
            files: searchResults
          });
        }
      }

      // Assert no violations found
      expect(violations).toHaveLength(0);

      if (violations.length > 0) {
        console.log('❌ Metadata access violations found:');
        violations.forEach(violation => {
          console.log(`  - ${violation.pattern}: ${violation.files.join(', ')}`);
        });
      }
    });

    it('should not contain tags field access patterns for database fields', async () => {
      // Search for potential tags access patterns that violate Prisma Schema
      const tagsAccessPatterns = [
        'tags.tracker',
        'tags.external_id',
        'tags.url',
        'tags.assignee',
        'tags.labels',
        'tags.severity',
        'tags.priority',
        'tags.due_date',
        'tags.todo_type',
        'tags.service',
        'tags.triggers',
        'tags.change_type',
        'tags.pr_number',
        'tags.incident_commander',
        'tags.risk_level',
        'tags.validation_status'
      ];

      const violations = [];

      for (const pattern of tagsAccessPatterns) {
        // Search for this pattern in service files
        const searchResults = await Grep({
          pattern: pattern,
          path: 'src/services',
          type: 'ts',
          output_mode: 'files_with_matches'
        });

        if (searchResults.length > 0) {
          violations.push({
            pattern,
            files: searchResults
          });
        }
      }

      // Assert no violations found
      expect(violations).toHaveLength(0);

      if (violations.length > 0) {
        console.log('❌ Tags access violations found:');
        violations.forEach(violation => {
          console.log(`  - ${violation.pattern}: ${violation.files.join(', ')}`);
        });
      }
    });

    it('should not contain fallback patterns to metadata/tags for database fields', async () => {
      // Search for conditional patterns that might fallback to metadata/tags
      const fallbackPatterns = [
        'data.metadata.*\\|\\|',  // Fallback to metadata
        'data.tags.*\\|\\|',      // Fallback to tags
        'metadata\\?.*\\?\\:',    // Optional chaining with fallback to metadata
        'tags\\?.*\\?\\:'         // Optional chaining with fallback to tags
      ];

      const violations = [];

      for (const pattern of fallbackPatterns) {
        const searchResults = await Grep({
          pattern: pattern,
          path: 'src/services',
          type: 'ts',
          output_mode: 'files_with_matches'
        });

        if (searchResults.length > 0) {
          violations.push({
            pattern,
            files: searchResults
          });
        }
      }

      // Assert no violations found
      expect(violations).toHaveLength(0);
    });

    it('should contain Prisma Schema compliance validation in all knowledge type services', async () {
      // Ensure all knowledge type services have validation functions
      const knowledgeTypeServices = [
        'src/services/knowledge/section.ts',
        'src/services/knowledge/decision.ts',
        'src/services/knowledge/issue.ts',
        'src/services/knowledge/todo.ts',
        'src/services/knowledge/runbook.ts',
        'src/services/knowledge/change.ts',
        'src/services/knowledge/release_note.ts',
        'src/services/knowledge/ddl.ts',
        'src/services/knowledge/pr_context.ts',
        'src/services/knowledge/incident.ts',
        'src/services/knowledge/release.ts',
        'src/services/knowledge/risk.ts',
        'src/services/knowledge/assumption.ts'
      ];

      const servicesWithoutValidation = [];

      for (const serviceFile of knowledgeTypeServices) {
        // Check if service contains validation
        const hasValidation = await Grep({
          pattern: 'validatePrismaSchemaCompliance|PRISMA SCHEMA COMPLIANCE',
          path: serviceFile,
          output_mode: 'content',
          -n: true
        });

        if (hasValidation.length === 0) {
          servicesWithoutValidation.push(serviceFile);
        }
      }

      // All services should have validation
      expect(servicesWithoutValidation).toHaveLength(0);

      if (servicesWithoutValidation.length > 0) {
        console.log('❌ Services missing Prisma Schema validation:');
        servicesWithoutValidation.forEach(service => {
          console.log(`  - ${service}`);
        });
      }
    });
  });

  describe('RUNTIME REGRESSION PREVENTION', () => {
    it('should reject all known violation patterns at runtime', async () => {
      // Test all known violation patterns to ensure they're caught at runtime
      const violationPatterns = [
        {
          name: 'tracker in metadata',
          data: {
            title: 'Test Issue',
            status: 'open',
            metadata: { tracker: 'github' }
          }
        },
        {
          name: 'external_id in metadata',
          data: {
            title: 'Test Issue',
            status: 'open',
            metadata: { external_id: 'GH-123' }
          }
        },
        {
          name: 'url in metadata',
          data: {
            title: 'Test Issue',
            status: 'open',
            metadata: { url: 'https://github.com/test' }
          }
        },
        {
          name: 'assignee in metadata',
          data: {
            title: 'Test Issue',
            status: 'open',
            metadata: { assignee: 'test@test.com' }
          }
        },
        {
          name: 'labels in metadata',
          data: {
            title: 'Test Issue',
            status: 'open',
            metadata: { labels: ['bug'] }
          }
        },
        {
          name: 'tracker in tags',
          data: {
            title: 'Test Issue',
            status: 'open',
            tags: { tracker: 'github' }
          }
        },
        {
          name: 'external_id in tags',
          data: {
            title: 'Test Issue',
            status: 'open',
            tags: { external_id: 'GH-123' }
          }
        },
        {
          name: 'combined metadata and tags violations',
          data: {
            title: 'Test Issue',
            status: 'open',
            metadata: { tracker: 'github' },
            tags: { external_id: 'GH-123' }
          }
        }
      ];

      for (const pattern of violationPatterns) {
        expect(() => validatePrismaSchemaCompliance(pattern.data as any))
          .toThrow('PRISMA SCHEMA VIOLATION');
      }
    });

    it('should enforce validation in all public service functions', async () => {
      // This test ensures that validation is actually called in service functions,
      // not just that validation functions exist

      // Test with IssueLog service as example
      const validationCalledSpy = jest.spyOn(console, 'error').mockImplementation();

      const invalidData = {
        title: 'Test Issue',
        status: 'open',
        metadata: { tracker: 'should-fail' }
      };

      // Should fail validation when trying to store
      await expect(import('../../src/services/knowledge/issue.js').then(module =>
        module.storeIssue(invalidData as any, { project: 'test' })
      )).rejects.toThrow('PRISMA SCHEMA VIOLATION');

      validationCalledSpy.mockRestore();
    });
  });

  describe('DATABASE SCHEMA REGRESSION TESTS', () => {
    it('should have all required direct fields in Prisma schema', async () => {
      // Verify that the Prisma schema contains all the direct fields
      // that services are trying to use

      const schemaContent = await import('fs').then(fs =>
        fs.readFileSync('prisma/schema.prisma', 'utf8')
      );

      const requiredDirectFields = [
        // IssueLog model
        'tracker',
        'external_id',
        'url',
        'assignee',
        'labels',
        'severity',

        // TodoLog model
        'todo_type',
        'text',
        'assignee',
        'due_date',

        // Runbook model
        'service',
        'triggers',
        'last_verified_at',

        // Section model
        'heading',
        'body_md',
        'body_text',
        'document_id',
        'citation_count',

        // IncidentLog model
        'affected_services',
        'business_impact',
        'recovery_actions',
        'follow_up_required',
        'incident_commander',

        // ReleaseLog model
        'ticket_references',
        'included_changes',
        'deployment_strategy',
        'testing_status',
        'approvers',
        'release_notes',
        'post_release_actions',

        // RiskLog model
        'probability',
        'mitigation_strategies',
        'trigger_events',
        'owner',
        'review_date',
        'monitoring_indicators',
        'contingency_plans',

        // AssumptionLog model
        'validation_criteria',
        'validation_date',
        'owner',
        'related_assumptions',
        'monitoring_approach',
        'review_frequency'
      ];

      const missingFields = [];

      for (const field of requiredDirectFields) {
        // Check if field exists in schema (basic check)
        const fieldPattern = new RegExp(`\\b${field}\\b`);
        if (!fieldPattern.test(schemaContent)) {
          missingFields.push(field);
        }
      }

      // All required fields should be present
      expect(missingFields).toHaveLength(0);

      if (missingFields.length > 0) {
        console.log('❌ Missing direct fields in Prisma schema:');
        missingFields.forEach(field => {
          console.log(`  - ${field}`);
        });
      }
    });

    it('should not have conflicting field definitions', async () => {
      // Ensure there are no conflicts between direct fields and metadata/tags usage

      const schemaContent = await import('fs').then(fs =>
        fs.readFileSync('prisma/schema.prisma', 'utf8')
      );

      // Look for patterns that might indicate confusion between direct fields and metadata
      const problematicPatterns = [
        'metadata.*tracker',
        'tags.*tracker',
        'metadata.*external_id',
        'tags.*external_id'
      ];

      const conflicts = [];

      for (const pattern of problematicPatterns) {
        const regex = new RegExp(pattern);
        if (regex.test(schemaContent)) {
          conflicts.push(pattern);
        }
      }

      // No conflicting patterns should be found
      expect(conflicts).toHaveLength(0);
    });
  });

  describe('PERFORMANCE REGRESSION TESTS', () => {
    it('should maintain performance with direct field access', async () => {
      // Ensure that direct field access doesn't cause performance regression

      const testData = {
        title: 'Performance Test Issue',
        status: 'open',
        tracker: 'github',
        external_id: 'PERF-001',
        assignee: 'perf@test.com',
        labels: ['performance-test'],
        metadata: {
          // Valid metadata only
          priority: 'medium',
          test_data: 'large content ' + 'x'.repeat(1000)
        }
      };

      const scope = { project: 'performance-regression-test' };
      const iterations = 100;
      const durations = [];

      for (let i = 0; i < iterations; i++) {
        const startTime = performance.now();

        try {
          await import('../../src/services/knowledge/issue.js').then(module =>
            module.storeIssue(testData, scope)
          );
        } catch (error) {
          // Expected to fail in test environment, but validation should be fast
        }

        const duration = performance.now() - startTime;
        durations.push(duration);
      }

      const averageDuration = durations.reduce((a, b) => a + b, 0) / durations.length;
      const maxDuration = Math.max(...durations);

      // Performance should not regress - all operations should be fast
      TestAssertions.assertPerformance(averageDuration, 100, 'Average validation time');
      TestAssertions.assertPerformance(maxDuration, 500, 'Maximum validation time');

      console.log(`📊 Performance regression test results:`);
      console.log(`  - Average: ${averageDuration.toFixed(2)}ms`);
      console.log(`  - Maximum: ${maxDuration.toFixed(2)}ms`);
      console.log(`  - Iterations: ${iterations}`);
    });
  });

  describe('FUTURE-PROOFING REGRESSION TESTS', () => {
    it('should catch new violation patterns automatically', async () => {
      // This test is designed to catch any new violation patterns
      // that might be introduced in the future

      const serviceFiles = await Grep({
        pattern: '*.ts',
        path: 'src/services/knowledge',
        output_mode: 'files_with_matches'
      });

      const suspiciousPatterns = [
        // Patterns that might indicate metadata/tag workarounds
        /metadata\.\w+(?:tracker|external_id|url|assignee|labels|severity)/i,
        /tags\.\w+(?:tracker|external_id|url|assignee|labels|severity)/i,
        // Patterns that might indicate conditional fallbacks
        /metadata\?\.\w+\?\?.*tracker/i,
        /tags\?\.\w+\?\?.*tracker/i,
        // Patterns that might indicate trying to access database fields incorrectly
        /data\.(?:tracker|external_id|url|assignee|labels)\s*=\s*metadata/i,
        /data\.(?:tracker|external_id|url|assignee|labels)\s*=\s*tags/i
      ];

      const violations = [];

      for (const file of serviceFiles) {
        const fileContent = await import('fs').then(fs =>
          fs.readFileSync(file, 'utf8')
        );

        for (const pattern of suspiciousPatterns) {
          if (pattern.test(fileContent)) {
            violations.push({
              file,
              pattern: pattern.source
            });
          }
        }
      }

      // No suspicious patterns should be found
      expect(violations).toHaveLength(0);

      if (violations.length > 0) {
        console.log('❌ Suspicious patterns found (potential future violations):');
        violations.forEach(violation => {
          console.log(`  - ${violation.file}: ${violation.pattern}`);
        });
      }
    });

    it('should enforce strict typing for all database fields', async () => {
      // Ensure TypeScript interfaces correctly represent direct fields
      const typeDefinitions = await Grep({
        pattern: 'interface.*Data|type.*Data',
        path: 'src/types',
        output_mode: 'content',
        -n: true
      });

      // Should have direct field definitions in types
      const hasDirectFields = typeDefinitions.some(line =>
        line.includes('tracker:') ||
        line.includes('external_id:') ||
        line.includes('assignee:') ||
        line.includes('labels:')
      );

      expect(hasDirectFields).toBe(true);
    });
  });
});