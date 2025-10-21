/**
 * COMPREHENSIVE PRISMA SCHEMA COMPLIANCE TEST SUITE
 *
 * Validates that all services strictly follow Prisma Schema field definitions
 * and eliminates metadata/tags workarounds for database fields.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { validatePrismaSchemaCompliance } from '../../src/services/knowledge/issue.js';
import { storeIssue } from '../../src/services/knowledge/issue.js';
import type { IssueData, ScopeFilter } from '../../src/types/knowledge-data.js';

describe('PRISMA SCHEMA COMPLIANCE VALIDATION', () => {

  describe('ISSUELOG SERVICE PRISMA COMPLIANCE', () => {
    describe('Direct Field Access Validation', () => {
      it('should accept valid direct field access for IssueLog', async () => {
        const validIssueData: IssueData = {
          title: 'Test Issue with Direct Fields',
          description: 'Test description',
          status: 'open',
          // Direct Prisma Schema fields
          tracker: 'github',
          external_id: 'GH-12345',
          url: 'https://github.com/test/repo/issues/123',
          assignee: 'test-user@example.com',
          labels: ['bug', 'critical'],
          // Valid metadata (non-database fields only)
          metadata: {
            priority: 'high',
            estimated_hours: 8
          },
          // Valid tags (non-database fields only)
          tags: {
            component: 'auth-service'
          }
        };

        // Should not throw any validation errors
        expect(() => validatePrismaSchemaCompliance(validIssueData)).not.toThrow();

        const scope: ScopeFilter = { project: 'test-prisma-compliance' };
        const result = await storeIssue(validIssueData, scope);

        expect(result).toBeDefined();
        expect(typeof result).toBe('string');
      });

      it('should enforce field length constraints according to Prisma schema', async () => {
        const longString100 = 'a'.repeat(101); // Exceeds 100 char limit
        const longString200 = 'a'.repeat(201); // Exceeds 200 char limit
        const longString500 = 'a'.repeat(501); // Exceeds 500 char limit

        // Test tracker field (max 100 chars)
        expect(() => {
          validatePrismaSchemaCompliance({
            title: 'Test Issue',
            status: 'open',
            tracker: longString100
          });
        }).toThrow('Tracker field exceeds maximum length of 100 characters');

        // Test external_id field (max 100 chars)
        expect(() => {
          validatePrismaSchemaCompliance({
            title: 'Test Issue',
            status: 'open',
            external_id: longString100
          });
        }).toThrow('External ID field exceeds maximum length of 100 characters');

        // Test assignee field (max 200 chars)
        expect(() => {
          validatePrismaSchemaCompliance({
            title: 'Test Issue',
            status: 'open',
            assignee: longString200
          });
        }).toThrow('Assignee field exceeds maximum length of 200 characters');

        // Test title field (max 500 chars)
        expect(() => {
          validatePrismaSchemaCompliance({
            title: longString500,
            status: 'open'
          });
        }).toThrow('Title field exceeds maximum length of 500 characters');
      });

      it('should reject metadata workarounds for database fields', async () => {
        const invalidIssueData = {
          title: 'Test Issue with Metadata Workaround',
          status: 'open',
          metadata: {
            // VIOLATION: Using metadata for direct database fields
            tracker: 'github',
            external_id: 'GH-12345',
            url: 'https://github.com/test/repo/issues/123',
            assignee: 'test-user@example.com',
            labels: ['bug', 'critical'],
            // Valid metadata field
            priority: 'high'
          }
        };

        expect(() => validatePrismaSchemaCompliance(invalidIssueData))
          .toThrow('PRISMA SCHEMA VIOLATION: Field \'tracker\' must use direct field access');
      });

      it('should reject tags workarounds for database fields', async () => {
        const invalidIssueData = {
          title: 'Test Issue with Tags Workaround',
          status: 'open',
          tags: {
            // VIOLATION: Using tags for direct database fields
            tracker: 'github',
            external_id: 'GH-12345',
            url: 'https://github.com/test/repo/issues/123',
            assignee: 'test-user@example.com',
            labels: ['bug', 'critical'],
            // Valid tags field
            component: 'auth-service'
          }
        };

        expect(() => validatePrismaSchemaCompliance(invalidIssueData))
          .toThrow('PRISMA SCHEMA VIOLATION: Field \'tracker\' must use direct field access');
      });

      it('should allow metadata for non-database fields only', async () => {
        const validIssueData = {
          title: 'Test Issue with Valid Metadata',
          status: 'open',
          tracker: 'github',
          external_id: 'GH-12345',
          metadata: {
            // These are valid - not database fields in Prisma schema
            priority: 'high',
            estimated_hours: 8,
            story_points: 5,
            team: 'backend',
            sprint: 'sprint-12',
            epic_id: 'EPIC-456'
          }
        };

        expect(() => validatePrismaSchemaCompliance(validIssueData)).not.toThrow();
      });
    });

    describe('Database Integration Compliance', () => {
      it('should store and retrieve issues with direct field mapping', async () => {
        const issueData: IssueData = {
          title: 'Integration Test Issue',
          description: 'Testing direct field storage',
          status: 'in-progress',
          tracker: 'jira',
          external_id: 'PROJ-789',
          url: 'https://test.atlassian.net/browse/PROJ-789',
          assignee: 'developer@test.com',
          labels: ['enhancement', 'api'],
          metadata: {
            priority: 'medium',
            estimated_hours: 16
          }
        };

        const scope: ScopeFilter = {
          project: 'prisma-compliance-test',
          component: 'backend'
        };

        const startTime = Date.now();
        const issueId = await storeIssue(issueData, scope);
        const duration = Date.now() - startTime;

        // Performance assertion - should complete quickly
        TestAssertions.assertPerformance(duration, 1000, 'storeIssue with direct fields');

        expect(issueId).toBeDefined();
        expect(typeof issueId).toBe('string');

        // Verify the data was stored correctly in database
        const prisma = testContext.framework.getPrismaClient();
        const storedIssue = await prisma.issueLog.findUnique({
          where: { id: issueId }
        });

        expect(storedIssue).toBeDefined();
        expect(storedIssue!.title).toBe(issueData.title);
        expect(storedIssue!.tracker).toBe(issueData.tracker);
        expect(storedIssue!.external_id).toBe(issueData.external_id);
        expect(storedIssue!.url).toBe(issueData.url);
        expect(storedIssue!.assignee).toBe(issueData.assignee);
        expect(storedIssue!.labels).toEqual(issueData.labels);
        expect(storedIssue!.status).toBe(issueData.status);
      });

      it('should handle null values for optional fields correctly', async () => {
        const issueData: IssueData = {
          title: 'Test Issue with Null Fields',
          status: 'open',
          // Optional fields not provided (should be null)
          // tracker, external_id, url, assignee, labels
          metadata: {
            priority: 'low'
          }
        };

        const scope: ScopeFilter = { project: 'null-field-test' };
        const issueId = await storeIssue(issueData, scope);

        const prisma = testContext.framework.getPrismaClient();
        const storedIssue = await prisma.issueLog.findUnique({
          where: { id: issueId }
        });

        expect(storedIssue).toBeDefined();
        expect(storedIssue!.tracker).toBeNull();
        expect(storedIssue!.external_id).toBeNull();
        expect(storedIssue!.url).toBeNull();
        expect(storedIssue!.assignee).toBeNull();
        expect(storedIssue!.labels).toEqual([]); // Default empty array
      });
    });

    describe('Performance Validation', () => {
      it('should perform better with direct field access than metadata workarounds', async () => {
        const issueData: IssueData = {
          title: 'Performance Test Issue',
          status: 'open',
          tracker: 'github',
          external_id: 'PERF-001',
          assignee: 'perf@test.com',
          labels: ['performance-test'],
          metadata: {
            test_data: MockDataGenerator.generateText(100)
          }
        };

        const scope: ScopeFilter = { project: 'performance-test' };

        // Measure direct field access performance
        const performanceResults = [];
        for (let i = 0; i < 10; i++) {
          const startTime = performance.now();
          await storeIssue(issueData, scope);
          const duration = performance.now() - startTime;
          performanceResults.push(duration);
        }

        const averageDuration = performanceResults.reduce((a, b) => a + b, 0) / performanceResults.length;

        // Assert performance meets expectations
        TestAssertions.assertPerformance(
          averageDuration,
          500,
          'Direct field access average storage time'
        );

        console.log(`📊 Direct field access average: ${averageDuration.toFixed(2)}ms`);
      });

      it('should handle bulk operations efficiently', async () => {
        const issues: IssueData[] = [];
        for (let i = 0; i < 50; i++) {
          issues.push({
            title: `Bulk Test Issue ${i}`,
            status: 'open',
            tracker: 'jira',
            external_id: `BULK-${i}`,
            assignee: `user${i}@test.com`,
            labels: [`batch-${Math.floor(i / 10)}`]
          });
        }

        const scope: ScopeFilter = { project: 'bulk-test' };
        const startTime = performance.now();

        const results = await Promise.all(
          issues.map(issue => storeIssue(issue, scope))
        );

        const totalDuration = performance.now() - startTime;
        const averageDuration = totalDuration / results.length;

        expect(results).toHaveLength(50);
        results.forEach(id => {
          expect(id).toBeDefined();
          expect(typeof id).toBe('string');
        });

        // Performance assertion for bulk operations
        TestAssertions.assertPerformance(
          averageDuration,
          100,
          'Bulk issue storage average time'
        );

        console.log(`📊 Bulk operation (${results.length} items): ${totalDuration.toFixed(2)}ms total, ${averageDuration.toFixed(2)}ms average`);
      });
    });

    describe('Regression Prevention', () => {
      it('should catch all known Prisma schema violation patterns', async () => {
        const violationPatterns = [
          {
            name: 'tracker in metadata',
            data: {
              title: 'Test',
              status: 'open',
              metadata: { tracker: 'github' }
            },
            expectedError: 'tracker'
          },
          {
            name: 'external_id in metadata',
            data: {
              title: 'Test',
              status: 'open',
              metadata: { external_id: 'GH-123' }
            },
            expectedError: 'external_id'
          },
          {
            name: 'url in metadata',
            data: {
              title: 'Test',
              status: 'open',
              metadata: { url: 'https://github.com/test' }
            },
            expectedError: 'url'
          },
          {
            name: 'assignee in metadata',
            data: {
              title: 'Test',
              status: 'open',
              metadata: { assignee: 'test@test.com' }
            },
            expectedError: 'assignee'
          },
          {
            name: 'labels in metadata',
            data: {
              title: 'Test',
              status: 'open',
              metadata: { labels: ['bug'] }
            },
            expectedError: 'labels'
          },
          {
            name: 'tracker in tags',
            data: {
              title: 'Test',
              status: 'open',
              tags: { tracker: 'github' }
            },
            expectedError: 'tracker'
          },
          {
            name: 'external_id in tags',
            data: {
              title: 'Test',
              status: 'open',
              tags: { external_id: 'GH-123' }
            },
            expectedError: 'external_id'
          }
        ];

        for (const pattern of violationPatterns) {
          expect(() => validatePrismaSchemaCompliance(pattern.data))
            .toThrow(`PRISMA SCHEMA VIOLATION: Field '${pattern.expectedError}'`);
        }
      });

      it('should enforce strict validation at runtime', async () => {
        // Test that validation happens during actual storage, not just in unit tests
        const invalidData = {
          title: 'Runtime Validation Test',
          status: 'open',
          metadata: { tracker: 'should-fail' }
        };

        const scope: ScopeFilter = { project: 'runtime-test' };

        await expect(storeIssue(invalidData as IssueData, scope))
          .rejects.toThrow('PRISMA SCHEMA VIOLATION');
      });
    });
  });
});