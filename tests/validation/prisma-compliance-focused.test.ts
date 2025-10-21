/**
 * FOCUSED PRISMA SCHEMA COMPLIANCE TESTS
 *
 * Simple, direct tests to validate Prisma Schema compliance without complex setup.
 */

import { describe, it, expect } from 'vitest';
import { validatePrismaSchemaCompliance } from '../../src/services/knowledge/issue.js';
import type { IssueData } from '../../src/types/knowledge-data.js';

describe('PRISMA SCHEMA COMPLIANCE - FOCUSED VALIDATION', () => {

  describe('Direct Field Access Validation', () => {
    it('should accept valid direct field access for IssueLog', () => {
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
        }
      };

      // Should not throw any validation errors
      expect(() => validatePrismaSchemaCompliance(validIssueData)).not.toThrow();
    });

    it('should reject metadata workarounds for database fields', () => {
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

    it('should reject tags workarounds for database fields', () => {
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

    it('should enforce field length constraints according to Prisma schema', () => {
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

    it('should allow metadata for non-database fields only', () => {
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

  describe('Comprehensive Violation Pattern Testing', () => {
    it('should catch all known Prisma schema violation patterns', () => {
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
        expect(() => validatePrismaSchemaCompliance(pattern.data as IssueData))
          .toThrow(`PRISMA SCHEMA VIOLATION: Field '${pattern.expectedError}'`);
      }
    });

    it('should handle null values for optional fields correctly', () => {
      const issueData: IssueData = {
        title: 'Test Issue with Null Fields',
        status: 'open',
        // Optional fields not provided (should be null)
        // tracker, external_id, url, assignee, labels
        metadata: {
          priority: 'low'
        }
      };

      expect(() => validatePrismaSchemaCompliance(issueData)).not.toThrow();
    });

    it('should validate labels as array type', () => {
      const issueData: IssueData = {
        title: 'Test Issue with Labels',
        status: 'open',
        labels: ['bug', 'critical', 'security'],
        tracker: 'github'
      };

      expect(() => validatePrismaSchemaCompliance(issueData)).not.toThrow();
    });
  });

  describe('Edge Cases and Error Conditions', () => {
    it('should handle empty metadata object', () => {
      const issueData: IssueData = {
        title: 'Test Issue',
        status: 'open',
        metadata: {}
      };

      expect(() => validatePrismaSchemaCompliance(issueData)).not.toThrow();
    });

    it('should handle empty tags object', () => {
      const issueData: IssueData = {
        title: 'Test Issue',
        status: 'open',
        tags: {}
      };

      expect(() => validatePrismaSchemaCompliance(issueData)).not.toThrow();
    });

    it('should handle missing metadata and tags', () => {
      const issueData: IssueData = {
        title: 'Test Issue',
        status: 'open',
        tracker: 'github'
      };

      expect(() => validatePrismaSchemaCompliance(issueData)).not.toThrow();
    });

    it('should handle undefined metadata', () => {
      const issueData: IssueData = {
        title: 'Test Issue',
        status: 'open',
        tracker: 'github',
        metadata: undefined
      };

      expect(() => validatePrismaSchemaCompliance(issueData)).not.toThrow();
    });

    it('should handle undefined tags', () => {
      const issueData: IssueData = {
        title: 'Test Issue',
        status: 'open',
        tracker: 'github',
        tags: undefined
      };

      expect(() => validatePrismaSchemaCompliance(issueData)).not.toThrow();
    });
  });

  describe('Performance Validation', () => {
    it('should validate quickly even with large datasets', () => {
      const largeIssueData: IssueData = {
        title: 'Test Issue with Large Data',
        status: 'open',
        tracker: 'github',
        external_id: 'GH-12345',
        assignee: 'test-user@example.com',
        labels: ['bug', 'critical'],
        metadata: {
          priority: 'high',
          // Large metadata to test performance
          description: 'x'.repeat(10000),
          notes: 'y'.repeat(5000),
          details: 'z'.repeat(2000)
        }
      };

      const startTime = performance.now();
      validatePrismaSchemaCompliance(largeIssueData);
      const duration = performance.now() - startTime;

      // Should complete quickly even with large data
      expect(duration).toBeLessThan(100); // Less than 100ms
    });

    it('should batch validate efficiently', () => {
      const issues: IssueData[] = [];
      for (let i = 0; i < 100; i++) {
        issues.push({
          title: `Test Issue ${i}`,
          status: 'open',
          tracker: 'github',
          external_id: `GH-${i}`,
          metadata: {
            priority: i % 3 === 0 ? 'high' : 'medium',
            index: i
          }
        });
      }

      const startTime = performance.now();
      issues.forEach(issue => validatePrismaSchemaCompliance(issue));
      const duration = performance.now() - startTime;

      // Should handle 100 validations quickly
      expect(duration).toBeLessThan(1000); // Less than 1 second for 100 validations
    });
  });
});