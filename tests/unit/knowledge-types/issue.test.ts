/**
 * Comprehensive Unit Tests for Issue Knowledge Type
 *
 * Tests issue knowledge type functionality including:
 * - Issue validation with all required fields
 * - Severity validation (low, medium, high, critical)
 * - Status constraints (open, in_progress, resolved, closed, won't_fix, duplicate)
 * - Issue type validation (bug, feature_request, improvement, task, question)
 * - Affected components and metadata handling
 * - Storage operations with batch processing
 * - Search functionality and filtering
 * - Scope isolation by project and branch
 * - Error handling and edge cases
 * - Integration with knowledge system
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { VectorDatabase } from '../../../src/index';
import { IssueSchema, validateKnowledgeItem } from '../../../src/schemas/knowledge-types';

// Mock Qdrant client - reusing pattern from memory-store.test.ts
vi.mock('@qdrant/js-client-rest', () => ({
  QdrantClient: class {
    constructor() {
      this.getCollections = vi.fn().mockResolvedValue({
        collections: [{ name: 'test-collection' }],
      });
      this.createCollection = vi.fn().mockResolvedValue(undefined);
      this.upsert = vi.fn().mockResolvedValue(undefined);
      this.search = vi.fn().mockResolvedValue([]);
      this.getCollection = vi.fn().mockResolvedValue({
        points_count: 0,
        status: 'green',
      });
      this.delete = vi.fn().mockResolvedValue({ status: 'completed' });
      this.count = vi.fn().mockResolvedValue({ count: 0 });
      this.healthCheck = vi.fn().mockResolvedValue(true);
    }
  },
}));

describe('Issue Knowledge Type - Comprehensive Testing', () => {
  let db: VectorDatabase;
  let mockQdrant: any;

  beforeEach(() => {
    db = new VectorDatabase();
    mockQdrant = (db as any).client;
  });

  describe('Issue Schema Validation', () => {
    it('should validate complete issue with all fields', () => {
      const issue = {
        kind: 'issue' as const,
        scope: {
          project: 'test-project',
          branch: 'main',
        },
        data: {
          tracker: 'github',
          external_id: 'GH-123',
          title: 'User authentication fails with OAuth 2.0',
          description:
            'Users are unable to authenticate using OAuth 2.0 tokens. The system returns 401 errors even with valid tokens.',
          status: 'open' as const,
          assignee: 'developer@example.com',
          labels: ['security', 'authentication'],
          url: 'https://github.com/test-project/issues/123',
        },
        tags: { security: true, authentication: true },
        source: {
          actor: 'support-system',
          tool: 'issue-tracker',
          timestamp: '2025-01-01T00:00:00Z',
        },
      };

      const result = IssueSchema.safeParse(issue);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.kind).toBe('issue');
        expect(result.data.data.title).toBe('User authentication fails with OAuth 2.0');
        expect(result.data.data.tracker).toBe('github');
        expect(result.data.data.external_id).toBe('GH-123');
        expect(result.data.data.status).toBe('open');
        expect(result.data.data.assignee).toBe('developer@example.com');
        expect(result.data.data.labels).toEqual(['security', 'authentication']);
      }
    });

    it('should validate minimal issue with only required fields', () => {
      const issue = {
        kind: 'issue' as const,
        scope: {
          project: 'test-project',
          branch: 'main',
        },
        data: {
          tracker: 'jira',
          external_id: 'PROJ-456',
          title: 'Simple issue',
          status: 'open' as const,
        },
      };

      const result = IssueSchema.safeParse(issue);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.title).toBe('Simple issue');
        expect(result.data.data.tracker).toBe('jira');
        expect(result.data.data.external_id).toBe('PROJ-456');
        expect(result.data.data.description).toBeUndefined();
        expect(result.data.data.assignee).toBeUndefined();
      }
    });

    it('should reject issue missing required fields', () => {
      const invalidIssues = [
        {
          kind: 'issue' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            // Missing tracker
            external_id: 'GH-123',
            title: 'Issue title',
            status: 'open',
          },
        },
        {
          kind: 'issue' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            tracker: 'github',
            // Missing external_id
            title: 'Issue title',
            status: 'open',
          },
        },
        {
          kind: 'issue' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            tracker: 'github',
            external_id: 'GH-123',
            // Missing title
          },
        },
      ];

      invalidIssues.forEach((issue, index) => {
        const result = IssueSchema.safeParse(issue);
        expect(result.success).toBe(false);
        if (!result.success) {
          expect(result.error.issues.length).toBeGreaterThan(0);
        }
      });
    });

    it('should enforce valid severity values', () => {
      const severities: Array<'low' | 'medium' | 'high' | 'critical'> = [
        'low',
        'medium',
        'high',
        'critical',
      ];

      severities.forEach((severity) => {
        const issue = {
          kind: 'issue' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            tracker: 'github',
            external_id: 'GH-123',
            title: 'Issue with severity',
            description: 'Description',
            severity,
            status: 'open' as const,
          },
        };

        const result = IssueSchema.safeParse(issue);
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.data.severity).toBe(severity);
        }
      });
    });

    it('should reject invalid severity values', () => {
      const issue = {
        kind: 'issue' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          tracker: 'github',
          external_id: 'GH-123',
          title: 'Issue title',
          description: 'Issue description',
          severity: 'urgent' as any, // Invalid severity
          status: 'open' as const,
        },
      };

      const result = IssueSchema.safeParse(issue);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('Invalid enum value');
      }
    });

    it('should enforce valid status values', () => {
      const statuses: Array<
        'open' | 'in_progress' | 'resolved' | 'closed' | 'wont_fix' | 'duplicate'
      > = ['open', 'in_progress', 'resolved', 'closed', 'wont_fix', 'duplicate'];

      statuses.forEach((status) => {
        const issue = {
          kind: 'issue' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            tracker: 'github',
            external_id: 'GH-123',
            title: 'Issue with status',
            description: 'Description',
            severity: 'medium' as const,
            status,
          },
        };

        const result = IssueSchema.safeParse(issue);
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.data.status).toBe(status);
        }
      });
    });

    it('should enforce valid issue_type values', () => {
      const issueTypes: Array<'bug' | 'feature_request' | 'improvement' | 'task' | 'question'> = [
        'bug',
        'feature_request',
        'improvement',
        'task',
        'question',
      ];

      issueTypes.forEach((issue_type) => {
        const issue = {
          kind: 'issue' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            tracker: 'github',
            external_id: 'GH-123',
            title: 'Issue with type',
            description: 'Description',
            severity: 'medium' as const,
            status: 'open' as const,
            issue_type,
          },
        };

        const result = IssueSchema.safeParse(issue);
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.data.issue_type).toBe(issue_type);
        }
      });
    });

    it('should enforce title length constraints', () => {
      const issue = {
        kind: 'issue' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          tracker: 'github',
          external_id: 'GH-123',
          title: 'x'.repeat(501), // Exceeds 500 character limit
          description: 'Issue description',
          severity: 'medium' as const,
          status: 'open' as const,
        },
      };

      const result = IssueSchema.safeParse(issue);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('500 characters or less');
      }
    });

    it('should enforce description length constraints', () => {
      const issue = {
        kind: 'issue' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          tracker: 'github',
          external_id: 'GH-123',
          title: 'Issue title',
          description: 'x'.repeat(5001), // Exceeds 5000 character limit
          severity: 'medium' as const,
          status: 'open' as const,
        },
      };

      const result = IssueSchema.safeParse(issue);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('5000 characters or less');
      }
    });
  });

  describe('Issue Storage Operations', () => {
    it('should store issue successfully using memory_store pattern', async () => {
      const issue = {
        kind: 'issue' as const,
        scope: {
          project: 'test-project',
          branch: 'main',
        },
        data: {
          title: 'API response timeout issue',
          description: 'The API gateway is experiencing timeouts when calling downstream services.',
          severity: 'high' as const,
          status: 'open' as const,
          issue_type: 'bug' as const,
          affected_components: ['api-gateway', 'user-service'],
        },
        content:
          'Issue: API response timeout issue - The API gateway is experiencing timeouts when calling downstream services.',
      };

      const result = await db.storeItems([issue]);

      expect(result.stored).toHaveLength(1);
      expect(result.errors).toHaveLength(0);
      expect(result.stored[0]).toHaveProperty('id');
      expect(result.stored[0].kind).toBe('issue');
      expect(result.stored[0].data.title).toBe('API response timeout issue');
      expect(result.stored[0].data.severity).toBe('high');

      // Verify Qdrant client was called
      expect(mockQdrant.upsert).toHaveBeenCalled();
    });

    it('should handle batch issue storage successfully', async () => {
      const issues = Array.from({ length: 5 }, (_, i) => ({
        kind: 'issue' as const,
        scope: {
          project: 'test-project',
          branch: 'main',
        },
        data: {
          title: `Issue ${i + 1}`,
          description: `Description for issue ${i + 1}`,
          severity: ['low', 'medium', 'high', 'critical', 'medium'][i] as any,
          status: 'open' as const,
          issue_type: 'bug' as const,
        },
        content: `Issue ${i + 1}: Description for issue ${i + 1}`,
      }));

      const result = await db.storeItems(issues);

      expect(result.stored).toHaveLength(5);
      expect(result.errors).toHaveLength(0);
      expect(mockQdrant.upsert).toHaveBeenCalledTimes(5);
    });

    it('should handle mixed valid and invalid issues in batch', async () => {
      const items = [
        {
          kind: 'issue' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            tracker: 'github',
            external_id: 'GH-123',
            title: 'Valid issue',
            description: 'Valid description',
            severity: 'medium' as const,
            status: 'open' as const,
          },
          content: 'Valid issue with complete data',
        },
        {
          kind: 'issue' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            tracker: 'github',
            external_id: 'GH-124',
            // Missing title and status - this should make it invalid
            description: 'Invalid issue missing required fields',
            severity: 'medium' as const,
          },
          content: 'Invalid issue missing required field',
        },
        {
          kind: 'issue' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            tracker: 'github',
            external_id: 'GH-125',
            title: 'Another valid issue',
            description: 'Another valid description',
            severity: 'high' as const,
            status: 'in_progress' as const,
            issue_type: 'feature_request' as const,
          },
          content: 'Another valid issue with feature request type',
        },
      ];

      const result = await db.storeItems(items);

      expect(result.stored).toHaveLength(2); // 2 valid issues
      expect(result.errors).toHaveLength(1); // 1 invalid issue
    });

    it('should handle issues with different types and severities', async () => {
      const issues = [
        {
          kind: 'issue' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Critical security bug',
            description: 'Security vulnerability in authentication',
            severity: 'critical' as const,
            status: 'open' as const,
            issue_type: 'bug' as const,
            affected_components: ['auth-service'],
          },
          content: 'Critical security bug in authentication system',
        },
        {
          kind: 'issue' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Feature request for dashboard',
            description: 'User wants new analytics dashboard',
            severity: 'low' as const,
            status: 'open' as const,
            issue_type: 'feature_request' as const,
          },
          content: 'Feature request for analytics dashboard',
        },
        {
          kind: 'issue' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Performance improvement task',
            description: 'Optimize database queries',
            severity: 'medium' as const,
            status: 'in_progress' as const,
            issue_type: 'improvement' as const,
          },
          content: 'Performance improvement task for database optimization',
        },
      ];

      const result = await db.storeItems(issues);

      expect(result.stored).toHaveLength(3);
      expect(result.stored[0].data.issue_type).toBe('bug');
      expect(result.stored[0].data.severity).toBe('critical');
      expect(result.stored[1].data.issue_type).toBe('feature_request');
      expect(result.stored[1].data.severity).toBe('low');
      expect(result.stored[2].data.issue_type).toBe('improvement');
      expect(result.stored[2].data.status).toBe('in_progress');
    });
  });

  describe('Issue Search Operations', () => {
    beforeEach(() => {
      // Setup search mock for issues
      mockQdrant.search.mockResolvedValue([
        {
          id: 'issue-id-1',
          score: 0.95,
          payload: {
            kind: 'issue',
            data: {
              title: 'Login fails with invalid credentials',
              description: 'Users cannot log in even with correct credentials',
              severity: 'high',
              status: 'open',
              issue_type: 'bug',
              affected_components: ['auth-service'],
            },
            scope: { project: 'test-project', branch: 'main' },
          },
        },
        {
          id: 'issue-id-2',
          score: 0.85,
          payload: {
            kind: 'issue',
            data: {
              title: 'Add two-factor authentication',
              description: 'Users request enhanced security with 2FA',
              severity: 'medium',
              status: 'open',
              issue_type: 'feature_request',
            },
            scope: { project: 'test-project', branch: 'main' },
          },
        },
      ]);
    });

    it('should find issues by authentication query', async () => {
      const query = 'login authentication security';

      const result = await db.searchItems(query);

      expect(result.items).toHaveLength(2);
      expect(result.items[0].data.title).toContain('Login fails');
      expect(result.items[0].data.issue_type).toBe('bug');
      expect(result.items[0].data.severity).toBe('high');
      expect(result.items[1].data.issue_type).toBe('feature_request');
      expect(mockQdrant.search).toHaveBeenCalled();
    });

    it('should handle empty issue search results', async () => {
      mockQdrant.search.mockResolvedValue([]);

      const result = await db.searchItems('nonexistent issue topic');

      expect(result.items).toHaveLength(0);
      expect(result.total).toBe(0);
    });

    it('should filter issues by reporter in search context', async () => {
      mockQdrant.search.mockResolvedValue([
        {
          id: 'issue-id-3',
          score: 0.9,
          payload: {
            kind: 'issue',
            data: {
              title: 'Reported by user@example.com',
              description: 'Issue reported by specific user',
              severity: 'medium',
              status: 'open',
              reporter: 'user@example.com',
            },
            scope: { project: 'test-project', branch: 'main' },
          },
        },
      ]);

      const result = await db.searchItems('issues from user@example.com');

      expect(result.items).toHaveLength(1);
      expect(result.items[0].data.reporter).toBe('user@example.com');
    });

    it('should find issues by assignee', async () => {
      mockQdrant.search.mockResolvedValue([
        {
          id: 'issue-id-4',
          score: 0.92,
          payload: {
            kind: 'issue',
            data: {
              title: 'Assigned to developer@example.com',
              description: 'Issue assigned to specific developer',
              severity: 'high',
              status: 'in_progress',
              assignee: 'developer@example.com',
            },
            scope: { project: 'test-project', branch: 'main' },
          },
        },
      ]);

      const result = await db.searchItems('assigned to developer@example.com');

      expect(result.items).toHaveLength(1);
      expect(result.items[0].data.assignee).toBe('developer@example.com');
      expect(result.items[0].data.status).toBe('in_progress');
    });
  });

  describe('Issue Scope Isolation', () => {
    it('should isolate issues by project scope', async () => {
      const issueProjectA = {
        kind: 'issue' as const,
        scope: {
          project: 'project-A',
          branch: 'main',
        },
        data: {
          title: 'Issue in Project A',
          description: 'Issue specific to project A',
          severity: 'medium' as const,
          status: 'open' as const,
        },
        content: 'Issue: Issue in Project A - Issue specific to project A',
      };

      const issueProjectB = {
        kind: 'issue' as const,
        scope: {
          project: 'project-B',
          branch: 'main',
        },
        data: {
          title: 'Issue in Project B',
          description: 'Issue specific to project B',
          severity: 'high' as const,
          status: 'open' as const,
        },
        content: 'Issue: Issue in Project B - Issue specific to project B',
      };

      // Store both issues
      await db.storeItems([issueProjectA, issueProjectB]);

      // Verify both were stored
      expect(mockQdrant.upsert).toHaveBeenCalledTimes(2);

      // Verify scope isolation in storage
      const storedCalls = mockQdrant.upsert.mock.calls;
      expect(storedCalls[0][0].points[0].payload.scope.project).toBe('project-A');
      expect(storedCalls[1][0].points[0].payload.scope.project).toBe('project-B');
    });

    it('should handle issues with different branch scopes', async () => {
      const issues = [
        {
          kind: 'issue' as const,
          scope: {
            project: 'test-project',
            branch: 'main',
          },
          data: {
            title: 'Main branch issue',
            description: 'Issue in main branch',
            severity: 'medium' as const,
            status: 'resolved' as const,
          },
          content: 'Issue: Main branch issue - Issue in main branch',
        },
        {
          kind: 'issue' as const,
          scope: {
            project: 'test-project',
            branch: 'develop',
          },
          data: {
            title: 'Develop branch issue',
            description: 'Issue in develop branch',
            severity: 'low' as const,
            status: 'open' as const,
          },
          content: 'Issue: Develop branch issue - Issue in develop branch',
        },
      ];

      await db.storeItems(issues);

      expect(mockQdrant.upsert).toHaveBeenCalledTimes(2);
      const storedCalls = mockQdrant.upsert.mock.calls;
      expect(storedCalls[0][0][0].payload.scope.branch).toBe('main');
      expect(storedCalls[1][0][0].payload.scope.branch).toBe('develop');
    });
  });

  describe('Issue Status Lifecycle Management', () => {
    it('should handle all valid issue statuses', async () => {
      const statuses: Array<
        'open' | 'in_progress' | 'resolved' | 'closed' | 'wont_fix' | 'duplicate'
      > = ['open', 'in_progress', 'resolved', 'closed', 'wont_fix', 'duplicate'];

      const issues = statuses.map((status, index) => ({
        kind: 'issue' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: `Issue with status ${status}`,
          description: `Description for ${status} issue`,
          severity: 'medium' as const,
          status,
        },
        content: `Issue with status ${status}: Description for ${status} issue`,
      }));

      const results = await Promise.all(issues.map((issue) => db.storeItems([issue])));

      results.forEach((result, index) => {
        expect(result.stored).toHaveLength(1);
        expect(result.stored[0].data.status).toBe(statuses[index]);
      });

      expect(mockQdrant.upsert).toHaveBeenCalledTimes(6);
    });

    it('should handle issues with resolution field', async () => {
      const issueWithResolution = {
        kind: 'issue' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Resolved issue',
          description: 'Issue that has been resolved',
          severity: 'high' as const,
          status: 'resolved' as const,
          issue_type: 'bug' as const,
          resolution: 'Fixed authentication token validation logic in auth service v2.1.0',
        },
        content: 'Resolved issue: Fixed authentication token validation logic',
      };

      const result = await db.storeItems([issueWithResolution]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].data.resolution).toContain('authentication token validation');
      expect(result.stored[0].data.status).toBe('resolved');
    });

    it('should handle timestamp fields correctly', async () => {
      const issueWithTimestamps = {
        kind: 'issue' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Issue with timestamps',
          description: 'Issue with created and updated timestamps',
          severity: 'low' as const,
          status: 'open' as const,
          created_at: '2025-01-01T10:00:00Z',
          updated_at: '2025-01-02T15:30:00Z',
          reporter: 'user@example.com',
          assignee: 'dev@example.com',
        },
        content: 'Issue with timestamps and assignment',
      };

      const result = await db.storeItems([issueWithTimestamps]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].data.created_at).toBe('2025-01-01T10:00:00Z');
      expect(result.stored[0].data.updated_at).toBe('2025-01-02T15:30:00Z');
      expect(result.stored[0].data.reporter).toBe('user@example.com');
    });
  });

  describe('Issue Edge Cases and Error Handling', () => {
    it('should handle issues with complex affected components', async () => {
      const complexIssue = {
        kind: 'issue' as const,
        scope: {
          project: 'test-project',
          branch: 'main',
        },
        data: {
          title: 'System-wide performance degradation',
          description: 'Multiple components experiencing performance issues',
          severity: 'critical' as const,
          status: 'in_progress' as const,
          issue_type: 'bug' as const,
          affected_components: [
            'api-gateway',
            'user-service',
            'payment-service',
            'notification-service',
            'database-primary',
            'database-replica',
            'cache-layer',
            'load-balancer',
          ],
        },
        content: 'System-wide performance degradation affecting multiple components',
      };

      const result = await db.storeItems([complexIssue]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].data.affected_components).toHaveLength(8);
      expect(result.stored[0].data.affected_components).toContain('api-gateway');
      expect(result.stored[0].data.affected_components).toContain('database-primary');
    });

    it('should handle issues with special characters in title and description', async () => {
      const specialCharIssue = {
        kind: 'issue' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'API endpoint /api/v1/users/{id} returns 500 with special chars: ñáéíóú',
          description:
            'When user names contain special characters (中文, русский, العربية, emoji 🚀), the API fails with internal server error. Error message includes "Invalid UTF-8 sequence in byte 0x80".',
          severity: 'medium' as const,
          status: 'open' as const,
          issue_type: 'bug' as const,
          affected_components: ['api-gateway', 'user-service'],
        },
        content: 'API endpoint fails with special characters in user data',
      };

      const result = await db.storeItems([specialCharIssue]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].data.title).toContain('/api/v1/users/{id}');
      expect(result.stored[0].data.description).toContain('中文');
      expect(result.stored[0].data.description).toContain('🚀');
    });

    it('should handle issue storage errors gracefully', async () => {
      const issue = {
        kind: 'issue' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Test issue',
          description: 'Test description',
          severity: 'medium' as const,
          status: 'open' as const,
        },
      };

      // Mock upsert to throw an error
      mockQdrant.upsert.mockRejectedValue(new Error('Database connection timeout'));

      const result = await db.storeItems([issue]);

      expect(result.stored).toHaveLength(0);
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0].error).toContain('Database connection timeout');
    });

    it('should handle issues with empty affected components array', () => {
      const issueWithEmptyComponents = {
        kind: 'issue' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          tracker: 'github',
          external_id: 'GH-123',
          title: 'Issue with no affected components',
          description: 'General issue not tied to specific components',
          severity: 'low' as const,
          status: 'open' as const,
          affected_components: [], // Empty array is valid
        },
      };

      const result = IssueSchema.safeParse(issueWithEmptyComponents);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.affected_components).toEqual([]);
      }
    });

    it('should handle issues with question type', async () => {
      const questionIssue = {
        kind: 'issue' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'How to implement caching strategy?',
          description:
            'Looking for guidance on best practices for implementing Redis caching in our microservices architecture.',
          severity: 'low' as const,
          status: 'open' as const,
          issue_type: 'question' as const,
          reporter: 'developer@example.com',
        },
        content: 'Question about caching strategy implementation',
      };

      const result = await db.storeItems([questionIssue]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].data.issue_type).toBe('question');
      expect(result.stored[0].data.title).toContain('caching strategy');
    });
  });

  describe('Issue Integration with Knowledge System', () => {
    it('should integrate with knowledge item validation', () => {
      const issue = {
        kind: 'issue' as const,
        scope: {
          project: 'test-project',
          branch: 'main',
        },
        data: {
          tracker: 'github',
          external_id: 'GH-456',
          title: 'Memory leak in background processing',
          description:
            'Background processing service shows memory usage growth over time, requiring daily restarts.',
          severity: 'high' as const,
          status: 'in_progress' as const,
          issue_type: 'bug' as const,
          affected_components: ['background-processor', 'memory-manager'],
          reporter: 'ops@example.com',
          assignee: 'backend-team@example.com',
        },
        tags: { performance: true, memory: true, critical: true },
        source: {
          actor: 'monitoring-system',
          tool: 'alert-manager',
          timestamp: '2025-01-01T00:00:00Z',
        },
        ttl_policy: 'long' as const,
      };

      const result = validateKnowledgeItem(issue);
      expect(result.kind).toBe('issue');
      expect(result.data.title).toContain('Memory leak');
      expect(result.data.severity).toBe('high');
      expect(result.tags.performance).toBe(true);
      expect(result.source.actor).toBe('monitoring-system');
      expect(result.ttl_policy).toBe('long');
    });

    it('should handle TTL policy for issues', async () => {
      const issue = {
        kind: 'issue' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Temporary deployment issue',
          description: 'Issue that should be resolved quickly',
          severity: 'low' as const,
          status: 'open' as const,
        },
        ttl_policy: 'short' as const,
      };

      const result = await db.storeItems([issue]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].ttl_policy).toBe('short');
    });

    it('should handle comprehensive issue metadata', async () => {
      const comprehensiveIssue = {
        kind: 'issue' as const,
        scope: {
          project: 'test-project',
          branch: 'feature-branch',
        },
        data: {
          title: 'Complete issue with all metadata',
          description: 'Issue with comprehensive metadata for testing',
          severity: 'critical' as const,
          status: 'in_progress' as const,
          issue_type: 'bug' as const,
          affected_components: ['component1', 'component2'],
          reporter: 'qa@example.com',
          assignee: 'senior-dev@example.com',
          created_at: '2025-01-01T00:00:00Z',
          updated_at: '2025-01-01T12:00:00Z',
          resolution: 'Working on fix in pull request #1234',
        },
        tags: {
          priority: 'urgent',
          category: 'bug',
          component: 'component1',
          team: 'backend',
        },
        source: {
          actor: 'qa-automation',
          tool: 'test-runner',
          timestamp: '2025-01-01T00:00:00Z',
        },
        metadata: {
          test_id: 'TEST-12345',
          test_suite: 'integration-tests',
          environment: 'staging',
          browser: 'chrome-120',
        },
      };

      const result = await db.storeItems([comprehensiveIssue]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].data.assignee).toBe('senior-dev@example.com');
      expect(result.stored[0].data.resolution).toContain('pull request #1234');
      expect(result.stored[0].tags.priority).toBe('urgent');
      expect(result.stored[0].metadata.test_id).toBe('TEST-12345');
    });
  });
});
