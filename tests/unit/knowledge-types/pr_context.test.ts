/**
 * Comprehensive Unit Tests for PR Context (pr_context) Knowledge Type
 *
 * Tests PR context knowledge type functionality including:
 * - Schema validation with required fields (pr_number, title, author, status, base_branch, head_branch)
 * - Optional fields validation (description, merged_at, expires_at)
 * - PR number validation (positive integer)
 * - Status validation (open, merged, closed, draft)
 * - Branch name and author validation with length constraints
 * - Storage operations and batch processing
 * - Search operations and query handling
 * - Scope isolation by project and branch
 * - Edge cases and error handling
 * - Integration with knowledge system and TTL policies
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { VectorDatabase } from '../../../src/index';
import {
  PRContextSchema,
  validateKnowledgeItem
} from '../../../src/schemas/knowledge-types';

// Mock Qdrant client - reusing pattern from memory-store.test.ts
vi.mock('@qdrant/js-client-rest', () => ({
  QdrantClient: class {
    constructor() {
      this.getCollections = vi.fn().mockResolvedValue({
        collections: [{ name: 'test-collection' }]
      });
      this.createCollection = vi.fn().mockResolvedValue(undefined);
      this.upsert = vi.fn().mockResolvedValue(undefined);
      this.search = vi.fn().mockResolvedValue([]);
      this.getCollection = vi.fn().mockResolvedValue({
        points_count: 0,
        status: 'green'
      });
      this.delete = vi.fn().mockResolvedValue({ status: 'completed' });
      this.count = vi.fn().mockResolvedValue({ count: 0 });
      this.healthCheck = vi.fn().mockResolvedValue(true);
    }
  }
}));

describe('PR Context (pr_context) Knowledge Type - Comprehensive Testing', () => {
  let db: VectorDatabase;
  let mockQdrant: any;

  beforeEach(() => {
    db = new VectorDatabase();
    mockQdrant = (db as any).client;
  });

  describe('PR Context Schema Validation', () => {
    it('should validate complete PR context with all fields', () => {
      const prContext = {
        kind: 'pr_context' as const,
        scope: {
          project: 'test-project',
          branch: 'main'
        },
        data: {
          pr_number: 12345,
          title: 'Add OAuth 2.0 authentication to API gateway',
          description: 'This PR implements OAuth 2.0 authentication using JWT tokens with refresh token support. It includes user authentication, token validation, and proper error handling.',
          author: 'john.doe',
          status: 'open' as const,
          base_branch: 'main',
          head_branch: 'feature/oauth-authentication',
          merged_at: undefined,
          expires_at: '2025-02-15T00:00:00Z'
        },
        tags: { security: true, authentication: true, 'api-gateway': true },
        source: {
          actor: 'github-actions',
          tool: 'pr-analyzer',
          timestamp: '2025-01-15T10:30:00Z'
        },
        ttl_policy: '30d' as const
      };

      const result = PRContextSchema.safeParse(prContext);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.kind).toBe('pr_context');
        expect(result.data.data.pr_number).toBe(12345);
        expect(result.data.data.title).toBe('Add OAuth 2.0 authentication to API gateway');
        expect(result.data.data.author).toBe('john.doe');
        expect(result.data.data.status).toBe('open');
        expect(result.data.data.base_branch).toBe('main');
        expect(result.data.data.head_branch).toBe('feature/oauth-authentication');
        expect(result.data.data.description).toContain('OAuth 2.0');
        expect(result.data.data.expires_at).toBe('2025-02-15T00:00:00Z');
      }
    });

    it('should validate minimal PR context with only required fields', () => {
      const prContext = {
        kind: 'pr_context' as const,
        scope: {
          project: 'test-project',
          branch: 'main'
        },
        data: {
          pr_number: 1,
          title: 'Initial commit',
          author: 'alice',
          status: 'draft' as const,
          base_branch: 'main',
          head_branch: 'feature/initial-setup'
        }
      };

      const result = PRContextSchema.safeParse(prContext);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.pr_number).toBe(1);
        expect(result.data.data.title).toBe('Initial commit');
        expect(result.data.data.author).toBe('alice');
        expect(result.data.data.status).toBe('draft');
        expect(result.data.data.description).toBeUndefined();
        expect(result.data.data.merged_at).toBeUndefined();
        expect(result.data.data.expires_at).toBeUndefined();
      }
    });

    it('should reject PR context missing required fields', () => {
      const invalidPRContexts = [
        {
          kind: 'pr_context' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            // Missing pr_number
            title: 'Test PR',
            author: 'test-user',
            status: 'open',
            base_branch: 'main',
            head_branch: 'feature/test'
          }
        },
        {
          kind: 'pr_context' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            pr_number: 123,
            // Missing title
            author: 'test-user',
            status: 'open',
            base_branch: 'main',
            head_branch: 'feature/test'
          }
        },
        {
          kind: 'pr_context' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            pr_number: 123,
            title: 'Test PR',
            // Missing author
            status: 'open',
            base_branch: 'main',
            head_branch: 'feature/test'
          }
        },
        {
          kind: 'pr_context' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            pr_number: 123,
            title: 'Test PR',
            author: 'test-user',
            // Missing status
            base_branch: 'main',
            head_branch: 'feature/test'
          }
        },
        {
          kind: 'pr_context' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            pr_number: 123,
            title: 'Test PR',
            author: 'test-user',
            status: 'open',
            // Missing base_branch
            head_branch: 'feature/test'
          }
        },
        {
          kind: 'pr_context' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            pr_number: 123,
            title: 'Test PR',
            author: 'test-user',
            status: 'open',
            base_branch: 'main'
            // Missing head_branch
          }
        }
      ];

      invalidPRContexts.forEach((prContext, index) => {
        const result = PRContextSchema.safeParse(prContext);
        expect(result.success).toBe(false);
        if (!result.success) {
          expect(result.error.issues.length).toBeGreaterThan(0);
        }
      });
    });

    it('should enforce valid PR number (positive integer)', () => {
      const invalidPRContexts = [
        {
          kind: 'pr_context' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            pr_number: -1, // Negative number
            title: 'Test PR',
            author: 'test-user',
            status: 'open',
            base_branch: 'main',
            head_branch: 'feature/test'
          }
        },
        {
          kind: 'pr_context' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            pr_number: 0, // Zero is not positive
            title: 'Test PR',
            author: 'test-user',
            status: 'open',
            base_branch: 'main',
            head_branch: 'feature/test'
          }
        },
        {
          kind: 'pr_context' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            pr_number: 123.5, // Not an integer
            title: 'Test PR',
            author: 'test-user',
            status: 'open',
            base_branch: 'main',
            head_branch: 'feature/test'
          }
        },
        {
          kind: 'pr_context' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            pr_number: '123', // String instead of number
            title: 'Test PR',
            author: 'test-user',
            status: 'open',
            base_branch: 'main',
            head_branch: 'feature/test'
          }
        }
      ];

      invalidPRContexts.forEach((prContext) => {
        const result = PRContextSchema.safeParse(prContext);
        expect(result.success).toBe(false);
      });
    });

    it('should enforce valid status values', () => {
      const validStatuses = ['open', 'merged', 'closed', 'draft'] as const;

      validStatuses.forEach((status) => {
        const prContext = {
          kind: 'pr_context' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            pr_number: 123,
            title: 'Test PR',
            author: 'test-user',
            status,
            base_branch: 'main',
            head_branch: 'feature/test'
          }
        };

        const result = PRContextSchema.safeParse(prContext);
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.data.status).toBe(status);
        }
      });

      // Test invalid status
      const invalidPRContext = {
        kind: 'pr_context' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          pr_number: 123,
          title: 'Test PR',
          author: 'test-user',
          status: 'invalid-status' as any,
          base_branch: 'main',
          head_branch: 'feature/test'
        }
      };

      const result = PRContextSchema.safeParse(invalidPRContext);
      expect(result.success).toBe(false);
    });

    it('should enforce title length constraints', () => {
      const prContext = {
        kind: 'pr_context' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          pr_number: 123,
          title: 'x'.repeat(501), // Exceeds 500 character limit
          author: 'test-user',
          status: 'open',
          base_branch: 'main',
          head_branch: 'feature/test'
        }
      };

      const result = PRContextSchema.safeParse(prContext);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('500 characters or less');
      }
    });

    it('should enforce author length constraints', () => {
      const prContext = {
        kind: 'pr_context' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          pr_number: 123,
          title: 'Test PR',
          author: 'x'.repeat(201), // Exceeds 200 character limit
          status: 'open',
          base_branch: 'main',
          head_branch: 'feature/test'
        }
      };

      const result = PRContextSchema.safeParse(prContext);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('200 characters or less');
      }
    });

    it('should enforce branch name length constraints', () => {
      const invalidBranchNames = [
        { field: 'base_branch', value: 'x'.repeat(201) },
        { field: 'head_branch', value: 'x'.repeat(201) }
      ];

      invalidBranchNames.forEach(({ field, value }) => {
        const prContext = {
          kind: 'pr_context' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            pr_number: 123,
            title: 'Test PR',
            author: 'test-user',
            status: 'open',
            base_branch: field === 'base_branch' ? value : 'main',
            head_branch: field === 'head_branch' ? value : 'feature/test'
          }
        };

        const result = PRContextSchema.safeParse(prContext);
        expect(result.success).toBe(false);
        if (!result.success) {
          expect(result.error.issues[0].message).toContain('200 characters or less');
        }
      });
    });

    it('should validate datetime format for merged_at and expires_at', () => {
      const prContext = {
        kind: 'pr_context' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          pr_number: 123,
          title: 'Test PR',
          author: 'test-user',
          status: 'merged',
          base_branch: 'main',
          head_branch: 'feature/test',
          merged_at: '2025-01-15T14:30:00Z',
          expires_at: '2025-02-14T14:30:00Z'
        }
      };

      const result = PRContextSchema.safeParse(prContext);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.merged_at).toBe('2025-01-15T14:30:00Z');
        expect(result.data.data.expires_at).toBe('2025-02-14T14:30:00Z');
      }
    });

    it('should reject invalid datetime formats', () => {
      const invalidPRContext = {
        kind: 'pr_context' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          pr_number: 123,
          title: 'Test PR',
          author: 'test-user',
          status: 'merged',
          base_branch: 'main',
          head_branch: 'feature/test',
          merged_at: 'invalid-date-format'
        }
      };

      const result = PRContextSchema.safeParse(invalidPRContext);
      expect(result.success).toBe(false);
    });
  });

  describe('PR Context Storage Operations', () => {
    it('should store open PR context successfully', async () => {
      const prContext = {
        kind: 'pr_context' as const,
        scope: {
          project: 'test-project',
          branch: 'main'
        },
        data: {
          pr_number: 42,
          title: 'Fix authentication bug in login service',
          author: 'bugfix-expert',
          status: 'open' as const,
          base_branch: 'main',
          head_branch: 'fix/auth-bug-42'
        }
      };

      const result = await db.storeItems([prContext]);

      expect(result.stored).toHaveLength(1);
      expect(result.errors).toHaveLength(0);
      expect(result.stored[0]).toHaveProperty('id');
      expect(result.stored[0].kind).toBe('pr_context');
      expect(result.stored[0].data.pr_number).toBe(42);
      expect(result.stored[0].data.status).toBe('open');
      expect(result.stored[0].data.author).toBe('bugfix-expert');

      // Verify Qdrant client was called
      expect(mockQdrant.upsert).toHaveBeenCalled();
    });

    it('should handle batch PR context storage with different statuses', async () => {
      const prContexts = [
        {
          kind: 'pr_context' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            pr_number: 100,
            title: 'Add user registration API',
            author: 'backend-dev',
            status: 'open' as const,
            base_branch: 'main',
            head_branch: 'feature/user-registration'
          }
        },
        {
          kind: 'pr_context' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            pr_number: 101,
            title: 'Implement password reset functionality',
            author: 'security-expert',
            status: 'merged' as const,
            base_branch: 'main',
            head_branch: 'feature/password-reset',
            merged_at: '2025-01-10T16:45:00Z'
          }
        },
        {
          kind: 'pr_context' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            pr_number: 102,
            title: 'Update React to version 19',
            author: 'frontend-lead',
            status: 'closed' as const,
            base_branch: 'main',
            head_branch: 'chore/react-upgrade'
          }
        },
        {
          kind: 'pr_context' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            pr_number: 103,
            title: 'WIP: Refactor authentication system',
            author: 'architect',
            status: 'draft' as const,
            base_branch: 'main',
            head_branch: 'wip/auth-refactor'
          }
        }
      ];

      const result = await db.storeItems(prContexts);

      expect(result.stored).toHaveLength(4);
      expect(result.errors).toHaveLength(0);
      expect(mockQdrant.upsert).toHaveBeenCalledTimes(4);

      const storedCalls = mockQdrant.upsert.mock.calls;
      expect(storedCalls[0][0][0].payload.data.status).toBe('open');
      expect(storedCalls[1][0][0].payload.data.status).toBe('merged');
      expect(storedCalls[2][0][0].payload.data.status).toBe('closed');
      expect(storedCalls[3][0][0].payload.data.status).toBe('draft');
    });

    it('should handle invalid PR contexts in batch', async () => {
      const items = [
        {
          kind: 'pr_context' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            pr_number: 1,
            title: 'Valid PR',
            author: 'valid-user',
            status: 'open' as const,
            base_branch: 'main',
            head_branch: 'feature/valid'
          }
        },
        {
          kind: 'pr_context' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            // Missing pr_number
            title: 'Invalid PR',
            author: 'invalid-user',
            status: 'open' as const,
            base_branch: 'main',
            head_branch: 'feature/invalid'
          }
        },
        {
          kind: 'pr_context' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            pr_number: 2,
            title: 'Another Valid PR',
            author: 'another-valid-user',
            status: 'merged' as const,
            base_branch: 'main',
            head_branch: 'feature/another-valid'
          }
        }
      ];

      const result = await db.storeItems(items);

      expect(result.stored).toHaveLength(2); // 2 valid PR contexts
      expect(result.errors).toHaveLength(1); // 1 invalid PR context
    });
  });

  describe('PR Context Search Operations', () => {
    beforeEach(() => {
      // Setup search mock for PR contexts
      mockQdrant.search.mockResolvedValue([
        {
          id: 'pr-id-1',
          score: 0.95,
          payload: {
            kind: 'pr_context',
            data: {
              pr_number: 12345,
              title: 'Add OAuth 2.0 authentication to API gateway',
              author: 'security-expert',
              status: 'open',
              base_branch: 'main',
              head_branch: 'feature/oauth-authentication',
              description: 'Implements OAuth 2.0 with JWT tokens'
            },
            scope: { project: 'test-project', branch: 'main' }
          }
        },
        {
          id: 'pr-id-2',
          score: 0.85,
          payload: {
            kind: 'pr_context',
            data: {
              pr_number: 12346,
              title: 'Fix authentication middleware bug',
              author: 'bugfix-expert',
              status: 'merged',
              base_branch: 'main',
              head_branch: 'fix/auth-middleware-bug',
              merged_at: '2025-01-10T12:00:00Z'
            },
            scope: { project: 'test-project', branch: 'main' }
          }
        }
      ]);
    });

    it('should find PR contexts by authentication query', async () => {
      const query = 'OAuth authentication security API';

      const result = await db.searchItems(query);

      expect(result.items).toHaveLength(2);
      expect(result.items[0].data.pr_number).toBe(12345);
      expect(result.items[0].data.title).toContain('OAuth 2.0');
      expect(result.items[0].data.author).toBe('security-expert');
      expect(result.items[0].data.status).toBe('open');
      expect(mockQdrant.search).toHaveBeenCalled();
    });

    it('should find PR contexts by author', async () => {
      const query = 'bugfix-expert middleware authentication';

      const result = await db.searchItems(query);

      expect(result.items).toHaveLength(2);
      expect(result.items[1].data.author).toBe('bugfix-expert');
      expect(result.items[1].data.title).toContain('authentication middleware');
      expect(result.items[1].data.status).toBe('merged');
    });

    it('should handle empty PR context search results', async () => {
      mockQdrant.search.mockResolvedValue([]);

      const result = await db.searchItems('nonexistent PR topic');

      expect(result.items).toHaveLength(0);
      expect(result.total).toBe(0);
    });
  });

  describe('PR Context Scope Isolation', () => {
    it('should isolate PR contexts by project scope', async () => {
      const prContexts = [
        {
          kind: 'pr_context' as const,
          scope: { project: 'frontend-app', branch: 'main' },
          data: {
            pr_number: 1,
            title: 'Add React component library',
            author: 'frontend-dev',
            status: 'open',
            base_branch: 'main',
            head_branch: 'feature/component-library'
          }
        },
        {
          kind: 'pr_context' as const,
          scope: { project: 'backend-api', branch: 'main' },
          data: {
            pr_number: 1,
            title: 'Add REST API endpoints',
            author: 'backend-dev',
            status: 'open',
            base_branch: 'main',
            head_branch: 'feature/api-endpoints'
          }
        }
      ];

      const results = await Promise.all(
        prContexts.map(prContext => db.storeItems([prContext]))
      );

      results.forEach((result) => {
        expect(result.stored).toHaveLength(1);
      });

      expect(mockQdrant.upsert).toHaveBeenCalledTimes(2);

      // Verify scope isolation in stored data
      const storedCalls = mockQdrant.upsert.mock.calls;
      expect(storedCalls[0][0][0].payload.scope.project).toBe('frontend-app');
      expect(storedCalls[1][0][0].payload.scope.project).toBe('backend-api');
    });

    it('should handle different branch scopes within same project', async () => {
      const prContexts = [
        {
          kind: 'pr_context' as const,
          scope: { project: 'monorepo', branch: 'main' },
          data: {
            pr_number: 100,
            title: 'Main branch feature',
            author: 'dev-1',
            status: 'merged',
            base_branch: 'main',
            head_branch: 'feature/main-branch'
          }
        },
        {
          kind: 'pr_context' as const,
          scope: { project: 'monorepo', branch: 'develop' },
          data: {
            pr_number: 101,
            title: 'Develop branch feature',
            author: 'dev-2',
            status: 'open',
            base_branch: 'develop',
            head_branch: 'feature/develop-branch'
          }
        }
      ];

      await Promise.all(
        prContexts.map(prContext => db.storeItems([prContext]))
      );

      const storedCalls = mockQdrant.upsert.mock.calls;
      expect(storedCalls[0][0][0].payload.scope.branch).toBe('main');
      expect(storedCalls[1][0][0].payload.scope.branch).toBe('develop');
    });
  });

  describe('PR Context Edge Cases and Error Handling', () => {
    it('should handle PR context storage errors gracefully', async () => {
      const prContext = {
        kind: 'pr_context' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          pr_number: 999,
          title: 'Test PR',
          author: 'test-user',
          status: 'open',
          base_branch: 'main',
          head_branch: 'feature/test'
        }
      };

      // Mock upsert to throw an error
      mockQdrant.upsert.mockRejectedValue(new Error('Database connection failed'));

      const result = await db.storeItems([prContext]);

      expect(result.stored).toHaveLength(0);
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0].error).toContain('Database connection failed');
    });

    it('should handle PR contexts with special characters in title and description', async () => {
      const prContext = {
        kind: 'pr_context' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          pr_number: 777,
          title: 'Fix: 🐛 Bug in API endpoint /api/v2/users/{id} returns 500 error',
          description: 'The API endpoint was failing when user ID contained special characters like @, #, $. This fix adds proper URL encoding and validation.',
          author: 'bug-hunter',
          status: 'open',
          base_branch: 'main',
          head_branch: 'fix/api-url-encoding'
        }
      };

      const result = await db.storeItems([prContext]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].data.title).toContain('🐛');
      expect(result.stored[0].data.description).toContain('URL encoding');
    });

    it('should handle PR context with long description within limits', async () => {
      const longDescription = 'This is a comprehensive PR that addresses multiple issues and improvements. '.repeat(20);

      const prContext = {
        kind: 'pr_context' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          pr_number: 888,
          title: 'Major refactoring and performance improvements',
          description: longDescription,
          author: 'senior-dev',
          status: 'open',
          base_branch: 'main',
          head_branch: 'refactor/major-performance'
        }
      };

      const result = await db.storeItems([prContext]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].data.description).toBe(longDescription);
    });

    it('should handle PR context with empty description', () => {
      const prContext = {
        kind: 'pr_context' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          pr_number: 555,
          title: 'Simple PR',
          author: 'minimal-user',
          status: 'open',
          base_branch: 'main',
          head_branch: 'feature/minimal',
          description: '' // Empty string is valid
        }
      };

      const result = PRContextSchema.safeParse(prContext);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.description).toBe('');
      }
    });

    it('should handle merged PR with timestamp', () => {
      const prContext = {
        kind: 'pr_context' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          pr_number: 444,
          title: 'Critical security fix',
          author: 'security-team',
          status: 'merged' as const,
          base_branch: 'main',
          head_branch: 'hotfix/security-patch',
          merged_at: '2025-01-20T09:15:30Z',
          expires_at: '2025-02-19T09:15:30Z' // 30 days after merge
        }
      };

      const result = PRContextSchema.safeParse(prContext);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.status).toBe('merged');
        expect(result.data.data.merged_at).toBe('2025-01-20T09:15:30Z');
        expect(result.data.data.expires_at).toBe('2025-02-19T09:15:30Z');
      }
    });

    it('should handle PR number zero as invalid', () => {
      const prContext = {
        kind: 'pr_context' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          pr_number: 0, // Zero is invalid (must be positive)
          title: 'Test PR',
          author: 'test-user',
          status: 'open',
          base_branch: 'main',
          head_branch: 'feature/test'
        }
      };

      const result = PRContextSchema.safeParse(prContext);
      expect(result.success).toBe(false);
    });

    it('should handle very large PR numbers', async () => {
      const prContext = {
        kind: 'pr_context' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          pr_number: 2147483647, // Max 32-bit integer
          title: 'High PR number test',
          author: 'test-user',
          status: 'open',
          base_branch: 'main',
          head_branch: 'feature/high-number'
        }
      };

      const result = await db.storeItems([prContext]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].data.pr_number).toBe(2147483647);
    });
  });

  describe('PR Context Integration with Knowledge System', () => {
    it('should integrate with knowledge item validation', () => {
      const prContext = {
        kind: 'pr_context' as const,
        scope: {
          project: 'test-project',
          branch: 'main'
        },
        data: {
          pr_number: 369,
          title: 'Implement CI/CD pipeline improvements',
          description: 'Add automated testing, security scanning, and deployment automation to the CI/CD pipeline.',
          author: 'devops-engineer',
          status: 'merged',
          base_branch: 'main',
          head_branch: 'feature/ci-cd-improvements',
          merged_at: '2025-01-18T14:20:00Z'
        },
        tags: { 'ci-cd': true, automation: true, 'devops': true },
        source: {
          actor: 'github-actions',
          tool: 'pr-analyzer',
          timestamp: '2025-01-18T14:25:00Z'
        },
        ttl_policy: '30d' as const
      };

      const result = validateKnowledgeItem(prContext);
      expect(result.kind).toBe('pr_context');
      expect(result.data.pr_number).toBe(369);
      expect(result.data.title).toBe('Implement CI/CD pipeline improvements');
      expect(result.tags['ci-cd']).toBe(true);
      expect(result.source.actor).toBe('github-actions');
      expect(result.ttl_policy).toBe('30d');
    });

    it('should handle PR context with comprehensive metadata', () => {
      const prContext = {
        kind: 'pr_context' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          pr_number: 258,
          title: 'Feature: Add real-time notifications with WebSocket',
          description: 'Implement real-time notification system using WebSocket connections. Includes push notifications, desktop alerts, and mobile push support.',
          author: 'fullstack-developer',
          status: 'open',
          base_branch: 'develop',
          head_branch: 'feature/realtime-notifications'
        },
        tags: {
          'websocket': true,
          'notifications': true,
          'real-time': true,
          'frontend': true,
          'backend': true
        },
        metadata: {
          files_changed: 15,
          lines_added: 542,
          lines_removed: 28,
          reviewers: ['tech-lead', 'senior-dev', 'frontend-expert'],
          approval_status: 'pending',
          ci_status: 'passed'
        }
      };

      const result = PRContextSchema.safeParse(prContext);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.pr_number).toBe(258);
        expect(result.data.tags['websocket']).toBe(true);
        expect(result.data.tags['real-time']).toBe(true);
      }
    });

    it('should support TTL policy for PR contexts', async () => {
      const prContext = {
        kind: 'pr_context' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          pr_number: 147,
          title: 'Hotfix: Fix production database connection issue',
          author: 'on-call-engineer',
          status: 'merged',
          base_branch: 'main',
          head_branch: 'hotfix/db-connection',
          merged_at: '2025-01-22T03:45:00Z',
          expires_at: '2025-02-21T03:45:00Z' // 30 days post-merge
        },
        ttl_policy: '30d' as const
      };

      const result = await db.storeItems([prContext]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].ttl_policy).toBe('30d');
      expect(result.stored[0].data.expires_at).toBe('2025-02-21T03:45:00Z');
    });

    it('should handle PR context with idempotency key', async () => {
      const prContext = {
        kind: 'pr_context' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          pr_number: 963,
          title: 'Add unit tests for authentication service',
          author: 'qa-engineer',
          status: 'open',
          base_branch: 'main',
          head_branch: 'test/auth-unit-tests'
        },
        idempotency_key: 'pr-963-auth-tests-v1'
      };

      const result = await db.storeItems([prContext]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].idempotency_key).toBe('pr-963-auth-tests-v1');
    });
  });
});