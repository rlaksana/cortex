/**
 * Comprehensive Unit Tests for Decision (ADR) Knowledge Type
 *
 * Tests decision knowledge type functionality including:
 * - ADR validation with all required fields
 * - Constitutional immutability requirements (Principle IV)
 * - Status transitions and lifecycle
 * - Component and rationale validation
 * - Decision metadata handling
 * - Error handling and edge cases
 * - Integration with decision workflows
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { VectorDatabase } from '../../../src/index';
import {
  DecisionSchema,
  validateKnowledgeItem,
  violatesADRImmutability
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

describe('Decision (ADR) Knowledge Type - Comprehensive Testing', () => {
  let db: VectorDatabase;
  let mockQdrant: any;

  beforeEach(() => {
    db = new VectorDatabase();
    mockQdrant = (db as any).client;
  });

  describe('Decision Schema Validation', () => {
    it('should validate complete decision with all fields', () => {
      const decision = {
        kind: 'decision' as const,
        scope: {
          project: 'test-project',
          branch: 'main'
        },
        data: {
          id: '550e8400-e29b-41d4-a716-446655440000',
          component: 'authentication-system',
          status: 'accepted' as const,
          title: 'Use OAuth 2.0 for authentication',
          rationale: 'OAuth 2.0 provides industry-standard security with token-based authentication and delegated access.',
          alternatives_considered: [
            'Basic Auth with API keys',
            'JWT-only implementation',
            'Custom session management'
          ],
          consequences: 'Requires additional infrastructure for token management but improves security posture.',
          supersedes: '550e8400-e29b-41d4-a716-446655440001'
        },
        tags: { security: true, architecture: true },
        source: {
          actor: 'tech-lead',
          tool: 'adr-system',
          timestamp: '2025-01-01T00:00:00Z'
        }
      };

      const result = DecisionSchema.safeParse(decision);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.kind).toBe('decision');
        expect(result.data.data.component).toBe('authentication-system');
        expect(result.data.data.status).toBe('accepted');
        expect(result.data.data.title).toBe('Use OAuth 2.0 for authentication');
        expect(result.data.data.alternatives_considered).toHaveLength(3);
      }
    });

    it('should validate minimal decision with only required fields', () => {
      const decision = {
        kind: 'decision' as const,
        scope: {
          project: 'test-project',
          branch: 'main'
        },
        data: {
          component: 'database-layer',
          status: 'proposed' as const,
          title: 'Choose primary database',
          rationale: 'We need a database that supports our performance requirements.'
        }
      };

      const result = DecisionSchema.safeParse(decision);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.component).toBe('database-layer');
        expect(result.data.data.status).toBe('proposed');
        expect(result.data.data.alternatives_considered).toBeUndefined();
        expect(result.data.data.consequences).toBeUndefined();
      }
    });

    it('should reject decision missing required fields', () => {
      const invalidDecisions = [
        {
          kind: 'decision' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            // Missing component
            status: 'accepted',
            title: 'Test decision',
            rationale: 'Test rationale'
          }
        },
        {
          kind: 'decision' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            component: 'test-component',
            // Missing status
            title: 'Test decision',
            rationale: 'Test rationale'
          }
        },
        {
          kind: 'decision' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            component: 'test-component',
            status: 'accepted',
            // Missing title
            rationale: 'Test rationale'
          }
        },
        {
          kind: 'decision' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            component: 'test-component',
            status: 'accepted',
            title: 'Test decision'
            // Missing rationale
          }
        }
      ];

      invalidDecisions.forEach((decision, index) => {
        const result = DecisionSchema.safeParse(decision);
        expect(result.success).toBe(false);
        if (!result.success) {
          expect(result.error.issues.length).toBeGreaterThan(0);
        }
      });
    });

    it('should enforce valid status values', () => {
      const decision = {
        kind: 'decision' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          component: 'test-component',
          status: 'invalid_status' as any, // Invalid status
          title: 'Test decision',
          rationale: 'Test rationale'
        }
      };

      const result = DecisionSchema.safeParse(decision);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('Invalid enum value');
      }
    });

    it('should enforce component length constraints', () => {
      const decision = {
        kind: 'decision' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          component: 'x'.repeat(201), // Exceeds 200 character limit
          status: 'proposed',
          title: 'Test decision',
          rationale: 'Test rationale'
        }
      };

      const result = DecisionSchema.safeParse(decision);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('200 characters or less');
      }
    });

    it('should enforce title length constraints', () => {
      const decision = {
        kind: 'decision' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          component: 'test-component',
          status: 'proposed',
          title: 'x'.repeat(501), // Exceeds 500 character limit
          rationale: 'Test rationale'
        }
      };

      const result = DecisionSchema.safeParse(decision);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('500 characters or less');
      }
    });
  });

  describe('ADR Immutability Constitutional Requirements', () => {
    it('should allow content changes for non-accepted decisions', () => {
      const existing = {
        kind: 'decision' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          component: 'test-component',
          status: 'proposed',
          title: 'Original title',
          rationale: 'Original rationale'
        }
      };

      const incoming = {
        kind: 'decision' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          component: 'test-component',
          status: 'proposed',
          title: 'Updated title',
          rationale: 'Updated rationale'
        }
      };

      const violatesImmutability = violatesADRImmutability(existing, incoming);
      expect(violatesImmutability).toBe(false);
    });

    it('should reject content changes for accepted decisions', () => {
      const existing = {
        kind: 'decision' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          component: 'authentication-system',
          status: 'accepted',
          title: 'Use OAuth 2.0',
          rationale: 'OAuth 2.0 provides industry-standard security.',
          alternatives_considered: ['Basic Auth'],
          consequences: 'Requires token management infrastructure.'
        }
      };

      const incoming = {
        kind: 'decision' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          component: 'authentication-system',
          status: 'accepted',
          title: 'Use OAuth 2.0 with Bearer tokens', // Title changed
          rationale: 'OAuth 2.0 provides industry-standard security.',
          alternatives_considered: ['Basic Auth'],
          consequences: 'Requires token management infrastructure.'
        }
      };

      const violatesImmutability = violatesADRImmutability(existing, incoming);
      expect(violatesImmutability).toBe(true);
    });

    it('should allow metadata updates for accepted decisions', () => {
      const existing = {
        kind: 'decision' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          component: 'authentication-system',
          status: 'accepted',
          title: 'Use OAuth 2.0',
          rationale: 'OAuth 2.0 provides industry-standard security.'
        }
      };

      const incoming = {
        kind: 'decision' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          component: 'authentication-system',
          status: 'accepted',
          title: 'Use OAuth 2.0',
          rationale: 'OAuth 2.0 provides industry-standard security.',
          supersedes: '550e8400-e29b-41d4-a716-446655440001' // New metadata
        }
      };

      const violatesImmutability = violatesADRImmutability(existing, incoming);
      expect(violatesImmutability).toBe(false);
    });

    it('should reject rationale changes for accepted decisions', () => {
      const existing = {
        kind: 'decision' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          component: 'test-component',
          status: 'accepted',
          title: 'Test Decision',
          rationale: 'Original rationale for the decision.'
        }
      };

      const incoming = {
        kind: 'decision' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          component: 'test-component',
          status: 'accepted',
          title: 'Test Decision',
          rationale: 'Modified rationale - this should be blocked.' // Rationale changed
        }
      };

      const violatesImmutability = violatesADRImmutability(existing, incoming);
      expect(violatesImmutability).toBe(true);
    });

    it('should reject component changes for accepted decisions', () => {
      const existing = {
        kind: 'decision' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          component: 'auth-service',
          status: 'accepted',
          title: 'Test Decision',
          rationale: 'Test rationale.'
        }
      };

      const incoming = {
        kind: 'decision' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          component: 'user-service', // Component changed
          status: 'accepted',
          title: 'Test Decision',
          rationale: 'Test rationale.'
        }
      };

      const violatesImmutability = violatesADRImmutability(existing, incoming);
      expect(violatesImmutability).toBe(true);
    });
  });

  describe('Decision Storage Operations', () => {
    it('should store proposed decision successfully', async () => {
      const decision = {
        kind: 'decision' as const,
        scope: {
          project: 'test-project',
          branch: 'main'
        },
        data: {
          component: 'api-gateway',
          status: 'proposed',
          title: 'Implement rate limiting',
          rationale: 'Rate limiting will prevent abuse and ensure fair usage.'
        }
      };

      const result = await db.storeItems([decision]);

      expect(result.stored).toHaveLength(1);
      expect(result.errors).toHaveLength(0);
      expect(result.stored[0]).toHaveProperty('id');
      expect(result.stored[0].kind).toBe('decision');
      expect(result.stored[0].data.status).toBe('proposed');
      expect(result.stored[0].data.component).toBe('api-gateway');

      // Verify Qdrant client was called
      expect(mockQdrant.upsert).toHaveBeenCalled();
    });

    it('should handle batch decision storage with different statuses', async () => {
      const decisions = [
        {
          kind: 'decision' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            component: 'database',
            status: 'proposed',
            title: 'Choose PostgreSQL',
            rationale: 'PostgreSQL offers good performance and features.'
          }
        },
        {
          kind: 'decision' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            component: 'cache-layer',
            status: 'accepted',
            title: 'Use Redis for caching',
            rationale: 'Redis provides fast in-memory caching.'
          }
        },
        {
          kind: 'decision' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            component: 'ui-framework',
            status: 'rejected',
            title: 'React vs Angular',
            rationale: 'Angular was rejected due to team expertise.'
          }
        }
      ];

      const result = await db.storeItems(decisions);

      expect(result.stored).toHaveLength(3);
      expect(result.errors).toHaveLength(0);
      expect(mockQdrant.upsert).toHaveBeenCalledTimes(3);

      const storedCalls = mockQdrant.upsert.mock.calls;
      expect(storedCalls[0][0][0].payload.data.status).toBe('proposed');
      expect(storedCalls[1][0][0].payload.data.status).toBe('accepted');
      expect(storedCalls[2][0][0].payload.data.status).toBe('rejected');
    });

    it('should handle invalid decisions in batch', async () => {
      const items = [
        {
          kind: 'decision' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            component: 'valid-component',
            status: 'proposed',
            title: 'Valid Decision',
            rationale: 'Valid rationale.'
          }
        },
        {
          kind: 'decision' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            // Missing component
            status: 'proposed',
            title: 'Invalid Decision',
            rationale: 'Invalid rationale.'
          }
        },
        {
          kind: 'decision' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            component: 'another-valid-component',
            status: 'accepted',
            title: 'Another Valid Decision',
            rationale: 'Another valid rationale.'
          }
        }
      ];

      const result = await db.storeItems(items);

      expect(result.stored).toHaveLength(2); // 2 valid decisions
      expect(result.errors).toHaveLength(1); // 1 invalid decision
    });
  });

  describe('Decision Search Operations', () => {
    beforeEach(() => {
      // Setup search mock for decisions
      mockQdrant.search.mockResolvedValue([
        {
          id: 'decision-id-1',
          score: 0.95,
          payload: {
            kind: 'decision',
            data: {
              component: 'authentication-system',
              status: 'accepted',
              title: 'Use OAuth 2.0 for authentication',
              rationale: 'OAuth 2.0 provides industry-standard security.'
            },
            scope: { project: 'test-project', branch: 'main' }
          }
        },
        {
          id: 'decision-id-2',
          score: 0.85,
          payload: {
            kind: 'decision',
            data: {
              component: 'database-layer',
              status: 'proposed',
              title: 'Choose primary database technology',
              rationale: 'We need to evaluate database options for performance.'
            },
            scope: { project: 'test-project', branch: 'main' }
          }
        }
      ]);
    });

    it('should find decisions by authentication query', async () => {
      const query = 'OAuth authentication security';

      const result = await db.searchItems(query);

      expect(result.items).toHaveLength(2);
      expect(result.items[0].data.component).toBe('authentication-system');
      expect(result.items[0].data.status).toBe('accepted');
      expect(result.items[0].data.title).toContain('OAuth 2.0');
      expect(mockQdrant.search).toHaveBeenCalled();
    });

    it('should handle empty decision search results', async () => {
      mockQdrant.search.mockResolvedValue([]);

      const result = await db.searchItems('nonexistent decision topic');

      expect(result.items).toHaveLength(0);
      expect(result.total).toBe(0);
    });
  });

  describe('Decision Status Lifecycle', () => {
    it('should handle all valid decision statuses', async () => {
      const statuses: Array<'proposed' | 'accepted' | 'rejected' | 'deprecated' | 'superseded'> = [
        'proposed', 'accepted', 'rejected', 'deprecated', 'superseded'
      ];

      const decisions = statuses.map((status, index) => ({
        kind: 'decision' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          component: `component-${index}`,
          status,
          title: `Decision with status ${status}`,
          rationale: `Rationale for ${status} decision.`
        }
      }));

      const results = await Promise.all(
        decisions.map(decision => db.storeItems([decision]))
      );

      results.forEach((result, index) => {
        expect(result.stored).toHaveLength(1);
        expect(result.stored[0].data.status).toBe(statuses[index]);
      });

      expect(mockQdrant.upsert).toHaveBeenCalledTimes(5);
    });

    it('should validate supersedes field with UUID format', () => {
      const decisionWithInvalidSupersedes = {
        kind: 'decision' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          component: 'test-component',
          status: 'accepted',
          title: 'Test Decision',
          rationale: 'Test rationale.',
          supersedes: 'invalid-uuid-format' // Invalid UUID
        }
      };

      const result = DecisionSchema.safeParse(decisionWithInvalidSupersedes);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('UUID');
      }
    });

    it('should accept valid UUID in supersedes field', () => {
      const decisionWithValidSupersedes = {
        kind: 'decision' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          component: 'test-component',
          status: 'accepted',
          title: 'Test Decision',
          rationale: 'Test rationale.',
          supersedes: '550e8400-e29b-41d4-a716-446655440000' // Valid UUID
        }
      };

      const result = DecisionSchema.safeParse(decisionWithValidSupersedes);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.supersedes).toBe('550e8400-e29b-41d4-a716-446655440000');
      }
    });
  });

  describe('Decision Integration with Knowledge System', () => {
    it('should integrate with knowledge item validation', () => {
      const decision = {
        kind: 'decision' as const,
        scope: {
          project: 'test-project',
          branch: 'main'
        },
        data: {
          component: 'microservices-architecture',
          status: 'accepted',
          title: 'Adopt microservices architecture',
          rationale: 'Microservices will improve scalability and maintainability.',
          alternatives_considered: [
            'Monolithic architecture',
            'Modular monolith'
          ],
          consequences: 'Increased operational complexity but better team autonomy.'
        },
        tags: { architecture: true, scale: true },
        source: {
          actor: 'principal-architect',
          tool: 'adr-workflow',
          timestamp: '2025-01-01T00:00:00Z'
        },
        ttl_policy: 'permanent' as const
      };

      const result = validateKnowledgeItem(decision);
      expect(result.kind).toBe('decision');
      expect(result.data.component).toBe('microservices-architecture');
      expect(result.data.status).toBe('accepted');
      expect(result.tags.architecture).toBe(true);
      expect(result.source.actor).toBe('principal-architect');
      expect(result.ttl_policy).toBe('permanent');
    });

    it('should handle decisions with comprehensive alternatives', () => {
      const decision = {
        kind: 'decision' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          component: 'payment-processor',
          status: 'accepted',
          title: 'Choose payment gateway provider',
          rationale: 'Stripe offers the best balance of features, documentation, and reliability.',
          alternatives_considered: [
            'Stripe - Excellent API and documentation, but higher fees',
            'PayPal - Widely recognized but limited API capabilities',
            'Braintree - Good features but complex integration',
            'Build custom solution - Maximum control but high maintenance overhead'
          ],
          consequences: '2.9% + 30¢ per transaction, but reduces development time by 3 months.'
        }
      };

      const result = DecisionSchema.safeParse(decision);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.alternatives_considered).toHaveLength(4);
        expect(result.data.data.alternatives_considered[0]).toContain('Stripe');
      }
    });
  });

  describe('Decision Error Handling and Edge Cases', () => {
    it('should handle decision storage errors gracefully', async () => {
      const decision = {
        kind: 'decision' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          component: 'test-component',
          status: 'proposed',
          title: 'Test Decision',
          rationale: 'Test rationale.'
        }
      };

      // Mock upsert to throw an error
      mockQdrant.upsert.mockRejectedValue(new Error('Database connection failed'));

      const result = await db.storeItems([decision]);

      expect(result.stored).toHaveLength(0);
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0].error).toContain('Database connection failed');
    });

    it('should handle decisions with special characters in title and rationale', async () => {
      const decision = {
        kind: 'decision' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          component: 'api-security',
          status: 'accepted',
          title: 'Implement JWT with RS256 (asymmetric keys) & refresh tokens',
          rationale: 'RS256 provides better security than HS256 for distributed systems. Refresh tokens improve UX by allowing long-lived sessions.',
          alternatives_considered: [
            'HS256 (symmetric) - simpler key management but less secure',
            'Session-based authentication - server-side state, less scalable'
          ]
        }
      };

      const result = await db.storeItems([decision]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].data.title).toContain('RS256');
      expect(result.stored[0].data.rationale).toContain('distributed systems');
    });

    it('should handle decisions with empty alternatives array', () => {
      const decision = {
        kind: 'decision' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          component: 'simple-component',
          status: 'accepted',
          title: 'Simple Decision',
          rationale: 'Simple rationale.',
          alternatives_considered: [] // Empty array is valid
        }
      };

      const result = DecisionSchema.safeParse(decision);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.alternatives_considered).toEqual([]);
      }
    });
  });
});