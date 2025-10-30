/**
 * Comprehensive Unit Tests for Assumption Knowledge Type
 *
 * Tests assumption knowledge type functionality including:
 * - Schema validation with all required and optional fields
 * - Assumption category validation (technical, business, user, market, resource)
 * - Validation status lifecycle (validated, assumed, invalidated, needs_validation)
 * - Impact assessment and validation criteria handling
 * - Related assumptions and dependencies linking
 * - Monitoring approach and review frequency validation
 * - Error handling and edge cases
 * - Integration with assumption management workflows
 * - TTL policy and metadata support
 * - Scope isolation for project/branch boundaries
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { VectorDatabase } from '../../../src/index';
import {
  AssumptionSchema,
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

describe('Assumption Knowledge Type - Comprehensive Testing', () => {
  let db: VectorDatabase;
  let mockQdrant: any;

  beforeEach(() => {
    db = new VectorDatabase();
    mockQdrant = (db as any).client;
  });

  describe('Assumption Schema Validation', () => {
    it('should validate complete technical assumption with all fields', () => {
      const assumption = {
        kind: 'assumption' as const,
        scope: {
          project: 'test-project',
          branch: 'main'
        },
        data: {
          title: 'Database can handle 10,000 concurrent connections',
          description: 'The PostgreSQL database configuration is optimized to handle peak load of 10,000 concurrent user connections without performance degradation.',
          category: 'technical' as const,
          validation_status: 'assumed' as const,
          impact_if_invalid: 'System will experience database connection timeouts during peak traffic, resulting in user-facing errors and potential revenue loss.',
          validation_criteria: [
            'Load testing with 10,000 concurrent connections',
            'Monitor connection pool utilization under load',
            'Verify response times remain < 100ms at peak load'
          ],
          validation_date: '2025-01-15T10:30:00Z',
          owner: 'database-team',
          related_assumptions: ['550e8400-e29b-41d4-a716-446655440001'],
          dependencies: ['postgresql-connection-pooling', 'load-balancer-configuration'],
          monitoring_approach: 'Database connection pool metrics via Prometheus + Grafana dashboard',
          review_frequency: 'monthly' as const
        },
        tags: { database: true, performance: true, scalability: true },
        source: {
          actor: 'database-architect',
          tool: 'assumption-tracking',
          timestamp: '2025-01-01T00:00:00Z'
        }
      };

      const result = AssumptionSchema.safeParse(assumption);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.kind).toBe('assumption');
        expect(result.data.data.category).toBe('technical');
        expect(result.data.data.validation_status).toBe('assumed');
        expect(result.data.data.title).toBe('Database can handle 10,000 concurrent connections');
        expect(result.data.data.validation_criteria).toHaveLength(3);
        expect(result.data.data.review_frequency).toBe('monthly');
      }
    });

    it('should validate minimal business assumption with only required fields', () => {
      const assumption = {
        kind: 'assumption' as const,
        scope: {
          project: 'test-project',
          branch: 'main'
        },
        data: {
          title: 'Market demand for mobile app features',
          description: 'Users are willing to pay premium for advanced mobile application features.',
          category: 'business' as const,
          validation_status: 'needs_validation' as const,
          impact_if_invalid: 'Development resources may be wasted on features that users do not value or want to purchase.'
        }
      };

      const result = AssumptionSchema.safeParse(assumption);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.category).toBe('business');
        expect(result.data.data.validation_status).toBe('needs_validation');
        expect(result.data.data.validation_criteria).toBeUndefined();
        expect(result.data.data.owner).toBeUndefined();
      }
    });

    it('should reject assumption missing required fields', () => {
      const invalidAssumptions = [
        {
          kind: 'assumption' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            // Missing title
            description: 'Test description',
            category: 'technical',
            validation_status: 'assumed',
            impact_if_invalid: 'Test impact'
          }
        },
        {
          kind: 'assumption' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Test title',
            // Missing description
            category: 'technical',
            validation_status: 'assumed',
            impact_if_invalid: 'Test impact'
          }
        },
        {
          kind: 'assumption' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Test title',
            description: 'Test description',
            // Missing category
            validation_status: 'assumed',
            impact_if_invalid: 'Test impact'
          }
        },
        {
          kind: 'assumption' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Test title',
            description: 'Test description',
            category: 'technical',
            // Missing validation_status
            impact_if_invalid: 'Test impact'
          }
        },
        {
          kind: 'assumption' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Test title',
            description: 'Test description',
            category: 'technical',
            validation_status: 'assumed'
            // Missing impact_if_invalid
          }
        }
      ];

      invalidAssumptions.forEach((assumption, index) => {
        const result = AssumptionSchema.safeParse(assumption);
        expect(result.success).toBe(false);
        if (!result.success) {
          expect(result.error.issues.length).toBeGreaterThan(0);
        }
      });
    });

    it('should enforce valid category values', () => {
      const assumption = {
        kind: 'assumption' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Test assumption',
          description: 'Test description',
          category: 'invalid_category' as any, // Invalid category
          validation_status: 'assumed',
          impact_if_invalid: 'Test impact'
        }
      };

      const result = AssumptionSchema.safeParse(assumption);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('Invalid enum value');
      }
    });

    it('should enforce valid validation_status values', () => {
      const assumption = {
        kind: 'assumption' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Test assumption',
          description: 'Test description',
          category: 'technical',
          validation_status: 'invalid_status' as any, // Invalid validation status
          impact_if_invalid: 'Test impact'
        }
      };

      const result = AssumptionSchema.safeParse(assumption);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('Invalid enum value');
      }
    });

    it('should enforce title length constraints', () => {
      const assumption = {
        kind: 'assumption' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'x'.repeat(501), // Exceeds 500 character limit
          description: 'Test description',
          category: 'technical',
          validation_status: 'assumed',
          impact_if_invalid: 'Test impact'
        }
      };

      const result = AssumptionSchema.safeParse(assumption);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('500 characters or less');
      }
    });

    it('should reject empty title', () => {
      const assumption = {
        kind: 'assumption' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: '', // Empty title
          description: 'Test description',
          category: 'technical',
          validation_status: 'assumed',
          impact_if_invalid: 'Test impact'
        }
      };

      const result = AssumptionSchema.safeParse(assumption);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('assumption title is required');
      }
    });

    it('should reject empty description', () => {
      const assumption = {
        kind: 'assumption' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Test title',
          description: '', // Empty description
          category: 'technical',
          validation_status: 'assumed',
          impact_if_invalid: 'Test impact'
        }
      };

      const result = AssumptionSchema.safeParse(assumption);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('assumption description is required');
      }
    });

    it('should reject empty impact_if_invalid', () => {
      const assumption = {
        kind: 'assumption' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Test title',
          description: 'Test description',
          category: 'technical',
          validation_status: 'assumed',
          impact_if_invalid: '' // Empty impact
        }
      };

      const result = AssumptionSchema.safeParse(assumption);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('impact description is required');
      }
    });
  });

  describe('Assumption Category Validation', () => {
    it('should validate all assumption categories', async () => {
      const categories: Array<'technical' | 'business' | 'user' | 'market' | 'resource'> = [
        'technical', 'business', 'user', 'market', 'resource'
      ];

      const assumptions = categories.map((category, index) => ({
        kind: 'assumption' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: `Assumption for ${category} category`,
          description: `Description for ${category} assumption.`,
          category,
          validation_status: 'assumed' as const,
          impact_if_invalid: `Impact if ${category} assumption is invalid.`
        },
        content: `Assumption: ${category} - Assumption for ${category} category`
      }));

      const results = await Promise.all(
        assumptions.map(assumption => db.storeItems([assumption]))
      );

      results.forEach((result, index) => {
        expect(result.stored).toHaveLength(1);
        expect(result.stored[0].data.category).toBe(categories[index]);
      });

      expect(mockQdrant.upsert).toHaveBeenCalledTimes(5);
    });

    it('should handle complex technical assumption with dependencies', () => {
      const technicalAssumption = {
        kind: 'assumption' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Kubernetes cluster auto-scaling handles burst traffic',
          description: 'The Kubernetes cluster auto-scaling configuration will automatically scale pods based on CPU/memory metrics during traffic bursts.',
          category: 'technical' as const,
          validation_status: 'validated' as const,
          impact_if_invalid: 'System will become unresponsive during traffic spikes, causing service degradation and potential outage.',
          validation_criteria: [
            'Chaos engineering tests with sudden traffic spikes',
            'Monitor pod scaling latency and success rate',
            'Verify resource requests/limits are properly configured',
            'Test cluster resource limits under maximum load'
          ],
          validation_date: '2025-01-20T14:00:00Z',
          owner: 'platform-engineering',
          dependencies: [
            'kubernetes-hpa-configuration',
            'metrics-server-setup',
            'pod-resource-limits'
          ],
          monitoring_approach: 'Prometheus alerts for pod scaling events and resource utilization',
          review_frequency: 'quarterly' as const
        }
      };

      const result = AssumptionSchema.safeParse(technicalAssumption);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.category).toBe('technical');
        expect(result.data.data.validation_status).toBe('validated');
        expect(result.data.data.validation_criteria).toHaveLength(4);
        expect(result.data.data.dependencies).toHaveLength(3);
        expect(result.data.data.validation_date).toBe('2025-01-20T14:00:00Z');
      }
    });

    it('should handle business assumption with market impact', () => {
      const businessAssumption = {
        kind: 'assumption' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Enterprise customers will pay for SSO integration',
          description: 'Enterprise customers are willing to pay premium pricing for single sign-on (SSO) integration with their existing identity providers.',
          category: 'business' as const,
          validation_status: 'needs_validation' as const,
          impact_if_invalid: 'Development effort spent on SSO integration may not generate expected revenue, affecting ROI and product strategy.',
          validation_criteria: [
            'Customer surveys on SSO feature priority',
            'Competitive analysis of SSO pricing models',
            'Sales team feedback on deal impact'
          ],
          owner: 'product-management',
          monitoring_approach: 'Track SSO feature adoption and revenue metrics',
          review_frequency: 'monthly' as const
        }
      };

      const result = AssumptionSchema.safeParse(businessAssumption);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.category).toBe('business');
        expect(result.data.data.validation_status).toBe('needs_validation');
        expect(result.data.data.owner).toBe('product-management');
      }
    });

    it('should handle user assumption with behavioral expectations', () => {
      const userAssumption = {
        kind: 'assumption' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Users prefer dark mode for extended usage sessions',
          description: 'Users spending more than 30 minutes in the application prefer dark mode interface to reduce eye strain.',
          category: 'user' as const,
          validation_status: 'assumed' as const,
          impact_if_invalid: 'Development effort on dark mode may not improve user retention or satisfaction as expected.',
          validation_criteria: [
            'A/B testing on user session duration with light/dark themes',
            'User preference tracking and feedback collection',
            'Analyze usage patterns of power users'
          ],
          monitoring_approach: 'User analytics dashboard tracking theme preferences and session duration',
          review_frequency: 'as_needed' as const
        }
      };

      const result = AssumptionSchema.safeParse(userAssumption);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.category).toBe('user');
        expect(result.data.data.review_frequency).toBe('as_needed');
      }
    });
  });

  describe('Assumption Validation Status Lifecycle', () => {
    it('should handle all validation status values', async () => {
      const statuses: Array<'validated' | 'assumed' | 'invalidated' | 'needs_validation'> = [
        'validated', 'assumed', 'invalidated', 'needs_validation'
      ];

      const assumptions = statuses.map((validation_status, index) => ({
        kind: 'assumption' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: `Assumption with status ${validation_status}`,
          description: `Description for ${validation_status} assumption.`,
          category: 'technical',
          validation_status,
          impact_if_invalid: `Impact if ${validation_status} assumption is invalid.`
        },
        content: `Assumption: ${validation_status} - Assumption with status ${validation_status}`
      }));

      const results = await Promise.all(
        assumptions.map(assumption => db.storeItems([assumption]))
      );

      results.forEach((result, index) => {
        expect(result.stored).toHaveLength(1);
        expect(result.stored[0].data.validation_status).toBe(statuses[index]);
      });

      expect(mockQdrant.upsert).toHaveBeenCalledTimes(4);
    });

    it('should validate validation_date format', () => {
      const assumptionWithInvalidDate = {
        kind: 'assumption' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Test assumption',
          description: 'Test description',
          category: 'technical',
          validation_status: 'validated',
          impact_if_invalid: 'Test impact',
          validation_date: 'invalid-date-format' // Invalid date format
        }
      };

      const result = AssumptionSchema.safeParse(assumptionWithInvalidDate);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('datetime');
      }
    });

    it('should accept valid datetime in validation_date', () => {
      const assumptionWithValidDate = {
        kind: 'assumption' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Test assumption',
          description: 'Test description',
          category: 'technical',
          validation_status: 'validated',
          impact_if_invalid: 'Test impact',
          validation_date: '2025-01-15T10:30:00Z' // Valid ISO datetime
        }
      };

      const result = AssumptionSchema.safeParse(assumptionWithValidDate);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.validation_date).toBe('2025-01-15T10:30:00Z');
      }
    });

    it('should handle assumption lifecycle from assumed to validated', () => {
      const assumedAssumption = {
        kind: 'assumption' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'API response time under 200ms',
          description: 'API endpoints will respond in under 200ms for 95% of requests.',
          category: 'technical',
          validation_status: 'assumed' as const,
          impact_if_invalid: 'Poor user experience and potential SLA violations.'
        }
      };

      const validatedAssumption = {
        kind: 'assumption' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'API response time under 200ms',
          description: 'API endpoints will respond in under 200ms for 95% of requests.',
          category: 'technical',
          validation_status: 'validated' as const,
          impact_if_invalid: 'Poor user experience and potential SLA violations.',
          validation_criteria: [
            'Load testing confirms 95th percentile < 200ms',
            'Production monitoring shows consistent performance'
          ],
          validation_date: '2025-01-25T16:45:00Z',
          owner: 'api-team'
        }
      };

      const assumedResult = AssumptionSchema.safeParse(assumedAssumption);
      expect(assumedResult.success).toBe(true);

      const validatedResult = AssumptionSchema.safeParse(validatedAssumption);
      expect(validatedResult.success).toBe(true);

      if (validatedResult.success) {
        expect(validatedResult.data.data.validation_status).toBe('validated');
        expect(validatedResult.data.data.validation_date).toBe('2025-01-25T16:45:00Z');
        expect(validatedResult.data.data.validation_criteria).toHaveLength(2);
      }
    });
  });

  describe('Assumption Storage Operations', () => {
    it('should store assumption with comprehensive validation criteria successfully', async () => {
      const assumption = {
        kind: 'assumption' as const,
        scope: {
          project: 'test-project',
          branch: 'main'
        },
        data: {
          title: 'Third-party payment gateway reliability',
          description: 'The payment gateway provider maintains 99.9% uptime and can handle our peak transaction volume.',
          category: 'resource' as const,
          validation_status: 'validated' as const,
          impact_if_invalid: 'Payment processing failures will result in lost revenue and customer trust issues.',
          validation_criteria: [
            'Review provider SLA and uptime guarantees',
            'Test transaction processing under peak load',
            'Verify failover and redundancy mechanisms',
            'Check customer support response times',
            'Validate security compliance certifications'
          ],
          validation_date: '2025-01-10T09:00:00Z',
          owner: 'finance-operations',
          dependencies: ['payment-gateway-integration', 'transaction-monitoring'],
          monitoring_approach: 'Real-time payment success rate monitoring and provider SLA tracking',
          review_frequency: 'weekly' as const
        },
        content: 'Assumption: Third-party payment gateway reliability - Payment gateway maintains 99.9% uptime and handles peak transaction volume'
      };

      const result = await db.storeItems([assumption]);

      expect(result.stored).toHaveLength(1);
      expect(result.errors).toHaveLength(0);
      expect(result.stored[0]).toHaveProperty('id');
      expect(result.stored[0].kind).toBe('assumption');
      expect(result.stored[0].data.category).toBe('resource');
      expect(result.stored[0].data.validation_status).toBe('validated');
      expect(result.stored[0].data.validation_criteria).toHaveLength(5);

      // Verify Qdrant client was called
      expect(mockQdrant.upsert).toHaveBeenCalled();
    });

    it('should handle batch assumption storage with different categories', async () => {
      const assumptions = [
        {
          kind: 'assumption' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'User base grows 20% monthly',
            description: 'User acquisition will maintain 20% month-over-month growth.',
            category: 'market' as const,
            validation_status: 'assumed' as const,
            impact_if_invalid: 'Infrastructure planning and resource allocation may be misaligned with actual growth.'
          },
          content: 'Assumption: User base grows 20% monthly - User acquisition maintains 20% month-over-month growth'
        },
        {
          kind: 'assumption' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Development team can maintain velocity',
            description: 'Development team can sustain current sprint velocity with current resources.',
            category: 'resource' as const,
            validation_status: 'needs_validation' as const,
            impact_if_invalid: 'Project timelines may be missed, requiring re-planning and additional resources.',
            owner: 'engineering-manager',
            review_frequency: 'monthly' as const
          },
          content: 'Assumption: Development team can maintain velocity - Development team can sustain current sprint velocity'
        },
        {
          kind: 'assumption' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Security model meets compliance requirements',
            description: 'Current security architecture satisfies GDPR and SOC 2 compliance requirements.',
            category: 'technical' as const,
            validation_status: 'validated' as const,
            impact_if_invalid: 'Non-compliance could result in fines and loss of enterprise customers.',
            validation_criteria: [
              'Third-party security audit',
              'Penetration testing results',
              'Compliance documentation review'
            ],
            validation_date: '2024-12-15T00:00:00Z'
          },
          content: 'Assumption: Security model meets compliance requirements - Security architecture satisfies GDPR and SOC 2'
        }
      ];

      const result = await db.storeItems(assumptions);

      expect(result.stored).toHaveLength(3);
      expect(result.errors).toHaveLength(0);
      expect(mockQdrant.upsert).toHaveBeenCalledTimes(3);

      // Verify that categories are correctly stored in the results
      expect(result.stored[0].data.category).toBe('market');
      expect(result.stored[1].data.category).toBe('resource');
      expect(result.stored[2].data.category).toBe('technical');
    });

    it('should handle invalid assumptions in batch', async () => {
      const items = [
        {
          kind: 'assumption' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Valid technical assumption',
            description: 'This is a valid technical assumption.',
            category: 'technical' as const,
            validation_status: 'assumed' as const,
            impact_if_invalid: 'Valid impact description.'
          },
          content: 'Assumption: Valid technical assumption - This is a valid technical assumption'
        },
        {
          kind: 'assumption' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Invalid assumption',
            description: 'This assumption is missing required fields.',
            category: 'invalid_category' as any, // Invalid category
            validation_status: 'assumed' as const,
            impact_if_invalid: 'Impact description.'
          },
          content: 'Assumption: Invalid assumption - This assumption is missing required fields'
        },
        {
          kind: 'assumption' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Another valid assumption',
            description: 'This is another valid assumption.',
            category: 'business' as const,
            validation_status: 'needs_validation' as const,
            impact_if_invalid: 'Another valid impact description.',
            owner: 'product-team'
          },
          content: 'Assumption: Another valid assumption - This is another valid assumption'
        }
      ];

      const result = await db.storeItems(items);

      expect(result.stored).toHaveLength(3); // All 3 assumptions stored (validation happens later)
      expect(result.errors).toHaveLength(0); // No storage errors
    });
  });

  describe('Assumption Search Operations', () => {
    beforeEach(() => {
      // Setup search mock for assumptions
      mockQdrant.search.mockResolvedValue([
        {
          id: 'assumption-id-1',
          score: 0.95,
          payload: {
            kind: 'assumption',
            data: {
              title: 'Database can handle 10,000 concurrent connections',
              description: 'The PostgreSQL database configuration is optimized for peak load.',
              category: 'technical',
              validation_status: 'validated',
              impact_if_invalid: 'System will experience timeouts during peak traffic.',
              validation_date: '2025-01-15T10:30:00Z',
              owner: 'database-team'
            },
            scope: { project: 'test-project', branch: 'main' }
          }
        },
        {
          id: 'assumption-id-2',
          score: 0.85,
          payload: {
            kind: 'assumption',
            data: {
              title: 'Enterprise customers will pay for SSO integration',
              description: 'Enterprise customers are willing to pay premium for SSO features.',
              category: 'business',
              validation_status: 'needs_validation',
              impact_if_invalid: 'Development effort may not generate expected revenue.',
              owner: 'product-management'
            },
            scope: { project: 'test-project', branch: 'main' }
          }
        }
      ]);
    });

    it('should find assumptions by database query', async () => {
      const query = 'database connections PostgreSQL performance';

      const result = await db.searchItems(query);

      expect(result.items).toHaveLength(2);
      expect(result.items[0].data.title).toContain('Database');
      expect(result.items[0].data.category).toBe('technical');
      expect(result.items[0].data.validation_status).toBe('validated');
      expect(result.items[0].data.owner).toBe('database-team');
      expect(mockQdrant.search).toHaveBeenCalled();
    });

    it('should find assumptions by business category query', async () => {
      const query = 'enterprise SSO revenue pricing';

      const result = await db.searchItems(query);

      expect(result.items).toHaveLength(2);
      expect(result.items[1].data.title).toContain('SSO');
      expect(result.items[1].data.category).toBe('business');
      expect(result.items[1].data.validation_status).toBe('needs_validation');
      expect(result.items[1].data.owner).toBe('product-management');
    });

    it('should handle empty assumption search results', async () => {
      mockQdrant.search.mockResolvedValue([]);

      const result = await db.searchItems('nonexistent assumption topic');

      expect(result.items).toHaveLength(0);
      expect(result.total).toBe(0);
    });

    it('should search assumptions by validation status', async () => {
      mockQdrant.search.mockResolvedValue([
        {
          id: 'assumption-id-3',
          score: 0.90,
          payload: {
            kind: 'assumption',
            data: {
              title: 'API response time requirements',
              description: 'API endpoints respond within acceptable time limits.',
              category: 'technical',
              validation_status: 'assumed',
              impact_if_invalid: 'Poor user experience and SLA violations.'
            },
            scope: { project: 'test-project', branch: 'main' }
          }
        }
      ]);

      const result = await db.searchItems('assumed validation status');

      expect(result.items).toHaveLength(1);
      expect(result.items[0].data.validation_status).toBe('assumed');
    });
  });

  describe('Assumption Scope Isolation', () => {
    it('should isolate assumptions by project scope', async () => {
      const projectAssumption = {
        kind: 'assumption' as const,
        scope: { project: 'project-alpha', branch: 'main' },
        data: {
          title: 'Project Alpha specific assumption',
          description: 'This assumption is specific to Project Alpha.',
          category: 'technical',
          validation_status: 'assumed',
          impact_if_invalid: 'Impact on Project Alpha.'
        },
        content: 'Assumption: Project Alpha specific assumption - This assumption is specific to Project Alpha'
      };

      const anotherProjectAssumption = {
        kind: 'assumption' as const,
        scope: { project: 'project-beta', branch: 'main' },
        data: {
          title: 'Project Beta specific assumption',
          description: 'This assumption is specific to Project Beta.',
          category: 'business',
          validation_status: 'needs_validation',
          impact_if_invalid: 'Impact on Project Beta.'
        },
        content: 'Assumption: Project Beta specific assumption - This assumption is specific to Project Beta'
      };

      const result = await db.storeItems([projectAssumption, anotherProjectAssumption]);

      expect(result.stored).toHaveLength(2);
      expect(mockQdrant.upsert).toHaveBeenCalledTimes(2);

      // Verify project scopes in the stored results
      expect(result.stored[0].scope.project).toBe('project-alpha');
      expect(result.stored[1].scope.project).toBe('project-beta');
    });

    it('should handle assumptions with different branch scopes', async () => {
      const mainBranchAssumption = {
        kind: 'assumption' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Main branch assumption',
          description: 'Assumption valid for main branch.',
          category: 'technical',
          validation_status: 'validated',
          impact_if_invalid: 'Main branch impact.'
        },
        content: 'Assumption: Main branch assumption - Assumption valid for main branch'
      };

      const featureBranchAssumption = {
        kind: 'assumption' as const,
        scope: { project: 'test-project', branch: 'feature/new-ui' },
        data: {
          title: 'Feature branch assumption',
          description: 'Assumption specific to feature branch.',
          category: 'user',
          validation_status: 'assumed',
          impact_if_invalid: 'Feature branch impact.'
        },
        content: 'Assumption: Feature branch assumption - Assumption specific to feature branch'
      };

      const result = await db.storeItems([mainBranchAssumption, featureBranchAssumption]);

      expect(result.stored).toHaveLength(2);
      expect(mockQdrant.upsert).toHaveBeenCalledTimes(2);

      // Verify branch scopes in the stored results
      expect(result.stored[0].scope.branch).toBe('main');
      expect(result.stored[1].scope.branch).toBe('feature/new-ui');
    });
  });

  describe('Assumption Related Assumptions and Dependencies', () => {
    it('should handle assumptions with related assumptions using UUIDs', () => {
      const assumptionWithRelations = {
        kind: 'assumption' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Authentication system scales with user growth',
          description: 'The authentication system can handle user growth from 10K to 1M users.',
          category: 'technical',
          validation_status: 'assumed',
          impact_if_invalid: 'Authentication bottlenecks will prevent user registration and login.',
          related_assumptions: [
            '550e8400-e29b-41d4-a716-446655440001',
            '550e8400-e29b-41d4-a716-446655440002',
            '550e8400-e29b-41d4-a716-446655440003'
          ],
          dependencies: ['oauth-provider-scaling', 'session-storage-scaling']
        }
      };

      const result = AssumptionSchema.safeParse(assumptionWithRelations);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.related_assumptions).toHaveLength(3);
        expect(result.data.data.related_assumptions[0]).toBe('550e8400-e29b-41d4-a716-446655440001');
        expect(result.data.data.dependencies).toHaveLength(2);
      }
    });

    it('should reject invalid UUID format in related_assumptions', () => {
      const assumptionWithInvalidUUID = {
        kind: 'assumption' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Test assumption',
          description: 'Test description.',
          category: 'technical',
          validation_status: 'assumed',
          impact_if_invalid: 'Test impact.',
          related_assumptions: ['invalid-uuid-format'] // Invalid UUID
        }
      };

      const result = AssumptionSchema.safeParse(assumptionWithInvalidUUID);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('Invalid uuid');
      }
    });

    it('should handle empty arrays for related_assumptions and dependencies', () => {
      const assumptionWithEmptyArrays = {
        kind: 'assumption' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Independent assumption',
          description: 'This assumption has no related assumptions or dependencies.',
          category: 'business',
          validation_status: 'needs_validation',
          impact_if_invalid: 'Independent impact.',
          related_assumptions: [], // Empty array is valid
          dependencies: [] // Empty array is valid
        }
      };

      const result = AssumptionSchema.safeParse(assumptionWithEmptyArrays);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.related_assumptions).toEqual([]);
        expect(result.data.data.dependencies).toEqual([]);
      }
    });
  });

  describe('Assumption Monitoring and Review Frequency', () => {
    it('should validate all review frequency options', async () => {
      const reviewFrequencies: Array<'daily' | 'weekly' | 'monthly' | 'quarterly' | 'as_needed'> = [
        'daily', 'weekly', 'monthly', 'quarterly', 'as_needed'
      ];

      const assumptions = reviewFrequencies.map((review_frequency, index) => ({
        kind: 'assumption' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: `Assumption with ${review_frequency} review`,
          description: `Description for ${review_frequency} review frequency.`,
          category: 'technical',
          validation_status: 'assumed',
          impact_if_invalid: 'Impact description.',
          monitoring_approach: `Monitoring approach for ${review_frequency} review.`,
          review_frequency
        },
        content: `Assumption: ${review_frequency} review - Assumption with ${review_frequency} review`
      }));

      const results = await Promise.all(
        assumptions.map(assumption => db.storeItems([assumption]))
      );

      results.forEach((result, index) => {
        expect(result.stored).toHaveLength(1);
        expect(result.stored[0].data.review_frequency).toBe(reviewFrequencies[index]);
      });

      expect(mockQdrant.upsert).toHaveBeenCalledTimes(5);
    });

    it('should handle comprehensive monitoring approach', () => {
      const assumptionWithMonitoring = {
        kind: 'assumption' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Third-party API rate limits are sufficient',
          description: 'External API rate limits can handle our projected traffic volume.',
          category: 'resource',
          validation_status: 'validated',
          impact_if_invalid: 'API rate limiting will cause service disruptions and poor user experience.',
          validation_criteria: [
            'API provider rate limit documentation review',
            'Load testing against rate limits',
            'Monitor API usage patterns in production'
          ],
          validation_date: '2025-01-18T11:30:00Z',
          owner: 'integration-team',
          monitoring_approach: 'Prometheus alerts tracking API request rates, response times, and rate limit breach events. Weekly usage reports and quarterly provider contract reviews.',
          review_frequency: 'weekly'
        }
      };

      const result = AssumptionSchema.safeParse(assumptionWithMonitoring);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.monitoring_approach).toContain('Prometheus');
        expect(result.data.data.monitoring_approach).toContain('Weekly');
        expect(result.data.data.review_frequency).toBe('weekly');
      }
    });

    it('should reject invalid review frequency', () => {
      const assumptionWithInvalidFrequency = {
        kind: 'assumption' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Test assumption',
          description: 'Test description.',
          category: 'technical',
          validation_status: 'assumed',
          impact_if_invalid: 'Test impact.',
          review_frequency: 'invalid_frequency' as any // Invalid review frequency
        }
      };

      const result = AssumptionSchema.safeParse(assumptionWithInvalidFrequency);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('Invalid enum value');
      }
    });
  });

  describe('Assumption Integration with Knowledge System', () => {
    it('should integrate with knowledge item validation', () => {
      const assumption = {
        kind: 'assumption' as const,
        scope: {
          project: 'test-project',
          branch: 'main'
        },
        data: {
          title: 'Cloud provider regional availability',
          description: 'Cloud provider maintains service availability across all required geographic regions.',
          category: 'resource',
          validation_status: 'validated',
          impact_if_invalid: 'Service availability issues in specific regions will affect customer base.',
          validation_criteria: [
            'Review cloud provider SLA documentation',
            'Test failover between regions',
            'Verify compliance with data residency requirements'
          ],
          validation_date: '2025-01-22T08:00:00Z',
          owner: 'infrastructure-team',
          monitoring_approach: 'Multi-region health checks and uptime monitoring',
          review_frequency: 'monthly'
        },
        tags: { infrastructure: true, compliance: true, availability: true },
        source: {
          actor: 'cloud-architect',
          tool: 'assumption-workflow',
          timestamp: '2025-01-01T00:00:00Z'
        },
        ttl_policy: 'long' as const
      };

      const result = validateKnowledgeItem(assumption);
      expect(result.kind).toBe('assumption');
      expect(result.data.category).toBe('resource');
      expect(result.data.validation_status).toBe('validated');
      expect(result.tags.infrastructure).toBe(true);
      expect(result.source.actor).toBe('cloud-architect');
      expect(result.ttl_policy).toBe('long');
    });

    it('should handle assumption with complex validation criteria', () => {
      const complexAssumption = {
        kind: 'assumption' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Machine learning model accuracy remains stable over time',
          description: 'ML model performance metrics (accuracy, precision, recall) remain within acceptable ranges as data distribution evolves.',
          category: 'technical',
          validation_status: 'needs_validation',
          impact_if_invalid: 'Model degradation will lead to poor predictions and business decisions without detection.',
          validation_criteria: [
            'Weekly performance metric tracking (accuracy > 85%, precision > 80%, recall > 75%)',
            'Monthly model retraining with fresh data',
            'Quarterly model performance audit against business KPIs',
            'Continuous monitoring for data drift and concept drift',
            'A/B testing against baseline model for major deployments',
            'Annual complete model validation and redevelopment if needed'
          ],
          owner: 'ml-engineering-team',
          dependencies: ['model-training-pipeline', 'feature-store', 'monitoring-infrastructure'],
          monitoring_approach: 'Real-time model performance dashboard with automated alerts for metric degradation',
          review_frequency: 'weekly'
        }
      };

      const result = AssumptionSchema.safeParse(complexAssumption);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.validation_criteria).toHaveLength(6);
        expect(result.data.data.validation_criteria[0]).toContain('accuracy > 85%');
        expect(result.data.data.dependencies).toHaveLength(3);
      }
    });
  });

  describe('Assumption Error Handling and Edge Cases', () => {
    it('should handle assumption storage errors gracefully', async () => {
      const assumption = {
        kind: 'assumption' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Test assumption',
          description: 'Test description.',
          category: 'technical',
          validation_status: 'assumed',
          impact_if_invalid: 'Test impact.'
        },
        content: 'Assumption: Test assumption - Test description'
      };

      // Mock upsert to throw an error
      mockQdrant.upsert.mockRejectedValue(new Error('Database connection failed'));

      const result = await db.storeItems([assumption]);

      expect(result.stored).toHaveLength(0);
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0].error).toContain('Database connection failed');
    });

    it('should handle assumptions with special characters in title and description', async () => {
      const assumption = {
        kind: 'assumption' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'API rate limiting (429 responses) < 0.1% of total requests',
          description: 'Rate limiting configuration ensures that less than 0.1% of API requests receive HTTP 429 (Too Many Requests) responses, even during peak traffic periods & DDoS protection events.',
          category: 'technical',
          validation_status: 'validated',
          impact_if_invalid: 'High rate of 429 responses will degrade user experience & indicate insufficient infrastructure capacity.',
          validation_criteria: [
            'Load testing with 10x normal traffic',
            'Monitor 429 response rates via API Gateway metrics',
            'Verify rate limiting rules are properly configured'
          ],
          validation_date: '2025-01-25T14:20:00Z',
          owner: 'api-platform-team',
          monitoring_approach: 'CloudWatch alarms for 429 response rate > 0.1%',
          review_frequency: 'daily'
        },
        content: 'Assumption: API rate limiting (429 responses) < 0.1% - Rate limiting ensures < 0.1% of API requests receive 429 responses'
      };

      const result = await db.storeItems([assumption]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].data.title).toContain('429 responses');
      expect(result.stored[0].data.description).toContain('DDoS protection');
    });

    it('should handle assumption with minimal monitoring approach', () => {
      const minimalAssumption = {
        kind: 'assumption' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Simple assumption',
          description: 'Simple description.',
          category: 'user',
          validation_status: 'assumed',
          impact_if_invalid: 'Simple impact.',
          monitoring_approach: 'Basic monitoring' // Minimal but valid
        }
      };

      const result = AssumptionSchema.safeParse(minimalAssumption);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.monitoring_approach).toBe('Basic monitoring');
      }
    });

    it('should handle assumption transition to invalidated status', () => {
      const invalidatedAssumption = {
        kind: 'assumption' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Legacy browser support is not required',
          description: 'Users have migrated to modern browsers, making Internet Explorer support unnecessary.',
          category: 'user',
          validation_status: 'invalidated' as const,
          impact_if_invalid: 'Continuing to support legacy browsers wastes development resources.',
          validation_criteria: [
            'Browser usage analytics showing < 1% IE traffic',
            'Customer feedback confirming modern browser usage'
          ],
          validation_date: '2025-01-30T16:00:00Z',
          owner: 'frontend-team',
          monitoring_approach: 'Monthly browser usage analytics review',
          review_frequency: 'monthly'
        }
      };

      const result = AssumptionSchema.safeParse(invalidatedAssumption);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.validation_status).toBe('invalidated');
        expect(result.data.data.validation_date).toBe('2025-01-30T16:00:00Z');
      }
    });
  });
});