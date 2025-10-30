/**
 * Comprehensive Unit Tests for Risk Knowledge Type
 *
 * Tests risk knowledge type functionality including:
 * - Schema validation with required fields (title, category, risk_level, probability, impact_description, status)
 * - Optional fields validation (trigger_events, mitigation_strategies, owner, review_date, related_decisions, monitoring_indicators, contingency_plans)
 * - Category validation (technical, business, operational, security, compliance)
 * - Risk level validation (critical, high, medium, low)
 * - Probability validation (very_likely, likely, possible, unlikely, very_unlikely)
 * - Status validation (active, mitigated, accepted, closed)
 * - Storage operations and batch processing
 * - Search operations and query handling
 * - Scope isolation by project and branch
 * - Edge cases and error handling
 * - Integration with knowledge system and TTL policies
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { VectorDatabase } from '../../../src/index';
import {
  RiskSchema,
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

describe('Risk Knowledge Type - Comprehensive Testing', () => {
  let db: VectorDatabase;
  let mockQdrant: any;

  beforeEach(() => {
    db = new VectorDatabase();
    mockQdrant = (db as any).client;
  });

  describe('Risk Schema Validation', () => {
    it('should validate complete risk with all fields', () => {
      const risk = {
        kind: 'risk' as const,
        scope: {
          project: 'test-project',
          branch: 'main'
        },
        data: {
          title: 'Critical security vulnerability in authentication system',
          category: 'security' as const,
          risk_level: 'critical' as const,
          probability: 'very_likely' as const,
          impact_description: 'Authentication bypass could allow unauthorized access to all user data, leading to data breach and privacy violations. Estimated impact includes regulatory fines, customer loss, and brand damage.',
          trigger_events: [
            'Discovery of zero-day exploit',
            'Malicious actor gains system access',
            'Failed security audit'
          ],
          mitigation_strategies: [
            'Implement multi-factor authentication immediately',
            'Apply security patches within 24 hours',
            'Conduct security audit of authentication flow',
            'Implement rate limiting and monitoring'
          ],
          owner: 'security-team-lead',
          review_date: '2025-02-15T00:00:00Z',
          status: 'active' as const,
          related_decisions: ['550e8400-e29b-41d4-a716-446655440001'],
          monitoring_indicators: [
            'Authentication failure rate > 5%',
            'Unusual login patterns detected',
            'Security scan results'
          ],
          contingency_plans: 'If breach occurs, immediately activate incident response team, notify affected users within 72 hours, and engage external security forensics team.'
        },
        tags: { security: true, authentication: true, 'critical-risk': true },
        source: {
          actor: 'security-auditor',
          tool: 'risk-assessment-platform',
          timestamp: '2025-01-15T10:30:00Z'
        },
        ttl_policy: '90d' as const
      };

      const result = RiskSchema.safeParse(risk);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.kind).toBe('risk');
        expect(result.data.data.title).toBe('Critical security vulnerability in authentication system');
        expect(result.data.data.category).toBe('security');
        expect(result.data.data.risk_level).toBe('critical');
        expect(result.data.data.probability).toBe('very_likely');
        expect(result.data.data.status).toBe('active');
        expect(result.data.data.mitigation_strategies).toHaveLength(4);
        expect(result.data.data.owner).toBe('security-team-lead');
        expect(result.data.data.monitoring_indicators).toHaveLength(3);
      }
    });

    it('should validate minimal risk with only required fields', () => {
      const risk = {
        kind: 'risk' as const,
        scope: {
          project: 'test-project',
          branch: 'main'
        },
        data: {
          title: 'API rate limiting may be insufficient',
          category: 'technical' as const,
          risk_level: 'medium' as const,
          probability: 'possible' as const,
          impact_description: 'Service could be overwhelmed by high traffic',
          status: 'active' as const
        }
      };

      const result = RiskSchema.safeParse(risk);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.title).toBe('API rate limiting may be insufficient');
        expect(result.data.data.category).toBe('technical');
        expect(result.data.data.risk_level).toBe('medium');
        expect(result.data.data.probability).toBe('possible');
        expect(result.data.data.status).toBe('active');
        expect(result.data.data.mitigation_strategies).toBeUndefined();
        expect(result.data.data.owner).toBeUndefined();
        expect(result.data.data.monitoring_indicators).toBeUndefined();
      }
    });

    it('should reject risk missing required fields', () => {
      const invalidRisks = [
        {
          kind: 'risk' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            // Missing title
            category: 'technical',
            risk_level: 'high',
            probability: 'likely',
            impact_description: 'Service could fail',
            status: 'active'
          }
        },
        {
          kind: 'risk' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Test Risk',
            // Missing category
            risk_level: 'high',
            probability: 'likely',
            impact_description: 'Service could fail',
            status: 'active'
          }
        },
        {
          kind: 'risk' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Test Risk',
            category: 'technical',
            // Missing risk_level
            probability: 'likely',
            impact_description: 'Service could fail',
            status: 'active'
          }
        },
        {
          kind: 'risk' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Test Risk',
            category: 'technical',
            risk_level: 'high',
            // Missing probability
            impact_description: 'Service could fail',
            status: 'active'
          }
        },
        {
          kind: 'risk' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Test Risk',
            category: 'technical',
            risk_level: 'high',
            probability: 'likely',
            // Missing impact_description
            status: 'active'
          }
        },
        {
          kind: 'risk' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Test Risk',
            category: 'technical',
            risk_level: 'high',
            probability: 'likely',
            impact_description: 'Service could fail'
            // Missing status
          }
        }
      ];

      invalidRisks.forEach((risk, index) => {
        const result = RiskSchema.safeParse(risk);
        expect(result.success).toBe(false);
        if (!result.success) {
          expect(result.error.issues.length).toBeGreaterThan(0);
        }
      });
    });

    it('should enforce valid category values', () => {
      const validCategories = ['technical', 'business', 'operational', 'security', 'compliance'] as const;

      validCategories.forEach((category) => {
        const risk = {
          kind: 'risk' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Test Risk',
            category,
            risk_level: 'medium' as const,
            probability: 'possible' as const,
            impact_description: 'Test impact description',
            status: 'active' as const
          }
        };

        const result = RiskSchema.safeParse(risk);
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.data.category).toBe(category);
        }
      });

      // Test invalid category
      const invalidRisk = {
        kind: 'risk' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Test Risk',
          category: 'invalid-category' as any,
          risk_level: 'medium' as const,
          probability: 'possible' as const,
          impact_description: 'Test impact description',
          status: 'active' as const
        }
      };

      const result = RiskSchema.safeParse(invalidRisk);
      expect(result.success).toBe(false);
    });

    it('should enforce valid risk level values', () => {
      const validRiskLevels = ['critical', 'high', 'medium', 'low'] as const;

      validRiskLevels.forEach((risk_level) => {
        const risk = {
          kind: 'risk' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Test Risk',
            category: 'technical' as const,
            risk_level,
            probability: 'possible' as const,
            impact_description: 'Test impact description',
            status: 'active' as const
          }
        };

        const result = RiskSchema.safeParse(risk);
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.data.risk_level).toBe(risk_level);
        }
      });

      // Test invalid risk level
      const invalidRisk = {
        kind: 'risk' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Test Risk',
          category: 'technical' as const,
          risk_level: 'urgent' as any,
          probability: 'possible' as const,
          impact_description: 'Test impact description',
          status: 'active' as const
        }
      };

      const result = RiskSchema.safeParse(invalidRisk);
      expect(result.success).toBe(false);
    });

    it('should enforce valid probability values', () => {
      const validProbabilities = ['very_likely', 'likely', 'possible', 'unlikely', 'very_unlikely'] as const;

      validProbabilities.forEach((probability) => {
        const risk = {
          kind: 'risk' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Test Risk',
            category: 'technical' as const,
            risk_level: 'medium' as const,
            probability,
            impact_description: 'Test impact description',
            status: 'active' as const
          }
        };

        const result = RiskSchema.safeParse(risk);
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.data.probability).toBe(probability);
        }
      });

      // Test invalid probability
      const invalidRisk = {
        kind: 'risk' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Test Risk',
          category: 'technical' as const,
          risk_level: 'medium' as const,
          probability: 'rarely' as any,
          impact_description: 'Test impact description',
          status: 'active' as const
        }
      };

      const result = RiskSchema.safeParse(invalidRisk);
      expect(result.success).toBe(false);
    });

    it('should enforce valid status values', () => {
      const validStatuses = ['active', 'mitigated', 'accepted', 'closed'] as const;

      validStatuses.forEach((status) => {
        const risk = {
          kind: 'risk' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Test Risk',
            category: 'technical' as const,
            risk_level: 'medium' as const,
            probability: 'possible' as const,
            impact_description: 'Test impact description',
            status
          }
        };

        const result = RiskSchema.safeParse(risk);
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.data.status).toBe(status);
        }
      });

      // Test invalid status
      const invalidRisk = {
        kind: 'risk' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Test Risk',
          category: 'technical' as const,
          risk_level: 'medium' as const,
          probability: 'possible' as const,
          impact_description: 'Test impact description',
          status: 'investigating' as any
        }
      };

      const result = RiskSchema.safeParse(invalidRisk);
      expect(result.success).toBe(false);
    });

    it('should enforce title length constraints', () => {
      const risk = {
        kind: 'risk' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'x'.repeat(501), // Exceeds 500 character limit
          category: 'technical' as const,
          risk_level: 'medium' as const,
          probability: 'possible' as const,
          impact_description: 'Test impact description',
          status: 'active' as const
        }
      };

      const result = RiskSchema.safeParse(risk);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('500 characters or less');
      }
    });

    it('should validate datetime format for review_date', () => {
      const risk = {
        kind: 'risk' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Test Risk',
          category: 'technical' as const,
          risk_level: 'medium' as const,
          probability: 'possible' as const,
          impact_description: 'Test impact description',
          status: 'active' as const,
          review_date: '2025-02-15T14:30:00Z'
        }
      };

      const result = RiskSchema.safeParse(risk);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.review_date).toBe('2025-02-15T14:30:00Z');
      }
    });

    it('should reject invalid datetime format for review_date', () => {
      const risk = {
        kind: 'risk' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Test Risk',
          category: 'technical' as const,
          risk_level: 'medium' as const,
          probability: 'possible' as const,
          impact_description: 'Test impact description',
          status: 'active' as const,
          review_date: 'invalid-date-format'
        }
      };

      const result = RiskSchema.safeParse(risk);
      expect(result.success).toBe(false);
    });

    it('should validate array fields with proper content', () => {
      const risk = {
        kind: 'risk' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Test Risk',
          category: 'technical' as const,
          risk_level: 'medium' as const,
          probability: 'possible' as const,
          impact_description: 'Test impact description',
          status: 'active' as const,
          trigger_events: ['Event 1', 'Event 2', 'Event 3'],
          mitigation_strategies: ['Strategy 1', 'Strategy 2'],
          related_decisions: ['550e8400-e29b-41d4-a716-446655440001', '550e8400-e29b-41d4-a716-446655440002'],
          monitoring_indicators: ['Indicator 1', 'Indicator 2', 'Indicator 3']
        }
      };

      const result = RiskSchema.safeParse(risk);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.trigger_events).toHaveLength(3);
        expect(result.data.data.mitigation_strategies).toHaveLength(2);
        expect(result.data.data.related_decisions).toHaveLength(2);
        expect(result.data.data.monitoring_indicators).toHaveLength(3);
      }
    });

    it('should handle empty arrays for optional array fields', () => {
      const risk = {
        kind: 'risk' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Test Risk',
          category: 'technical' as const,
          risk_level: 'medium' as const,
          probability: 'possible' as const,
          impact_description: 'Test impact description',
          status: 'active' as const,
          trigger_events: [],
          mitigation_strategies: [],
          related_decisions: [],
          monitoring_indicators: []
        }
      };

      const result = RiskSchema.safeParse(risk);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.trigger_events).toEqual([]);
        expect(result.data.data.mitigation_strategies).toEqual([]);
        expect(result.data.data.related_decisions).toEqual([]);
        expect(result.data.data.monitoring_indicators).toEqual([]);
      }
    });
  });

  describe('Risk Storage Operations', () => {
    it('should store critical security risk successfully', async () => {
      const risk = {
        kind: 'risk' as const,
        scope: {
          project: 'test-project',
          branch: 'main'
        },
        data: {
          title: 'Database encryption keys may be exposed',
          category: 'security' as const,
          risk_level: 'critical' as const,
          probability: 'unlikely' as const,
          impact_description: 'Exposure of database encryption keys would compromise all stored data, including user credentials and sensitive business information.',
          status: 'active' as const,
          owner: 'database-administrator',
          mitigation_strategies: [
            'Implement key rotation policy',
            'Use hardware security modules (HSM)',
            'Restrict key access to minimum personnel'
          ]
        }
      };

      const result = await db.storeItems([risk]);

      expect(result.stored).toHaveLength(1);
      expect(result.errors).toHaveLength(0);
      expect(result.stored[0]).toHaveProperty('id');
      expect(result.stored[0].kind).toBe('risk');
      expect(result.stored[0].data.title).toBe('Database encryption keys may be exposed');
      expect(result.stored[0].data.risk_level).toBe('critical');
      expect(result.stored[0].data.category).toBe('security');
      expect(result.stored[0].data.owner).toBe('database-administrator');

      // Verify Qdrant client was called
      expect(mockQdrant.upsert).toHaveBeenCalled();
    });

    it('should handle batch risk storage with different categories and levels', async () => {
      const risks = [
        {
          kind: 'risk' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Third-party service dependency may fail',
            category: 'operational' as const,
            risk_level: 'high' as const,
            probability: 'likely' as const,
            impact_description: 'Payment processing service failure could prevent revenue generation',
            status: 'active' as const,
            owner: 'operations-team',
            mitigation_strategies: ['Implement backup payment provider', 'Add circuit breakers']
          }
        },
        {
          kind: 'risk' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'GDPR compliance requirements may not be met',
            category: 'compliance' as const,
            risk_level: 'high' as const,
            probability: 'possible' as const,
            impact_description: 'Non-compliance could result in fines up to 4% of global revenue',
            status: 'active' as const,
            owner: 'legal-team',
            review_date: '2025-03-01T00:00:00Z'
          }
        },
        {
          kind: 'risk' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Market adoption may be lower than projected',
            category: 'business' as const,
            risk_level: 'medium' as const,
            probability: 'possible' as const,
            impact_description: 'Lower adoption could impact revenue projections by 30%',
            status: 'accepted' as const,
            owner: 'product-manager'
          }
        },
        {
          kind: 'risk' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'API documentation may be outdated',
            category: 'technical' as const,
            risk_level: 'low' as const,
            probability: 'very_likely' as const,
            impact_description: 'Developers may experience integration issues',
            status: 'mitigated' as const,
            mitigation_strategies: ['Implement automated documentation updates']
          }
        }
      ];

      const result = await db.storeItems(risks);

      expect(result.stored).toHaveLength(4);
      expect(result.errors).toHaveLength(0);
      expect(mockQdrant.upsert).toHaveBeenCalledTimes(4);

      const storedCalls = mockQdrant.upsert.mock.calls;
      expect(storedCalls[0][0][0].payload.data.category).toBe('operational');
      expect(storedCalls[0][0][0].payload.data.risk_level).toBe('high');
      expect(storedCalls[1][0][0].payload.data.category).toBe('compliance');
      expect(storedCalls[2][0][0].payload.data.category).toBe('business');
      expect(storedCalls[2][0][0].payload.data.status).toBe('accepted');
      expect(storedCalls[3][0][0].payload.data.risk_level).toBe('low');
    });

    it('should handle invalid risks in batch', async () => {
      const items = [
        {
          kind: 'risk' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Valid Risk',
            category: 'technical' as const,
            risk_level: 'medium' as const,
            probability: 'possible' as const,
            impact_description: 'Valid impact description',
            status: 'active' as const
          }
        },
        {
          kind: 'risk' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            // Missing title
            category: 'technical' as const,
            risk_level: 'medium' as const,
            probability: 'possible' as const,
            impact_description: 'Invalid impact description',
            status: 'active' as const
          }
        },
        {
          kind: 'risk' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Another Valid Risk',
            category: 'security' as const,
            risk_level: 'critical' as const,
            probability: 'unlikely' as const,
            impact_description: 'Another valid impact description',
            status: 'active' as const,
            owner: 'security-team'
          }
        }
      ];

      const result = await db.storeItems(items);

      expect(result.stored).toHaveLength(2); // 2 valid risks
      expect(result.errors).toHaveLength(1); // 1 invalid risk
    });

    it('should store risk with comprehensive contingency plans', async () => {
      const risk = {
        kind: 'risk' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Data center may experience extended outage',
          category: 'operational' as const,
          risk_level: 'high' as const,
          probability: 'unlikely' as const,
          impact_description: 'Extended data center outage could result in complete service unavailability and data loss if backup systems fail.',
          status: 'active' as const,
          owner: 'infrastructure-team',
          mitigation_strategies: [
            'Implement multi-region redundancy',
            'Regular disaster recovery testing',
            'Automated failover systems'
          ],
          monitoring_indicators: [
            'Data center power status',
            'Network connectivity metrics',
            'Backup system health checks'
          ],
          contingency_plans: '1. Activate disaster recovery site within 30 minutes\n2. Notify all stakeholders via emergency communication channels\n3. Engage third-party disaster recovery services\n4. Implement manual workarounds for critical business functions\n5. Provide regular status updates to customers and executives'
        }
      };

      const result = await db.storeItems([risk]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].data.contingency_plans).toContain('disaster recovery');
      expect(result.stored[0].data.monitoring_indicators).toHaveLength(3);
    });
  });

  describe('Risk Search Operations', () => {
    beforeEach(() => {
      // Setup search mock for risks
      mockQdrant.search.mockResolvedValue([
        {
          id: 'risk-id-1',
          score: 0.95,
          payload: {
            kind: 'risk',
            data: {
              title: 'Critical security vulnerability in authentication system',
              category: 'security',
              risk_level: 'critical',
              probability: 'very_likely',
              impact_description: 'Authentication bypass could allow unauthorized access',
              status: 'active',
              owner: 'security-team'
            },
            scope: { project: 'test-project', branch: 'main' }
          }
        },
        {
          id: 'risk-id-2',
          score: 0.85,
          payload: {
            kind: 'risk',
            data: {
              title: 'Database performance degradation under load',
              category: 'technical',
              risk_level: 'high',
              probability: 'likely',
              impact_description: 'System may become unresponsive during peak usage',
              status: 'mitigated',
              owner: 'database-administrator'
            },
            scope: { project: 'test-project', branch: 'main' }
          }
        }
      ]);
    });

    it('should find risks by security query', async () => {
      const query = 'security authentication vulnerability breach';

      const result = await db.searchItems(query);

      expect(result.items).toHaveLength(2);
      expect(result.items[0].data.title).toContain('security vulnerability');
      expect(result.items[0].data.category).toBe('security');
      expect(result.items[0].data.risk_level).toBe('critical');
      expect(result.items[0].data.status).toBe('active');
      expect(mockQdrant.search).toHaveBeenCalled();
    });

    it('should find risks by owner', async () => {
      const query = 'database administrator performance load';

      const result = await db.searchItems(query);

      expect(result.items).toHaveLength(2);
      expect(result.items[1].data.owner).toBe('database-administrator');
      expect(result.items[1].data.title).toContain('performance degradation');
      expect(result.items[1].data.status).toBe('mitigated');
    });

    it('should find risks by risk level', async () => {
      const query = 'critical high risk security vulnerability';

      const result = await db.searchItems(query);

      expect(result.items).toHaveLength(2);
      expect(result.items[0].data.risk_level).toBe('critical');
      expect(result.items[1].data.risk_level).toBe('high');
    });

    it('should handle empty risk search results', async () => {
      mockQdrant.search.mockResolvedValue([]);

      const result = await db.searchItems('nonexistent risk topic');

      expect(result.items).toHaveLength(0);
      expect(result.total).toBe(0);
    });

    it('should find risks by probability and impact', async () => {
      const query = 'very likely impact unauthorized access performance';

      const result = await db.searchItems(query);

      expect(result.items).toHaveLength(2);
      expect(result.items[0].data.probability).toBe('very_likely');
      expect(result.items[1].data.probability).toBe('likely');
    });
  });

  describe('Risk Scope Isolation', () => {
    it('should isolate risks by project scope', async () => {
      const risks = [
        {
          kind: 'risk' as const,
          scope: { project: 'frontend-app', branch: 'main' },
          data: {
            title: 'React library compatibility issues',
            category: 'technical' as const,
            risk_level: 'medium' as const,
            probability: 'possible' as const,
            impact_description: 'Frontend may break after React upgrade',
            status: 'active' as const,
            owner: 'frontend-team'
          }
        },
        {
          kind: 'risk' as const,
          scope: { project: 'backend-api', branch: 'main' },
          data: {
            title: 'API rate limiting configuration errors',
            category: 'operational' as const,
            risk_level: 'high' as const,
            probability: 'likely' as const,
            impact_description: 'API could be overwhelmed by requests',
            status: 'active' as const,
            owner: 'backend-team'
          }
        }
      ];

      const results = await Promise.all(
        risks.map(risk => db.storeItems([risk]))
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
      const risks = [
        {
          kind: 'risk' as const,
          scope: { project: 'monorepo', branch: 'main' },
          data: {
            title: 'Production deployment failures',
            category: 'operational' as const,
            risk_level: 'high' as const,
            probability: 'unlikely' as const,
            impact_description: 'Production deployment process may fail',
            status: 'mitigated' as const,
            owner: 'devops-team'
          }
        },
        {
          kind: 'risk' as const,
          scope: { project: 'monorepo', branch: 'develop' },
          data: {
            title: 'Development environment instability',
            category: 'technical' as const,
            risk_level: 'medium' as const,
            probability: 'possible' as const,
            impact_description: 'Development environment may be unreliable',
            status: 'active' as const,
            owner: 'platform-team'
          }
        }
      ];

      await Promise.all(
        risks.map(risk => db.storeItems([risk]))
      );

      const storedCalls = mockQdrant.upsert.mock.calls;
      expect(storedCalls[0][0][0].payload.scope.branch).toBe('main');
      expect(storedCalls[1][0][0].payload.scope.branch).toBe('develop');
    });
  });

  describe('Risk Edge Cases and Error Handling', () => {
    it('should handle risk storage errors gracefully', async () => {
      const risk = {
        kind: 'risk' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Test Risk',
          category: 'technical' as const,
          risk_level: 'medium' as const,
          probability: 'possible' as const,
          impact_description: 'Test impact description',
          status: 'active' as const
        }
      };

      // Mock upsert to throw an error
      mockQdrant.upsert.mockRejectedValue(new Error('Database connection failed'));

      const result = await db.storeItems([risk]);

      expect(result.stored).toHaveLength(0);
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0].error).toContain('Database connection failed');
    });

    it('should handle risk with special characters in title and description', async () => {
      const risk = {
        kind: 'risk' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: '🚨 Critical: API endpoint /api/v2/users/{id} returns 500 error with SQL injection vulnerability (CVE-2025-1234)',
          category: 'security' as const,
          risk_level: 'critical' as const,
          probability: 'very_likely' as const,
          impact_description: 'The API endpoint is vulnerable to SQL injection attacks when user ID contains special characters like @, #, $, %. This could allow attackers to dump the entire database and access sensitive user information including passwords and payment data.',
          status: 'active' as const,
          owner: 'security-incident-response-team'
        }
      };

      const result = await db.storeItems([risk]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].data.title).toContain('🚨');
      expect(result.stored[0].data.title).toContain('SQL injection');
      expect(result.stored[0].data.description).toContain('attackers');
    });

    it('should handle risk with long impact description within limits', async () => {
      const longImpactDescription = 'This risk represents a significant threat to our business operations and could result in substantial financial losses, regulatory penalties, reputational damage, customer churn, legal liabilities, operational disruptions, competitive disadvantages, and strategic setbacks. '.repeat(5);

      const risk = {
        kind: 'risk' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Comprehensive business risk assessment',
          category: 'business' as const,
          risk_level: 'high' as const,
          probability: 'possible' as const,
          impact_description: longImpactDescription,
          status: 'active' as const,
          owner: 'risk-management-committee'
        }
      };

      const result = await db.storeItems([risk]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].data.impact_description).toBe(longImpactDescription);
    });

    it('should handle risk with multiple monitoring indicators', async () => {
      const risk = {
        kind: 'risk' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'System performance degradation',
          category: 'technical' as const,
          risk_level: 'medium' as const,
          probability: 'likely' as const,
          impact_description: 'System performance may degrade under load',
          status: 'active' as const,
          owner: 'sre-team',
          monitoring_indicators: [
            'CPU utilization > 80% for more than 5 minutes',
            'Memory usage > 90% causing swapping',
            'Database connection pool exhaustion',
            'API response time p95 > 2 seconds',
            'Error rate > 1% over 10 minute window',
            'Disk I/O wait time > 20ms',
            'Network latency > 100ms between services'
          ]
        }
      };

      const result = await db.storeItems([risk]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].data.monitoring_indicators).toHaveLength(7);
    });

    it('should handle risk with multiple related decisions', async () => {
      const risk = {
        kind: 'risk' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Technology stack migration risks',
          category: 'technical' as const,
          risk_level: 'high' as const,
          probability: 'possible' as const,
          impact_description: 'Migration to new technology stack may introduce bugs and performance issues',
          status: 'active' as const,
          owner: 'architecture-team',
          related_decisions: [
            '550e8400-e29b-41d4-a716-446655440001',
            '550e8400-e29b-41d4-a716-446655440002',
            '550e8400-e29b-41d4-a716-446655440003',
            '550e8400-e29b-41d4-a716-446655440004'
          ]
        }
      };

      const result = await db.storeItems([risk]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].data.related_decisions).toHaveLength(4);
    });

    it('should handle risk acceptance with justification', () => {
      const risk = {
        kind: 'risk' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Minor UI inconsistencies in legacy components',
          category: 'technical' as const,
          risk_level: 'low' as const,
          probability: 'very_likely' as const,
          impact_description: 'Some legacy components have minor UI inconsistencies that do not affect functionality',
          status: 'accepted' as const,
          owner: 'product-manager',
          mitigation_strategies: ['Accept as-is due to low priority', 'Address during future redesign']
        }
      };

      const result = RiskSchema.safeParse(risk);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.status).toBe('accepted');
        expect(result.data.data.risk_level).toBe('low');
      }
    });

    it('should handle risk with complex trigger events', async () => {
      const risk = {
        kind: 'risk' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Supply chain disruptions',
          category: 'operational' as const,
          risk_level: 'medium' as const,
          probability: 'possible' as const,
          impact_description: 'Supply chain disruptions could delay product delivery and increase costs',
          status: 'active' as const,
          owner: 'operations-team',
          trigger_events: [
            'Natural disasters affecting key suppliers',
            'Geopolitical tensions causing trade restrictions',
            'Transportation strikes or labor disputes',
            'Raw material shortages or price spikes',
            'Customs and regulatory changes',
            'Supplier bankruptcy or financial distress'
          ]
        }
      };

      const result = await db.storeItems([risk]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].data.trigger_events).toHaveLength(6);
    });

    it('should handle risk with probability and impact quantification', () => {
      const risk = {
        kind: 'risk' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Customer data breach due to insufficient encryption',
          category: 'security' as const,
          risk_level: 'critical' as const,
          probability: 'unlikely' as const,
          impact_description: 'Data breach could affect up to 10 million customers, resulting in estimated costs of $50M including fines, legal fees, and customer compensation. Regulatory penalties could be up to $25M under GDPR and CCPA.',
          status: 'active' as const,
          owner: 'ciso',
          review_date: '2025-03-15T00:00:00Z'
        }
      };

      const result = RiskSchema.safeParse(risk);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.impact_description).toContain('$50M');
        expect(result.data.data.impact_description).toContain('10 million customers');
      }
    });
  });

  describe('Risk Integration with Knowledge System', () => {
    it('should integrate with knowledge item validation', () => {
      const risk = {
        kind: 'risk' as const,
        scope: {
          project: 'test-project',
          branch: 'main'
        },
        data: {
          title: 'Cloud provider service level agreement violations',
          category: 'operational' as const,
          risk_level: 'high' as const,
          probability: 'unlikely' as const,
          impact_description: 'Cloud provider SLA violations could result in service unavailability and financial credits that may not cover business losses',
          status: 'active' as const,
          owner: 'infrastructure-team',
          mitigation_strategies: [
            'Multi-cloud strategy for redundancy',
            'Service credits negotiation',
            'Local failover infrastructure'
          ]
        },
        tags: { cloud: true, sla: true, 'high-availability': true },
        source: {
          actor: 'risk-assessment-tool',
          tool: 'enterprise-risk-manager',
          timestamp: '2025-01-18T14:20:00Z'
        },
        ttl_policy: '90d' as const
      };

      const result = validateKnowledgeItem(risk);
      expect(result.kind).toBe('risk');
      expect(result.data.title).toBe('Cloud provider service level agreement violations');
      expect(result.data.category).toBe('operational');
      expect(result.tags.cloud).toBe(true);
      expect(result.source.actor).toBe('risk-assessment-tool');
      expect(result.ttl_policy).toBe('90d');
    });

    it('should handle risk with comprehensive metadata', () => {
      const risk = {
        kind: 'risk' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Artificial intelligence model bias and fairness issues',
          category: 'technical' as const,
          risk_level: 'medium' as const,
          probability: 'possible' as const,
          impact_description: 'AI models may exhibit bias leading to unfair outcomes and potential regulatory compliance issues',
          status: 'active' as const,
          owner: 'ai-ethics-committee',
          mitigation_strategies: [
            'Implement bias detection and monitoring',
            'Diverse training data collection',
            'Regular model audits and reviews',
            'Transparency in AI decision-making'
          ],
          monitoring_indicators: [
            'Model performance across demographic groups',
            'User feedback on AI fairness',
            'Regulatory compliance metrics',
            'Bias detection system alerts'
          ]
        },
        tags: {
          'ai': true,
          'bias': true,
          'fairness': true,
          'ml': true,
          'ethics': true,
          'compliance': true
        },
        metadata: {
          risk_score: 6.5,
          financial_exposure: '$250K',
          regulatory_impact: 'high',
          stakeholder_concern: 'medium',
          first_identified: '2025-01-10T00:00:00Z',
          last_reviewed: '2025-01-25T00:00:00Z',
          next_review: '2025-02-25T00:00:00Z',
          external_references: ['AI Ethics Guidelines v2.0', 'EU AI Act Requirements'],
          risk_owner_department: 'Data Science',
          escalation_level: 2
        }
      };

      const result = RiskSchema.safeParse(risk);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.title).toContain('bias');
        expect(result.data.tags.ai).toBe(true);
        expect(result.data.tags.ethics).toBe(true);
      }
    });

    it('should support TTL policy for risks', async () => {
      const risk = {
        kind: 'risk' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Temporary API endpoint deprecation risk',
          category: 'technical' as const,
          risk_level: 'low' as const,
          probability: 'very_likely' as const,
          impact_description: 'Temporary API endpoints will be deprecated next quarter',
          status: 'active' as const,
          owner: 'api-team',
          review_date: '2025-04-01T00:00:00Z'
        },
        ttl_policy: '30d' as const
      };

      const result = await db.storeItems([risk]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].ttl_policy).toBe('30d');
    });

    it('should handle risk with idempotency key', async () => {
      const risk = {
        kind: 'risk' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Container security vulnerabilities',
          category: 'security' as const,
          risk_level: 'high' as const,
          probability: 'possible' as const,
          impact_description: 'Container images may contain security vulnerabilities',
          status: 'active' as const,
          owner: 'devsecops-team'
        },
        idempotency_key: 'risk-container-security-v1'
      };

      const result = await db.storeItems([risk]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].idempotency_key).toBe('risk-container-security-v1');
    });

    it('should handle risk closure with lessons learned', async () => {
      const risk = {
        kind: 'risk' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Legacy system single point of failure',
          category: 'technical' as const,
          risk_level: 'critical' as const,
          probability: 'unlikely' as const,
          impact_description: 'Legacy system failure could cause complete service outage',
          status: 'closed' as const,
          owner: 'infrastructure-team',
          mitigation_strategies: [
            'Implemented redundant failover systems',
            'Migrated to modern architecture',
            'Established 24/7 monitoring'
          ],
          contingency_plans: 'Risk successfully mitigated through system modernization and redundancy implementation. Lessons learned: prioritize technical debt reduction, invest in monitoring, and establish clear migration timelines.',
          review_date: '2025-01-30T00:00:00Z'
        }
      };

      const result = await db.storeItems([risk]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].data.status).toBe('closed');
      expect(result.stored[0].data.contingency_plans).toContain('successfully mitigated');
    });
  });
});