/**
 * Comprehensive Unit Tests for Incident Knowledge Type
 *
 * Tests incident knowledge type functionality including:
 * - Incident validation with all required fields
 * - Severity and status validation
 * - Timeline and impact assessment
 * - Root cause analysis handling
 * - Incident commander and recovery actions
 * - Scope isolation for incidents
 * - Error handling and edge cases
 * - Integration with incident management workflows
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { VectorDatabase } from '../../../src/index';
import { IncidentSchema, validateKnowledgeItem } from '../../../src/schemas/knowledge-types';

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

describe('Incident Knowledge Type - Comprehensive Testing', () => {
  let db: VectorDatabase;
  let mockQdrant: any;

  beforeEach(() => {
    db = new VectorDatabase();
    mockQdrant = (db as any).client;
  });

  describe('Incident Schema Validation', () => {
    it('should validate complete incident with all fields', () => {
      const incident = {
        kind: 'incident' as const,
        scope: {
          project: 'test-project',
          branch: 'main'
        },
        data: {
          id: '550e8400-e29b-41d4-a716-446655440000',
          title: 'Database connectivity failure in production',
          severity: 'critical' as const,
          impact: 'Complete service outage affecting all users, no data access possible',
          timeline: [
            {
              timestamp: '2025-01-01T10:00:00Z',
              event: 'Database connection failures detected',
              actor: 'monitoring-system'
            },
            {
              timestamp: '2025-01-01T10:05:00Z',
              event: 'Incident declared, incident commander assigned',
              actor: 'on-call-engineer'
            },
            {
              timestamp: '2025-01-01T10:15:00Z',
              event: 'Root cause identified: connection pool exhaustion',
              actor: 'senior-engineer'
            }
          ],
          root_cause_analysis: 'Connection pool exhaustion due to memory leak in database driver. The driver was not properly releasing connections under high load, causing gradual depletion of available connections.',
          resolution_status: 'resolved' as const,
          affected_services: ['user-service', 'order-service', 'payment-service'],
          business_impact: 'Estimated $50,000 revenue loss per hour during outage',
          recovery_actions: [
            'Restarted database connection pool',
            'Applied hotfix to connection management code',
            'Increased monitoring alerts for connection pool metrics'
          ],
          follow_up_required: true,
          incident_commander: 'jane.doe@company.com'
        },
        tags: { severity: 'critical', outage: true, database: true },
        source: {
          actor: 'incident-response-team',
          tool: 'incident-management-system',
          timestamp: '2025-01-01T11:30:00Z'
        }
      };

      const result = IncidentSchema.safeParse(incident);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.kind).toBe('incident');
        expect(result.data.data.title).toBe('Database connectivity failure in production');
        expect(result.data.data.severity).toBe('critical');
        expect(result.data.data.resolution_status).toBe('resolved');
        expect(result.data.data.timeline).toHaveLength(3);
        expect(result.data.data.affected_services).toHaveLength(3);
        expect(result.data.data.recovery_actions).toHaveLength(3);
      }
    });

    it('should validate minimal incident with only required fields', () => {
      const incident = {
        kind: 'incident' as const,
        scope: {
          project: 'test-project',
          branch: 'main'
        },
        data: {
          title: 'Minor performance degradation',
          severity: 'low' as const,
          impact: 'Users experiencing slightly slower response times',
          resolution_status: 'open' as const
        }
      };

      const result = IncidentSchema.safeParse(incident);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.title).toBe('Minor performance degradation');
        expect(result.data.data.severity).toBe('low');
        expect(result.data.data.impact).toBe('Users experiencing slightly slower response times');
        expect(result.data.data.resolution_status).toBe('open');
        expect(result.data.data.timeline).toBeUndefined();
        expect(result.data.data.root_cause_analysis).toBeUndefined();
        expect(result.data.data.affected_services).toBeUndefined();
      }
    });

    it('should reject incident missing required fields', () => {
      const invalidIncidents = [
        {
          kind: 'incident' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            // Missing title
            severity: 'high',
            impact: 'Test impact',
            resolution_status: 'open'
          }
        },
        {
          kind: 'incident' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Test incident',
            // Missing severity
            impact: 'Test impact',
            resolution_status: 'open'
          }
        },
        {
          kind: 'incident' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Test incident',
            severity: 'medium',
            // Missing impact
            resolution_status: 'investigating'
          }
        },
        {
          kind: 'incident' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Test incident',
            severity: 'low',
            impact: 'Test impact'
            // Missing resolution_status
          }
        }
      ];

      invalidIncidents.forEach((incident, index) => {
        const result = IncidentSchema.safeParse(incident);
        expect(result.success).toBe(false);
        if (!result.success) {
          expect(result.error.issues.length).toBeGreaterThan(0);
        }
      });
    });

    it('should enforce valid severity values', () => {
      const incident = {
        kind: 'incident' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Test incident',
          severity: 'urgent' as any, // Invalid severity
          impact: 'Test impact',
          resolution_status: 'open'
        }
      };

      const result = IncidentSchema.safeParse(incident);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('Invalid enum value');
      }
    });

    it('should enforce valid resolution_status values', () => {
      const incident = {
        kind: 'incident' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Test incident',
          severity: 'high',
          impact: 'Test impact',
          resolution_status: 'fixed' as any // Invalid status
        }
      };

      const result = IncidentSchema.safeParse(incident);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('Invalid enum value');
      }
    });

    it('should enforce title length constraints', () => {
      const incident = {
        kind: 'incident' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'x'.repeat(501), // Exceeds 500 character limit
          severity: 'medium',
          impact: 'Test impact',
          resolution_status: 'open'
        }
      };

      const result = IncidentSchema.safeParse(incident);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('500 characters or less');
      }
    });

    it('should validate timeline entry structure', () => {
      const incident = {
        kind: 'incident' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Test incident',
          severity: 'high',
          impact: 'Test impact',
          resolution_status: 'investigating',
          timeline: [
            {
              timestamp: '2025-01-01T10:00:00Z',
              event: 'Incident detected',
              actor: 'monitoring'
            },
            {
              // Missing required timestamp
              event: 'Invalid timeline entry',
              actor: 'system'
            }
          ]
        }
      };

      const result = IncidentSchema.safeParse(incident);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues.some(issue =>
          issue.path.includes('timestamp')
        )).toBe(true);
      }
    });

    it('should validate timeline datetime format', () => {
      const incident = {
        kind: 'incident' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Test incident',
          severity: 'medium',
          impact: 'Test impact',
          resolution_status: 'open',
          timeline: [
            {
              timestamp: 'invalid-datetime', // Invalid datetime format
              event: 'Test event',
              actor: 'test'
            }
          ]
        }
      };

      const result = IncidentSchema.safeParse(incident);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('datetime');
      }
    });
  });

  describe('Incident Storage Operations', () => {
    it('should store incident successfully using memory_store pattern', async () => {
      const incident = {
        kind: 'incident' as const,
        scope: {
          project: 'test-project',
          branch: 'main'
        },
        data: {
          title: 'API gateway timeout errors',
          severity: 'high',
          impact: 'Users unable to complete transactions',
          resolution_status: 'investigating',
          affected_services: ['api-gateway', 'payment-service']
        },
        content: 'Incident: API gateway timeout errors affecting payment processing' // Required for embedding generation
      };

      const result = await db.storeItems([incident]);

      expect(result.stored).toHaveLength(1);
      expect(result.errors).toHaveLength(0);
      expect(result.stored[0]).toHaveProperty('id');
      expect(result.stored[0].kind).toBe('incident');
      expect(result.stored[0].data.title).toBe('API gateway timeout errors');
      expect(result.stored[0].data.severity).toBe('high');
      expect(result.stored[0].data.affected_services).toHaveLength(2);

      // Verify Qdrant client was called
      expect(mockQdrant.upsert).toHaveBeenCalled();
    });

    it('should handle batch incident storage with different severities', async () => {
      const incidents = [
        {
          kind: 'incident' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Critical database outage',
            severity: 'critical' as const,
            impact: 'Complete service failure',
            resolution_status: 'open'
          },
          content: 'Critical incident: database outage'
        },
        {
          kind: 'incident' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Minor UI glitch',
            severity: 'low' as const,
            impact: 'Cosmetic issue on dashboard',
            resolution_status: 'resolved'
          },
          content: 'Low severity incident: UI glitch'
        },
        {
          kind: 'incident' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Performance degradation',
            severity: 'medium' as const,
            impact: 'Slower response times',
            resolution_status: 'investigating'
          },
          content: 'Medium severity incident: performance issues'
        }
      ];

      const result = await db.storeItems(incidents);

      expect(result.stored).toHaveLength(3);
      expect(result.errors).toHaveLength(0);
      expect(mockQdrant.upsert).toHaveBeenCalledTimes(3);

      const storedCalls = mockQdrant.upsert.mock.calls;
      expect(storedCalls[0][0][0].payload.data.severity).toBe('critical');
      expect(storedCalls[1][0][0].payload.data.severity).toBe('low');
      expect(storedCalls[2][0][0].payload.data.severity).toBe('medium');
    });

    it('should handle mixed valid and invalid incidents in batch', async () => {
      const items = [
        {
          kind: 'incident' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Valid incident',
            severity: 'high',
            impact: 'Valid impact description',
            resolution_status: 'open'
          },
          content: 'Valid incident content'
        },
        {
          kind: 'incident' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            // Missing title
            severity: 'medium',
            impact: 'Invalid incident',
            resolution_status: 'investigating'
          },
          content: 'Invalid incident content'
        },
        {
          kind: 'incident' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Another valid incident',
            severity: 'low',
            impact: 'Another valid impact',
            resolution_status: 'resolved'
          },
          content: 'Another valid incident content'
        }
      ];

      const result = await db.storeItems(items);

      expect(result.stored).toHaveLength(2); // 2 valid incidents
      expect(result.errors).toHaveLength(1); // 1 invalid incident
    });
  });

  describe('Incident Search Operations', () => {
    beforeEach(() => {
      // Setup search mock for incidents
      mockQdrant.search.mockResolvedValue([
        {
          id: 'incident-id-1',
          score: 0.95,
          payload: {
            kind: 'incident',
            data: {
              title: 'Database connectivity failure',
              severity: 'critical',
              impact: 'Complete service outage',
              resolution_status: 'resolved',
              affected_services: ['user-service', 'order-service']
            },
            scope: { project: 'test-project', branch: 'main' }
          }
        },
        {
          id: 'incident-id-2',
          score: 0.85,
          payload: {
            kind: 'incident',
            data: {
              title: 'API rate limiting issues',
              severity: 'medium',
              impact: 'Some users experiencing throttling',
              resolution_status: 'investigating',
              affected_services: ['api-gateway']
            },
            scope: { project: 'test-project', branch: 'main' }
          }
        }
      ]);
    });

    it('should find incidents by database query', async () => {
      const query = 'database connectivity failure outage';

      const result = await db.searchItems(query);

      expect(result.items).toHaveLength(2);
      expect(result.items[0].data.title).toContain('Database connectivity failure');
      expect(result.items[0].data.severity).toBe('critical');
      expect(result.items[0].data.resolution_status).toBe('resolved');
      expect(result.items[0].data.affected_services).toHaveLength(2);
      expect(mockQdrant.search).toHaveBeenCalled();
    });

    it('should handle empty incident search results', async () => {
      mockQdrant.search.mockResolvedValue([]);

      const result = await db.searchItems('nonexistent incident type');

      expect(result.items).toHaveLength(0);
      expect(result.total).toBe(0);
    });

    it('should find incidents by affected service', async () => {
      const query = 'api-gateway rate limiting';

      const result = await db.searchItems(query);

      expect(result.items).toHaveLength(2);
      expect(result.items[1].data.affected_services).toContain('api-gateway');
      expect(result.items[1].data.severity).toBe('medium');
    });
  });

  describe('Incident Severity and Status Lifecycle', () => {
    it('should handle all valid severity levels', async () => {
      const severities: Array<'critical' | 'high' | 'medium' | 'low'> = [
        'critical', 'high', 'medium', 'low'
      ];

      const incidents = severities.map((severity, index) => ({
        kind: 'incident' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: `Incident with ${severity} severity`,
          severity,
          impact: `Impact for ${severity} severity incident`,
          resolution_status: 'open' as const
        },
        content: `Incident: ${severity} severity`
      }));

      const results = await Promise.all(
        incidents.map(incident => db.storeItems([incident]))
      );

      results.forEach((result, index) => {
        expect(result.stored).toHaveLength(1);
        expect(result.stored[0].data.severity).toBe(severities[index]);
      });

      expect(mockQdrant.upsert).toHaveBeenCalledTimes(4);
    });

    it('should handle all valid resolution statuses', async () => {
      const statuses: Array<'open' | 'investigating' | 'resolved' | 'closed'> = [
        'open', 'investigating', 'resolved', 'closed'
      ];

      const incidents = statuses.map((resolution_status, index) => ({
        kind: 'incident' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: `Incident with status ${resolution_status}`,
          severity: 'medium' as const,
          impact: 'Test impact',
          resolution_status
        },
        content: `Incident: status ${resolution_status}`
      }));

      const results = await Promise.all(
        incidents.map(incident => db.storeItems([incident]))
      );

      results.forEach((result, index) => {
        expect(result.stored).toHaveLength(1);
        expect(result.stored[0].data.resolution_status).toBe(statuses[index]);
      });

      expect(mockQdrant.upsert).toHaveBeenCalledTimes(4);
    });
  });

  describe('Incident Timeline and Recovery Actions', () => {
    it('should handle incidents with comprehensive timeline', async () => {
      const incidentWithTimeline = {
        kind: 'incident' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Complex incident with detailed timeline',
          severity: 'high',
          impact: 'Multi-system failure affecting core services',
          resolution_status: 'resolved',
          timeline: [
            {
              timestamp: '2025-01-01T08:00:00Z',
              event: 'Initial alerts triggered for high error rates',
              actor: 'monitoring-system'
            },
            {
              timestamp: '2025-01-01T08:05:00Z',
              event: 'On-call engineer acknowledges alert',
              actor: 'on-call-engineer'
            },
            {
              timestamp: '2025-01-01T08:15:00Z',
              event: 'Incident declared, war room activated',
              actor: 'incident-commander'
            },
            {
              timestamp: '2025-01-01T08:30:00Z',
              event: 'Root cause identified in authentication service',
              actor: 'senior-engineer'
            },
            {
              timestamp: '2025-01-01T09:00:00Z',
              event: 'Fix deployed and verified',
              actor: 'deployment-team'
            },
            {
              timestamp: '2025-01-01T09:15:00Z',
              event: 'Service restored to normal operation',
              actor: 'incident-commander'
            }
          ],
          root_cause_analysis: 'Authentication service memory leak causing cascade failures',
          recovery_actions: [
            'Restarted authentication service',
            'Applied memory leak patch',
            'Added additional monitoring',
            'Updated capacity planning'
          ]
        },
        content: 'Complex incident with detailed timeline and recovery actions'
      };

      const result = await db.storeItems([incidentWithTimeline]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].data.timeline).toHaveLength(6);
      expect(result.stored[0].data.recovery_actions).toHaveLength(4);
      expect(result.stored[0].data.root_cause_analysis).toContain('memory leak');
    });

    it('should handle incidents without timeline', async () => {
      const incidentWithoutTimeline = {
        kind: 'incident' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Simple incident without timeline',
          severity: 'low',
          impact: 'Minor issue with quick resolution',
          resolution_status: 'resolved'
        },
        content: 'Simple incident without timeline tracking'
      };

      const result = IncidentSchema.safeParse(incidentWithoutTimeline);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.timeline).toBeUndefined();
      }
    });

    it('should handle incidents with empty recovery actions array', () => {
      const incidentWithEmptyRecovery = {
        kind: 'incident' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Incident with no recovery actions yet',
          severity: 'medium',
          impact: 'Issue still being investigated',
          resolution_status: 'investigating',
          recovery_actions: [] // Empty array is valid
        }
      };

      const result = IncidentSchema.safeParse(incidentWithEmptyRecovery);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.recovery_actions).toEqual([]);
      }
    });
  });

  describe('Incident Scope Isolation', () => {
    it('should isolate incidents by project scope', async () => {
      const incidentProjectA = {
        kind: 'incident' as const,
        scope: {
          project: 'project-A',
          branch: 'main'
        },
        data: {
          title: 'Critical incident in Project A',
          severity: 'critical',
          impact: 'Project A services down',
          resolution_status: 'open'
        },
        content: 'Critical incident for Project A'
      };

      const incidentProjectB = {
        kind: 'incident' as const,
        scope: {
          project: 'project-B',
          branch: 'main'
        },
        data: {
          title: 'Minor incident in Project B',
          severity: 'low',
          impact: 'Project B has minor issues',
          resolution_status: 'resolved'
        },
        content: 'Minor incident for Project B'
      };

      // Store both incidents
      await db.storeItems([incidentProjectA, incidentProjectB]);

      // Verify both were stored
      expect(mockQdrant.upsert).toHaveBeenCalledTimes(2);
    });

    it('should handle incidents in different branches', async () => {
      const incidentMain = {
        kind: 'incident' as const,
        scope: {
          project: 'test-project',
          branch: 'main'
        },
        data: {
          title: 'Production incident',
          severity: 'high',
          impact: 'Production environment affected',
          resolution_status: 'investigating'
        },
        content: 'Production incident on main branch'
      };

      const incidentDev = {
        kind: 'incident' as const,
        scope: {
          project: 'test-project',
          branch: 'develop'
        },
        data: {
          title: 'Development environment issue',
          severity: 'low',
          impact: 'Dev environment problems',
          resolution_status: 'resolved'
        },
        content: 'Development incident on develop branch'
      };

      const results = await Promise.all([
        db.storeItems([incidentMain]),
        db.storeItems([incidentDev])
      ]);

      expect(results[0].stored[0].scope.branch).toBe('main');
      expect(results[1].stored[0].scope.branch).toBe('develop');
    });
  });

  describe('Incident Edge Cases and Error Handling', () => {
    it('should handle incident storage errors gracefully', async () => {
      const incident = {
        kind: 'incident' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Test incident',
          severity: 'medium',
          impact: 'Test impact',
          resolution_status: 'open'
        },
        content: 'Test incident content'
      };

      // Mock upsert to throw an error
      mockQdrant.upsert.mockRejectedValue(new Error('Database connection failed'));

      const result = await db.storeItems([incident]);

      expect(result.stored).toHaveLength(0);
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0].error).toContain('Database connection failed');
    });

    it('should handle incidents with special characters in title and impact', async () => {
      const incident = {
        kind: 'incident' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'HTTP 503 Service Unavailable: API Gateway Timeout (ERR_CONNECTION_TIMED_OUT)',
          severity: 'high',
          impact: 'Users cannot complete checkout process due to payment gateway SSL certificate expiration (SSL_CERT_HAS_EXPIRED)',
          resolution_status: 'investigating'
        },
        content: 'Incident with special characters and error codes'
      };

      const result = await db.storeItems([incident]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].data.title).toContain('503');
      expect(result.stored[0].data.impact).toContain('SSL');
    });

    it('should handle incidents with very long impact description', async () => {
      const longImpactText = 'x'.repeat(2000); // 2000 character impact description
      const incident = {
        kind: 'incident' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Incident with very long impact description',
          severity: 'medium',
          impact: longImpactText,
          resolution_status: 'open'
        },
        content: `Incident: ${longImpactText.substring(0, 50)}...`
      };

      const result = await db.storeItems([incident]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].data.impact).toHaveLength(2000);
    });

    it('should handle incidents with complex affected services array', async () => {
      const incident = {
        kind: 'incident' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Multi-service cascade failure',
          severity: 'critical',
          impact: 'Multiple interconnected services experiencing failures',
          resolution_status: 'investigating',
          affected_services: [
            'api-gateway',
            'user-service',
            'order-service',
            'payment-service',
            'notification-service',
            'inventory-service',
            'analytics-service'
          ]
        },
        content: 'Multi-service incident affecting many services'
      };

      const result = await db.storeItems([incident]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].data.affected_services).toHaveLength(7);
      expect(result.stored[0].data.affected_services).toContain('payment-service');
    });
  });

  describe('Incident Integration with Knowledge System', () => {
    it('should integrate with knowledge item validation', () => {
      const incident = {
        kind: 'incident' as const,
        scope: {
          project: 'test-project',
          branch: 'main'
        },
        data: {
          title: 'Security incident: unauthorized access attempt',
          severity: 'high',
          impact: 'Potential data breach detected',
          resolution_status: 'investigating',
          incident_commander: 'security-team-lead@company.com',
          follow_up_required: true
        },
        tags: { security: true, high_severity: true, investigation: true },
        source: {
          actor: 'security-operations-center',
          tool: 'security-monitoring',
          timestamp: '2025-01-01T00:00:00Z'
        },
        ttl_policy: 'extended' as const
      };

      const result = validateKnowledgeItem(incident);
      expect(result.kind).toBe('incident');
      expect(result.data.severity).toBe('high');
      expect(result.data.incident_commander).toBe('security-team-lead@company.com');
      expect(result.tags.security).toBe(true);
      expect(result.source.actor).toBe('security-operations-center');
      expect(result.ttl_policy).toBe('extended');
    });

    it('should handle TTL policy for incidents', async () => {
      const incident = {
        kind: 'incident' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Temporary service degradation',
          severity: 'low',
          impact: 'Minor performance issues during maintenance',
          resolution_status: 'resolved'
        },
        ttl_policy: 'short' as const,
        content: 'Temporary incident with short TTL'
      };

      const result = await db.storeItems([incident]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].ttl_policy).toBe('short');
    });

    it('should handle incident with comprehensive business impact analysis', async () => {
      const incidentWithBusinessImpact = {
        kind: 'incident' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'E-commerce platform checkout failure',
          severity: 'critical',
          impact: 'Users unable to complete purchases, complete revenue loss',
          business_impact: 'Estimated revenue loss: $25,000/hour. Customer trust impact: High. Potential churn rate increase: 15%. SLA breach penalties: $10,000.',
          resolution_status: 'resolved',
          recovery_actions: [
            'Fixed payment gateway integration',
            'Implemented circuit breaker pattern',
            'Added real-time monitoring for checkout flow',
            'Established backup payment provider'
          ],
          follow_up_required: true,
          incident_commander: 'ecommerce-ops-lead@company.com'
        },
        content: 'Critical e-commerce incident with comprehensive business impact analysis'
      };

      const result = await db.storeItems([incidentWithBusinessImpact]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].data.business_impact).toContain('revenue loss');
      expect(result.stored[0].data.business_impact).toContain('SLA breach');
      expect(result.stored[0].data.recovery_actions).toHaveLength(4);
      expect(result.stored[0].data.follow_up_required).toBe(true);
    });
  });
});