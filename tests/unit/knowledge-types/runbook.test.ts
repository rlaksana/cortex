/**
 * Comprehensive Unit Tests for Runbook Knowledge Type
 *
 * Tests runbook knowledge type functionality including:
 * - Runbook validation with all required fields
 * - Procedure steps validation and structure
 * - Service, title, and description constraints
 * - Triggers and verification timestamps
 * - Scope isolation by project and branch
 * - Error handling and edge cases
 * - Complex nested procedure steps
 * - Storage operations with Qdrant integration
 * - Search operations and content retrieval
 * - Integration with knowledge system validation
 * - TTL policy and metadata support
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { VectorDatabase } from '../../../src/index';
import { RunbookSchema, validateKnowledgeItem } from '../../../src/schemas/knowledge-types';

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

describe('Runbook Knowledge Type - Comprehensive Testing', () => {
  let db: VectorDatabase;
  let mockQdrant: any;

  beforeEach(() => {
    db = new VectorDatabase();
    mockQdrant = (db as any).client;
  });

  describe('Runbook Schema Validation', () => {
    it('should validate complete runbook with all fields', () => {
      const runbook = {
        kind: 'runbook' as const,
        scope: {
          project: 'test-project',
          branch: 'main',
        },
        data: {
          service: 'authentication-service',
          title: 'Database Connection Pool Recovery',
          description:
            'Procedures for recovering database connection pool when connections are exhausted',
          steps: [
            {
              step_number: 1,
              description: 'Check current connection pool status',
              command: 'kubectl logs -n auth deployment/auth-service | grep "connection pool"',
              expected_outcome: 'Pool status should show active connections and available capacity',
            },
            {
              step_number: 2,
              description: 'Scale up the service to force connection pool reset',
              command: 'kubectl scale deployment auth-service --replicas=3 -n auth',
              expected_outcome: 'New pods should start with fresh connection pools',
            },
            {
              step_number: 3,
              description: 'Verify service health after scaling',
              command: 'kubectl get pods -n auth -l app=auth-service',
              expected_outcome: 'All pods should be in Running state with ready containers',
            },
          ],
          triggers: [
            'Database connection timeout errors',
            'High latency on authentication endpoints',
            'Connection pool exhaustion alerts',
          ],
          last_verified_at: '2025-01-01T00:00:00Z',
        },
        tags: { critical: true, recovery: true },
        source: {
          actor: 'sre-lead',
          tool: 'incident-response',
          timestamp: '2025-01-01T00:00:00Z',
        },
      };

      const result = RunbookSchema.safeParse(runbook);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.kind).toBe('runbook');
        expect(result.data.data.service).toBe('authentication-service');
        expect(result.data.data.title).toBe('Database Connection Pool Recovery');
        expect(result.data.data.steps).toHaveLength(3);
        expect(result.data.data.triggers).toHaveLength(3);
      }
    });

    it('should validate minimal runbook with only required fields', () => {
      const runbook = {
        kind: 'runbook' as const,
        scope: {
          project: 'test-project',
          branch: 'main',
        },
        data: {
          service: 'api-gateway',
          title: 'Service Restart',
          steps: [
            {
              step_number: 1,
              description: 'Restart the service',
              command: 'systemctl restart api-gateway',
            },
          ],
        },
      };

      const result = RunbookSchema.safeParse(runbook);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.service).toBe('api-gateway');
        expect(result.data.data.title).toBe('Service Restart');
        expect(result.data.data.steps).toHaveLength(1);
        expect(result.data.data.description).toBeUndefined();
        expect(result.data.data.triggers).toBeUndefined();
      }
    });

    it('should reject runbook missing required fields', () => {
      const invalidRunbooks = [
        {
          kind: 'runbook' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            // Missing service
            title: 'Test runbook',
            steps: [{ step_number: 1, description: 'Test step' }],
          },
        },
        {
          kind: 'runbook' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            service: 'test-service',
            // Missing title
            steps: [{ step_number: 1, description: 'Test step' }],
          },
        },
        {
          kind: 'runbook' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            service: 'test-service',
            title: 'Test runbook',
            // Missing steps
          },
        },
        {
          kind: 'runbook' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            service: '', // Empty service
            title: 'Test runbook',
            steps: [{ step_number: 1, description: 'Test step' }],
          },
        },
        {
          kind: 'runbook' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            service: 'test-service',
            title: '', // Empty title
            steps: [{ step_number: 1, description: 'Test step' }],
          },
        },
      ];

      invalidRunbooks.forEach((runbook, index) => {
        const result = RunbookSchema.safeParse(runbook);
        expect(result.success).toBe(false);
        if (!result.success) {
          expect(result.error.issues.length).toBeGreaterThan(0);
        }
      });
    });

    it('should enforce service length constraints', () => {
      const runbook = {
        kind: 'runbook' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          service: 'x'.repeat(201), // Exceeds 200 character limit
          title: 'Test runbook',
          steps: [{ step_number: 1, description: 'Test step' }],
        },
      };

      const result = RunbookSchema.safeParse(runbook);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('200 characters or less');
      }
    });

    it('should enforce title length constraints', () => {
      const runbook = {
        kind: 'runbook' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          service: 'test-service',
          title: 'x'.repeat(501), // Exceeds 500 character limit
          steps: [{ step_number: 1, description: 'Test step' }],
        },
      };

      const result = RunbookSchema.safeParse(runbook);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('500 characters or less');
      }
    });

    it('should reject runbook with empty steps array', () => {
      const runbook = {
        kind: 'runbook' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          service: 'test-service',
          title: 'Test runbook',
          steps: [], // Empty steps array
        },
      };

      const result = RunbookSchema.safeParse(runbook);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('At least one step is required');
      }
    });
  });

  describe('Procedure Steps Validation', () => {
    it('should validate complete procedure steps with all fields', () => {
      const steps = [
        {
          step_number: 1,
          description: 'Check service logs for errors',
          command: 'kubectl logs -f deployment/my-service --tail=100',
          expected_outcome: 'No error messages in recent logs',
        },
        {
          step_number: 2,
          description: 'Verify service health endpoint',
          command: 'curl -f http://my-service/health',
          expected_outcome: 'HTTP 200 response with healthy status',
        },
        {
          step_number: 3,
          description: 'Check database connectivity',
          command: 'kubectl exec -it deployment/my-service -- nc -zv database 5432',
          expected_outcome: 'Connection to database port 5432 successful',
        },
      ];

      const runbook = {
        kind: 'runbook' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          service: 'my-service',
          title: 'Service Health Check',
          steps,
        },
      };

      const result = RunbookSchema.safeParse(runbook);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.steps).toHaveLength(3);
        result.data.data.steps.forEach((step, index) => {
          expect(step.step_number).toBe(index + 1);
          expect(step.description).toBeTruthy();
          expect(step.command).toBeTruthy();
          expect(step.expected_outcome).toBeTruthy();
        });
      }
    });

    it('should validate minimal procedure steps with only required fields', () => {
      const steps = [
        {
          step_number: 1,
          description: 'Restart service',
          // command and expected_outcome are optional
        },
      ];

      const runbook = {
        kind: 'runbook' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          service: 'test-service',
          title: 'Simple restart',
          steps,
        },
      };

      const result = RunbookSchema.safeParse(runbook);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.steps[0].command).toBeUndefined();
        expect(result.data.data.steps[0].expected_outcome).toBeUndefined();
      }
    });

    it('should reject invalid procedure steps', () => {
      const invalidSteps = [
        {
          // Missing step_number
          description: 'Invalid step',
          command: 'echo test',
        },
        {
          step_number: 0, // Non-positive step number
          description: 'Invalid step number',
          command: 'echo test',
        },
        {
          step_number: -1, // Negative step number
          description: 'Invalid step number',
          command: 'echo test',
        },
        {
          step_number: 1,
          // Missing description
          command: 'echo test',
        },
        {
          step_number: 1,
          description: '', // Empty description
          command: 'echo test',
        },
      ];

      invalidSteps.forEach((step, index) => {
        const runbook = {
          kind: 'runbook' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            service: 'test-service',
            title: 'Invalid runbook',
            steps: [step],
          },
        };

        const result = RunbookSchema.safeParse(runbook);
        expect(result.success).toBe(false);
      });
    });

    it('should enforce step_number as positive integer', () => {
      const runbook = {
        kind: 'runbook' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          service: 'test-service',
          title: 'Test runbook',
          steps: [
            {
              step_number: 1.5, // Not an integer
              description: 'Invalid step number',
            },
          ],
        },
      };

      const result = RunbookSchema.safeParse(runbook);
      expect(result.success).toBe(false);
    });
  });

  describe('Runbook Storage Operations', () => {
    it('should store runbook successfully using memory_store pattern', async () => {
      const runbook = {
        kind: 'runbook' as const,
        scope: {
          project: 'test-project',
          branch: 'main',
        },
        data: {
          service: 'payment-service',
          title: 'Payment Gateway Failover',
          description: 'Switch to backup payment gateway when primary fails',
          steps: [
            {
              step_number: 1,
              description: 'Check primary gateway status',
              command: 'curl -f https://primary-gateway.health/endpoint',
              expected_outcome: 'Primary gateway responds with HTTP 200',
            },
            {
              step_number: 2,
              description: 'Update configuration to use backup gateway',
              command: 'kubectl edit configmap payment-config -n payments',
              expected_outcome: 'Configuration updated to use backup gateway URL',
            },
          ],
        },
        content: 'Runbook: Payment Gateway Failover for payment-service with 2 steps',
      };

      const result = await db.storeItems([runbook]);

      expect(result.stored).toHaveLength(1);
      expect(result.errors).toHaveLength(0);
      expect(result.stored[0]).toHaveProperty('id');
      expect(result.stored[0].kind).toBe('runbook');
      expect(result.stored[0].data.service).toBe('payment-service');
      expect(result.stored[0].data.title).toBe('Payment Gateway Failover');
      expect(result.stored[0].data.steps).toHaveLength(2);

      // Verify Qdrant client was called
      expect(mockQdrant.upsert).toHaveBeenCalled();
    });

    it('should handle batch runbook storage successfully', async () => {
      const runbooks = Array.from({ length: 3 }, (_, i) => ({
        kind: 'runbook' as const,
        scope: {
          project: 'test-project',
          branch: 'main',
        },
        data: {
          service: `service-${i}`,
          title: `Runbook for service-${i}`,
          description: `Procedures for handling service-${i} incidents`,
          steps: [
            {
              step_number: 1,
              description: `Check service-${i} status`,
              command: `kubectl get pods -l service=service-${i}`,
              expected_outcome: `All service-${i} pods are running`,
            },
          ],
        },
        content: `Runbook: ${i} for service-${i} with status check procedures`,
      }));

      const result = await db.storeItems(runbooks);

      expect(result.stored).toHaveLength(3);
      expect(result.errors).toHaveLength(0);
      expect(mockQdrant.upsert).toHaveBeenCalledTimes(3);
    });

    it('should handle mixed valid and invalid runbooks in batch', async () => {
      const items = [
        {
          kind: 'runbook' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            service: 'valid-service',
            title: 'Valid Runbook',
            steps: [{ step_number: 1, description: 'Valid step' }],
          },
          content: 'Valid runbook content',
        },
        {
          kind: 'runbook' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            // Missing service
            title: 'Invalid Runbook',
            steps: [{ step_number: 1, description: 'Invalid step' }],
          },
          content: 'Invalid runbook content',
        },
        {
          kind: 'runbook' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            service: 'another-valid-service',
            title: 'Another Valid Runbook',
            steps: [{ step_number: 1, description: 'Another valid step' }],
          },
          content: 'Another valid runbook content',
        },
      ];

      const result = await db.storeItems(items);

      expect(result.stored).toHaveLength(2); // 2 valid runbooks
      expect(result.errors).toHaveLength(1); // 1 invalid runbook
    });
  });

  describe('Runbook Search Operations', () => {
    beforeEach(() => {
      // Setup search mock for runbooks
      mockQdrant.search.mockResolvedValue([
        {
          id: 'runbook-id-1',
          score: 0.92,
          payload: {
            kind: 'runbook',
            data: {
              service: 'database-service',
              title: 'Database Connection Recovery',
              description: 'Procedures for recovering database connections',
              steps: [
                {
                  step_number: 1,
                  description: 'Check database connection pool',
                  command: 'kubectl logs -n database deployment/database-service',
                  expected_outcome: 'Connection pool status available',
                },
              ],
              triggers: ['Database timeout errors'],
              last_verified_at: '2025-01-01T00:00:00Z',
            },
            scope: { project: 'test-project', branch: 'main' },
          },
        },
        {
          id: 'runbook-id-2',
          score: 0.87,
          payload: {
            kind: 'runbook',
            data: {
              service: 'api-gateway',
              title: 'Rate Limit Configuration',
              description: 'Configure rate limits for API endpoints',
              steps: [
                {
                  step_number: 1,
                  description: 'Update rate limit configuration',
                  command: 'kubectl edit configmap api-gateway-config',
                },
              ],
            },
            scope: { project: 'test-project', branch: 'main' },
          },
        },
      ]);
    });

    it('should find runbooks by database recovery query', async () => {
      const query = 'database connection recovery timeout';

      const result = await db.searchItems(query);

      expect(result.items).toHaveLength(2);
      expect(result.items[0].data.service).toBe('database-service');
      expect(result.items[0].data.title).toBe('Database Connection Recovery');
      expect(result.items[0].data.steps).toHaveLength(1);
      expect(result.items[0].data.triggers).toContain('Database timeout errors');
      expect(mockQdrant.search).toHaveBeenCalled();
    });

    it('should handle empty runbook search results', async () => {
      mockQdrant.search.mockResolvedValue([]);

      const result = await db.searchItems('nonexistent runbook topic');

      expect(result.items).toHaveLength(0);
      expect(result.total).toBe(0);
    });
  });

  describe('Runbook Scope Isolation', () => {
    it('should isolate runbooks by project scope', async () => {
      const runbookProjectA = {
        kind: 'runbook' as const,
        scope: {
          project: 'project-A',
          branch: 'main',
        },
        data: {
          service: 'web-service',
          title: 'Service Restart Procedure',
          steps: [{ step_number: 1, description: 'Restart web service' }],
        },
        content: 'Runbook: Service Restart for project-A',
      };

      const runbookProjectB = {
        kind: 'runbook' as const,
        scope: {
          project: 'project-B',
          branch: 'main',
        },
        data: {
          service: 'web-service',
          title: 'Service Restart Procedure',
          steps: [{ step_number: 1, description: 'Restart web service' }],
        },
        content: 'Runbook: Service Restart for project-B',
      };

      // Store both runbooks
      await db.storeItems([runbookProjectA, runbookProjectB]);

      // Verify both were stored
      expect(mockQdrant.upsert).toHaveBeenCalledTimes(2);

      // Verify scope isolation in stored data
      const storedCalls = mockQdrant.upsert.mock.calls;
      expect(storedCalls[0][0].points[0].payload.scope.project).toBe('project-A');
      expect(storedCalls[1][0].points[0].payload.scope.project).toBe('project-B');
    });

    it('should handle runbooks with different branch scopes', async () => {
      const runbooks = [
        {
          kind: 'runbook' as const,
          scope: {
            project: 'test-project',
            branch: 'main',
          },
          data: {
            service: 'production-service',
            title: 'Production Recovery',
            steps: [{ step_number: 1, description: 'Production recovery step' }],
          },
          content: 'Production recovery runbook',
        },
        {
          kind: 'runbook' as const,
          scope: {
            project: 'test-project',
            branch: 'develop',
          },
          data: {
            service: 'staging-service',
            title: 'Staging Recovery',
            steps: [{ step_number: 1, description: 'Staging recovery step' }],
          },
          content: 'Staging recovery runbook',
        },
      ];

      await db.storeItems(runbooks);

      expect(mockQdrant.upsert).toHaveBeenCalledTimes(2);
      const storedCalls = mockQdrant.upsert.mock.calls;
      expect(storedCalls[0][0][0].payload.scope.branch).toBe('main');
      expect(storedCalls[1][0][0].payload.scope.branch).toBe('develop');
    });
  });

  describe('Runbook Edge Cases and Error Handling', () => {
    it('should handle complex nested procedure steps', async () => {
      const complexRunbook = {
        kind: 'runbook' as const,
        scope: {
          project: 'test-project',
          branch: 'main',
        },
        data: {
          service: 'microservices-platform',
          title: 'Complete System Recovery',
          description: 'Comprehensive recovery procedures for entire platform',
          steps: [
            {
              step_number: 1,
              description: 'Assess system impact and identify affected services',
              command:
                'kubectl get pods --all-namespaces | grep -E "(CrashLoopBackOff|Error|Pending)"',
              expected_outcome: 'List of unhealthy services identified',
            },
            {
              step_number: 2,
              description: 'Check dependencies and external service connectivity',
              command:
                "kubectl exec -it $(kubectl get pods -n monitoring -l app=service-mesh -o jsonpath='{.items[0].metadata.name}') -- curl -s external-service.health/endpoint",
              expected_outcome: 'External dependencies are accessible',
            },
            {
              step_number: 3,
              description: 'Execute service-specific recovery in dependency order',
              command:
                'for service in database cache auth api-gateway; do kubectl rollout restart deployment/$service; sleep 30; done',
              expected_outcome: 'All services restarted in correct order',
            },
            {
              step_number: 4,
              description: 'Verify system health and performance metrics',
              command:
                'kubectl top pods --all-namespaces && curl -s http://monitoring/grafana/api/health',
              expected_outcome: 'System performance metrics within normal ranges',
            },
          ],
          triggers: [
            'Multiple service failures detected',
            'System-wide performance degradation',
            'Cascading failure events',
          ],
          last_verified_at: '2025-01-15T10:30:00Z',
        },
      };

      const result = await db.storeItems([complexRunbook]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].data.steps).toHaveLength(4);
      expect(result.stored[0].data.triggers).toHaveLength(3);
      expect(result.stored[0].data.steps[2].description).toContain('dependency order');
    });

    it('should handle runbooks with special characters in service and title', async () => {
      const runbooks = [
        {
          kind: 'runbook' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            service: 'user-auth-service',
            title: 'User Authentication Service (OAuth 2.0) Recovery',
            steps: [{ step_number: 1, description: 'Test step with special chars: @#$%^&*()' }],
          },
          content: 'Runbook with special characters',
        },
        {
          kind: 'runbook' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            service: 'payment-gateway.v2',
            title: 'Payment Gateway v2.0 - SSL Certificate Renewal',
            steps: [{ step_number: 1, description: 'Renew SSL certificates for *.example.com' }],
          },
          content: 'SSL certificate renewal runbook',
        },
      ];

      const result = await db.storeItems(runbooks);

      expect(result.stored).toHaveLength(2);
      expect(mockQdrant.upsert).toHaveBeenCalledTimes(2);
    });

    it('should handle runbook storage errors gracefully', async () => {
      const runbook = {
        kind: 'runbook' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          service: 'test-service',
          title: 'Test Runbook',
          steps: [{ step_number: 1, description: 'Test step' }],
        },
      };

      // Mock upsert to throw an error
      mockQdrant.upsert.mockRejectedValue(new Error('Connection timeout'));

      const result = await db.storeItems([runbook]);

      expect(result.stored).toHaveLength(0);
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0].error).toContain('Connection timeout');
    });

    it('should handle runbooks with very long commands and descriptions', async () => {
      const longCommand =
        'kubectl exec -it deployment/complex-service -- bash -c "for i in {1..100}; do echo \'Processing item $i\'; curl -s -X POST https://api.example.com/process -H \'Content-Type: application/json\' -d \'{\\"id\\": \\"$i\\", \\"data\\": \\"complex processing data with lots of fields and nested objects\\"}\' | jq .status; sleep 1; done"';

      const longDescription =
        'This is a very detailed step that explains exactly what needs to be done, including all the context about why this step is necessary, what the expected outcomes should be, how to verify that the step completed successfully, and what to do if something goes wrong during the execution of this particular step in the runbook.';

      const runbook = {
        kind: 'runbook' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          service: 'complex-service',
          title: 'Complex Service Recovery',
          steps: [
            {
              step_number: 1,
              description: longDescription,
              command: longCommand,
              expected_outcome: `${longDescription} Expected outcome should match description.`,
            },
          ],
        },
      };

      const result = await db.storeItems([runbook]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].data.steps[0].description).toBe(longDescription);
      expect(result.stored[0].data.steps[0].command).toBe(longCommand);
    });
  });

  describe('Runbook Integration with Knowledge System', () => {
    it('should integrate with knowledge item validation', () => {
      const runbook = {
        kind: 'runbook' as const,
        scope: {
          project: 'test-project',
          branch: 'main',
        },
        data: {
          service: 'critical-business-service',
          title: 'Complete Service Outage Recovery',
          description:
            'Emergency procedures for recovering critical business service during major incidents',
          steps: [
            {
              step_number: 1,
              description: 'Declare incident and assemble response team',
              command:
                'slack-cli @incident-response "Critical service outage detected - immediate response required"',
              expected_outcome: 'Incident response team acknowledged and assembled',
            },
            {
              step_number: 2,
              description: 'Implement disaster recovery procedures',
              command:
                './scripts/disaster-recovery.sh --service=critical-business-service --environment=production',
              expected_outcome: 'Service recovered from disaster recovery site',
            },
          ],
          triggers: ['Complete service outage', 'Major data corruption', 'Natural disaster'],
          last_verified_at: '2025-01-01T12:00:00Z',
        },
        tags: {
          critical: true,
          disaster_recovery: true,
          emergency: true,
          business_continuity: true,
        },
        source: {
          actor: 'disaster-recovery-lead',
          tool: 'incident-management-platform',
          timestamp: '2025-01-01T12:00:00Z',
        },
        ttl_policy: 'permanent' as const,
      };

      const result = validateKnowledgeItem(runbook);
      expect(result.kind).toBe('runbook');
      expect(result.data.service).toBe('critical-business-service');
      expect(result.tags.critical).toBe(true);
      expect(result.tags.disaster_recovery).toBe(true);
      expect(result.source.actor).toBe('disaster-recovery-lead');
      expect(result.ttl_policy).toBe('permanent');
    });

    it('should handle TTL policy for runbooks', async () => {
      const runbook = {
        kind: 'runbook' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          service: 'temporary-service',
          title: 'Temporary Service Recovery',
          steps: [{ step_number: 1, description: 'Temporary recovery step' }],
        },
        ttl_policy: 'short' as const,
      };

      const result = await db.storeItems([runbook]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].ttl_policy).toBe('short');
    });

    it('should handle runbooks with comprehensive metadata', () => {
      const runbook = {
        kind: 'runbook' as const,
        scope: {
          project: 'test-project',
          branch: 'main',
          environment: 'production',
        },
        data: {
          service: 'monitoring-service',
          title: 'Monitoring System Recovery',
          description: 'Procedures for recovering monitoring and alerting systems',
          steps: [
            {
              step_number: 1,
              description: 'Check Prometheus connectivity',
              command: 'curl -s http://prometheus:9090/-/healthy',
            },
            {
              step_number: 2,
              description: 'Restart Grafana if needed',
              command: 'kubectl rollout restart deployment/grafana',
            },
          ],
          triggers: ['Monitoring dashboard unavailable', 'Alert delivery failures'],
          last_verified_at: '2025-01-10T15:30:00Z',
        },
        tags: {
          monitoring: true,
          observability: true,
          sre: true,
          automated: true,
        },
        source: {
          actor: 'platform-engineer',
          tool: 'runbook-generator',
          timestamp: '2025-01-10T15:30:00Z',
        },
        idempotency_key: 'monitoring-recovery-v1.2.3',
      };

      const result = validateKnowledgeItem(runbook);
      expect(result.kind).toBe('runbook');
      expect(result.scope.environment).toBe('production');
      expect(result.tags.monitoring).toBe(true);
      expect(result.tags.sre).toBe(true);
      expect(result.source.tool).toBe('runbook-generator');
      expect(result.idempotency_key).toBe('monitoring-recovery-v1.2.3');
    });
  });

  describe('Runbook Timestamp and Validation', () => {
    it('should handle valid datetime for last_verified_at', () => {
      const runbook = {
        kind: 'runbook' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          service: 'test-service',
          title: 'Test Runbook',
          steps: [{ step_number: 1, description: 'Test step' }],
          last_verified_at: '2025-01-01T00:00:00Z',
        },
      };

      const result = RunbookSchema.safeParse(runbook);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.last_verified_at).toBe('2025-01-01T00:00:00Z');
      }
    });

    it('should reject invalid datetime format for last_verified_at', () => {
      const runbook = {
        kind: 'runbook' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          service: 'test-service',
          title: 'Test Runbook',
          steps: [{ step_number: 1, description: 'Test step' }],
          last_verified_at: 'invalid-date', // Invalid datetime format
        },
      };

      const result = RunbookSchema.safeParse(runbook);
      expect(result.success).toBe(false);
    });

    it('should handle runbooks without last_verified_at', () => {
      const runbook = {
        kind: 'runbook' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          service: 'test-service',
          title: 'Test Runbook',
          steps: [{ step_number: 1, description: 'Test step' }],
          // last_verified_at is optional
        },
      };

      const result = RunbookSchema.safeParse(runbook);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.last_verified_at).toBeUndefined();
      }
    });
  });
});
