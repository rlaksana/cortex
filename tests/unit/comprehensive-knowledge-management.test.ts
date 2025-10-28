/**
 * COMPREHENSIVE CORTEX MCP KNOWLEDGE MANAGEMENT TEST SUITE
 *
 * Tests all 16 knowledge types and 8-LOG system functionality
 *
 * KNOWLEDGE TYPES TO TEST:
 * 1. Section
 * 2. Decision
 * 3. Issue
 * 4. Todo
 * 5. Runbook
 * 6. Change
 * 7. Release_note
 * 8. DDL
 * 9. PR_context
 * 10. Entity
 * 11. Relation
 * 12. Observation
 * 13. Incident
 * 14. Release
 * 15. Risk
 * 16. Assumption
 *
 * 8-LOG SYSTEM TESTING:
 * - CHANGELOG (ChangeLog model)
 * - DECISIONLOG (AdrDecision model)
 * - ISSUELOG (IssueLog model)
 * - TODOLOG (TodoLog model)
 * - INCIDENTLOG (IncidentLog model)
 * - RELEASELOG (ReleaseLog model)
 * - RISKLOG (RiskLog model)
 * - ASSUMPTIONLOG (AssumptionLog model)
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { memoryStore } from '../../src/services/memory-store.js';
import { memoryFind } from '../../src/services/memory-find.js';

const TEST_SCOPE = {
  project: 'cortex-test-comprehensive',
  branch: 'test-knowledge-types',
  org: 'test-org',
  environment: 'test'
};

describe('COMPREHENSIVE CORTEX MCP KNOWLEDGE MANAGEMENT TEST SUITE', () => {
  let storedIds: Record<string, string[]> = {};

  beforeAll(async () => {
    console.log('🧪 Starting comprehensive Cortex MCP knowledge management test suite...');
  });

  afterAll(async () => {
    console.log('🏁 Comprehensive test suite completed');
  });

  describe('PHASE 1: BASIC KNOWLEDGE TYPES (1-9)', () => {

    describe('1. Section Knowledge Type', () => {
      it('should store section with markdown content', async () => {
        const result = await memoryStore([
          {
            kind: 'section',
            scope: TEST_SCOPE,
            data: {
              title: 'API Authentication Section',
              heading: 'Authentication Overview',
              body_md: '# Authentication\nThis section covers OAuth 2.0 implementation',
              body_text: 'Authentication Overview - This section covers OAuth 2.0 implementation',
              document_id: 'doc-001',
              citation_count: 5
            }
          }
        ]);

        expect(result.errors).toHaveLength(0);
        expect(result.stored).toHaveLength(1);
        expect(result.stored[0].kind).toBe('section');
        expect(result.stored[0].status).toBe('inserted');

        storedIds.section = result.stored.map(s => s.id);
        console.log('✅ Section stored successfully:', result.stored[0].id);
      });

      it('should retrieve stored section via memory find', async () => {
        const result = await memoryFind({
          query: 'API Authentication',
          scope: TEST_SCOPE,
          types: ['section'],
          top_k: 5
        });

        expect(result.hits).toHaveLength(1);
        expect(result.hits[0].kind).toBe('section');
        expect(result.hits[0].title).toContain('API Authentication');
        expect(result.hits[0].confidence).toBeGreaterThan(0);

        console.log('✅ Section retrieved successfully:', result.hits[0].id);
      });
    });

    describe('2. Decision Knowledge Type (ADR)', () => {
      it('should store ADR with proposed status', async () => {
        const result = await memoryStore([
          {
            kind: 'decision',
            scope: TEST_SCOPE,
            data: {
              component: 'authentication-service',
              status: 'proposed',
              title: 'Use JWT tokens for authentication',
              rationale: 'JWT provides stateless authentication with built-in expiration',
              alternatives_considered: ['Session-based authentication', 'OAuth 2.0 with refresh tokens'],
              consequences: 'Tokens must be properly validated and refreshed'
            }
          }
        ]);

        expect(result.errors).toHaveLength(0);
        expect(result.stored).toHaveLength(1);
        expect(result.stored[0].kind).toBe('decision');

        storedIds.decision = result.stored.map(s => s.id);
        console.log('✅ Decision (ADR) stored successfully:', result.stored[0].id);
      });

      it('should retrieve ADR via memory find', async () => {
        const result = await memoryFind({
          query: 'JWT authentication',
          scope: TEST_SCOPE,
          types: ['decision'],
          top_k: 5
        });

        expect(result.hits).toHaveLength(1);
        expect(result.hits[0].kind).toBe('decision');
        expect(result.hits[0].title).toContain('JWT');

        console.log('✅ Decision (ADR) retrieved successfully:', result.hits[0].id);
      });
    });

    describe('3. Issue Knowledge Type', () => {
      it('should store issue with external tracker reference', async () => {
        const result = await memoryStore([
          {
            kind: 'issue',
            scope: TEST_SCOPE,
            data: {
              tracker: 'github',
              external_id: 'GH-1234',
              title: 'Memory leak in authentication service',
              status: 'in_progress',
              description: 'Service memory usage increases by 10MB per hour under load',
              assignee: 'john.doe',
              labels: ['bug', 'performance', 'critical'],
              url: 'https://github.com/test/repo/issues/1234'
            }
          }
        ]);

        expect(result.errors).toHaveLength(0);
        expect(result.stored).toHaveLength(1);
        expect(result.stored[0].kind).toBe('issue');

        storedIds.issue = result.stored.map(s => s.id);
        console.log('✅ Issue stored successfully:', result.stored[0].id);
      });

      it('should retrieve issue via memory find', async () => {
        const result = await memoryFind({
          query: 'memory leak authentication',
          scope: TEST_SCOPE,
          types: ['issue'],
          top_k: 5
        });

        expect(result.hits).toHaveLength(1);
        expect(result.hits[0].kind).toBe('issue');
        expect(result.hits[0].title).toContain('Memory leak');

        console.log('✅ Issue retrieved successfully:', result.hits[0].id);
      });
    });

    describe('4. Todo Knowledge Type', () => {
      it('should store todo with task details', async () => {
        const result = await memoryStore([
          {
            kind: 'todo',
            scope: TEST_SCOPE,
            data: {
              scope: 'task',
              todo_type: 'task',
              text: 'Implement rate limiting for authentication endpoints',
              status: 'open',
              priority: 'high',
              assignee: 'jane.smith',
              due_date: '2025-01-31T23:59:59Z'
            }
          }
        ]);

        expect(result.errors).toHaveLength(0);
        expect(result.stored).toHaveLength(1);
        expect(result.stored[0].kind).toBe('todo');

        storedIds.todo = result.stored.map(s => s.id);
        console.log('✅ Todo stored successfully:', result.stored[0].id);
      });

      it('should retrieve todo via memory find', async () => {
        const result = await memoryFind({
          query: 'rate limiting',
          scope: TEST_SCOPE,
          types: ['todo'],
          top_k: 5
        });

        expect(result.hits).toHaveLength(1);
        expect(result.hits[0].kind).toBe('todo');
        expect(result.hits[0].title).toContain('rate limiting');

        console.log('✅ Todo retrieved successfully:', result.hits[0].id);
      });
    });

    describe('5. Runbook Knowledge Type', () => {
      it('should store runbook with procedural steps', async () => {
        const result = await memoryStore([
          {
            kind: 'runbook',
            scope: TEST_SCOPE,
            data: {
              title: 'Database Backup Runbook',
              description: 'Automated database backup procedures',
              service: 'postgresql-service',
              steps: [
                {
                  step_number: 1,
                  description: 'Create database snapshot',
                  command: 'pg_dump cortex_prod > backup_$(date +%Y%m%d).sql',
                  expected_outcome: 'SQL backup file created successfully'
                },
                {
                  step_number: 2,
                  description: 'Verify backup integrity',
                  command: 'pg_verify backup_$(date +%Y%m%d).sql',
                  expected_outcome: 'Backup verification passed'
                }
              ],
              triggers: ['scheduled', 'manual', 'pre-deployment'],
              last_verified_at: '2025-01-20T10:00:00Z'
            }
          }
        ]);

        expect(result.errors).toHaveLength(0);
        expect(result.stored).toHaveLength(1);
        expect(result.stored[0].kind).toBe('runbook');

        storedIds.runbook = result.stored.map(s => s.id);
        console.log('✅ Runbook stored successfully:', result.stored[0].id);
      });

      it('should retrieve runbook via memory find', async () => {
        const result = await memoryFind({
          query: 'database backup',
          scope: TEST_SCOPE,
          types: ['runbook'],
          top_k: 5
        });

        expect(result.hits).toHaveLength(1);
        expect(result.hits[0].kind).toBe('runbook');
        expect(result.hits[0].title).toContain('Database Backup');

        console.log('✅ Runbook retrieved successfully:', result.hits[0].id);
      });
    });

    describe('6. Change Knowledge Type', () => {
      it('should store change record', async () => {
        const result = await memoryStore([
          {
            kind: 'change',
            scope: TEST_SCOPE,
            data: {
              change_type: 'feature_add',
              subject_ref: 'PR-5678',
              summary: 'Add rate limiting middleware to API endpoints',
              details: 'Implemented token bucket algorithm with Redis backend',
              affected_files: ['src/middleware/rate-limiter.ts', 'src/config/redis.ts'],
              author: 'jane.smith',
              commit_sha: 'abc123def456789'
            }
          }
        ]);

        expect(result.errors).toHaveLength(0);
        expect(result.stored).toHaveLength(1);
        expect(result.stored[0].kind).toBe('change');

        storedIds.change = result.stored.map(s => s.id);
        console.log('✅ Change stored successfully:', result.stored[0].id);
      });

      it('should retrieve change via memory find', async () => {
        const result = await memoryFind({
          query: 'rate limiting middleware',
          scope: TEST_SCOPE,
          types: ['change'],
          top_k: 5
        });

        expect(result.hits).toHaveLength(1);
        expect(result.hits[0].kind).toBe('change');
        expect(result.hits[0].title).toContain('PR-5678');

        console.log('✅ Change retrieved successfully:', result.hits[0].id);
      });
    });

    describe('7. Release Note Knowledge Type', () => {
      it('should store release note', async () => {
        const result = await memoryStore([
          {
            kind: 'release_note',
            scope: TEST_SCOPE,
            data: {
              version: '2.1.0',
              release_date: '2025-01-20T15:00:00Z',
              summary: 'Security and performance improvements',
              breaking_changes: ['Removed deprecated /legacy endpoint'],
              new_features: ['Added rate limiting', 'Enhanced audit logging'],
              bug_fixes: ['Fixed memory leak in auth service', 'Resolved timeout issues']
            }
          }
        ]);

        expect(result.errors).toHaveLength(0);
        expect(result.stored).toHaveLength(1);
        expect(result.stored[0].kind).toBe('release_note');

        storedIds.release_note = result.stored.map(s => s.id);
        console.log('✅ Release Note stored successfully:', result.stored[0].id);
      });

      it('should retrieve release note via memory find', async () => {
        const result = await memoryFind({
          query: 'security performance improvements',
          scope: TEST_SCOPE,
          types: ['release_note'],
          top_k: 5
        });

        expect(result.hits).toHaveLength(1);
        expect(result.hits[0].kind).toBe('release_note');
        expect(result.hits[0].title).toContain('2.1.0');

        console.log('✅ Release Note retrieved successfully:', result.hits[0].id);
      });
    });

    describe('8. DDL Knowledge Type', () => {
      it('should store DDL migration record', async () => {
        const result = await memoryStore([
          {
            kind: 'ddl',
            scope: TEST_SCOPE,
            data: {
              migration_id: '004_add_rate_limiting_table',
              ddl_text: 'CREATE TABLE rate_limits (id SERIAL PRIMARY KEY, user_id VARCHAR(255), service VARCHAR(100), requests_per_minute INTEGER, created_at TIMESTAMP DEFAULT NOW());',
              checksum: 'a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
              applied_at: '2025-01-20T12:00:00Z',
              description: 'Add table for storing rate limiting configurations'
            }
          }
        ]);

        expect(result.errors).toHaveLength(0);
        expect(result.stored).toHaveLength(1);
        expect(result.stored[0].kind).toBe('ddl');

        storedIds.ddl = result.stored.map(s => s.id);
        console.log('✅ DDL stored successfully:', result.stored[0].id);
      });

      it('should retrieve DDL via memory find', async () => {
        const result = await memoryFind({
          query: 'rate limiting table',
          scope: TEST_SCOPE,
          types: ['ddl'],
          top_k: 5
        });

        expect(result.hits).toHaveLength(1);
        expect(result.hits[0].kind).toBe('ddl');
        expect(result.hits[0].title).toContain('004_add_rate_limiting_table');

        console.log('✅ DDL retrieved successfully:', result.hits[0].id);
      });
    });

    describe('9. PR Context Knowledge Type', () => {
      it('should store PR context', async () => {
        const result = await memoryStore([
          {
            kind: 'pr_context',
            scope: TEST_SCOPE,
            data: {
              pr_number: 5678,
              title: 'Add rate limiting middleware to API endpoints',
              description: 'Implements token bucket rate limiting with Redis backend for all API endpoints',
              author: 'jane.smith',
              status: 'merged',
              base_branch: 'main',
              head_branch: 'feature/rate-limiting',
              merged_at: '2025-01-20T14:30:00Z',
              expires_at: '2025-02-19T14:30:00Z'
            }
          }
        ]);

        expect(result.errors).toHaveLength(0);
        expect(result.stored).toHaveLength(1);
        expect(result.stored[0].kind).toBe('pr_context');

        storedIds.pr_context = result.stored.map(s => s.id);
        console.log('✅ PR Context stored successfully:', result.stored[0].id);
      });

      it('should retrieve PR context via memory find', async () => {
        const result = await memoryFind({
          query: 'rate limiting middleware',
          scope: TEST_SCOPE,
          types: ['pr_context'],
          top_k: 5
        });

        expect(result.hits).toHaveLength(1);
        expect(result.hits[0].kind).toBe('pr_context');
        expect(result.hits[0].title).toContain('PR #5678');

        console.log('✅ PR Context retrieved successfully:', result.hits[0].id);
      });
    });
  });

  describe('PHASE 2: GRAPH EXTENSION KNOWLEDGE TYPES (10-12)', () => {

    describe('10. Entity Knowledge Type', () => {
      it('should store flexible entity with custom data', async () => {
        const result = await memoryStore([
          {
            kind: 'entity',
            scope: TEST_SCOPE,
            data: {
              entity_type: 'user',
              name: 'john.doe',
              data: {
                email: 'john.doe@company.com',
                role: 'senior-developer',
                department: 'engineering',
                skills: ['typescript', 'node.js', 'postgresql'],
                join_date: '2023-03-15',
                location: 'Remote'
              }
            }
          }
        ]);

        expect(result.errors).toHaveLength(0);
        expect(result.stored).toHaveLength(1);
        expect(result.stored[0].kind).toBe('entity');

        storedIds.entity = result.stored.map(s => s.id);
        console.log('✅ Entity stored successfully:', result.stored[0].id);
      });

      it('should retrieve entity via memory find', async () => {
        const result = await memoryFind({
          query: 'john.doe senior developer',
          scope: TEST_SCOPE,
          types: ['entity'],
          top_k: 5
        });

        expect(result.hits).toHaveLength(1);
        expect(result.hits[0].kind).toBe('entity');
        expect(result.hits[0].title).toContain('user: john.doe');

        console.log('✅ Entity retrieved successfully:', result.hits[0].id);
      });
    });

    describe('11. Relation Knowledge Type', () => {
      it('should store entity relationship', async () => {
        // First create another entity to relate to
        const entityResult = await memoryStore([
          {
            kind: 'entity',
            scope: TEST_SCOPE,
            data: {
              entity_type: 'service',
              name: 'authentication-service',
              data: {
                version: '2.1.0',
                status: 'active',
                repository: 'github.com/company/auth-service'
              }
            }
          }
        ]);

        expect(entityResult.stored).toHaveLength(1);
        const serviceEntityId = entityResult.stored[0].id;

        const result = await memoryStore([
          {
            kind: 'relation',
            scope: TEST_SCOPE,
            data: {
              from_entity_type: 'user',
              from_entity_id: storedIds.entity[0],
              to_entity_type: 'service',
              to_entity_id: serviceEntityId,
              relation_type: 'maintains',
              metadata: {
                role: 'lead-developer',
                since: '2023-06-01',
                responsibilities: ['feature-development', 'bug-fixes', 'code-reviews']
              }
            }
          }
        ]);

        expect(result.errors).toHaveLength(0);
        expect(result.stored).toHaveLength(1);
        expect(result.stored[0].kind).toBe('relation');

        storedIds.relation = result.stored.map(s => s.id);
        storedIds.service_entity = [serviceEntityId];
        console.log('✅ Relation stored successfully:', result.stored[0].id);
      });

      it('should retrieve relation via memory find', async () => {
        const result = await memoryFind({
          query: 'maintains service relationship',
          scope: TEST_SCOPE,
          types: ['relation'],
          top_k: 5
        });

        expect(result.hits).toHaveLength(1);
        expect(result.hits[0].kind).toBe('relation');

        console.log('✅ Relation retrieved successfully:', result.hits[0].id);
      });
    });

    describe('12. Observation Knowledge Type', () => {
      it('should store fine-grained observation', async () => {
        const result = await memoryStore([
          {
            kind: 'observation',
            scope: TEST_SCOPE,
            data: {
              entity_type: 'user',
              entity_id: storedIds.entity[0],
              observation: 'User completed advanced TypeScript certification',
              observation_type: 'achievement',
              metadata: {
                certification: 'typescript-advanced',
                date: '2025-01-15',
                issuer: 'typescript-institute',
                score: 95
              }
            }
          }
        ]);

        expect(result.errors).toHaveLength(0);
        expect(result.stored).toHaveLength(1);
        expect(result.stored[0].kind).toBe('observation');

        storedIds.observation = result.stored.map(s => s.id);
        console.log('✅ Observation stored successfully:', result.stored[0].id);
      });

      it('should retrieve observation via memory find', async () => {
        const result = await memoryFind({
          query: 'typescript certification',
          scope: TEST_SCOPE,
          types: ['observation'],
          top_k: 5
        });

        expect(result.hits).toHaveLength(1);
        expect(result.hits[0].kind).toBe('observation');

        console.log('✅ Observation retrieved successfully:', result.hits[0].id);
      });
    });
  });

  describe('PHASE 3: 8-LOG SYSTEM KNOWLEDGE TYPES (13-16)', () => {

    describe('13. Incident Knowledge Type (IncidentLog)', () => {
      it('should store incident with timeline and RCA', async () => {
        const result = await memoryStore([
          {
            kind: 'incident',
            scope: TEST_SCOPE,
            data: {
              title: 'Authentication Service Outage',
              severity: 'high',
              impact: 'Users unable to log in to the platform for 45 minutes',
              resolution_status: 'resolved',
              timeline: [
                {
                  timestamp: '2025-01-20T08:00:00Z',
                  event: 'Alert: High error rate detected in auth service',
                  actor: 'monitoring-system'
                },
                {
                  timestamp: '2025-01-20T08:05:00Z',
                  event: 'Incident declared and response team mobilized',
                  actor: 'incident-commander'
                },
                {
                  timestamp: '2025-01-20T08:15:00Z',
                  event: 'Root cause identified: Database connection pool exhausted',
                  actor: 'lead-engineer'
                },
                {
                  timestamp: '2025-01-20T08:30:00Z',
                  event: 'Service restored after increasing connection pool size',
                  actor: 'ops-team'
                },
                {
                  timestamp: '2025-01-20T08:45:00Z',
                  event: 'Incident resolved',
                  actor: 'incident-commander'
                }
              ],
              root_cause_analysis: 'Database connection pool was not configured to handle increased traffic from new feature deployment. QdrantClient size was set too low for production load.',
              resolution: 'Increased database connection pool size by 300% and implemented connection monitoring',
              affected_services: ['authentication-service', 'api-gateway'],
              business_impact: 'Customer login failure rate increased by 100%',
              recovery_actions: ['Increased DB pool size', 'Added connection monitoring', 'Implemented automated scaling'],
              follow_up_required: true,
              incident_commander: 'jane.smith'
            }
          }
        ]);

        expect(result.errors).toHaveLength(0);
        expect(result.stored).toHaveLength(1);
        expect(result.stored[0].kind).toBe('incident');

        storedIds.incident = result.stored.map(s => s.id);
        console.log('✅ Incident stored successfully:', result.stored[0].id);
      });

      it('should retrieve incident via memory find', async () => {
        const result = await memoryFind({
          query: 'authentication service outage',
          scope: TEST_SCOPE,
          types: ['incident'],
          top_k: 5
        });

        expect(result.hits).toHaveLength(1);
        expect(result.hits[0].kind).toBe('incident');
        expect(result.hits[0].title).toContain('INCIDENT: Authentication Service Outage');

        console.log('✅ Incident retrieved successfully:', result.hits[0].id);
      });
    });

    describe('14. Release Knowledge Type (ReleaseLog)', () => {
      it('should store comprehensive release log', async () => {
        const result = await memoryStore([
          {
            kind: 'release',
            scope: TEST_SCOPE,
            data: {
              version: '2.2.0',
              release_type: 'minor',
              scope: 'Authentication service enhancement with rate limiting and security improvements',
              release_date: '2025-01-20T16:00:00Z',
              status: 'completed',
              ticket_references: ['TICKET-123', 'TICKET-124', 'TICKET-125'],
              included_changes: ['Added rate limiting', 'Enhanced security headers', 'Improved error handling'],
              deployment_strategy: 'Blue-green deployment with gradual traffic shift',
              rollback_plan: 'Immediate rollback to version 2.1.0 via automated script',
              testing_status: 'All tests passed (unit: 98%, integration: 95%, e2e: 92%)',
              approvers: ['tech-lead', 'qa-manager', 'product-owner'],
              release_notes: 'This release adds rate limiting capabilities to prevent abuse, enhances security with improved headers, and fixes several edge cases in error handling.',
              post_release_actions: ['Monitor error rates', 'Check performance metrics', 'Verify rate limiting effectiveness']
            }
          }
        ]);

        expect(result.errors).toHaveLength(0);
        expect(result.stored).toHaveLength(1);
        expect(result.stored[0].kind).toBe('release');

        storedIds.release = result.stored.map(s => s.id);
        console.log('✅ Release stored successfully:', result.stored[0].id);
      });

      it('should retrieve release via memory find', async () => {
        const result = await memoryFind({
          query: 'version 2.2.0 authentication service',
          scope: TEST_SCOPE,
          types: ['release'],
          top_k: 5
        });

        expect(result.hits).toHaveLength(1);
        expect(result.hits[0].kind).toBe('release');
        expect(result.hits[0].title).toContain('RELEASE: 2.2.0');

        console.log('✅ Release retrieved successfully:', result.hits[0].id);
      });
    });

    describe('15. Risk Knowledge Type (RiskLog)', () => {
      it('should store risk assessment with mitigation strategies', async () => {
        const result = await memoryStore([
          {
            kind: 'risk',
            scope: TEST_SCOPE,
            data: {
              title: 'Database Connection QdrantClient Exhaustion',
              category: 'technical',
              risk_level: 'high',
              probability: 'likely',
              impact_description: 'Service becomes unavailable when database connection pool is exhausted, leading to complete system outage',
              trigger_events: ['Sudden traffic spikes', 'Memory leaks in application', 'Database performance degradation'],
              mitigation_strategies: [
                'Implement connection pool monitoring and alerts',
                'Configure automatic pool scaling',
                'Add circuit breaker pattern for database connections',
                'Regular performance testing under load'
              ],
              owner: 'infrastructure-team',
              review_date: '2025-02-01T00:00:00Z',
              status: 'mitigated',
              monitoring_indicators: ['Connection pool usage %', 'Database response time', 'Active connection count'],
              contingency_plans: 'Manual intervention to restart services and manually adjust pool size if automatic systems fail'
            }
          }
        ]);

        expect(result.errors).toHaveLength(0);
        expect(result.stored).toHaveLength(1);
        expect(result.stored[0].kind).toBe('risk');

        storedIds.risk = result.stored.map(s => s.id);
        console.log('✅ Risk stored successfully:', result.stored[0].id);
      });

      it('should retrieve risk via memory find', async () => {
        const result = await memoryFind({
          query: 'database connection pool risk',
          scope: TEST_SCOPE,
          types: ['risk'],
          top_k: 5
        });

        expect(result.hits).toHaveLength(1);
        expect(result.hits[0].kind).toBe('risk');
        expect(result.hits[0].title).toContain('RISK: Database Connection QdrantClient Exhaustion');

        console.log('✅ Risk retrieved successfully:', result.hits[0].id);
      });
    });

    describe('16. Assumption Knowledge Type (AssumptionLog)', () => {
      it('should store assumption with validation criteria', async () => {
        const result = await memoryStore([
          {
            kind: 'assumption',
            scope: TEST_SCOPE,
            data: {
              title: 'Current database infrastructure can handle 10x load',
              description: 'We assume our PostgreSQL setup with current connection pooling and indexing strategies can sustain a 10x increase in user traffic without performance degradation',
              category: 'technical',
              validation_status: 'needs_validation',
              impact_if_invalid: 'System performance degradation or complete outage during scaling events, potential loss of customers and revenue',
              validation_criteria: [
                'Conduct load testing with 10x current traffic',
                'Monitor database performance metrics under load',
                'Verify connection pool sizing is adequate',
                'Check query performance with larger datasets'
              ],
              validation_date: '2025-02-15T00:00:00Z',
              owner: 'architecture-team',
              related_assumptions: [],
              dependencies: ['Database server capacity', 'Network bandwidth', 'Application efficiency'],
              monitoring_approach: 'Continuous monitoring of database response times, connection usage, and query performance',
              review_frequency: 'monthly'
            }
          }
        ]);

        expect(result.errors).toHaveLength(0);
        expect(result.stored).toHaveLength(1);
        expect(result.stored[0].kind).toBe('assumption');

        storedIds.assumption = result.stored.map(s => s.id);
        console.log('✅ Assumption stored successfully:', result.stored[0].id);
      });

      it('should retrieve assumption via memory find', async () => {
        const result = await memoryFind({
          query: 'database infrastructure load assumption',
          scope: TEST_SCOPE,
          types: ['assumption'],
          top_k: 5
        });

        expect(result.hits).toHaveLength(1);
        expect(result.hits[0].kind).toBe('assumption');
        expect(result.hits[0].title).toContain('ASSUMPTION: Current database infrastructure can handle 10x load');

        console.log('✅ Assumption retrieved successfully:', result.hits[0].id);
      });
    });
  });

  describe('PHASE 4: COMPREHENSIVE SYSTEM TESTING', () => {

    it('should retrieve all knowledge types in comprehensive search', async () => {
      const result = await memoryFind({
        query: 'authentication service',
        scope: TEST_SCOPE,
        top_k: 20,
        mode: 'deep'
      });

      expect(result.hits.length).toBeGreaterThan(10);

      // Verify we have hits from multiple knowledge types
      const knowledgeTypesFound = new Set(result.hits.map(h => h.kind));
      console.log('🔍 Found knowledge types in comprehensive search:', Array.from(knowledgeTypesFound));

      // Should include at least section, decision, issue, todo, incident, release, risk, assumption
      expect(knowledgeTypesFound.has('section')).toBe(true);
      expect(knowledgeTypesFound.has('decision')).toBe(true);
      expect(knowledgeTypesFound.has('incident')).toBe(true);
      expect(knowledgeTypesFound.has('release')).toBe(true);

      console.log('✅ Comprehensive search returned', result.hits.length, 'results from', knowledgeTypesFound.size, 'knowledge types');
    });

    it('should respect scope filtering', async () => {
      // Search with correct scope
      const resultWithScope = await memoryFind({
        query: 'authentication',
        scope: TEST_SCOPE,
        top_k: 20
      });

      // Search without scope
      const resultWithoutScope = await memoryFind({
        query: 'authentication',
        top_k: 20
      });

      expect(resultWithScope.hits.length).toBeGreaterThan(0);
      expect(resultWithoutScope.hits.length).toBeGreaterThanOrEqual(resultWithScope.hits.length);

      console.log('✅ Scope filtering test passed - with scope:', resultWithScope.hits.length, 'without scope:', resultWithoutScope.hits.length);
    });

    it('should test knowledge type-specific searches', async () => {
      const searches = [
        { type: 'section', query: 'API Authentication' },
        { type: 'decision', query: 'JWT tokens' },
        { type: 'issue', query: 'memory leak' },
        { type: 'todo', query: 'rate limiting' },
        { type: 'runbook', query: 'database backup' },
        { type: 'change', query: 'rate limiting middleware' },
        { type: 'release_note', query: 'security performance' },
        { type: 'ddl', query: 'rate limiting table' },
        { type: 'pr_context', query: 'rate limiting' },
        { type: 'entity', query: 'john.doe' },
        { type: 'relation', query: 'maintains' },
        { type: 'observation', query: 'typescript certification' },
        { type: 'incident', query: 'service outage' },
        { type: 'release', query: '2.2.0' },
        { type: 'risk', query: 'connection pool' },
        { type: 'assumption', query: 'database infrastructure' }
      ];

      const results = [];

      for (const search of searches) {
        const result = await memoryFind({
          query: search.query,
          scope: TEST_SCOPE,
          types: [search.type],
          top_k: 5
        });

        results.push({ type: search.type, found: result.hits.length > 0, count: result.hits.length });
      }

      // All searches should find at least one result
      for (const result of results) {
        expect(result.found).toBe(true);
        expect(result.count).toBeGreaterThan(0);
      }

      console.log('✅ Knowledge type-specific searches completed:');
      results.forEach(r => console.log(`  ${r.type}: ${r.count} results found`));
    });

    it('should test autonomous metadata and confidence scoring', async () => {
      const result = await memoryFind({
        query: 'authentication',
        scope: TEST_SCOPE,
        top_k: 10,
        mode: 'auto'
      });

      expect(result.autonomous_metadata).toBeDefined();
      expect(result.autonomous_metadata.confidence).toBeDefined();
      expect(result.autonomous_metadata.total_results).toBeGreaterThan(0);
      expect(result.autonomous_metadata.avg_score).toBeGreaterThan(0);
      expect(result.autonomous_metadata.strategy_used).toBeDefined();
      expect(result.autonomous_metadata.recommendation).toBeDefined();
      expect(result.autonomous_metadata.user_message_suggestion).toBeDefined();

      console.log('🤖 Autonomous metadata:');
      console.log(`  Strategy: ${result.autonomous_metadata.strategy_used}`);
      console.log(`  Confidence: ${result.autonomous_metadata.confidence}`);
      console.log(`  Results: ${result.autonomous_metadata.total_results}`);
      console.log(`  Avg Score: ${result.autonomous_metadata.avg_score.toFixed(3)}`);
      console.log(`  Recommendation: ${result.autonomous_metadata.recommendation}`);

      expect(['high', 'medium', 'low']).toContain(result.autonomous_metadata.confidence);
      expect(result.autonomous_metadata.total_results).toBe(result.hits.length);

      console.log('✅ Autonomous metadata test passed');
    });

    it('should test batch operations with multiple knowledge types', async () => {
      const batchData = [
        {
          kind: 'todo' as const,
          scope: TEST_SCOPE,
          data: {
            scope: 'task' as const,
            todo_type: 'task' as const,
            text: 'Batch test todo item 1',
            status: 'open' as const
          }
        },
        {
          kind: 'section' as const,
          scope: TEST_SCOPE,
          data: {
            title: 'Batch test section',
            heading: 'Test Section',
            body_md: 'This is a test section created in batch'
          }
        },
        {
          kind: 'observation' as const,
          scope: TEST_SCOPE,
          data: {
            entity_type: 'test',
            entity_id: 'test-batch-001',
            observation: 'Batch operation completed successfully',
            observation_type: 'test'
          }
        }
      ];

      const result = await memoryStore(batchData);

      expect(result.errors).toHaveLength(0);
      expect(result.stored).toHaveLength(3);
      expect(result.autonomous_context.action_performed).toBe('batch');

      const storedKinds = result.stored.map(s => s.kind).sort();
      const expectedKinds = ['observation', 'section', 'todo'].sort();
      expect(storedKinds).toEqual(expectedKinds);

      console.log('✅ Batch operation test passed - stored', result.stored.length, 'items of types:', storedKinds.join(', '));
    });
  });

  describe('PHASE 5: ERROR HANDLING AND VALIDATION', () => {

    it('should handle invalid knowledge type gracefully', async () => {
      const result = await memoryStore([
        {
          kind: 'invalid_type' as any,
          scope: TEST_SCOPE,
          data: {
            title: 'This should fail'
          }
        }
      ]);

      expect(result.errors).toHaveLength(1);
      expect(result.stored).toHaveLength(0);
      expect(result.errors[0].error_code).toContain('INVALID');

      console.log('✅ Invalid knowledge type handled gracefully');
    });

    it('should handle missing required fields', async () => {
      const result = await memoryStore([
        {
          kind: 'decision',
          scope: TEST_SCOPE,
          data: {
            // Missing required fields: component, title, rationale
            status: 'proposed'
          } as any
        }
      ]);

      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.stored).toHaveLength(0);

      console.log('✅ Missing required fields validation test passed');
    });

    it('should handle malformed data gracefully', async () => {
      const result = await memoryStore([
        {
          kind: 'todo',
          scope: TEST_SCOPE,
          data: {
            scope: 'task',
            todo_type: 'invalid_type' as any, // Invalid enum value
            text: 'Test todo',
            status: 'open'
          }
        }
      ]);

      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.stored).toHaveLength(0);

      console.log('✅ Malformed data validation test passed');
    });
  });

  describe('PHASE 6: PERFORMANCE AND STRESS TESTING', () => {

    it('should handle concurrent memory operations', async () => {
      const concurrentOperations = Array.from({ length: 10 }, (_, i) =>
        memoryStore([
          {
            kind: 'todo' as const,
            scope: { ...TEST_SCOPE, test: `concurrent-${i}` },
            data: {
              scope: 'task' as const,
              todo_type: 'task' as const,
              text: `Concurrent test todo ${i}`,
              status: 'open' as const
            }
          }
        ])
      );

      const results = await Promise.all(concurrentOperations);

      // All operations should succeed
      results.forEach((result, index) => {
        expect(result.errors).toHaveLength(0);
        expect(result.stored).toHaveLength(1);
        expect(result.stored[0].kind).toBe('todo');
      });

      console.log('✅ Concurrent operations test passed -', results.length, 'operations completed successfully');
    });

    it('should maintain performance with large result sets', async () => {
      const startTime = Date.now();

      const result = await memoryFind({
        query: 'test',
        scope: TEST_SCOPE,
        top_k: 50,
        mode: 'deep'
      });

      const duration = Date.now() - startTime;

      expect(duration).toBeLessThan(5000); // Should complete within 5 seconds
      expect(result.debug).toBeDefined();
      expect(result.debug.query_duration_ms).toBeLessThan(5000);

      console.log(`✅ Performance test passed - ${result.hits.length} results in ${duration}ms (${result.debug.query_duration_ms}ms internal)`);
    });
  });
});