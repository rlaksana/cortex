/**
 * MCP Knowledge Types Comprehensive Test
 *
 * This test verifies that all 16 knowledge types work correctly through the MCP protocol.
 * It tests storage, retrieval, validation, and advanced features for each knowledge type.
 *
 * Knowledge Types Tested:
 * 1. entity - Graph nodes representing concepts/objects
 * 2. relation - Graph edges connecting entities
 * 3. observation - Fine-grained data attached to entities
 * 4. section - Document containers for organizing knowledge
 * 5. runbook - Step-by-step operational procedures
 * 6. change - Code change tracking and history
 * 7. issue - Bug tracking and problem management
 * 8. decision - Architecture Decision Records (ADRs)
 * 9. todo - Task and action item tracking
 * 10. release_note - Release documentation and changelogs
 * 11. ddl - Database schema migration history
 * 12. pr_context - Pull request metadata and context
 * 13. incident - Incident response and management
 * 14. release - Release deployment tracking
 * 15. risk - Risk assessment and mitigation
 * 16. assumption - Business and technical assumptions
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { createMcpServer } from '../../src/index';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';

// Mock OpenAI embeddings
vi.mock('openai', () => ({
  OpenAI: class {
    async embeddings() {
      return {
        data: [{ embedding: Array(1536).fill(0.1) }],
      };
    }
  },
}));

// Mock Qdrant client
vi.mock('@qdrant/js-client-rest', () => ({
  QdrantClient: class {
    constructor() {}
    async getCollections() {
      return { collections: [] };
    }
    async createCollection() {
      return undefined;
    }
    async upsert() {
      return { status: 'completed' };
    }
    async search() {
      return [];
    }
    async getCollection() {
      return { points_count: 0, status: 'green' };
    }
    async delete() {
      return { status: 'completed' };
    }
    async count() {
      return { count: 0 };
    }
    async healthCheck() {
      return true;
    }
  },
}));

describe('MCP Knowledge Types Comprehensive Test', () => {
  let server: McpServer;
  let transport: InMemoryTransport;
  let client: any;

  beforeEach(async () => {
    // Set up environment
    process.env['OPENAI_API_KEY'] = 'test-key';
    process.env['QDRANT_URL'] = 'http://localhost:6333';
    process.env['NODE_ENV'] = 'test';

    // Create MCP server
    server = createMcpServer();
    transport = new InMemoryTransport();

    // Connect client and server
    await server.connect(transport);
    client = transport.client;
  });

  afterEach(async () => {
    if (server) {
      await server.close();
    }
  });

  describe('Core Knowledge Types - Storage and Retrieval', () => {
    it('should handle entity knowledge type through MCP', async () => {
      const entityItem = {
        kind: 'entity' as const,
        data: {
          entity_type: 'user',
          name: 'john_doe',
          data: {
            email: 'john@example.com',
            role: 'developer',
            department: 'engineering',
          },
        },
        scope: {
          project: 'user-management',
          branch: 'main',
        },
        content: 'Entity: user john_doe, developer in engineering department',
      };

      // Store entity via MCP
      const storeResult = await client.request({
        method: 'tools/call',
        params: {
          name: 'memory_store',
          arguments: {
            items: [entityItem],
            deduplication: {
              enabled: true,
              merge_strategy: 'intelligent',
            },
          },
        },
      });

      expect(storeResult.content).toBeDefined();
      expect(storeResult.content[0].type).toBe('text');

      const resultData = JSON.parse(storeResult.content[0].text);
      expect(resultData.stored).toHaveLength(1);
      expect(resultData.stored[0].kind).toBe('entity');
      expect(resultData.stored[0].data.entity_type).toBe('user');
      expect(resultData.stored[0].data.name).toBe('john_doe');

      // Search for entity via MCP
      const searchResult = await client.request({
        method: 'tools/call',
        params: {
          name: 'memory_find',
          arguments: {
            query: 'john doe developer',
            types: ['entity'],
            limit: 10,
          },
        },
      });

      expect(searchResult.content).toBeDefined();
      const searchData = JSON.parse(searchResult.content[0].text);
      expect(searchData.results).toBeDefined();
    });

    it('should handle relation knowledge type through MCP', async () => {
      const relationItem = {
        kind: 'relation' as const,
        data: {
          relation_type: 'works_with',
          source_entity: 'john_doe',
          target_entity: 'jane_smith',
          metadata: {
            project: 'web-platform',
            since: '2024-01-15',
          },
        },
        scope: {
          project: 'team-structure',
          branch: 'main',
        },
        content: 'Relation: john_doe works_with jane_smith on web-platform project',
      };

      const storeResult = await client.request({
        method: 'tools/call',
        params: {
          name: 'memory_store',
          arguments: {
            items: [relationItem],
          },
        },
      });

      const resultData = JSON.parse(storeResult.content[0].text);
      expect(resultData.stored).toHaveLength(1);
      expect(resultData.stored[0].kind).toBe('relation');
      expect(resultData.stored[0].data.relation_type).toBe('works_with');
    });

    it('should handle observation knowledge type through MCP', async () => {
      const observationItem = {
        kind: 'observation' as const,
        data: {
          observed_entity: 'user_session',
          observation_type: 'behavior_pattern',
          details: {
            action: 'login_attempt',
            timestamp: '2025-01-15T10:30:00Z',
            success: true,
            location: 'New York',
            device: 'mobile',
          },
        },
        scope: {
          project: 'user-analytics',
          branch: 'production',
        },
        content: 'Observation: user login attempt from mobile device in New York',
      };

      const storeResult = await client.request({
        method: 'tools/call',
        params: {
          name: 'memory_store',
          arguments: {
            items: [observationItem],
          },
        },
      });

      const resultData = JSON.parse(storeResult.content[0].text);
      expect(resultData.stored).toHaveLength(1);
      expect(resultData.stored[0].kind).toBe('observation');
      expect(resultData.stored[0].data.observation_type).toBe('behavior_pattern');
    });

    it('should handle section knowledge type through MCP', async () => {
      const sectionItem = {
        kind: 'section' as const,
        data: {
          section_type: 'documentation',
          title: 'API Authentication Guide',
          content: 'This section covers OAuth 2.0 implementation details...',
          metadata: {
            author: 'technical-writer',
            last_updated: '2025-01-10',
            version: '2.1',
          },
        },
        scope: {
          project: 'api-docs',
          branch: 'main',
        },
        content: 'Section: API Authentication Guide covering OAuth 2.0 implementation',
      };

      const storeResult = await client.request({
        method: 'tools/call',
        params: {
          name: 'memory_store',
          arguments: {
            items: [sectionItem],
          },
        },
      });

      const resultData = JSON.parse(storeResult.content[0].text);
      expect(resultData.stored).toHaveLength(1);
      expect(resultData.stored[0].kind).toBe('section');
      expect(resultData.stored[0].data.section_type).toBe('documentation');
    });

    it('should handle runbook knowledge type through MCP', async () => {
      const runbookItem = {
        kind: 'runbook' as const,
        data: {
          title: 'Database Backup Restoration',
          purpose: 'Restore PostgreSQL database from backup',
          prerequisites: [
            'Valid backup file available',
            'Database access credentials',
            'Sufficient disk space',
          ],
          steps: [
            'Stop application services',
            'Create current database backup',
            'Restore from backup file',
            'Verify data integrity',
            'Restart application services',
          ],
          troubleshooting: {
            common_issues: [
              'Insufficient disk space',
              'Permission denied errors',
              'Network connectivity issues',
            ],
            solutions: [
              'Free up disk space before restoration',
              'Verify user permissions',
              'Check network configuration',
            ],
          },
          estimated_time: '30 minutes',
          complexity: 'medium',
        },
        scope: {
          project: 'operations',
          branch: 'main',
        },
        content: 'Runbook: Database Backup Restoration procedure with troubleshooting steps',
      };

      const storeResult = await client.request({
        method: 'tools/call',
        params: {
          name: 'memory_store',
          arguments: {
            items: [runbookItem],
          },
        },
      });

      const resultData = JSON.parse(storeResult.content[0].text);
      expect(resultData.stored).toHaveLength(1);
      expect(resultData.stored[0].kind).toBe('runbook');
      expect(resultData.stored[0].data.title).toBe('Database Backup Restoration');
      expect(resultData.stored[0].data.steps).toHaveLength(5);
    });
  });

  describe('Development and Tracking Knowledge Types', () => {
    it('should handle change knowledge type through MCP', async () => {
      const changeItem = {
        kind: 'change' as const,
        data: {
          change_type: 'feature',
          title: 'Add OAuth 2.0 authentication',
          description: 'Implement OAuth 2.0 with JWT token support',
          files_modified: [
            'src/auth/oauth.service.ts',
            'src/middleware/auth.middleware.ts',
            'tests/auth/oauth.test.ts',
          ],
          impact: {
            breaking_changes: false,
            api_changes: true,
            database_changes: false,
          },
          metadata: {
            author: 'backend-team',
            pull_request: '#1234',
            commit_hash: 'abc123def456',
          },
        },
        scope: {
          project: 'user-service',
          branch: 'feature/oauth-implementation',
        },
        content: 'Change: Add OAuth 2.0 authentication with JWT token support',
      };

      const storeResult = await client.request({
        method: 'tools/call',
        params: {
          name: 'memory_store',
          arguments: {
            items: [changeItem],
          },
        },
      });

      const resultData = JSON.parse(storeResult.content[0].text);
      expect(resultData.stored).toHaveLength(1);
      expect(resultData.stored[0].kind).toBe('change');
      expect(resultData.stored[0].data.change_type).toBe('feature');
    });

    it('should handle issue knowledge type through MCP', async () => {
      const issueItem = {
        kind: 'issue' as const,
        data: {
          title: 'Memory leak in batch processing',
          description: 'Memory usage increases continuously during large batch operations',
          severity: 'high',
          priority: 'P1',
          status: 'open',
          category: 'performance',
          steps_to_reproduce: [
            'Process large dataset (>100k records)',
            'Monitor memory usage',
            'Observe continuous increase',
          ],
          expected_behavior: 'Memory usage should remain stable',
          actual_behavior: 'Memory usage increases until application crashes',
          environment: 'production',
          affected_users: 'all',
          reported_by: 'monitoring-system',
          assigned_to: 'backend-team',
        },
        scope: {
          project: 'data-processing',
          branch: 'main',
        },
        content: 'Issue: Memory leak in batch processing causing application crashes',
      };

      const storeResult = await client.request({
        method: 'tools/call',
        params: {
          name: 'memory_store',
          arguments: {
            items: [issueItem],
          },
        },
      });

      const resultData = JSON.parse(storeResult.content[0].text);
      expect(resultData.stored).toHaveLength(1);
      expect(resultData.stored[0].kind).toBe('issue');
      expect(resultData.stored[0].data.severity).toBe('high');
      expect(resultData.stored[0].data.priority).toBe('P1');
    });

    it('should handle decision knowledge type through MCP', async () => {
      const decisionItem = {
        kind: 'decision' as const,
        data: {
          title: 'Use PostgreSQL as Primary Database',
          rationale: 'Strong ACID compliance, advanced JSON support, and mature ecosystem',
          alternatives: [
            {
              option: 'MongoDB',
              pros: ['Flexible schema', 'Horizontal scaling'],
              cons: ['Weaker consistency', 'Less mature JSON features'],
            },
            {
              option: 'MySQL',
              pros: ['Mature', 'Good performance'],
              cons: ['Limited JSON support', 'Complex licensing'],
            },
          ],
          decision: 'PostgreSQL',
          impact: {
            level: 'high',
            affected_components: ['data-layer', 'migration-scripts', 'monitoring'],
            migration_effort: 'medium',
          },
          status: 'accepted',
          decision_date: '2025-01-01',
          decision_maker: 'architecture-committee',
          review_date: '2025-06-01',
        },
        scope: {
          project: 'platform-architecture',
          branch: 'main',
        },
        content: 'Decision: Use PostgreSQL as Primary Database for ACID compliance',
      };

      const storeResult = await client.request({
        method: 'tools/call',
        params: {
          name: 'memory_store',
          arguments: {
            items: [decisionItem],
          },
        },
      });

      const resultData = JSON.parse(storeResult.content[0].text);
      expect(resultData.stored).toHaveLength(1);
      expect(resultData.stored[0].kind).toBe('decision');
      expect(resultData.stored[0].data.status).toBe('accepted');
      expect(resultData.stored[0].data.alternatives).toHaveLength(2);
    });

    it('should handle todo knowledge type through MCP', async () => {
      const todoItem = {
        kind: 'todo' as const,
        data: {
          title: 'Implement database connection pooling',
          description: 'Add connection pooling to improve database performance under load',
          priority: 'high',
          status: 'in_progress',
          assignee: 'backend-team',
          due_date: '2025-01-20',
          estimated_hours: 16,
          tags: ['performance', 'database', 'infrastructure'],
          subtasks: [
            'Research connection pooling libraries',
            'Implement pool configuration',
            'Add health checks for pool',
            'Update database client code',
            'Add performance monitoring',
            'Write integration tests',
          ],
          dependencies: ['database-migration-completed'],
          definition_of_done: [
            'Connection pooling implemented',
            'Performance tests show improvement',
            'Health checks working',
            'Documentation updated',
            'Code reviewed and merged',
          ],
        },
        scope: {
          project: 'performance-improvements',
          branch: 'feature/connection-pooling',
        },
        content: 'Todo: Implement database connection pooling for performance improvement',
      };

      const storeResult = await client.request({
        method: 'tools/call',
        params: {
          name: 'memory_store',
          arguments: {
            items: [todoItem],
          },
        },
      });

      const resultData = JSON.parse(storeResult.content[0].text);
      expect(resultData.stored).toHaveLength(1);
      expect(resultData.stored[0].kind).toBe('todo');
      expect(resultData.stored[0].data.status).toBe('in_progress');
      expect(resultData.stored[0].data.subtasks).toHaveLength(6);
    });
  });

  describe('Release and Deployment Knowledge Types', () => {
    it('should handle release_note knowledge type through MCP', async () => {
      const releaseNoteItem = {
        kind: 'release_note' as const,
        data: {
          version: '2.1.0',
          release_date: '2025-01-15',
          title: 'Performance Enhancements and Bug Fixes',
          summary:
            'This release includes significant performance improvements and critical bug fixes',
          features: [
            'Added database connection pooling',
            'Implemented response caching',
            'Enhanced search performance',
          ],
          bug_fixes: [
            'Fixed memory leak in batch processing',
            'Resolved authentication timeout issue',
            'Fixed data validation errors',
          ],
          breaking_changes: [],
          known_issues: ['Minor UI glitch in Safari (under investigation)'],
          upgrade_notes: [
            'Database migration required',
            'Update configuration files',
            'Clear cache after upgrade',
          ],
          contributor: 'release-team',
        },
        scope: {
          project: 'platform',
          branch: 'release/v2.1.0',
        },
        content: 'Release Note: Version 2.1.0 with performance enhancements and bug fixes',
      };

      const storeResult = await client.request({
        method: 'tools/call',
        params: {
          name: 'memory_store',
          arguments: {
            items: [releaseNoteItem],
          },
        },
      });

      const resultData = JSON.parse(storeResult.content[0].text);
      expect(resultData.stored).toHaveLength(1);
      expect(resultData.stored[0].kind).toBe('release_note');
      expect(resultData.stored[0].data.version).toBe('2.1.0');
      expect(resultData.stored[0].data.features).toHaveLength(3);
    });

    it('should handle ddl knowledge type through MCP', async () => {
      const ddlItem = {
        kind: 'ddl' as const,
        data: {
          migration_name: 'add_user_preferences_table',
          version: '20250115_001_add_user_preferences',
          database: 'postgresql',
          environment: 'production',
          sql_up: `
            CREATE TABLE user_preferences (
              id SERIAL PRIMARY KEY,
              user_id INTEGER NOT NULL REFERENCES users(id),
              preference_key VARCHAR(100) NOT NULL,
              preference_value TEXT,
              created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
              updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
              UNIQUE(user_id, preference_key)
            );

            CREATE INDEX idx_user_preferences_user_id ON user_preferences(user_id);
          `,
          sql_down: `
            DROP TABLE IF EXISTS user_preferences;
          `,
          description: 'Add user preferences table for storing user-specific settings',
          impact: {
            tables_added: ['user_preferences'],
            tables_modified: [],
            indexes_added: ['idx_user_preferences_user_id'],
            estimated_downtime: '0 minutes',
          },
          rollback_plan: 'Execute down migration to remove table and indexes',
          tested: true,
          test_results: 'All tests passed, performance impact minimal',
        },
        scope: {
          project: 'database-migrations',
          branch: 'main',
        },
        content: 'DDL: Migration to add user_preferences table with proper indexing',
      };

      const storeResult = await client.request({
        method: 'tools/call',
        params: {
          name: 'memory_store',
          arguments: {
            items: [ddlItem],
          },
        },
      });

      const resultData = JSON.parse(storeResult.content[0].text);
      expect(resultData.stored).toHaveLength(1);
      expect(resultData.stored[0].kind).toBe('ddl');
      expect(resultData.stored[0].data.version).toBe('20250115_001_add_user_preferences');
    });

    it('should handle pr_context knowledge type through MCP', async () => {
      const prContextItem = {
        kind: 'pr_context' as const,
        data: {
          pr_number: 1234,
          title: 'Add OAuth 2.0 authentication support',
          description: 'Implements OAuth 2.0 with JWT tokens for secure authentication',
          author: 'developer-1',
          reviewers: ['senior-dev-1', 'tech-lead-1'],
          source_branch: 'feature/oauth-implementation',
          target_branch: 'main',
          status: 'open',
          created_at: '2025-01-10T10:00:00Z',
          updated_at: '2025-01-15T14:30:00Z',
          files_changed: 15,
          lines_added: 450,
          lines_removed: 120,
          commits: 8,
          checks_status: 'passing',
          conflicts: false,
          labels: ['feature', 'authentication', 'security'],
          related_issues: ['#567', '#568'],
          approval_status: 'approved',
          mergeable: true,
        },
        scope: {
          project: 'user-service',
          branch: 'feature/oauth-implementation',
        },
        content: 'PR Context: Add OAuth 2.0 authentication support with comprehensive testing',
      };

      const storeResult = await client.request({
        method: 'tools/call',
        params: {
          name: 'memory_store',
          arguments: {
            items: [prContextItem],
          },
        },
      });

      const resultData = JSON.parse(storeResult.content[0].text);
      expect(resultData.stored).toHaveLength(1);
      expect(resultData.stored[0].kind).toBe('pr_context');
      expect(resultData.stored[0].data.pr_number).toBe(1234);
      expect(resultData.stored[0].data.status).toBe('open');
    });

    it('should handle incident knowledge type through MCP', async () => {
      const incidentItem = {
        kind: 'incident' as const,
        data: {
          incident_id: 'INC-2025-001',
          title: 'Database connection pool exhaustion',
          severity: 'high',
          priority: 'P0',
          status: 'resolved',
          category: 'infrastructure',
          impact: {
            affected_services: ['user-api', 'order-service', 'notification-service'],
            user_impact: 'high',
            business_impact: 'revenue loss',
            estimated_affected_users: 50000,
          },
          timeline: {
            detected_at: '2025-01-15T09:15:00Z',
            acknowledged_at: '2025-01-15T09:20:00Z',
            mitigated_at: '2025-01-15T10:30:00Z',
            resolved_at: '2025-01-15T11:45:00Z',
            duration_minutes: 150,
          },
          root_cause: {
            primary: 'Database connection pool not properly configured for high traffic',
            contributing: ['Insufficient monitoring', 'Missing alert thresholds'],
          },
          resolution: {
            description: 'Increased connection pool size and added proper monitoring',
            permanent_fix: 'Updated configuration and added alerting',
            preventive_measures: ['Add load testing', 'Implement circuit breakers'],
          },
          lessons_learned: [
            'Need better capacity planning',
            'Monitoring gaps identified',
            'Response time can be improved',
          ],
          postmortem_required: true,
          communication_sent: true,
        },
        scope: {
          project: 'incident-management',
          branch: 'main',
        },
        content: 'Incident: Database connection pool exhaustion affecting multiple services',
      };

      const storeResult = await client.request({
        method: 'tools/call',
        params: {
          name: 'memory_store',
          arguments: {
            items: [incidentItem],
          },
        },
      });

      const resultData = JSON.parse(storeResult.content[0].text);
      expect(resultData.stored).toHaveLength(1);
      expect(resultData.stored[0].kind).toBe('incident');
      expect(resultData.stored[0].data.severity).toBe('high');
      expect(resultData.stored[0].data.status).toBe('resolved');
    });

    it('should handle release knowledge type through MCP', async () => {
      const releaseItem = {
        kind: 'release' as const,
        data: {
          release_name: 'v2.1.0',
          version: '2.1.0',
          release_type: 'minor',
          status: 'deployed',
          created_at: '2025-01-15T08:00:00Z',
          deployed_at: '2025-01-15T10:30:00Z',
          environment: 'production',
          description: 'Performance enhancements and critical bug fixes',
          features: ['Database connection pooling', 'Response caching', 'Enhanced search'],
          fixes: ['Memory leak resolution', 'Authentication fixes', 'UI improvements'],
          deployment_info: {
            deployment_strategy: 'blue-green',
            rollback_available: true,
            health_checks_passed: true,
            monitoring_active: true,
          },
          metrics: {
            deployment_duration_minutes: 45,
            rollback_time_seconds: 0,
            post_deployment_issues: 0,
          },
          release_manager: 'devops-team',
          approval_status: 'approved',
        },
        scope: {
          project: 'platform',
          branch: 'release/v2.1.0',
        },
        content: 'Release: v2.1.0 successfully deployed to production',
      };

      const storeResult = await client.request({
        method: 'tools/call',
        params: {
          name: 'memory_store',
          arguments: {
            items: [releaseItem],
          },
        },
      });

      const resultData = JSON.parse(storeResult.content[0].text);
      expect(resultData.stored).toHaveLength(1);
      expect(resultData.stored[0].kind).toBe('release');
      expect(resultData.stored[0].data.status).toBe('deployed');
      expect(resultData.stored[0].data.version).toBe('2.1.0');
    });
  });

  describe('Risk and Planning Knowledge Types', () => {
    it('should handle risk knowledge type through MCP', async () => {
      const riskItem = {
        kind: 'risk' as const,
        data: {
          title: 'Database vendor lock-in risk',
          category: 'technical',
          probability: 'medium',
          impact: 'high',
          risk_score: 12, // probability (3) x impact (4)
          description:
            'Heavy reliance on PostgreSQL-specific features may limit future flexibility',
          triggers: [
            'Need to migrate to different database',
            'PostgreSQL licensing changes',
            'Performance requirements exceed PostgreSQL capabilities',
          ],
          mitigations: [
            {
              strategy: 'Use database abstraction layer',
              implementation: 'Implement repository pattern with database-agnostic interfaces',
              owner: 'architecture-team',
              due_date: '2025-03-01',
              status: 'in_progress',
            },
            {
              strategy: 'Multi-database testing',
              implementation: 'Set up testing environments with alternative databases',
              owner: 'qa-team',
              due_date: '2025-04-01',
              status: 'planned',
            },
          ],
          contingency_plans: [
            'Develop migration scripts for PostgreSQL alternatives',
            'Document PostgreSQL-specific features used',
            'Evaluate cloud database services',
          ],
          owner: 'cto',
          review_date: '2025-06-01',
          status: 'active',
        },
        scope: {
          project: 'platform-architecture',
          branch: 'main',
        },
        content: 'Risk: Database vendor lock-in with medium probability and high impact',
      };

      const storeResult = await client.request({
        method: 'tools/call',
        params: {
          name: 'memory_store',
          arguments: {
            items: [riskItem],
          },
        },
      });

      const resultData = JSON.parse(storeResult.content[0].text);
      expect(resultData.stored).toHaveLength(1);
      expect(resultData.stored[0].kind).toBe('risk');
      expect(resultData.stored[0].data.category).toBe('technical');
      expect(resultData.stored[0].data.risk_score).toBe(12);
      expect(resultData.stored[0].data.mitigations).toHaveLength(2);
    });

    it('should handle assumption knowledge type through MCP', async () => {
      const assumptionItem = {
        kind: 'assumption' as const,
        data: {
          title: 'User adoption of new features will be high',
          category: 'business',
          description:
            'Assumes users will quickly adopt new features based on positive feedback from beta testing',
          impact_level: 'high',
          confidence_level: 'medium',
          validation_method: 'User feedback surveys and usage analytics',
          validation_date: '2025-03-01',
          made_by: 'product-team',
          made_date: '2025-01-01',
          supporting_evidence: [
            'Beta testing showed 80% positive feedback',
            'Similar features in competitors have high adoption',
            'User requests indicate high demand',
          ],
          risks_if_invalid: [
            'Lower than expected revenue',
            'Feature development resources wasted',
            'Need for additional user training',
          ],
          monitoring_plan: [
            'Track feature adoption rates weekly',
            'Monitor user feedback channels',
            'Analyze usage patterns and drop-off points',
          ],
          status: 'active',
        },
        scope: {
          project: 'product-development',
          branch: 'main',
        },
        content: 'Assumption: High user adoption of new features based on beta testing feedback',
      };

      const storeResult = await client.request({
        method: 'tools/call',
        params: {
          name: 'memory_store',
          arguments: {
            items: [assumptionItem],
          },
        },
      });

      const resultData = JSON.parse(storeResult.content[0].text);
      expect(resultData.stored).toHaveLength(1);
      expect(resultData.stored[0].kind).toBe('assumption');
      expect(resultData.stored[0].data.category).toBe('business');
      expect(resultData.stored[0].data.confidence_level).toBe('medium');
    });
  });

  describe('Advanced Features Testing', () => {
    it('should handle TTL policies for all knowledge types through MCP', async () => {
      const knowledgeTypesWithTTL = [
        { kind: 'entity' as const, ttl_policy: 'short' as const },
        { kind: 'decision' as const, ttl_policy: 'long' as const },
        { kind: 'incident' as const, ttl_policy: 'permanent' as const },
        { kind: 'todo' as const, ttl_policy: 'default' as const },
      ];

      for (const typeConfig of knowledgeTypesWithTTL) {
        const item = {
          kind: typeConfig.kind,
          data: {
            title: `Test ${typeConfig.kind} with TTL`,
            description: `Testing ${typeConfig['ttl_policy']} TTL policy`,
          },
          scope: {
            project: 'ttl-testing',
            branch: 'main',
          },
          ttl_config: {
            policy: typeConfig['ttl_policy'],
            auto_extend: typeConfig['ttl_policy'] !== 'short',
          },
          content: `${typeConfig.kind} with ${typeConfig['ttl_policy']} TTL policy`,
        };

        const storeResult = await client.request({
          method: 'tools/call',
          params: {
            name: 'memory_store',
            arguments: {
              items: [item],
              global_ttl: {
                policy: typeConfig['ttl_policy'],
                auto_extend: true,
              },
            },
          },
        });

        const resultData = JSON.parse(storeResult.content[0].text);
        expect(resultData.stored).toHaveLength(1);
        expect(resultData.stored[0].kind).toBe(typeConfig.kind);
      }
    });

    it('should handle intelligent deduplication across knowledge types through MCP', async () => {
      const similarItems = [
        {
          kind: 'decision' as const,
          data: {
            title: 'Use OAuth 2.0 for Authentication',
            rationale: 'Industry standard with robust security features',
          },
          scope: { project: 'auth-project', branch: 'main' },
          content: 'Decision to use OAuth 2.0 for authentication',
        },
        {
          kind: 'decision' as const,
          data: {
            title: 'OAuth 2.0 Authentication Implementation',
            rationale: 'Industry standard security approach with robust features',
          },
          scope: { project: 'auth-project', branch: 'main' },
          content: 'Implementation of OAuth 2.0 authentication system',
        },
      ];

      const storeResult = await client.request({
        method: 'tools/call',
        params: {
          name: 'memory_store',
          arguments: {
            items: similarItems,
            deduplication: {
              enabled: true,
              merge_strategy: 'intelligent',
              similarity_threshold: 0.8,
              enable_intelligent_merging: true,
              enable_audit_logging: true,
            },
          },
        },
      });

      const resultData = JSON.parse(storeResult.content[0].text);
      expect(resultData.duplicates_found).toBeGreaterThan(0);
      expect(resultData.stored.length + resultData.errors.length).toBe(2);
    });

    it('should handle graph expansion search through MCP', async () => {
      // First store some related items
      const entity = {
        kind: 'entity' as const,
        data: {
          entity_type: 'user',
          name: 'john_doe',
        },
        scope: { project: 'graph-test', branch: 'main' },
        content: 'Entity: user john_doe',
      };

      const relation = {
        kind: 'relation' as const,
        data: {
          relation_type: 'works_with',
          source_entity: 'john_doe',
          target_entity: 'jane_smith',
        },
        scope: { project: 'graph-test', branch: 'main' },
        content: 'Relation: john_doe works_with jane_smith',
      };

      // Store both items
      await client.request({
        method: 'tools/call',
        params: {
          name: 'memory_store',
          arguments: {
            items: [entity, relation],
          },
        },
      });

      // Search with graph expansion
      const searchResult = await client.request({
        method: 'tools/call',
        params: {
          name: 'memory_find',
          arguments: {
            query: 'john doe',
            types: ['entity'],
            graph_expansion: {
              enabled: true,
              expansion_type: 'relations',
              max_depth: 2,
              max_nodes: 10,
            },
          },
        },
      });

      const searchData = JSON.parse(searchResult.content[0].text);
      expect(searchData.results).toBeDefined();
      expect(searchData.graph_expansion).toBeDefined();
    });
  });

  describe('Cross-Type Search and Filtering', () => {
    it('should search across multiple knowledge types through MCP', async () => {
      // Store items of different types with similar content
      const items = [
        {
          kind: 'decision' as const,
          data: { title: 'Database technology choice', decision: 'PostgreSQL' },
          scope: { project: 'architecture', branch: 'main' },
          content: 'Decision to use PostgreSQL database',
        },
        {
          kind: 'risk' as const,
          data: { title: 'Database risks', description: 'Vendor lock-in concerns' },
          scope: { project: 'architecture', branch: 'main' },
          content: 'Risk assessment for database vendor lock-in',
        },
        {
          kind: 'todo' as const,
          data: { title: 'Database setup', status: 'pending' },
          scope: { project: 'architecture', branch: 'main' },
          content: 'Setup database configuration and connection pooling',
        },
      ];

      await client.request({
        method: 'tools/call',
        params: {
          name: 'memory_store',
          arguments: { items },
        },
      });

      // Search across all types
      const searchResult = await client.request({
        method: 'tools/call',
        params: {
          name: 'memory_find',
          arguments: {
            query: 'database',
            types: ['decision', 'risk', 'todo'],
            limit: 10,
          },
        },
      });

      const searchData = JSON.parse(searchResult.content[0].text);
      expect(searchData.results).toBeDefined();
    });

    it('should filter by scope and time through MCP', async () => {
      const searchResult = await client.request({
        method: 'tools/call',
        params: {
          name: 'memory_find',
          arguments: {
            query: 'test',
            scope: {
              project: 'test-project',
              branch: 'main',
            },
            filters: {
              created_after: '2025-01-01T00:00:00Z',
              confidence_min: 0.5,
            },
            ttl_filters: {
              include_expired: false,
              ttl_policies: ['default', 'long', 'permanent'],
            },
            formatting: {
              include_content: true,
              include_metadata: true,
              include_confidence_scores: true,
            },
          },
        },
      });

      const searchData = JSON.parse(searchResult.content[0].text);
      expect(searchData.results).toBeDefined();
    });
  });

  describe('System Status and Monitoring', () => {
    it('should provide comprehensive system status through MCP', async () => {
      const healthResult = await client.request({
        method: 'tools/call',
        params: {
          name: 'system_status',
          arguments: {
            operation: 'health',
            include_detailed_metrics: true,
            response_formatting: {
              verbose: true,
              include_timestamps: true,
            },
          },
        },
      });

      expect(healthResult.content).toBeDefined();
      const healthData = JSON.parse(healthResult.content[0].text);
      expect(healthData.operation).toBe('health');
      expect(healthData.status).toBeDefined();
      expect(healthData.capabilities).toBeDefined();
      expect(healthData.capabilities.mcp_version).toBeDefined();
      expect(healthData.capabilities.supported_operations).toContain('health');
      expect(healthData.capabilities.knowledge_types).toHaveLength(16);
    });

    it('should provide system statistics through MCP', async () => {
      const statsResult = await client.request({
        method: 'tools/call',
        params: {
          name: 'system_status',
          arguments: {
            operation: 'stats',
            stats_period_days: 30,
            include_detailed_metrics: true,
          },
        },
      });

      const statsData = JSON.parse(statsResult.content[0].text);
      expect(statsData.operation).toBe('stats');
      expect(statsData.data).toBeDefined();
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle invalid knowledge types gracefully through MCP', async () => {
      const invalidItem = {
        kind: 'invalid_type' as any,
        data: { title: 'Invalid item' },
        content: 'This should fail validation',
      };

      const storeResult = await client.request({
        method: 'tools/call',
        params: {
          name: 'memory_store',
          arguments: {
            items: [invalidItem],
          },
        },
      });

      const resultData = JSON.parse(storeResult.content[0].text);
      expect(resultData.stored).toHaveLength(0);
      expect(resultData.errors).toHaveLength(1);
      expect(resultData.errors[0].error_code).toBe('VALIDATION_ERROR');
    });

    it('should handle missing required fields through MCP', async () => {
      const incompleteItem = {
        kind: 'entity' as const,
        // Missing required data fields
        scope: { project: 'test', branch: 'main' },
        content: 'Incomplete entity',
      };

      const storeResult = await client.request({
        method: 'tools/call',
        params: {
          name: 'memory_store',
          arguments: {
            items: [incompleteItem],
          },
        },
      });

      const resultData = JSON.parse(storeResult.content[0].text);
      expect(resultData.stored).toHaveLength(0);
      expect(resultData.errors).toHaveLength(1);
    });

    it('should handle very large content through MCP', async () => {
      const largeContent = 'x'.repeat(10000); // 10KB content
      const largeItem = {
        kind: 'section' as const,
        data: {
          title: 'Large content section',
          content: largeContent,
        },
        scope: { project: 'test', branch: 'main' },
        content: largeContent,
      };

      const storeResult = await client.request({
        method: 'tools/call',
        params: {
          name: 'memory_store',
          arguments: {
            items: [largeItem],
            global_truncation: {
              enabled: true,
              max_chars: 5000,
              mode: 'intelligent',
            },
          },
        },
      });

      const resultData = JSON.parse(storeResult.content[0].text);
      expect(resultData.stored).toHaveLength(1);
      // Content should be truncated
      expect(resultData.stored[0].content.length).toBeLessThanOrEqual(5000);
    });
  });
});
