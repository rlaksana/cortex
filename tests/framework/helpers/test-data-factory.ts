/**
 * Test Data Factory
 *
 * Creates test data for all 16 knowledge types with validation
 * and comprehensive coverage of edge cases.
 */

import { MockDataGenerator } from '../test-setup';
import type {
  EnhancedKnowledgeItem,
  SectionData,
  DecisionData,
  IssueData,
  TodoData,
  RunbookData,
  ChangeData,
  ReleaseNoteData,
  DDLData,
  PRContextData,
  EntityData,
  RelationData,
  ObservationData,
  IncidentData,
  ReleaseData,
  RiskData,
  AssumptionData,
} from '../../../src/types/index';

/**
 * Test data factory for all knowledge types
 */
export class TestDataFactory {
  /**
   * Create a section test item
   */
  createSection(overrides: Partial<SectionData> = {}): EnhancedKnowledgeItem {
    const id = overrides.id || MockDataGenerator.generateUUID();
    return {
      kind: 'section',
      scope: MockDataGenerator.generateScope(),
      data: {
        id,
        title: 'Test Section',
        heading: 'Test Section',
        body_md: MockDataGenerator.generateMarkdown(),
        body_text: MockDataGenerator.generateText(50),
        tags: { category: 'test', priority: 'medium' },
        ...overrides,
      },
      tags: { test: 'true', type: 'section' },
      idempotency_key: MockDataGenerator.generateUUID(),
    };
  }

  /**
   * Create a decision test item
   */
  createDecision(overrides: Partial<DecisionData> = {}): EnhancedKnowledgeItem {
    const id = overrides.id || MockDataGenerator.generateUUID();
    return {
      kind: 'decision',
      scope: MockDataGenerator.generateScope(),
      data: {
        id,
        component: 'auth',
        status: 'proposed',
        title: 'Use OAuth 2.0 for Authentication',
        rationale:
          'OAuth 2.0 is the industry standard for API authentication with comprehensive security features.',
        alternatives_considered: ['Basic Authentication', 'JWT-only', 'API Keys'],
        consequences: 'Requires additional infrastructure for token management',
        supersedes: '',
        ...overrides,
      },
      tags: { test: 'true', type: 'decision', adr: 'true' },
      idempotency_key: MockDataGenerator.generateUUID(),
    };
  }

  /**
   * Create an issue test item
   */
  createIssue(overrides: Partial<IssueData> = {}): EnhancedKnowledgeItem {
    const id = overrides.id || MockDataGenerator.generateUUID();
    return {
      kind: 'issue',
      scope: MockDataGenerator.generateScope(),
      data: {
        id,
        title: 'Authentication Service Timeout',
        description: 'The authentication service is experiencing timeouts under heavy load.',
        severity: 'high',
        status: 'open',
        assignee: 'john.doe@example.com',
        labels: ['bug', 'performance', 'authentication'],
        reported_by: 'jane.smith@example.com',
        reported_at: MockDataGenerator.generateTimestamp(-1),
        ...overrides,
      },
      tags: { test: 'true', type: 'issue', priority: 'high' },
      idempotency_key: MockDataGenerator.generateUUID(),
    };
  }

  /**
   * Create a TODO test item
   */
  createTodo(overrides: Partial<TodoData> = {}): EnhancedKnowledgeItem {
    const id = overrides.id || MockDataGenerator.generateUUID();
    return {
      kind: 'todo',
      scope: MockDataGenerator.generateScope(),
      data: {
        id,
        text: 'Implement rate limiting for authentication endpoints',
        status: 'pending',
        priority: 'high',
        assignee: 'developer@example.com',
        due_date: MockDataGenerator.generateTimestamp(7),
        created_at: MockDataGenerator.generateTimestamp(-2),
        tags: ['backend', 'security', 'performance'],
        ...overrides,
      },
      tags: { test: 'true', type: 'todo', priority: 'high' },
      idempotency_key: MockDataGenerator.generateUUID(),
    };
  }

  /**
   * Create a runbook test item
   */
  createRunbook(overrides: Partial<RunbookData> = {}): EnhancedKnowledgeItem {
    const id = overrides.id || MockDataGenerator.generateUUID();
    return {
      kind: 'runbook',
      scope: MockDataGenerator.generateScope(),
      data: {
        id,
        title: 'Database Backup Recovery',
        service: 'database',
        description: 'Procedures for recovering from database backups',
        steps: [
          {
            name: 'Identify backup to restore',
            command: 'list-backups --latest',
            expected_output: 'backup-2024-01-15.sql',
            timeout_seconds: 30,
          },
          {
            name: 'Stop application services',
            command: 'docker-compose down',
            expected_output: 'Container stopped',
            timeout_seconds: 60,
          },
          {
            name: 'Restore database',
            command: 'psql -d app_db -f backup.sql',
            expected_output: 'RESTORE COMPLETE',
            timeout_seconds: 300,
          },
          {
            name: 'Start application services',
            command: 'docker-compose up -d',
            expected_output: 'Container started',
            timeout_seconds: 60,
          },
        ],
        prerequisites: ['Database access', 'Backup file available'],
        rollback_procedure: 'Restore original database from backup',
        tags: ['database', 'recovery', 'critical'],
        ...overrides,
      },
      tags: { test: 'true', type: 'runbook', category: 'database' },
      idempotency_key: MockDataGenerator.generateUUID(),
    };
  }

  /**
   * Create a change log test item
   */
  createChange(overrides: Partial<ChangeData> = {}): EnhancedKnowledgeItem {
    const id = overrides.id || MockDataGenerator.generateUUID();
    return {
      kind: 'change',
      scope: MockDataGenerator.generateScope(),
      data: {
        id,
        subject_ref: 'AUTH-2024-001',
        summary: 'Add OAuth 2.0 authentication support',
        details:
          'Implemented complete OAuth 2.0 flow with access tokens, refresh tokens, and proper security measures.',
        author: 'security-team@example.com',
        change_type: 'feature',
        impact: 'medium',
        risk_level: 'low',
        test_results: 'All tests passing',
        deployment_notes: 'Requires database migration for token tables',
        rollback_plan: 'Revert to previous authentication method',
        approved_by: 'tech-lead@example.com',
        approved_at: MockDataGenerator.generateTimestamp(-1),
        deployed_at: MockDataGenerator.generateTimestamp(),
        ...overrides,
      },
      tags: { test: 'true', type: 'change', category: 'feature' },
      idempotency_key: MockDataGenerator.generateUUID(),
    };
  }

  /**
   * Create a release note test item
   */
  createReleaseNote(overrides: Partial<ReleaseNoteData> = {}): EnhancedKnowledgeItem {
    const id = overrides.id || MockDataGenerator.generateUUID();
    return {
      kind: 'release_note',
      scope: MockDataGenerator.generateScope(),
      data: {
        id,
        version: 'v2.1.0',
        summary: 'Major release with OAuth 2.0 authentication and performance improvements',
        features: [
          'OAuth 2.0 authentication support',
          'Improved search performance',
          'Enhanced error handling',
          'New admin dashboard',
        ],
        bug_fixes: [
          'Fixed authentication timeout issue',
          'Resolved memory leak in search service',
          'Fixed CORS configuration',
        ],
        breaking_changes: [
          'Authentication API endpoint changed',
          'Database schema update required',
        ],
        migration_notes: 'Run migration script migrate-v2.1.0.sql before upgrade',
        security_notes: 'Update all API clients to use OAuth 2.0 flow',
        ...overrides,
      },
      tags: { test: 'true', type: 'release_note', version: 'v2.1.0' },
      idempotency_key: MockDataGenerator.generateUUID(),
    };
  }

  /**
   * Create a DDL test item
   */
  createDDL(overrides: Partial<DDLData> = {}): EnhancedKnowledgeItem {
    const id = overrides.id || MockDataGenerator.generateUUID();
    return {
      kind: 'ddl',
      scope: MockDataGenerator.generateScope(),
      data: {
        id,
        migration_id: '2024_01_15_add_oauth_tokens.sql',
        description: 'Add OAuth 2.0 token tables and indexes',
        sql_content: `
          CREATE TABLE oauth_tokens (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id UUID NOT NULL REFERENCES users(id),
            access_token TEXT NOT NULL,
            refresh_token TEXT NOT NULL,
            expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
          );

          CREATE INDEX idx_oauth_tokens_user_id ON oauth_tokens(user_id);
          CREATE INDEX idx_oauth_tokens_expires_at ON oauth_tokens(expires_at);
        `,
        checksum: 'abc123def456',
        applied_at: MockDataGenerator.generateTimestamp(-1),
        applied_by: 'migration-system',
        rollback_sql: `
          DROP TABLE IF EXISTS oauth_tokens;
        `,
        dependencies: ['2024_01_10_add_users_table.sql'],
        impact: 'medium',
        risk_level: 'low',
        ...overrides,
      },
      tags: { test: 'true', type: 'ddl', category: 'database' },
      idempotency_key: MockDataGenerator.generateUUID(),
    };
  }

  /**
   * Create a PR context test item
   */
  createPRContext(overrides: Partial<PRContextData> = {}): EnhancedKnowledgeItem {
    const id = overrides.id || MockDataGenerator.generateUUID();
    return {
      kind: 'pr_context',
      scope: MockDataGenerator.generateScope(),
      data: {
        id,
        title: 'Add OAuth 2.0 authentication support',
        description:
          'This PR implements OAuth 2.0 authentication with proper security measures and comprehensive testing.',
        pr_number: 1234,
        author: 'developer@example.com',
        reviewers: ['tech-lead@example.com', 'security-team@example.com'],
        status: 'merged',
        merge_commit: 'abc123def456',
        base_branch: 'main',
        head_branch: 'feature/oauth-implementation',
        files_changed: 15,
        additions: 500,
        deletions: 50,
        tests_added: 25,
        tests_passed: true,
        coverage_change: 5.2,
        performance_impact: 'positive',
        security_review: 'approved',
        documentation_updated: true,
        breaking_change: false,
        migration_required: true,
        ...overrides,
      },
      tags: { test: 'true', type: 'pr_context', pr_number: '1234' },
      idempotency_key: MockDataGenerator.generateUUID(),
    };
  }

  /**
   * Create an entity test item
   */
  createEntity(overrides: Partial<EntityData> = {}): EnhancedKnowledgeItem {
    const id = overrides.id || MockDataGenerator.generateUUID();
    return {
      kind: 'entity',
      scope: MockDataGenerator.generateScope(),
      data: {
        id,
        entity_type: 'service',
        name: 'Authentication Service',
        description: 'Handles user authentication and authorization using OAuth 2.0',
        properties: {
          version: '2.1.0',
          language: 'TypeScript',
          framework: 'Node.js',
          database: 'PostgreSQL',
          cache: 'Redis',
        },
        status: 'active',
        owner: 'security-team@example.com',
        created_by: 'architect@example.com',
        created_at: MockDataGenerator.generateTimestamp(-30),
        updated_at: MockDataGenerator.generateTimestamp(-1),
        tags: ['microservice', 'security', 'oauth', 'critical'],
        ...overrides,
      },
      tags: { test: 'true', type: 'entity', category: 'service' },
      idempotency_key: MockDataGenerator.generateUUID(),
    };
  }

  /**
   * Create a relation test item
   */
  createRelation(overrides: Partial<RelationData> = {}): EnhancedKnowledgeItem {
    const id = overrides.id || MockDataGenerator.generateUUID();
    return {
      kind: 'relation',
      scope: MockDataGenerator.generateScope(),
      data: {
        id,
        from_entity_type: 'service',
        from_entity_id: MockDataGenerator.generateUUID(),
        to_entity_type: 'service',
        to_entity_id: MockDataGenerator.generateUUID(),
        relation_type: 'depends_on',
        description: 'Authentication service depends on User service for user validation',
        properties: {
          dependency_type: 'service',
          criticality: 'high',
          fallback_available: false,
          monitoring_enabled: true,
        },
        strength: 0.8,
        bidirectional: false,
        created_by: 'architect@example.com',
        created_at: MockDataGenerator.generateTimestamp(-15),
        updated_at: MockDataGenerator.generateTimestamp(-5),
        tags: ['dependency', 'service', 'critical'],
        ...overrides,
      },
      tags: { test: 'true', type: 'relation', category: 'dependency' },
      idempotency_key: MockDataGenerator.generateUUID(),
    };
  }

  /**
   * Create an observation test item
   */
  createObservation(overrides: Partial<ObservationData> = {}): EnhancedKnowledgeItem {
    const id = overrides.id || MockDataGenerator.generateUUID();
    return {
      kind: 'observation',
      scope: MockDataGenerator.generateScope(),
      data: {
        id,
        entity_type: 'service',
        entity_id: MockDataGenerator.generateUUID(),
        observation_type: 'performance_metric',
        key: 'response_time_p95',
        value: 150,
        unit: 'milliseconds',
        timestamp: MockDataGenerator.generateTimestamp(-1),
        source: 'prometheus',
        context: {
          endpoint: '/api/auth/login',
          method: 'POST',
          status_code: '200',
          region: 'us-east-1',
        },
        confidence: 0.95,
        verified: true,
        tags: ['performance', 'monitoring', 'authentication'],
        ...overrides,
      },
      tags: { test: 'true', type: 'observation', category: 'performance' },
      idempotency_key: MockDataGenerator.generateUUID(),
    };
  }

  /**
   * Create an incident test item
   */
  createIncident(overrides: Partial<IncidentData> = {}): EnhancedKnowledgeItem {
    const id = overrides.id || MockDataGenerator.generateUUID();
    return {
      kind: 'incident',
      scope: MockDataGenerator.generateScope(),
      data: {
        id,
        title: 'Authentication Service Outage',
        severity: 'critical',
        impact: 'Users unable to log in to the application',
        status: 'resolved',
        detected_at: MockDataGenerator.generateTimestamp(-3),
        resolved_at: MockDataGenerator.generateTimestamp(-1),
        duration_minutes: 120,
        affected_services: ['authentication-service', 'user-service'],
        affected_users: 5000,
        root_cause_analysis: 'Database connection pool exhaustion due to memory leak',
        resolution: 'Fixed memory leak and increased connection pool size',
        prevention_measures: [
          'Added memory monitoring alerts',
          'Implemented connection pool monitoring',
          'Added circuit breaker pattern',
        ],
        lessons_learned: [
          'Need better monitoring of resource usage',
          'Implement gradual rollout for critical services',
        ],
        post_mortem_link: 'https://incident-reports.example.com/auth-outage-2024-01',
        coordinator: 'ops-team@example.com',
        participants: ['dev-team@example.com', 'ops-team@example.com'],
        communication_channels: ['#incidents', '#engineering'],
        ...overrides,
      },
      tags: { test: 'true', type: 'incident', severity: 'critical' },
      idempotency_key: MockDataGenerator.generateUUID(),
    };
  }

  /**
   * Create a release test item
   */
  createRelease(overrides: Partial<ReleaseData> = {}): EnhancedKnowledgeItem {
    const id = overrides.id || MockDataGenerator.generateUUID();
    return {
      kind: 'release',
      scope: MockDataGenerator.generateScope(),
      data: {
        id,
        version: 'v2.1.0',
        release_type: 'major',
        status: 'deployed',
        scope: 'OAuth 2.0 authentication implementation with performance improvements',
        planned_date: MockDataGenerator.generateTimestamp(-2),
        actual_date: MockDataGenerator.generateTimestamp(-1),
        description:
          'Major release implementing OAuth 2.0 authentication with comprehensive security measures',
        features: [
          'OAuth 2.0 authentication flow',
          'Token management system',
          'Enhanced security headers',
          'Performance optimizations',
        ],
        bug_fixes: [
          'Fixed authentication timeout issue',
          'Resolved memory leak in token validation',
        ],
        breaking_changes: [
          'Authentication API endpoint changed',
          'Database schema update required',
        ],
        rollback_procedure: 'Revert to v2.0.0 using database backup',
        deployment_strategy: 'blue-green',
        testing_summary: 'All tests passing, security review completed',
        performance_impact: 'positive',
        security_review: 'approved',
        approved_by: 'release-manager@example.com',
        deployment_notes: 'Requires database migration and configuration update',
        ...overrides,
      },
      tags: { test: 'true', type: 'release', version: 'v2.1.0' },
      idempotency_key: MockDataGenerator.generateUUID(),
    };
  }

  /**
   * Create a risk test item
   */
  createRisk(overrides: Partial<RiskData> = {}): EnhancedKnowledgeItem {
    const id = overrides.id || MockDataGenerator.generateUUID();
    return {
      kind: 'risk',
      scope: MockDataGenerator.generateScope(),
      data: {
        id,
        title: 'OAuth Token Storage Security Risk',
        category: 'security',
        risk_level: 'high',
        impact_description:
          'Compromise of OAuth tokens could lead to unauthorized access to user accounts',
        probability: 'medium',
        impact_score: 8,
        probability_score: 5,
        risk_score: 40,
        identified_date: MockDataGenerator.generateTimestamp(-10),
        status: 'mitigated',
        mitigation_strategies: [
          'Implement token encryption at rest',
          'Add token rotation mechanism',
          'Implement token revocation system',
          'Add comprehensive audit logging',
        ],
        mitigation_status: 'completed',
        residual_risk: 'low',
        owner: 'security-team@example.com',
        reviewer: 'ciso@example.com',
        review_date: MockDataGenerator.generateTimestamp(-2),
        next_review_date: MockDataGenerator.generateTimestamp(90),
        tags: ['security', 'oauth', 'authentication', 'tokens'],
        ...overrides,
      },
      tags: { test: 'true', type: 'risk', category: 'security' },
      idempotency_key: MockDataGenerator.generateUUID(),
    };
  }

  /**
   * Create an assumption test item
   */
  createAssumption(overrides: Partial<AssumptionData> = {}): EnhancedKnowledgeItem {
    const id = overrides.id || MockDataGenerator.generateUUID();
    return {
      kind: 'assumption',
      scope: MockDataGenerator.generateScope(),
      data: {
        id,
        title: 'Users have OAuth 2.0 compatible clients',
        description:
          'Assumes that all client applications can be updated to support OAuth 2.0 authentication flow',
        category: 'technical',
        validation_status: 'validated',
        impact_if_invalid: 'High impact - would require maintaining legacy authentication systems',
        validation_method: 'Client application compatibility testing',
        validation_date: MockDataGenerator.generateTimestamp(-5),
        validator: 'integration-team@example.com',
        confidence_level: 0.9,
        dependencies: ['Client application updates', 'Legacy system support'],
        expiry_date: MockDataGenerator.generateTimestamp(180),
        tags: ['oauth', 'authentication', 'client-compatibility'],
        ...overrides,
      },
      tags: { test: 'true', type: 'assumption', category: 'technical' },
      idempotency_key: MockDataGenerator.generateUUID(),
    };
  }

  /**
   * Create batch of mixed knowledge items for testing
   */
  createMixedBatch(count: number = 10): EnhancedKnowledgeItem[] {
    const items: EnhancedKnowledgeItem[] = [];
    const factories = [
      () => this.createSection(),
      () => this.createDecision(),
      () => this.createIssue(),
      () => this.createTodo(),
      () => this.createRunbook(),
      () => this.createChange(),
      () => this.createReleaseNote(),
      () => this.createDDL(),
      () => this.createPRContext(),
      () => this.createEntity(),
      () => this.createRelation(),
      () => this.createObservation(),
      () => this.createIncident(),
      () => this.createRelease(),
      () => this.createRisk(),
      () => this.createAssumption(),
    ];

    for (let i = 0; i < count; i++) {
      const factory = factories[i % factories.length];
      items.push(factory());
    }

    return items;
  }

  /**
   * Create test items with specific characteristics for edge case testing
   */
  createEdgeCaseItems(): {
    oversized: EnhancedKnowledgeItem;
    minimal: EnhancedKnowledgeItem;
    withSpecialCharacters: EnhancedKnowledgeItem;
    withNullValues: EnhancedKnowledgeItem;
    withEmptyStrings: EnhancedKnowledgeItem;
    withLargeArrays: EnhancedKnowledgeItem;
    withDeepNesting: EnhancedKnowledgeItem;
  } {
    return {
      oversized: this.createSection({
        title: MockDataGenerator.generateText(1000),
        body_md: MockDataGenerator.generateMarkdown() + '\n'.repeat(100),
        tags: Array.from({ length: 50 }, (_, i) => `tag${i}:value${i}`),
      }),

      minimal: this.createSection({
        title: 'A',
        heading: 'A',
        body_md: 'B',
        body_text: 'B',
      }),

      withSpecialCharacters: this.createSection({
        title: 'Special Characters: !@#$%^&*()_+-=[]{}|;:,.<>?',
        body_md: 'Content with unicode: áéíóú ñ 中文 🚀 🔒 💡',
      }),

      withNullValues: this.createEntity({
        properties: {
          version: null,
          language: null,
          framework: 'Node.js',
        },
      }),

      withEmptyStrings: this.createDecision({
        title: '',
        rationale: '',
        alternatives_considered: [],
      }),

      withLargeArrays: this.createRunbook({
        steps: Array.from({ length: 100 }, (_, i) => ({
          name: `Step ${i + 1}`,
          command: `command-${i + 1}`,
          expected_output: `output-${i + 1}`,
          timeout_seconds: 30,
        })),
      }),

      withDeepNesting: this.createEntity({
        properties: {
          nested: {
            level1: {
              level2: {
                level3: {
                  level4: {
                    deep: 'value',
                  },
                },
              },
            },
          },
        },
      }),
    };
  }
}
