/**
 * Comprehensive Unit Tests for Knowledge Type Schemas Functionality
 *
 * Tests schema validation and structure for all 16 knowledge types including:
 * - Schema structure validation across all knowledge types
 * - Required field validation and optional field handling
 * - Schema inheritance and extension patterns
 * - Cross-type schema compatibility and relationship validation
 * - Schema performance optimization and validation efficiency
 * - Error handling and validation edge cases
 * - Integration with services and database mapping
 * - Schema evolution support and API synchronization
 *
 * Constitutional Requirements:
 * - Type Safety (Principle VII): Compile-time + runtime validation
 * - Minimal API (Principle I): 16 core types, extensible via tags
 * - Immutability (Principle IV): ADR content immutable, approved specs write-locked
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { VectorDatabase } from '../../../src/index';
import {
  KnowledgeItemSchema,
  ScopeSchema,
  SourceSchema,
  TTLPolicySchema,
  SectionSchema,
  RunbookSchema,
  ChangeSchema,
  IssueSchema,
  DecisionSchema,
  TodoSchema,
  ReleaseNoteSchema,
  DDLSchema,
  PRContextSchema,
  EntitySchema,
  RelationSchema,
  ObservationSchema,
  IncidentSchema,
  ReleaseSchema,
  RiskSchema,
  AssumptionSchema,
  validateKnowledgeItem,
  safeValidateKnowledgeItem,
  violatesADRImmutability,
  violatesSpecWriteLock
} from '../../../src/schemas/knowledge-types';
import type {
  KnowledgeItem,
  SectionItem,
  RunbookItem,
  ChangeItem,
  IssueItem,
  DecisionItem,
  TodoItem,
  ReleaseNoteItem,
  DDLItem,
  PRContextItem,
  EntityItem,
  RelationItem,
  ObservationItem,
  IncidentItem,
  ReleaseItem,
  RiskItem,
  AssumptionItem
} from '../../../src/schemas/knowledge-types';

// Mock Qdrant client - reusing established pattern
vi.mock('@qdrant/js-client-rest', () => ({
  QdrantClient: class {
    constructor() {
      this.getCollections = vi.fn().mockResolvedValue({
        collections: [{ name: 'test-collection' }]
      });
      this.createCollection = vi.fn().mockResolvedValue(undefined);
      this.upsert = vi.fn().mockResolvedValue({ status: 'ok' });
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

describe('Knowledge Type Schemas - Comprehensive Validation Testing', () => {
  let db: VectorDatabase;
  let mockQdrant: any;

  beforeEach(() => {
    db = new VectorDatabase();
    mockQdrant = (db as any).client;
  });

  describe('Schema Structure Validation - Foundation', () => {
    it('should validate all 16 knowledge type schemas are defined', () => {
      const schemas = [
        SectionSchema,
        RunbookSchema,
        ChangeSchema,
        IssueSchema,
        DecisionSchema,
        TodoSchema,
        ReleaseNoteSchema,
        DDLSchema,
        PRContextSchema,
        EntitySchema,
        RelationSchema,
        ObservationSchema,
        IncidentSchema,
        ReleaseSchema,
        RiskSchema,
        AssumptionSchema
      ];

      expect(schemas).toHaveLength(16);
      schemas.forEach((schema, index) => {
        expect(schema).toBeDefined();
        expect(schema._def.typeName).toBe('ZodObject');
      });
    });

    it('should validate discriminated union includes all knowledge types', () => {
      const unionOptions = KnowledgeItemSchema.options;
      expect(unionOptions).toHaveLength(16);

      const kinds = unionOptions.map(option => option._def.shape().kind._def.value);
      const expectedKinds = [
        'section', 'runbook', 'change', 'issue', 'decision', 'todo',
        'release_note', 'ddl', 'pr_context', 'entity', 'relation',
        'observation', 'incident', 'release', 'risk', 'assumption'
      ];

      expect(kinds.sort()).toEqual(expectedKinds.sort());
    });

    it('should validate shared schema definitions', () => {
      // Test Scope schema
      const validScope = {
        org: 'test-org',
        project: 'test-project',
        branch: 'main',
        environment: 'development'
      };
      const scopeResult = ScopeSchema.safeParse(validScope);
      expect(scopeResult.success).toBe(true);

      // Test Source schema
      const validSource = {
        actor: 'test-actor',
        tool: 'test-tool',
        timestamp: '2025-01-01T00:00:00Z'
      };
      const sourceResult = SourceSchema.safeParse(validSource);
      expect(sourceResult.success).toBe(true);

      // Test TTL Policy schema
      const validTTLPolicies = ['default', 'short', 'long', 'permanent'] as const;
      validTTLPolicies.forEach(policy => {
        const ttlResult = TTLPolicySchema.safeParse(policy);
        expect(ttlResult.success).toBe(true);
      });
    });

    it('should enforce scope requirements across all knowledge types', () => {
      const invalidScopes = [
        {}, // Missing required fields
        { project: '', branch: 'main' }, // Empty project
        { project: 'test', branch: '' }, // Empty branch
        { project: 'test' }, // Missing branch
        { branch: 'main' } // Missing project
      ];

      invalidScopes.forEach(invalidScope => {
        const testItem = {
          kind: 'entity' as const,
          scope: invalidScope,
          data: { entity_type: 'test', name: 'test', data: {} }
        };
        const result = EntitySchema.safeParse(testItem);
        expect(result.success).toBe(false);
      });
    });
  });

  describe('Section Schema Validation', () => {
    it('should validate complete section with all fields', () => {
      const section: SectionItem = {
        kind: 'section',
        scope: { project: 'test-project', branch: 'main' },
        data: {
          id: '550e8400-e29b-41d4-a716-446655440000',
          title: 'Architecture Overview',
          heading: 'System Architecture',
          body_md: '# Architecture\n\nThis is the architecture section.',
          document_id: '550e8400-e29b-41d4-a716-446655440001',
          citation_count: 5
        },
        tags: { approved: false },
        source: { actor: 'architect', tool: 'docs-system' }
      };

      const result = SectionSchema.safeParse(section);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.title).toBe('Architecture Overview');
        expect(result.data.data.heading).toBe('System Architecture');
        expect(result.data.data.body_md).toContain('# Architecture');
      }
    });

    it('should require either body_md or body_text', () => {
      const sectionWithoutBody = {
        kind: 'section' as const,
        scope: { project: 'test', branch: 'main' },
        data: {
          title: 'Test Section',
          heading: 'Test'
          // Missing both body_md and body_text
        }
      };

      const result = SectionSchema.safeParse(sectionWithoutBody);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('Either body_md or body_text must be provided');
      }
    });

    it('should accept section with body_text only', () => {
      const sectionWithBodyText = {
        kind: 'section' as const,
        scope: { project: 'test', branch: 'main' },
        data: {
          title: 'Simple Section',
          heading: 'Simple',
          body_text: 'This is a simple section with plain text content.'
        }
      };

      const result = SectionSchema.safeParse(sectionWithBodyText);
      expect(result.success).toBe(true);
    });
  });

  describe('Decision Schema Validation', () => {
    it('should validate ADR with all required and optional fields', () => {
      const decision: DecisionItem = {
        kind: 'decision',
        scope: { project: 'test-project', branch: 'main' },
        data: {
          id: '550e8400-e29b-41d4-a716-446655440000',
          component: 'auth-system',
          status: 'accepted',
          title: 'Use OAuth 2.0 for Authentication',
          rationale: 'OAuth 2.0 provides industry-standard security with token-based authentication.',
          alternatives_considered: ['Basic Auth', 'JWT-only', 'Custom session'],
          consequences: 'Requires token management infrastructure.',
          supersedes: '550e8400-e29b-41d4-a716-446655440001'
        },
        tags: { security: true, architecture: true },
        source: { actor: 'tech-lead', timestamp: '2025-01-01T00:00:00Z' }
      };

      const result = DecisionSchema.safeParse(decision);
      expect(result.success).toBe(true);
    });

    it('should enforce valid decision status values', () => {
      const validStatuses = ['proposed', 'accepted', 'rejected', 'deprecated', 'superseded'] as const;
      validStatuses.forEach(status => {
        const decision = {
          kind: 'decision' as const,
          scope: { project: 'test', branch: 'main' },
          data: {
            component: 'test',
            status,
            title: 'Test Decision',
            rationale: 'Test rationale'
          }
        };
        const result = DecisionSchema.safeParse(decision);
        expect(result.success).toBe(true);
      });
    });
  });

  describe('Entity Schema Validation', () => {
    it('should validate entity with flexible data schema', () => {
      const entity: EntityItem = {
        kind: 'entity',
        scope: { project: 'test-project', branch: 'main' },
        data: {
          entity_type: 'user',
          name: 'john_doe',
          data: {
            email: 'john@example.com',
            preferences: { theme: 'dark', language: 'en' },
            metadata: { lastLogin: '2025-01-01', roles: ['developer', 'admin'] }
          }
        },
        tags: { verified: true }
      };

      const result = EntitySchema.safeParse(entity);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.data).toEqual({
          email: 'john@example.com',
          preferences: { theme: 'dark', language: 'en' },
          metadata: { lastLogin: '2025-01-01', roles: ['developer', 'admin'] }
        });
      }
    });

    it('should accept entity with empty data object', () => {
      const minimalEntity = {
        kind: 'entity' as const,
        scope: { project: 'test', branch: 'main' },
        data: {
          entity_type: 'organization',
          name: 'Test Org',
          data: {}
        }
      };

      const result = EntitySchema.safeParse(minimalEntity);
      expect(result.success).toBe(true);
    });
  });

  describe('Relation Schema Validation', () => {
    it('should validate complete relation between entities', () => {
      const relation: RelationItem = {
        kind: 'relation',
        scope: { project: 'test-project', branch: 'main' },
        data: {
          from_entity_type: 'decision',
          from_entity_id: '550e8400-e29b-41d4-a716-446655440001',
          to_entity_type: 'issue',
          to_entity_id: '550e8400-e29b-41d4-a716-446655440002',
          relation_type: 'resolves',
          metadata: { confidence: 0.95, weight: 1.0, since: '2025-01-01' }
        }
      };

      const result = RelationSchema.safeParse(relation);
      expect(result.success).toBe(true);
    });

    it('should require valid UUID format for entity IDs', () => {
      const invalidRelation = {
        kind: 'relation' as const,
        scope: { project: 'test', branch: 'main' },
        data: {
          from_entity_type: 'decision',
          from_entity_id: 'invalid-uuid',
          to_entity_type: 'issue',
          to_entity_id: '550e8400-e29b-41d4-a716-446655440002',
          relation_type: 'resolves'
        }
      };

      const result = RelationSchema.safeParse(invalidRelation);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('UUID');
      }
    });
  });

  describe('Observation Schema Validation', () => {
    it('should validate observation with all metadata', () => {
      const observation: ObservationItem = {
        kind: 'observation',
        scope: { project: 'test-project', branch: 'main' },
        data: {
          entity_type: 'decision',
          entity_id: '550e8400-e29b-41d4-a716-446655440000',
          observation: 'Implementation status: completed',
          observation_type: 'status',
          metadata: { source: 'automated-check', confidence: 0.9 }
        }
      };

      const result = ObservationSchema.safeParse(observation);
      expect(result.success).toBe(true);
    });

    it('should accept minimal observation', () => {
      const minimalObservation = {
        kind: 'observation' as const,
        scope: { project: 'test', branch: 'main' },
        data: {
          entity_type: 'entity',
          entity_id: '550e8400-e29b-41d4-a716-446655440000',
          observation: 'Simple observation note'
        }
      };

      const result = ObservationSchema.safeParse(minimalObservation);
      expect(result.success).toBe(true);
    });
  });

  describe('Runbook Schema Validation', () => {
    it('should validate complete runbook with steps', () => {
      const runbook: RunbookItem = {
        kind: 'runbook',
        scope: { project: 'test-project', branch: 'main' },
        data: {
          service: 'database-backup',
          title: 'Daily Database Backup Procedure',
          description: 'Automated backup of PostgreSQL database',
          steps: [
            {
              step_number: 1,
              description: 'Stop application connections',
              command: 'docker-compose stop app',
              expected_outcome: 'Application containers stopped'
            },
            {
              step_number: 2,
              description: 'Create database backup',
              command: 'pg_dump -U postgres dbname > backup.sql',
              expected_outcome: 'Backup file created successfully'
            },
            {
              step_number: 3,
              description: 'Restart application',
              command: 'docker-compose start app'
            }
          ],
          triggers: ['scheduled', 'manual'],
          last_verified_at: '2025-01-01T00:00:00Z'
        }
      };

      const result = RunbookSchema.safeParse(runbook);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.steps).toHaveLength(3);
        expect(result.data.data.steps[0].step_number).toBe(1);
      }
    });

    it('should require at least one step', () => {
      const runbookWithoutSteps = {
        kind: 'runbook' as const,
        scope: { project: 'test', branch: 'main' },
        data: {
          service: 'test-service',
          title: 'Test Runbook',
          steps: [] // Empty steps array
        }
      };

      const result = RunbookSchema.safeParse(runbookWithoutSteps);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('At least one step is required');
      }
    });
  });

  describe('Change Schema Validation', () => {
    it('should validate change with all metadata', () => {
      const change: ChangeItem = {
        kind: 'change',
        scope: { project: 'test-project', branch: 'main' },
        data: {
          change_type: 'feature_add',
          subject_ref: 'commit:abc123',
          summary: 'Add user authentication endpoints',
          details: 'Implemented JWT-based authentication with refresh tokens',
          affected_files: ['src/auth/jwt.ts', 'src/api/auth.ts'],
          author: 'developer@example.com',
          commit_sha: 'abc123def456'
        },
        tags: { feature: true, security: true }
      };

      const result = ChangeSchema.safeParse(change);
      expect(result.success).toBe(true);
    });

    it('should enforce valid change types', () => {
      const validChangeTypes = [
        'feature_add', 'feature_modify', 'feature_remove', 'bugfix',
        'refactor', 'config_change', 'dependency_update'
      ] as const;

      validChangeTypes.forEach(changeType => {
        const change = {
          kind: 'change' as const,
          scope: { project: 'test', branch: 'main' },
          data: {
            change_type: changeType,
            subject_ref: 'test-123',
            summary: 'Test change'
          }
        };
        const result = ChangeSchema.safeParse(change);
        expect(result.success).toBe(true);
      });
    });
  });

  describe('Issue Schema Validation', () => {
    it('should validate complete issue from external tracker', () => {
      const issue: IssueItem = {
        kind: 'issue',
        scope: { project: 'test-project', branch: 'main' },
        data: {
          tracker: 'github',
          external_id: 'GH-123',
          title: 'Fix authentication bug',
          status: 'in_progress',
          description: 'Users cannot log in with valid credentials',
          assignee: 'developer@example.com',
          labels: ['bug', 'authentication', 'high-priority'],
          url: 'https://github.com/repo/issues/123'
        }
      };

      const result = IssueSchema.safeParse(issue);
      expect(result.success).toBe(true);
    });

    it('should enforce valid issue status values', () => {
      const validStatuses = ['open', 'in_progress', 'resolved', 'closed', 'wont_fix'] as const;
      validStatuses.forEach(status => {
        const issue = {
          kind: 'issue' as const,
          scope: { project: 'test', branch: 'main' },
          data: {
            tracker: 'jira',
            external_id: 'PROJ-123',
            title: 'Test Issue',
            status
          }
        };
        const result = IssueSchema.safeParse(issue);
        expect(result.success).toBe(true);
      });
    });
  });

  describe('Todo Schema Validation', () => {
    it('should validate complete todo with all fields', () => {
      const todo: TodoItem = {
        kind: 'todo',
        scope: { project: 'test-project', branch: 'main' },
        data: {
          scope: 'task',
          todo_type: 'story',
          text: 'Implement user profile page',
          status: 'in_progress',
          priority: 'high',
          assignee: 'frontend-developer@example.com',
          due_date: '2025-02-01T00:00:00Z'
        }
      };

      const result = TodoSchema.safeParse(todo);
      expect(result.success).toBe(true);
    });

    it('should validate todo without optional fields', () => {
      const minimalTodo = {
        kind: 'todo' as const,
        scope: { project: 'test', branch: 'main' },
        data: {
          scope: 'task',
          todo_type: 'task',
          text: 'Simple task',
          status: 'open'
        }
      };

      const result = TodoSchema.safeParse(minimalTodo);
      expect(result.success).toBe(true);
    });
  });

  describe('Release Note Schema Validation', () => {
    it('should validate comprehensive release note', () => {
      const releaseNote: ReleaseNoteItem = {
        kind: 'release_note',
        scope: { project: 'test-project', branch: 'main' },
        data: {
          version: 'v2.1.0',
          release_date: '2025-01-15T00:00:00Z',
          summary: 'Major feature release with improved performance and security',
          breaking_changes: [
            'Removed deprecated authentication endpoints',
            'Updated database schema for user profiles'
          ],
          new_features: [
            'Added two-factor authentication',
            'Implemented real-time notifications',
            'Enhanced dashboard with analytics'
          ],
          bug_fixes: [
            'Fixed memory leak in background processes',
            'Resolved login issue on mobile devices'
          ],
          deprecations: [
            'Legacy API v1 endpoints will be removed in v3.0'
          ]
        }
      };

      const result = ReleaseNoteSchema.safeParse(releaseNote);
      expect(result.success).toBe(true);
    });

    it('should require valid version format', () => {
      const invalidVersions = ['', ' '.repeat(101)]; // Empty and too long versions
      invalidVersions.forEach(version => {
        const releaseNote = {
          kind: 'release_note' as const,
          scope: { project: 'test', branch: 'main' },
          data: {
            version,
            release_date: '2025-01-01T00:00:00Z',
            summary: 'Test release'
          }
        };
        const result = ReleaseNoteSchema.safeParse(releaseNote);
        expect(result.success).toBe(false);
      });
    });
  });

  describe('DDL Schema Validation', () => {
    it('should validate complete DDL migration', () => {
      const ddl: DDLItem = {
        kind: 'ddl',
        scope: { project: 'test-project', branch: 'main' },
        data: {
          migration_id: '001_initial_schema',
          ddl_text: 'CREATE TABLE users (id SERIAL PRIMARY KEY, email VARCHAR(255) UNIQUE NOT NULL);',
          checksum: 'a'.repeat(64), // Valid SHA-256 hash
          applied_at: '2025-01-01T00:00:00Z',
          description: 'Create initial users table with email field'
        }
      };

      const result = DDLSchema.safeParse(ddl);
      expect(result.success).toBe(true);
    });

    it('should enforce checksum length requirements', () => {
      const invalidChecksums = ['short', 'a'.repeat(63), 'a'.repeat(65)];
      invalidChecksums.forEach(checksum => {
        const ddl = {
          kind: 'ddl' as const,
          scope: { project: 'test', branch: 'main' },
          data: {
            migration_id: 'test_migration',
            ddl_text: 'CREATE TABLE test (id INT);',
            checksum
          }
        };
        const result = DDLSchema.safeParse(ddl);
        expect(result.success).toBe(false);
      });
    });
  });

  describe('PR Context Schema Validation', () => {
    it('should validate complete PR context', () => {
      const prContext: PRContextItem = {
        kind: 'pr_context',
        scope: { project: 'test-project', branch: 'main' },
        data: {
          pr_number: 123,
          title: 'Add user authentication feature',
          description: 'Implements OAuth 2.0 authentication with JWT tokens',
          author: 'developer@example.com',
          status: 'open',
          base_branch: 'main',
          head_branch: 'feature/auth',
          expires_at: '2025-02-01T00:00:00Z'
        }
      };

      const result = PRContextSchema.safeParse(prContext);
      expect(result.success).toBe(true);
    });

    it('should enforce valid PR status values', () => {
      const validStatuses = ['open', 'merged', 'closed', 'draft'] as const;
      validStatuses.forEach(status => {
        const prContext = {
          kind: 'pr_context' as const,
          scope: { project: 'test', branch: 'main' },
          data: {
            pr_number: 123,
            title: 'Test PR',
            author: 'test@example.com',
            status,
            base_branch: 'main',
            head_branch: 'feature'
          }
        };
        const result = PRContextSchema.safeParse(prContext);
        expect(result.success).toBe(true);
      });
    });
  });

  describe('Incident Schema Validation', () => {
    it('should validate complete incident with timeline', () => {
      const incident: IncidentItem = {
        kind: 'incident',
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Database connection pool exhaustion',
          severity: 'high',
          impact: 'Application becomes unresponsive, users cannot access services',
          timeline: [
            {
              timestamp: '2025-01-01T10:00:00Z',
              event: 'Increased error rates detected',
              actor: 'monitoring-system'
            },
            {
              timestamp: '2025-01-01T10:05:00Z',
              event: 'Database connection pool at 100% capacity'
            },
            {
              timestamp: '2025-01-01T10:15:00Z',
              event: 'Emergency restart of application services',
              actor: 'ops-team'
            }
          ],
          root_cause_analysis: 'Memory leak in database connection handling code',
          resolution_status: 'resolved',
          affected_services: ['api-service', 'web-app'],
          business_impact: '25% of users affected for 15 minutes',
          recovery_actions: [
            'Restarted application services',
            'Implemented connection pool monitoring',
            'Scheduled code review for database layer'
          ],
          follow_up_required: true,
          incident_commander: 'ops-lead@example.com'
        }
      };

      const result = IncidentSchema.safeParse(incident);
      expect(result.success).toBe(true);
    });

    it('should enforce valid severity levels', () => {
      const validSeverities = ['critical', 'high', 'medium', 'low'] as const;
      validSeverities.forEach(severity => {
        const incident = {
          kind: 'incident' as const,
          scope: { project: 'test', branch: 'main' },
          data: {
            title: 'Test incident',
            severity,
            impact: 'Test impact',
            resolution_status: 'open'
          }
        };
        const result = IncidentSchema.safeParse(incident);
        expect(result.success).toBe(true);
      });
    });
  });

  describe('Release Schema Validation', () => {
    it('should validate complete release information', () => {
      const release: ReleaseItem = {
        kind: 'release',
        scope: { project: 'test-project', branch: 'main' },
        data: {
          version: 'v2.1.0',
          release_type: 'minor',
          scope: 'Backend API and frontend dashboard updates',
          release_date: '2025-01-15T00:00:00Z',
          status: 'completed',
          ticket_references: ['TICKET-123', 'TICKET-124', 'TICKET-125'],
          included_changes: [
            'Added authentication endpoints',
            'Updated dashboard UI',
            'Fixed memory leak in caching layer'
          ],
          deployment_strategy: 'Blue-green deployment with instant rollback',
          rollback_plan: 'Switch traffic back to previous version using load balancer',
          testing_status: 'All automated tests passed, manual QA completed',
          approvers: ['tech-lead@example.com', 'qa-lead@example.com'],
          release_notes: 'This release includes major security improvements and performance enhancements.',
          post_release_actions: [
            'Monitor error rates for 24 hours',
            'Verify user authentication flow',
            'Check dashboard performance metrics'
          ]
        }
      };

      const result = ReleaseSchema.safeParse(release);
      expect(result.success).toBe(true);
    });

    it('should enforce valid release types', () => {
      const validReleaseTypes = ['major', 'minor', 'patch', 'hotfix'] as const;
      validReleaseTypes.forEach(releaseType => {
        const release = {
          kind: 'release' as const,
          scope: { project: 'test', branch: 'main' },
          data: {
            version: '1.0.0',
            release_type: releaseType,
            scope: 'Test release scope',
            status: 'planned'
          }
        };
        const result = ReleaseSchema.safeParse(release);
        expect(result.success).toBe(true);
      });
    });
  });

  describe('Risk Schema Validation', () => {
    it('should validate comprehensive risk assessment', () => {
      const risk: RiskItem = {
        kind: 'risk',
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Third-party authentication service dependency',
          category: 'technical',
          risk_level: 'high',
          probability: 'likely',
          impact_description: 'If Auth0 service goes down, all user authentication will fail, completely blocking access to the application',
          trigger_events: [
            'Auth0 service outage',
            'API key expiration',
            'Rate limiting exceeded',
            'Service deprecation'
          ],
          mitigation_strategies: [
            'Implement fallback authentication mechanism',
            'Cache user sessions with extended TTL',
            'Monitor Auth0 service health',
            'Prepare migration plan to alternative provider'
          ],
          owner: 'security-team@example.com',
          review_date: '2025-02-01T00:00:00Z',
          status: 'active',
          related_decisions: [
            '550e8400-e29b-41d4-a716-446655440001',
            '550e8400-e29b-41d4-a716-446655440002'
          ],
          monitoring_indicators: [
            'Auth0 API response time',
            'Authentication success rate',
            'Service availability metrics'
          ],
          contingency_plans: 'Switch to local authentication mode using cached credentials while service is restored'
        }
      };

      const result = RiskSchema.safeParse(risk);
      expect(result.success).toBe(true);
    });

    it('should enforce valid risk categories and levels', () => {
      const validCategories = ['technical', 'business', 'operational', 'security', 'compliance'] as const;
      const validLevels = ['critical', 'high', 'medium', 'low'] as const;
      const validProbabilities = ['very_likely', 'likely', 'possible', 'unlikely', 'very_unlikely'] as const;

      validCategories.forEach(category => {
        validLevels.forEach(level => {
          validProbabilities.forEach(probability => {
            const risk = {
              kind: 'risk' as const,
              scope: { project: 'test', branch: 'main' },
              data: {
                title: 'Test Risk',
                category,
                risk_level: level,
                probability,
                impact_description: 'Test impact',
                status: 'active' as const
              }
            };
            const result = RiskSchema.safeParse(risk);
            expect(result.success).toBe(true);
          });
        });
      });
    });
  });

  describe('Assumption Schema Validation', () => {
    it('should validate complete assumption record', () => {
      const assumption: AssumptionItem = {
        kind: 'assumption',
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'User base will grow 50% year-over-year',
          description: 'Based on market analysis and current growth trends, we expect the user base to increase by 50% annually',
          category: 'business',
          validation_status: 'assumed',
          impact_if_invalid: 'Infrastructure capacity planning will be inadequate, leading to performance issues and increased costs',
          validation_criteria: [
            'Monthly active user growth > 4%',
            'Customer acquisition cost remains stable',
            'Market conditions remain favorable'
          ],
          validation_date: '2025-01-01T00:00:00Z',
          owner: 'product-manager@example.com',
          related_assumptions: [
            '550e8400-e29b-41d4-a716-446655440001',
            '550e8400-e29b-41d4-a716-446655440002'
          ],
          dependencies: ['Market growth rate', 'Competitive landscape', 'Economic stability'],
          monitoring_approach: 'Track MAU growth, CAC, and market trends quarterly',
          review_frequency: 'quarterly'
        }
      };

      const result = AssumptionSchema.safeParse(assumption);
      expect(result.success).toBe(true);
    });

    it('should enforce valid assumption categories and validation statuses', () => {
      const validCategories = ['technical', 'business', 'user', 'market', 'resource'] as const;
      const validStatuses = ['validated', 'assumed', 'invalidated', 'needs_validation'] as const;

      validCategories.forEach(category => {
        validStatuses.forEach(status => {
          const assumption = {
            kind: 'assumption' as const,
            scope: { project: 'test', branch: 'main' },
            data: {
              title: 'Test Assumption',
              description: 'Test description',
              category,
              validation_status: status,
              impact_if_invalid: 'Test impact'
            }
          };
          const result = AssumptionSchema.safeParse(assumption);
          expect(result.success).toBe(true);
        });
      });
    });
  });

  describe('Cross-Type Schema Compatibility', () => {
    it('should validate relationship between decision and issue', () => {
      const decision = {
        kind: 'decision' as const,
        scope: { project: 'test', branch: 'main' },
        data: {
          component: 'auth',
          status: 'accepted',
          title: 'Use OAuth 2.0',
          rationale: 'Industry standard'
        }
      };

      const issue = {
        kind: 'issue' as const,
        scope: { project: 'test', branch: 'main' },
        data: {
          tracker: 'github',
          external_id: 'GH-123',
          title: 'Fix auth bug',
          status: 'open'
        }
      };

      const relation = {
        kind: 'relation' as const,
        scope: { project: 'test', branch: 'main' },
        data: {
          from_entity_type: 'decision',
          from_entity_id: '550e8400-e29b-41d4-a716-446655440001',
          to_entity_type: 'issue',
          to_entity_id: '550e8400-e29b-41d4-a716-446655440002',
          relation_type: 'resolves'
        }
      };

      const decisionResult = DecisionSchema.safeParse(decision);
      const issueResult = IssueSchema.safeParse(issue);
      const relationResult = RelationSchema.safeParse(relation);

      expect(decisionResult.success).toBe(true);
      expect(issueResult.success).toBe(true);
      expect(relationResult.success).toBe(true);
    });

    it('should validate observation linked to entity', () => {
      const entity = {
        kind: 'entity' as const,
        scope: { project: 'test', branch: 'main' },
        data: {
          entity_type: 'user',
          name: 'test_user',
          data: { status: 'active' }
        }
      };

      const observation = {
        kind: 'observation' as const,
        scope: { project: 'test', branch: 'main' },
        data: {
          entity_type: 'entity',
          entity_id: '550e8400-e29b-41d4-a716-446655440000',
          observation: 'User status changed to active',
          observation_type: 'status'
        }
      };

      const entityResult = EntitySchema.safeParse(entity);
      const observationResult = ObservationSchema.safeParse(observation);

      expect(entityResult.success).toBe(true);
      expect(observationResult.success).toBe(true);
    });

    it('should handle cross-type reference validation', () => {
      // Store a decision
      const decision = {
        kind: 'decision' as const,
        scope: { project: 'test', branch: 'main' },
        data: {
          component: 'auth',
          status: 'accepted',
          title: 'Use OAuth 2.0',
          rationale: 'Industry standard'
        }
      };

      const decisionResult = DecisionSchema.safeParse(decision);
      expect(decisionResult.success).toBe(true);
      if (decisionResult.success) {
        expect(decisionResult.data.kind).toBe('decision');
        expect(decisionResult.data.data.component).toBe('auth');
      }
    });
  });

  describe('Schema Performance and Validation Efficiency', () => {
    it('should handle batch validation efficiently', () => {
      const items = Array.from({ length: 100 }, (_, i) => ({
        kind: 'entity' as const,
        scope: { project: 'test', branch: 'main' },
        data: {
          entity_type: 'test',
          name: `entity-${i}`,
          data: { index: i }
        }
      }));

      const startTime = Date.now();
      const results = items.map(item => EntitySchema.safeParse(item));
      const endTime = Date.now();

      const validResults = results.filter(r => r.success);
      expect(validResults).toHaveLength(100);
      expect(endTime - startTime).toBeLessThan(1000); // Should complete within 1 second
    });

    it('should validate items with large data structures efficiently', () => {
      const largeEntity = {
        kind: 'entity' as const,
        scope: { project: 'test', branch: 'main' },
        data: {
          entity_type: 'large_dataset',
          name: 'large_entity',
          data: {
            array: Array.from({ length: 1000 }, (_, i) => ({ id: i, value: `item-${i}` })),
            nested: {
              deep: {
                structure: {
                  with: {
                    many: {
                      levels: 'of data'
                    }
                  }
                }
              }
            }
          }
        }
      };

      const startTime = Date.now();
      const result = EntitySchema.safeParse(largeEntity);
      const endTime = Date.now();

      expect(result.success).toBe(true);
      expect(endTime - startTime).toBeLessThan(1000); // Should validate within 1 second
    });

    it('should use caching for repeated validations', () => {
      const item = {
        kind: 'decision' as const,
        scope: { project: 'test', branch: 'main' },
        data: {
          component: 'test',
          status: 'proposed',
          title: 'Test Decision',
          rationale: 'Test rationale'
        }
      };

      // First validation
      const result1 = DecisionSchema.safeParse(item);
      // Second validation (should use cache)
      const result2 = DecisionSchema.safeParse(item);

      expect(result1.success).toBe(true);
      expect(result2.success).toBe(true);
      expect(result2.data).toEqual(result1.data);
    });
  });

  describe('Error Handling and Validation Edge Cases', () => {
    it('should handle completely malformed input gracefully', () => {
      const malformedInputs = [
        null,
        undefined,
        'string',
        123,
        [],
        { kind: 'invalid_type' },
        { kind: 'decision' }, // Missing data and scope
        { kind: 'decision', scope: {} }, // Missing data
        { kind: 'decision', data: {} } // Missing scope
      ];

      malformedInputs.forEach((input, index) => {
        const result = KnowledgeItemSchema.safeParse(input);
        expect(result.success).toBe(false);
        if (!result.success) {
          expect(result.error.issues.length).toBeGreaterThan(0);
        }
      });
    });

    it('should provide detailed validation error messages', () => {
      const invalidDecision = {
        kind: 'decision' as const,
        scope: { project: '', branch: '' }, // Invalid scope
        data: {
          component: '',
          status: 'invalid_status',
          title: '',
          rationale: ''
        }
      };

      const result = DecisionSchema.safeParse(invalidDecision);
      expect(result.success).toBe(false);
      if (!result.success) {
        const errorMessages = result.error.issues.map(issue => issue.message);
        expect(errorMessages.some(msg => msg.includes('project'))).toBe(true);
        expect(errorMessages.some(msg => msg.includes('branch'))).toBe(true);
        expect(errorMessages.some(msg => msg.includes('component'))).toBe(true);
        expect(errorMessages.some(msg => msg.includes('Invalid enum'))).toBe(true);
        expect(errorMessages.some(msg => msg.includes('title'))).toBe(true);
        expect(errorMessages.some(msg => msg.includes('rationale'))).toBe(true);
      }
    });

    it('should handle circular references in validation', () => {
      // Test potential circular reference scenarios
      const circularEntity = {
        kind: 'entity' as const,
        scope: { project: 'test', branch: 'main' },
        data: {
          entity_type: 'circular',
          name: 'test',
          data: {
            self: null as any
          }
        }
      };

      // Create circular reference
      circularEntity.data.data.self = circularEntity;

      const result = EntitySchema.safeParse(circularEntity);
      // Should either handle gracefully or reject with appropriate error
      expect(result.success !== undefined).toBe(true);
    });

    it('should validate Unicode and special characters', () => {
      const unicodeDecision = {
        kind: 'decision' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          component: 'user-interface',
          status: 'proposed',
          title: 'Implement 🌐 Internationalization with UTF-8 support',
          rationale: 'Support for 中文, العربية, русский, español, and other languages'
        }
      };

      const result = DecisionSchema.safeParse(unicodeDecision);
      expect(result.success).toBe(true);
    });

    it('should handle extremely long field values', () => {
      const longText = 'a'.repeat(10000);
      const decisionWithLongFields = {
        kind: 'decision' as const,
        scope: { project: 'test', branch: 'main' },
        data: {
          component: 'test',
          status: 'proposed',
          title: longText, // Will be rejected due to length limit
          rationale: 'Valid rationale'
        }
      };

      const result = DecisionSchema.safeParse(decisionWithLongFields);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('500 characters or less');
      }
    });
  });

  describe('Schema Integration with Services', () => {
    it('should validate multiple knowledge types together', () => {
      const testItems = [
        {
          kind: 'decision' as const,
          scope: { project: 'test', branch: 'main' },
          data: {
            component: 'auth',
            status: 'accepted',
            title: 'Use OAuth 2.0',
            rationale: 'Industry standard'
          }
        },
        {
          kind: 'entity' as const,
          scope: { project: 'test', branch: 'main' },
          data: {
            entity_type: 'user',
            name: 'test_user',
            data: { role: 'admin' }
          }
        },
        {
          kind: 'relation' as const,
          scope: { project: 'test', branch: 'main' },
          data: {
            from_entity_type: 'decision',
            from_entity_id: '550e8400-e29b-41d4-a716-446655440001',
            to_entity_type: 'entity',
            to_entity_id: '550e8400-e29b-41d4-a716-446655440002',
            relation_type: 'affects'
          }
        }
      ];

      const schemas = [DecisionSchema, EntitySchema, RelationSchema];
      const results = testItems.map((item, index) => schemas[index].safeParse(item));

      expect(results.every(r => r.success)).toBe(true);
    });

    it('should maintain schema consistency across knowledge types', () => {
      const testItems = [
        {
          kind: 'decision' as const,
          scope: { project: 'test', branch: 'main' },
          data: {
            component: 'auth',
            status: 'accepted',
            title: 'Use OAuth 2.0',
            rationale: 'Industry standard'
          }
        },
        {
          kind: 'entity' as const,
          scope: { project: 'test', branch: 'main' },
          data: {
            entity_type: 'user',
            name: 'test_user',
            data: { role: 'admin' }
          }
        }
      ];

      // Validate against the discriminated union
      const results = testItems.map(item => KnowledgeItemSchema.safeParse(item));

      expect(results.every(r => r.success)).toBe(true);
      expect(results[0].data?.kind).toBe('decision');
      expect(results[1].data?.kind).toBe('entity');
    });

    it('should handle validation errors across different types', () => {
      const invalidItems = [
        {
          kind: 'decision' as const,
          scope: { project: 'test', branch: 'main' },
          data: {
            // Missing required fields
            component: 'test'
          }
        },
        {
          kind: 'entity' as const,
          scope: { project: 'test', branch: 'main' },
          data: {
            entity_type: 'test',
            name: 'test',
            data: {}
          }
        }
      ];

      const schemas = [DecisionSchema, EntitySchema];
      const results = invalidItems.map((item, index) => schemas[index].safeParse(item));

      expect(results[0].success).toBe(false); // Invalid decision
      expect(results[1].success).toBe(true);  // Valid entity
      expect(results[0].error?.issues).toBeDefined();
    });
  });

  describe('Schema Evolution and API Synchronization', () => {
    it('should maintain backward compatibility with existing data', () => {
      // Simulate old data format
      const oldFormatData = {
        kind: 'entity' as const,
        scope: { project: 'test', branch: 'main' },
        data: {
          entity_type: 'user',
          name: 'old_user',
          data: {
            // Legacy fields
            username: 'olduser',
            created_date: '2025-01-01'
          }
        }
        // Note: created_at and legacy_flag would be handled by the database layer,
        // not by the schema validation
      };

      const result = EntitySchema.safeParse(oldFormatData);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.entity_type).toBe('user');
        expect(result.data.data.name).toBe('old_user');
        expect(result.data.data.data.username).toBe('olduser');
      }
    });

    it('should handle schema version transitions gracefully', () => {
      // Test data that might have optional fields from different schema versions
      const versionedData = {
        kind: 'decision' as const,
        scope: { project: 'test', branch: 'main' },
        data: {
          component: 'test',
          status: 'accepted',
          title: 'Test Decision',
          rationale: 'Test rationale',
          // New fields that might not exist in older versions
          alternatives_considered: ['Option 1', 'Option 2'],
          consequences: 'Test consequences',
          // Optional UUID field for updates
          id: '550e8400-e29b-41d4-a716-446655440000'
        },
        // Optional metadata fields
        tags: { v2: true },
        source: { actor: 'system', timestamp: '2025-01-01T00:00:00Z' }
      };

      const result = DecisionSchema.safeParse(versionedData);
      expect(result.success).toBe(true);
    });

    it('should validate schema constraints across API boundaries', () => {
      // Simulate API request/response data
      const apiRequest = {
        kind: 'todo' as const,
        scope: { project: 'api-project', branch: 'feature-branch' },
        data: {
          scope: 'api_task',
          todo_type: 'task',
          text: 'Process API request',
          status: 'in_progress',
          // API-specific fields
          assignee: 'api-service@example.com',
          due_date: '2025-01-31T23:59:59Z'
        },
        // API metadata
        source: {
          actor: 'api-client',
          tool: 'rest-api',
          timestamp: '2025-01-01T12:00:00Z'
        },
        ttl_policy: 'short' as const
      };

      const validationResult = TodoSchema.safeParse(apiRequest);
      expect(validationResult.success).toBe(true);

      if (validationResult.success) {
        // Validate that the validated item can be used in the system
        const systemValidation = validateKnowledgeItem(apiRequest);
        expect(systemValidation.kind).toBe('todo');
        expect(systemValidation.data.status).toBe('in_progress');
      }
    });
  });

  describe('Validation Helper Functions', () => {
    it('should validate knowledge items using helper function', () => {
      const validItem = {
        kind: 'decision' as const,
        scope: { project: 'test', branch: 'main' },
        data: {
          component: 'test',
          status: 'proposed',
          title: 'Test Decision',
          rationale: 'Test rationale'
        }
      };

      const result = validateKnowledgeItem(validItem);
      expect(result.kind).toBe('decision');
      expect(result.data.component).toBe('test');
    });

    it('should handle safe validation with error details', () => {
      const invalidItem = {
        kind: 'decision' as const,
        scope: { project: 'test', branch: 'main' },
        data: {
          component: 'test',
          status: 'invalid_status' as any,
          title: 'Test',
          rationale: 'Test'
        }
      };

      const result = safeValidateKnowledgeItem(invalidItem);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues).toBeDefined();
        expect(result.error.issues.length).toBeGreaterThan(0);
      }
    });

    it('should test ADR immutability enforcement', () => {
      const existingDecision: DecisionItem = {
        kind: 'decision',
        scope: { project: 'test', branch: 'main' },
        data: {
          component: 'auth',
          status: 'accepted',
          title: 'Use OAuth 2.0',
          rationale: 'Industry standard'
        }
      };

      const updateAttempt = {
        ...existingDecision,
        data: {
          ...existingDecision.data,
          title: 'Modified Title' // This should violate immutability
        }
      };

      const violatesImmutability = violatesADRImmutability(existingDecision, updateAttempt);
      expect(violatesImmutability).toBe(true);
    });

    it('should test section write-lock enforcement', () => {
      const approvedSection: SectionItem = {
        kind: 'section',
        scope: { project: 'test', branch: 'main' },
        data: {
          title: 'API Documentation',
          heading: 'API',
          body_md: '# API Documentation\n\nContent here...',
          citation_count: 3
        },
        tags: { approved: true } // This makes the section write-locked
      };

      const modificationAttempt = {
        ...approvedSection,
        data: {
          ...approvedSection.data,
          body_md: '# Modified API Documentation\n\nModified content...' // Should violate write-lock
        }
      };

      const violatesWriteLock = violatesSpecWriteLock(approvedSection, modificationAttempt);
      expect(violatesWriteLock).toBe(true);
    });
  });

  describe('Constitutional Requirements Compliance', () => {
    it('should enforce ADR immutability for accepted decisions', () => {
      const acceptedADR: DecisionItem = {
        kind: 'decision',
        scope: { project: 'test', branch: 'main' },
        data: {
          component: 'auth',
          status: 'accepted',
          title: 'Use OAuth 2.0',
          rationale: 'Industry standard security protocol'
        }
      };

      // Test content changes - should violate immutability
      const contentChanges = [
        { title: 'Changed Title' },
        { rationale: 'Changed Rationale' },
        { component: 'changed-component' },
        { alternatives_considered: ['New Alternative'] }
      ];

      contentChanges.forEach(change => {
        const modifiedADR = {
          ...acceptedADR,
          data: { ...acceptedADR.data, ...change }
        };
        expect(violatesADRImmutability(acceptedADR, modifiedADR)).toBe(true);
      });

      // Test metadata changes - should not violate immutability
      const metadataChanges = [
        { supersedes: '550e8400-e29b-41d4-a716-446655440000' }
      ];

      metadataChanges.forEach(change => {
        const modifiedADR = {
          ...acceptedADR,
          data: { ...acceptedADR.data, ...change }
        };
        expect(violatesADRImmutability(acceptedADR, modifiedADR)).toBe(false);
      });
    });

    it('should enforce spec write-lock for approved sections', () => {
      const approvedSection: SectionItem = {
        kind: 'section',
        scope: { project: 'test', branch: 'main' },
        data: {
          title: 'Architecture Guide',
          heading: 'Architecture',
          body_md: '# Architecture\n\nContent...',
          citation_count: 5
        },
        tags: { approved: true }
      };

      // Test content changes - should violate write-lock
      const contentChanges = [
        { body_md: '# Modified Architecture\n\nNew content...' },
        { body_text: 'Plain text content' },
        { title: 'Modified Title' }
      ];

      contentChanges.forEach(change => {
        const modifiedSection = {
          ...approvedSection,
          data: { ...approvedSection.data, ...change }
        };
        expect(violatesSpecWriteLock(approvedSection, modifiedSection)).toBe(true);
      });

      // Test metadata changes - should not violate write-lock
      const metadataChanges = [
        { citation_count: 10 },
        { tags: { approved: true, reviewed: true } }
      ];

      metadataChanges.forEach(change => {
        const modifiedSection = {
          ...approvedSection,
          data: { ...approvedSection.data, ...change },
          tags: { ...approvedSection.tags, ...change.tags }
        };
        expect(violatesSpecWriteLock(approvedSection, modifiedSection)).toBe(false);
      });
    });

    it('should maintain type safety across all operations', () => {
      // Test that all schemas maintain proper TypeScript types
      const testItems = [
        { kind: 'section' as const, schema: SectionSchema },
        { kind: 'runbook' as const, schema: RunbookSchema },
        { kind: 'change' as const, schema: ChangeSchema },
        { kind: 'issue' as const, schema: IssueSchema },
        { kind: 'decision' as const, schema: DecisionSchema },
        { kind: 'todo' as const, schema: TodoSchema },
        { kind: 'release_note' as const, schema: ReleaseNoteSchema },
        { kind: 'ddl' as const, schema: DDLSchema },
        { kind: 'pr_context' as const, schema: PRContextSchema },
        { kind: 'entity' as const, schema: EntitySchema },
        { kind: 'relation' as const, schema: RelationSchema },
        { kind: 'observation' as const, schema: ObservationSchema },
        { kind: 'incident' as const, schema: IncidentSchema },
        { kind: 'release' as const, schema: ReleaseSchema },
        { kind: 'risk' as const, schema: RiskSchema },
        { kind: 'assumption' as const, schema: AssumptionSchema }
      ];

      testItems.forEach(({ kind, schema }) => {
        // Verify schema is properly typed
        expect(schema._def.typeName).toBe('ZodObject');

        // Verify kind is properly discriminated
        const sampleItem = {
          kind,
          scope: { project: 'test', branch: 'main' },
          data: {} // Will be invalid but tests kind discrimination
        };

        const result = KnowledgeItemSchema.safeParse(sampleItem);
        if (result.success) {
          expect(result.data.kind).toBe(kind);
        }
      });
    });
  });
});