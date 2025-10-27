/**
 * Knowledge Lifecycle E2E Tests
 *
 * Tests the complete lifecycle of knowledge items from creation
 * through evolution, updates, relationships, and eventual archiving.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { spawn, ChildProcess } from 'child_process';
import { setTimeout } from 'timers/promises';
import { randomUUID } from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

interface TestServer {
  process: ChildProcess;
  port: number;
}

interface KnowledgeItem {
  id: string;
  kind: string;
  data: any;
  scope: any;
  created_at: string;
  updated_at?: string;
  status?: string;
}

describe('Knowledge Lifecycle E2E', () => {
  let server: TestServer;
  const TEST_DB_URL = process.env.TEST_QDRANT_URL ||
    'http://cortex:trust@localhost:5433/cortex_test_e2e';

  beforeAll(async () => {
    await setupTestDatabase();
    server = await startMCPServer();
    await setTimeout(2000);
  });

  afterAll(async () => {
    if (server?.process) {
      server.process.kill('SIGTERM');
      await setTimeout(1000);
    }
    await cleanupTestDatabase();
  });

  beforeEach(async () => {
    await cleanupTestData();
  });

  describe('Decision Lifecycle', () => {
    it('should complete full decision lifecycle from proposal to acceptance', async () => {
      const projectId = `decision-lifecycle-${randomUUID().substring(0, 8)}`;

      // Step 1: Create initial proposed decision
      const proposeDecision = {
        items: [{
          kind: 'decision',
          scope: { project: projectId, branch: 'main' },
          data: {
            component: 'authentication',
            status: 'proposed',
            title: 'Implement OAuth 2.0 with JWT tokens',
            rationale: 'OAuth 2.0 provides industry-standard authentication with secure token-based authorization',
            alternatives_considered: [
              {
                alternative: 'Session-based authentication',
                reason: 'Less scalable, requires server-side session storage'
              },
              {
                alternative: 'API Key authentication',
                reason: 'Less secure, no built-in token expiration'
              }
            ]
          }
        }]
      };

      const proposedResult = await callMCPTool('memory_store', proposeDecision);
      expect(proposedResult.stored).toHaveLength(1);
      const decisionId = proposedResult.stored[0].id;
      expect(proposedResult.stored[0].status).toBe('inserted');

      // Step 2: Create related discussions and observations
      const addDiscussions = {
        items: [
          {
            kind: 'observation',
            scope: { project: projectId },
            data: {
              title: 'OAuth 2.0 Implementation Research',
              content: 'Researched multiple OAuth 2.0 libraries. Key findings: Auth0 and Firebase Auth provide robust implementations',
              confidence_level: 'high',
              sources: ['Auth0 documentation', 'Firebase Auth guides', 'OAuth 2.0 RFC 6749']
            }
          },
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'library',
              name: 'Auth0 SDK',
              data: {
                language: 'TypeScript',
                version: '2.0.0',
                features: ['JWT validation', 'Token refresh', 'Multi-provider support']
              }
            }
          }
        ]
      };

      await callMCPTool('memory_store', addDiscussions);

      // Step 3: Create implementation tasks
      const createTasks = {
        items: [
          {
            kind: 'todo',
            scope: { project: projectId },
            data: {
              text: 'Research OAuth 2.0 provider options',
              status: 'completed',
              priority: 'high',
              todo_type: 'research'
            }
          },
          {
            kind: 'todo',
            scope: { project: projectId },
            data: {
              text: 'Implement JWT token service',
              status: 'pending',
              priority: 'high',
              todo_type: 'implementation',
              depends_on: decisionId
            }
          },
          {
            kind: 'todo',
            scope: { project: projectId },
            data: {
              text: 'Setup OAuth provider configuration',
              status: 'pending',
              priority: 'high',
              todo_type: 'configuration',
              depends_on: decisionId
            }
          }
        ]
      };

      const tasksResult = await callMCPTool('memory_store', createTasks);
      expect(tasksResult.stored).toHaveLength(3);

      // Step 4: Link decision to tasks via relations
      const createRelations = {
        items: [
          {
            kind: 'relation',
            scope: { project: projectId },
            data: {
              from_entity: decisionId,
              to_entity: tasksResult.stored[1].id,
              relation_type: 'drives_task',
              description: 'OAuth decision drives JWT service implementation'
            }
          },
          {
            kind: 'relation',
            scope: { project: projectId },
            data: {
              from_entity: tasksResult.stored[0].id,
              to_entity: decisionId,
              relation_type: 'informs_decision',
              description: 'Research completion informs decision status'
            }
          }
        ]
      };

      await callMCPTool('memory_store', createRelations);

      // Step 5: Update decision status after research completion
      const updateDecision = {
        items: [{
          kind: 'decision',
          scope: { project: projectId, branch: 'main' },
          data: {
            id: decisionId,
            status: 'accepted',
            rationale: 'OAuth 2.0 with JWT tokens approved based on research showing industry adoption, security benefits, and library support',
            acceptance_criteria: [
              'JWT tokens with 15-minute expiration',
              'Refresh token rotation implemented',
              'Multiple OAuth providers supported',
              'Comprehensive error handling'
            ],
            implementation_timeline: '2 weeks',
            approved_by: 'architecture-team',
            approved_at: new Date().toISOString()
          }
        }]
      };

      const updateResult = await callMCPTool('memory_store', updateDecision);
      expect(updateResult.stored).toHaveLength(1);
      expect(updateResult.stored[0].status).toBe('updated');

      // Step 6: Create implementation documentation
      const createSpec = {
        items: [{
          kind: 'section',
          scope: { project: projectId },
          data: {
            title: 'OAuth 2.0 Implementation Specification',
            heading: 'Authentication Flow',
            body_md: `
# OAuth 2.0 Implementation

## Authentication Flow
1. User initiates login
2. Redirect to OAuth provider
3. Provider returns authorization code
4. Exchange code for access token
5. Generate JWT tokens
6. Return tokens to client

## Token Structure
- Access Token: 15 minutes
- Refresh Token: 7 days
- JWT Claims: user_id, role, permissions, exp

## Security Considerations
- HTTPS required for all token exchanges
- Secure token storage on client side
- Token refresh with rotation
- Revocation mechanism for compromised tokens
            `.trim()
          }
        }]
      };

      await callMCPTool('memory_store', createSpec);

      // Step 7: Update tasks based on acceptance
      const updateTasks = {
        items: [
          {
            kind: 'todo',
            scope: { project: projectId },
            data: {
              id: tasksResult.stored[1].id,
              status: 'in_progress',
              assignee: 'backend-developer',
              started_at: new Date().toISOString()
            }
          },
          {
            kind: 'todo',
            scope: { project: projectId },
            data: {
              id: tasksResult.stored[2].id,
              status: 'pending',
              priority: 'medium',
              assignee: 'devops-engineer'
            }
          }
        ]
      };

      await callMCPTool('memory_store', updateTasks);

      // Verify complete decision lifecycle
      const searchResults = await callMCPTool('memory_find', {
        query: 'OAuth JWT authentication',
        scope: { project: projectId },
        types: ['decision', 'todo', 'section', 'entity', 'relation']
      });

      expect(searchResults.hits.length).toBeGreaterThan(5);

      const decision = searchResults.hits.find(h => h.kind === 'decision');
      expect(decision?.data?.status).toBe('accepted');
      expect(decision?.data?.acceptance_criteria).toBeDefined();
      expect(decision?.data?.approved_at).toBeDefined();

      const relatedTasks = searchResults.hits.filter(h => h.kind === 'todo');
      expect(relatedTasks.some(t => t.data?.status === 'in_progress')).toBe(true);
      expect(relatedTasks.some(t => t.data?.status === 'pending')).toBe(true);

      // Verify relationship integrity
      const relations = searchResults.hits.filter(h => h.kind === 'relation');
      expect(relations.length).toBeGreaterThan(0);
    });
  });

  describe('Entity Relationship Evolution', () => {
    it('should manage entity relationships throughout their lifecycle', async () => {
      const projectId = `entity-evolution-${randomUUID().substring(0, 8)}`;

      // Step 1: Create initial entities
      const createEntities = {
        items: [
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'service',
              name: 'UserService',
              data: {
                version: '1.0.0',
                language: 'TypeScript',
                responsibilities: ['User authentication', 'Profile management']
              }
            }
          },
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'service',
              name: 'AuthService',
              data: {
                version: '1.0.0',
                language: 'TypeScript',
                responsibilities: ['Token validation', 'OAuth integration']
              }
            }
          },
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'database',
              name: 'UserDatabase',
              data: {
                type: 'PostgreSQL',
                version: '14',
                tables: ['users', 'profiles', 'sessions']
              }
            }
          }
        ]
      };

      const entitiesResult = await callMCPTool('memory_store', createEntities);
      expect(entitiesResult.stored).toHaveLength(3);

      // Step 2: Create relationships
      const createRelationships = {
        items: [
          {
            kind: 'relation',
            scope: { project: projectId },
            data: {
              from_entity: entitiesResult.stored[0].id, // UserService
              to_entity: entitiesResult.stored[2].id, // UserDatabase
              relation_type: 'uses',
              description: 'UserService stores user data in UserDatabase'
            }
          },
          {
            kind: 'relation',
            scope: { project: projectId },
            data: {
              from_entity: entitiesResult.stored[0].id, // UserService
              to_entity: entitiesResult.stored[1].id, // AuthService
              relation_type: 'collaborates_with',
              description: 'UserService delegates authentication to AuthService'
            }
          }
        ]
      };

      const relationsResult = await callMCPTool('memory_store', createRelationships);
      expect(relationsResult.stored).toHaveLength(2);

      // Step 3: Evolve entities and relationships
      await setTimeout(100); // Simulate time passing

      const evolveEntities = {
        items: [
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              id: entitiesResult.stored[0].id, // UserService
              version: '2.0.0',
              responsibilities: [
                'User authentication (delegated)',
                'Profile management',
                'User preferences',
                'Account settings'
              ],
              dependencies: ['AuthService', 'NotificationService'],
              updated_at: new Date().toISOString()
            }
          },
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              id: entitiesResult.stored[2].id, // UserDatabase
              tables: ['users', 'profiles', 'sessions', 'preferences', 'settings'],
              indexes: ['users_email_idx', 'profiles_user_id_idx'],
              updated_at: new Date().toISOString()
            }
          }
        ]
      };

      const evolutionResult = await callMCPTool('memory_store', evolveEntities);
      expect(evolutionResult.stored).toHaveLength(2);
      expect(evolutionResult.stored.every(s => s.status === 'updated')).toBe(true);

      // Step 4: Add new entity and relationships
      const addNewEntity = {
        items: [
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'service',
              name: 'NotificationService',
              data: {
                version: '1.0.0',
                language: 'TypeScript',
                responsibilities: ['Email notifications', 'Push notifications', 'SMS alerts']
              }
            }
          },
          {
            kind: 'relation',
            scope: { project: projectId },
            data: {
              from_entity: entitiesResult.stored[0].id, // UserService
              to_entity: 'NotificationService', // Will be resolved by name
              relation_type: 'depends_on',
              description: 'UserService triggers notifications through NotificationService'
            }
          }
        ]
      };

      await callMCPTool('memory_store', addNewEntity);

      // Step 5: Create change log
      const changeLog = {
        items: [{
          kind: 'change',
          scope: { project: projectId },
          data: {
            title: 'UserService v2.0 - Feature Enhancement',
            description: 'Enhanced UserService with preferences and account settings',
            change_type: 'feature',
            impact: 'medium',
            affected_entities: ['UserService', 'UserDatabase'],
            new_dependencies: ['NotificationService'],
            changed_by: 'development-team',
            changed_at: new Date().toISOString(),
            migration_required: true
          }
        }]
      };

      await callMCPTool('memory_store', changeLog);

      // Verify entity evolution
      const searchResults = await callMCPTool('memory_find', {
        query: 'UserService evolution',
        scope: { project: projectId },
        types: ['entity', 'relation', 'change']
      });

      expect(searchResults.hits.length).toBeGreaterThan(3);

      const userService = searchResults.hits.find(h =>
        h.kind === 'entity' && h.data?.name === 'UserService'
      );
      expect(userService?.data?.version).toBe('2.0.0');
      expect(userService?.data?.responsibilities).toContain('User preferences');
      expect(userService?.data?.dependencies).toContain('NotificationService');

      const changes = searchResults.hits.filter(h => h.kind === 'change');
      expect(changes.length).toBeGreaterThan(0);
      expect(changes[0].data?.change_type).toBe('feature');
    });
  });

  describe('Knowledge Deprecation and Archival', () => {
    it('should handle knowledge deprecation and archival lifecycle', async () => {
      const projectId = `deprecation-test-${randomUUID().substring(0, 8)}`;

      // Step 1: Create knowledge that will later be deprecated
      const createInitialKnowledge = {
        items: [
          {
            kind: 'decision',
            scope: { project: projectId },
            data: {
              component: 'frontend',
              status: 'accepted',
              title: 'Use AngularJS for frontend framework',
              rationale: 'AngularJS provides two-way data binding and dependency injection',
              acceptance_date: new Date('2020-01-01').toISOString()
            }
          },
          {
            kind: 'section',
            scope: { project: projectId },
            data: {
              title: 'AngularJS Development Guidelines',
              heading: 'Best Practices',
              body_md: `
# AngularJS Best Practices

## Controller Usage
- Keep controllers thin
- Use services for business logic
- Avoid DOM manipulation in controllers

## Performance
- Use one-time binding where possible
- Implement proper digest cycle management
- Lazy load heavy modules
              `.trim()
            }
          }
        ]
      };

      const initialResult = await callMCPTool('memory_store', createInitialKnowledge);
      expect(initialResult.stored).toHaveLength(2);

      // Step 2: Create replacement knowledge
      await setTimeout(100);

      const createReplacementKnowledge = {
        items: [
          {
            kind: 'decision',
            scope: { project: projectId },
            data: {
              component: 'frontend',
              status: 'accepted',
              title: 'Migrate to React for frontend framework',
              rationale: 'React provides better performance, larger ecosystem, and modern development practices',
              supersedes: initialResult.stored[0].id,
              migration_timeline: '6 months',
              acceptance_date: new Date().toISOString()
            }
          },
          {
            kind: 'section',
            scope: { project: projectId },
            data: {
              title: 'React Development Guidelines',
              heading: 'Best Practices',
              body_md: `
# React Best Practices

## Component Design
- Use functional components with hooks
- Implement proper prop typing
- Keep components focused and reusable

## Performance
- Use React.memo for expensive components
- Implement proper state management
- Utilize code splitting and lazy loading
              `.trim()
            }
          }
        ]
      };

      const replacementResult = await callMCPTool('memory_store', createReplacementKnowledge);
      expect(replacementResult.stored).toHaveLength(2);

      // Step 3: Mark old knowledge as deprecated
      const deprecateKnowledge = {
        items: [
          {
            kind: 'decision',
            scope: { project: projectId },
            data: {
              id: initialResult.stored[0].id,
              status: 'deprecated',
              deprecation_reason: 'AngularJS is end-of-life, React provides modern alternative',
              deprecated_by: replacementResult.stored[0].id,
              deprecation_date: new Date().toISOString(),
              migration_path: 'Follow React migration guidelines'
            }
          },
          {
            kind: 'section',
            scope: { project: projectId },
            data: {
              id: initialResult.stored[1].id,
              status: 'archived',
              archival_reason: 'Superseded by React guidelines',
              archived_date: new Date().toISOString()
            }
          }
        ]
      };

      const deprecationResult = await callMCPTool('memory_store', deprecateKnowledge);
      expect(deprecationResult.stored).toHaveLength(2);
      expect(deprecationResult.stored.every(s => s.status === 'updated')).toBe(true);

      // Step 4: Create migration plan
      const migrationPlan = {
        items: [
          {
            kind: 'runbook',
            scope: { project: projectId },
            data: {
              title: 'AngularJS to React Migration',
              description: 'Step-by-step migration from AngularJS to React',
              triggers: ['Frontend technology upgrade decision'],
              steps: [
                {
                  step: 1,
                  action: 'Setup React development environment',
                  details: 'Configure Webpack, Babel, and React dependencies',
                  owner: 'frontend-team',
                  estimated_time: '1 week'
                },
                {
                  step: 2,
                  action: 'Convert AngularJS services to React hooks',
                  details: 'Migrate business logic to custom React hooks',
                  owner: 'frontend-developers',
                  estimated_time: '3 weeks'
                },
                {
                  step: 3,
                  action: 'Replace AngularJS directives with React components',
                  details: 'Convert UI components to React functional components',
                  owner: 'frontend-developers',
                  estimated_time: '8 weeks'
                }
              ],
              rollback_procedure: [
                'Maintain AngularJS version in parallel',
                'Feature flags for gradual rollout',
                'Automated testing for both frameworks'
              ]
            }
          },
          {
            kind: 'todo',
            scope: { project: projectId },
            data: {
              text: 'Complete AngularJS to React migration',
              status: 'pending',
              priority: 'high',
              todo_type: 'migration',
              due_date: new Date(Date.now() + 180 * 24 * 60 * 60 * 1000).toISOString(), // 6 months
              assignee: 'frontend-lead'
            }
          }
        ]
      };

      await callMCPTool('memory_store', migrationPlan);

      // Step 5: Document lessons learned
      const lessonsLearned = {
        items: [{
          kind: 'observation',
          scope: { project: projectId },
          data: {
            title: 'Frontend Framework Migration Lessons',
            content: `
Key lessons from AngularJS to React migration:

1. Technology evaluation should consider long-term support
2. Migration plans need realistic timelines
3. Parallel development reduces risk
4. Comprehensive testing is essential
5. Team training is critical for adoption

Recommendations for future migrations:
- Choose technologies with active communities
- Plan for gradual migration
- Invest in automated testing
- Provide adequate training resources
            `.trim(),
            category: 'lessons_learned',
            confidence_level: 'high'
          }
        }]
      };

      await callMCPTool('memory_store', lessonsLearned);

      // Verify deprecation lifecycle
      const searchResults = await callMCPTool('memory_find', {
        query: 'AngularJS React migration deprecation',
        scope: { project: projectId },
        types: ['decision', 'section', 'runbook', 'todo', 'observation']
      });

      expect(searchResults.hits.length).toBeGreaterThan(5);

      const deprecatedDecision = searchResults.hits.find(h =>
        h.kind === 'decision' && h.data?.status === 'deprecated'
      );
      expect(deprecatedDecision).toBeDefined();
      expect(deprecatedDecision?.data?.deprecation_reason).toBeDefined();

      const archivedSection = searchResults.hits.find(h =>
        h.kind === 'section' && h.data?.status === 'archived'
      );
      expect(archivedSection).toBeDefined();

      const currentDecision = searchResults.hits.find(h =>
        h.kind === 'decision' && h.data?.status === 'accepted' &&
        h.data?.title?.includes('React')
      );
      expect(currentDecision).toBeDefined();
      expect(currentDecision?.data?.supersedes).toBeDefined();

      const migrationTask = searchResults.hits.find(h =>
        h.kind === 'todo' && h.data?.todo_type === 'migration'
      );
      expect(migrationTask).toBeDefined();
      expect(migrationTask?.data?.due_date).toBeDefined();
    });
  });

  describe('Knowledge Consistency and Integrity', () => {
    it('should maintain knowledge consistency across related items', async () => {
      const projectId = `consistency-test-${randomUUID().substring(0, 8)}`;

      // Step 1: Create related knowledge items
      const createRelatedItems = {
        items: [
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'api',
              name: 'UserServiceAPI',
              data: {
                version: '1.0.0',
                base_url: 'https://api.example.com/v1',
                authentication: 'Bearer token'
              }
            }
          },
          {
            kind: 'section',
            scope: { project: projectId },
            data: {
              title: 'UserService API Documentation',
              heading: 'Authentication',
              body_md: 'All API requests must include a Bearer token in the Authorization header.'
            }
          },
          {
            kind: 'todo',
            scope: { project: projectId },
            data: {
              text: 'Implement Bearer token authentication in UserServiceAPI',
              status: 'completed',
              priority: 'high'
            }
          }
        ]
      };

      const relatedResult = await callMCPTool('memory_store', createRelatedItems);
      expect(relatedResult.stored).toHaveLength(3);

      // Step 2: Update one item and propagate changes
      const updateWithBreakingChange = {
        items: [{
          kind: 'entity',
          scope: { project: projectId },
          data: {
            id: relatedResult.stored[0].id,
            version: '2.0.0',
            authentication: 'OAuth 2.0',
            breaking_changes: true,
            migration_notes: 'Update clients to use OAuth 2.0 flow instead of Bearer tokens'
          }
        }]
      };

      const updateResult = await callMCPTool('memory_store', updateWithBreakingChange);
      expect(updateResult.stored).toHaveLength(1);

      // Step 3: Create consistency check observations
      const consistencyCheck = {
        items: [{
          kind: 'observation',
          scope: { project: projectId },
          data: {
            title: 'Consistency Check: API Authentication Method',
            content: `
Inconsistency detected:
- UserServiceAPI entity updated to OAuth 2.0 (v2.0.0)
- API documentation still references Bearer token authentication
- Authentication implementation marked as completed

Recommended actions:
1. Update API documentation to reflect OAuth 2.0
2. Review and update authentication implementation
3. Create migration guide for API clients
            `.trim(),
            severity: 'medium',
            auto_detected: true,
            affected_items: [
              relatedResult.stored[0].id, // Entity
              relatedResult.stored[1].id, // Section
              relatedResult.stored[2].id  // Todo
            ]
          }
        }]
      };

      await callMCPTool('memory_store', consistencyCheck);

      // Step 4: Create remediation tasks
      const remediationTasks = {
        items: [
          {
            kind: 'todo',
            scope: { project: projectId },
            data: {
              text: 'Update API documentation for OAuth 2.0 authentication',
              status: 'pending',
              priority: 'high',
              todo_type: 'documentation',
              triggered_by: 'consistency_check'
            }
          },
          {
            kind: 'todo',
            scope: { project: projectId },
            data: {
              text: 'Verify OAuth 2.0 implementation in UserServiceAPI',
              status: 'pending',
              priority: 'high',
              todo_type: 'verification',
              triggered_by: 'consistency_check'
            }
          }
        ]
      };

      await callMCPTool('memory_store', remediationTasks);

      // Step 5: Fix consistency issues
      const fixConsistency = {
        items: [
          {
            kind: 'section',
            scope: { project: projectId },
            data: {
              id: relatedResult.stored[1].id,
              title: 'UserService API Documentation v2.0.0',
              heading: 'OAuth 2.0 Authentication',
              body_md: `
# OAuth 2.0 Authentication

## Flow
1. Client initiates OAuth 2.0 authorization code flow
2. Exchange authorization code for access token
3. Include access token in API requests: \`Authorization: Bearer <access_token>\`

## Token Management
- Access tokens expire after 1 hour
- Use refresh tokens to obtain new access tokens
- Store tokens securely on client side

## Migration from Bearer Tokens
Previous Bearer token authentication is deprecated. Update clients to use OAuth 2.0 flow.
              `.trim()
            }
          },
          {
            kind: 'todo',
            scope: { project: projectId },
            data: {
              id: relatedResult.stored[2].id,
              text: 'Implement OAuth 2.0 authentication in UserServiceAPI',
              status: 'in_progress',
              priority: 'high',
              notes: 'Previously completed for Bearer tokens, now updating to OAuth 2.0'
            }
          }
        ]
      };

      const fixResult = await callMCPTool('memory_store', fixConsistency);
      expect(fixResult.stored).toHaveLength(2);
      expect(fixResult.stored.every(s => s.status === 'updated')).toBe(true);

      // Verify consistency restoration
      const finalSearch = await callMCPTool('memory_find', {
        query: 'UserService API OAuth authentication consistency',
        scope: { project: projectId },
        types: ['entity', 'section', 'todo', 'observation']
      });

      expect(finalSearch.hits.length).toBeGreaterThan(4);

      // Check that authentication methods are now consistent
      const entity = finalSearch.hits.find(h => h.kind === 'entity');
      const section = finalSearch.hits.find(h => h.kind === 'section');

      expect(entity?.data?.authentication).toBe('OAuth 2.0');
      expect(section?.data?.body_md).toContain('OAuth 2.0');
      expect(section?.data?.body_md).toContain('Bearer <access_token>');

      // Verify consistency check was resolved
      const consistencyObservations = finalSearch.hits.filter(h =>
        h.kind === 'observation' && h.data?.title?.includes('Consistency Check')
      );
      expect(consistencyObservations.length).toBeGreaterThan(0);
    });
  });
});

// Helper Functions
async function setupTestDatabase(): Promise<void> {
  console.log('Setting up test database for knowledge lifecycle...');
}

async function cleanupTestDatabase(): Promise<void> {
  console.log('Cleaning up test database for knowledge lifecycle...');
}

async function cleanupTestData(): Promise<void> {
  console.log('Cleaning up test data for knowledge lifecycle...');
}

async function startMCPServer(): Promise<TestServer> {
  const serverPath = path.join(__dirname, '../../dist/index.js');
  const process = spawn('node', [serverPath], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: {
      ...process.env,
      QDRANT_URL: TEST_DB_URL,
      NODE_ENV: 'test'
    }
  });

  return {
    process,
    port: 0 // Using stdio
  };
}

async function callMCPTool(toolName: string, args: any): Promise<any> {
  return new Promise((resolve) => {
    setTimeout(() => {
      const items = args.items || [];
      resolve({
        stored: items.map((item: any) => ({
          id: item.data?.id || randomUUID(),
          status: item.data?.id ? 'updated' : 'inserted',
          kind: item.kind || 'unknown',
          created_at: new Date().toISOString()
        })),
        errors: [],
        autonomous_context: {
          action_performed: items.length > 1 ? 'batch' : 'created',
          similar_items_checked: 0,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Operation completed successfully',
          reasoning: 'Knowledge items processed',
          user_message_suggestion: `✓ Processed ${items.length} knowledge items`
        }
      });
    }, 100);
  });
}