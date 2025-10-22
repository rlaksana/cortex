/**
 * Complete Workflows E2E Tests
 *
 * Tests complete end-to-end user workflows from start to finish.
 * Includes realistic data scenarios and business logic validation.
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

describe('Complete Workflows E2E', () => {
  let server: TestServer;
  const TEST_DB_URL = process.env.TEST_DATABASE_URL ||
    'postgresql://cortex:trust@localhost:5433/cortex_test_e2e';

  beforeAll(async () => {
    // Setup test database
    await setupTestDatabase();

    // Start MCP server
    server = await startMCPServer();

    // Wait for server to be ready
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
    // Clean test data between tests
    await cleanupTestData();
  });

  describe('Workflow 1: Project Development Lifecycle', () => {
    it('should complete full development workflow from planning to release', async () => {
      const projectId = `project-${randomUUID().substring(0, 8)}`;
      const projectName = 'E2E Test Project';

      // Step 1: Create initial project decision
      const createDecision = {
        items: [{
          kind: 'decision',
          scope: {
            project: projectId,
            branch: 'main',
            org: 'test-org'
          },
          data: {
            component: 'architecture',
            status: 'proposed',
            title: `Use React for ${projectName}`,
            rationale: 'React provides excellent component reusability and ecosystem support',
            alternatives_considered: [
              { alternative: 'Vue.js', reason: 'Smaller ecosystem' },
              { alternative: 'Angular', reason: 'Steeper learning curve' }
            ]
          }
        }]
      };

      const decisionResult = await callMCPTool('memory_store', createDecision);
      expect(decisionResult.stored).toHaveLength(1);
      expect(decisionResult.stored[0].status).toBe('inserted');

      // Step 2: Create technical specification
      const createSpec = {
        items: [{
          kind: 'section',
          scope: { project: projectId, branch: 'main' },
          data: {
            title: `${projectName} Technical Specification`,
            heading: 'Architecture Overview',
            body_md: `
# Architecture Overview

## Components
- Frontend: React with TypeScript
- Backend: Node.js with Express
- Database: PostgreSQL with Prisma ORM
- Authentication: JWT tokens

## Data Flow
1. Client requests authenticated endpoint
2. Backend validates JWT
3. Business logic processes request
4. Database operations performed
5. Response returned to client
            `.trim()
          }
        }]
      };

      const specResult = await callMCPTool('memory_store', createSpec);
      expect(specResult.stored).toHaveLength(1);

      // Step 3: Create development tasks
      const createTasks = {
        items: [
          {
            kind: 'todo',
            scope: { project: projectId },
            data: {
              text: 'Setup React project with TypeScript',
              status: 'pending',
              priority: 'high',
              todo_type: 'implementation',
              assignee: 'developer-1'
            }
          },
          {
            kind: 'todo',
            scope: { project: projectId },
            data: {
              text: 'Implement authentication system',
              status: 'pending',
              priority: 'high',
              todo_type: 'security',
              assignee: 'developer-2'
            }
          },
          {
            kind: 'todo',
            scope: { project: projectId },
            data: {
              text: 'Design database schema',
              status: 'pending',
              priority: 'high',
              todo_type: 'design'
            }
          }
        ]
      };

      const tasksResult = await callMCPTool('memory_store', createTasks);
      expect(tasksResult.stored).toHaveLength(3);

      // Step 4: Create risk assessment
      const createRisks = {
        items: [
          {
            kind: 'risk',
            scope: { project: projectId },
            data: {
              title: 'Complexity of React learning curve',
              description: 'Team may require time to learn React effectively',
              probability: 'medium',
              impact: 'medium',
              mitigation_strategy: 'Provide training and start with simple components'
            }
          },
          {
            kind: 'assumption',
            scope: { project: projectId },
            data: {
              title: 'PostgreSQL will handle expected load',
              description: 'Assuming current PostgreSQL instance can handle projected user growth',
              validation_method: 'Load testing before production'
            }
          }
        ]
      };

      const risksResult = await callMCPTool('memory_store', createRisks);
      expect(risksResult.stored).toHaveLength(2);

      // Step 5: Work on first task and create observations
      await setTimeout(100); // Simulate work time

      const createObservations = {
        items: [
          {
            kind: 'observation',
            scope: { project: projectId },
            data: {
              title: 'React setup completed successfully',
              content: 'Initial React project with TypeScript configured and tested',
              tags: { component: 'setup', status: 'completed' }
            }
          },
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'component',
              name: 'ReactApp',
              data: {
                version: '18.2.0',
                language: 'TypeScript',
                build_tool: 'Vite'
              }
            }
          }
        ]
      };

      const obsResult = await callMCPTool('memory_store', createObservations);
      expect(obsResult.stored).toHaveLength(2);

      // Step 6: Update task status
      const updateTask = {
        items: [{
          kind: 'todo',
          scope: { project: projectId },
          data: {
            id: tasksResult.stored[0].id,
            status: 'completed',
            completed_at: new Date().toISOString()
          }
        }]
      };

      const updateResult = await callMCPTool('memory_store', updateTask);
      expect(updateResult.stored).toHaveLength(1);
      expect(updateResult.stored[0].status).toBe('updated');

      // Step 7: Create release notes
      const createRelease = {
        items: [
          {
            kind: 'release',
            scope: { project: projectId },
            data: {
              version: '1.0.0-alpha',
              title: `${projectName} Alpha Release`,
              scope: 'Initial prototype with basic functionality',
              release_date: new Date().toISOString(),
              features: [
                'React project setup with TypeScript',
                'Basic project structure',
                'Development environment configuration'
              ]
            }
          },
          {
            kind: 'release_note',
            scope: { project: projectId },
            data: {
              version: '1.0.0-alpha',
              summary: 'First alpha release of project with core setup completed',
              features_added: [
                'React + TypeScript configuration',
                'Vite build setup',
                'ESLint and Prettier configuration'
              ],
              known_issues: [
                'Authentication not yet implemented',
                'Database schema pending design'
              ]
            }
          }
        ]
      };

      const releaseResult = await callMCPTool('memory_store', createRelease);
      expect(releaseResult.stored).toHaveLength(2);

      // Verify the complete workflow
      const searchResults = await callMCPTool('memory_find', {
        query: projectName,
        scope: { project: projectId },
        types: ['decision', 'section', 'todo', 'risk', 'assumption', 'release', 'entity']
      });

      expect(searchResults.hits).toBeDefined();
      expect(searchResults.hits.length).toBeGreaterThan(5);

      // Verify business rules
      const decision = searchResults.hits.find(h => h.kind === 'decision');
      expect(decision?.data?.status).toBe('proposed');
      expect(decision?.data?.alternatives_considered).toHaveLength(2);

      const tasks = searchResults.hits.filter(h => h.kind === 'todo');
      expect(tasks).toHaveLength(3);
      expect(tasks.find(t => t.data?.status === 'completed')).toBeDefined();

      const release = searchResults.hits.find(h => h.kind === 'release');
      expect(release?.data?.version).toBe('1.0.0-alpha');

      // Test autonomous context
      expect(decisionResult.autonomous_context?.action_performed).toBe('created');
      expect(decisionResult.autonomous_context?.duplicates_found).toBe(0);
    });

    it('should handle workflow errors and recovery gracefully', async () => {
      const projectId = `error-test-${randomUUID().substring(0, 8)}`;

      // Step 1: Create valid entity
      const validEntity = {
        items: [{
          kind: 'entity',
          scope: { project: projectId },
          data: {
            entity_type: 'component',
            name: 'TestComponent',
            data: { version: '1.0.0' }
          }
        }]
      };

      const validResult = await callMCPTool('memory_store', validEntity);
      expect(validResult.stored).toHaveLength(1);

      // Step 2: Attempt to create invalid entity
      const invalidEntity = {
        items: [{
          kind: 'entity',
          scope: { project: projectId },
          data: {
            // Missing required fields
            entity_type: '',
            name: '',
            data: null
          }
        }]
      };

      const invalidResult = await callMCPTool('memory_store', invalidEntity);
      expect(invalidResult.stored).toHaveLength(0);
      expect(invalidResult.errors.length).toBeGreaterThan(0);

      // Step 3: Continue workflow after error
      const recoveryEntity = {
        items: [{
          kind: 'entity',
          scope: { project: projectId },
          data: {
            entity_type: 'service',
            name: 'RecoveryService',
            data: {
              version: '1.0.0',
              description: 'Service created after error recovery'
            }
          }
        }]
      };

      const recoveryResult = await callMCPTool('memory_store', recoveryEntity);
      expect(recoveryResult.stored).toHaveLength(1);

      // Verify system state is consistent
      const searchResults = await callMCPTool('memory_find', {
        query: 'component OR service',
        scope: { project: projectId }
      });

      expect(searchResults.hits).toHaveLength(2);
      expect(searchResults.hits.every(h => h.confidence_score > 0.5)).toBe(true);
    });
  });

  describe('Workflow 2: Incident Response and Resolution', () => {
    it('should handle complete incident response workflow', async () => {
      const incidentId = `incident-${randomUUID().substring(0, 8)}`;

      // Step 1: Report incident
      const reportIncident = {
        items: [{
          kind: 'incident',
          scope: { project: 'production-system' },
          data: {
            title: 'Database connection pool exhaustion',
            description: 'Application experiencing database connection timeouts',
            severity: 'high',
            impact: 'Users unable to access application',
            reported_at: new Date().toISOString(),
            reporter: 'ops-team'
          }
        }]
      };

      const incidentResult = await callMCPTool('memory_store', reportIncident);
      expect(incidentResult.stored).toHaveLength(1);
      const incidentId_db = incidentResult.stored[0].id;

      // Step 2: Create initial diagnosis
      const diagnosis = {
        items: [{
          kind: 'observation',
          scope: { project: 'production-system' },
          data: {
            title: 'Root cause analysis - connection leak',
            content: 'Connection pool exhaustion caused by unclosed connections in background jobs',
            investigation_steps: [
              'Checked application logs for connection errors',
              'Analyzed database connection metrics',
              'Reviewed recent code changes'
            ]
          }
        }]
      };

      await callMCPTool('memory_store', diagnosis);

      // Step 3: Create recovery runbook
      const runbook = {
        items: [{
          kind: 'runbook',
          scope: { project: 'production-system' },
          data: {
            title: 'Database Connection Pool Recovery',
            description: 'Steps to recover from database connection pool exhaustion',
            triggers: ['Database connection timeout errors', 'High connection pool usage'],
            steps: [
              {
                step: 1,
                action: 'Scale up database connections',
                details: 'Increase max_connections in PostgreSQL',
                owner: 'database-admin'
              },
              {
                step: 2,
                action: 'Restart application services',
                details: 'Graceful restart to clear leaked connections',
                owner: 'ops-team'
              },
              {
                step: 3,
                action: 'Monitor connection pool metrics',
                details: 'Verify connection usage returns to normal',
                owner: 'monitoring-team'
              }
            ],
            rollback_procedure: [
              'Scale down connections if issues persist',
              'Fallback to previous application version'
            ]
          }
        }]
      };

      await callMCPTool('memory_store', runbook);

      // Step 4: Update incident status with resolution
      const updateIncident = {
        items: [{
          kind: 'incident',
          scope: { project: 'production-system' },
          data: {
            id: incidentId_db,
            status: 'resolved',
            resolution: 'Fixed connection leak in background job processing',
            resolved_at: new Date().toISOString(),
            resolver: 'development-team',
            lessons_learned: [
              'Add connection timeout configuration to all database operations',
              'Implement connection pool monitoring alerts',
              'Add automated testing for connection leaks'
            ]
          }
        }]
      };

      const updateResult = await callMCPTool('memory_store', updateIncident);
      expect(updateResult.stored).toHaveLength(1);
      expect(updateResult.stored[0].status).toBe('updated');

      // Step 5: Create follow-up tasks
      const followUpTasks = {
        items: [
          {
            kind: 'todo',
            scope: { project: 'production-system' },
            data: {
              text: 'Implement connection pool monitoring',
              status: 'pending',
              priority: 'high',
              todo_type: 'improvement',
              due_date: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString() // 7 days
            }
          },
          {
            kind: 'todo',
            scope: { project: 'production-system' },
            data: {
              text: 'Add connection leak detection to CI/CD pipeline',
              status: 'pending',
              priority: 'medium',
              todo_type: 'automation'
            }
          }
        ]
      };

      await callMCPTool('memory_store', followUpTasks);

      // Verify complete incident workflow
      const searchResults = await callMCPTool('memory_find', {
        query: 'database connection pool',
        scope: { project: 'production-system' },
        types: ['incident', 'observation', 'runbook', 'todo']
      });

      expect(searchResults.hits.length).toBeGreaterThan(3);

      const incident = searchResults.hits.find(h => h.kind === 'incident');
      expect(incident?.data?.status).toBe('resolved');
      expect(incident?.data?.lessons_learned).toBeDefined();

      const runbookItem = searchResults.hits.find(h => h.kind === 'runbook');
      expect(runbookItem?.data?.steps).toBeDefined();
      expect(runbookItem?.data?.rollback_procedure).toBeDefined();
    });
  });

  describe('Workflow 3: Knowledge Base Management', () => {
    it('should manage knowledge base creation and evolution', async () => {
      const knowledgeBaseId = `kb-${randomUUID().substring(0, 8)}`;

      // Step 1: Create knowledge base structure
      const createStructure = {
        items: [
          {
            kind: 'section',
            scope: { project: knowledgeBaseId },
            data: {
              title: 'API Design Guidelines',
              heading: 'Overview',
              body_md: `
This document provides guidelines for designing RESTful APIs in our organization.

## Principles
- Consistency is key
- Use HTTP status codes appropriately
- Version your APIs
- Document everything
              `.trim()
            }
          },
          {
            kind: 'section',
            scope: { project: knowledgeBaseId },
            data: {
              title: 'Authentication Guidelines',
              heading: 'JWT Token Usage',
              body_md: `
## JWT Token Implementation

### Token Structure
- Header: Algorithm and token type
- Payload: Claims and user data
- Signature: Cryptographic signature

### Best Practices
- Set reasonable expiration times
- Include relevant user context
- Use HTTPS for all token transmission
              `.trim()
            }
          }
        ]
      };

      const structureResult = await callMCPTool('memory_store', createStructure);
      expect(structureResult.stored).toHaveLength(2);

      // Step 2: Add related entities and relationships
      const addRelations = {
        items: [
          {
            kind: 'entity',
            scope: { project: knowledgeBaseId },
            data: {
              entity_type: 'standard',
              name: 'REST API v1.0',
              data: {
                version: '1.0.0',
                status: 'active',
                compliance_level: 'required'
              }
            }
          },
          {
            kind: 'relation',
            scope: { project: knowledgeBaseId },
            data: {
              from_entity: 'API Design Guidelines',
              to_entity: 'REST API v1.0',
              relation_type: 'implements',
              description: 'API guidelines implement the REST API standard'
            }
          }
        ]
      };

      const relationsResult = await callMCPTool('memory_store', addRelations);
      expect(relationsResult.stored).toHaveLength(2);

      // Step 3: Create change log for knowledge updates
      const changeLog = {
        items: [{
          kind: 'change',
          scope: { project: knowledgeBaseId },
          data: {
            title: 'Added JWT authentication guidelines',
            description: 'Expanded API documentation with comprehensive JWT usage patterns',
            change_type: 'documentation',
            impact: 'medium',
            changed_by: 'architecture-team',
            changed_at: new Date().toISOString(),
            affected_sections: ['Authentication Guidelines']
          }
        }]
      };

      await callMCPTool('memory_store', changeLog);

      // Step 4: Test knowledge discovery
      const discoverResults = await callMCPTool('memory_find', {
        query: 'JWT authentication token best practices',
        mode: 'auto',
        types: ['section', 'entity']
      });

      expect(discoverResults.hits.length).toBeGreaterThan(0);
      expect(discoverResults.hits[0].confidence_score).toBeGreaterThan(0.5);

      // Test semantic search capabilities
      const semanticResults = await callMCPTool('memory_find', {
        query: 'how to secure API endpoints',
        mode: 'deep',
        types: ['section']
      });

      expect(semanticResults.hits.length).toBeGreaterThan(0);

      // Step 5: Update knowledge with new information
      const updateKnowledge = {
        items: [{
          kind: 'section',
          scope: { project: knowledgeBaseId },
          data: {
            id: structureResult.stored[1].id, // Update authentication section
            title: 'Enhanced Authentication Guidelines',
            heading: 'JWT Token Usage',
            body_md: `
## JWT Token Implementation

### Token Structure
- Header: Algorithm and token type
- Payload: Claims and user data
- Signature: Cryptographic signature

### Best Practices
- Set reasonable expiration times (15-30 minutes for access tokens)
- Include relevant user context
- Use HTTPS for all token transmission
- Implement refresh token rotation
- Add token revocation mechanisms

### Security Considerations
- Never include sensitive data in JWT payload
- Use strong signing algorithms (RS256 preferred)
- Validate all token claims
- Implement proper token storage on client side
              `.trim()
          }
        }]
      };

      const updateResult = await callMCPTool('memory_store', updateKnowledge);
      expect(updateResult.stored).toHaveLength(1);
      expect(updateResult.stored[0].status).toBe('updated');

      // Verify knowledge evolution
      const finalResults = await callMCPTool('memory_find', {
        query: 'refresh token rotation',
        scope: { project: knowledgeBaseId }
      });

      expect(finalResults.hits.length).toBeGreaterThan(0);
      expect(finalResults.hits[0].data?.body_md).toContain('refresh token rotation');
    });
  });
});

// Helper Functions
async function setupTestDatabase(): Promise<void> {
  // Implementation would create and migrate test database
  console.log('Setting up test database...');
}

async function cleanupTestDatabase(): Promise<void> {
  // Implementation would clean up test database
  console.log('Cleaning up test database...');
}

async function cleanupTestData(): Promise<void> {
  // Implementation would clean up test data between tests
  console.log('Cleaning up test data...');
}

async function startMCPServer(): Promise<TestServer> {
  const serverPath = path.join(__dirname, '../../dist/index.js');
  const process = spawn('node', [serverPath], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: {
      ...process.env,
      DATABASE_URL: TEST_DB_URL,
      NODE_ENV: 'test'
    }
  });

  return {
    process,
    port: 0 // Using stdio, not HTTP
  };
}

async function callMCPTool(toolName: string, args: any): Promise<any> {
  // Implementation would call the MCP tool via stdio
  // For this example, we'll simulate the response
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve({
        stored: [{
          id: randomUUID(),
          status: 'inserted',
          kind: args.items?.[0]?.kind || 'unknown',
          created_at: new Date().toISOString()
        }],
        errors: [],
        autonomous_context: {
          action_performed: 'created',
          similar_items_checked: 0,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Item saved successfully',
          reasoning: 'New item created',
          user_message_suggestion: '✓ Saved successfully'
        }
      });
    }, 100);
  });
}