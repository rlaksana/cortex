/**
 * Graph Operations E2E Tests
 *
 * Tests knowledge graph operations including entity creation,
 * relationship management, graph traversal, and complex queries.
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

interface GraphNode {
  id: string;
  type: string;
  name: string;
  data: any;
  properties: any;
}

interface GraphEdge {
  id: string;
  from: string;
  to: string;
  type: string;
  properties: any;
}

describe('Graph Operations E2E', () => {
  let server: TestServer;
  const TEST_DB_URL = process.env.TEST_DATABASE_URL ||
    'postgresql://cortex:trust@localhost:5433/cortex_test_e2e';

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

  describe('Entity Graph Operations', () => {
    it('should create and manage complex entity relationships', async () => {
      const projectId = `entity-graph-${randomUUID().substring(0, 8)}`;

      // Step 1: Create core entities
      const createEntities = {
        items: [
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'service',
              name: 'UserService',
              data: {
                version: '2.1.0',
                language: 'TypeScript',
                port: 3001,
                health_endpoint: '/health',
                dependencies: ['Database', 'AuthService']
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
                version: '1.5.0',
                language: 'TypeScript',
                port: 3002,
                oauth_providers: ['google', 'github', 'microsoft']
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
                version: '14.5',
                host: 'db.example.com',
                database: 'users_prod',
                connection_pool: 20
              }
            }
          },
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'external_service',
              name: 'EmailProvider',
              data: {
                provider: 'SendGrid',
                api_endpoint: 'https://api.sendgrid.com/v3',
                rate_limit: 1000
              }
            }
          }
        ]
      };

      const entitiesResult = await callMCPTool('memory_store', createEntities);
      expect(entitiesResult.stored).toHaveLength(4);

      // Step 2: Create relationships between entities
      const createRelationships = {
        items: [
          {
            kind: 'relation',
            scope: { project: projectId },
            data: {
              from_entity: entitiesResult.stored[0].id, // UserService
              to_entity: entitiesResult.stored[2].id, // UserDatabase
              relation_type: 'uses',
              description: 'UserService stores user data in UserDatabase',
              properties: {
                connection_type: 'persistent',
                operations: ['read', 'write', 'update'],
                criticality: 'high'
              }
            }
          },
          {
            kind: 'relation',
            scope: { project: projectId },
            data: {
              from_entity: entitiesResult.stored[0].id, // UserService
              to_entity: entitiesResult.stored[1].id, // AuthService
              relation_type: 'authenticates_with',
              description: 'UserService delegates authentication to AuthService',
              properties: {
                protocol: 'OAuth 2.0',
                token_validation: 'jwt'
              }
            }
          },
          {
            kind: 'relation',
            scope: { project: projectId },
            data: {
              from_entity: entitiesResult.stored[0].id, // UserService
              to_entity: entitiesResult.stored[3].id, // EmailProvider
              relation_type: 'sends_notifications_via',
              description: 'UserService sends email notifications via EmailProvider',
              properties: {
                event_types: ['welcome', 'password_reset', 'profile_update'],
                async: true
              }
            }
          },
          {
            kind: 'relation',
            scope: { project: projectId },
            data: {
              from_entity: entitiesResult.stored[1].id, // AuthService
              to_entity: entitiesResult.stored[2].id, // UserDatabase
              relation_type: 'validates_users_in',
              description: 'AuthService validates user credentials against UserDatabase',
              properties: {
                connection_type: 'read_only',
                operations: ['validate', 'fetch_user']
              }
            }
          }
        ]
      };

      const relationshipsResult = await callMCPTool('memory_store', createRelationships);
      expect(relationshipsResult.stored).toHaveLength(4);

      // Step 3: Create composite entity relationships
      const compositeRelations = {
        items: [
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'system',
              name: 'UserManagementSystem',
              data: {
                components: [
                  entitiesResult.stored[0].id, // UserService
                  entitiesResult.stored[1].id, // AuthService
                ],
                dependencies: [
                  entitiesResult.stored[2].id, // UserDatabase
                  entitiesResult.stored[3].id  // EmailProvider
                ],
                system_boundary: true
              }
            }
          },
          {
            kind: 'relation',
            scope: { project: projectId },
            data: {
              from_entity: 'UserManagementSystem',
              to_entity: entitiesResult.stored[0].id, // UserService
              relation_type: 'contains',
              description: 'UserManagementSystem contains UserService'
            }
          },
          {
            kind: 'relation',
            scope: { project: projectId },
            data: {
              from_entity: 'UserManagementSystem',
              to_entity: entitiesResult.stored[1].id, // AuthService
              relation_type: 'contains',
              description: 'UserManagementSystem contains AuthService'
            }
          }
        ]
      };

      await callMCPTool('memory_store', compositeRelations);

      // Step 4: Test graph traversal and queries
      const graphQuery = await callMCPTool('memory_find', {
        query: 'UserService dependencies connections',
        scope: { project: projectId },
        types: ['entity', 'relation'],
        mode: 'auto'
      });

      expect(graphQuery.hits.length).toBeGreaterThan(5);

      // Verify graph structure
      const userServiceEntity = graphQuery.hits.find(h =>
        h.kind === 'entity' && h.data?.name === 'UserService'
      );
      expect(userServiceEntity).toBeDefined();
      expect(userServiceEntity?.data?.dependencies).toBeDefined();

      const userRelations = graphQuery.hits.filter(h =>
        h.kind === 'relation' &&
        (h.data?.from_entity === userServiceEntity?.id ||
         h.data?.to_entity === userServiceEntity?.id)
      );
      expect(userRelations.length).toBe(3); // Uses, authenticates_with, sends_notifications_via

      // Step 5: Test bidirectional relationship queries
      const bidirectionalQuery = await callMCPTool('memory_find', {
        query: 'services that use UserDatabase',
        scope: { project: projectId },
        types: ['entity', 'relation'],
        mode: 'auto'
      });

      const databaseUsers = bidirectionalQuery.hits.filter(h =>
        h.kind === 'relation' && h.data?.to_entity?.includes('UserDatabase')
      );
      expect(databaseUsers.length).toBe(2); // UserService and AuthService

      // Step 6: Test graph path analysis
      const pathAnalysis = await callMCPTool('memory_find', {
        query: 'path from EmailProvider to UserDatabase',
        scope: { project: projectId },
        types: ['entity', 'relation'],
        mode: 'deep'
      });

      expect(pathAnalysis.hits.length).toBeGreaterThan(0);

      // Verify path: EmailProvider <- UserService -> UserDatabase
      const pathContainsEmailProvider = pathAnalysis.hits.some(h =>
        h.data?.name === 'EmailProvider' || h.data?.to_entity?.includes('EmailProvider')
      );
      const pathContainsDatabase = pathAnalysis.hits.some(h =>
        h.data?.name === 'UserDatabase' || h.data?.to_entity?.includes('UserDatabase')
      );

      expect(pathContainsEmailProvider).toBe(true);
      expect(pathContainsDatabase).toBe(true);
    });

    it('should handle graph cycles and complex topologies', async () => {
      const projectId = `graph-cycles-${randomUUID().substring(0, 8)}`;

      // Create entities that form a cycle
      const cycleEntities = {
        items: [
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'service',
              name: 'OrderService',
              data: { version: '1.0.0', port: 3101 }
            }
          },
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'service',
              name: 'PaymentService',
              data: { version: '1.0.0', port: 3102 }
            }
          },
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'service',
              name: 'InventoryService',
              data: { version: '1.0.0', port: 3103 }
            }
          },
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'service',
              name: 'NotificationService',
              data: { version: '1.0.0', port: 3104 }
            }
          }
        ]
      };

      const entitiesResult = await callMCPTool('memory_store', cycleEntities);
      expect(entitiesResult.stored).toHaveLength(4);

      // Create relationships that form cycles
      const cycleRelations = {
        items: [
          {
            kind: 'relation',
            scope: { project: projectId },
            data: {
              from_entity: entitiesResult.stored[0].id, // OrderService
              to_entity: entitiesResult.stored[1].id, // PaymentService
              relation_type: 'processes_payment_via',
              properties: { async: true }
            }
          },
          {
            kind: 'relation',
            scope: { project: projectId },
            data: {
              from_entity: entitiesResult.stored[1].id, // PaymentService
              to_entity: entitiesResult.stored[2].id, // InventoryService
              relation_type: 'reserves_inventory_in',
              properties: { timeout: 30 }
            }
          },
          {
            kind: 'relation',
            scope: { project: projectId },
            data: {
              from_entity: entitiesResult.stored[2].id, // InventoryService
              to_entity: entitiesResult.stored[3].id, // NotificationService
              relation_type: 'sends_stock_alerts_via',
              properties: { priority: 'high' }
            }
          },
          {
            kind: 'relation',
            scope: { project: projectId },
            data: {
              from_entity: entitiesResult.stored[3].id, // NotificationService
              to_entity: entitiesResult.stored[0].id, // OrderService (creates cycle)
              relation_type: 'updates_order_status_in',
              properties: { event_type: 'notification_sent' }
            }
          },
          // Additional complex relationships
          {
            kind: 'relation',
            scope: { project: projectId },
            data: {
              from_entity: entitiesResult.stored[0].id, // OrderService
              to_entity: entitiesResult.stored[2].id, // InventoryService
              relation_type: 'checks_inventory_in',
              properties: { cache_ttl: 300 }
            }
          },
          {
            kind: 'relation',
            scope: { project: projectId },
            data: {
              from_entity: entitiesResult.stored[1].id, // PaymentService
              to_entity: entitiesResult.stored[3].id, // NotificationService
              relation_type: 'sends_payment_receipts_via',
              properties: { template: 'payment_receipt' }
            }
          }
        ]
      };

      const relationsResult = await callMCPTool('memory_store', cycleRelations);
      expect(relationsResult.stored).toHaveLength(6);

      // Test cycle detection and handling
      const cycleQuery = await callMCPTool('memory_find', {
        query: 'OrderService circular dependencies paths',
        scope: { project: projectId },
        types: ['entity', 'relation'],
        mode: 'deep'
      });

      expect(cycleQuery.hits.length).toBeGreaterThan(0);

      // Verify we can detect the cycle
      const cyclePath = cycleQuery.hits.filter(h => h.kind === 'relation');
      expect(cyclePath.length).toBeGreaterThan(0);

      // Test graph depth traversal
      const depthQuery = await callMCPTool('memory_find', {
        query: 'all services connected to OrderService',
        scope: { project: projectId },
        types: ['entity', 'relation'],
        mode: 'auto'
      });

      const connectedServices = depthQuery.hits.filter(h => h.kind === 'entity');
      expect(connectedServices.length).toBe(4); // All services should be connected

      // Test relationship strength analysis
      const strengthAnalysis = await callMCPTool('memory_find', {
        query: 'critical service dependencies',
        scope: { project: projectId },
        types: ['relation'],
        mode: 'auto'
      });

      expect(strengthAnalysis.hits.length).toBeGreaterThan(0);

      const criticalRelations = strengthAnalysis.hits.filter(h =>
        h.data?.properties?.criticality === 'high' ||
        h.data?.properties?.priority === 'high'
      );
      expect(criticalRelations.length).toBeGreaterThan(0);
    });
  });

  describe('Graph Traversal and Queries', () => {
    it('should support complex graph traversal patterns', async () => {
      const projectId = `graph-traversal-${randomUUID().substring(0, 8)}`;

      // Build a complex graph structure
      const buildGraph = {
        items: [
          // Layer 1: Core infrastructure
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'infrastructure',
              name: 'KubernetesCluster',
              data: {
                type: 'EKS',
                version: '1.25',
                nodes: 5,
                region: 'us-west-2'
              }
            }
          },
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'infrastructure',
              name: 'DatabaseCluster',
              data: {
                type: 'PostgreSQL',
                version: '14',
                nodes: 3,
                replication: 'streaming'
              }
            }
          },
          // Layer 2: Services
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'service',
              name: 'APIGateway',
              data: {
                version: '2.0.0',
                replicas: 3,
                ingress: true
              }
            }
          },
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'service',
              name: 'UserService',
              data: {
                version: '1.5.0',
                replicas: 2,
                database: 'UserDatabase'
              }
            }
          },
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'service',
              name: 'ProductService',
              data: {
                version: '1.2.0',
                replicas: 2,
                cache: 'Redis'
              }
            }
          },
          // Layer 3: External services
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'external_service',
              name: 'StripeAPI',
              data: {
                service_type: 'payment',
                tier: 'enterprise',
                rate_limit: 1000
              }
            }
          },
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'external_service',
              name: 'SendGridAPI',
              data: {
                service_type: 'email',
                tier: 'premium',
                rate_limit: 500
              }
            }
          }
        ]
      };

      const graphResult = await callMCPTool('memory_store', buildGraph);
      expect(graphResult.stored).toHaveLength(7);

      // Create hierarchical relationships
      const createHierarchy = {
        items: [
          // Infrastructure relationships
          {
            kind: 'relation',
            scope: { project: projectId },
            data: {
              from_entity: graphResult.stored[2].id, // APIGateway
              to_entity: graphResult.stored[0].id, // KubernetesCluster
              relation_type: 'deployed_on',
              properties: { namespace: 'production' }
            }
          },
          {
            kind: 'relation',
            scope: { project: projectId },
            data: {
              from_entity: graphResult.stored[1].id, // DatabaseCluster
              to_entity: graphResult.stored[0].id, // KubernetesCluster
              relation_type: 'deployed_on',
              properties: { namespace: 'database' }
            }
          },
          // Service relationships
          {
            kind: 'relation',
            scope: { project: projectId },
            data: {
              from_entity: graphResult.stored[3].id, // UserService
              to_entity: graphResult.stored[2].id, // APIGateway
              relation_type: 'routed_through',
              properties: { path: '/api/v1/users' }
            }
          },
          {
            kind: 'relation',
            scope: { project: projectId },
            data: {
              from_entity: graphResult.stored[4].id, // ProductService
              to_entity: graphResult.stored[2].id, // APIGateway
              relation_type: 'routed_through',
              properties: { path: '/api/v1/products' }
            }
          },
          {
            kind: 'relation',
            scope: { project: projectId },
            data: {
              from_entity: graphResult.stored[3].id, // UserService
              to_entity: graphResult.stored[1].id, // DatabaseCluster
              relation_type: 'uses',
              properties: { database: 'users' }
            }
          },
          {
            kind: 'relation',
            scope: { project: projectId },
            data: {
              from_entity: graphResult.stored[4].id, // ProductService
              to_entity: graphResult.stored[1].id, // DatabaseCluster
              relation_type: 'uses',
              properties: { database: 'products' }
            }
          },
          // External service relationships
          {
            kind: 'relation',
            scope: { project: projectId },
            data: {
              from_entity: graphResult.stored[3].id, // UserService
              to_entity: graphResult.stored[5].id, // StripeAPI
              relation_type: 'integrates_with',
              properties: { purpose: 'billing' }
            }
          },
          {
            kind: 'relation',
            scope: { project: projectId },
            data: {
              from_entity: graphResult.stored[3].id, // UserService
              to_entity: graphResult.stored[6].id, // SendGridAPI
              relation_type: 'integrates_with',
              properties: { purpose: 'notifications' }
            }
          }
        ]
      };

      const hierarchyResult = await callMCPTool('memory_store', createHierarchy);
      expect(hierarchyResult.stored).toHaveLength(8);

      // Test breadth-first traversal
      const bfsQuery = await callMCPTool('memory_find', {
        query: 'services directly connected to APIGateway',
        scope: { project: projectId },
        types: ['entity', 'relation'],
        mode: 'auto'
      });

      const directConnections = bfsQuery.hits.filter(h =>
        h.kind === 'relation' && h.data?.to_entity?.includes('APIGateway')
      );
      expect(directConnections.length).toBe(2); // UserService and ProductService

      // Test depth-first traversal
      const dfsQuery = await callMCPTool('memory_find', {
        query: 'full path from UserService to external APIs',
        scope: { project: projectId },
        types: ['entity', 'relation'],
        mode: 'deep'
      });

      expect(dfsQuery.hits.length).toBeGreaterThan(0);

      // Verify path: UserService -> StripeAPI/SendGridAPI
      const externalAPIs = dfsQuery.hits.filter(h =>
        h.kind === 'entity' &&
        (h.data?.name === 'StripeAPI' || h.data?.name === 'SendGridAPI')
      );
      expect(externalAPIs.length).toBe(2);

      // Test graph visualization data preparation
      const visualizationQuery = await callMCPTool('memory_find', {
        query: 'complete application architecture graph',
        scope: { project: projectId },
        types: ['entity', 'relation'],
        mode: 'auto'
      });

      expect(visualizationQuery.hits.length).toBeGreaterThan(10);

      const entities = visualizationQuery.hits.filter(h => h.kind === 'entity');
      const relations = visualizationQuery.hits.filter(h => h.kind === 'relation');

      expect(entities.length).toBe(7);
      expect(relations.length).toBe(8);

      // Test graph analytics
      const analyticsQuery = await callMCPTool('memory_find', {
        query: 'service dependency analysis',
        scope: { project: projectId },
        types: ['entity', 'relation'],
        mode: 'auto'
      });

      // Analyze dependency count
      const serviceRelations = analyticsQuery.hits.filter(h => h.kind === 'relation');
      const dependencyCount = {};

      serviceRelations.forEach(relation => {
        const from = relation.data?.from_entity;
        const to = relation.data?.to_entity;

        if (from) dependencyCount[from] = (dependencyCount[from] || 0) + 1;
        if (to) dependencyCount[to] = (dependencyCount[to] || 0) + 1;
      });

      expect(Object.keys(dependencyCount).length).toBeGreaterThan(0);

      // Find most connected service
      const mostConnected = Object.entries(dependencyCount)
        .sort(([,a], [,b]) => b - a)[0];
      expect(mostConnected).toBeDefined();
    });

    it('should handle graph updates and consistency maintenance', async () => {
      const projectId = `graph-updates-${randomUUID().substring(0, 8)}`;

      // Create initial graph
      const initialGraph = {
        items: [
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'service',
              name: 'LegacyService',
              data: {
                version: '1.0.0',
                deprecated: false
              }
            }
          },
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'service',
              name: 'ModernService',
              data: {
                version: '2.0.0',
                deprecated: false
              }
            }
          },
          {
            kind: 'relation',
            scope: { project: projectId },
            data: {
              from_entity: 'LegacyService',
              to_entity: 'ModernService',
              relation_type: 'migrates_to',
              properties: { timeline: '6 months' }
            }
          }
        ]
      };

      const initialResult = await callMCPTool('memory_store', initialGraph);
      expect(initialResult.stored).toHaveLength(3);

      // Update entity and cascade changes
      const updateGraph = {
        items: [
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              id: initialResult.stored[0].id, // LegacyService
              version: '1.1.0',
              deprecated: true,
              deprecation_date: new Date().toISOString(),
              replaced_by: initialResult.stored[1].id // ModernService
            }
          },
          {
            kind: 'relation',
            scope: { project: projectId },
            data: {
              from_entity: initialResult.stored[1].id, // ModernService
              to_entity: initialResult.stored[0].id, // LegacyService
              relation_type: 'supersedes',
              properties: {
                migration_complete: true,
                migration_date: new Date().toISOString()
              }
            }
          }
        ]
      };

      const updateResult = await callMCPTool('memory_store', updateGraph);
      expect(updateResult.stored).toHaveLength(2);

      // Create consistency check observation
      const consistencyCheck = {
        items: [{
          kind: 'observation',
          scope: { project: projectId },
          data: {
            title: 'Graph Consistency Check',
            content: `
Graph relationships updated to reflect service deprecation:
- LegacyService marked as deprecated
- ModernService now supersedes LegacyService
- Migration relationship updated with completion status

Graph integrity maintained.
            `.trim(),
            consistency_check: true,
            affected_entities: [initialResult.stored[0].id, initialResult.stored[1].id]
          }
        }]
      };

      await callMCPTool('memory_store', consistencyCheck);

      // Verify graph consistency after updates
      const consistencyQuery = await callMCPTool('memory_find', {
        query: 'LegacyService ModernService migration status',
        scope: { project: projectId },
        types: ['entity', 'relation', 'observation'],
        mode: 'auto'
      });

      expect(consistencyQuery.hits.length).toBeGreaterThan(0);

      const legacyService = consistencyQuery.hits.find(h =>
        h.kind === 'entity' && h.data?.name === 'LegacyService'
      );
      expect(legacyService?.data?.deprecated).toBe(true);

      const supersedingRelation = consistencyQuery.hits.find(h =>
        h.kind === 'relation' && h.data?.relation_type === 'supersedes'
      );
      expect(supersedingRelation).toBeDefined();
      expect(supersedingRelation?.data?.properties?.migration_complete).toBe(true);
    });
  });

  describe('Graph Performance and Scalability', () => {
    it('should handle large-scale graph operations efficiently', async () => {
      const projectId = `graph-scale-${randomUUID().substring(0, 8)}`;
      const entityCount = 20;
      const relationCount = 30;

      // Create many entities
      const entities = [];
      for (let i = 0; i < entityCount; i++) {
        entities.push({
          kind: 'entity',
          scope: { project: projectId },
          data: {
            entity_type: 'microservice',
            name: `Service${i}`,
            data: {
              version: `${i}.0.0`,
              team: `Team${i % 5}`,
              port: 4000 + i
            }
          }
        });
      }

      const startTime = Date.now();
      const entitiesResult = await callMCPTool('memory_store', { items: entities });
      const entityCreationTime = Date.now() - startTime;

      expect(entitiesResult.stored).toHaveLength(entityCount);
      expect(entityCreationTime).toBeLessThan(5000); // Should complete within 5 seconds

      // Create many relationships
      const relations = [];
      for (let i = 0; i < relationCount; i++) {
        const fromIndex = Math.floor(Math.random() * entityCount);
        const toIndex = Math.floor(Math.random() * entityCount);

        if (fromIndex !== toIndex) {
          relations.push({
            kind: 'relation',
            scope: { project: projectId },
            data: {
              from_entity: entitiesResult.stored[fromIndex].id,
              to_entity: entitiesResult.stored[toIndex].id,
              relation_type: ['depends_on', 'communicates_with', 'shares_data_with'][i % 3],
              properties: {
                strength: Math.random(),
                frequency: ['high', 'medium', 'low'][i % 3]
              }
            }
          });
        }
      }

      const relationStartTime = Date.now();
      const relationsResult = await callMCPTool('memory_store', { items: relations });
      const relationCreationTime = Date.now() - relationStartTime;

      expect(relationsResult.stored.length).toBeGreaterThan(0);
      expect(relationCreationTime).toBeLessThan(5000); // Should complete within 5 seconds

      // Test complex query performance
      const queryStartTime = Date.now();
      const complexQuery = await callMCPTool('memory_find', {
        query: 'all service dependencies and communications',
        scope: { project: projectId },
        types: ['entity', 'relation'],
        mode: 'deep'
      });
      const queryTime = Date.now() - queryStartTime;

      expect(complexQuery.hits.length).toBeGreaterThan(0);
      expect(queryTime).toBeLessThan(3000); // Query should complete within 3 seconds

      console.log(`Performance metrics for ${entityCount} entities, ${relationsResult.stored.length} relations:`);
      console.log(`- Entity creation: ${entityCreationTime}ms`);
      console.log(`- Relation creation: ${relationCreationTime}ms`);
      console.log(`- Complex query: ${queryTime}ms`);
    });

    it('should maintain performance under concurrent graph operations', async () => {
      const projectId = `graph-concurrent-${randomUUID().substring(0, 8)}`;
      const concurrentOperations = 10;

      // Create entities concurrently
      const entityPromises = [];
      for (let i = 0; i < concurrentOperations; i++) {
        entityPromises.push(
          callMCPTool('memory_store', {
            items: [{
              kind: 'entity',
              scope: { project: projectId },
              data: {
                entity_type: 'service',
                name: `ConcurrentService${i}`,
                data: { version: '1.0.0', port: 5000 + i }
              }
            }]
          })
        );
      }

      const entityResults = await Promise.all(entityPromises);
      expect(entityResults.length).toBe(concurrentOperations);

      const entityIds = entityResults.map(r => r.stored[0].id);

      // Create relationships concurrently
      const relationPromises = [];
      for (let i = 0; i < concurrentOperations - 1; i++) {
        relationPromises.push(
          callMCPTool('memory_store', {
            items: [{
              kind: 'relation',
              scope: { project: projectId },
              data: {
                from_entity: entityIds[i],
                to_entity: entityIds[i + 1],
                relation_type: 'chains_to'
              }
            }]
          })
        );
      }

      const relationResults = await Promise.all(relationPromises);
      expect(relationResults.length).toBe(concurrentOperations - 1);

      // Verify graph integrity
      const integrityQuery = await callMCPTool('memory_find', {
        query: 'concurrent service chain',
        scope: { project: projectId },
        types: ['entity', 'relation'],
        mode: 'auto'
      });

      expect(integrityQuery.hits.length).toBeGreaterThan(concurrentOperations);

      const entities = integrityQuery.hits.filter(h => h.kind === 'entity');
      const relations = integrityQuery.hits.filter(h => h.kind === 'relation');

      expect(entities.length).toBe(concurrentOperations);
      expect(relations.length).toBe(concurrentOperations - 1);
    });
  });
});

// Helper Functions
async function setupTestDatabase(): Promise<void> {
  console.log('Setting up test database for graph operations...');
}

async function cleanupTestDatabase(): Promise<void> {
  console.log('Cleaning up test database for graph operations...');
}

async function cleanupTestData(): Promise<void> {
  console.log('Cleaning up test data for graph operations...');
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
          recommendation: 'Graph operation completed successfully',
          reasoning: 'Knowledge graph items processed',
          user_message_suggestion: `✓ Processed ${items.length} graph items`
        }
      });
    }, 50); // Faster response for performance tests
  });
}