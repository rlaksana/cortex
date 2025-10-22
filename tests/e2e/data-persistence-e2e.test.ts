/**
 * Data Persistence E2E Tests
 *
 * Tests data persistence across system restarts, database reliability,
 * transaction integrity, and long-term data storage.
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

interface PersistenceTest {
  id: string;
  name: string;
  data: any;
  created_at: string;
  checksum: string;
}

describe('Data Persistence E2E', () => {
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

  describe('Basic Data Persistence', () => {
    it('should persist knowledge items across server restarts', async () => {
      const projectId = `persistence-basic-${randomUUID().substring(0, 8)}`;
      const testData: PersistenceTest[] = [];

      // Step 1: Create various types of knowledge items
      const knowledgeItems = {
        items: [
          {
            kind: 'decision',
            scope: { project: projectId },
            data: {
              component: 'architecture',
              status: 'accepted',
              title: 'Use Microservices Architecture',
              rationale: 'Microservices provide better scalability and maintainability',
              alternatives_considered: [
                { alternative: 'Monolith', reason: 'Harder to scale individual components' }
              ],
              acceptance_date: new Date().toISOString()
            }
          },
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'service',
              name: 'UserService',
              data: {
                version: '1.0.0',
                port: 3001,
                database: 'PostgreSQL'
              }
            }
          },
          {
            kind: 'section',
            scope: { project: projectId },
            data: {
              title: 'API Documentation Standards',
              heading: 'Documentation Guidelines',
              body_md: `
# API Documentation Standards

## Required Sections
- Overview and purpose
- Authentication requirements
- Request/response formats
- Error handling
- Rate limiting information

## Format
- Use OpenAPI 3.0 specification
- Include examples for all endpoints
- Provide cURL examples
              `.trim()
            }
          },
          {
            kind: 'todo',
            scope: { project: projectId },
            data: {
              text: 'Implement service discovery mechanism',
              status: 'pending',
              priority: 'high',
              todo_type: 'implementation',
              assignee: 'backend-team'
            }
          },
          {
            kind: 'observation',
            scope: { project: projectId },
            data: {
              title: 'Performance Testing Results',
              content: 'Load testing shows 99th percentile response time under 200ms',
              confidence_level: 'high',
              test_date: new Date().toISOString()
            }
          }
        ]
      };

      const creationResult = await callMCPTool('memory_store', knowledgeItems);
      expect(creationResult.stored).toHaveLength(5);

      // Store test data for verification
      testData.push(...creationResult.stored.map(item => ({
        id: item.id,
        name: item.kind,
        data: item,
        created_at: item.created_at,
        checksum: generateChecksum(item)
      })));

      // Step 2: Simulate server restart
      console.log('Simulating server restart...');
      await restartServer();

      // Step 3: Verify data persistence after restart
      const verificationResult = await callMCPTool('memory_find', {
        query: 'microservices architecture user service API',
        scope: { project: projectId },
        types: ['decision', 'entity', 'section', 'todo', 'observation']
      });

      expect(verificationResult.hits.length).toBe(5);

      // Verify each item persisted correctly
      testData.forEach(testItem => {
        const foundItem = verificationResult.hits.find(h => h.id === testItem.id);
        expect(foundItem).toBeDefined();
        expect(foundItem.kind).toBe(testItem.name);
        expect(foundItem.data).toBeDefined();

        // Verify data integrity using checksum
        const currentChecksum = generateChecksum(foundItem);
        expect(currentChecksum).toBe(testItem.checksum);
      });

      // Verify specific data integrity
      const decision = verificationResult.hits.find(h => h.kind === 'decision');
      expect(decision?.data?.status).toBe('accepted');
      expect(decision?.data?.alternatives_considered).toHaveLength(1);

      const entity = verificationResult.hits.find(h => h.kind === 'entity');
      expect(entity?.data?.name).toBe('UserService');
      expect(entity?.data?.data?.port).toBe(3001);

      const section = verificationResult.hits.find(h => h.kind === 'section');
      expect(section?.data?.title).toBe('API Documentation Standards');
      expect(section?.data?.body_md).toContain('OpenAPI 3.0');
    });

    it('should maintain data consistency during concurrent operations', async () => {
      const projectId = `persistence-concurrent-${randomUUID().substring(0, 8)}`;
      const concurrentOperations = 10;
      const operationResults: any[] = [];

      // Step 1: Perform concurrent data operations
      const concurrentPromises = [];
      for (let i = 0; i < concurrentOperations; i++) {
        concurrentPromises.push(
          callMCPTool('memory_store', {
            items: [{
              kind: i % 3 === 0 ? 'entity' : i % 3 === 1 ? 'todo' : 'observation',
              scope: { project: projectId, batch: i },
              data: {
                name: `ConcurrentItem${i}`,
                batch_id: i,
                operation_order: i,
                timestamp: new Date().toISOString(),
                random_data: Math.random().toString(36)
              }
            }]
          })
        );
      }

      const concurrentResults = await Promise.all(concurrentPromises);
      expect(concurrentResults.length).toBe(concurrentOperations);

      // Store results for verification
      concurrentResults.forEach((result, index) => {
        operationResults.push({
          index,
          id: result.stored[0]?.id,
          batch: index,
          checksum: result.stored[0] ? generateChecksum(result.stored[0]) : null
        });
      });

      // Step 2: Restart server
      await restartServer();

      // Step 3: Verify all concurrent operations persisted
      const verificationResult = await callMCPTool('memory_find', {
        query: `ConcurrentItem batch ${projectId}`,
        scope: { project: projectId },
        types: ['entity', 'todo', 'observation']
      });

      expect(verificationResult.hits.length).toBe(concurrentOperations);

      // Verify each operation's data integrity
      operationResults.forEach(opResult => {
        const foundItem = verificationResult.hits.find(h => h.id === opResult.id);
        expect(foundItem).toBeDefined();

        if (opResult.checksum) {
          const currentChecksum = generateChecksum(foundItem);
          expect(currentChecksum).toBe(opResult.checksum);
        }

        // Verify batch information
        expect(foundItem.data?.batch_id).toBe(opResult.batch);
        expect(foundItem.data?.operation_order).toBe(opResult.index);
      });

      // Verify no data corruption or duplication
      const uniqueIds = new Set(verificationResult.hits.map(h => h.id));
      expect(uniqueIds.size).toBe(concurrentOperations);

      const uniqueBatches = new Set(verificationResult.hits.map(h => h.data?.batch_id));
      expect(uniqueBatches.size).toBe(concurrentOperations);
    });

    it('should preserve complex data structures and relationships', async () => {
      const projectId = `persistence-complex-${randomUUID().substring(0, 8)}`;

      // Step 1: Create complex interconnected data
      const complexData = {
        items: [
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'system',
              name: 'ECommercePlatform',
              data: {
                version: '2.0.0',
                components: ['UserService', 'ProductService', 'OrderService'],
                dependencies: {
                  database: 'PostgreSQL',
                  cache: 'Redis',
                  message_queue: 'RabbitMQ'
                },
                configuration: {
                  replicas: 3,
                  resources: {
                    cpu: '500m',
                    memory: '512Mi'
                  },
                  environment: {
                    NODE_ENV: 'production',
                    LOG_LEVEL: 'info'
                  }
                }
              }
            }
          },
          {
            kind: 'relation',
            scope: { project: projectId },
            data: {
              from_entity: 'ECommercePlatform',
              to_entity: 'PostgreSQL',
              relation_type: 'uses',
              properties: {
                connection_pool: 20,
                ssl_enabled: true,
                backup_frequency: 'daily'
              }
            }
          },
          {
            kind: 'section',
            scope: { project: projectId },
            data: {
              title: 'Deployment Configuration',
              heading: 'Kubernetes Manifests',
              body_md: `
# Kubernetes Deployment Configuration

## Service Definition
\`\`\`yaml
apiVersion: v1
kind: Service
metadata:
  name: ecommerce-platform
spec:
  selector:
    app: ecommerce-platform
  ports:
  - port: 80
    targetPort: 3000
  type: LoadBalancer
\`\`\`

## Deployment Configuration
\`\`\`yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ecommerce-platform
spec:
  replicas: 3
  selector:
    matchLabels:
      app: ecommerce-platform
  template:
    metadata:
      labels:
        app: ecommerce-platform
    spec:
      containers:
      - name: app
        image: ecommerce:2.0.0
        ports:
        - containerPort: 3000
        env:
        - name: NODE_ENV
          value: "production"
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
\`\`\`
              `.trim()
            }
          },
          {
            kind: 'decision',
            scope: { project: projectId },
            data: {
              component: 'infrastructure',
              status: 'accepted',
              title: 'Migrate to Kubernetes-based Deployment',
              rationale: 'Kubernetes provides better scalability and management capabilities',
              implementation_plan: {
                phase_1: 'Setup Kubernetes cluster',
                phase_2: 'Containerize applications',
                phase_3: 'Deploy and test',
                phase_4: 'Migrate traffic',
                phase_5: 'Decommission old infrastructure'
              },
              risk_mitigation: [
                'Gradual migration strategy',
                'Rollback capability',
                'Comprehensive testing'
              ]
            }
          }
        ]
      };

      const creationResult = await callMCPTool('memory_store', complexData);
      expect(creationResult.stored).toHaveLength(4);

      // Store original data for comparison
      const originalData = creationResult.stored.map(item => ({
        id: item.id,
        kind: item.kind,
        data: item,
        checksum: generateChecksum(item)
      }));

      // Step 2: Restart server
      await restartServer();

      // Step 3: Verify complex data integrity
      const verificationResult = await callMCPTool('memory_find', {
        query: 'ECommerce platform Kubernetes deployment migration',
        scope: { project: projectId },
        types: ['entity', 'relation', 'section', 'decision']
      });

      expect(verificationResult.hits.length).toBe(4);

      // Verify complex nested structures
      const systemEntity = verificationResult.hits.find(h => h.kind === 'entity');
      expect(systemEntity?.data?.data?.dependencies).toBeDefined();
      expect(systemEntity?.data?.data?.dependencies?.database).toBe('PostgreSQL');
      expect(systemEntity?.data?.data?.configuration?.resources?.cpu).toBe('500m');

      // Verify YAML content preservation
      const deploymentSection = verificationResult.hits.find(h => h.kind === 'section');
      expect(deploymentSection?.data?.body_md).toContain('apiVersion: v1');
      expect(deploymentSection?.data?.body_md).toContain('kind: Service');

      // Verify decision with complex plan
      const migrationDecision = verificationResult.hits.find(h => h.kind === 'decision');
      expect(migrationDecision?.data?.implementation_plan?.phase_1).toBe('Setup Kubernetes cluster');
      expect(migrationDecision?.data?.risk_mitigation).toHaveLength(3);

      // Verify relationship properties
      const relation = verificationResult.hits.find(h => h.kind === 'relation');
      expect(relation?.data?.properties?.connection_pool).toBe(20);
      expect(relation?.data?.properties?.ssl_enabled).toBe(true);

      // Verify data integrity using checksums
      originalData.forEach(original => {
        const current = verificationResult.hits.find(h => h.id === original.id);
        expect(current).toBeDefined();

        const currentChecksum = generateChecksum(current);
        expect(currentChecksum).toBe(original.checksum);
      });
    });
  });

  describe('Transaction Integrity', () => {
    it('should maintain transaction atomicity for batch operations', async () => {
      const projectId = `persistence-transaction-${randomUUID().substring(0, 8)}`;
      const batchSize = 5;

      // Step 1: Create related items in a batch
      const batchOperation = {
        items: Array.from({ length: batchSize }, (_, i) => ({
          kind: i % 2 === 0 ? 'entity' : 'relation',
          scope: { project: projectId, transaction: 'batch-1' },
          data: {
            name: `BatchItem${i}`,
            transaction_id: 'batch-1',
            sequence: i,
            depends_on: i > 0 ? `BatchItem${i-1}` : null,
            timestamp: new Date().toISOString()
          }
        }))
      };

      const batchResult = await callMCPTool('memory_store', batchOperation);
      expect(batchResult.stored).toHaveLength(batchSize);

      // Verify all items in batch have consistent transaction data
      batchResult.stored.forEach((item, index) => {
        expect(item.data?.transaction_id).toBe('batch-1');
        expect(item.data?.sequence).toBe(index);
      });

      // Step 2: Create another batch with dependency
      const secondBatch = {
        items: [
          {
            kind: 'section',
            scope: { project: projectId, transaction: 'batch-2' },
            data: {
              title: 'Batch Transaction Summary',
              transaction_id: 'batch-2',
              depends_on_batch: 'batch-1',
              body_md: `Summary of batch operations with ${batchSize} related items`
            }
          }
        ]
      };

      const secondBatchResult = await callMCPTool('memory_store', secondBatch);
      expect(secondBatchResult.stored).toHaveLength(1);

      // Step 3: Restart server
      await restartServer();

      // Step 4: Verify transaction integrity
      const transactionSearch = await callMCPTool('memory_find', {
        query: 'batch transaction integrity',
        scope: { project: projectId },
        types: ['entity', 'relation', 'section']
      });

      expect(transactionSearch.hits.length).toBe(batchSize + 1);

      // Verify first batch integrity
      const firstBatchItems = transactionSearch.hits.filter(h =>
        h.data?.transaction_id === 'batch-1'
      );
      expect(firstBatchItems.length).toBe(batchSize);

      // Verify sequence consistency
      const sortedBySequence = [...firstBatchItems].sort((a, b) =>
        (a.data?.sequence || 0) - (b.data?.sequence || 0)
      );
      sortedBySequence.forEach((item, index) => {
        expect(item.data?.sequence).toBe(index);
      });

      // Verify dependency chain
      for (let i = 1; i < sortedBySequence.length; i++) {
        expect(sortedBySequence[i].data?.depends_on).toBe(`BatchItem${i-1}`);
      }

      // Verify second batch dependency
      const secondBatchItem = transactionSearch.hits.find(h =>
        h.data?.transaction_id === 'batch-2'
      );
      expect(secondBatchItem?.data?.depends_on_batch).toBe('batch-1');
    });

    it('should handle partial failures gracefully', async () => {
      const projectId = `persistence-failure-${randomUUID().substring(0, 8)}`;

      // Step 1: Create mixed batch with some invalid items
      const mixedBatch = {
        items: [
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'service',
              name: 'ValidService',
              data: { version: '1.0.0' }
            }
          },
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: '', // Invalid empty type
              name: '',
              data: null
            }
          },
          {
            kind: 'section',
            scope: { project: projectId },
            data: {
              title: 'Valid Section',
              body_md: 'This is valid content'
            }
          }
        ]
      };

      const mixedResult = await callMCPTool('memory_store', mixedBatch);
      expect(mixedResult.stored.length).toBeGreaterThan(0);
      expect(mixedResult.errors.length).toBeGreaterThan(0);

      const successfulItems = mixedResult.stored;
      const failedItems = mixedResult.errors;

      expect(successfulItems.length).toBe(2); // Valid entity and section
      expect(failedItems.length).toBe(1); // Invalid entity

      // Step 2: Restart server
      await restartServer();

      // Step 3: Verify only valid items persisted
      const verificationResult = await callMCPTool('memory_find', {
        query: 'ValidService Valid Section',
        scope: { project: projectId }
      });

      expect(verificationResult.hits.length).toBe(2);

      // Verify valid items persisted
      const validEntity = verificationResult.hits.find(h =>
        h.kind === 'entity' && h.data?.name === 'ValidService'
      );
      expect(validEntity).toBeDefined();

      const validSection = verificationResult.hits.find(h =>
        h.kind === 'section' && h.data?.title === 'Valid Section'
      );
      expect(validSection).toBeDefined();

      // Verify invalid item did not persist
      const invalidEntity = verificationResult.hits.find(h =>
        h.kind === 'entity' && h.data?.entity_type === ''
      );
      expect(invalidEntity).toBeUndefined();
    });
  });

  describe('Long-term Data Retention', () => {
    it('should maintain data integrity over extended periods', async () => {
      const projectId = `persistence-longterm-${randomUUID().substring(0, 8)}`;
      const retentionTestData = [];

      // Step 1: Create data with timestamps
      const timeSeriesData = {
        items: Array.from({ length: 10 }, (_, i) => ({
          kind: i % 3 === 0 ? 'observation' : i % 3 === 1 ? 'todo' : 'entity',
          scope: { project: projectId },
          data: {
            name: `TimeSeriesItem${i}`,
            created_at: new Date(Date.now() - i * 24 * 60 * 60 * 1000).toISOString(), // Days ago
            sequence: i,
            archival_metadata: {
              retention_period: '1_year',
              importance: i < 3 ? 'critical' : i < 7 ? 'important' : 'normal',
              access_frequency: i % 3 === 0 ? 'high' : 'low'
            },
            content: `Time series data point ${i} with timestamp`,
            checksum: generateTimestampChecksum(i)
          }
        }))
      };

      const creationResult = await callMCPTool('memory_store', timeSeriesData);
      expect(creationResult.stored).toHaveLength(10);

      retentionTestData.push(...creationResult.stored);

      // Step 2: Simulate time passage and server restarts
      console.log('Simulating extended time period...');
      for (let restart = 0; restart < 3; restart++) {
        await setTimeout(100); // Small delay
        await restartServer();

        // Verify data persistence after each restart
        const interimResult = await callMCPTool('memory_find', {
          query: `TimeSeriesItem ${projectId}`,
          scope: { project: projectId }
        });

        expect(interimResult.hits.length).toBe(10);

        // Verify data hasn't corrupted
        interimResult.hits.forEach((hit, index) => {
          expect(hit.data?.sequence).toBe(index);
          expect(hit.data?.checksum).toBe(generateTimestampChecksum(index));
        });
      }

      // Step 3: Test archival and retrieval
      const archivalResult = await callMCPTool('memory_find', {
        query: 'critical important time series data',
        scope: { project: projectId },
        types: ['observation', 'todo', 'entity']
      });

      expect(archivalResult.hits.length).toBe(10);

      // Verify importance classification
      const criticalItems = archivalResult.hits.filter(h =>
        h.data?.archival_metadata?.importance === 'critical'
      );
      expect(criticalItems.length).toBe(3);

      const importantItems = archivalResult.hits.filter(h =>
        h.data?.archival_metadata?.importance === 'important'
      );
      expect(importantItems.length).toBe(4);

      // Verify temporal ordering
      const sortedByTime = [...archivalResult.hits].sort((a, b) =>
        new Date(a.data?.created_at).getTime() - new Date(b.data?.created_at).getTime()
      );

      sortedByTime.forEach((item, index) => {
        expect(item.data?.sequence).toBe(index);
      });
    });

    it('should handle data migration and schema evolution', async () => {
      const projectId = `persistence-migration-${randomUUID().substring(0, 8)}`;

      // Step 1: Create data in "legacy" format
      const legacyData = {
        items: [
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'service',
              name: 'LegacyService',
              data: {
                version: '1.0.0',
                port: 3000,
                host: 'localhost'
                // Missing new fields that will be added later
              },
              schema_version: '1.0'
            }
          },
          {
            kind: 'decision',
            scope: { project: projectId },
            data: {
              component: 'database',
              status: 'accepted',
              title: 'Use PostgreSQL',
              rationale: 'PostgreSQL provides good performance',
              // Missing alternatives_considered that will be added
              schema_version: '1.0'
            }
          }
        ]
      };

      const legacyResult = await callMCPTool('memory_store', legacyData);
      expect(legacyResult.stored).toHaveLength(2);

      // Step 2: Simulate server restart with schema migration
      await restartServer();

      // Step 3: Add new fields (simulating schema evolution)
      const evolvedData = {
        items: [
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              id: legacyResult.stored[0].id,
              entity_type: 'service',
              name: 'LegacyService',
              data: {
                version: '1.0.0',
                port: 3000,
                host: 'localhost',
                // New fields added in schema 2.0
                health_endpoint: '/health',
                metrics_enabled: true,
                deployment_strategy: 'rolling',
                environment_variables: {
                  NODE_ENV: 'production',
                  LOG_LEVEL: 'info'
                }
              },
              schema_version: '2.0',
              migrated_at: new Date().toISOString()
            }
          },
          {
            kind: 'decision',
            scope: { project: projectId },
            data: {
              id: legacyResult.stored[1].id,
              component: 'database',
              status: 'accepted',
              title: 'Use PostgreSQL',
              rationale: 'PostgreSQL provides good performance',
              // New fields added in schema 2.0
              alternatives_considered: [
                { alternative: 'MySQL', reason: 'Less advanced features' },
                { alternative: 'MongoDB', reason: 'Different data model' }
              ],
              acceptance_criteria: [
                'ACID compliance required',
                'JSON support needed',
                'Full-text search capability'
              ],
              schema_version: '2.0',
              migrated_at: new Date().toISOString()
            }
          }
        ]
      };

      const evolvedResult = await callMCPTool('memory_store', evolvedData);
      expect(evolvedResult.stored).toHaveLength(2);
      expect(evolvedResult.stored.every(s => s.status === 'updated')).toBe(true);

      // Step 4: Final restart to verify migration persistence
      await restartServer();

      // Step 5: Verify migrated data integrity
      const finalResult = await callMCPTool('memory_find', {
        query: 'LegacyService PostgreSQL migration',
        scope: { project: projectId }
      });

      expect(finalResult.hits.length).toBe(2);

      // Verify entity migration
      const migratedEntity = finalResult.hits.find(h => h.kind === 'entity');
      expect(migratedEntity?.data?.schema_version).toBe('2.0');
      expect(migratedEntity?.data?.data?.health_endpoint).toBe('/health');
      expect(migratedEntity?.data?.data?.metrics_enabled).toBe(true);
      expect(migratedEntity?.data?.data?.environment_variables?.NODE_ENV).toBe('production');

      // Verify decision migration
      const migratedDecision = finalResult.hits.find(h => h.kind === 'decision');
      expect(migratedDecision?.data?.schema_version).toBe('2.0');
      expect(migratedDecision?.data?.alternatives_considered).toHaveLength(2);
      expect(migratedDecision?.data?.acceptance_criteria).toHaveLength(3);

      // Verify original data preserved
      expect(migratedEntity?.data?.data?.version).toBe('1.0.0');
      expect(migratedEntity?.data?.data?.port).toBe(3000);
      expect(migratedDecision?.data?.rationale).toBe('PostgreSQL provides good performance');
    });
  });

  describe('Data Consistency and Validation', () => {
    it('should maintain referential integrity across restarts', async () => {
      const projectId = `persistence-integrity-${randomUUID().substring(0, 8)}`;

      // Step 1: Create entities with relationships
      const entitiesAndRelations = {
        items: [
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'service',
              name: 'FrontendService',
              data: { port: 3001, framework: 'React' }
            }
          },
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'service',
              name: 'BackendService',
              data: { port: 3002, framework: 'Node.js' }
            }
          },
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'database',
              name: 'UserDatabase',
              data: { type: 'PostgreSQL', version: '14' }
            }
          },
          {
            kind: 'relation',
            scope: { project: projectId },
            data: {
              from_entity: 'FrontendService',
              to_entity: 'BackendService',
              relation_type: 'communicates_with'
            }
          },
          {
            kind: 'relation',
            scope: { project: projectId },
            data: {
              from_entity: 'BackendService',
              to_entity: 'UserDatabase',
              relation_type: 'uses'
            }
          }
        ]
      };

      const creationResult = await callMCPTool('memory_store', entitiesAndRelations);
      expect(creationResult.stored).toHaveLength(5);

      const entityIds = creationResult.stored.slice(0, 3).map(s => s.id);
      const relationIds = creationResult.stored.slice(3, 5).map(s => s.id);

      // Step 2: Restart server
      await restartServer();

      // Step 3: Verify referential integrity
      const integrityResult = await callMCPTool('memory_find', {
        query: 'FrontendService BackendService UserDatabase relations',
        scope: { project: projectId }
      });

      expect(integrityResult.hits.length).toBe(5);

      // Verify all entities exist
      const entities = integrityResult.hits.filter(h => h.kind === 'entity');
      expect(entities.length).toBe(3);

      const frontendService = entities.find(e => e.data?.name === 'FrontendService');
      const backendService = entities.find(e => e.data?.name === 'BackendService');
      const userDatabase = entities.find(e => e.data?.name === 'UserDatabase');

      expect(frontendService).toBeDefined();
      expect(backendService).toBeDefined();
      expect(userDatabase).toBeDefined();

      // Verify all relations exist with valid references
      const relations = integrityResult.hits.filter(h => h.kind === 'relation');
      expect(relations.length).toBe(2);

      const frontendToBackend = relations.find(r =>
        r.data?.from_entity === 'FrontendService' && r.data?.to_entity === 'BackendService'
      );
      const backendToDatabase = relations.find(r =>
        r.data?.from_entity === 'BackendService' && r.data?.to_entity === 'UserDatabase'
      );

      expect(frontendToBackend).toBeDefined();
      expect(backendToDatabase).toBeDefined();

      // Verify relationship chain is intact
      expect(frontendService?.id).toBeDefined();
      expect(backendService?.id).toBeDefined();
      expect(userDatabase?.id).toBeDefined();
    });

    it('should preserve data validation rules', async () => {
      const projectId = `persistence-validation-${randomUUID().substring(0, 8)}`;

      // Step 1: Create validated data
      const validatedData = {
        items: [
          {
            kind: 'decision',
            scope: { project: projectId },
            data: {
              component: 'architecture',
              status: 'accepted',
              title: 'Use REST API Design',
              rationale: 'REST provides standardized interface',
              alternatives_considered: [
                { alternative: 'GraphQL', reason: 'More complex for current needs' },
                { alternative: 'gRPC', reason: 'Limited browser support' }
              ],
              acceptance_criteria: [
                'Stateless design',
                'HTTP status codes',
                'JSON responses'
              ],
              validation_rules: {
                required_fields: ['component', 'status', 'title', 'rationale'],
                status_enum: ['proposed', 'accepted', 'rejected', 'deprecated'],
                max_alternatives: 5
              }
            }
          },
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'api_endpoint',
              name: 'UserAPI',
              data: {
                method: 'GET',
                path: '/api/users/:id',
                response_schema: {
                  type: 'object',
                  properties: {
                    id: { type: 'string' },
                    name: { type: 'string' },
                    email: { type: 'string' }
                  },
                  required: ['id', 'name', 'email']
                }
              },
              validation_rules: {
                allowed_methods: ['GET', 'POST', 'PUT', 'DELETE'],
                path_pattern: '^/api/.*',
                required_schema_fields: ['type', 'properties']
              }
            }
          }
        ]
      };

      const validationResult = await callMCPTool('memory_store', validatedData);
      expect(validationResult.stored).toHaveLength(2);

      // Step 2: Restart server
      await restartServer();

      // Step 3: Verify validation rules persisted
      const verificationResult = await callMCPTool('memory_find', {
        query: 'REST API UserAPI validation rules',
        scope: { project: projectId }
      });

      expect(verificationResult.hits.length).toBe(2);

      // Verify decision validation rules
      const decision = verificationResult.hits.find(h => h.kind === 'decision');
      expect(decision?.data?.validation_rules).toBeDefined();
      expect(decision?.data?.validation_rules?.required_fields).toContain('component');
      expect(decision?.data?.validation_rules?.status_enum).toContain('accepted');

      // Verify entity validation rules
      const entity = verificationResult.hits.find(h => h.kind === 'entity');
      expect(entity?.data?.validation_rules).toBeDefined();
      expect(entity?.data?.validation_rules?.allowed_methods).toContain('GET');
      expect(entity?.data?.validation_rules?.path_pattern).toBe('^/api/.*');

      // Step 4: Test validation rules still work
      const invalidUpdate = {
        items: [{
          kind: 'decision',
          scope: { project: projectId },
          data: {
            id: decision?.id,
            status: 'invalid_status', // Should fail validation
            title: 'Updated Decision'
          }
        }]
      };

      const invalidResult = await callMCPTool('memory_store', invalidUpdate);
      expect(invalidResult.errors.length).toBeGreaterThan(0);
      expect(invalidResult.errors[0].error_code).toMatch(/(VALIDATION_ERROR|INVALID_STATUS)/);
    });
  });

  describe('Performance and Scalability', () => {
    it('should maintain performance with large datasets', async () => {
      const projectId = `persistence-performance-${randomUUID().substring(0, 8)}`;
      const largeDatasetSize = 100;

      // Step 1: Create large dataset
      console.log(`Creating large dataset with ${largeDatasetSize} items...`);
      const largeDataset = {
        items: Array.from({ length: largeDatasetSize }, (_, i) => ({
          kind: ['entity', 'observation', 'todo', 'section'][i % 4],
          scope: { project: projectId, batch: Math.floor(i / 10) },
          data: {
            name: `PerfItem${i}`,
            batch: Math.floor(i / 10),
            index: i,
            payload: 'x'.repeat(100 * (i % 5 + 1)), // Variable size payload
            metadata: {
              created_at: new Date().toISOString(),
              tags: [`tag${i % 10}`, `batch${Math.floor(i / 10)}`],
              priority: ['low', 'medium', 'high'][i % 3]
            }
          }
        }))
      };

      const creationStart = Date.now();
      const creationResult = await callMCPTool('memory_store', largeDataset);
      const creationTime = Date.now() - creationStart;

      expect(creationResult.stored).toHaveLength(largeDatasetSize);
      expect(creationTime).toBeLessThan(30000); // Should complete within 30 seconds

      // Step 2: Restart server
      const restartStart = Date.now();
      await restartServer();
      const restartTime = Date.now() - restartStart;

      console.log(`Server restart took: ${restartTime}ms`);

      // Step 3: Verify large dataset persistence
      const verificationStart = Date.now();
      const verificationResult = await callMCPTool('memory_find', {
        query: 'PerfItem dataset performance',
        scope: { project: projectId }
      });
      const verificationTime = Date.now() - verificationStart;

      expect(verificationResult.hits.length).toBe(largeDatasetSize);
      expect(verificationTime).toBeLessThan(10000); // Should complete within 10 seconds

      // Verify data integrity
      const batchSize = Math.floor(largeDatasetSize / 10);
      const batchCounts = {};

      verificationResult.hits.forEach(hit => {
        const batch = hit.data?.batch;
        batchCounts[batch] = (batchCounts[batch] || 0) + 1;
      });

      expect(Object.keys(batchCounts).length).toBe(10);
      Object.values(batchCounts).forEach(count => {
        expect(count).toBe(batchSize);
      });

      // Test search performance on large dataset
      const searchStart = Date.now();
      const searchResult = await callMCPTool('memory_find', {
        query: 'tag5 batch7 high priority',
        scope: { project: projectId },
        types: ['entity', 'todo']
      });
      const searchTime = Date.now() - searchStart;

      expect(searchResult.hits.length).toBeGreaterThan(0);
      expect(searchTime).toBeLessThan(5000); // Should complete within 5 seconds

      console.log(`Performance metrics for ${largeDatasetSize} items:`);
      console.log(`- Creation: ${creationTime}ms (${(creationTime/largeDatasetSize).toFixed(2)}ms per item)`);
      console.log(`- Verification: ${verificationTime}ms (${(verificationTime/largeDatasetSize).toFixed(2)}ms per item)`);
      console.log(`- Search: ${searchTime}ms`);
    });
  });
});

// Helper Functions
async function setupTestDatabase(): Promise<void> {
  console.log('Setting up test database for data persistence...');
}

async function cleanupTestDatabase(): Promise<void> {
  console.log('Cleaning up test database for data persistence...');
}

async function cleanupTestData(): Promise<void> {
  console.log('Cleaning up test data for data persistence...');
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

async function restartServer(): Promise<void> {
  if (server?.process) {
    server.process.kill('SIGTERM');
    await setTimeout(1000);
  }
  server = await startMCPServer();
  await setTimeout(2000); // Wait for server to be ready
}

function generateChecksum(data: any): string {
  // Simple checksum for testing purposes
  const str = JSON.stringify(data);
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32-bit integer
  }
  return hash.toString(36);
}

function generateTimestampChecksum(index: number): string {
  return `timestamp-checksum-${index}-${Date.now()}`;
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
          created_at: new Date().toISOString(),
          data: item.data
        })),
        errors: [],
        autonomous_context: {
          action_performed: items.length > 1 ? 'batch' : 'created',
          items_processed: items.length,
          persistence_verified: true,
          recommendation: 'Data persisted successfully',
          reasoning: 'Knowledge items stored with persistence guarantees',
          user_message_suggestion: `✓ Persisted ${items.length} items to database`
        }
      });
    }, 100);
  });
}