/**
 * Backup and Restore E2E Tests
 *
 * Tests data backup creation, restoration processes, disaster recovery,
 * and data migration between systems.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { spawn, ChildProcess } from 'child_process';
import { setTimeout } from 'timers/promises';
import { randomUUID } from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';
import { writeFileSync, unlinkSync, existsSync, mkdirSync } from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

interface TestServer {
  process: ChildProcess;
  port: number;
}

interface BackupManifest {
  id: string;
  created_at: string;
  version: string;
  items_count: number;
  size_bytes: number;
  checksum: string;
  compressed: boolean;
  encryption_enabled: boolean;
}

interface RestoreResult {
  success: boolean;
  items_restored: number;
  items_failed: number;
  errors: string[];
  restore_id: string;
  timestamp: string;
}

describe('Backup and Restore E2E', () => {
  let server: TestServer;
  const TEST_DB_URL = process.env.TEST_DATABASE_URL ||
    'postgresql://cortex:trust@localhost:5433/cortex_test_e2e';
  const BACKUP_DIR = path.join(__dirname, '../../backups');

  beforeAll(async () => {
    // Ensure backup directory exists
    if (!existsSync(BACKUP_DIR)) {
      mkdirSync(BACKUP_DIR, { recursive: true });
    }

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

    // Clean up backup files
    try {
      const backupFiles = require('fs').readdirSync(BACKUP_DIR);
      backupFiles.forEach(file => {
        require('fs').unlinkSync(path.join(BACKUP_DIR, file));
      });
    } catch (error) {
      // Ignore cleanup errors
    }
  });

  beforeEach(async () => {
    await cleanupTestData();
  });

  describe('Backup Creation', () => {
    it('should create complete backup of all knowledge items', async () => {
      const projectId = `backup-complete-${randomUUID().substring(0, 8)}`;

      // Step 1: Create diverse knowledge items
      const testData = {
        items: [
          {
            kind: 'decision',
            scope: { project: projectId },
            data: {
              component: 'architecture',
              status: 'accepted',
              title: 'Use Microservices Pattern',
              rationale: 'Microservices provide better scalability and team autonomy',
              alternatives_considered: [
                { alternative: 'Monolith', reason: 'Harder to scale independently' }
              ],
              acceptance_date: new Date().toISOString()
            }
          },
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'service',
              name: 'OrderService',
              data: {
                version: '2.1.0',
                port: 3003,
                dependencies: ['UserService', 'PaymentService', 'InventoryService'],
                health_check: '/health'
              }
            }
          },
          {
            kind: 'section',
            scope: { project: projectId },
            data: {
              title: 'API Design Guidelines',
              heading: 'RESTful API Standards',
              body_md: `
# API Design Guidelines

## Principles
- Use HTTP verbs correctly
- Provide clear error messages
- Include versioning in URLs
- Use appropriate status codes

## Authentication
- JWT tokens for authentication
- API keys for service-to-service communication
- OAuth 2.0 for third-party access
              `.trim()
            }
          },
          {
            kind: 'todo',
            scope: { project: projectId },
            data: {
              text: 'Implement circuit breaker pattern',
              status: 'in_progress',
              priority: 'high',
              todo_type: 'reliability',
              assignee: 'backend-team',
              due_date: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()
            }
          },
          {
            kind: 'observation',
            scope: { project: projectId },
            data: {
              title: 'Performance Benchmark Results',
              content: 'Load testing showed 95th percentile response time under 100ms with 1000 concurrent users',
              confidence_level: 'high',
              test_environment: 'staging',
              test_date: new Date().toISOString()
            }
          },
          {
            kind: 'relation',
            scope: { project: projectId },
            data: {
              from_entity: 'OrderService',
              to_entity: 'UserService',
              relation_type: 'depends_on',
              description: 'Order service depends on user service for customer information'
            }
          }
        ]
      };

      const creationResult = await callMCPTool('memory_store', testData);
      expect(creationResult.stored).toHaveLength(6);

      // Step 2: Create backup
      const backupRequest = {
        backup_id: `backup-${randomUUID().substring(0, 8)}`,
        scope: { project: projectId },
        include_types: ['decision', 'entity', 'section', 'todo', 'observation', 'relation'],
        compression: true,
        encryption: false,
        include_metadata: true
      };

      const backupResult = await callMCPTool('create_backup', backupRequest);
      expect(backupResult.success).toBe(true);
      expect(backupResult.backup_id).toBeDefined();
      expect(backupResult.items_backed_up).toBe(6);
      expect(backupResult.backup_size_bytes).toBeGreaterThan(0);

      // Verify backup manifest
      const manifest = backupResult.manifest as BackupManifest;
      expect(manifest.id).toBe(backupRequest.backup_id);
      expect(manifest.items_count).toBe(6);
      expect(manifest.compressed).toBe(true);
      expect(manifest.created_at).toBeDefined();

      // Step 3: Verify backup file was created
      const backupFilePath = path.join(BACKUP_DIR, `${backupRequest.backup_id}.backup`);
      expect(existsSync(backupFilePath)).toBe(true);

      // Step 4: Verify backup content integrity
      const backupContent = await callMCPTool('verify_backup', {
        backup_id: backupRequest.backup_id,
        verify_checksums: true
      });

      expect(backupContent.verified).toBe(true);
      expect(backupContent.items_verified).toBe(6);
      expect(backupContent.checksums_valid).toBe(true);
    });

    it('should support selective backup by type and scope', async () => {
      const projectId1 = `backup-selective-1-${randomUUID().substring(0, 8)}`;
      const projectId2 = `backup-selective-2-${randomUUID().substring(0, 8)}`;

      // Create data in different projects and types
      await callMCPTool('memory_store', {
        items: [
          {
            kind: 'decision',
            scope: { project: projectId1 },
            data: { title: 'Project 1 Decision', status: 'accepted' }
          },
          {
            kind: 'entity',
            scope: { project: projectId1 },
            data: { entity_type: 'service', name: 'Service1' }
          }
        ]
      });

      await callMCPTool('memory_store', {
        items: [
          {
            kind: 'decision',
            scope: { project: projectId2 },
            data: { title: 'Project 2 Decision', status: 'proposed' }
          },
          {
            kind: 'todo',
            scope: { project: projectId2 },
            data: { text: 'Task for project 2', status: 'pending' }
          }
        ]
      });

      // Step 1: Create selective backup for project 1 only
      const selectiveBackup1 = await callMCPTool('create_backup', {
        backup_id: `selective-backup-1-${randomUUID().substring(0, 8)}`,
        scope: { project: projectId1 },
        include_types: ['decision', 'entity'],
        compression: false
      });

      expect(selectiveBackup1.success).toBe(true);
      expect(selectiveBackup1.items_backed_up).toBe(2);

      // Step 2: Create selective backup for decisions only across all projects
      const selectiveBackup2 = await callMCPTool('create_backup', {
        backup_id: `selective-backup-2-${randomUUID().substring(0, 8)}`,
        include_types: ['decision'],
        compression: true
      });

      expect(selectiveBackup2.success).toBe(true);
      expect(selectiveBackup2.items_backed_up).toBe(2);

      // Step 3: Create selective backup for todos only
      const selectiveBackup3 = await callMCPTool('create_backup', {
        backup_id: `selective-backup-3-${randomUUID().substring(0, 8)}`,
        include_types: ['todo'],
        compression: true
      });

      expect(selectiveBackup3.success).toBe(true);
      expect(selectiveBackup3.items_backed_up).toBe(1);

      // Verify backup files exist
      expect(existsSync(path.join(BACKUP_DIR, `${selectiveBackup1.backup_id}.backup`))).toBe(true);
      expect(existsSync(path.join(BACKUP_DIR, `${selectiveBackup2.backup_id}.backup`))).toBe(true);
      expect(existsSync(path.join(BACKUP_DIR, `${selectiveBackup3.backup_id}.backup`))).toBe(true);
    });

    it('should handle incremental backups efficiently', async () => {
      const projectId = `backup-incremental-${randomUUID().substring(0, 8)}`;

      // Step 1: Create initial data
      const initialData = {
        items: Array.from({ length: 10 }, (_, i) => ({
          kind: i % 2 === 0 ? 'entity' : 'observation',
          scope: { project: projectId },
          data: {
            name: `InitialItem${i}`,
            batch: 'initial',
            created_at: new Date(Date.now() - 3600000).toISOString() // 1 hour ago
          }
        }))
      };

      await callMCPTool('memory_store', initialData);

      // Step 2: Create full backup
      const fullBackup = await callMCPTool('create_backup', {
        backup_id: `full-backup-${randomUUID().substring(0, 8)}`,
        scope: { project: projectId },
        backup_type: 'full',
        compression: true
      });

      expect(fullBackup.success).toBe(true);
      expect(fullBackup.items_backed_up).toBe(10);
      expect(fullBackup.backup_type).toBe('full');

      // Step 3: Add new data
      await setTimeout(1000); // Ensure different timestamps
      const newData = {
        items: Array.from({ length: 5 }, (_, i) => ({
          kind: i % 2 === 0 ? 'todo' : 'decision',
          scope: { project: projectId },
          data: {
            name: `NewItem${i}`,
            batch: 'incremental',
            created_at: new Date().toISOString()
          }
        }))
      };

      await callMCPTool('memory_store', newData);

      // Step 4: Create incremental backup
      const incrementalBackup = await callMCPTool('create_backup', {
        backup_id: `incremental-backup-${randomUUID().substring(0, 8)}`,
        scope: { project: projectId },
        backup_type: 'incremental',
        base_backup_id: fullBackup.backup_id,
        compression: true
      });

      expect(incrementalBackup.success).toBe(true);
      expect(incrementalBackup.items_backed_up).toBe(5);
      expect(incrementalBackup.backup_type).toBe('incremental');
      expect(incrementalBackup.base_backup_id).toBe(fullBackup.backup_id);

      // Verify incremental backup is smaller than full backup
      expect(incrementalBackup.backup_size_bytes).toBeLessThan(fullBackup.backup_size_bytes);

      // Step 5: Verify backup chain integrity
      const chainVerification = await callMCPTool('verify_backup_chain', {
        backup_ids: [fullBackup.backup_id, incrementalBackup.backup_id]
      });

      expect(chainVerification.chain_valid).toBe(true);
      expect(chainVerification.total_items).toBe(15);
    });
  });

  describe('Data Restoration', () => {
    it('should restore complete backup to original state', async () => {
      const projectId = `restore-complete-${randomUUID().substring(0, 8)}`;
      const originalData = [];

      // Step 1: Create comprehensive test data
      const testData = {
        items: [
          {
            kind: 'decision',
            scope: { project: projectId },
            data: {
              component: 'frontend',
              status: 'accepted',
              title: 'Use React with TypeScript',
              rationale: 'TypeScript provides type safety and better developer experience',
              acceptance_criteria: ['Full type coverage', 'Strict mode enabled'],
              acceptance_date: new Date().toISOString()
            }
          },
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'component',
              name: 'UserProfile',
              data: {
                props: ['id', 'name', 'email', 'avatar'],
                state: ['user', 'loading', 'error'],
                hooks: ['useState', 'useEffect', 'useContext']
              }
            }
          },
          {
            kind: 'section',
            scope: { project: projectId },
            data: {
              title: 'Component Development Guidelines',
              heading: 'Best Practices',
              body_md: `
# React Component Best Practices

## Structure
- Use functional components with hooks
- Keep components small and focused
- Use TypeScript for type safety

## Performance
- Use React.memo for expensive components
- Implement proper dependency arrays
- Avoid unnecessary re-renders
              `.trim()
            }
          },
          {
            kind: 'todo',
            scope: { project: projectId },
            data: {
              text: 'Add unit tests for UserProfile component',
              status: 'pending',
              priority: 'medium',
              todo_type: 'testing',
              assignee: 'frontend-team'
            }
          },
          {
            kind: 'relation',
            scope: { project: projectId },
            data: {
              from_entity: 'UserProfile',
              to_entity: 'React Guidelines',
              relation_type: 'follows',
              description: 'UserProfile component follows development guidelines'
            }
          }
        ]
      };

      const creationResult = await callMCPTool('memory_store', testData);
      expect(creationResult.stored).toHaveLength(5);

      // Store original data for comparison
      originalData.push(...creationResult.stored);

      // Step 2: Create backup
      const backupResult = await callMCPTool('create_backup', {
        backup_id: `restore-backup-${randomUUID().substring(0, 8)}`,
        scope: { project: projectId },
        compression: true,
        include_metadata: true
      });

      expect(backupResult.success).toBe(true);

      // Step 3: Clear all data (simulate disaster)
      await callMCPTool('clear_project_data', {
        scope: { project: projectId },
        confirmation: true
      });

      // Verify data is gone
      const clearedSearch = await callMCPTool('memory_find', {
        query: 'React TypeScript UserProfile',
        scope: { project: projectId }
      });

      expect(clearedSearch.hits).toHaveLength(0);

      // Step 4: Restore from backup
      const restoreResult = await callMCPTool('restore_backup', {
        backup_id: backupResult.backup_id,
        target_scope: { project: projectId },
        overwrite_existing: true,
        verify_restoration: true
      }) as RestoreResult;

      expect(restoreResult.success).toBe(true);
      expect(restoreResult.items_restored).toBe(5);
      expect(restoreResult.items_failed).toBe(0);
      expect(restoreResult.errors).toHaveLength(0);

      // Step 5: Verify restoration completeness
      const verificationResult = await callMCPTool('memory_find', {
        query: 'React TypeScript UserProfile component guidelines',
        scope: { project: projectId }
      });

      expect(verificationResult.hits).toHaveLength(5);

      // Verify data integrity after restoration
      verificationResult.hits.forEach(restoredItem => {
        const originalItem = originalData.find(o => o.id === restoredItem.id);
        expect(originalItem).toBeDefined();
        expect(restoredItem.kind).toBe(originalItem.kind);

        // Deep comparison of critical fields
        if (restoredItem.kind === 'decision') {
          expect(restoredItem.data?.status).toBe(originalItem.data?.status);
          expect(restoredItem.data?.title).toBe(originalItem.data?.title);
          expect(restoredItem.data?.rationale).toBe(originalItem.data?.rationale);
        } else if (restoredItem.kind === 'entity') {
          expect(restoredItem.data?.name).toBe(originalItem.data?.name);
          expect(restoredItem.data?.entity_type).toBe(originalItem.data?.entity_type);
        } else if (restoredItem.kind === 'section') {
          expect(restoredItem.data?.title).toBe(originalItem.data?.title);
          expect(restoredItem.data?.body_md).toBe(originalItem.data?.body_md);
        }
      });

      // Verify relationships are restored correctly
      const relations = verificationResult.hits.filter(h => h.kind === 'relation');
      expect(relations.length).toBe(1);
      expect(relations[0].data?.from_entity).toBe('UserProfile');
      expect(relations[0].data?.relation_type).toBe('follows');
    });

    it('should handle partial restoration and conflict resolution', async () => {
      const projectId = `restore-partial-${randomUUID().substring(0, 8)}`;

      // Step 1: Create initial data
      const initialData = {
        items: [
          {
            kind: 'decision',
            scope: { project: projectId },
            data: {
              title: 'Use REST API Design',
              status: 'accepted',
              rationale: 'REST is well-understood and widely supported'
            }
          },
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'api',
              name: 'UserAPI',
              data: { version: '1.0.0', base_path: '/api/v1' }
            }
          }
        ]
      };

      await callMCPTool('memory_store', initialData);

      // Step 2: Create backup
      const backupResult = await callMCPTool('create_backup', {
        backup_id: `partial-backup-${randomUUID().substring(0, 8)}`,
        scope: { project: projectId },
        include_types: ['decision'] // Only backup decisions
      });

      expect(backupResult.success).toBe(true);
      expect(backupResult.items_backed_up).toBe(1);

      // Step 3: Modify existing data and add new data
      await callMCPTool('memory_store', {
        items: [
          {
            kind: 'decision',
            scope: { project: projectId },
            data: {
              title: 'Use REST API Design',
              status: 'deprecated', // Changed status
              rationale: 'REST is well-understood and widely supported',
              deprecation_reason: 'Moving to GraphQL for better flexibility'
            }
          },
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'api',
              name: 'UserAPI',
              data: { version: '2.0.0', base_path: '/api/v2' } // Updated version
            }
          },
          {
            kind: 'section',
            scope: { project: projectId },
            data: {
              title: 'New Section Added After Backup',
              body_md: 'This content was added after the backup was created'
            }
          }
        ]
      });

      // Step 4: Partial restore with conflict resolution
      const restoreResult = await callMCPTool('restore_backup', {
        backup_id: backupResult.backup_id,
        target_scope: { project: projectId },
        conflict_resolution: 'keep_existing', // Keep existing data when conflicts occur
        restore_types: ['decision']
      }) as RestoreResult;

      expect(restoreResult.success).toBe(true);

      // Step 5: Verify conflict resolution
      const verificationResult = await callMCPTool('memory_find', {
        query: 'REST API UserAPI',
        scope: { project: projectId }
      });

      expect(verificationResult.hits.length).toBe(3);

      // Decision should retain existing (deprecated) status
      const decision = verificationResult.hits.find(h => h.kind === 'decision');
      expect(decision?.data?.status).toBe('deprecated');
      expect(decision?.data?.deprecation_reason).toBeDefined();

      // Entity should not be restored (wasn't in backup types)
      const entity = verificationResult.hits.find(h => h.kind === 'entity');
      expect(entity?.data?.data?.version).toBe('2.0.0'); // Should keep newer version

      // New section should remain (wasn't affected by restore)
      const section = verificationResult.hits.find(h => h.kind === 'section');
      expect(section?.data?.title).toBe('New Section Added After Backup');
    });

    it('should restore across different projects and environments', async () => {
      const sourceProjectId = `restore-cross-source-${randomUUID().substring(0, 8)}`;
      const targetProjectId = `restore-cross-target-${randomUUID().substring(0, 8)}`;

      // Step 1: Create data in source project
      const sourceData = {
        items: [
          {
            kind: 'decision',
            scope: { project: sourceProjectId, environment: 'development' },
            data: {
              title: 'Development Database Strategy',
              status: 'accepted',
              rationale: 'Use PostgreSQL for development environment',
              environment_specific: true
            }
          },
          {
            kind: 'entity',
            scope: { project: sourceProjectId, environment: 'development' },
            data: {
              entity_type: 'database',
              name: 'DevDB',
              data: { type: 'PostgreSQL', version: '14-dev' }
            }
          }
        ]
      };

      await callMCPTool('memory_store', sourceData);

      // Step 2: Create backup from source
      const backupResult = await callMCPTool('create_backup', {
        backup_id: `cross-env-backup-${randomUUID().substring(0, 8)}`,
        scope: { project: sourceProjectId },
        include_metadata: true
      });

      expect(backupResult.success).toBe(true);

      // Step 3: Restore to different project with environment transformation
      const restoreResult = await callMCPTool('restore_backup', {
        backup_id: backupResult.backup_id,
        target_scope: { project: targetProjectId, environment: 'production' },
        transformation_rules: {
          replace_environment: {
            from: 'development',
            to: 'production'
          },
          update_versions: {
            database: { version: '14-prod' }
          },
          add_production_tags: true
        },
        overwrite_existing: true
      }) as RestoreResult;

      expect(restoreResult.success).toBe(true);
      expect(restoreResult.items_restored).toBe(2);

      // Step 4: Verify cross-project restoration with transformations
      const targetResult = await callMCPTool('memory_find', {
        query: 'Database Strategy PostgreSQL',
        scope: { project: targetProjectId }
      });

      expect(targetResult.hits.length).toBe(2);

      // Verify environment transformation
      const decision = targetResult.hits.find(h => h.kind === 'decision');
      expect(decision?.data?.title).toBe('Production Database Strategy'); // Should be transformed
      expect(decision?.data?.scope?.environment).toBe('production');
      expect(decision?.data?.production_tags).toBeDefined();

      // Verify version transformation
      const entity = targetResult.hits.find(h => h.kind === 'entity');
      expect(entity?.data?.name).toBe('ProdDB'); // Should be transformed
      expect(entity?.data?.data?.version).toBe('14-prod');
    });
  });

  describe('Disaster Recovery', () => {
    it('should handle complete system recovery from backup', async () => {
      const projectId = `disaster-recovery-${randomUUID().substring(0, 8)}`;
      const criticalData = [];

      // Step 1: Create critical business data
      const criticalItems = {
        items: [
          {
            kind: 'decision',
            scope: { project: projectId, criticality: 'high' },
            data: {
              title: 'Payment Processing Architecture',
              status: 'accepted',
              rationale: 'Critical for business operations',
              business_impact: 'high',
              compliance_requirements: ['PCI-DSS', 'GDPR'],
              implementation_date: new Date().toISOString()
            }
          },
          {
            kind: 'entity',
            scope: { project: projectId, criticality: 'high' },
            data: {
              entity_type: 'service',
              name: 'PaymentService',
              data: {
                version: '3.2.1',
                sla: '99.99%',
                disaster_recovery: true,
                backup_frequency: 'real-time'
              }
            }
          },
          {
            kind: 'runbook',
            scope: { project: projectId, criticality: 'high' },
            data: {
              title: 'Payment Service Emergency Procedures',
              description: 'Critical procedures for payment service incidents',
              severity: 'critical',
              response_time: '15_minutes',
              escalation_contacts: ['CTO', 'Head of Engineering', 'VP of Product']
            }
          },
          {
            kind: 'observation',
            scope: { project: projectId, criticality: 'high' },
            data: {
              title: 'Security Audit Results',
              content: 'Payment system passed all security audits with no critical findings',
              audit_date: new Date().toISOString(),
              next_audit: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString()
            }
          }
        ]
      };

      const creationResult = await callMCPTool('memory_store', criticalItems);
      expect(creationResult.stored).toHaveLength(4);
      criticalData.push(...creationResult.stored);

      // Step 2: Create disaster recovery backup
      const drBackup = await callMCPTool('create_backup', {
        backup_id: `dr-backup-${randomUUID().substring(0, 8)}`,
        scope: { project: projectId },
        backup_type: 'disaster_recovery',
        compression: true,
        encryption: true,
        include_dependencies: true,
        verify_after_creation: true
      });

      expect(drBackup.success).toBe(true);
      expect(drBackup.encryption_enabled).toBe(true);
      expect(drBackup.verified).toBe(true);

      // Step 3: Store backup metadata in external location
      const backupMetadata = {
        backup_id: drBackup.backup_id,
        created_at: drBackup.created_at,
        items_count: drBackup.items_backed_up,
        checksum: drBackup.checksum,
        criticality: 'high',
        retention_period: '7_years',
        recovery_point_objective: '15_minutes',
        recovery_time_objective: '4_hours'
      };

      const metadataPath = path.join(BACKUP_DIR, `${drBackup.backup_id}-metadata.json`);
      writeFileSync(metadataPath, JSON.stringify(backupMetadata, null, 2));

      // Step 4: Simulate complete system failure
      await callMCPTool('simulate_system_failure', {
        scope: { project: projectId },
        failure_type: 'complete_data_loss',
        confirmation: true
      });

      // Verify system is down
      const failureCheck = await callMCPTool('memory_find', {
        query: 'Payment Processing Architecture',
        scope: { project: projectId }
      });

      expect(failureCheck.hits).toHaveLength(0);

      // Step 5: Perform disaster recovery
      const recoveryResult = await callMCPTool('disaster_recovery', {
        backup_id: drBackup.backup_id,
        target_scope: { project: projectId },
        recovery_mode: 'full',
        verify_recovery: true,
        recovery_procedures: {
          pre_recovery_checks: true,
          post_recovery_validation: true,
          rollback_capability: true
        }
      });

      expect(recoveryResult.success).toBe(true);
      expect(recoveryResult.items_recovered).toBe(4);
      expect(recoveryResult.recovery_time_ms).toBeLessThan(60000); // Should complete within 1 minute

      // Step 6: Verify disaster recovery success
      const recoveryVerification = await callMCPTool('memory_find', {
        query: 'Payment service critical business data',
        scope: { project: projectId }
      });

      expect(recoveryVerification.hits).toHaveLength(4);

      // Verify critical data integrity
      criticalData.forEach(originalItem => {
        const recoveredItem = recoveryVerification.hits.find(h => h.id === originalItem.id);
        expect(recoveredItem).toBeDefined();
        expect(recoveredItem.kind).toBe(originalItem.kind);

        if (recoveredItem.kind === 'decision') {
          expect(recoveredItem.data?.business_impact).toBe('high');
          expect(recoveredItem.data?.compliance_requirements).toBeDefined();
        } else if (recoveredItem.kind === 'entity') {
          expect(recoveredItem.data?.sla).toBe('99.99%');
          expect(recoveredItem.data?.disaster_recovery).toBe(true);
        }
      });

      // Verify system is fully operational
      const operationalCheck = await callMCPTool('system_health_check', {
        scope: { project: projectId }
      });

      expect(operationalCheck.status).toBe('healthy');
      expect(operationalCheck.data_integrity).toBe('verified');
    });

    it('should handle point-in-time recovery', async () => {
      const projectId = `point-in-time-${randomUUID().substring(0, 8)}`;
      const timeline = [];

      // Step 1: Create initial data (T0)
      const t0Data = {
        items: [{
          kind: 'decision',
          scope: { project: projectId },
          data: {
            title: 'Initial Architecture Decision',
            status: 'accepted',
            rationale: 'Starting point for system architecture',
            timestamp: new Date().toISOString()
          }
        }]
      };

      const t0Result = await callMCPTool('memory_store', t0Data);
      timeline.push({ time: new Date(), action: 'created', items: 1 });

      // Step 2: Create backup at T0
      const t0Backup = await callMCPTool('create_backup', {
        backup_id: `pit-backup-t0-${randomUUID().substring(0, 8)}`,
        scope: { project: projectId },
        backup_type: 'point_in_time'
      });

      // Step 3: Add more data (T1)
      await setTimeout(1000);
      const t1Data = {
        items: [
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              name: 'ServiceA',
              timestamp: new Date().toISOString()
            }
          },
          {
            kind: 'todo',
            scope: { project: projectId },
            data: {
              text: 'Task A',
              timestamp: new Date().toISOString()
            }
          }
        ]
      };

      const t1Result = await callMCPTool('memory_store', t1Data);
      timeline.push({ time: new Date(), action: 'added', items: 2 });

      // Step 4: Create backup at T1
      const t1Backup = await callMCPTool('create_backup', {
        backup_id: `pit-backup-t1-${randomUUID().substring(0, 8)}`,
        scope: { project: projectId },
        backup_type: 'point_in_time',
        base_backup_id: t0Backup.backup_id
      });

      // Step 5: Add final data (T2)
      await setTimeout(1000);
      const t2Data = {
        items: [{
          kind: 'section',
          scope: { project: projectId },
          data: {
            title: 'Final Documentation',
            timestamp: new Date().toISOString()
          }
        }]
      };

      await callMCPTool('memory_store', t2Data);
      timeline.push({ time: new Date(), action: 'added', items: 1 });

      // Step 6: Verify current state (should have 4 items)
      const currentState = await callMCPTool('memory_find', {
        query: 'architecture decision service task documentation',
        scope: { project: projectId }
      });

      expect(currentState.hits).toHaveLength(4);

      // Step 7: Perform point-in-time recovery to T1
      const pitRecovery = await callMCPTool('point_in_time_recovery', {
        backup_id: t1Backup.backup_id,
        target_scope: { project: projectId },
        recovery_point: t1Backup.created_at,
        preserve_later_changes: false
      });

      expect(pitRecovery.success).toBe(true);

      // Step 8: Verify recovery to T1 state (should have 3 items)
      const recoveredState = await callMCPTool('memory_find', {
        query: 'architecture decision service task',
        scope: { project: projectId }
      });

      expect(recoveredState.hits).toHaveLength(3);

      // Verify correct items are present
      const decision = recoveredState.hits.find(h => h.kind === 'decision');
      const entity = recoveredState.hits.find(h => h.kind === 'entity');
      const todo = recoveredState.hits.find(h => h.kind === 'todo');

      expect(decision).toBeDefined();
      expect(entity).toBeDefined();
      expect(todo).toBeDefined();

      // Verify T2 data is not present
      const section = recoveredState.hits.find(h => h.kind === 'section');
      expect(section).toBeUndefined();

      // Verify timeline integrity
      expect(decision?.data?.timestamp).toBe(t0Data.items[0].data.timestamp);
      expect(entity?.data?.timestamp).toBe(t1Data.items[0].data.timestamp);
      expect(todo?.data?.timestamp).toBe(t1Data.items[1].data.timestamp);
    });
  });

  describe('Backup Validation and Integrity', () => {
    it('should validate backup integrity and detect corruption', async () => {
      const projectId = `backup-validation-${randomUUID().substring(0, 8)}`;

      // Step 1: Create test data with checksums
      const testData = {
        items: [
          {
            kind: 'decision',
            scope: { project: projectId },
            data: {
              title: 'Data Integrity Test Decision',
              status: 'accepted',
              rationale: 'Testing backup validation mechanisms',
              checksum: generateDataChecksum('decision-1')
            }
          },
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'service',
              name: 'ValidationService',
              data: { checksum: generateDataChecksum('entity-1') }
            }
          }
        ]
      };

      await callMCPTool('memory_store', testData);

      // Step 2: Create backup with integrity verification
      const backupResult = await callMCPTool('create_backup', {
        backup_id: `validation-backup-${randomUUID().substring(0, 8)}`,
        scope: { project: projectId },
        integrity_check: 'deep',
        compression: false,
        calculate_checksums: true
      });

      expect(backupResult.success).toBe(true);
      expect(backupResult.checksum_verified).toBe(true);

      // Step 3: Verify backup integrity
      const integrityCheck = await callMCPTool('verify_backup_integrity', {
        backup_id: backupResult.backup_id,
        deep_verification: true,
        compare_checksums: true
      });

      expect(integrityCheck.valid).toBe(true);
      expect(integrityCheck.items_validated).toBe(2);
      expect(integrityCheck.checksums_matched).toBe(2);
      expect(integrityCheck.corruption_detected).toBe(false);

      // Step 4: Test corruption detection (simulate corruption)
      const corruptionTest = await callMCPTool('simulate_backup_corruption', {
        backup_id: backupResult.backup_id,
        corruption_type: 'bit_flip',
        corruption_percentage: 5
      });

      // Verify corruption is detected
      const corruptedCheck = await callMCPTool('verify_backup_integrity', {
        backup_id: backupResult.backup_id,
        deep_verification: true
      });

      expect(corruptedCheck.valid).toBe(false);
      expect(corruptedCheck.corruption_detected).toBe(true);
      expect(corruptedCheck.corrupted_items).toBeGreaterThan(0);

      // Step 5: Test backup repair
      const repairResult = await callMCPTool('repair_backup', {
        backup_id: backupResult.backup_id,
        repair_method: 'restore_from_original',
        verify_repair: true
      });

      expect(repairResult.repaired).toBe(true);
      expect(repairResult.items_repaired).toBeGreaterThan(0);

      // Final verification after repair
      const finalCheck = await callMCPTool('verify_backup_integrity', {
        backup_id: backupResult.backup_id
      });

      expect(finalCheck.valid).toBe(true);
      expect(finalCheck.corruption_detected).toBe(false);
    });

    it('should maintain backup chain consistency', async () => {
      const projectId = `backup-chain-${randomUUID().substring(0, 8)}`;
      const backupChain = [];

      // Step 1: Create initial data and full backup
      await callMCPTool('memory_store', {
        items: [{
          kind: 'entity',
          scope: { project: projectId },
          data: { name: 'BaseEntity', version: '1.0' }
        }]
      });

      const fullBackup = await callMCPTool('create_backup', {
        backup_id: `chain-full-${randomUUID().substring(0, 8)}`,
        scope: { project: projectId },
        backup_type: 'full'
      });

      backupChain.push(fullBackup.backup_id);

      // Step 2: Create multiple incremental backups
      for (let i = 1; i <= 3; i++) {
        await callMCPTool('memory_store', {
          items: [{
            kind: 'entity',
            scope: { project: projectId },
            data: { name: `Entity${i}`, version: `${i}.0` }
          }]
        });

        const incrementalBackup = await callMCPTool('create_backup', {
          backup_id: `chain-inc-${i}-${randomUUID().substring(0, 8)}`,
          scope: { project: projectId },
          backup_type: 'incremental',
          base_backup_id: backupChain[i - 1]
        });

        backupChain.push(incrementalBackup.backup_id);
      }

      // Step 3: Verify backup chain integrity
      const chainVerification = await callMCPTool('verify_backup_chain', {
        backup_ids: backupChain,
        deep_verification: true
      });

      expect(chainVerification.chain_valid).toBe(true);
      expect(chainVerification.backup_count).toBe(4);
      expect(chainVerification.total_items).toBe(4);
      expect(chainVerification.broken_links).toHaveLength(0);

      // Step 4: Test chain restoration
      const chainRestore = await callMCPTool('restore_backup_chain', {
        backup_ids: backupChain,
        target_scope: { project: `${projectId}-restored` },
        verify_restoration: true
      });

      expect(chainRestore.success).toBe(true);
      expect(chainRestore.items_restored).toBe(4);

      // Step 5: Test chain with missing backup
      const incompleteChain = await callMCPTool('verify_backup_chain', {
        backup_ids: [backupChain[0], backupChain[2]], // Missing backupChain[1]
        allow_incomplete: true
      });

      expect(incompleteChain.chain_valid).toBe(false);
      expect(incompleteChain.broken_links).toHaveLength(1);
      expect(incompleteChain.missing_backups).toHaveLength(1);
    });
  });

  describe('Performance and Scalability', () => {
    it('should handle large backup and restore operations efficiently', async () => {
      const projectId = `backup-scalability-${randomUUID().substring(0, 8)}`;
      const largeDataSize = 500;

      // Step 1: Create large dataset
      console.log(`Creating large dataset with ${largeDataSize} items...`);
      const largeDataset = {
        items: Array.from({ length: largeDataSize }, (_, i) => ({
          kind: ['entity', 'observation', 'todo', 'section'][i % 4],
          scope: { project: projectId, batch: Math.floor(i / 50) },
          data: {
            name: `LargeItem${i}`,
            batch: Math.floor(i / 50),
            index: i,
            payload: 'x'.repeat(200 * (i % 5 + 1)), // Variable size content
            metadata: {
              created_at: new Date().toISOString(),
              tags: Array.from({ length: 3 }, (_, j) => `tag${(i + j) % 20}`),
              priority: ['low', 'medium', 'high', 'critical'][i % 4]
            }
          }
        }))
      };

      const creationStart = Date.now();
      await callMCPTool('memory_store', largeDataset);
      const creationTime = Date.now() - creationStart;

      console.log(`Large dataset creation: ${creationTime}ms`);

      // Step 2: Create large backup
      const backupStart = Date.now();
      const largeBackup = await callMCPTool('create_backup', {
        backup_id: `large-backup-${randomUUID().substring(0, 8)}`,
        scope: { project: projectId },
        compression: true,
        parallel_processing: true,
        chunk_size: 100
      });
      const backupTime = Date.now() - backupStart;

      expect(largeBackup.success).toBe(true);
      expect(largeBackup.items_backed_up).toBe(largeDataSize);
      expect(backupTime).toBeLessThan(60000); // Should complete within 1 minute

      console.log(`Large backup creation: ${backupTime}ms (${(backupTime/largeDataSize).toFixed(2)}ms per item)`);
      console.log(`Backup size: ${(largeBackup.backup_size_bytes / 1024 / 1024).toFixed(2)}MB`);

      // Step 3: Clear data and test large restore
      await callMCPTool('clear_project_data', {
        scope: { project: projectId },
        confirmation: true
      });

      const restoreStart = Date.now();
      const largeRestore = await callMCPTool('restore_backup', {
        backup_id: largeBackup.backup_id,
        target_scope: { project: `${projectId}-restored` },
        parallel_processing: true,
        batch_size: 50
      });
      const restoreTime = Date.now() - restoreStart;

      expect(largeRestore.success).toBe(true);
      expect(largeRestore.items_restored).toBe(largeDataSize);
      expect(restoreTime).toBeLessThan(120000); // Should complete within 2 minutes

      console.log(`Large restore operation: ${restoreTime}ms (${(restoreTime/largeDataSize).toFixed(2)}ms per item)`);

      // Step 4: Verify restored data integrity
      const verificationStart = Date.now();
      const verificationResult = await callMCPTool('memory_find', {
        query: 'LargeItem dataset scalability test',
        scope: { project: `${projectId}-restored` }
      });
      const verificationTime = Date.now() - verificationStart;

      expect(verificationResult.hits).toHaveLength(largeDataSize);
      expect(verificationTime).toBeLessThan(30000); // Should complete within 30 seconds

      // Verify data distribution across batches
      const batchCounts = {};
      verificationResult.hits.forEach(hit => {
        const batch = hit.data?.batch;
        batchCounts[batch] = (batchCounts[batch] || 0) + 1;
      });

      expect(Object.keys(batchCounts).length).toBe(10); // 500 items / 50 per batch
      Object.values(batchCounts).forEach(count => {
        expect(count).toBe(50);
      });

      console.log(`Performance Summary:`);
      console.log(`- Creation: ${creationTime}ms`);
      console.log(`- Backup: ${backupTime}ms`);
      console.log(`- Restore: ${restoreTime}ms`);
      console.log(`- Verification: ${verificationTime}ms`);
      console.log(`- Total: ${creationTime + backupTime + restoreTime + verificationTime}ms`);
    });
  });
});

// Helper Functions
async function setupTestDatabase(): Promise<void> {
  console.log('Setting up test database for backup and restore...');
}

async function cleanupTestDatabase(): Promise<void> {
  console.log('Cleaning up test database for backup and restore...');
}

async function cleanupTestData(): Promise<void> {
  console.log('Cleaning up test data for backup and restore...');
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

function generateDataChecksum(data: string): string {
  // Simple checksum function for testing
  let hash = 0;
  for (let i = 0; i < data.length; i++) {
    const char = data.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return `checksum-${hash.toString(36)}`;
}

async function callMCPTool(toolName: string, args: any): Promise<any> {
  return new Promise((resolve) => {
    setTimeout(() => {
      // Simulate different backup/restore operations
      if (toolName === 'create_backup') {
        resolve({
          success: true,
          backup_id: args.backup_id || `backup-${randomUUID().substring(0, 8)}`,
          created_at: new Date().toISOString(),
          items_backed_up: args.items?.length || Math.floor(Math.random() * 10) + 1,
          backup_size_bytes: Math.floor(Math.random() * 1000000) + 100000,
          checksum: `checksum-${randomUUID().substring(0, 8)}`,
          compressed: args.compression || false,
          encryption_enabled: args.encryption || false,
          backup_type: args.backup_type || 'full',
          verified: args.verify_after_creation || false,
          manifest: {
            id: args.backup_id,
            created_at: new Date().toISOString(),
            version: '1.0',
            items_count: args.items?.length || 5,
            size_bytes: Math.floor(Math.random() * 1000000) + 100000,
            checksum: `checksum-${randomUUID().substring(0, 8)}`,
            compressed: args.compression || false,
            encryption_enabled: args.encryption || false
          }
        });
      } else if (toolName === 'restore_backup') {
        resolve({
          success: true,
          items_restored: Math.floor(Math.random() * 10) + 1,
          items_failed: 0,
          errors: [],
          restore_id: `restore-${randomUUID().substring(0, 8)}`,
          timestamp: new Date().toISOString(),
          recovery_time_ms: Math.floor(Math.random() * 5000) + 1000
        });
      } else if (toolName === 'verify_backup') {
        resolve({
          verified: true,
          items_verified: Math.floor(Math.random() * 10) + 1,
          checksums_valid: true
        });
      } else if (toolName === 'verify_backup_integrity') {
        const corrupted = args.corrupted || false;
        resolve({
          valid: !corrupted,
          items_validated: Math.floor(Math.random() * 10) + 1,
          checksums_matched: !corrupted,
          corruption_detected: corrupted,
          corrupted_items: corrupted ? Math.floor(Math.random() * 3) + 1 : 0
        });
      } else if (toolName === 'memory_find') {
        // Standard search response
        resolve({
          hits: Array.from({ length: Math.floor(Math.random() * 5) + 1 }, (_, i) => ({
            id: randomUUID(),
            kind: ['entity', 'decision', 'section', 'todo', 'observation'][i % 5],
            data: {
              title: `Search Result ${i + 1}`,
              content: `Mock search result content for ${args.query || 'search'}`,
              scope: args.scope || {}
            }
          })),
          total: Math.floor(Math.random() * 5) + 1,
          query_time_ms: Math.floor(Math.random() * 200) + 50
        });
      } else if (toolName === 'memory_store') {
        // Standard store response
        const items = args.items || [];
        resolve({
          stored: items.map((item: any) => ({
            id: randomUUID(),
            status: 'inserted',
            kind: item.kind || 'unknown',
            created_at: new Date().toISOString(),
            data: item.data
          })),
          errors: [],
          autonomous_context: {
            action_performed: items.length > 1 ? 'batch' : 'created',
            items_processed: items.length,
            recommendation: 'Backup and restore test data created',
            reasoning: 'Mock data for backup/restore testing',
            user_message_suggestion: `✓ Created ${items.length} test items`
          }
        });
      } else {
        // Default response for other operations
        resolve({
          success: true,
          operation: toolName,
          timestamp: new Date().toISOString(),
          message: `Mock ${toolName} operation completed`
        });
      }
    }, 150); // Slightly longer delay for backup/restore operations
  });
}