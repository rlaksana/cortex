/**
 * Comprehensive Unit Tests for Backup Service
 *
 * Tests advanced backup service functionality including:
 * - Full and incremental backup creation and management
 * - Backup scheduling and automation capabilities
 * - Backup validation and integrity checking
 * - Backup compression and optimization
 * - Complete and partial recovery operations
 * - Point-in-time recovery functionality
 * - Recovery validation and verification
 * - Rollback and disaster recovery capabilities
 * - Backup storage location management
 * - Backup retention policies and enforcement
 * - Storage cleanup and archiving operations
 * - Cross-region backup replication
 * - Backup encryption and decryption
 * - Access control for backup operations
 * - Secure key management
 * - Compliance and audit requirements
 * - Backup performance optimization
 * - Progress tracking and monitoring
 * - Resource usage during backup operations
 * - Impact on system performance analysis
 * - Knowledge base backup strategies
 * - Graph data backup and recovery
 * - Metadata preservation during backups
 * - Relationship integrity during recovery
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { BackupService } from '../../../src/services/backup/backup.service';
import type {
  BackupConfig,
  BackupOperation,
  BackupMetadata,
  RecoveryOperation,
  BackupStorage,
  BackupSchedule,
  BackupValidation,
  RecoveryValidation,
  BackupEncryption,
  AccessControl
} from '../../../src/types/core-interfaces';

// Mock dependencies
vi.mock('../../../src/utils/logger', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn()
  }
}));

vi.mock('../../../src/db/qdrant', () => ({
  getQdrantClient: () => mockQdrantClient
}));

// Mock comprehensive database layer
const mockQdrantClient = {
  // Knowledge base models
  knowledgeEntity: {
    findMany: vi.fn(),
    count: vi.fn(),
    create: vi.fn(),
    updateMany: vi.fn(),
    deleteMany: vi.fn()
  },
  knowledgeRelation: {
    findMany: vi.fn(),
    count: vi.fn(),
    create: vi.fn(),
    updateMany: vi.fn(),
    deleteMany: vi.fn()
  },
  knowledgeObservation: {
    findMany: vi.fn(),
    count: vi.fn(),
    create: vi.fn(),
    updateMany: vi.fn(),
    deleteMany: vi.fn()
  },
  section: {
    findMany: vi.fn(),
    count: vi.fn(),
    create: vi.fn(),
    updateMany: vi.fn(),
    deleteMany: vi.fn()
  },
  adrDecision: {
    findMany: vi.fn(),
    count: vi.fn(),
    create: vi.fn(),
    updateMany: vi.fn(),
    deleteMany: vi.fn()
  },
  issueLog: {
    findMany: vi.fn(),
    count: vi.fn(),
    create: vi.fn(),
    updateMany: vi.fn(),
    deleteMany: vi.fn()
  },
  todoLog: {
    findMany: vi.fn(),
    count: vi.fn(),
    create: vi.fn(),
    updateMany: vi.fn(),
    deleteMany: vi.fn()
  },
  runbook: {
    findMany: vi.fn(),
    count: vi.fn(),
    create: vi.fn(),
    updateMany: vi.fn(),
    deleteMany: vi.fn()
  },
  changeLog: {
    findMany: vi.fn(),
    count: vi.fn(),
    create: vi.fn(),
    updateMany: vi.fn(),
    deleteMany: vi.fn()
  },
  releaseNote: {
    findMany: vi.fn(),
    count: vi.fn(),
    create: vi.fn(),
    updateMany: vi.fn(),
    deleteMany: vi.fn()
  },
  ddlHistory: {
    findMany: vi.fn(),
    count: vi.fn(),
    create: vi.fn(),
    updateMany: vi.fn(),
    deleteMany: vi.fn()
  },
  prContext: {
    findMany: vi.fn(),
    count: vi.fn(),
    create: vi.fn(),
    updateMany: vi.fn(),
    deleteMany: vi.fn()
  },
  incidentLog: {
    findMany: vi.fn(),
    count: vi.fn(),
    create: vi.fn(),
    updateMany: vi.fn(),
    deleteMany: vi.fn()
  },
  releaseLog: {
    findMany: vi.fn(),
    count: vi.fn(),
    create: vi.fn(),
    updateMany: vi.fn(),
    deleteMany: vi.fn()
  },
  riskLog: {
    findMany: vi.fn(),
    count: vi.fn(),
    create: vi.fn(),
    updateMany: vi.fn(),
    deleteMany: vi.fn()
  },
  assumptionLog: {
    findMany: vi.fn(),
    count: vi.fn(),
    create: vi.fn(),
    updateMany: vi.fn(),
    deleteMany: vi.fn()
  },
  // Backup management models
  backupMetadata: {
    findMany: vi.fn(),
    findUnique: vi.fn(),
    create: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
    count: vi.fn()
  },
  backupOperation: {
    findMany: vi.fn(),
    findUnique: vi.fn(),
    create: vi.fn(),
    update: vi.fn(),
    delete: vi.fn()
  },
  recoveryOperation: {
    findMany: vi.fn(),
    findUnique: vi.fn(),
    create: vi.fn(),
    update: vi.fn(),
    delete: vi.fn()
  },
  backupSchedule: {
    findMany: vi.fn(),
    findUnique: vi.fn(),
    create: vi.fn(),
    update: vi.fn(),
    delete: vi.fn()
  },
  backupStorage: {
    findMany: vi.fn(),
    findUnique: vi.fn(),
    create: vi.fn(),
    update: vi.fn(),
    delete: vi.fn()
  },
  auditLog: {
    create: vi.fn(),
    findMany: vi.fn()
  }
};

// Mock file system operations
const mockFileSystem = {
  existsSync: vi.fn(),
  mkdirSync: vi.fn(),
  writeFileSync: vi.fn(),
  readFileSync: vi.fn(),
  unlinkSync: vi.fn(),
  readdirSync: vi.fn(),
  statSync: vi.fn(),
  copyFileSync: vi.fn(),
  renameSync: vi.fn()
};

// Mock encryption service
const mockEncryptionService = {
  encrypt: vi.fn(),
  decrypt: vi.fn(),
  generateKey: vi.fn(),
  hashData: vi.fn(),
  verifyHash: vi.fn()
};

// Mock compression service
const mockCompressionService = {
  compress: vi.fn(),
  decompress: vi.fn(),
  estimateCompressionRatio: vi.fn()
};

describe('BackupService - Comprehensive Backup Functionality', () => {
  let backupService: BackupService;
  let defaultConfig: BackupConfig;

  beforeEach(() => {
    // Reset all mocks
    vi.clearAllMocks();

    // Setup default backup configuration
    defaultConfig = {
      storageLocations: [
        {
          id: 'primary',
          type: 'local',
          path: '/backups/primary',
          isDefault: true,
          encryptionEnabled: true,
          compressionEnabled: true,
          retentionDays: 30,
          maxStorageGB: 1000
        },
        {
          id: 'secondary',
          type: 's3',
          path: 's3://backup-bucket/cortex',
          isDefault: false,
          encryptionEnabled: true,
          compressionEnabled: true,
          retentionDays: 90,
          maxStorageGB: 5000
        }
      ],
      schedules: [
        {
          id: 'daily-full',
          type: 'full',
          frequency: 'daily',
          time: '02:00',
          enabled: true,
          retentionDays: 30,
          compressionLevel: 'medium'
        },
        {
          id: 'hourly-incremental',
          type: 'incremental',
          frequency: 'hourly',
          time: '*/30 * * * *',
          enabled: true,
          retentionDays: 7,
          compressionLevel: 'high'
        }
      ],
      encryption: {
        enabled: true,
        algorithm: 'AES-256-GCM',
        keyRotationDays: 90,
        keyDerivationIterations: 100000
      },
      compression: {
        enabled: true,
        algorithm: 'gzip',
        level: 'medium',
        thresholdMB: 10
      },
      validation: {
        enabled: true,
        checksumAlgorithm: 'sha256',
        integrityCheck: true,
        testRecovery: false
      },
      performance: {
        maxConcurrentOperations: 3,
        throttleRateMBps: 100,
        timeoutMinutes: 120,
        retryAttempts: 3
      },
      monitoring: {
        enabled: true,
        alertThresholds: {
          failureRate: 0.05,
          durationMinutes: 60,
          storageUsage: 0.85
        }
      }
    };

    backupService = new BackupService(defaultConfig);

    // Setup default mock responses
    Object.values(mockQdrantClient).forEach((model: any) => {
      if (model.findMany) model.findMany.mockResolvedValue([]);
      if (model.count) model.count.mockResolvedValue(0);
      if (model.create) model.create.mockResolvedValue({ id: 'mock-id' });
      if (model.findUnique) model.findUnique.mockResolvedValue(null);
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // 1. Backup Operations Tests
  describe('Backup Operations', () => {
    it('should create full backup successfully', async () => {
      // Mock knowledge base data
      const mockKnowledgeData = {
        entities: [
          { id: 'entity-1', data: { title: 'Entity 1' }, tags: { project: 'test' } },
          { id: 'entity-2', data: { title: 'Entity 2' }, tags: { project: 'test' } }
        ],
        relations: [
          { id: 'rel-1', relation_type: 'depends_on', source_entity_id: 'entity-1', target_entity_id: 'entity-2' }
        ],
        observations: [
          { id: 'obs-1', content: 'Test observation', kind: 'observation' }
        ]
      };

      mockQdrantClient.knowledgeEntity.findMany.mockResolvedValue(mockKnowledgeData.entities);
      mockQdrantClient.knowledgeRelation.findMany.mockResolvedValue(mockKnowledgeData.relations);
      mockQdrantClient.knowledgeObservation.findResolvedValue(mockKnowledgeData.observations);
      mockQdrantClient.knowledgeEntity.count.mockResolvedValue(mockKnowledgeData.entities.length);
      mockQdrantClient.knowledgeRelation.count.mockResolvedValue(mockKnowledgeData.relations.length);
      mockQdrantClient.knowledgeObservation.count.mockResolvedValue(mockKnowledgeData.observations.length);

      // Mock file system and compression
      mockFileSystem.existsSync.mockReturnValue(true);
      mockFileSystem.mkdirSync.mockReturnValue(undefined);
      mockFileSystem.writeFileSync.mockReturnValue(undefined);
      mockCompressionService.compress.mockResolvedValue({
        compressedSize: 1024,
        originalSize: 2048,
        compressionRatio: 0.5
      });
      mockEncryptionService.encrypt.mockResolvedValue({
        encryptedData: Buffer.from('encrypted-data'),
        iv: Buffer.from('iv-data'),
        tag: Buffer.from('tag-data')
      });

      const backupOperation: BackupOperation = {
        type: 'full',
        scope: { project: 'test-project' },
        storageLocationId: 'primary',
        compressionEnabled: true,
        encryptionEnabled: true,
        validationEnabled: true
      };

      const result = await backupService.createBackup(backupOperation);

      expect(result).toBeDefined();
      expect(result.id).toBeDefined();
      expect(result.type).toBe('full');
      expect(result.status).toBe('completed');
      expect(result.startTime).toBeInstanceOf(Date);
      expect(result.endTime).toBeInstanceOf(Date);
      expect(result.metadata.totalEntities).toBe(mockKnowledgeData.entities.length);
      expect(result.metadata.totalRelations).toBe(mockKnowledgeData.relations.length);
      expect(result.metadata.totalObservations).toBe(mockKnowledgeData.observations.length);
      expect(result.metadata.storageSize).toBeGreaterThan(0);
      expect(result.metadata.compressedSize).toBeGreaterThan(0);
      expect(result.metadata.checksum).toBeDefined();
      expect(result.storageLocationId).toBe('primary');
    });

    it('should create incremental backup successfully', async () => {
      // Mock last full backup
      const lastFullBackup: BackupMetadata = {
        id: 'backup-full-1',
        type: 'full',
        createdAt: new Date('2024-01-01T02:00:00Z'),
        status: 'completed',
        scope: { project: 'test-project' },
        metadata: {
          totalEntities: 100,
          totalRelations: 150,
          totalObservations: 200,
          storageSize: 5000000,
          compressedSize: 2500000,
          checksum: 'checksum-full-1'
        },
        storageLocationId: 'primary'
      };

      mockQdrantClient.backupMetadata.findUnique.mockResolvedValue(lastFullBackup);

      // Mock incremental data (changed since last full backup)
      const newEntities = [
        { id: 'entity-new-1', data: { title: 'New Entity' }, created_at: new Date('2024-01-02') }
      ];
      const updatedEntities = [
        { id: 'entity-updated-1', data: { title: 'Updated Entity' }, updated_at: new Date('2024-01-02') }
      ];

      mockQdrantClient.knowledgeEntity.findMany
        .mockResolvedValueOnce(newEntities) // New entities
        .mockResolvedValueOnce(updatedEntities); // Updated entities

      mockQdrantClient.knowledgeEntity.count.mockResolvedValue(102); // 100 + 2 new

      const incrementalBackup: BackupOperation = {
        type: 'incremental',
        scope: { project: 'test-project' },
        storageLocationId: 'primary',
        baseBackupId: 'backup-full-1',
        compressionEnabled: true,
        encryptionEnabled: true
      };

      const result = await backupService.createBackup(incrementalBackup);

      expect(result).toBeDefined();
      expect(result.type).toBe('incremental');
      expect(result.baseBackupId).toBe('backup-full-1');
      expect(result.metadata.newEntities).toBe(newEntities.length);
      expect(result.metadata.updatedEntities).toBe(updatedEntities.length);
      expect(result.status).toBe('completed');
    });

    it('should schedule backup operations automatically', async () => {
      const backupSchedule: BackupSchedule = {
        id: 'scheduled-backup-1',
        type: 'full',
        frequency: 'daily',
        time: '02:00',
        enabled: true,
        scope: { project: 'scheduled-project' },
        storageLocationId: 'primary',
        retentionDays: 30
      };

      mockQdrantClient.backupSchedule.create.mockResolvedValue({
        id: 'scheduled-backup-1',
        ...backupSchedule,
        createdAt: new Date(),
        lastRunAt: null,
        nextRunAt: backupService['calculateNextRun'](backupSchedule)
      });

      const result = await backupService.createSchedule(backupSchedule);

      expect(result).toBeDefined();
      expect(result.id).toBe('scheduled-backup-1');
      expect(result.enabled).toBe(true);
      expect(result.nextRunAt).toBeInstanceOf(Date);
      expect(mockQdrantClient.backupSchedule.create).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'full',
          frequency: 'daily',
          time: '02:00',
          enabled: true
        })
      );
    });

    it('should validate backup integrity after creation', async () => {
      const backupId = 'backup-to-validate';

      // Mock backup metadata
      const backupMetadata: BackupMetadata = {
        id: backupId,
        type: 'full',
        createdAt: new Date(),
        status: 'completed',
        scope: { project: 'validation-test' },
        metadata: {
          totalEntities: 50,
          totalRelations: 75,
          totalObservations: 100,
          storageSize: 1000000,
          compressedSize: 500000,
          checksum: 'original-checksum'
        },
        storageLocationId: 'primary'
      };

      mockQdrantClient.backupMetadata.findUnique.mockResolvedValue(backupMetadata);
      mockFileSystem.existsSync.mockReturnValue(true);
      mockFileSystem.readFileSync.mockReturnValue(Buffer.from('backup-data'));
      mockEncryptionService.hashData.mockResolvedValue('original-checksum');

      const validation = await backupService.validateBackup(backupId);

      expect(validation).toBeDefined();
      expect(validation.backupId).toBe(backupId);
      expect(validation.isValid).toBe(true);
      expect(validation.checksumMatch).toBe(true);
      expect(validation.validationTime).toBeInstanceOf(Date);
      expect(validation.issues).toHaveLength(0);
    });

    it('should optimize backup compression based on content type', async () => {
      // Mock different content types for compression optimization
      const textHeavyData = Buffer.from('a'.repeat(1000000)); // Highly compressible
      const binaryData = Buffer.from(Array.from({ length: 1000000 }, () => Math.random() * 255)); // Less compressible

      mockCompressionService.estimateCompressionRatio
        .mockResolvedValueOnce(0.1) // Text data - high compression
        .mockResolvedValueOnce(0.95); // Binary data - low compression

      const textOptimization = await backupService['optimizeCompression'](textHeavyData, 'text');
      const binaryOptimization = await backupService['optimizeCompression'](binaryData, 'binary');

      expect(textOptimization.compressionLevel).toBe('high');
      expect(textOptimization.algorithm).toBe('gzip');
      expect(binaryOptimization.compressionLevel).toBe('low');
      expect(binaryOptimization.algorithm).toBe('none'); // Skip compression for already compressed data
    });

    it('should handle backup creation errors gracefully', async () => {
      // Mock database error during backup
      mockQdrantClient.knowledgeEntity.findMany.mockRejectedValue(new Error('Database connection failed'));

      const backupOperation: BackupOperation = {
        type: 'full',
        scope: { project: 'error-test' },
        storageLocationId: 'primary'
      };

      await expect(backupService.createBackup(backupOperation)).rejects.toThrow('Failed to create backup');

      // Verify cleanup on error
      expect(mockFileSystem.unlinkSync).toHaveBeenCalled();
    });

    it('should retry failed backup operations', async () => {
      let attemptCount = 0;
      mockQdrantClient.knowledgeEntity.findMany.mockImplementation(() => {
        attemptCount++;
        if (attemptCount < 3) {
          return Promise.reject(new Error('Temporary failure'));
        }
        return Promise.resolve([{ id: 'entity-1', data: { title: 'Test Entity' } }]);
      });

      const backupOperation: BackupOperation = {
        type: 'full',
        scope: { project: 'retry-test' },
        storageLocationId: 'primary',
        retryAttempts: 3
      };

      const result = await backupService.createBackup(backupOperation);

      expect(result).toBeDefined();
      expect(result.status).toBe('completed');
      expect(attemptCount).toBe(3);
    });
  });

  // 2. Recovery Operations Tests
  describe('Recovery Operations', () => {
    it('should perform complete recovery from full backup', async () => {
      const backupId = 'full-backup-1';

      // Mock backup metadata
      const backupMetadata: BackupMetadata = {
        id: backupId,
        type: 'full',
        createdAt: new Date('2024-01-01T02:00:00Z'),
        status: 'completed',
        scope: { project: 'recovery-test' },
        metadata: {
          totalEntities: 100,
          totalRelations: 150,
          totalObservations: 200,
          storageSize: 5000000,
          compressedSize: 2500000,
          checksum: 'recovery-checksum'
        },
        storageLocationId: 'primary'
      };

      mockQdrantClient.backupMetadata.findUnique.mockResolvedValue(backupMetadata);
      mockFileSystem.existsSync.mockReturnValue(true);
      mockFileSystem.readFileSync.mockReturnValue(Buffer.from('backup-data'));
      mockEncryptionService.decrypt.mockResolvedValue(Buffer.from('decrypted-data'));
      mockCompressionService.decompress.mockResolvedValue(Buffer.from('decompressed-data'));

      // Mock successful data restoration
      mockQdrantClient.knowledgeEntity.create.mockResolvedValue({ id: 'restored-entity' });
      mockQdrantClient.knowledgeRelation.create.mockResolvedValue({ id: 'restored-relation' });
      mockQdrantClient.knowledgeObservation.create.mockResolvedValue({ id: 'restored-observation' });

      const recoveryOperation: RecoveryOperation = {
        backupId,
        type: 'complete',
        scope: { project: 'recovery-test' },
        validateBeforeRecovery: true,
        validateAfterRecovery: true
      };

      const result = await backupService.performRecovery(recoveryOperation);

      expect(result).toBeDefined();
      expect(result.backupId).toBe(backupId);
      expect(result.type).toBe('complete');
      expect(result.status).toBe('completed');
      expect(result.startTime).toBeInstanceOf(Date);
      expect(result.endTime).toBeInstanceOf(Date);
      expect(result.metadata.restoredEntities).toBe(backupMetadata.metadata.totalEntities);
      expect(result.metadata.restoredRelations).toBe(backupMetadata.metadata.totalRelations);
      expect(result.metadata.restoredObservations).toBe(backupMetadata.metadata.totalObservations);
      expect(result.validation.beforeRecovery).toBe(true);
      expect(result.validation.afterRecovery).toBe(true);
    });

    it('should perform partial recovery from backup', async () => {
      const backupId = 'partial-backup-1';

      const backupMetadata: BackupMetadata = {
        id: backupId,
        type: 'full',
        createdAt: new Date('2024-01-01T02:00:00Z'),
        status: 'completed',
        scope: { project: 'partial-recovery-test' },
        metadata: {
          totalEntities: 100,
          totalRelations: 150,
          totalObservations: 200,
          storageSize: 5000000,
          compressedSize: 2500000,
          checksum: 'partial-recovery-checksum'
        },
        storageLocationId: 'primary'
      };

      mockQdrantClient.backupMetadata.findUnique.mockResolvedValue(backupMetadata);
      mockFileSystem.existsSync.mockReturnValue(true);
      mockFileSystem.readFileSync.mockReturnValue(Buffer.from('partial-backup-data'));
      mockEncryptionService.decrypt.mockResolvedValue(Buffer.from('decrypted-partial-data'));
      mockCompressionService.decompress.mockResolvedValue(Buffer.from('decompressed-partial-data'));

      const partialRecovery: RecoveryOperation = {
        backupId,
        type: 'partial',
        scope: { project: 'partial-recovery-test' },
        filters: {
          types: ['entity', 'relation'],
          dateRange: {
            startDate: new Date('2024-01-01'),
            endDate: new Date('2024-01-31')
          },
          tags: { category: 'critical' }
        },
        validateBeforeRecovery: true,
        validateAfterRecovery: true
      };

      const result = await backupService.performRecovery(partialRecovery);

      expect(result).toBeDefined();
      expect(result.type).toBe('partial');
      expect(result.status).toBe('completed');
      expect(result.filters).toEqual(partialRecovery.filters);
      expect(result.metadata.restoredEntities).toBeGreaterThanOrEqual(0);
      expect(result.metadata.restoredRelations).toBeGreaterThanOrEqual(0);
    });

    it('should perform point-in-time recovery', async () => {
      const targetTime = new Date('2024-01-15T12:00:00Z');

      // Mock backup chain for point-in-time recovery
      const fullBackup: BackupMetadata = {
        id: 'full-base',
        type: 'full',
        createdAt: new Date('2024-01-01T02:00:00Z'),
        status: 'completed',
        scope: { project: 'pitr-test' },
        metadata: {
          totalEntities: 100,
          totalRelations: 150,
          totalObservations: 200,
          storageSize: 5000000,
          compressedSize: 2500000,
          checksum: 'base-checksum'
        },
        storageLocationId: 'primary'
      };

      const incrementalBackups: BackupMetadata[] = [
        {
          id: 'inc-1',
          type: 'incremental',
          createdAt: new Date('2024-01-10T02:00:00Z'),
          status: 'completed',
          scope: { project: 'pitr-test' },
          baseBackupId: 'full-base',
          metadata: {
            newEntities: 10,
            updatedEntities: 5,
            newRelations: 15,
            storageSize: 500000,
            compressedSize: 250000
          },
          storageLocationId: 'primary'
        },
        {
          id: 'inc-2',
          type: 'incremental',
          createdAt: new Date('2024-01-20T02:00:00Z'),
          status: 'completed',
          scope: { project: 'pitr-test' },
          baseBackupId: 'full-base',
          metadata: {
            newEntities: 8,
            updatedEntities: 3,
            newRelations: 12,
            storageSize: 400000,
            compressedSize: 200000
          },
          storageLocationId: 'primary'
        }
      ];

      mockQdrantClient.backupMetadata.findMany.mockResolvedValue([fullBackup, ...incrementalBackups]);
      mockQdrantClient.backupMetadata.findUnique.mockResolvedValue(fullBackup);

      const pitrRecovery: RecoveryOperation = {
        backupId: 'full-base',
        type: 'point-in-time',
        targetTime,
        scope: { project: 'pitr-test' },
        validateBeforeRecovery: true,
        validateAfterRecovery: true
      };

      const result = await backupService.performRecovery(pitrRecovery);

      expect(result).toBeDefined();
      expect(result.type).toBe('point-in-time');
      expect(result.targetTime).toEqual(targetTime);
      expect(result.status).toBe('completed');
      expect(result.metadata.appliedBackups).toContain('full-base');
      expect(result.metadata.appliedBackups).toContain('inc-1');
      expect(result.metadata.appliedBackups).not.toContain('inc-2'); // After target time
    });

    it('should validate recovery after completion', async () => {
      const backupId = 'validation-backup';

      const backupMetadata: BackupMetadata = {
        id: backupId,
        type: 'full',
        createdAt: new Date(),
        status: 'completed',
        scope: { project: 'validation-test' },
        metadata: {
          totalEntities: 50,
          totalRelations: 75,
          totalObservations: 100,
          storageSize: 2500000,
          compressedSize: 1250000,
          checksum: 'validation-checksum'
        },
        storageLocationId: 'primary'
      };

      mockQdrantClient.backupMetadata.findUnique.mockResolvedValue(backupMetadata);
      mockQdrantClient.knowledgeEntity.count.mockResolvedValue(50);
      mockQdrantClient.knowledgeRelation.count.mockResolvedValue(75);
      mockQdrantClient.knowledgeObservation.count.mockResolvedValue(100);

      const validation = await backupService.validateRecovery(backupId);

      expect(validation).toBeDefined();
      expect(validation.backupId).toBe(backupId);
      expect(validation.isValid).toBe(true);
      expect(validation.entityCount).toBe(50);
      expect(validation.relationCount).toBe(75);
      expect(validation.observationCount).toBe(100);
      expect(validation.validationTime).toBeInstanceOf(Date);
      expect(validation.issues).toHaveLength(0);
    });

    it('should rollback failed recovery operations', async () => {
      const backupId = 'rollback-backup';

      // Mock partial recovery failure
      mockQdrantClient.backupMetadata.findUnique.mockResolvedValue({
        id: backupId,
        type: 'full',
        status: 'completed',
        metadata: {
          totalEntities: 100,
          totalRelations: 150
        }
      });

      // Mock successful entity restoration but failed relation restoration
      mockQdrantClient.knowledgeEntity.create.mockResolvedValue({ id: 'restored-entity' });
      mockQdrantClient.knowledgeRelation.create.mockRejectedValue(new Error('Relation restoration failed'));

      // Mock rollback operations
      mockQdrantClient.knowledgeEntity.deleteMany.mockResolvedValue({ count: 100 });

      const recoveryOperation: RecoveryOperation = {
        backupId,
        type: 'complete',
        scope: { project: 'rollback-test' },
        rollbackOnFailure: true
      };

      await expect(backupService.performRecovery(recoveryOperation)).rejects.toThrow();

      // Verify rollback was attempted
      expect(mockQdrantClient.knowledgeEntity.deleteMany).toHaveBeenCalled();
    });

    it('should handle concurrent recovery operations safely', async () => {
      const backupId = 'concurrent-backup';

      mockQdrantClient.backupMetadata.findUnique.mockResolvedValue({
        id: backupId,
        type: 'full',
        status: 'completed',
        scope: { project: 'concurrent-test' },
        metadata: { totalEntities: 100, totalRelations: 150 }
      });

      // Attempt multiple concurrent recoveries
      const recoveries = Array.from({ length: 3 }, () =>
        backupService.performRecovery({
          backupId,
          type: 'complete',
          scope: { project: 'concurrent-test' }
        })
      );

      const results = await Promise.allSettled(recoveries);

      // Only one should succeed, others should fail with concurrent operation error
      const successful = results.filter(r => r.status === 'fulfilled');
      const failed = results.filter(r => r.status === 'rejected');

      expect(successful).toHaveLength(1);
      expect(failed).toHaveLength(2);
      failed.forEach(result => {
        if (result.status === 'rejected') {
          expect(result.reason.message).toContain('concurrent');
        }
      });
    });
  });

  // 3. Storage Management Tests
  describe('Storage Management', () => {
    it('should manage multiple storage locations', async () => {
      const storageLocations: BackupStorage[] = [
        {
          id: 'local-primary',
          type: 'local',
          path: '/backups/primary',
          isDefault: true,
          encryptionEnabled: true,
          compressionEnabled: true,
          retentionDays: 30,
          maxStorageGB: 1000,
          status: 'active'
        },
        {
          id: 's3-secondary',
          type: 's3',
          path: 's3://backup-bucket/cortex',
          isDefault: false,
          encryptionEnabled: true,
          compressionEnabled: true,
          retentionDays: 90,
          maxStorageGB: 5000,
          status: 'active'
        },
        {
          id: 'azure-archive',
          type: 'azure',
          path: 'azure://backup-account/cortex-archive',
          isDefault: false,
          encryptionEnabled: true,
          compressionEnabled: false,
          retentionDays: 365,
          maxStorageGB: 10000,
          status: 'active'
        }
      ];

      mockQdrantClient.backupStorage.findMany.mockResolvedValue(storageLocations);

      const result = await backupService.getStorageLocations();

      expect(result).toHaveLength(3);
      expect(result[0].id).toBe('local-primary');
      expect(result[0].isDefault).toBe(true);
      expect(result[1].type).toBe('s3');
      expect(result[2].retentionDays).toBe(365);
    });

    it('should enforce backup retention policies', async () => {
      const expiredBackups = [
        {
          id: 'expired-1',
          type: 'full',
          createdAt: new Date('2023-01-01'),
          status: 'completed',
          retentionDays: 30,
          storageLocationId: 'primary'
        },
        {
          id: 'expired-2',
          type: 'incremental',
          createdAt: new Date('2023-12-01'),
          status: 'completed',
          retentionDays: 7,
          storageLocationId: 'primary'
        }
      ];

      const activeBackups = [
        {
          id: 'active-1',
          type: 'full',
          createdAt: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000), // 10 days ago
          status: 'completed',
          retentionDays: 30,
          storageLocationId: 'primary'
        }
      ];

      mockQdrantClient.backupMetadata.findMany.mockResolvedValue([...expiredBackups, ...activeBackups]);
      mockQdrantClient.backupMetadata.deleteMany.mockResolvedValue({ count: 2 });
      mockFileSystem.existsSync.mockReturnValue(true);
      mockFileSystem.unlinkSync.mockReturnValue(undefined);

      const cleanupResult = await backupService.enforceRetentionPolicies();

      expect(cleanupResult.deletedBackups).toHaveLength(2);
      expect(cleanupResult.deletedBackups.map(b => b.id)).toContain('expired-1');
      expect(cleanupResult.deletedBackups.map(b => b.id)).toContain('expired-2');
      expect(cleanupResult.deletedBackups.map(b => b.id)).not.toContain('active-1');
      expect(cleanupResult.freedSpaceBytes).toBeGreaterThan(0);
    });

    it('should perform storage cleanup and archiving', async () => {
      const storageStats = {
        totalSize: 800 * 1024 * 1024 * 1024, // 800GB
        usedSize: 750 * 1024 * 1024 * 1024, // 750GB
        availableSize: 50 * 1024 * 1024 * 1024, // 50GB
        backupCount: 150
      };

      mockQdrantClient.backupStorage.findUnique.mockResolvedValue({
        id: 'primary',
        type: 'local',
        path: '/backups/primary',
        maxStorageGB: 1000,
        ...storageStats
      });

      // Mock old backups for archiving
      const oldBackups = Array.from({ length: 20 }, (_, i) => ({
        id: `old-backup-${i}`,
        type: 'full',
        createdAt: new Date(Date.now() - (i + 30) * 24 * 60 * 60 * 1000),
        status: 'completed',
        size: 5 * 1024 * 1024 * 1024 // 5GB each
      }));

      mockQdrantClient.backupMetadata.findMany.mockResolvedValue(oldBackups);
      mockFileSystem.existsSync.mockReturnValue(true);
      mockFileSystem.statSync.mockReturnValue({ size: 5 * 1024 * 1024 * 1024 });

      const cleanupResult = await backupService.performStorageCleanup('primary');

      expect(cleanupResult.archivedBackups.length).toBeGreaterThan(0);
      expect(cleanupResult.freedSpaceBytes).toBeGreaterThan(0);
      expect(cleanupResult.storageUtilizationAfter).toBeLessThan(storageStats.usedSize);
    });

    it('should replicate backups across regions', async () => {
      const primaryBackup: BackupMetadata = {
        id: 'primary-backup',
        type: 'full',
        createdAt: new Date(),
        status: 'completed',
        scope: { project: 'replication-test' },
        metadata: {
          totalEntities: 100,
          totalRelations: 150,
          storageSize: 5000000,
          compressedSize: 2500000,
          checksum: 'replication-checksum'
        },
        storageLocationId: 'primary'
      };

      const secondaryStorage: BackupStorage = {
        id: 'secondary-region',
        type: 's3',
        path: 's3://backup-bucket-secondary/cortex',
        region: 'us-west-2',
        isDefault: false,
        encryptionEnabled: true,
        status: 'active'
      };

      mockQdrantClient.backupMetadata.findUnique.mockResolvedValue(primaryBackup);
      mockQdrantClient.backupStorage.findUnique.mockResolvedValue(secondaryStorage);
      mockFileSystem.existsSync.mockReturnValue(true);
      mockFileSystem.readFileSync.mockReturnValue(Buffer.from('backup-data'));
      mockFileSystem.writeFileSync.mockReturnValue(undefined);

      const replicationResult = await backupService.replicateBackup('primary-backup', 'secondary-region');

      expect(replicationResult).toBeDefined();
      expect(replicationResult.sourceBackupId).toBe('primary-backup');
      expect(replicationResult.targetLocationId).toBe('secondary-region');
      expect(replicationResult.status).toBe('completed');
      expect(replicationResult.replicatedSize).toBe(primaryBackup.metadata.storageSize);
      expect(replicationResult.checksumMatch).toBe(true);
    });

    it('should monitor storage usage and alert thresholds', async () => {
      const storageUsages = [
        {
          locationId: 'primary',
          type: 'local',
          usedGB: 850,
          maxGB: 1000,
          usagePercentage: 85,
          status: 'warning'
        },
        {
          locationId: 'secondary',
          type: 's3',
          usedGB: 4500,
          maxGB: 5000,
          usagePercentage: 90,
          status: 'critical'
        }
      ];

      mockQdrantClient.backupStorage.findMany.mockResolvedValue(storageUsages.map(usage => ({
        id: usage.locationId,
        type: usage.type,
        usedSize: usage.usedGB * 1024 * 1024 * 1024,
        maxSize: usage.maxGB * 1024 * 1024 * 1024
      })));

      const monitoringResult = await backupService.monitorStorageUsage();

      expect(monitoringResult).toHaveLength(2);
      expect(monitoringResult[0].status).toBe('warning');
      expect(monitoringResult[1].status).toBe('critical');
      expect(monitoringResult[1].alerts).toContain('Storage usage exceeds 85% threshold');
      expect(monitoringResult[1].recommendations.length).toBeGreaterThan(0);
    });
  });

  // 4. Security and Encryption Tests
  describe('Security and Encryption', () => {
    it('should encrypt backup data with specified algorithm', async () => {
      const backupData = Buffer.from('sensitive-backup-data');
      const encryptionKey = Buffer.from('encryption-key-32-bytes-long');

      mockEncryptionService.encrypt.mockResolvedValue({
        encryptedData: Buffer.from('encrypted-content'),
        iv: Buffer.from('initialization-vector'),
        tag: Buffer.from('authentication-tag')
      });
      mockEncryptionService.generateKey.mockResolvedValue(encryptionKey);

      const encryptionConfig: BackupEncryption = {
        enabled: true,
        algorithm: 'AES-256-GCM',
        keyDerivationIterations: 100000
      };

      const encryptedResult = await backupService.encryptBackupData(backupData, encryptionConfig);

      expect(encryptedResult).toBeDefined();
      expect(encryptedResult.encryptedData).toBeDefined();
      expect(encryptedResult.iv).toBeDefined();
      expect(encryptedResult.tag).toBeDefined();
      expect(encryptedResult.algorithm).toBe('AES-256-GCM');
      expect(encryptedResult.keyId).toBeDefined();
      expect(mockEncryptionService.encrypt).toHaveBeenCalledWith(
        backupData,
        expect.objectContaining({
          algorithm: 'AES-256-GCM'
        })
      );
    });

    it('should decrypt backup data successfully', async () => {
      const encryptedData = {
        encryptedData: Buffer.from('encrypted-content'),
        iv: Buffer.from('initialization-vector'),
        tag: Buffer.from('authentication-tag'),
        algorithm: 'AES-256-GCM',
        keyId: 'key-123'
      };

      const decryptedData = Buffer.from('original-backup-data');

      mockEncryptionService.decrypt.mockResolvedValue(decryptedData);

      const result = await backupService.decryptBackupData(encryptedData);

      expect(result).toBeDefined();
      expect(result.equals(decryptedData)).toBe(true);
      expect(mockEncryptionService.decrypt).toHaveBeenCalledWith(
        encryptedData.encryptedData,
        expect.objectContaining({
          iv: encryptedData.iv,
          tag: encryptedData.tag,
          algorithm: encryptedData.algorithm
        })
      );
    });

    it('should manage encryption keys securely', async () => {
      const keyMetadata = {
        keyId: 'key-456',
        algorithm: 'AES-256-GCM',
        createdAt: new Date(),
        status: 'active',
        rotationDays: 90,
        lastRotatedAt: new Date(),
        expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000)
      };

      mockEncryptionService.generateKey.mockResolvedValue(Buffer.from('new-encryption-key'));

      const newKey = await backupService.rotateEncryptionKey('key-456');

      expect(newKey).toBeDefined();
      expect(newKey.keyId).toBeDefined();
      expect(newKey.algorithm).toBe('AES-256-GCM');
      expect(newKey.status).toBe('active');
      expect(mockEncryptionService.generateKey).toHaveBeenCalled();
    });

    it('should enforce access control for backup operations', async () => {
      const accessControl: AccessControl = {
        userId: 'user-123',
        roles: ['backup-operator'],
        permissions: ['backup:read', 'backup:create', 'backup:delete'],
        scopeRestrictions: { project: 'allowed-project' }
      };

      // Mock successful access check
      const canCreateBackup = await backupService.checkAccess('backup:create', accessControl);
      expect(canCreateBackup).toBe(true);

      // Mock failed access check
      const restrictedAccess: AccessControl = {
        userId: 'user-456',
        roles: ['readonly-user'],
        permissions: ['backup:read'],
        scopeRestrictions: { project: 'different-project' }
      };

      const canDeleteBackup = await backupService.checkAccess('backup:delete', restrictedAccess);
      expect(canDeleteBackup).toBe(false);
    });

    it('should maintain audit trail for backup operations', async () => {
      const auditEvents = [
        {
          operation: 'backup:create',
          userId: 'user-123',
          backupId: 'backup-789',
          timestamp: new Date(),
          details: { type: 'full', scope: { project: 'audit-test' } },
          ipAddress: '192.168.1.100',
          userAgent: 'Cortex-Backup-Client/1.0'
        },
        {
          operation: 'backup:restore',
          userId: 'user-123',
          backupId: 'backup-789',
          timestamp: new Date(),
          details: { type: 'complete', validateAfterRecovery: true },
          ipAddress: '192.168.1.100',
          userAgent: 'Cortex-Backup-Client/1.0'
        }
      ];

      mockQdrantClient.auditLog.create.mockResolvedValue({ id: 'audit-1' });

      for (const event of auditEvents) {
        await backupService.logAuditEvent(event);
        expect(mockQdrantClient.auditLog.create).toHaveBeenCalledWith(
          expect.objectContaining({
            operation: event.operation,
            userId: event.userId,
            backupId: event.backupId,
            details: event.details
          })
        );
      }
    });

    it('should validate compliance requirements', async () => {
      const complianceRequirements = {
        dataRetention: { minDays: 90, maxDays: 2555 }, // 7 years
        encryption: { required: true, minKeyLength: 256 },
        accessControl: { required: true, auditRetentionDays: 2555 },
        geoRedundancy: { required: true, minRegions: 2 },
        integrityChecks: { frequency: 'weekly', algorithm: 'SHA-256' }
      };

      const backupConfig = {
        retentionDays: 365,
        encryption: { enabled: true, algorithm: 'AES-256-GCM', keyLength: 256 },
        accessControl: { enabled: true, auditRetention: 2555 },
        storageRegions: ['us-east-1', 'eu-west-1'],
        integrityChecks: { enabled: true, frequency: 'weekly', algorithm: 'SHA-256' }
      };

      const complianceResult = await backupService.validateCompliance(backupConfig, complianceRequirements);

      expect(complianceResult.isCompliant).toBe(true);
      expect(complianceResult.validations).toHaveLength(5);
      complianceResult.validations.forEach(validation => {
        expect(validation.passed).toBe(true);
      });
    });
  });

  // 5. Performance and Monitoring Tests
  describe('Performance and Monitoring', () => {
    it('should optimize backup performance based on system resources', async () => {
      const systemResources = {
        cpuUsage: 0.3, // 30%
        memoryUsage: 0.6, // 60%
        diskIO: 0.8, // 80%
        networkIO: 0.4 // 40%
      };

      const optimization = await backupService.optimizeBackupPerformance(systemResources);

      expect(optimization).toBeDefined();
      expect(optimization.concurrencyLevel).toBeGreaterThan(0);
      expect(optimization.throttleRateMBps).toBeGreaterThan(0);
      expect(optimization.compressionLevel).toBeDefined();

      // High disk IO should reduce throttle rate
      if (systemResources.diskIO > 0.7) {
        expect(optimization.throttleRateMBps).toBeLessThan(100);
      }
    });

    it('should track backup progress in real-time', async () => {
      const backupId = 'progress-backup';

      // Mock backup progress updates
      const progressUpdates = [
        { percentage: 10, stage: 'data-extraction', estimatedTimeRemaining: 1800 },
        { percentage: 25, stage: 'compression', estimatedTimeRemaining: 1200 },
        { percentage: 50, stage: 'encryption', estimatedTimeRemaining: 600 },
        { percentage: 75, stage: 'upload', estimatedTimeRemaining: 300 },
        { percentage: 100, stage: 'validation', estimatedTimeRemaining: 0 }
      ];

      mockQdrantClient.backupOperation.findUnique.mockResolvedValue({
        id: backupId,
        status: 'in-progress',
        progress: 0
      });

      const progressTracker = await backupService.trackBackupProgress(backupId);

      expect(progressTracker).toBeDefined();
      expect(progressTracker.backupId).toBe(backupId);
      expect(progressTracker.startTime).toBeInstanceOf(Date);

      // Simulate progress updates
      for (const update of progressUpdates) {
        await progressTracker.updateProgress(update);
        expect(progressTracker.currentProgress).toBe(update.percentage);
        expect(progressTracker.currentStage).toBe(update.stage);
        expect(progressTracker.estimatedTimeRemaining).toBe(update.estimatedTimeRemaining);
      }
    });

    it('should monitor resource usage during backup operations', async () => {
      const resourceMonitor = await backupService.startResourceMonitoring();

      expect(resourceMonitor).toBeDefined();
      expect(resourceMonitor.startTime).toBeInstanceOf(Date);
      expect(resourceMonitor.metrics).toBeDefined();

      // Simulate resource usage updates
      const resourceSnapshots = [
        { timestamp: new Date(), cpuUsage: 0.4, memoryUsage: 0.5, diskIO: 100, networkIO: 50 },
        { timestamp: new Date(), cpuUsage: 0.6, memoryUsage: 0.7, diskIO: 150, networkIO: 80 },
        { timestamp: new Date(), cpuUsage: 0.3, memoryUsage: 0.6, diskIO: 80, networkIO: 40 }
      ];

      for (const snapshot of resourceSnapshots) {
        resourceMonitor.recordSnapshot(snapshot);
      }

      const summary = resourceMonitor.getSummary();
      expect(summary.avgCpuUsage).toBeGreaterThan(0);
      expect(summary.avgMemoryUsage).toBeGreaterThan(0);
      expect(summary.peakDiskIO).toBeGreaterThan(0);
      expect(summary.totalDuration).toBeGreaterThan(0);
    });

    it('should analyze impact on system performance', async () => {
      const baselineMetrics = {
        averageResponseTime: 100, // ms
        throughput: 1000, // requests/sec
        errorRate: 0.01, // 1%
        cpuUsage: 0.2,
        memoryUsage: 0.4
      };

      const backupMetrics = {
        averageResponseTime: 150, // ms
        throughput: 800, // requests/sec
        errorRate: 0.02, // 2%
        cpuUsage: 0.5,
        memoryUsage: 0.6
      };

      const impactAnalysis = await backupService.analyzePerformanceImpact(baselineMetrics, backupMetrics);

      expect(impactAnalysis).toBeDefined();
      expect(impactAnalysis.responseTimeIncrease).toBe(50); // 50ms increase
      expect(impactAnalysis.throughputDecrease).toBe(200); // 200 requests/sec decrease
      expect(impactAnalysis.errorRateIncrease).toBe(0.01); // 1% increase
      expect(impactAnalysis.cpuUsageIncrease).toBe(0.3); // 30% increase
      expect(impactAnalysis.memoryUsageIncrease).toBe(0.2); // 20% increase
      expect(impactAnalysis.overallImpact).toBe('medium');
      expect(impactAnalysis.recommendations.length).toBeGreaterThan(0);
    });

    it('should provide performance optimization suggestions', async () => {
      const performanceData = {
        backupDuration: 7200, // 2 hours
        throughputMBps: 10, // 10 MB/sec
        compressionRatio: 0.3,
        encryptionOverhead: 0.2,
        storageWriteSpeed: 15, // 15 MB/sec
        networkBandwidth: 100 // 100 MB/sec
      };

      const suggestions = await backupService.getPerformanceOptimizations(performanceData);

      expect(suggestions).toBeDefined();
      expect(suggestions.optimizations).toBeInstanceOf(Array);

      // Should suggest compression level adjustment if ratio is poor
      if (performanceData.compressionRatio > 0.5) {
        expect(suggestions.optimizations.some(opt =>
          opt.category === 'compression' && opt.description.includes('compression level')
        )).toBe(true);
      }

      // Should suggest concurrency adjustments if throughput is low
      if (performanceData.throughputMBps < 50) {
        expect(suggestions.optimizations.some(opt =>
          opt.category === 'concurrency' && opt.description.includes('concurrent')
        )).toBe(true);
      }

      expect(suggestions.expectedImprovements).toBeDefined();
      expect(suggestions.implementationComplexity).toBeDefined();
    });
  });

  // 6. Knowledge System Integration Tests
  describe('Knowledge System Integration', () => {
    it('should backup knowledge graph with relationship integrity', async () => {
      const knowledgeGraph = {
        entities: [
          { id: 'entity-1', type: 'component', data: { name: 'Component A' } },
          { id: 'entity-2', type: 'component', data: { name: 'Component B' } },
          { id: 'entity-3', type: 'system', data: { name: 'System X' } }
        ],
        relations: [
          {
            id: 'rel-1',
            type: 'depends_on',
            sourceEntityId: 'entity-1',
            targetEntityId: 'entity-2',
            metadata: { strength: 0.8 }
          },
          {
            id: 'rel-2',
            type: 'implements',
            sourceEntityId: 'entity-1',
            targetEntityId: 'entity-3',
            metadata: { version: '1.0' }
          }
        ]
      };

      mockQdrantClient.knowledgeEntity.findMany.mockResolvedValue(knowledgeGraph.entities);
      mockQdrantClient.knowledgeRelation.findMany.mockResolvedValue(knowledgeGraph.relations);

      const graphBackup = await backupService.backupKnowledgeGraph({
        scope: { project: 'graph-backup-test' },
        includeRelations: true,
        validateIntegrity: true,
        preserveMetadata: true
      });

      expect(graphBackup).toBeDefined();
      expect(graphBackup.entityCount).toBe(knowledgeGraph.entities.length);
      expect(graphBackup.relationCount).toBe(knowledgeGraph.relations.length);
      expect(graphBackup.integrityValidation.passed).toBe(true);
      expect(graphBackup.metadata.entityTypes).toContain('component');
      expect(graphBackup.metadata.entityTypes).toContain('system');
      expect(graphBackup.metadata.relationTypes).toContain('depends_on');
      expect(graphBackup.metadata.relationTypes).toContain('implements');
    });

    it('should preserve metadata during backup and recovery', async () => {
      const originalMetadata = {
        entities: [
          {
            id: 'entity-with-metadata',
            data: { title: 'Entity with rich metadata' },
            tags: { project: 'metadata-test', category: 'important' },
            created_at: new Date('2024-01-01'),
            updated_at: new Date('2024-01-15'),
            version: 3,
            author: 'user-123',
            confidence: 0.95
          }
        ],
        observations: [
          {
            id: 'obs-with-metadata',
            content: 'Observation with metadata',
            kind: 'observation',
            tags: { verified: true, source: 'manual' },
            created_at: new Date('2024-01-10'),
            verified_by: 'expert-456',
            reliability: 0.88
          }
        ]
      };

      mockQdrantClient.knowledgeEntity.findMany.mockResolvedValue(originalMetadata.entities);
      mockQdrantClient.knowledgeObservation.findMany.mockResolvedValue(originalMetadata.observations);

      // Backup
      const backupResult = await backupService.createBackup({
        type: 'full',
        scope: { project: 'metadata-test' },
        preserveAllMetadata: true
      });

      expect(backupResult.metadata.preservedMetadataFields).toContain('tags');
      expect(backupResult.metadata.preservedMetadataFields).toContain('created_at');
      expect(backupResult.metadata.preservedMetadataFields).toContain('updated_at');

      // Recovery
      mockQdrantClient.backupMetadata.findUnique.mockResolvedValue(backupResult);
      mockFileSystem.existsSync.mockReturnValue(true);
      mockFileSystem.readFileSync.mockReturnValue(Buffer.from('backup-with-metadata'));
      mockEncryptionService.decrypt.mockResolvedValue(Buffer.from('decrypted-metadata'));
      mockCompressionService.decompress.mockResolvedValue(Buffer.from('decompressed-metadata'));

      const recoveryResult = await backupService.performRecovery({
        backupId: backupResult.id,
        type: 'complete',
        validateMetadataIntegrity: true
      });

      expect(recoveryResult.metadata.preservationValidation.passed).toBe(true);
      expect(recoveryResult.metadata.preservedEntitiesCount).toBe(originalMetadata.entities.length);
      expect(recoveryResult.metadata.preservedObservationsCount).toBe(originalMetadata.observations.length);
    });

    it('should handle large knowledge graphs efficiently', async () => {
      const largeGraph = {
        entityCount: 100000,
        relationCount: 250000,
        estimatedSize: 500 * 1024 * 1024 // 500MB
      };

      mockQdrantClient.knowledgeEntity.count.mockResolvedValue(largeGraph.entityCount);
      mockQdrantClient.knowledgeRelation.count.mockResolvedValue(largeGraph.relationCount);

      // Mock chunked data retrieval for large graphs
      const mockEntityChunks = Array.from({ length: 10 }, (_, i) =>
        Array.from({ length: 10000 }, (_, j) => ({
          id: `entity-${i}-${j}`,
          data: { chunk: i }
        }))
      );

      mockQdrantClient.knowledgeEntity.findMany.mockImplementation(({ take, skip }) => {
        const chunkIndex = Math.floor(skip / 10000);
        return Promise.resolve(mockEntityChunks[chunkIndex] || []);
      });

      const largeBackup = await backupService.createBackup({
        type: 'full',
        scope: { project: 'large-graph-test' },
        chunkSize: 10000,
        parallelProcessing: true,
        progressTracking: true
      });

      expect(largeBackup).toBeDefined();
      expect(largeBackup.metadata.entityCount).toBe(largeGraph.entityCount);
      expect(largeBackup.metadata.relationCount).toBe(largeGraph.relationCount);
      expect(largeBackup.metadata.processingChunks).toBe(10);
      expect(largeBackup.metadata.parallelProcessingUsed).toBe(true);
      expect(largeBackup.metadata.processingTime).toBeGreaterThan(0);
    });

    it('should validate relationship integrity during recovery', async () => {
      const relationshipsToValidate = [
        {
          id: 'rel-1',
          type: 'depends_on',
          sourceEntityId: 'entity-a',
          targetEntityId: 'entity-b'
        },
        {
          id: 'rel-2',
          type: 'implements',
          sourceEntityId: 'entity-a',
          targetEntityId: 'entity-c'
        }
      ];

      // Mock recovered entities
      const recoveredEntities = [
        { id: 'entity-a', data: { name: 'Entity A' } },
        { id: 'entity-b', data: { name: 'Entity B' } },
        { id: 'entity-c', data: { name: 'Entity C' } }
      ];

      mockQdrantClient.knowledgeRelation.findMany.mockResolvedValue(relationshipsToValidate);
      mockQdrantClient.knowledgeEntity.findMany.mockResolvedValue(recoveredEntities);

      const integrityValidation = await backupService.validateRelationshipIntegrity('recovery-backup-id');

      expect(integrityValidation).toBeDefined();
      expect(integrityValidation.totalRelations).toBe(relationshipsToValidate.length);
      expect(integrityValidation.validRelations).toBe(relationshipsToValidate.length);
      expect(integrityValidation.brokenRelations).toHaveLength(0);
      expect(integrityValidation.orphanedEntities).toHaveLength(0);
      expect(integrityValidation.passed).toBe(true);
    });

    it('should maintain scope isolation during backup and recovery', async () => {
      const scopes = [
        { project: 'project-a', org: 'org-1', branch: 'main' },
        { project: 'project-b', org: 'org-1', branch: 'develop' },
        { project: 'project-c', org: 'org-2', branch: 'main' }
      ];

      // Mock scoped data
      mockQdrantClient.knowledgeEntity.findMany.mockImplementation(({ where }) => {
        const scope = where.tags;
        const matchingProject = scopes.find(s => s.project === scope.project);
        return Promise.resolve(matchingProject ? [
          { id: `${scope.project}-entity-1`, tags: scope }
        ] : []);
      });

      const scopedBackups = await Promise.all(
        scopes.map(scope =>
          backupService.createBackup({
            type: 'full',
            scope,
            enforceScopeIsolation: true
          })
        )
      );

      scopedBackups.forEach((backup, index) => {
        expect(backup.scope).toEqual(scopes[index]);
        expect(backup.metadata.isolatedScope).toBe(true);
      });

      // Test recovery with scope enforcement
      for (let i = 0; i < scopedBackups.length; i++) {
        mockQdrantClient.backupMetadata.findUnique.mockResolvedValue(scopedBackups[i]);

        const recovery = await backupService.performRecovery({
          backupId: scopedBackups[i].id,
          type: 'complete',
          enforceScopeIsolation: true
        });

        expect(recovery.metadata.scopeEnforced).toBe(true);
        expect(recovery.metadata.recoveredScope).toEqual(scopes[i]);
      }
    });
  });

  // 7. Error Handling and Edge Cases Tests
  describe('Error Handling and Edge Cases', () => {
    it('should handle backup storage location failures', async () => {
      // Mock primary storage failure
      const primaryStorageFailure = new Error('Primary storage unavailable');
      mockFileSystem.existsSync.mockReturnValue(false);

      const backupOperation: BackupOperation = {
        type: 'full',
        scope: { project: 'storage-failure-test' },
        storageLocationId: 'primary',
        failoverToSecondary: true
      };

      // Mock successful failover to secondary storage
      mockFileSystem.existsSync.mockImplementationOnce(() => false) // Primary fails
        .mockImplementationOnce(() => true);  // Secondary succeeds

      const result = await backupService.createBackup(backupOperation);

      expect(result).toBeDefined();
      expect(result.status).toBe('completed');
      expect(result.metadata.failoverTriggered).toBe(true);
      expect(result.storageLocationId).toBe('secondary');
    });

    it('should handle encryption key rotation during active backups', async () => {
      // Mock backup in progress when key rotation occurs
      const activeBackup = {
        id: 'active-backup',
        type: 'full',
        status: 'in-progress',
        encryptionKeyId: 'old-key-123',
        startTime: new Date()
      };

      const keyRotationEvent = {
        keyId: 'new-key-456',
        rotationTime: new Date(),
        algorithm: 'AES-256-GCM'
      };

      mockQdrantClient.backupOperation.findUnique.mockResolvedValue(activeBackup);
      mockEncryptionService.reencrypt.mockResolvedValue(Buffer.from('reencrypted-data'));

      const rotationResult = await backupService.handleKeyRotationDuringBackup(
        activeBackup.id,
        keyRotationEvent
      );

      expect(rotationResult).toBeDefined();
      expect(rotationResult.backupId).toBe(activeBackup.id);
      expect(rotationResult.oldKeyId).toBe('old-key-123');
      expect(rotationResult.newKeyId).toBe('new-key-456');
      expect(rotationResult.status).toBe('completed');
    });

    it('should handle corrupted backup files during recovery', async () => {
      const corruptedBackup: BackupMetadata = {
        id: 'corrupted-backup',
        type: 'full',
        status: 'completed',
        metadata: {
          checksum: 'original-checksum',
          storageSize: 5000000
        }
      };

      mockQdrantClient.backupMetadata.findUnique.mockResolvedValue(corruptedBackup);
      mockFileSystem.existsSync.mockReturnValue(true);
      mockFileSystem.readFileSync.mockReturnValue(Buffer.from('corrupted-data'));
      mockEncryptionService.hashData.mockResolvedValue('corrupted-checksum'); // Different checksum

      const recoveryOperation: RecoveryOperation = {
        backupId: 'corrupted-backup',
        type: 'complete',
        validateBeforeRecovery: true
      };

      await expect(backupService.performRecovery(recoveryOperation)).rejects.toThrow('Backup validation failed');

      // Should attempt to find backup replicas
      expect(mockQdrantClient.backupMetadata.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            baseBackupId: corruptedBackup.id
          })
        })
      );
    });

    it('should handle concurrent backup and recovery conflicts', async () => {
      const ongoingBackup = {
        id: 'ongoing-backup',
        type: 'full',
        status: 'in-progress',
        scope: { project: 'conflict-test' },
        startTime: new Date()
      };

      mockQdrantClient.backupOperation.findUnique.mockResolvedValue(ongoingBackup);

      const conflictingRecovery: RecoveryOperation = {
        backupId: 'previous-backup',
        type: 'complete',
        scope: { project: 'conflict-test' }
      };

      await expect(backupService.performRecovery(conflictingRecovery)).rejects.toThrow('Cannot perform recovery while backup is in progress');

      // Should offer conflict resolution options
      const conflictResolution = await backupService.getConflictResolutionOptions('conflict-test');
      expect(conflictResolution.options).toContain('wait-for-backup');
      expect(conflictResolution.options).toContain('cancel-backup');
      expect(conflictResolution.options).toContain('schedule-recovery');
    });

    it('should handle partial backup failures gracefully', async () => {
      // Mock partial failure during backup
      let entityExtractionFailed = false;
      let relationExtractionSucceeded = false;

      mockQdrantClient.knowledgeEntity.findMany.mockImplementation(() => {
        if (!entityExtractionFailed) {
          entityExtractionFailed = true;
          return Promise.reject(new Error('Entity extraction failed'));
        }
        return Promise.resolve([]);
      });

      mockQdrantClient.knowledgeRelation.findMany.mockImplementation(() => {
        if (!relationExtractionSucceeded) {
          relationExtractionSucceeded = true;
          return Promise.resolve([{ id: 'rel-1', type: 'depends_on' }]);
        }
        return Promise.resolve([]);
      });

      const partialBackup: BackupOperation = {
        type: 'full',
        scope: { project: 'partial-failure-test' },
        allowPartialSuccess: true
      };

      const result = await backupService.createBackup(partialBackup);

      expect(result).toBeDefined();
      expect(result.status).toBe('completed_with_warnings');
      expect(result.metadata.errors).toContain('Entity extraction failed');
      expect(result.metadata.partialBackup).toBe(true);
      expect(result.metadata.successfulComponents).toContain('relations');
    });

    it('should handle extremely large backup metadata', async () => {
      const hugeMetadata = {
        entities: Array.from({ length: 1000000 }, (_, i) => ({
          id: `entity-${i}`,
          metadata: {
            description: `Entity ${i} description`.repeat(100),
            tags: Array.from({ length: 50 }, (_, j) => `tag-${j}`),
            customFields: Array.from({ length: 20 }, (_, k) => ({
              key: `field-${k}`,
              value: `value-${k}`.repeat(10)
            }))
          }
        }))
      };

      // Mock memory pressure during metadata processing
      const originalJSONStringify = JSON.stringify;
      JSON.stringify = vi.fn().mockImplementation((obj) => {
        if (obj === hugeMetadata.entities) {
          throw new Error('Stringify failed - object too large');
        }
        return originalJSONStringify(obj);
      });

      const backupOperation: BackupOperation = {
        type: 'full',
        scope: { project: 'huge-metadata-test' },
        chunkMetadata: true,
        compressionLevel: 'maximum'
      };

      const result = await backupService.createBackup(backupOperation);

      expect(result).toBeDefined();
      expect(result.metadata.chunked).toBe(true);
      expect(result.metadata.metadataChunks).toBeGreaterThan(1);

      // Restore original JSON.stringify
      JSON.stringify = originalJSONStringify;
    });
  });

  // 8. Integration and End-to-End Tests
  describe('Integration and End-to-End Tests', () => {
    it('should perform complete backup and recovery workflow', async () => {
      // Step 1: Create comprehensive backup
      const comprehensiveData = {
        entities: Array.from({ length: 100 }, (_, i) => ({
          id: `entity-${i}`,
          data: { name: `Entity ${i}`, type: 'component' },
          tags: { project: 'e2e-test', category: i % 2 === 0 ? 'primary' : 'secondary' }
        })),
        relations: Array.from({ length: 150 }, (_, i) => ({
          id: `relation-${i}`,
          type: ['depends_on', 'implements', 'relates_to'][i % 3],
          sourceEntityId: `entity-${i % 100}`,
          targetEntityId: `entity-${(i + 1) % 100}`
        })),
        observations: Array.from({ length: 200 }, (_, i) => ({
          id: `observation-${i}`,
          content: `Observation ${i} content`,
          kind: 'observation',
          tags: { verified: i % 3 === 0 }
        }))
      };

      mockQdrantClient.knowledgeEntity.findMany.mockResolvedValue(comprehensiveData.entities);
      mockQdrantClient.knowledgeRelation.findMany.mockResolvedValue(comprehensiveData.relations);
      mockQdrantClient.knowledgeObservation.findMany.mockResolvedValue(comprehensiveData.observations);
      mockQdrantClient.knowledgeEntity.count.mockResolvedValue(comprehensiveData.entities.length);
      mockQdrantClient.knowledgeRelation.count.mockResolvedValue(comprehensiveData.relations.length);
      mockQdrantClient.knowledgeObservation.count.mockResolvedValue(comprehensiveData.observations.length);

      mockFileSystem.existsSync.mockReturnValue(true);
      mockFileSystem.writeFileSync.mockReturnValue(undefined);
      mockCompressionService.compress.mockResolvedValue({
        compressedSize: 5000000,
        originalSize: 10000000,
        compressionRatio: 0.5
      });
      mockEncryptionService.encrypt.mockResolvedValue({
        encryptedData: Buffer.from('encrypted-backup'),
        iv: Buffer.from('backup-iv'),
        tag: Buffer.from('backup-tag')
      });

      const backupResult = await backupService.createBackup({
        type: 'full',
        scope: { project: 'e2e-test' },
        compressionEnabled: true,
        encryptionEnabled: true,
        validationEnabled: true
      });

      expect(backupResult.status).toBe('completed');
      expect(backupResult.metadata.totalEntities).toBe(comprehensiveData.entities.length);
      expect(backupResult.metadata.totalRelations).toBe(comprehensiveData.relations.length);
      expect(backupResult.metadata.totalObservations).toBe(comprehensiveData.observations.length);

      // Step 2: Simulate data loss
      mockQdrantClient.knowledgeEntity.findMany.mockResolvedValue([]);
      mockQdrantClient.knowledgeRelation.findMany.mockResolvedValue([]);
      mockQdrantClient.knowledgeObservation.findMany.mockResolvedValue([]);
      mockQdrantClient.knowledgeEntity.count.mockResolvedValue(0);
      mockQdrantClient.knowledgeRelation.count.mockResolvedValue(0);
      mockQdrantClient.knowledgeObservation.count.mockResolvedValue(0);

      // Step 3: Perform complete recovery
      mockQdrantClient.backupMetadata.findUnique.mockResolvedValue(backupResult);
      mockFileSystem.readFileSync.mockReturnValue(Buffer.from('backup-data'));
      mockEncryptionService.decrypt.mockResolvedValue(Buffer.from('decrypted-data'));
      mockCompressionService.decompress.mockResolvedValue(Buffer.from('decompressed-data'));

      // Mock successful restoration
      mockQdrantClient.knowledgeEntity.create.mockResolvedValue({ id: 'restored-entity' });
      mockQdrantClient.knowledgeRelation.create.mockResolvedValue({ id: 'restored-relation' });
      mockQdrantClient.knowledgeObservation.create.mockResolvedValue({ id: 'restored-observation' });

      const recoveryResult = await backupService.performRecovery({
        backupId: backupResult.id,
        type: 'complete',
        validateBeforeRecovery: true,
        validateAfterRecovery: true
      });

      expect(recoveryResult.status).toBe('completed');
      expect(recoveryResult.metadata.restoredEntities).toBe(comprehensiveData.entities.length);
      expect(recoveryResult.metadata.restoredRelations).toBe(comprehensiveData.relations.length);
      expect(recoveryResult.metadata.restoredObservations).toBe(comprehensiveData.observations.length);

      // Step 4: Validate complete recovery
      mockQdrantClient.knowledgeEntity.count.mockResolvedValue(comprehensiveData.entities.length);
      mockQdrantClient.knowledgeRelation.count.mockResolvedValue(comprehensiveData.relations.length);
      mockQdrantClient.knowledgeObservation.count.mockResolvedValue(comprehensiveData.observations.length);

      const validation = await backupService.validateRecovery(backupResult.id);
      expect(validation.isValid).toBe(true);
      expect(validation.entityCount).toBe(comprehensiveData.entities.length);
      expect(validation.relationCount).toBe(comprehensiveData.relations.length);
      expect(validation.observationCount).toBe(comprehensiveData.observations.length);
    });

    it('should handle disaster recovery scenario', async () => {
      // Simulate complete system failure with only backup metadata available
      const disasterScenario = {
        primaryBackup: {
          id: 'disaster-backup-primary',
          type: 'full',
          createdAt: new Date('2024-01-01'),
          storageLocationId: 'primary',
          status: 'completed',
          metadata: { totalEntities: 1000, totalRelations: 1500, totalObservations: 2000 }
        },
        secondaryBackup: {
          id: 'disaster-backup-secondary',
          type: 'full',
          createdAt: new Date('2024-01-01'),
          storageLocationId: 'secondary',
          status: 'completed',
          metadata: { totalEntities: 1000, totalRelations: 1500, totalObservations: 2000 }
        },
        incrementalChain: [
          {
            id: 'inc-1',
            type: 'incremental',
            createdAt: new Date('2024-01-02'),
            baseBackupId: 'disaster-backup-primary',
            metadata: { newEntities: 50, updatedEntities: 25 }
          },
          {
            id: 'inc-2',
            type: 'incremental',
            createdAt: new Date('2024-01-03'),
            baseBackupId: 'disaster-backup-primary',
            metadata: { newEntities: 30, updatedEntities: 15 }
          }
        ]
      };

      // Primary storage unavailable, secondary available
      mockQdrantClient.backupMetadata.findUnique
        .mockResolvedValueOnce(disasterScenario.primaryBackup) // Primary lookup
        .mockResolvedValueOnce(disasterScenario.secondaryBackup); // Secondary fallback

      mockQdrantClient.backupMetadata.findMany.mockResolvedValue([
        disasterScenario.secondaryBackup,
        ...disasterScenario.incrementalChain
      ]);

      mockFileSystem.existsSync.mockImplementation((path) => {
        return path.includes('secondary'); // Only secondary storage available
      });

      mockFileSystem.readFileSync.mockReturnValue(Buffer.from('disaster-recovery-data'));
      mockEncryptionService.decrypt.mockResolvedValue(Buffer.from('decrypted-disaster-data'));
      mockCompressionService.decompress.mockResolvedValue(Buffer.from('recovered-system-data'));

      const disasterRecovery = await backupService.performDisasterRecovery({
        scope: { project: 'disaster-recovery-test' },
        preferredLocation: 'secondary',
        allowCrossRegionRestore: true,
        validationLevel: 'comprehensive'
      });

      expect(disasterRecovery).toBeDefined();
      expect(disasterRecovery.status).toBe('completed');
      expect(disasterRecovery.primaryBackupUnavailable).toBe(true);
      expect(disasterRecovery.usedSecondaryBackup).toBe(true);
      expect(disasterRecovery.restoredFromIncrementalChain).toBe(true);
      expect(disasterRecovery.metadata.totalRestoredEntities).toBe(1080); // 1000 + 50 + 30
      expect(disasterRecovery.validation.comprehensive).toBe(true);
      expect(disasterRecovery.validation.integrityCheck).toBe(true);
    });

    it('should maintain backup consistency across multiple locations', async () => {
      const multiLocationConfig = {
        primary: { id: 'primary', region: 'us-east-1', endpoint: 'local' },
        secondary: { id: 'secondary', region: 'us-west-2', endpoint: 's3' },
        tertiary: { id: 'tertiary', region: 'eu-west-1', endpoint: 'azure' }
      };

      const backupId = 'multi-location-backup';

      // Create backup with multi-location replication
      mockQdrantClient.backupStorage.findMany.mockResolvedValue(
        Object.values(multiLocationConfig)
      );

      mockFileSystem.existsSync.mockReturnValue(true);
      mockFileSystem.writeFileSync.mockReturnValue(undefined);

      const multiLocationBackup = await backupService.createBackup({
        type: 'full',
        scope: { project: 'multi-location-test' },
        replicateToAllLocations: true,
        consistencyLevel: 'strong'
      });

      expect(multiLocationBackup).toBeDefined();
      expect(multiLocationBackup.replicationStatus).toHaveLength(3);
      multiLocationBackup.replicationStatus.forEach(status => {
        expect(status.status).toBe('completed');
        expect(status.replicatedAt).toBeInstanceOf(Date);
        expect(status.checksumMatch).toBe(true);
      });

      // Verify consistency across locations
      const consistencyCheck = await backupService.verifyMultiLocationConsistency(backupId);
      expect(consistencyCheck.isConsistent).toBe(true);
      expect(consistencyCheck.locationResults).toHaveLength(3);
      expect(consistencyCheck.inconsistencies).toHaveLength(0);
    });
  });

  // 9. Performance Benchmark Tests
  describe('Performance Benchmarks', () => {
    it('should meet performance targets for large backups', async () => {
      const performanceTargets = {
        maxBackupDurationMinutes: 60,
        minThroughputMBps: 50,
        maxCompressionOverheadPercent: 20,
        maxEncryptionOverheadPercent: 15
      };

      const largeDataset = {
        entityCount: 50000,
        relationCount: 75000,
        observationCount: 100000,
        estimatedSize: 2 * 1024 * 1024 * 1024 // 2GB
      };

      const startTime = Date.now();

      mockQdrantClient.knowledgeEntity.count.mockResolvedValue(largeDataset.entityCount);
      mockQdrantClient.knowledgeRelation.count.mockResolvedValue(largeDataset.relationCount);
      mockQdrantClient.knowledgeObservation.count.mockResolvedValue(largeDataset.observationCount);

      // Mock efficient chunked processing
      mockQdrantClient.knowledgeEntity.findMany.mockImplementation(({ take, skip }) => {
        const chunk = Array.from({ length: take }, (_, i) => ({
          id: `entity-${skip + i}`,
          data: { content: 'x'.repeat(1000) } // ~1KB per entity
        }));
        return Promise.resolve(chunk);
      });

      mockCompressionService.compress.mockResolvedValue({
        compressedSize: largeDataset.estimatedSize * 0.6, // 40% compression
        originalSize: largeDataset.estimatedSize,
        compressionRatio: 0.6
      });

      mockEncryptionService.encrypt.mockResolvedValue({
        encryptedData: Buffer.from('encrypted-large-data'),
        iv: Buffer.from('iv'),
        tag: Buffer.from('tag')
      });

      const performanceTestBackup = await backupService.createBackup({
        type: 'full',
        scope: { project: 'performance-test' },
        chunkSize: 5000,
        parallelProcessing: true,
        performanceMode: 'maximum'
      });

      const duration = Date.now() - startTime;
      const durationMinutes = duration / (1000 * 60);
      const throughputMBps = (largeDataset.estimatedSize / (1024 * 1024)) / (duration / 1000);

      expect(performanceTestBackup.status).toBe('completed');
      expect(durationMinutes).toBeLessThanOrEqual(performanceTargets.maxBackupDurationMinutes);
      expect(throughputMBps).toBeGreaterThanOrEqual(performanceTargets.minThroughputMBps);
      expect(performanceTestBackup.metadata.compressionOverheadPercent).toBeLessThanOrEqual(
        performanceTargets.maxCompressionOverheadPercent
      );
      expect(performanceTestBackup.metadata.encryptionOverheadPercent).toBeLessThanOrEqual(
        performanceTargets.maxEncryptionOverheadPercent
      );
    });

    it('should maintain performance under concurrent load', async () => {
      const concurrentBackups = 5;
      const backupSize = 100 * 1024 * 1024; // 100MB per backup

      const concurrentStartTime = Date.now();

      const concurrentPromises = Array.from({ length: concurrentBackups }, (_, i) =>
        backupService.createBackup({
          type: 'full',
          scope: { project: `concurrent-perf-${i}` },
          priority: 'normal'
        })
      );

      // Mock database for concurrent operations
      mockQdrantClient.knowledgeEntity.count.mockResolvedValue(1000);
      mockQdrantClient.knowledgeRelation.count.mockResolvedValue(1500);
      mockQdrantClient.knowledgeObservation.count.mockResolvedValue(2000);

      mockCompressionService.compress.mockResolvedValue({
        compressedSize: backupSize * 0.7,
        originalSize: backupSize,
        compressionRatio: 0.7
      });

      const concurrentResults = await Promise.all(concurrentPromises);
      const concurrentDuration = Date.now() - concurrentStartTime;

      expect(concurrentResults).toHaveLength(concurrentBackups);
      concurrentResults.forEach((result, index) => {
        expect(result.status).toBe('completed');
        expect(result.scope.project).toBe(`concurrent-perf-${index}`);
      });

      // Concurrent operations should complete in reasonable time
      const expectedMaxDuration = (backupSize / (1024 * 1024)) / 20 * 1000 * concurrentBackups; // 20 MB/sec baseline
      expect(concurrentDuration).toBeLessThan(expectedMaxDuration * 1.5); // Allow 50% overhead for concurrency

      // System should remain responsive
      const systemLoad = await backupService.getSystemLoad();
      expect(systemLoad.cpuUsage).toBeLessThan(0.9); // Less than 90% CPU
      expect(systemLoad.memoryUsage).toBeLessThan(0.8); // Less than 80% memory
    });
  });

  // 10. Configuration and Management Tests
  describe('Configuration and Management', () => {
    it('should accept and validate custom backup configuration', () => {
      const customConfig: BackupConfig = {
        storageLocations: [
          {
            id: 'custom-primary',
            type: 'local',
            path: '/custom/backups',
            isDefault: true,
            encryptionEnabled: true,
            compressionEnabled: true,
            retentionDays: 60,
            maxStorageGB: 2000
          }
        ],
        schedules: [
          {
            id: 'custom-weekly',
            type: 'full',
            frequency: 'weekly',
            time: '01:00',
            enabled: true,
            retentionDays: 90,
            compressionLevel: 'high'
          }
        ],
        encryption: {
          enabled: true,
          algorithm: 'AES-256-GCM',
          keyRotationDays: 120,
          keyDerivationIterations: 200000
        },
        compression: {
          enabled: true,
          algorithm: 'lz4',
          level: 'high',
          thresholdMB: 50
        },
        validation: {
          enabled: true,
          checksumAlgorithm: 'sha512',
          integrityCheck: true,
          testRecovery: true
        },
        performance: {
          maxConcurrentOperations: 5,
          throttleRateMBps: 200,
          timeoutMinutes: 180,
          retryAttempts: 5
        },
        monitoring: {
          enabled: true,
          alertThresholds: {
            failureRate: 0.02,
            durationMinutes: 45,
            storageUsage: 0.75
          }
        }
      };

      expect(() => new BackupService(customConfig)).not.toThrow();

      const service = new BackupService(customConfig);
      const config = service.getConfig();

      expect(config.storageLocations).toHaveLength(1);
      expect(config.storageLocations[0].retentionDays).toBe(60);
      expect(config.encryption.keyDerivationIterations).toBe(200000);
      expect(config.compression.algorithm).toBe('lz4');
      expect(config.validation.checksumAlgorithm).toBe('sha512');
      expect(config.performance.maxConcurrentOperations).toBe(5);
      expect(config.monitoring.alertThresholds.failureRate).toBe(0.02);
    });

    it('should update configuration dynamically', () => {
      const service = new BackupService(defaultConfig);
      const initialConfig = service.getConfig();

      const configUpdates = {
        encryption: {
          ...initialConfig.encryption,
          keyRotationDays: 180
        },
        performance: {
          ...initialConfig.performance,
          maxConcurrentOperations: 8
        },
        monitoring: {
          ...initialConfig.monitoring,
          alertThresholds: {
            ...initialConfig.monitoring.alertThresholds,
            storageUsage: 0.9
          }
        }
      };

      service.updateConfig(configUpdates);

      const updatedConfig = service.getConfig();
      expect(updatedConfig.encryption.keyRotationDays).toBe(180);
      expect(updatedConfig.performance.maxConcurrentOperations).toBe(8);
      expect(updatedConfig.monitoring.alertThresholds.storageUsage).toBe(0.9);

      // Other settings should remain unchanged
      expect(updatedConfig.storageLocations).toEqual(initialConfig.storageLocations);
      expect(updatedConfig.compression).toEqual(initialConfig.compression);
    });

    it('should export and import backup configurations', async () => {
      const service = new BackupService(defaultConfig);

      const exportedConfig = await service.exportConfiguration();
      expect(exportedConfig).toBeDefined();
      expect(exportedConfig.version).toBeDefined();
      expect(exportedConfig.exportedAt).toBeInstanceOf(Date);
      expect(exportedConfig.config).toEqual(defaultConfig);

      // Import configuration
      const newService = new BackupService();
      await newService.importConfiguration(exportedConfig);

      const importedConfig = newService.getConfig();
      expect(importedConfig).toEqual(defaultConfig);
    });

    it('should validate configuration changes', () => {
      const service = new BackupService(defaultConfig);

      // Valid configuration change
      const validChange = {
        performance: {
          maxConcurrentOperations: 10,
          throttleRateMBps: 150
        }
      };

      const validationResult = service.validateConfigChange(validChange);
      expect(validationResult.isValid).toBe(true);
      expect(validationResult.errors).toHaveLength(0);

      // Invalid configuration change
      const invalidChange = {
        performance: {
          maxConcurrentOperations: -1, // Invalid negative value
          throttleRateMBps: 0 // Invalid zero value
        },
        encryption: {
          algorithm: 'INVALID-ALGORITHM' // Unsupported algorithm
        }
      };

      const invalidValidationResult = service.validateConfigChange(invalidChange);
      expect(invalidValidationResult.isValid).toBe(false);
      expect(invalidValidationResult.errors.length).toBeGreaterThan(0);
      expect(invalidValidationResult.errors.some(e =>
        e.includes('maxConcurrentOperations') && e.includes('positive')
      )).toBe(true);
      expect(invalidValidationResult.errors.some(e =>
        e.includes('algorithm') && e.includes('supported')
      )).toBe(true);
    });
  });
});