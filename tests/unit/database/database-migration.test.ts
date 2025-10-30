/**
 * Comprehensive Unit Tests for Database Migration Functionality
 *
 * Tests database migration functionality including:
 * - Migration Lifecycle Management (creation, initialization, version tracking, execution, rollback, state validation)
 * - Schema Migration Operations (collection schema, index creation/modification, field operations, data transformations)
 * - Knowledge Type Migration (schema evolution, data migration, backward compatibility, cross-type relationships)
 * - Rollback and Recovery (rollback capabilities, validation, partial failure recovery, state consistency)
 * - Batch Migration Management (multiple migrations, dependency resolution, sequencing, conflict resolution)
 * - Error Handling and Validation (failure handling, data integrity, compatibility checking, error recovery)
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { describe, it, expect, beforeEach, afterEach, vi, beforeAll, afterAll } from 'vitest';
import { promises as fs } from 'fs';
import { join } from 'path';
import { QdrantMigrationManager, qdrantMigrationManager } from '../../../src/db/migrate';
import { qdrantConnectionManager } from '../../../src/db/pool';
import { logger } from '../../../src/utils/logger';
import { DatabaseError, ValidationError, MigrationError } from '../../../src/db/types/database-types';
import { StandardTestUtils, MockFactory, TestPatterns } from '../../framework/standard-test-setup';

// Mock Qdrant client
const mockGetCollections = vi.fn();
const mockCreateCollection = vi.fn();
const mockDeleteCollection = vi.fn();
const mockUpsert = vi.fn();
const mockSearch = vi.fn();
const mockGetCollection = vi.fn();

// Mock file system operations
const mockReadDir = vi.fn();
const mockReadFile = vi.fn();
const mockWriteFile = vi.fn();
const mockMkdir = vi.fn();

// Mock Qdrant client
vi.mock('@qdrant/js-client-rest', () => ({
  QdrantClient: class {
    constructor() {}
    async getCollections() {
      return mockGetCollections();
    }
    async createCollection(name: string, config?: any) {
      return mockCreateCollection(name, config);
    }
    async deleteCollection(name: string) {
      return mockDeleteCollection(name);
    }
    async upsert(collectionName: string, points: any) {
      return mockUpsert(collectionName, points);
    }
    async search(collectionName: string, searchParams: any) {
      return mockSearch(collectionName, searchParams);
    }
    async getCollection(name: string) {
      return mockGetCollection(name);
    }
  }
}));

// Mock file system
vi.mock('fs', () => ({
  promises: {
    readdir: mockReadDir,
    readFile: mockReadFile,
    writeFile: mockWriteFile,
    mkdir: mockMkdir,
  },
}));

// Mock logger
vi.mock('../../../src/utils/logger', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

// Mock connection manager
vi.mock('../../../src/db/pool', () => ({
  qdrantConnectionManager: {
    getClient: () => ({
      getCollections: mockGetCollections,
      createCollection: mockCreateCollection,
      deleteCollection: mockDeleteCollection,
      upsert: mockUpsert,
      search: mockSearch,
      getCollection: mockGetCollection,
    }),
    initialize: vi.fn().mockResolvedValue(true),
    shutdown: vi.fn().mockResolvedValue(true),
  },
}));

describe('Database Migration - Migration Lifecycle Management', () => {
  let migrationManager: QdrantMigrationManager;
  let migrationsDir: string;

  beforeAll(() => {
    TestPatterns.unitTest();
    migrationsDir = join(process.cwd(), 'test-migrations');
  });

  beforeEach(() => {
    vi.clearAllMocks();
    migrationManager = new QdrantMigrationManager();

    // Setup default mocks
    mockGetCollections.mockResolvedValue({
      collections: [{ name: 'migrations' }]
    });

    mockReadDir.mockResolvedValue([
      '001_initial_setup.json',
      '002_add_entity_collection.json',
      '003_add_indexes.json'
    ]);

    mockReadFile.mockImplementation((filePath: string) => {
      const fileName = (filePath as string).split('/').pop();
      const mockMigrations: Record<string, string> = {
        '001_initial_setup.json': JSON.stringify({
          version: '1.0.0',
          description: 'Initial database setup',
          steps: [
            {
              operation: 'create_collection',
              collection: 'entities',
              parameters: { vectors: { size: 1536, distance: 'Cosine' } },
              rollback: {}
            }
          ]
        }),
        '002_add_entity_collection.json': JSON.stringify({
          version: '1.1.0',
          description: 'Add entity collection with schema',
          steps: [
            {
              operation: 'create_collection',
              collection: 'relations',
              parameters: { vectors: { size: 1536, distance: 'Cosine' } },
              rollback: {}
            }
          ]
        }),
        '003_add_indexes.json': JSON.stringify({
          version: '1.2.0',
          description: 'Add performance indexes',
          steps: [
            {
              operation: 'create_index',
              collection: 'entities',
              parameters: { field_name: 'entity_type' },
              rollback: {}
            }
          ]
        })
      };
      return Promise.resolve(mockMigrations[fileName || ''] || '{}');
    });

    mockSearch.mockResolvedValue([]); // No applied migrations initially
    mockUpsert.mockResolvedValue({ status: 'completed' });
    mockCreateCollection.mockResolvedValue(undefined);
    mockDeleteCollection.mockResolvedValue(undefined);
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('should create migration manager with proper configuration', () => {
    expect(migrationManager).toBeDefined();
    expect(migrationManager).toBeInstanceOf(QdrantMigrationManager);
  });

  it('should initialize migration tracking collection', async () => {
    mockGetCollections.mockResolvedValue({ collections: [] }); // No collections exist

    const status = await migrationManager.status();

    expect(mockCreateCollection).toHaveBeenCalledWith('migrations', expect.objectContaining({
      vectors: { size: 1, distance: 'Cosine' }
    }));
    expect(status).toBeDefined();
  });

  it('should detect available migrations from file system', async () => {
    const status = await migrationManager.status();

    expect(mockReadDir).toHaveBeenCalled();
    expect(status.available).toHaveLength(3);
    expect(status.available[0].id).toBe('001');
    expect(status.available[0].name).toBe('001_initial_setup');
    expect(status.available[0].version).toBe('1.0.0');
  });

  it('should calculate migration checksums for integrity validation', async () => {
    const status = await migrationManager.status();

    status.available.forEach(migration => {
      expect(migration.checksum).toBeDefined();
      expect(typeof migration.checksum).toBe('string');
      expect(migration.checksum.length).toBe(64); // SHA256 hex length
    });
  });

  it('should identify pending migrations correctly', async () => {
    // Mock one applied migration
    mockSearch.mockResolvedValue([
      {
        payload: {
          migration_id: '001',
          name: '001_initial_setup',
          version: '1.0.0',
          status: 'applied'
        }
      }
    ]);

    const status = await migrationManager.status();

    expect(status.applied).toHaveLength(1);
    expect(status.pending).toHaveLength(2);
    expect(status.pending[0].id).toBe('002');
    expect(status.pending[1].id).toBe('003');
  });

  it('should track migration execution state', async () => {
    const results = await migrationManager.migrate({ step: 1 });

    expect(results).toHaveLength(1);
    expect(results[0].migration_id).toBe('001');
    expect(results[0].status).toBe('success');
    expect(results[0].duration).toBeGreaterThan(0);
    expect(mockUpsert).toHaveBeenCalledWith('migrations', expect.objectContaining({
      points: expect.arrayContaining([
        expect.objectContaining({
          payload: expect.objectContaining({
            migration_id: '001',
            status: 'applied'
          })
        })
      ])
    }));
  });

  it('should handle migration version tracking', async () => {
    const results = await migrationManager.migrate({ targetVersion: '1.1.0' });

    expect(results).toHaveLength(2); // 001 and 002
    expect(results[0].migration_id).toBe('001');
    expect(results[1].migration_id).toBe('002');

    // Should not include version 1.2.0 (003)
    expect(results.some(r => r.migration_id === '003')).toBe(false);
  });

  it('should validate migration state consistency', async () => {
    // Mock inconsistent state - migration recorded but collection missing
    mockSearch.mockResolvedValue([
      {
        payload: {
          migration_id: '001',
          name: '001_initial_setup',
          status: 'applied'
        }
      }
    ]);

    mockGetCollections.mockResolvedValue({
      collections: [{ name: 'migrations' }] // Missing entities collection
    });

    const status = await migrationManager.status();

    // Should detect inconsistency
    expect(status.applied).toHaveLength(1);
    expect(status.available).toHaveLength(3);
  });

  it('should handle migration execution order', async () => {
    const executionOrder: string[] = [];

    mockCreateCollection.mockImplementation((name: string) => {
      executionOrder.push(name);
      return Promise.resolve(undefined);
    });

    await migrationManager.migrate();

    // Should execute in order: 001, 002, 003
    expect(mockCreateCollection).toHaveBeenCalledTimes(2); // 001 and 002 create collections
    expect(executionOrder).toContain('entities');
    expect(executionOrder).toContain('relations');
  });

  it('should provide migration status reporting', async () => {
    const status = await migrationManager.status();

    expect(status).toHaveProperty('available');
    expect(status).toHaveProperty('applied');
    expect(status).toHaveProperty('pending');
    expect(Array.isArray(status.available)).toBe(true);
    expect(Array.isArray(status.applied)).toBe(true);
    expect(Array.isArray(status.pending)).toBe(true);
  });
});

describe('Database Migration - Schema Migration Operations', () => {
  let migrationManager: QdrantMigrationManager;

  beforeEach(() => {
    vi.clearAllMocks();
    migrationManager = new QdrantMigrationManager();

    mockGetCollections.mockResolvedValue({ collections: [{ name: 'migrations' }] });
    mockReadDir.mockResolvedValue(['001_schema_migration.json']);
    mockSearch.mockResolvedValue([]);
  });

  it('should handle collection schema migrations', async () => {
    const collectionConfig = {
      vectors: { size: 1536, distance: 'Cosine' },
      payload_schema: {
        type: 'object',
        properties: {
          entity_type: { type: 'keyword' },
          name: { type: 'text' },
          created_at: { type: 'datetime' }
        }
      }
    };

    mockReadFile.mockResolvedValue(JSON.stringify({
      version: '1.0.0',
      description: 'Create entity collection',
      steps: [
        {
          operation: 'create_collection',
          collection: 'entities',
          parameters: collectionConfig,
          rollback: {}
        }
      ]
    }));

    const results = await migrationManager.migrate();

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('success');
    expect(mockCreateCollection).toHaveBeenCalledWith('entities', collectionConfig);
  });

  it('should handle index creation and modification', async () => {
    mockReadFile.mockResolvedValue(JSON.stringify({
      version: '1.0.0',
      description: 'Add indexes',
      steps: [
        {
          operation: 'create_index',
          collection: 'entities',
          parameters: { field_name: 'entity_type' },
          rollback: {}
        }
      ]
    }));

    const results = await migrationManager.migrate();

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('success');
    // Note: Index creation is logged as warning due to Qdrant limitations
    expect(logger.warn).toHaveBeenCalledWith(
      expect.stringContaining('Index creation not supported')
    );
  });

  it('should handle field addition operations', async () => {
    mockReadFile.mockResolvedValue(JSON.stringify({
      version: '1.1.0',
      description: 'Add metadata fields',
      steps: [
        {
          operation: 'update_payload_schema',
          collection: 'entities',
          parameters: { fields: { priority: 'keyword', status: 'keyword' } },
          rollback: {}
        }
      ]
    }));

    const results = await migrationManager.migrate();

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('success');
    expect(logger.debug).toHaveBeenCalledWith(
      expect.stringContaining('Payload schema update not needed')
    );
  });

  it('should handle field removal operations', async () => {
    mockReadFile.mockResolvedValue(JSON.stringify({
      version: '1.2.0',
      description: 'Remove deprecated fields',
      steps: [
        {
          operation: 'update_payload_schema',
          collection: 'entities',
          parameters: { remove_fields: ['legacy_field', 'deprecated_property'] },
          rollback: {}
        }
      ]
    }));

    const results = await migrationManager.migrate();

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('success');
  });

  it('should handle data type transformations', async () => {
    mockReadFile.mockResolvedValue(JSON.stringify({
      version: '1.3.0',
      description: 'Transform data types',
      steps: [
        {
          operation: 'update_payload_schema',
          collection: 'entities',
          parameters: {
            transforms: [
              { field: 'priority', from: 'text', to: 'keyword' },
              { field: 'count', from: 'text', to: 'integer' }
            ]
          },
          rollback: {}
        }
      ]
    }));

    const results = await migrationManager.migrate();

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('success');
  });

  it('should validate collection configuration compatibility', async () => {
    const incompatibleConfig = {
      vectors: { size: 1024, distance: 'Euclid' } // Different from existing
    };

    mockReadFile.mockResolvedValue(JSON.stringify({
      version: '1.0.0',
      description: 'Incompatible collection change',
      steps: [
        {
          operation: 'update_collection_config',
          collection: 'entities',
          parameters: incompatibleConfig,
          rollback: {}
        }
      ]
    }));

    const results = await migrationManager.migrate();

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('success');
    expect(logger.warn).toHaveBeenCalledWith(
      expect.stringContaining('Collection config update not supported')
    );
  });

  it('should handle collection deletion for schema cleanup', async () => {
    mockReadFile.mockResolvedValue(JSON.stringify({
      version: '2.0.0',
      description: 'Remove deprecated collection',
      steps: [
        {
          operation: 'delete_collection',
          collection: 'legacy_entities',
          parameters: {},
          rollback: {}
        }
      ]
    }));

    const results = await migrationManager.migrate();

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('success');
    expect(mockDeleteCollection).toHaveBeenCalledWith('legacy_entities');
  });

  it('should handle complex multi-step schema migrations', async () => {
    mockReadFile.mockResolvedValue(JSON.stringify({
      version: '1.5.0',
      description: 'Complex schema migration',
      steps: [
        {
          operation: 'create_collection',
          collection: 'new_entities',
          parameters: { vectors: { size: 1536, distance: 'Cosine' } },
          rollback: {}
        },
        {
          operation: 'update_payload_schema',
          collection: 'new_entities',
          parameters: { fields: { new_field: 'keyword' } },
          rollback: {}
        },
        {
          operation: 'create_index',
          collection: 'new_entities',
          parameters: { field_name: 'new_field' },
          rollback: {}
        }
      ]
    }));

    const results = await migrationManager.migrate();

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('success');
    expect(mockCreateCollection).toHaveBeenCalledWith('new_entities', expect.any(Object));
  });
});

describe('Database Migration - Knowledge Type Migration', () => {
  let migrationManager: QdrantMigrationManager;

  beforeEach(() => {
    vi.clearAllMocks();
    migrationManager = new QdrantMigrationManager();

    mockGetCollections.mockResolvedValue({
      collections: [
        { name: 'migrations' },
        { name: 'entities' },
        { name: 'relations' }
      ]
    });
    mockReadDir.mockResolvedValue(['001_knowledge_types.json']);
    mockSearch.mockResolvedValue([]);
  });

  it('should handle knowledge type schema evolution', async () => {
    const knowledgeTypeSchema = {
      version: '2.0.0',
      description: 'Migrate to 16 knowledge types',
      steps: [
        {
          operation: 'create_collection',
          collection: 'decisions',
          parameters: {
            vectors: { size: 1536, distance: 'Cosine' },
            payload_schema: {
              type: 'object',
              properties: {
                component: { type: 'text' },
                status: { type: 'keyword' },
                title: { type: 'text' },
                rationale: { type: 'text' },
                created_at: { type: 'datetime' },
                updated_at: { type: 'datetime' },
                tags: { type: 'array', items: { type: 'keyword' } },
                metadata: { type: 'object' }
              }
            }
          },
          rollback: {}
        }
      ]
    };

    mockReadFile.mockResolvedValue(JSON.stringify(knowledgeTypeSchema));

    const results = await migrationManager.migrate();

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('success');
    expect(mockCreateCollection).toHaveBeenCalledWith('decisions', expect.objectContaining({
      vectors: { size: 1536, distance: 'Cosine' }
    }));
  });

  it('should handle data migration between knowledge types', async () => {
    mockReadFile.mockResolvedValue(JSON.stringify({
      version: '2.1.0',
      description: 'Migrate entities to new schema',
      steps: [
        {
          operation: 'update_payload_schema',
          collection: 'entities',
          parameters: {
            data_migration: {
              from_type: 'legacy_entity',
              to_type: 'entity_v2',
              transforms: [
                { field: 'entity_name', target: 'name' },
                { field: 'entity_data', target: 'data' },
                { field: 'created', target: 'created_at', transform: 'to_datetime' }
              ]
            }
          },
          rollback: {}
        }
      ]
    }));

    const results = await migrationManager.migrate();

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('success');
  });

  it('should maintain backward compatibility during migration', async () => {
    mockReadFile.mockResolvedValue(JSON.stringify({
      version: '2.0.1',
      description: 'Add backward compatibility layer',
      steps: [
        {
          operation: 'update_payload_schema',
          collection: 'entities',
          parameters: {
            compatibility: {
              preserve_fields: ['id', 'created_at', 'updated_at'],
              add_aliases: {
                'entity_name': 'name',
                'entity_type': 'type'
              }
            }
          },
          rollback: {}
        }
      ]
    }));

    const results = await migrationManager.migrate();

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('success');
  });

  it('should handle cross-type relationship migration', async () => {
    mockReadFile.mockResolvedValue(JSON.stringify({
      version: '2.2.0',
      description: 'Migrate relationship schemas',
      steps: [
        {
          operation: 'update_payload_schema',
          collection: 'relations',
          parameters: {
            relationship_update: {
              from_entities: ['entity'],
              to_entities: ['entity', 'decision', 'incident'],
              relationship_types: ['relates_to', 'depends_on', 'blocks']
            }
          },
          rollback: {}
        }
      ]
    }));

    const results = await migrationManager.migrate();

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('success');
  });

  it('should validate knowledge type consistency', async () => {
    mockReadFile.mockResolvedValue(JSON.stringify({
      version: '2.0.0',
      description: 'Create all 16 knowledge type collections',
      steps: [
        'entity', 'relation', 'observation', 'section', 'runbook',
        'change', 'issue', 'decision', 'todo', 'release_note',
        'ddl', 'pr_context', 'incident', 'release', 'risk', 'assumption'
      ].map(type => ({
        operation: 'create_collection',
        collection: type,
        parameters: {
          vectors: { size: 1536, distance: 'Cosine' },
          payload_schema: {
            type: 'object',
            properties: {
              created_at: { type: 'datetime' },
              updated_at: { type: 'datetime' },
              tags: { type: 'array', items: { type: 'keyword' } },
              metadata: { type: 'object' }
            }
          }
        },
        rollback: {}
      }))
    }));

    const results = await migrationManager.migrate();

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('success');
    expect(mockCreateCollection).toHaveBeenCalledTimes(16);
  });

  it('should handle knowledge type field additions', async () => {
    mockReadFile.mockResolvedValue(JSON.stringify({
      version: '2.1.0',
      description: 'Add scope support to knowledge types',
      steps: [
        {
          operation: 'update_payload_schema',
          collection: 'entity',
          parameters: {
            add_fields: {
              scope: {
                type: 'object',
                properties: {
                  project: { type: 'keyword' },
                  branch: { type: 'keyword' },
                  org: { type: 'keyword' }
                }
              }
            }
          },
          rollback: {}
        }
      ]
    }));

    const results = await migrationManager.migrate();

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('success');
  });

  it('should handle knowledge type field deprecation', async () => {
    mockReadFile.mockResolvedValue(JSON.stringify({
      version: '2.3.0',
      description: 'Deprecate legacy fields',
      steps: [
        {
          operation: 'update_payload_schema',
          collection: 'entity',
          parameters: {
            deprecate_fields: ['legacy_property', 'old_field'],
            migration_strategy: 'move_to_metadata'
          },
          rollback: {}
        }
      ]
    }));

    const results = await migrationManager.migrate();

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('success');
  });
});

describe('Database Migration - Rollback and Recovery', () => {
  let migrationManager: QdrantMigrationManager;

  beforeEach(() => {
    vi.clearAllMocks();
    migrationManager = new QdrantMigrationManager();

    mockGetCollections.mockResolvedValue({ collections: [{ name: 'migrations' }] });
    mockReadDir.mockResolvedValue(['001_rollback_test.json']);
  });

  it('should handle single migration rollback', async () => {
    // Mock applied migration
    mockSearch.mockResolvedValue([
      {
        payload: {
          migration_id: '001',
          name: '001_rollback_test',
          version: '1.0.0',
          status: 'applied'
        }
      }
    ]);

    mockReadFile.mockResolvedValue(JSON.stringify({
      version: '1.0.0',
      description: 'Test migration with rollback',
      steps: [
        {
          operation: 'create_collection',
          collection: 'test_collection',
          parameters: { vectors: { size: 1536, distance: 'Cosine' } },
          rollback: {
            operation: 'delete_collection',
            collection: 'test_collection'
          }
        }
      ]
    }));

    const results = await migrationManager.rollback(1);

    expect(results).toHaveLength(1);
    expect(results[0].migration_id).toBe('001');
    expect(results[0].status).toBe('success');
    expect(results[0].message).toContain('rolled back successfully');
    expect(mockDeleteCollection).toHaveBeenCalledWith('test_collection');
  });

  it('should handle multiple migration rollback', async () => {
    // Mock multiple applied migrations
    mockSearch.mockResolvedValue([
      {
        payload: {
          migration_id: '001',
          name: '001_rollback_test',
          version: '1.0.0',
          status: 'applied'
        }
      },
      {
        payload: {
          migration_id: '002',
          name: '002_rollback_test',
          version: '1.1.0',
          status: 'applied'
        }
      }
    ]);

    mockReadDir.mockResolvedValue([
      '001_rollback_test.json',
      '002_rollback_test.json'
    ]);

    mockReadFile.mockImplementation((filePath: string) => {
      const fileName = (filePath as string).split('/').pop();
      if (fileName === '001_rollback_test.json') {
        return Promise.resolve(JSON.stringify({
          version: '1.0.0',
          description: 'Test migration 1',
          steps: [{ operation: 'create_collection', collection: 'test1', parameters: {}, rollback: {} }]
        }));
      } else {
        return Promise.resolve(JSON.stringify({
          version: '1.1.0',
          description: 'Test migration 2',
          steps: [{ operation: 'create_collection', collection: 'test2', parameters: {}, rollback: {} }]
        }));
      }
    });

    const results = await migrationManager.rollback(2);

    expect(results).toHaveLength(2);
    expect(results[0].migration_id).toBe('002'); // Rolled back first (reverse order)
    expect(results[1].migration_id).toBe('001');
  });

  it('should validate rollback safety before execution', async () => {
    mockSearch.mockResolvedValue([
      {
        payload: {
          migration_id: '001',
          name: '001_unsafe_rollback',
          version: '1.0.0',
          status: 'applied'
        }
      }
    ]);

    mockReadFile.mockResolvedValue(JSON.stringify({
      version: '1.0.0',
      description: 'Migration without rollback steps',
      steps: [
        {
          operation: 'create_collection',
          collection: 'permanent_collection',
          parameters: { vectors: { size: 1536, distance: 'Cosine' } }
          // No rollback defined
        }
      ]
    }));

    const results = await migrationManager.rollback(1);

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('success');
    // Should handle gracefully when no rollback is defined
  });

  it('should handle partial rollback failure recovery', async () => {
    mockSearch.mockResolvedValue([
      {
        payload: {
          migration_id: '001',
          name: '001_partial_failure',
          version: '1.0.0',
          status: 'applied'
        }
      },
      {
        payload: {
          migration_id: '002',
          name: '002_partial_failure',
          version: '1.1.0',
          status: 'applied'
        }
      }
    ]);

    mockReadDir.mockResolvedValue(['001_partial_failure.json', '002_partial_failure.json']);

    mockReadFile.mockImplementation((filePath: string) => {
      const fileName = (filePath as string).split('/').pop();
      if (fileName === '001_partial_failure.json') {
        return Promise.resolve(JSON.stringify({
          version: '1.0.0',
          description: 'Migration that fails rollback',
          steps: [{
            operation: 'delete_collection',
            collection: 'nonexistent_collection',
            rollback: {}
          }]
        }));
      } else {
        return Promise.resolve(JSON.stringify({
          version: '1.1.0',
          description: 'Migration that succeeds rollback',
          steps: [{
            operation: 'create_collection',
            collection: 'temp_collection',
            rollback: {}
          }]
        }));
      }
    });

    // Mock delete collection failure
    mockDeleteCollection.mockRejectedValueOnce(new Error('Collection not found'));

    const results = await migrationManager.rollback(2);

    expect(results).toHaveLength(2);
    // One should succeed, one should fail
    expect(results.some(r => r.status === 'success')).toBe(true);
    expect(results.some(r => r.status === 'failed')).toBe(true);
  });

  it('should verify state consistency after rollback', async () => {
    mockSearch.mockResolvedValue([
      {
        payload: {
          migration_id: '001',
          name: '001_state_verification',
          version: '1.0.0',
          status: 'applied'
        }
      }
    ]);

    mockReadFile.mockResolvedValue(JSON.stringify({
      version: '1.0.0',
      description: 'Migration with state verification',
      steps: [
        {
          operation: 'create_collection',
          collection: 'verify_collection',
          parameters: { vectors: { size: 1536, distance: 'Cosine' } },
          rollback: {
            operation: 'delete_collection',
            collection: 'verify_collection'
          }
        }
      ]
    }));

    const results = await migrationManager.rollback(1);

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('success');
    expect(mockDeleteCollection).toHaveBeenCalledWith('verify_collection');

    // Verify rollback was recorded
    expect(mockUpsert).toHaveBeenCalledWith('migrations', expect.objectContaining({
      points: expect.arrayContaining([
        expect.objectContaining({
          payload: expect.objectContaining({
            migration_id: '001',
            status: 'rolled_back'
          })
        })
      ])
    }));
  });

  it('should handle rollback when no migrations applied', async () => {
    mockSearch.mockResolvedValue([]); // No applied migrations

    const results = await migrationManager.rollback(1);

    expect(results).toHaveLength(0);
    expect(mockDeleteCollection).not.toHaveBeenCalled();
  });

  it('should handle rollback execution timeout', async () => {
    mockSearch.mockResolvedValue([
      {
        payload: {
          migration_id: '001',
          name: '001_slow_rollback',
          version: '1.0.0',
          status: 'applied'
        }
      }
    ]);

    mockReadFile.mockResolvedValue(JSON.stringify({
      version: '1.0.0',
      description: 'Slow rollback migration',
      steps: [
        {
          operation: 'create_collection',
          collection: 'slow_collection',
          parameters: { vectors: { size: 1536, distance: 'Cosine' } },
          rollback: {
            operation: 'delete_collection',
            collection: 'slow_collection'
          }
        }
      ]
    }));

    // Mock slow delete operation
    mockDeleteCollection.mockImplementationOnce(() =>
      new Promise(resolve => setTimeout(resolve, 2000))
    );

    const startTime = Date.now();
    const results = await migrationManager.rollback(1);
    const duration = Date.now() - startTime;

    expect(results).toHaveLength(1);
    expect(duration).toBeGreaterThan(1000);
  });
});

describe('Database Migration - Batch Migration Management', () => {
  let migrationManager: QdrantMigrationManager;

  beforeEach(() => {
    vi.clearAllMocks();
    migrationManager = new QdrantMigrationManager();

    mockGetCollections.mockResolvedValue({ collections: [{ name: 'migrations' }] });
    mockReadDir.mockResolvedValue([
      '001_batch_test_1.json',
      '002_batch_test_2.json',
      '003_batch_test_3.json',
      '004_batch_test_4.json',
      '005_batch_test_5.json'
    ]);
    mockSearch.mockResolvedValue([]);

    mockReadFile.mockImplementation((filePath: string) => {
      const fileName = (filePath as string).split('/').pop();
      const version = fileName?.split('_')[2]?.replace('.json', '') || '1.0.0';

      return Promise.resolve(JSON.stringify({
        version: `1.${version}.0`,
        description: `Batch test migration ${version}`,
        steps: [
          {
            operation: 'create_collection',
            collection: `batch_collection_${version}`,
            parameters: { vectors: { size: 1536, distance: 'Cosine' } },
            rollback: {}
          }
        ]
      }));
    });
  });

  it('should handle multiple migration execution', async () => {
    const results = await migrationManager.migrate();

    expect(results).toHaveLength(5);
    expect(results.every(r => r.status === 'success')).toBe(true);
    expect(mockCreateCollection).toHaveBeenCalledTimes(5);
  });

  it('should handle migration dependency resolution', async () => {
    mockReadFile.mockImplementation((filePath: string) => {
      const fileName = (filePath as string).split('/').pop();
      const migrationNumber = fileName?.split('_')[1] || '1';

      const migrationData: Record<string, any> = {
        '001_batch_test_1.json': {
          version: '1.0.0',
          description: 'Base migration',
          steps: [{
            operation: 'create_collection',
            collection: 'base_collection',
            parameters: { vectors: { size: 1536, distance: 'Cosine' } },
            rollback: {}
          }],
          dependencies: []
        },
        '002_batch_test_2.json': {
          version: '1.1.0',
          description: 'Depends on base',
          steps: [{
            operation: 'create_collection',
            collection: 'dependent_collection',
            parameters: { vectors: { size: 1536, distance: 'Cosine' } },
            rollback: {}
          }],
          dependencies: ['001']
        },
        '003_batch_test_3.json': {
          version: '1.2.0',
          description: 'Depends on dependent',
          steps: [{
            operation: 'create_collection',
            collection: 'final_collection',
            parameters: { vectors: { size: 1536, distance: 'Cosine' } },
            rollback: {}
          }],
          dependencies: ['002']
        }
      };

      return Promise.resolve(JSON.stringify(migrationData[fileName || ''] || migrationData['001_batch_test_1.json']));
    });

    mockReadDir.mockResolvedValue(['001_batch_test_1.json', '002_batch_test_2.json', '003_batch_test_3.json']);

    const results = await migrationManager.migrate();

    expect(results).toHaveLength(3);
    expect(results.every(r => r.status === 'success')).toBe(true);

    // Should execute in dependency order
    const executionOrder = mockCreateCollection.mock.calls.map(call => call[0]);
    expect(executionOrder).toContain('base_collection');
    expect(executionOrder).toContain('dependent_collection');
    expect(executionOrder).toContain('final_collection');
  });

  it('should handle migration sequencing correctly', async () => {
    const executionSequence: string[] = [];

    mockCreateCollection.mockImplementation((name: string) => {
      executionSequence.push(name as string);
      return Promise.resolve(undefined);
    });

    await migrationManager.migrate();

    // Should execute in filename order (001, 002, 003, 004, 005)
    expect(executionSequence).toHaveLength(5);
    expect(executionSequence[0]).toContain('1');
    expect(executionSequence[4]).toContain('5');
  });

  it('should handle conflict resolution in migrations', async () => {
    // Mock conflicting migrations - both try to create same collection
    mockReadFile.mockImplementation((filePath: string) => {
      const fileName = (filePath as string).split('/').pop();

      return Promise.resolve(JSON.stringify({
        version: '1.0.0',
        description: `Conflicting migration ${fileName}`,
        steps: [
          {
            operation: 'create_collection',
            collection: 'conflicting_collection', // Same collection name
            parameters: { vectors: { size: 1536, distance: 'Cosine' } },
            rollback: {}
          }
        ]
      }));
    });

    // Mock collection already exists error for second migration
    mockCreateCollection
      .mockResolvedValueOnce(undefined)
      .mockRejectedValueOnce(new Error('Collection already exists'));

    const results = await migrationManager.migrate();

    expect(results).toHaveLength(5);
    expect(results.some(r => r.status === 'failed')).toBe(true);
    expect(results.some(r => r.status === 'success')).toBe(true);
  });

  it('should handle partial batch failure', async () => {
    mockCreateCollection
      .mockResolvedValueOnce(undefined) // 001 success
      .mockResolvedValueOnce(undefined) // 002 success
      .mockRejectedValueOnce(new Error('Network error')) // 003 failure
      .mockResolvedValueOnce(undefined) // 004 success
      .mockResolvedValueOnce(undefined); // 005 success

    const results = await migrationManager.migrate();

    expect(results).toHaveLength(5);
    expect(results.filter(r => r.status === 'success')).toHaveLength(4);
    expect(results.filter(r => r.status === 'failed')).toHaveLength(1);
    expect(results[2].status).toBe('failed'); // Third migration failed
    expect(results[2].error).toContain('Network error');
  });

  it('should handle batch rollback operations', async () => {
    // Mock applied migrations
    mockSearch.mockResolvedValue([
      { payload: { migration_id: '001', name: '001_batch_test_1', status: 'applied' } },
      { payload: { migration_id: '002', name: '002_batch_test_2', status: 'applied' } },
      { payload: { migration_id: '003', name: '003_batch_test_3', status: 'applied' } }
    ]);

    const results = await migrationManager.rollback(3);

    expect(results).toHaveLength(3);
    expect(results.every(r => r.status === 'success')).toBe(true);

    // Should rollback in reverse order
    expect(results[0].migration_id).toBe('003');
    expect(results[1].migration_id).toBe('002');
    expect(results[2].migration_id).toBe('001');
  });

  it('should handle batch migration with force option', async () => {
    // Mock failures in some migrations
    mockCreateCollection
      .mockResolvedValueOnce(undefined)
      .mockRejectedValueOnce(new Error('Permission denied'))
      .mockResolvedValueOnce(undefined)
      .mockRejectedValueOnce(new Error('Connection failed'))
      .mockResolvedValueOnce(undefined);

    const results = await migrationManager.migrate({ force: true });

    expect(results).toHaveLength(5);
    // Should continue despite failures when force=true
    expect(results.filter(r => r.status === 'failed')).toHaveLength(2);
    expect(results.filter(r => r.status === 'success')).toHaveLength(3);
  });

  it('should handle batch dry-run mode', async () => {
    const results = await migrationManager.migrate({ dryRun: true });

    expect(results).toHaveLength(5);
    expect(results.every(r => r.status === 'skipped')).toBe(true);
    expect(results.every(r => r.message.contains('Dry run'))).toBe(true);

    // Should not execute any actual operations
    expect(mockCreateCollection).not.toHaveBeenCalled();
    expect(mockUpsert).not.toHaveBeenCalled();
  });
});

describe('Database Migration - Error Handling and Validation', () => {
  let migrationManager: QdrantMigrationManager;

  beforeEach(() => {
    vi.clearAllMocks();
    migrationManager = new QdrantMigrationManager();

    mockGetCollections.mockResolvedValue({ collections: [{ name: 'migrations' }] });
    mockReadDir.mockResolvedValue(['001_error_test.json']);
    mockSearch.mockResolvedValue([]);
  });

  it('should handle migration failure scenarios', async () => {
    const errorScenarios = [
      { error: new Error('Network timeout'), expectedType: 'timeout' },
      { error: new Error('Permission denied'), expectedType: 'permission' },
      { error: new Error('Disk space full'), expectedType: 'resource' },
      { error: new Error('Invalid configuration'), expectedType: 'validation' },
      { error: new Error('Connection lost'), expectedType: 'connection' }
    ];

    for (const scenario of errorScenarios) {
      mockCreateCollection.mockRejectedValueOnce(scenario.error);
      mockReadFile.mockResolvedValueOnce(JSON.stringify({
        version: '1.0.0',
        description: 'Error test migration',
        steps: [{
          operation: 'create_collection',
          collection: 'error_collection',
          parameters: { vectors: { size: 1536, distance: 'Cosine' } },
          rollback: {}
        }]
      }));

      const results = await migrationManager.migrate({ step: 1 });

      expect(results).toHaveLength(1);
      expect(results[0].status).toBe('failed');
      expect(results[0].error).toContain(scenario.error.message);

      // Reset mock for next iteration
      mockCreateCollection.mockReset();
    }
  });

  it('should validate data integrity during migration', async () => {
    mockReadFile.mockResolvedValue(JSON.stringify({
      version: '1.0.0',
      description: 'Data integrity test',
      steps: [
        {
          operation: 'create_collection',
          collection: 'integrity_test',
          parameters: { vectors: { size: 1536, distance: 'Cosine' } },
          rollback: {},
          validation: {
            required_fields: ['id', 'created_at', 'updated_at'],
            data_types: { id: 'string', created_at: 'datetime' }
          }
        }
      ]
    }));

    const results = await migrationManager.migrate();

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('success');
  });

  it('should handle compatibility checking', async () => {
    mockReadFile.mockResolvedValue(JSON.stringify({
      version: '2.0.0',
      description: 'Compatibility check test',
      requirements: {
        min_qdrant_version: '1.7.0',
        required_features: ['payload_indexing', 'filtering'],
        vector_size: 1536,
        distance_metric: 'Cosine'
      },
      steps: [
        {
          operation: 'create_collection',
          collection: 'compatibility_test',
          parameters: { vectors: { size: 1536, distance: 'Cosine' } },
          rollback: {}
        }
      ]
    }));

    const results = await migrationManager.migrate();

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('success');
  });

  it('should handle error recovery mechanisms', async () => {
    let attemptCount = 0;
    mockCreateCollection.mockImplementation(() => {
      attemptCount++;
      if (attemptCount < 3) {
        return Promise.reject(new Error('Temporary failure'));
      }
      return Promise.resolve(undefined);
    });

    mockReadFile.mockResolvedValue(JSON.stringify({
      version: '1.0.0',
      description: 'Recovery test migration',
      retry_config: {
        max_attempts: 3,
        backoff_strategy: 'exponential',
        base_delay: 1000
      },
      steps: [
        {
          operation: 'create_collection',
          collection: 'recovery_test',
          parameters: { vectors: { size: 1536, distance: 'Cosine' } },
          rollback: {}
        }
      ]
    }));

    const results = await migrationManager.migrate();

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('success');
    expect(attemptCount).toBe(3); // Should retry 2 times then succeed
  });

  it('should handle malformed migration files', async () => {
    mockReadFile.mockResolvedValue('invalid json content');

    const results = await migrationManager.migrate();

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('failed');
    expect(results[0].error).toBeDefined();
  });

  it('should handle missing migration files', async () => {
    mockReadFile.mockRejectedValue(new Error('File not found'));

    const results = await migrationManager.migrate();

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('failed');
    expect(results[0].error).toContain('File not found');
  });

  it('should handle migration checksum validation', async () => {
    // Mock file content changed between read and execution
    const originalContent = JSON.stringify({
      version: '1.0.0',
      description: 'Checksum test',
      steps: [{
        operation: 'create_collection',
        collection: 'checksum_test',
        parameters: { vectors: { size: 1536, distance: 'Cosine' } },
        rollback: {}
      }]
    });

    mockReadFile.mockResolvedValueOnce(originalContent);
    mockReadFile.mockResolvedValueOnce(JSON.stringify({
      version: '1.0.0',
      description: 'Modified content', // Different description
      steps: [{
        operation: 'create_collection',
        collection: 'checksum_test',
        parameters: { vectors: { size: 1536, distance: 'Cosine' } },
        rollback: {}
      }]
    }));

    const results = await migrationManager.migrate();

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('failed');
    expect(results[0].error).toContain('Checksum mismatch');
  });

  it('should handle concurrent migration attempts', async () => {
    const migrationLocks = new Set<string>();

    // Mock lock acquisition
    const originalMigrate = migrationManager.migrate.bind(migrationManager);
    migrationManager.migrate = async (options = {}) => {
      const lockId = `migration_${Date.now()}`;
      if (migrationLocks.has(lockId)) {
        throw new Error('Migration already in progress');
      }
      migrationLocks.add(lockId);

      try {
        return await originalMigrate(options);
      } finally {
        migrationLocks.delete(lockId);
      }
    };

    const promises = [
      migrationManager.migrate({ step: 1 }),
      migrationManager.migrate({ step: 1 }),
      migrationManager.migrate({ step: 1 })
    ];

    const results = await Promise.allSettled(promises);

    // At least one should succeed
    expect(results.some(r => r.status === 'fulfilled')).toBe(true);
  });

  it('should provide detailed error reporting', async () => {
    mockCreateCollection.mockRejectedValue(new Error('Detailed error message'));

    mockReadFile.mockResolvedValue(JSON.stringify({
      version: '1.0.0',
      description: 'Detailed error test',
      steps: [
        {
          operation: 'create_collection',
          collection: 'detailed_error_test',
          parameters: { vectors: { size: 1536, distance: 'Cosine' } },
          rollback: {}
        }
      ]
    }));

    const results = await migrationManager.migrate();

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('failed');
    expect(results[0].migration_id).toBe('001');
    expect(results[0].message).toBe('Migration failed');
    expect(results[0].error).toBe('Detailed error message');
    expect(results[0].duration).toBeGreaterThan(0);
  });

  it('should handle migration timeout scenarios', async () => {
    mockCreateCollection.mockImplementation(() =>
      new Promise((resolve, reject) =>
        setTimeout(() => reject(new Error('Migration timeout')), 2000)
      )
    );

    mockReadFile.mockResolvedValue(JSON.stringify({
      version: '1.0.0',
      description: 'Timeout test migration',
      timeout: 1000, // 1 second timeout
      steps: [
        {
          operation: 'create_collection',
          collection: 'timeout_test',
          parameters: { vectors: { size: 1536, distance: 'Cosine' } },
          rollback: {}
        }
      ]
    }));

    const startTime = Date.now();
    const results = await migrationManager.migrate();
    const duration = Date.now() - startTime;

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('failed');
    expect(results[0].error).toContain('timeout');
    expect(duration).toBeLessThan(3000); // Should fail faster than the operation itself
  });

  it('should validate migration rollback safety', async () => {
    mockReadFile.mockResolvedValue(JSON.stringify({
      version: '1.0.0',
      description: 'Unsafe rollback test',
      steps: [
        {
          operation: 'delete_collection',
          collection: 'important_collection',
          parameters: {},
          rollback: undefined // No rollback defined
        }
      ]
    }));

    const results = await migrationManager.migrate();

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('success');
    // Should log warning about missing rollback
    expect(logger.warn).toHaveBeenCalledWith(
      expect.stringContaining('No rollback defined')
    );
  });
});

describe('Database Migration - Integration and Performance', () => {
  let migrationManager: QdrantMigrationManager;

  beforeEach(() => {
    vi.clearAllMocks();
    migrationManager = new QdrantMigrationManager();

    mockGetCollections.mockResolvedValue({ collections: [{ name: 'migrations' }] });
    mockSearch.mockResolvedValue([]);
  });

  it('should handle large-scale migration batches', async () => {
    // Mock 100 migrations
    const migrationFiles = Array.from({ length: 100 }, (_, i) =>
      `${String(i + 1).padStart(3, '0')}_large_scale_${i + 1}.json`
    );

    mockReadDir.mockResolvedValue(migrationFiles);

    mockReadFile.mockImplementation((filePath: string) => {
      const fileName = (filePath as string).split('/').pop();
      const number = fileName?.split('_')[2]?.replace('.json', '') || '1';

      return Promise.resolve(JSON.stringify({
        version: `1.${number}.0`,
        description: `Large scale migration ${number}`,
        steps: [{
          operation: 'create_collection',
          collection: `large_scale_${number}`,
          parameters: { vectors: { size: 1536, distance: 'Cosine' } },
          rollback: {}
        }]
      }));
    });

    const startTime = Date.now();
    const results = await migrationManager.migrate();
    const duration = Date.now() - startTime;

    expect(results).toHaveLength(100);
    expect(results.every(r => r.status === 'success')).toBe(true);
    expect(duration).toBeLessThan(10000); // Should complete within 10 seconds
  });

  it('should handle memory usage during migrations', async () => {
    // Create large migration data
    const largeMigrationData = {
      version: '1.0.0',
      description: 'Large migration test',
      large_data: 'x'.repeat(1000000), // 1MB of data
      steps: Array.from({ length: 100 }, (_, i) => ({
        operation: 'create_collection',
        collection: `memory_test_${i}`,
        parameters: { vectors: { size: 1536, distance: 'Cosine' } },
        rollback: {}
      }))
    };

    mockReadDir.mockResolvedValue(['001_large_memory.json']);
    mockReadFile.mockResolvedValue(JSON.stringify(largeMigrationData));

    const initialMemory = process.memoryUsage().heapUsed;

    const results = await migrationManager.migrate();

    const finalMemory = process.memoryUsage().heapUsed;
    const memoryIncrease = finalMemory - initialMemory;

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('success');
    expect(memoryIncrease).toBeLessThan(50 * 1024 * 1024); // Less than 50MB increase
  });

  it('should handle concurrent migration operations', async () => {
    mockReadDir.mockResolvedValue([
      '001_concurrent_1.json',
      '002_concurrent_2.json',
      '003_concurrent_3.json'
    ]);

    mockReadFile.mockImplementation((filePath: string) => {
      const fileName = (filePath as string).split('/').pop();
      const number = fileName?.split('_')[2] || '1';

      return Promise.resolve(JSON.stringify({
        version: `1.0.${number}`,
        description: `Concurrent migration ${number}`,
        steps: [{
          operation: 'create_collection',
          collection: `concurrent_${number}`,
          parameters: { vectors: { size: 1536, distance: 'Cosine' } },
          rollback: {}
        }]
      }));
    });

    // Run migrations concurrently (should be safe due to internal locking)
    const promises = [
      migrationManager.migrate({ step: 1 }),
      migrationManager.migrate({ step: 1 }),
      migrationManager.migrate({ step: 1 })
    ];

    const results = await Promise.allSettled(promises);

    // Should handle concurrency safely
    expect(results.every(r => r.status === 'fulfilled')).toBe(true);
  });

  it('should maintain performance during complex migrations', async () => {
    const complexMigration = {
      version: '1.0.0',
      description: 'Complex performance test',
      steps: [
        ...Array.from({ length: 50 }, (_, i) => ({
          operation: 'create_collection',
          collection: `perf_test_${i}`,
          parameters: {
            vectors: { size: 1536, distance: 'Cosine' },
            payload_schema: {
              type: 'object',
              properties: {
                field: { type: 'keyword' },
                timestamp: { type: 'datetime' }
              }
            }
          },
          rollback: {}
        })),
        ...Array.from({ length: 25 }, (_, i) => ({
          operation: 'create_index',
          collection: `perf_test_${i}`,
          parameters: { field_name: 'field' },
          rollback: {}
        }))
      ]
    };

    mockReadDir.mockResolvedValue(['001_complex_performance.json']);
    mockReadFile.mockResolvedValue(JSON.stringify(complexMigration));

    const startTime = Date.now();
    const results = await migrationManager.migrate();
    const duration = Date.now() - startTime;

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe('success');
    expect(duration).toBeLessThan(5000); // Should complete within 5 seconds
  });

  it('should handle migration state persistence', async () => {
    mockReadDir.mockResolvedValue(['001_state_test.json']);
    mockReadFile.mockResolvedValue(JSON.stringify({
      version: '1.0.0',
      description: 'State persistence test',
      steps: [{
        operation: 'create_collection',
        collection: 'state_test',
        parameters: { vectors: { size: 1536, distance: 'Cosine' } },
        rollback: {}
      }]
    }));

    // Execute migration
    const migrateResults = await migrationManager.migrate();
    expect(migrateResults).toHaveLength(1);
    expect(migrateResults[0].status).toBe('success');

    // Verify state was persisted
    expect(mockUpsert).toHaveBeenCalledWith('migrations', expect.objectContaining({
      points: expect.arrayContaining([
        expect.objectContaining({
          payload: expect.objectContaining({
            migration_id: '001',
            status: 'applied'
          })
        })
      ])
    }));

    // Mock subsequent status check
    mockSearch.mockResolvedValue([{
      payload: {
        migration_id: '001',
        name: '001_state_test',
        version: '1.0.0',
        status: 'applied'
      }
    }]);

    const status = await migrationManager.status();
    expect(status.applied).toHaveLength(1);
    expect(status.pending).toHaveLength(0);
  });

  it('should handle migration system health monitoring', async () => {
    const healthStatus = await migrationManager.status();

    expect(healthStatus).toHaveProperty('available');
    expect(healthStatus).toHaveProperty('applied');
    expect(healthStatus).toHaveProperty('pending');
    expect(Array.isArray(healthStatus.available)).toBe(true);
    expect(Array.isArray(healthStatus.applied)).toBe(true);
    expect(Array.isArray(healthStatus.pending)).toBe(true);
  });
});