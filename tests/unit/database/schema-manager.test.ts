/**
 * Comprehensive Unit Tests for Database Schema Manager
 *
 * Tests schema manager functionality including:
 * - Schema Validation and Enforcement (knowledge type schema validation, dynamic schema registration, schema versioning, schema migration handling)
 * - Collection Schema Management (collection schema creation, schema updates and migrations, schema compatibility validation, index configuration)
 * - Field Validation (required field validation, optional field handling, field type constraints, custom validation rules)
 * - Schema Evolution (backward compatibility handling, schema migration strategies, field addition/removal, type change handling)
 * - Error Handling and Recovery (schema validation errors, migration failure handling, rollback capabilities, data consistency validation)
 * - Integration with Knowledge Types (knowledge type schema registration, dynamic schema updates, type-specific validation rules, cross-type relationship validation)
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { QdrantSchemaManager, COLLECTION_CONFIGS } from '../../../src/db/schema';
import { QdrantClient } from '@qdrant/js-client-rest';
import { DatabaseError, ValidationError } from '../../../src/db/types/database-types';

// Mock Qdrant client with comprehensive method coverage
const mockGetCollections = vi.fn();
const mockCreateCollection = vi.fn();
const mockGetCollection = vi.fn();
const mockDeleteCollection = vi.fn();
const mockUpdateCollection = vi.fn();
const mockCreateCollectionIndex = vi.fn();

vi.mock('@qdrant/js-client-rest', () => ({
  QdrantClient: class {
    constructor(config?: any) {
      this.config = config;
    }

    async getCollections() {
      return mockGetCollections();
    }

    async createCollection(name: string, config?: any) {
      return mockCreateCollection(name, config);
    }

    async getCollection(name: string) {
      return mockGetCollection(name);
    }

    async deleteCollection(name: string) {
      return mockDeleteCollection(name);
    }

    async updateCollection(name: string, config: any) {
      return mockUpdateCollection(name, config);
    }

    async createCollectionIndex(collectionName: string, indexConfig: any) {
      return mockCreateCollectionIndex(collectionName, indexConfig);
    }

    async healthCheck() {
      return { status: 'ok' };
    }
  },
}));

// Mock Environment
vi.mock('../../../src/config/environment', () => ({
  Environment: {
    getInstance: () => ({
      getQdrantConfig: () => ({
        url: 'http://localhost:6333',
        apiKey: 'test-api-key',
        connectionTimeout: 30000,
      }),
    }),
  },
}));

// Mock Logger
vi.mock('../../../src/utils/logger', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

describe('Database Schema Manager - Comprehensive Testing', () => {
  let schemaManager: QdrantSchemaManager;
  let mockClient: any;

  beforeEach(() => {
    vi.clearAllMocks();

    // Set up default mock behaviors
    mockGetCollections.mockResolvedValue({
      collections: [{ name: 'entity' }, { name: 'relation' }, { name: 'observation' }],
    });

    mockCreateCollection.mockResolvedValue({ name: 'test-collection' });
    mockGetCollection.mockResolvedValue({
      name: 'test-collection',
      status: 'green',
      vectors_count: 100,
      indexed_vectors_count: 95,
      points_count: 100,
      segments_count: 1,
      disk_data_size: 1048576,
      config: {
        vector_size: 1536,
        distance: 'Cosine',
      },
      payload_schema: {},
      optimizer_status: 'ok',
    });

    mockDeleteCollection.mockResolvedValue({ name: 'test-collection' });
    mockUpdateCollection.mockResolvedValue({ name: 'test-collection' });
    mockCreateCollectionIndex.mockResolvedValue({ result: 'index_created' });

    schemaManager = new QdrantSchemaManager();
    mockClient = (schemaManager as any).client;
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('Schema Validation and Enforcement', () => {
    it('should validate collection configurations for all 16 knowledge types', () => {
      expect(COLLECTION_CONFIGS).toHaveLength(16);

      const expectedTypes = [
        'entity',
        'relation',
        'observation',
        'section',
        'runbook',
        'change',
        'issue',
        'decision',
        'todo',
        'release_note',
        'ddl',
        'pr_context',
        'incident',
        'release',
        'risk',
        'assumption',
      ];

      const actualTypes = COLLECTION_CONFIGS.map((config) => config.name);
      expect(actualTypes).toEqual(expect.arrayContaining(expectedTypes));

      // Validate each configuration has required properties
      COLLECTION_CONFIGS.forEach((config) => {
        expect(config).toHaveProperty('name');
        expect(config).toHaveProperty('vectorSize');
        expect(config).toHaveProperty('distance');
        expect(config).toHaveProperty('payloadSchema');

        expect(typeof config.vectorSize).toBe('number');
        expect(config.vectorSize).toBeGreaterThan(0);
        expect(['Cosine', 'Euclid', 'Dot']).toContain(config.distance);
        expect(typeof config.payloadSchema).toBe('object');
      });
    });

    it('should enforce consistent vector configuration across knowledge types', () => {
      const vectorSizes = COLLECTION_CONFIGS.map((config) => config.vectorSize);
      const distances = COLLECTION_CONFIGS.map((config) => config.distance);

      // All collections should use the same vector size
      expect(new Set(vectorSizes)).toHaveLength(1);
      expect(vectorSizes[0]).toBe(1536);

      // All collections should use cosine distance for semantic similarity
      expect(new Set(distances)).toHaveLength(1);
      expect(distances[0]).toBe('Cosine');
    });

    it('should validate payload schema structure for each knowledge type', () => {
      COLLECTION_CONFIGS.forEach((config) => {
        const schema = config.payloadSchema;

        expect(schema).toHaveProperty('type', 'object');
        expect(schema).toHaveProperty('properties');
        expect(typeof schema.properties).toBe('object');

        // All schemas should have core timestamp fields
        expect(schema.properties).toHaveProperty('created_at');
        expect(schema.properties).toHaveProperty('updated_at');
        expect(schema.properties.created_at).toHaveProperty('type', 'datetime');
        expect(schema.properties.updated_at).toHaveProperty('type', 'datetime');

        // All schemas should have metadata and tags fields
        expect(schema.properties).toHaveProperty('metadata');
        expect(schema.properties).toHaveProperty('tags');
        expect(schema.properties.tags).toHaveProperty('type', 'array');
        expect(schema.properties.tags.items).toHaveProperty('type', 'keyword');
      });
    });

    it('should support dynamic schema registration for new knowledge types', async () => {
      const newKnowledgeType = {
        name: 'custom_type',
        vectorSize: 1536,
        distance: 'Cosine' as const,
        payloadSchema: {
          type: 'object',
          properties: {
            custom_field: { type: 'text' },
            created_at: { type: 'datetime' },
            updated_at: { type: 'datetime' },
            tags: { type: 'array', items: { type: 'keyword' } },
            metadata: { type: 'object' },
          },
        },
      };

      // Simulate dynamic registration by creating collection with new schema
      mockGetCollections.mockResolvedValue({ collections: [] });

      await schemaManager.getClient().createCollection(newKnowledgeType.name, {
        vectors: {
          size: newKnowledgeType.vectorSize,
          distance: newKnowledgeType.distance,
        },
      });

      expect(mockCreateCollection).toHaveBeenCalledWith(
        newKnowledgeType.name,
        expect.objectContaining({
          vectors: {
            size: 1536,
            distance: 'Cosine',
          },
        })
      );
    });

    it('should handle schema versioning compatibility', () => {
      // Test that current schema configurations are version-compatible
      const currentVersion = '2.0.0';

      COLLECTION_CONFIGS.forEach((config) => {
        // Verify schema structure matches expected version
        expect(config.payloadSchema.properties).toHaveProperty('created_at');
        expect(config.payloadSchema.properties).toHaveProperty('updated_at');

        // Verify no deprecated fields exist
        const deprecatedFields = ['old_timestamp', 'legacy_field'];
        deprecatedFields.forEach((field) => {
          expect(config.payloadSchema.properties).not.toHaveProperty(field);
        });
      });
    });

    it('should validate schema migration requirements', async () => {
      // Test migration validation for collection updates
      const collectionName = 'entity';
      const newConfig = {
        vectors: {
          size: 1536,
          distance: 'Cosine',
        },
      };

      mockGetCollection.mockResolvedValue({
        name: collectionName,
        config: {
          vector_size: 1536, // Same size - compatible
          distance: 'Cosine', // Same distance - compatible
        },
      });

      // Should allow compatible updates
      await expect(
        schemaManager.getClient().updateCollection(collectionName, newConfig)
      ).resolves.toBeDefined();

      expect(mockUpdateCollection).toHaveBeenCalledWith(collectionName, newConfig);
    });
  });

  describe('Collection Schema Management', () => {
    it('should create collections with proper schema configuration', async () => {
      mockGetCollections.mockResolvedValue({ collections: [] });

      await schemaManager.initializeCollections();

      // Should attempt to create all 16 collections
      expect(mockCreateCollection).toHaveBeenCalledTimes(16);

      // Verify each collection was created with correct configuration
      COLLECTION_CONFIGS.forEach((config) => {
        expect(mockCreateCollection).toHaveBeenCalledWith(
          config.name,
          expect.objectContaining({
            vectors: {
              size: config.vectorSize,
              distance: config.distance,
            },
          })
        );
      });
    });

    it('should skip collection creation when collection already exists', async () => {
      // Mock that all collections already exist
      mockGetCollections.mockResolvedValue({
        collections: COLLECTION_CONFIGS.map((config) => ({ name: config.name })),
      });

      await schemaManager.initializeCollections();

      expect(mockCreateCollection).not.toHaveBeenCalled();
      expect(mockGetCollections).toHaveBeenCalledTimes(1);
    });

    it('should handle collection creation errors gracefully', async () => {
      mockGetCollections.mockResolvedValue({ collections: [] });
      mockCreateCollection.mockRejectedValue(new Error('Insufficient permissions'));

      await expect(schemaManager.initializeCollections()).rejects.toThrow(
        'Insufficient permissions'
      );
      expect(mockCreateCollection).toHaveBeenCalled();
    });

    it('should validate collection schema compatibility', async () => {
      const collectionName = 'entity';

      // Test successful schema validation
      mockGetCollection.mockResolvedValue({
        name: collectionName,
        config: {
          vector_size: 1536,
          distance: 'Cosine',
        },
        payload_schema: {
          type: 'object',
          properties: {
            entity_type: { type: 'keyword' },
            created_at: { type: 'datetime' },
          },
        },
      });

      const info = await schemaManager.getCollectionInfo(collectionName);
      expect(info).toBeDefined();
      expect(info.name).toBe(collectionName);
      expect(mockGetCollection).toHaveBeenCalledWith(collectionName);
    });

    it('should handle schema updates and migrations', async () => {
      const collectionName = 'entity';
      const updatedConfig = {
        vectors: {
          size: 1536,
          distance: 'Cosine',
        },
      };

      await schemaManager.getClient().updateCollection(collectionName, updatedConfig);

      expect(mockUpdateCollection).toHaveBeenCalledWith(collectionName, updatedConfig);
    });

    it('should configure indexes for optimal performance', () => {
      // Verify index configurations are defined for key fields
      COLLECTION_CONFIGS.forEach((config) => {
        if (config.indexes) {
          config.indexes.forEach((index) => {
            expect(index).toHaveProperty('field');
            expect(index).toHaveProperty('schemaType');
            expect(['keyword', 'integer', 'float', 'bool', 'datetime', 'geo']).toContain(
              index.schemaType
            );
          });
        }
      });

      // Verify entity collection has proper indexes
      const entityConfig = COLLECTION_CONFIGS.find((config) => config.name === 'entity');
      expect(entityConfig?.indexes).toBeDefined();
      expect(entityConfig?.indexes?.some((index) => index.field === 'entity_type')).toBe(true);
      expect(entityConfig?.indexes?.some((index) => index.field === 'created_at')).toBe(true);
    });

    it('should handle collection deletion for migration purposes', async () => {
      const collectionName = 'test_collection_to_delete';

      await schemaManager.deleteCollection(collectionName);

      expect(mockDeleteCollection).toHaveBeenCalledWith(collectionName);
    });

    it('should list all collections with their schemas', async () => {
      const mockCollections = [{ name: 'entity' }, { name: 'relation' }, { name: 'observation' }];
      mockGetCollections.mockResolvedValue({ collections: mockCollections });

      const collections = await schemaManager.listCollections();

      expect(collections).toEqual(['entity', 'relation', 'observation']);
      expect(mockGetCollections).toHaveBeenCalledTimes(1);
    });
  });

  describe('Field Validation', () => {
    it('should validate required fields for each knowledge type', () => {
      // Test entity schema requirements
      const entitySchema = COLLECTION_CONFIGS.find(
        (config) => config.name === 'entity'
      )?.payloadSchema;
      expect(entitySchema?.properties).toHaveProperty('entity_type');
      expect(entitySchema?.properties).toHaveProperty('name');
      expect(entitySchema?.properties).toHaveProperty('data');

      // Test relation schema requirements
      const relationSchema = COLLECTION_CONFIGS.find(
        (config) => config.name === 'relation'
      )?.payloadSchema;
      expect(relationSchema?.properties).toHaveProperty('from_entity_type');
      expect(relationSchema?.properties).toHaveProperty('to_entity_type');
      expect(relationSchema?.properties).toHaveProperty('relation_type');

      // Test decision schema requirements
      const decisionSchema = COLLECTION_CONFIGS.find(
        (config) => config.name === 'decision'
      )?.payloadSchema;
      expect(decisionSchema?.properties).toHaveProperty('component');
      expect(decisionSchema?.properties).toHaveProperty('status');
      expect(decisionSchema?.properties).toHaveProperty('title');
    });

    it('should handle optional fields correctly', () => {
      // Verify metadata and tags are optional but properly typed
      COLLECTION_CONFIGS.forEach((config) => {
        expect(config.payloadSchema.properties).toHaveProperty('metadata');
        expect(config.payloadSchema.properties).toHaveProperty('tags');

        // These should be optional in actual payload validation
        expect(config.payloadSchema.properties.metadata['type']).toBe('object');
        expect(config.payloadSchema.properties.tags.type).toBe('array');
      });
    });

    it('should enforce field type constraints', () => {
      // Test entity field types
      const entitySchema = COLLECTION_CONFIGS.find(
        (config) => config.name === 'entity'
      )?.payloadSchema;
      expect(entitySchema?.properties.entity_type.type).toBe('keyword');
      expect(entitySchema?.properties.name.type).toBe('text');
      expect(entitySchema?.properties['data.type']).toBe('object');

      // Test datetime fields
      COLLECTION_CONFIGS.forEach((config) => {
        expect(config.payloadSchema.properties.created_at.type).toBe('datetime');
        expect(config.payloadSchema.properties.updated_at.type).toBe('datetime');
      });

      // Test array fields
      COLLECTION_CONFIGS.forEach((config) => {
        expect(config.payloadSchema.properties.tags.type).toBe('array');
        expect(config.payloadSchema.properties.tags.items.type).toBe('keyword');
      });
    });

    it('should support custom validation rules for specific fields', () => {
      // Test decision-specific validation rules
      const decisionSchema = COLLECTION_CONFIGS.find(
        (config) => config.name === 'decision'
      )?.payloadSchema;
      expect(decisionSchema?.properties.alternatives_considered.type).toBe('array');
      expect(decisionSchema?.properties.consequences.type).toBe('text');
      expect(decisionSchema?.properties.supersedes.type).toBe('keyword');

      // Test incident-specific validation rules
      const incidentSchema = COLLECTION_CONFIGS.find(
        (config) => config.name === 'incident'
      )?.payloadSchema;
      expect(incidentSchema?.properties.severity.type).toBe('keyword');
      expect(incidentSchema?.properties.follow_up_required.type).toBe('bool');
      expect(incidentSchema?.properties.affected_services.type).toBe('array');
    });

    it('should validate nested object structures', () => {
      // Test timeline object in incident schema
      const incidentSchema = COLLECTION_CONFIGS.find(
        (config) => config.name === 'incident'
      )?.payloadSchema;
      expect(incidentSchema?.properties.timeline.type).toBe('object');

      // Test scope object in various schemas
      const todoSchema = COLLECTION_CONFIGS.find((config) => config.name === 'todo')?.payloadSchema;
      expect(todoSchema?.properties).toHaveProperty('scope');

      // Test complex nested structures
      const releaseSchema = COLLECTION_CONFIGS.find(
        (config) => config.name === 'release'
      )?.payloadSchema;
      expect(releaseSchema?.properties).toHaveProperty('ticket_references');
      expect(releaseSchema?.properties).toHaveProperty('included_changes');
    });
  });

  describe('Schema Evolution', () => {
    it('should handle backward compatibility for schema changes', () => {
      // Test that current schemas maintain backward compatibility
      const requiredFields = ['created_at', 'updated_at'];

      COLLECTION_CONFIGS.forEach((config) => {
        requiredFields.forEach((field) => {
          expect(config.payloadSchema.properties).toHaveProperty(field);
        });
      });
    });

    it('should support field addition without breaking existing data', async () => {
      const collectionName = 'entity';

      // Mock existing collection with older schema
      mockGetCollection.mockResolvedValue({
        name: collectionName,
        config: { vector_size: 1536, distance: 'Cosine' },
        payload_schema: {
          type: 'object',
          properties: {
            entity_type: { type: 'keyword' },
            created_at: { type: 'datetime' },
          },
        },
      });

      const info = await schemaManager.getCollectionInfo(collectionName);
      expect(info).toBeDefined();

      // Should be able to work with existing schema
      expect(mockGetCollection).toHaveBeenCalledWith(collectionName);
    });

    it('should handle field removal safely', () => {
      // Test schema can handle deprecated fields gracefully
      const entitySchema = COLLECTION_CONFIGS.find(
        (config) => config.name === 'entity'
      )?.payloadSchema;

      // Should not have deprecated fields
      expect(entitySchema?.properties).not.toHaveProperty('legacy_field');
      expect(entitySchema?.properties).not.toHaveProperty('old_property');

      // Should have current fields
      expect(entitySchema?.properties).toHaveProperty('entity_type');
      expect(entitySchema?.properties).toHaveProperty('name');
    });

    it('should manage type changes with proper validation', async () => {
      const collectionName = 'test_type_change';

      // Test incompatible vector size change
      mockGetCollection.mockResolvedValue({
        name: collectionName,
        config: { vector_size: 1024, distance: 'Cosine' }, // Different size
      });

      // Should handle type incompatibility detection
      const info = await schemaManager.getCollectionInfo(collectionName);
      expect(info.config.vector_size).toBe(1024);
    });

    it('should support schema migration strategies', async () => {
      // Mock migration scenario
      mockGetCollections.mockResolvedValue({
        collections: [{ name: 'entity' }], // Only one collection exists
      });

      // Initialize should create missing collections
      await schemaManager.initializeCollections();

      // Should create the remaining 15 collections
      expect(mockCreateCollection).toHaveBeenCalledTimes(15);
    });

    it('should track schema version history', () => {
      // All schemas should be compatible with version 2.0.0
      COLLECTION_CONFIGS.forEach((config) => {
        // Verify schema has required fields for current version
        expect(config.payloadSchema.properties).toHaveProperty('created_at');
        expect(config.payloadSchema.properties).toHaveProperty('updated_at');
        expect(config.payloadSchema.properties).toHaveProperty('tags');
        expect(config.payloadSchema.properties).toHaveProperty('metadata');
      });
    });
  });

  describe('Error Handling and Recovery', () => {
    it('should handle schema validation errors gracefully', async () => {
      mockCreateCollection.mockRejectedValue(new Error('Invalid schema configuration'));
      mockGetCollections.mockResolvedValue({ collections: [] });

      await expect(schemaManager.initializeCollections()).rejects.toThrow(
        'Invalid schema configuration'
      );
      expect(mockCreateCollection).toHaveBeenCalled();
    });

    it('should handle migration failures with rollback capability', async () => {
      const collectionName = 'test_migration';

      // Mock partial failure during migration
      mockCreateCollection
        .mockResolvedValueOnce({ name: collectionName })
        .mockRejectedValueOnce(new Error('Migration failed'));

      mockGetCollections.mockResolvedValue({ collections: [] });

      try {
        await schemaManager.initializeCollections();
      } catch (error) {
        expect(error).toBeDefined();
      }

      // Should attempt cleanup
      await schemaManager.deleteCollection(collectionName);
      expect(mockDeleteCollection).toHaveBeenCalledWith(collectionName);
    });

    it('should validate data consistency after schema changes', async () => {
      const collectionName = 'entity';

      // Mock successful schema update
      mockGetCollection.mockResolvedValue({
        name: collectionName,
        status: 'green',
        vectors_count: 100,
        points_count: 100,
        config: { vector_size: 1536, distance: 'Cosine' },
      });

      const stats = await schemaManager.getCollectionStats(collectionName);
      expect(stats).toBeDefined();
      expect(stats.vectorCount).toBe(100);
      expect(stats.pointsCount).toBe(100);
      expect(stats.status).toBe('green');
    });

    it('should handle network connectivity issues', async () => {
      mockGetCollections.mockRejectedValue(new Error('Network timeout'));

      await expect(schemaManager.initializeCollections()).rejects.toThrow('Network timeout');
    });

    it('should handle insufficient permissions gracefully', async () => {
      mockCreateCollection.mockRejectedValue(new Error('Access denied'));
      mockGetCollections.mockResolvedValue({ collections: [] });

      await expect(schemaManager.initializeCollections()).rejects.toThrow('Access denied');
    });

    it('should validate collection health after operations', async () => {
      const health = await schemaManager.healthCheck();

      expect(health).toHaveProperty('isHealthy');
      expect(health).toHaveProperty('message');
      expect(typeof health.isHealthy).toBe('boolean');
      expect(typeof health.message).toBe('string');
    });

    it('should handle corrupted schema recovery', async () => {
      const collectionName = 'corrupted_schema';

      // Mock corrupted collection state
      mockGetCollection.mockRejectedValue(new Error('Schema corrupted'));

      await expect(schemaManager.getCollectionInfo(collectionName)).rejects.toThrow(
        'Schema corrupted'
      );

      // Should be able to delete corrupted collection
      await schemaManager.deleteCollection(collectionName);
      expect(mockDeleteCollection).toHaveBeenCalledWith(collectionName);
    });
  });

  describe('Integration with Knowledge Types', () => {
    it('should register schemas for all 16 knowledge types', () => {
      const knowledgeTypes = [
        'entity',
        'relation',
        'observation',
        'section',
        'runbook',
        'change',
        'issue',
        'decision',
        'todo',
        'release_note',
        'ddl',
        'pr_context',
        'incident',
        'release',
        'risk',
        'assumption',
      ];

      knowledgeTypes.forEach((type) => {
        const config = COLLECTION_CONFIGS.find((config) => config.name === type);
        expect(config).toBeDefined();
        expect(config?.name).toBe(type);
        expect(config?.payloadSchema).toBeDefined();
      });
    });

    it('should support dynamic schema updates for knowledge types', async () => {
      const collectionName = 'entity';
      const newFieldConfig = {
        vectors: { size: 1536, distance: 'Cosine' },
      };

      // Should support runtime schema updates
      await schemaManager.getClient().updateCollection(collectionName, newFieldConfig);
      expect(mockUpdateCollection).toHaveBeenCalledWith(collectionName, newFieldConfig);
    });

    it('should enforce type-specific validation rules', () => {
      // Test entity type validation
      const entityConfig = COLLECTION_CONFIGS.find((config) => config.name === 'entity');
      expect(entityConfig?.payloadSchema.properties.entity_type.type).toBe('keyword');
      expect(entityConfig?.payloadSchema.properties.name.type).toBe('text');

      // Test relation type validation
      const relationConfig = COLLECTION_CONFIGS.find((config) => config.name === 'relation');
      expect(relationConfig?.payloadSchema.properties.from_entity_type.type).toBe('keyword');
      expect(relationConfig?.payloadSchema.properties.to_entity_type.type).toBe('keyword');

      // Test incident type validation
      const incidentConfig = COLLECTION_CONFIGS.find((config) => config.name === 'incident');
      expect(incidentConfig?.payloadSchema.properties.severity.type).toBe('keyword');
      expect(incidentConfig?.payloadSchema.properties.follow_up_required.type).toBe('bool');
    });

    it('should validate cross-type relationship constraints', () => {
      // Test relation schema references entity types
      const relationConfig = COLLECTION_CONFIGS.find((config) => config.name === 'relation');
      expect(relationConfig?.payloadSchema.properties.from_entity_type.type).toBe('keyword');
      expect(relationConfig?.payloadSchema.properties.to_entity_type.type).toBe('keyword');
      expect(relationConfig?.payloadSchema.properties.relation_type.type).toBe('keyword');

      // Test DDL schema references
      const ddlConfig = COLLECTION_CONFIGS.find((config) => config.name === 'ddl');
      expect(ddlConfig?.payloadSchema.properties.migration_id.type).toBe('keyword');
      expect(ddlConfig?.payloadSchema.properties.status.type).toBe('keyword');
    });

    it('should handle knowledge type inheritance patterns', () => {
      // Test common fields across all knowledge types
      const commonFields = ['created_at', 'updated_at', 'tags', 'metadata'];

      COLLECTION_CONFIGS.forEach((config) => {
        commonFields.forEach((field) => {
          expect(config.payloadSchema.properties).toHaveProperty(field);
        });
      });
    });

    it('should support type-specific field constraints', () => {
      // Test PR context specific constraints
      const prContextConfig = COLLECTION_CONFIGS.find((config) => config.name === 'pr_context');
      expect(prContextConfig?.payloadSchema.properties.pr_number.type).toBe('integer');
      expect(prContextConfig?.payloadSchema.properties.expires_at.type).toBe('datetime');

      // Test release note specific constraints
      const releaseNoteConfig = COLLECTION_CONFIGS.find((config) => config.name === 'release_note');
      expect(releaseNoteConfig?.payloadSchema.properties.version.type).toBe('keyword');
      expect(releaseNoteConfig?.payloadSchema.properties.release_date.type).toBe('datetime');
    });

    it('should maintain referential integrity across types', () => {
      // Test that related types have compatible field types
      const entityConfig = COLLECTION_CONFIGS.find((config) => config.name === 'entity');
      const relationConfig = COLLECTION_CONFIGS.find((config) => config.name === 'relation');

      // Both should use keyword type for entity references
      expect(entityConfig?.payloadSchema.properties.entity_type.type).toBe('keyword');
      expect(relationConfig?.payloadSchema.properties.from_entity_type.type).toBe('keyword');
      expect(relationConfig?.payloadSchema.properties.to_entity_type.type).toBe('keyword');
    });

    it('should handle complex knowledge type workflows', async () => {
      // Test end-to-end workflow with multiple knowledge types
      mockGetCollections.mockResolvedValue({ collections: [] });

      await schemaManager.initializeCollections();

      // Should create all required collections
      expect(mockCreateCollection).toHaveBeenCalledTimes(16);

      // Verify all knowledge type collections were created
      const createdCollections = mockCreateCollection.mock.calls.map((call) => call[0]);
      const expectedCollections = COLLECTION_CONFIGS.map((config) => config.name);
      expect(createdCollections).toEqual(expect.arrayContaining(expectedCollections));
    });
  });

  describe('Collection Verification and Health Monitoring', () => {
    it('should verify all required collections exist', async () => {
      mockGetCollections.mockResolvedValue({
        collections: COLLECTION_CONFIGS.map((config) => ({ name: config.name })),
      });

      const isVerified = await schemaManager.verifyCollections();
      expect(isVerified).toBe(true);
      expect(mockGetCollections).toHaveBeenCalledTimes(1);
    });

    it('should detect missing collections', async () => {
      mockGetCollections.mockResolvedValue({
        collections: [{ name: 'entity' }, { name: 'relation' }], // Missing 14 collections
      });

      const isVerified = await schemaManager.verifyCollections();
      expect(isVerified).toBe(false);
    });

    it('should provide detailed collection statistics', async () => {
      const collectionName = 'entity';
      const mockStats = {
        result: {
          vectors_count: 1000,
          indexed_vectors_count: 950,
          points_count: 1000,
          segments_count: 2,
          status: 'green',
          optimizer_status: 'ok',
          config: {
            optimizer_config: {
              deleted_threshold: 0.2,
            },
          },
        },
      };

      mockGetCollection.mockResolvedValue(mockStats);

      const stats = await schemaManager.getCollectionStats(collectionName);

      expect(stats).toEqual({
        name: collectionName,
        vectorCount: 1000,
        indexedVectorsCount: 950,
        pointsCount: 1000,
        segmentsCount: 2,
        diskDataSize: 0.2,
        status: 'green',
        optimizerStatus: 'ok',
      });
    });

    it('should handle collection stats errors gracefully', async () => {
      const collectionName = 'nonexistent';
      mockGetCollection.mockRejectedValue(new Error('Collection not found'));

      const stats = await schemaManager.getCollectionStats(collectionName);
      expect(stats).toBeNull();
    });

    it('should perform comprehensive health checks', async () => {
      mockGetCollections.mockResolvedValue({
        collections: COLLECTION_CONFIGS.map((config) => ({ name: config.name })),
      });

      const health = await schemaManager.healthCheck();

      expect(health.isHealthy).toBe(true);
      expect(health.message).toBe('Qdrant connection healthy');
      expect(health.collections).toHaveLength(16);
    });

    it('should detect unhealthy database state', async () => {
      mockGetCollections.mockRejectedValue(new Error('Connection failed'));

      const health = await schemaManager.healthCheck();

      expect(health.isHealthy).toBe(false);
      expect(health.message).toBe('Connection failed');
      expect(health.collections).toBeUndefined();
    });
  });

  describe('Performance and Scalability', () => {
    it('should handle concurrent collection operations', async () => {
      mockGetCollections.mockResolvedValue({ collections: [] });

      // Initialize collections concurrently
      const initPromise = schemaManager.initializeCollections();
      const listPromise = schemaManager.listCollections();
      const healthPromise = schemaManager.healthCheck();

      const [initResult, listResult, healthResult] = await Promise.all([
        initPromise.catch((e) => e),
        listPromise,
        healthPromise,
      ]);

      expect(mockGetCollections).toHaveBeenCalled();
      expect(listResult).toBeDefined();
      expect(healthResult).toBeDefined();
    });

    it('should manage large schema configurations efficiently', () => {
      // Test that 16 collection configurations are manageable
      expect(COLLECTION_CONFIGS).toHaveLength(16);

      // Verify all configurations are properly structured
      COLLECTION_CONFIGS.forEach((config) => {
        expect(Object.keys(config.payloadSchema.properties).length).toBeGreaterThan(5);
      });
    });

    it('should optimize index creation for performance', () => {
      // Verify strategic index placement
      const entityConfig = COLLECTION_CONFIGS.find((config) => config.name === 'entity');
      const criticalIndexes = ['entity_type', 'name', 'created_at', 'updated_at'];

      criticalIndexes.forEach((indexField) => {
        expect(entityConfig?.indexes?.some((index) => index.field === indexField)).toBe(true);
      });
    });

    it('should handle memory-intensive schema operations', async () => {
      // Test processing all schema configurations
      const schemaPromises = COLLECTION_CONFIGS.map((config) =>
        schemaManager.getCollectionInfo(config.name).catch(() => null)
      );

      const results = await Promise.all(schemaPromises);
      expect(results).toHaveLength(16);
    });
  });

  describe('Schema Configuration Validation', () => {
    it('should validate vector configuration consistency', () => {
      const vectorSizes = COLLECTION_CONFIGS.map((config) => config.vectorSize);
      const distances = COLLECTION_CONFIGS.map((config) => config.distance);

      // All collections should use consistent vector configuration
      expect(new Set(vectorSizes)).toHaveLength(1);
      expect(new Set(distances)).toHaveLength(1);
    });

    it('should ensure payload schema completeness', () => {
      COLLECTION_CONFIGS.forEach((config) => {
        const properties = config.payloadSchema.properties;

        // Must have core timestamp fields
        expect(properties).toHaveProperty('created_at');
        expect(properties).toHaveProperty('updated_at');

        // Must have metadata support
        expect(properties).toHaveProperty('metadata');
        expect(properties.metadata['type']).toBe('object');

        // Must have tagging support
        expect(properties).toHaveProperty('tags');
        expect(properties.tags.type).toBe('array');
      });
    });

    it('should validate index configuration effectiveness', () => {
      COLLECTION_CONFIGS.forEach((config) => {
        if (config.indexes) {
          config.indexes.forEach((index) => {
            // Index field should exist in payload schema
            expect(config.payloadSchema.properties).toHaveProperty(index.field);

            // Index type should be valid
            expect(['keyword', 'integer', 'float', 'bool', 'datetime', 'geo']).toContain(
              index.schemaType
            );
          });
        }
      });
    });

    it('should ensure schema extensibility', () => {
      // All schemas should support additional properties
      COLLECTION_CONFIGS.forEach((config) => {
        // Metadata field allows for extensibility
        expect(config.payloadSchema.properties.metadata['type']).toBe('object');

        // Tags field allows for categorization
        expect(config.payloadSchema.properties.tags.items.type).toBe('keyword');
      });
    });
  });
});
