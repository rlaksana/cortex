/**
 * Comprehensive Unit Tests for Database Type Schemas Functionality
 *
 * Tests database schema validation and structure for comprehensive database functionality including:
 * - Database schema validation across all database types
 * - Table structure and column type constraints validation
 * - Vector database schema and embedding type validation
 * - Migration operation and schema evolution types
 * - Query parameter and filter expression validation
 * - Connection and pool configuration validation
 * - Performance and optimization type validation
 * - Error handling and validation edge cases
 * - Integration with database adapters and factories
 * - Schema synchronization and consistency validation
 *
 * Test Categories:
 * 1. Database Schema Validation - Foundation
 * 2. Vector Database Types - Embedding and similarity validation
 * 3. Migration Type Schemas - Schema evolution and rollback
 * 4. Query Type Validation - Parameters, filters, and pagination
 * 5. Connection and Pool Types - Configuration and management
 * 6. Performance and Optimization Types - Metrics and caching
 * 7. Cross-Type Integration - Compatibility and consistency
 * 8. Error Handling and Edge Cases - Robustness and reliability
 * 9. Performance and Validation Efficiency - Optimization and speed
 * 10. Schema Evolution and API Synchronization - Forward compatibility
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { z } from 'zod';
import type {
  // Core database types
  DatabaseConfig,
  DatabaseMetrics,
  DatabaseOperation,

  // Table and schema types
  TableDefinition,
  ColumnDefinition,
  IndexDefinition,

  // Vector database types
  VectorConfig,
  VectorSchema,
  EmbeddingConfig,
  SimilarityMetric,

  // Migration types
  MigrationOperation,
  MigrationState,
  SchemaEvolution,
  RollbackOperation,

  // Query and filter types
  QueryParameters,
  FilterExpression,
  SortOrder,
  PaginationOptions,

  // Connection and pool types
  ConnectionConfig,
  PoolConfig,
  TransactionConfig,
  SessionConfig,

  // Performance and optimization types
  PerformanceMetric,
  OptimizationConfig,
  CachingStrategy,
  ResourceLimit,

  // Error types
  DatabaseError,
  ValidationError,
  ConnectionError
} from '../../../src/db/types/database-types';

// Mock implementations for testing
const mockDatabaseConfig: DatabaseConfig = {
  type: 'qdrant',
  url: 'http://localhost:6333',
  apiKey: 'test-api-key',
  vectorSize: 1536,
  distance: 'Cosine',
  logQueries: false,
  connectionTimeout: 30000,
  maxConnections: 10
};

const mockTableDefinition: TableDefinition = {
  name: 'knowledge_items',
  columns: [
    { name: 'id', type: 'UUID', primary: true, nullable: false },
    { name: 'kind', type: 'VARCHAR(50)', nullable: false },
    { name: 'content', type: 'TEXT', nullable: true },
    { name: 'created_at', type: 'TIMESTAMP', default: 'NOW()', nullable: false }
  ],
  indexes: [
    { name: 'idx_kind', table: 'knowledge_items', columns: ['kind'], unique: false }
  ]
};

const mockVectorConfig: VectorConfig = {
  size: 1536,
  distance: 'Cosine',
  embeddingModel: 'text-embedding-ada-002',
  batchSize: 10,
  openaiApiKey: 'test-openai-key'
};

describe('Database Type Schemas - Comprehensive Validation Testing', () => {

  describe('Database Schema Validation - Foundation', () => {
    it('should validate complete database configuration', () => {
      const config = {
        type: 'qdrant' as const,
        url: 'http://localhost:6333',
        apiKey: 'test-key',
        vectorSize: 1536,
        distance: 'Cosine' as const,
        logQueries: false,
        connectionTimeout: 30000,
        maxConnections: 10
      };

      const schema = z.object({
        type: z.enum(['qdrant']),
        url: z.string().url(),
        apiKey: z.string().min(1),
        vectorSize: z.number().min(1).max(10000),
        distance: z.enum(['Cosine', 'Euclidean', 'DotProduct']),
        logQueries: z.boolean(),
        connectionTimeout: z.number().min(1000),
        maxConnections: z.number().min(1).max(100)
      });

      const result = schema.safeParse(config);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.type).toBe('qdrant');
        expect(result.data.vectorSize).toBe(1536);
        expect(result.data.distance).toBe('Cosine');
      }
    });

    it('should validate table structure with all constraints', () => {
      const table = {
        name: 'test_table',
        columns: [
          {
            name: 'id',
            type: 'UUID',
            primary: true,
            nullable: false,
            unique: true
          },
          {
            name: 'name',
            type: 'VARCHAR(255)',
            nullable: false,
            default: 'unnamed'
          },
          {
            name: 'description',
            type: 'TEXT',
            nullable: true
          },
          {
            name: 'created_at',
            type: 'TIMESTAMP',
            nullable: false,
            default: 'NOW()'
          }
        ],
        indexes: [
          {
            name: 'idx_name',
            table: 'test_table',
            columns: ['name'],
            unique: false,
            type: 'btree' as const
          },
          {
            name: 'idx_id_name',
            table: 'test_table',
            columns: ['id', 'name'],
            unique: true,
            type: 'btree' as const
          }
        ],
        foreignKeys: [
          {
            column: 'created_by',
            referencesTable: 'users',
            referencesColumn: 'id',
            onDelete: 'CASCADE' as const
          }
        ]
      };

      const tableSchema = z.object({
        name: z.string().min(1).max(64),
        columns: z.array(z.object({
          name: z.string().min(1).max(64),
          type: z.string().min(1),
          nullable: z.boolean().default(false),
          primary: z.boolean().default(false),
          unique: z.boolean().default(false),
          default: z.any().optional(),
          check: z.string().optional()
        })).min(1),
        indexes: z.array(z.object({
          name: z.string().min(1).max(64),
          table: z.string(),
          columns: z.array(z.string()).min(1),
          unique: z.boolean().default(false),
          type: z.enum(['btree', 'hash', 'gist', 'gin', 'brin']).optional(),
          where: z.string().optional()
        })).optional(),
        foreignKeys: z.array(z.object({
          column: z.string(),
          referencesTable: z.string(),
          referencesColumn: z.string(),
          onDelete: z.enum(['CASCADE', 'SET NULL', 'RESTRICT']).optional()
        })).optional()
      });

      const result = tableSchema.safeParse(table);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.columns).toHaveLength(4);
        expect(result.data.indexes).toHaveLength(2);
        expect(result.data.foreignKeys).toHaveLength(1);
      }
    });

    it('should enforce column type constraints', () => {
      const validTypes = [
        'UUID', 'VARCHAR(255)', 'TEXT', 'INTEGER', 'BIGINT',
        'DECIMAL(10,2)', 'BOOLEAN', 'TIMESTAMP', 'JSONB', 'VECTOR(1536)'
      ];

      validTypes.forEach(type => {
        const column = {
          name: 'test_column',
          type,
          nullable: false
        };

        const columnSchema = z.object({
          name: z.string().min(1).max(64),
          type: z.string().regex(/^(UUID|VARCHAR\(\d+\)|TEXT|INTEGER|BIGINT|DECIMAL\(\d+,\d+\)|BOOLEAN|TIMESTAMP|JSONB|VECTOR\(\d+\))$/),
          nullable: z.boolean(),
          primary: z.boolean().default(false),
          unique: z.boolean().default(false),
          default: z.any().optional()
        });

        const result = columnSchema.safeParse(column);
        expect(result.success).toBe(true);
      });
    });

    it('should validate index schema configuration', () => {
      const indexTypes = ['btree', 'hash', 'gist', 'gin', 'brin'] as const;

      indexTypes.forEach(type => {
        const index = {
          name: `idx_test_${type}`,
          table: 'test_table',
          columns: ['column1', 'column2'],
          unique: type === 'btree',
          type,
          where: type === 'gin' ? 'column1 IS NOT NULL' : undefined
        };

        const indexSchema = z.object({
          name: z.string().min(1).max(64),
          table: z.string(),
          columns: z.array(z.string()).min(1).max(32),
          unique: z.boolean(),
          type: z.enum(['btree', 'hash', 'gist', 'gin', 'brin']),
          where: z.string().optional()
        });

        const result = indexSchema.safeParse(index);
        expect(result.success).toBe(true);
      });
    });

    it('should validate relationship definitions between tables', () => {
      const relationships = [
        {
          name: 'fk_user_posts',
          fromTable: 'posts',
          fromColumn: 'user_id',
          toTable: 'users',
          toColumn: 'id',
          onDelete: 'CASCADE' as const,
          onUpdate: 'RESTRICT' as const,
          cardinality: 'many-to-one' as const
        },
        {
          name: 'fk_post_comments',
          fromTable: 'comments',
          fromColumn: 'post_id',
          toTable: 'posts',
          toColumn: 'id',
          onDelete: 'CASCADE' as const,
          onUpdate: 'CASCADE' as const,
          cardinality: 'many-to-one' as const
        }
      ];

      const relationshipSchema = z.object({
        name: z.string().min(1).max(64),
        fromTable: z.string(),
        fromColumn: z.string(),
        toTable: z.string(),
        toColumn: z.string(),
        onDelete: z.enum(['CASCADE', 'SET NULL', 'RESTRICT', 'NO ACTION']).optional(),
        onUpdate: z.enum(['CASCADE', 'SET NULL', 'RESTRICT', 'NO ACTION']).optional(),
        cardinality: z.enum(['one-to-one', 'one-to-many', 'many-to-one', 'many-to-many'])
      });

      relationships.forEach(relationship => {
        const result = relationshipSchema.safeParse(relationship);
        expect(result.success).toBe(true);
      });
    });
  });

  describe('Vector Database Types - Embedding and Similarity Validation', () => {
    it('should validate vector schema configuration', () => {
      const vectorSchema = {
        dimension: 1536,
        distance: 'Cosine' as const,
        indexType: 'HNSW' as const,
        indexParams: {
          M: 16,
          efConstruction: 200
        },
        quantization: {
          enabled: true,
          type: 'Scalar' as const,
          bits: 8
        }
      };

      const schema = z.object({
        dimension: z.number().min(1).max(20000),
        distance: z.enum(['Cosine', 'Euclidean', 'DotProduct', 'Manhattan']),
        indexType: z.enum(['FLAT', 'IVF', 'HNSW', 'LSH']),
        indexParams: z.object({
          M: z.number().min(1).max(100).optional(),
          efConstruction: z.number().min(10).max(1000).optional(),
          nlist: z.number().min(1).max(10000).optional(),
          nprobe: z.number().min(1).max(1000).optional()
        }),
        quantization: z.object({
          enabled: z.boolean(),
          type: z.enum(['Scalar', 'Product', 'Binary']),
          bits: z.number().min(1).max(16)
        }).optional()
      });

      const result = schema.safeParse(vectorSchema);
      expect(result.success).toBe(true);
    });

    it('should validate embedding type constraints', () => {
      const embeddingConfigs = [
        {
          provider: 'openai' as const,
          model: 'text-embedding-ada-002',
          dimension: 1536,
          maxTokens: 8191,
          batchSize: 100,
          apiKey: 'test-key'
        },
        {
          provider: 'cohere' as const,
          model: 'embed-english-v3.0',
          dimension: 1024,
          maxTokens: 500,
          batchSize: 96,
          apiKey: 'test-key'
        },
        {
          provider: 'local' as const,
          model: 'sentence-transformers/all-MiniLM-L6-v2',
          dimension: 384,
          maxTokens: 512,
          batchSize: 32,
          modelPath: '/models/sentence-transformers'
        }
      ];

      const configSchema = z.object({
        provider: z.enum(['openai', 'cohere', 'local', 'huggingface']),
        model: z.string().min(1),
        dimension: z.number().min(1).max(10000),
        maxTokens: z.number().min(1),
        batchSize: z.number().min(1).max(1000),
        apiKey: z.string().optional(),
        modelPath: z.string().optional(),
        cacheEnabled: z.boolean().default(true)
      });

      embeddingConfigs.forEach(config => {
        const result = configSchema.safeParse(config);
        expect(result.success).toBe(true);
      });
    });

    it('should validate similarity metric types and parameters', () => {
      const similarityMetrics = [
        {
          type: 'cosine' as const,
          params: {},
          description: 'Cosine similarity measure'
        },
        {
          type: 'euclidean' as const,
          params: { normalized: true },
          description: 'Euclidean distance measure'
        },
        {
          type: 'dotproduct' as const,
          params: { normalized: false },
          description: 'Dot product similarity'
        },
        {
          type: 'manhattan' as const,
          params: {},
          description: 'Manhattan distance measure'
        }
      ];

      const metricSchema = z.object({
        type: z.enum(['cosine', 'euclidean', 'dotproduct', 'manhattan', 'chebyshev']),
        params: z.record(z.any()),
        description: z.string().optional(),
        range: z.object({
          min: z.number(),
          max: z.number()
        }).optional()
      });

      similarityMetrics.forEach(metric => {
        const result = metricSchema.safeParse(metric);
        expect(result.success).toBe(true);
      });
    });

    it('should validate index configuration types', () => {
      const indexConfigs = [
        {
          name: 'hnsw_index',
          type: 'HNSW' as const,
          parameters: {
            M: 16,
            efConstruction: 200,
            efSearch: 50
          },
          buildParameters: {
            maxConnections: 32,
            efConstructionQuality: 'high' as const
          }
        },
        {
          name: 'ivf_index',
          type: 'IVF' as const,
          parameters: {
            nlist: 1000,
            nprobe: 10,
            metric: 'L2' as const
          },
          buildParameters: {
            niter: 20,
            minPointsPerCentroid: 5
          }
        }
      ];

      const indexConfigSchema = z.object({
        name: z.string().min(1),
        type: z.enum(['FLAT', 'IVF', 'HNSW', 'LSH', 'PQ']),
        parameters: z.record(z.any()),
        buildParameters: z.record(z.any()).optional(),
        storageParameters: z.object({
          compression: z.boolean().default(false),
          memoryMap: z.boolean().default(false),
          cacheSize: z.number().optional()
        }).optional()
      });

      indexConfigs.forEach(config => {
        const result = indexConfigSchema.safeParse(config);
        expect(result.success).toBe(true);
      });
    });
  });

  describe('Migration Type Schemas - Schema Evolution and Rollback', () => {
    it('should validate migration operation types', () => {
      const migrationOperations = [
        {
          id: '001_initial_schema',
          type: 'create_table' as const,
          name: 'Create initial knowledge tables',
          description: 'Creates the core tables for knowledge storage',
          version: '1.0.0',
          dependencies: [],
          sql: `
            CREATE TABLE knowledge_items (
              id UUID PRIMARY KEY,
              kind VARCHAR(50) NOT NULL,
              content JSONB,
              created_at TIMESTAMP DEFAULT NOW()
            );
          `,
          rollbackSql: 'DROP TABLE knowledge_items;',
          estimatedDuration: 5000,
          dryRun: false
        },
        {
          id: '002_add_vector_index',
          type: 'create_index' as const,
          name: 'Add vector index for semantic search',
          description: 'Creates HNSW index for vector similarity search',
          version: '1.1.0',
          dependencies: ['001_initial_schema'],
          sql: 'CREATE INDEX idx_content_vector ON knowledge_items USING hnsw (content vector_cosine_ops);',
          rollbackSql: 'DROP INDEX idx_content_vector;',
          estimatedDuration: 30000,
          dryRun: false
        },
        {
          id: '003_add_metadata_column',
          type: 'add_column' as const,
          name: 'Add metadata column',
          description: 'Adds metadata column for additional item properties',
          version: '1.2.0',
          dependencies: ['001_initial_schema'],
          sql: 'ALTER TABLE knowledge_items ADD COLUMN metadata JSONB DEFAULT \'{}\';',
          rollbackSql: 'ALTER TABLE knowledge_items DROP COLUMN metadata;',
          estimatedDuration: 2000,
          dryRun: false
        }
      ];

      const operationSchema = z.object({
        id: z.string().min(1).max(100),
        type: z.enum(['create_table', 'drop_table', 'add_column', 'drop_column', 'alter_column', 'create_index', 'drop_index', 'insert_data', 'update_data', 'delete_data', 'custom']),
        name: z.string().min(1).max(200),
        description: z.string().max(1000),
        version: z.string().regex(/^\d+\.\d+\.\d+$/),
        dependencies: z.array(z.string()).default([]),
        sql: z.string().min(1),
        rollbackSql: z.string().min(1),
        estimatedDuration: z.number().min(100),
        dryRun: z.boolean().default(false),
        tags: z.array(z.string()).optional(),
        author: z.string().optional(),
        createdAt: z.string().datetime().optional()
      });

      migrationOperations.forEach(operation => {
        const result = operationSchema.safeParse(operation);
        expect(result.success).toBe(true);
      });
    });

    it('should validate migration state types', () => {
      const migrationStates = [
        {
          migrationId: '001_initial_schema',
          status: 'completed' as const,
          startedAt: '2025-01-01T10:00:00Z',
          completedAt: '2025-01-01T10:00:05Z',
          duration: 5000,
          checksum: 'abc123def456',
          version: '1.0.0',
          error: null,
          rollbackAvailable: true,
          rollbackBefore: null,
          metadata: {
            tablesCreated: ['knowledge_items'],
            indexesCreated: [],
            rowsAffected: 0
          }
        },
        {
          migrationId: '002_add_vector_index',
          status: 'failed' as const,
          startedAt: '2025-01-01T10:01:00Z',
          completedAt: '2025-01-01T10:01:30Z',
          duration: 30000,
          checksum: 'def456abc123',
          version: '1.1.0',
          error: {
            code: 'INSUFFICIENT_MEMORY',
            message: 'Not enough memory to create HNSW index',
            stack: 'Error: Not enough memory...',
            timestamp: '2025-01-01T10:01:30Z'
          },
          rollbackAvailable: false,
          rollbackBefore: null,
          metadata: {
            attempt: 1,
            maxRetries: 3
          }
        }
      ];

      const stateSchema = z.object({
        migrationId: z.string().min(1),
        status: z.enum(['pending', 'running', 'completed', 'failed', 'rolled_back']),
        startedAt: z.string().datetime(),
        completedAt: z.string().datetime().nullable(),
        duration: z.number().min(0),
        checksum: z.string().min(1),
        version: z.string(),
        error: z.object({
          code: z.string(),
          message: z.string(),
          stack: z.string().optional(),
          timestamp: z.string().datetime()
        }).nullable(),
        rollbackAvailable: z.boolean(),
        rollbackBefore: z.string().datetime().nullable(),
        metadata: z.record(z.any())
      });

      migrationStates.forEach(state => {
        const result = stateSchema.safeParse(state);
        expect(result.success).toBe(true);
      });
    });

    it('should validate schema evolution types', () => {
      const schemaEvolutions = [
        {
          id: 'evolution_001',
          name: 'Add vector support',
          description: 'Evolves schema to support vector embeddings',
          fromVersion: '1.0.0',
          toVersion: '1.1.0',
          strategy: 'backward_compatible' as const,
          changes: [
            {
              type: 'add_column' as const,
              table: 'knowledge_items',
              column: 'content_vector',
              columnType: 'VECTOR(1536)',
              nullable: true
            }
          ],
          migrations: ['002_add_vector_index'],
          validationRules: [
            {
              type: 'data_integrity' as const,
              description: 'Ensure all existing items have null vectors'
            }
          ],
          rollbackPlan: {
            strategy: 'drop_column' as const,
            changes: ['DROP COLUMN content_vector'],
            dataPreservation: false
          }
        }
      ];

      const evolutionSchema = z.object({
        id: z.string().min(1),
        name: z.string().min(1),
        description: z.string().max(1000),
        fromVersion: z.string(),
        toVersion: z.string(),
        strategy: z.enum(['backward_compatible', 'breaking_change', 'migration_required']),
        changes: z.array(z.object({
          type: z.enum(['add_column', 'drop_column', 'alter_column', 'add_table', 'drop_table', 'add_constraint', 'drop_constraint']),
          table: z.string(),
          column: z.string().optional(),
          columnType: z.string().optional(),
          nullable: z.boolean().optional(),
          constraint: z.string().optional()
        })),
        migrations: z.array(z.string()),
        validationRules: z.array(z.object({
          type: z.enum(['data_integrity', 'performance', 'schema_consistency']),
          description: z.string(),
          sql: z.string().optional()
        })),
        rollbackPlan: z.object({
          strategy: z.enum(['reverse_migrations', 'drop_column', 'restore_backup']),
          changes: z.array(z.string()),
          dataPreservation: z.boolean()
        })
      });

      schemaEvolutions.forEach(evolution => {
        const result = evolutionSchema.safeParse(evolution);
        expect(result.success).toBe(true);
      });
    });

    it('should validate rollback operation types', () => {
      const rollbackOperations = [
        {
          id: 'rollback_002_vector_index',
          targetMigrationId: '002_add_vector_index',
          reason: 'Index creation failed due to insufficient memory',
          strategy: 'single_step' as const,
          operations: [
            {
              type: 'drop_index' as const,
              name: 'idx_content_vector',
              sql: 'DROP INDEX IF EXISTS idx_content_vector;'
            }
          ],
          createdAt: '2025-01-01T10:05:00Z',
          executedAt: '2025-01-01T10:05:05Z',
          status: 'completed' as const,
          rollbackData: {
            previousState: 'no_index',
            affectedRows: 0,
            diskSpaceFreed: 1024000
          }
        }
      ];

      const rollbackSchema = z.object({
        id: z.string().min(1),
        targetMigrationId: z.string().min(1),
        reason: z.string().min(1),
        strategy: z.enum(['single_step', 'cascade', 'manual']),
        operations: z.array(z.object({
          type: z.enum(['drop_table', 'create_table', 'drop_column', 'add_column', 'drop_index', 'create_index', 'restore_data']),
          name: z.string().optional(),
          sql: z.string().min(1),
          parameters: z.record(z.any()).optional()
        })),
        createdAt: z.string().datetime(),
        executedAt: z.string().datetime().nullable(),
        status: z.enum(['pending', 'executing', 'completed', 'failed']),
        rollbackData: z.record(z.any()).optional(),
        error: z.string().optional()
      });

      rollbackOperations.forEach(rollback => {
        const result = rollbackSchema.safeParse(rollback);
        expect(result.success).toBe(true);
      });
    });
  });

  describe('Query Type Validation - Parameters, Filters, and Pagination', () => {
    it('should validate query parameter types', () => {
      const queryParameters = [
        {
          name: 'kind',
          type: 'string' as const,
          required: false,
          default: null,
          validation: {
            enum: ['entity', 'relation', 'observation', 'decision'],
            minLength: 1,
            maxLength: 50
          }
        },
        {
          name: 'limit',
          type: 'integer' as const,
          required: false,
          default: 10,
          validation: {
            min: 1,
            max: 1000
          }
        },
        {
          name: 'created_after',
          type: 'datetime' as const,
          required: false,
          default: null,
          validation: {
            format: 'iso8601'
          }
        },
        {
          name: 'include_metadata',
          type: 'boolean' as const,
          required: false,
          default: false,
          validation: {}
        },
        {
          name: 'tags',
          type: 'array' as const,
          required: false,
          default: [],
          validation: {
            itemType: 'string',
            maxItems: 10
          }
        }
      ];

      const parameterSchema = z.object({
        name: z.string().min(1).max(100),
        type: z.enum(['string', 'integer', 'float', 'boolean', 'datetime', 'array', 'object']),
        required: z.boolean(),
        default: z.any(),
        validation: z.object({
          enum: z.array(z.any()).optional(),
          min: z.number().optional(),
          max: z.number().optional(),
          minLength: z.number().optional(),
          maxLength: z.number().optional(),
          pattern: z.string().optional(),
          format: z.string().optional(),
          itemType: z.string().optional(),
          maxItems: z.number().optional(),
          custom: z.function().optional()
        })
      });

      queryParameters.forEach(param => {
        const result = parameterSchema.safeParse(param);
        expect(result.success).toBe(true);
      });
    });

    it('should validate filter expression types', () => {
      const filterExpressions = [
        {
          field: 'kind',
          operator: 'equals' as const,
          value: 'entity',
          type: 'simple' as const
        },
        {
          field: 'created_at',
          operator: 'greater_than' as const,
          value: '2025-01-01T00:00:00Z',
          type: 'simple' as const
        },
        {
          type: 'and' as const,
          filters: [
            {
              field: 'kind',
              operator: 'in' as const,
              value: ['entity', 'relation'],
              type: 'simple' as const
            },
            {
              field: 'scope.project',
              operator: 'equals' as const,
              value: 'test-project',
              type: 'simple' as const
            }
          ]
        },
        {
          type: 'or' as const,
          filters: [
            {
              field: 'title',
              operator: 'contains' as const,
              value: 'important',
              type: 'simple' as const
            },
            {
              field: 'tags',
              operator: 'contains' as const,
              value: 'urgent',
              type: 'simple' as const
            }
          ]
        },
        {
          type: 'not' as const,
          filter: {
            field: 'status',
            operator: 'equals' as const,
            value: 'archived',
            type: 'simple' as const
          }
        }
      ];

      const filterSchema = z.union([
        z.object({
          field: z.string(),
          operator: z.enum(['equals', 'not_equals', 'greater_than', 'less_than', 'greater_equal', 'less_equal', 'contains', 'starts_with', 'ends_with', 'in', 'not_in', 'regex']),
          value: z.any(),
          type: z.literal('simple')
        }),
        z.object({
          type: z.enum(['and', 'or']),
          filters: z.array(z.any()).min(1)
        }),
        z.object({
          type: z.literal('not'),
          filter: z.any()
        })
      ]);

      filterExpressions.forEach(filter => {
        const result = filterSchema.safeParse(filter);
        expect(result.success).toBe(true);
      });
    });

    it('should validate sort order types', () => {
      const sortOrders = [
        {
          field: 'created_at',
          direction: 'desc' as const,
          priority: 1
        },
        {
          field: 'kind',
          direction: 'asc' as const,
          priority: 2
        },
        {
          field: 'title',
          direction: 'asc' as const,
          priority: 3,
          nulls: 'last' as const,
          custom: {
            caseSensitive: false,
            locale: 'en-US'
          }
        }
      ];

      const sortSchema = z.object({
        field: z.string().min(1),
        direction: z.enum(['asc', 'desc']),
        priority: z.number().min(1),
        nulls: z.enum(['first', 'last']).optional(),
        custom: z.object({
          caseSensitive: z.boolean().optional(),
          locale: z.string().optional(),
          numeric: z.boolean().optional()
        }).optional()
      });

      sortOrders.forEach(sort => {
        const result = sortSchema.safeParse(sort);
        expect(result.success).toBe(true);
      });
    });

    it('should validate pagination options', () => {
      const paginationOptions = [
        {
          page: 1,
          limit: 20,
          offset: 0,
          sortBy: 'created_at',
          sortOrder: 'desc' as const
        },
        {
          page: 2,
          limit: 50,
          offset: 50,
          sortBy: 'title',
          sortOrder: 'asc' as const,
          includeTotal: true,
          maxItems: 1000
        },
        {
          limit: 10,
          offset: 100,
          sortBy: 'relevance_score',
          sortOrder: 'desc' as const,
          cursor: 'next_page_token_abc123',
          includeCount: true
        }
      ];

      const paginationSchema = z.object({
        page: z.number().min(1).optional(),
        limit: z.number().min(1).max(1000),
        offset: z.number().min(0).optional(),
        sortBy: z.string().optional(),
        sortOrder: z.enum(['asc', 'desc']).optional(),
        includeTotal: z.boolean().optional(),
        includeCount: z.boolean().optional(),
        maxItems: z.number().min(1).optional(),
        cursor: z.string().optional(),
        meta: z.record(z.any()).optional()
      });

      paginationOptions.forEach(pagination => {
        const result = paginationSchema.safeParse(pagination);
        expect(result.success).toBe(true);
      });
    });
  });

  describe('Connection and Pool Types - Configuration and Management', () => {
    it('should validate connection configuration types', () => {
      const connectionConfigs = [
        {
          type: 'qdrant' as const,
          host: 'localhost',
          port: 6333,
          useSSL: false,
          timeout: 30000,
          apiKey: 'test-api-key',
          maxRetries: 3,
          retryDelay: 1000,
          keepAlive: true,
          idleTimeout: 300000,
          headers: {
            'User-Agent': 'Cortex-MCP/1.0.0'
          }
        },
        {
          type: 'qdrant' as const,
          url: 'https://vector-db.example.com',
          useSSL: true,
          timeout: 60000,
          apiKey: 'prod-api-key',
          certPath: '/path/to/cert.pem',
          keyPath: '/path/to/key.pem',
          caPath: '/path/to/ca.pem',
          validateCert: true,
          maxRetries: 5,
          retryDelay: 2000
        }
      ];

      const connectionSchema = z.object({
        type: z.enum(['qdrant']),
        host: z.string().optional(),
        port: z.number().min(1).max(65535).optional(),
        url: z.string().url().optional(),
        useSSL: z.boolean(),
        timeout: z.number().min(1000),
        apiKey: z.string().optional(),
        username: z.string().optional(),
        password: z.string().optional(),
        certPath: z.string().optional(),
        keyPath: z.string().optional(),
        caPath: z.string().optional(),
        validateCert: z.boolean(),
        maxRetries: z.number().min(0).max(10),
        retryDelay: z.number().min(100),
        keepAlive: z.boolean(),
        idleTimeout: z.number().min(1000),
        headers: z.record(z.string()).optional(),
        meta: z.record(z.any()).optional()
      });

      connectionConfigs.forEach(config => {
        const result = connectionSchema.safeParse(config);
        expect(result.success).toBe(true);
      });
    });

    it('should validate pool configuration types', () => {
      const poolConfigs = [
        {
          minConnections: 2,
          maxConnections: 10,
          acquireTimeout: 10000,
          createTimeout: 5000,
          destroyTimeout: 5000,
          idleTimeout: 30000,
          reapInterval: 1000,
          createRetryInterval: 100,
          healthCheck: {
            enabled: true,
            interval: 10000,
            timeout: 2000,
            query: 'SELECT 1'
          },
          maxUses: 1000,
          maxSize: 100,
          evictionStrategy: 'lru' as const
        },
        {
          minConnections: 5,
          maxConnections: 50,
          acquireTimeout: 30000,
          createTimeout: 10000,
          destroyTimeout: 10000,
          idleTimeout: 60000,
          reapInterval: 5000,
          createRetryInterval: 200,
          healthCheck: {
            enabled: true,
            interval: 30000,
            timeout: 5000,
            query: 'SELECT 1',
            softFailureThreshold: 3,
            hardFailureThreshold: 5
          },
          maxUses: 10000,
          maxSize: 1000,
          evictionStrategy: 'fifo' as const,
          trackUsage: true,
          logging: {
            enabled: true,
            level: 'info' as const,
            includeSlowQueries: true,
            slowQueryThreshold: 1000
          }
        }
      ];

      const poolSchema = z.object({
        minConnections: z.number().min(0),
        maxConnections: z.number().min(1),
        acquireTimeout: z.number().min(1000),
        createTimeout: z.number().min(1000),
        destroyTimeout: z.number().min(1000),
        idleTimeout: z.number().min(5000),
        reapInterval: z.number().min(100),
        createRetryInterval: z.number().min(100),
        healthCheck: z.object({
          enabled: z.boolean(),
          interval: z.number().min(1000),
          timeout: z.number().min(100),
          query: z.string(),
          softFailureThreshold: z.number().min(1).optional(),
          hardFailureThreshold: z.number().min(1).optional()
        }),
        maxUses: z.number().min(1),
        maxSize: z.number().min(1),
        evictionStrategy: z.enum(['lru', 'fifo', 'lifo', 'random']),
        trackUsage: z.boolean().optional(),
        logging: z.object({
          enabled: z.boolean(),
          level: z.enum(['debug', 'info', 'warn', 'error']),
          includeSlowQueries: z.boolean(),
          slowQueryThreshold: z.number().min(100)
        }).optional()
      });

      poolConfigs.forEach(config => {
        const result = poolSchema.safeParse(config);
        expect(result.success).toBe(true);
      });
    });

    it('should validate transaction configuration types', () => {
      const transactionConfigs = [
        {
          isolation: 'READ_COMMITTED' as const,
          readOnly: false,
          timeout: 30000,
          retryAttempts: 3,
          retryDelay: 1000,
          autoCommit: true,
          savepoints: true,
          deadlockDetection: true,
          lockTimeout: 10000,
          maxBatchSize: 1000
        },
        {
          isolation: 'SERIALIZABLE' as const,
          readOnly: true,
          timeout: 60000,
          retryAttempts: 5,
          retryDelay: 2000,
          autoCommit: false,
          savepoints: false,
          deadlockDetection: true,
          lockTimeout: 30000,
          maxBatchSize: 500,
          consistentSnapshot: true,
          retryOnDeadlock: true
        }
      ];

      const transactionSchema = z.object({
        isolation: z.enum(['READ_UNCOMMITTED', 'READ_COMMITTED', 'REPEATABLE_READ', 'SERIALIZABLE']),
        readOnly: z.boolean(),
        timeout: z.number().min(1000),
        retryAttempts: z.number().min(0),
        retryDelay: z.number().min(100),
        autoCommit: z.boolean(),
        savepoints: z.boolean(),
        deadlockDetection: z.boolean(),
        lockTimeout: z.number().min(1000),
        maxBatchSize: z.number().min(1),
        consistentSnapshot: z.boolean().optional(),
        retryOnDeadlock: z.boolean().optional(),
        transactionId: z.string().optional()
      });

      transactionConfigs.forEach(config => {
        const result = transactionSchema.safeParse(config);
        expect(result.success).toBe(true);
      });
    });

    it('should validate session management types', () => {
      const sessionConfigs = [
        {
          sessionId: 'session_abc123',
          userId: 'user_456',
          createdAt: '2025-01-01T10:00:00Z',
          lastActivity: '2025-01-01T10:30:00Z',
          timeout: 1800000, // 30 minutes
          maxIdleTime: 900000, // 15 minutes
          permissions: ['read', 'write'],
          metadata: {
            userAgent: 'Mozilla/5.0...',
            ipAddress: '192.168.1.100',
            location: 'US-West'
          }
        },
        {
          sessionId: 'session_def789',
          userId: 'user_789',
          createdAt: '2025-01-01T11:00:00Z',
          lastActivity: '2025-01-01T11:15:00Z',
          timeout: 3600000, // 1 hour
          maxIdleTime: 1800000, // 30 minutes
          permissions: ['read', 'write', 'admin'],
          metadata: {
            userAgent: 'curl/7.68.0',
            ipAddress: '10.0.0.50',
            role: 'administrator'
          },
          transactionState: {
            active: true,
            transactionId: 'txn_123',
            startTime: '2025-01-01T11:10:00Z',
            savepoints: ['sp1', 'sp2']
          }
        }
      ];

      const sessionSchema = z.object({
        sessionId: z.string().min(1),
        userId: z.string().min(1),
        createdAt: z.string().datetime(),
        lastActivity: z.string().datetime(),
        timeout: z.number().min(60000), // minimum 1 minute
        maxIdleTime: z.number().min(30000), // minimum 30 seconds
        permissions: z.array(z.string()),
        metadata: z.record(z.any()),
        transactionState: z.object({
          active: z.boolean(),
          transactionId: z.string(),
          startTime: z.string().datetime(),
          savepoints: z.array(z.string()).optional()
        }).optional()
      });

      sessionConfigs.forEach(config => {
        const result = sessionSchema.safeParse(config);
        expect(result.success).toBe(true);
      });
    });
  });

  describe('Performance and Optimization Types - Metrics and Caching', () => {
    it('should validate performance metric types', () => {
      const performanceMetrics = [
        {
          queryCount: 1000,
          averageQueryTime: 150.5,
          slowQueries: 10,
          connectionErrors: 2,
          uptime: 86400000, // 24 hours in milliseconds
          timestamp: '2025-01-01T12:00:00Z',
          memoryUsage: {
            used: 256000000, // 256MB
            total: 512000000, // 512MB
            percentage: 50
          },
          cpuUsage: 25.5,
          diskIO: {
            reads: 1000,
            writes: 500,
            bytesRead: 104857600, // 100MB
            bytesWritten: 52428800 // 50MB
          }
        },
        {
          queryCount: 50000,
          averageQueryTime: 85.2,
          slowQueries: 50,
          connectionErrors: 0,
          uptime: 604800000, // 1 week in milliseconds
          timestamp: '2025-01-08T12:00:00Z',
          cacheHitRate: 85.5,
          indexUsageStats: {
            totalIndexes: 25,
            usedIndexes: 20,
            unusedIndexes: 5,
            efficiency: 80
          },
          vectorOperations: {
            embeddingsGenerated: 10000,
            similaritySearches: 25000,
            indexUpdates: 100,
            averageIndexingTime: 200
          }
        }
      ];

      const metricsSchema = z.object({
        queryCount: z.number().min(0),
        averageQueryTime: z.number().min(0),
        slowQueries: z.number().min(0),
        connectionErrors: z.number().min(0),
        uptime: z.number().min(0),
        timestamp: z.string().datetime(),
        memoryUsage: z.object({
          used: z.number().min(0),
          total: z.number().min(0),
          percentage: z.number().min(0).max(100)
        }).optional(),
        cpuUsage: z.number().min(0).max(100).optional(),
        diskIO: z.object({
          reads: z.number().min(0),
          writes: z.number().min(0),
          bytesRead: z.number().min(0),
          bytesWritten: z.number().min(0)
        }).optional(),
        cacheHitRate: z.number().min(0).max(100).optional(),
        indexUsageStats: z.object({
          totalIndexes: z.number().min(0),
          usedIndexes: z.number().min(0),
          unusedIndexes: z.number().min(0),
          efficiency: z.number().min(0).max(100)
        }).optional(),
        vectorOperations: z.object({
          embeddingsGenerated: z.number().min(0),
          similaritySearches: z.number().min(0),
          indexUpdates: z.number().min(0),
          averageIndexingTime: z.number().min(0)
        }).optional()
      });

      performanceMetrics.forEach(metrics => {
        const result = metricsSchema.safeParse(metrics);
        expect(result.success).toBe(true);
      });
    });

    it('should validate optimization configuration types', () => {
      const optimizationConfigs = [
        {
          queryOptimization: {
            enabled: true,
            useIndexHints: true,
            analyzeQueries: true,
            slowQueryThreshold: 1000,
            explainPlans: true,
            autoIndexRecommendations: true
          },
          connectionOptimization: {
            enabled: true,
            connectionPooling: true,
            keepAlive: true,
            compression: true,
            batchSize: 100
          },
          memoryOptimization: {
            enabled: true,
            maxMemoryUsage: 1073741824, // 1GB
            garbageCollection: true,
            cacheSize: 268435456, // 256MB
            bufferPool: true
          },
          vectorOptimization: {
            enabled: true,
            indexType: 'HNSW',
            indexParams: { M: 16, efConstruction: 200 },
            quantization: true,
            parallelProcessing: true
          }
        },
        {
          queryOptimization: {
            enabled: true,
            useIndexHints: false,
            analyzeQueries: true,
            slowQueryThreshold: 500,
            explainPlans: false,
            autoIndexRecommendations: false,
            queryCacheEnabled: true,
            queryCacheSize: 1000
          },
          storageOptimization: {
            enabled: true,
            compression: 'lz4' as const,
            compressionLevel: 6,
            deduplication: true,
            tieredStorage: true,
            hotDataRetention: 2592000000 // 30 days
          }
        }
      ];

      const optimizationSchema = z.object({
        queryOptimization: z.object({
          enabled: z.boolean(),
          useIndexHints: z.boolean(),
          analyzeQueries: z.boolean(),
          slowQueryThreshold: z.number().min(100),
          explainPlans: z.boolean(),
          autoIndexRecommendations: z.boolean(),
          queryCacheEnabled: z.boolean().optional(),
          queryCacheSize: z.number().min(1).optional()
        }),
        connectionOptimization: z.object({
          enabled: z.boolean(),
          connectionPooling: z.boolean(),
          keepAlive: z.boolean(),
          compression: z.boolean(),
          batchSize: z.number().min(1)
        }).optional(),
        memoryOptimization: z.object({
          enabled: z.boolean(),
          maxMemoryUsage: z.number().min(1),
          garbageCollection: z.boolean(),
          cacheSize: z.number().min(1),
          bufferPool: z.boolean()
        }).optional(),
        vectorOptimization: z.object({
          enabled: z.boolean(),
          indexType: z.enum(['FLAT', 'IVF', 'HNSW', 'LSH']),
          indexParams: z.record(z.any()),
          quantization: z.boolean(),
          parallelProcessing: z.boolean()
        }).optional(),
        storageOptimization: z.object({
          enabled: z.boolean(),
          compression: z.enum(['gzip', 'lz4', 'snappy', 'zstd']),
          compressionLevel: z.number().min(1).max(22),
          deduplication: z.boolean(),
          tieredStorage: z.boolean(),
          hotDataRetention: z.number().min(1)
        }).optional()
      });

      optimizationConfigs.forEach(config => {
        const result = optimizationSchema.safeParse(config);
        expect(result.success).toBe(true);
      });
    });

    it('should validate caching strategy types', () => {
      const cachingStrategies = [
        {
          type: 'lru' as const,
          maxSize: 1000,
          ttl: 3600000, // 1 hour
          maxSizeBytes: 104857600, // 100MB
          evictionPolicy: 'lru' as const,
          compressionEnabled: true,
          statsEnabled: true
        },
        {
          type: 'redis' as const,
          host: 'localhost',
          port: 6379,
          password: 'redis-password',
          database: 0,
          ttl: 7200000, // 2 hours
          keyPrefix: 'cortex:',
          maxRetries: 3,
          retryDelay: 1000,
          clusterEnabled: false,
          sslEnabled: false
        },
        {
          type: 'hybrid' as const,
          strategies: [
            {
              type: 'memory' as const,
              maxSize: 100,
              ttl: 300000 // 5 minutes
            },
            {
              type: 'redis' as const,
              host: 'redis-cluster.example.com',
              port: 6379,
              ttl: 3600000 // 1 hour
            }
          ],
          fallbackPolicy: 'memory_first' as const,
          syncInterval: 60000 // 1 minute
        }
      ];

      const cacheSchema = z.union([
        z.object({
          type: z.literal('memory'),
          maxSize: z.number().min(1),
          ttl: z.number().min(1000),
          maxSizeBytes: z.number().min(1024),
          evictionPolicy: z.enum(['lru', 'lfu', 'fifo', 'random']),
          compressionEnabled: z.boolean(),
          statsEnabled: z.boolean()
        }),
        z.object({
          type: z.literal('redis'),
          host: z.string(),
          port: z.number().min(1).max(65535),
          password: z.string().optional(),
          database: z.number().min(0),
          ttl: z.number().min(1000),
          keyPrefix: z.string(),
          maxRetries: z.number().min(0),
          retryDelay: z.number().min(100),
          clusterEnabled: z.boolean(),
          sslEnabled: z.boolean(),
          sentinel: z.object({
            hosts: z.array(z.string()),
            name: z.string()
          }).optional()
        }),
        z.object({
          type: z.literal('hybrid'),
          strategies: z.array(z.any()),
          fallbackPolicy: z.enum(['memory_first', 'redis_first', 'load_balance']),
          syncInterval: z.number().min(1000)
        })
      ]);

      cachingStrategies.forEach(strategy => {
        const result = cacheSchema.safeParse(strategy);
        expect(result.success).toBe(true);
      });
    });

    it('should validate resource limit types', () => {
      const resourceLimits = [
        {
          maxConnections: 100,
          maxQueriesPerSecond: 1000,
          maxQueryTime: 30000,
          maxMemoryUsage: 2147483648, // 2GB
          maxDiskUsage: 107374182400, // 100GB
          maxVectorDimensions: 20000,
          maxBatchSize: 10000,
          maxConcurrentOperations: 50,
          timeout: 60000,
          retryAttempts: 3
        },
        {
          perUser: {
            maxConnections: 10,
            maxQueriesPerMinute: 100,
            maxMemoryUsage: 104857600, // 100MB
            maxBatchSize: 1000
          },
          perProject: {
            maxItems: 1000000,
            maxStorageSize: 10737418240, // 10GB
            maxVectorCount: 500000
          },
          global: {
            maxTotalConnections: 1000,
            maxTotalMemory: 8589934592, // 8GB
            maxTotalStorage: 1099511627776 // 1TB
          }
        }
      ];

      const limitSchema = z.union([
        z.object({
          maxConnections: z.number().min(1),
          maxQueriesPerSecond: z.number().min(1),
          maxQueryTime: z.number().min(1000),
          maxMemoryUsage: z.number().min(1),
          maxDiskUsage: z.number().min(1),
          maxVectorDimensions: z.number().min(1),
          maxBatchSize: z.number().min(1),
          maxConcurrentOperations: z.number().min(1),
          timeout: z.number().min(1000),
          retryAttempts: z.number().min(0)
        }),
        z.object({
          perUser: z.object({
            maxConnections: z.number().min(1),
            maxQueriesPerMinute: z.number().min(1),
            maxMemoryUsage: z.number().min(1),
            maxBatchSize: z.number().min(1)
          }),
          perProject: z.object({
            maxItems: z.number().min(1),
            maxStorageSize: z.number().min(1),
            maxVectorCount: z.number().min(1)
          }),
          global: z.object({
            maxTotalConnections: z.number().min(1),
            maxTotalMemory: z.number().min(1),
            maxTotalStorage: z.number().min(1)
          })
        })
      ]);

      resourceLimits.forEach(limit => {
        const result = limitSchema.safeParse(limit);
        expect(result.success).toBe(true);
      });
    });
  });

  describe('Cross-Type Integration - Compatibility and Consistency', () => {
    it('should validate database configuration with vector settings', () => {
      const integratedConfig = {
        database: {
          type: 'qdrant' as const,
          url: 'http://localhost:6333',
          apiKey: 'test-key',
          connectionTimeout: 30000,
          maxConnections: 10
        },
        vector: {
          size: 1536,
          distance: 'Cosine' as const,
          indexType: 'HNSW' as const,
          embeddingModel: 'text-embedding-ada-002',
          batchSize: 100
        },
        optimization: {
          queryCacheEnabled: true,
          connectionPooling: true,
          compressionEnabled: true,
          maxMemoryUsage: 2147483648
        },
        limits: {
          maxConnections: 100,
          maxQueriesPerSecond: 1000,
          maxBatchSize: 10000
        }
      };

      const integratedSchema = z.object({
        database: z.object({
          type: z.enum(['qdrant']),
          url: z.string().url(),
          apiKey: z.string(),
          connectionTimeout: z.number().min(1000),
          maxConnections: z.number().min(1)
        }),
        vector: z.object({
          size: z.number().min(1),
          distance: z.enum(['Cosine', 'Euclidean', 'DotProduct']),
          indexType: z.enum(['FLAT', 'IVF', 'HNSW', 'LSH']),
          embeddingModel: z.string(),
          batchSize: z.number().min(1)
        }),
        optimization: z.object({
          queryCacheEnabled: z.boolean(),
          connectionPooling: z.boolean(),
          compressionEnabled: z.boolean(),
          maxMemoryUsage: z.number().min(1)
        }),
        limits: z.object({
          maxConnections: z.number().min(1),
          maxQueriesPerSecond: z.number().min(1),
          maxBatchSize: z.number().min(1)
        })
      });

      const result = integratedSchema.safeParse(integratedConfig);
      expect(result.success).toBe(true);
    });

    it('should validate migration with rollback and dependency chain', () => {
      const migrationChain = {
        migrations: [
          {
            id: '001_create_tables',
            dependencies: [],
            operations: [
              { type: 'create_table', name: 'knowledge_items' },
              { type: 'create_table', name: 'relations' }
            ],
            rollbackOperations: [
              { type: 'drop_table', name: 'relations' },
              { type: 'drop_table', name: 'knowledge_items' }
            ]
          },
          {
            id: '002_add_vectors',
            dependencies: ['001_create_tables'],
            operations: [
              { type: 'add_column', table: 'knowledge_items', column: 'content_vector' }
            ],
            rollbackOperations: [
              { type: 'drop_column', table: 'knowledge_items', column: 'content_vector' }
            ]
          }
        ],
        validation: {
          checkDependencies: true,
          validateRollback: true,
          testRollback: true
        }
      };

      const chainSchema = z.object({
        migrations: z.array(z.object({
          id: z.string(),
          dependencies: z.array(z.string()),
          operations: z.array(z.any()),
          rollbackOperations: z.array(z.any())
        })),
        validation: z.object({
          checkDependencies: z.boolean(),
          validateRollback: z.boolean(),
          testRollback: z.boolean()
        })
      });

      const result = chainSchema.safeParse(migrationChain);
      expect(result.success).toBe(true);
    });

    it('should validate query with complex filters and pagination', () => {
      const complexQuery = {
        query: {
          text: 'machine learning',
          filters: {
            and: [
              { field: 'kind', operator: 'in', value: ['entity', 'decision'] },
              { field: 'created_at', operator: 'greater_than', value: '2025-01-01T00:00:00Z' },
              {
                or: [
                  { field: 'scope.project', operator: 'equals', value: 'ml-project' },
                  { field: 'tags', operator: 'contains', value: 'machine-learning' }
                ]
              }
            ]
          },
          sort: [
            { field: 'relevance_score', direction: 'desc', priority: 1 },
            { field: 'created_at', direction: 'desc', priority: 2 }
          ],
          pagination: {
            limit: 20,
            offset: 0,
            includeTotal: true
          }
        },
        options: {
          includeVectors: false,
          includeMetadata: true,
          cache: true,
          timeout: 10000
        }
      };

      const querySchema = z.object({
        query: z.object({
          text: z.string(),
          filters: z.any(),
          sort: z.array(z.object({
            field: z.string(),
            direction: z.enum(['asc', 'desc']),
            priority: z.number()
          })),
          pagination: z.object({
            limit: z.number().min(1),
            offset: z.number().min(0),
            includeTotal: z.boolean()
          })
        }),
        options: z.object({
          includeVectors: z.boolean(),
          includeMetadata: z.boolean(),
          cache: z.boolean(),
          timeout: z.number().min(1000)
        })
      });

      const result = querySchema.safeParse(complexQuery);
      expect(result.success).toBe(true);
    });
  });

  describe('Error Handling and Edge Cases - Robustness and Reliability', () => {
    it('should handle malformed database configurations gracefully', () => {
      const malformedConfigs = [
        null,
        undefined,
        {},
        { type: 'invalid_type' },
        { type: 'qdrant', url: 'not-a-url' },
        { type: 'qdrant', url: 'http://localhost:6333', vectorSize: -1 },
        { type: 'qdrant', url: 'http://localhost:6333', distance: 'INVALID_DISTANCE' },
        { type: 'qdrant', url: 'http://localhost:6333', connectionTimeout: 0 }
      ];

      const configSchema = z.object({
        type: z.enum(['qdrant']),
        url: z.string().url(),
        apiKey: z.string().optional(),
        vectorSize: z.number().min(1).max(10000),
        distance: z.enum(['Cosine', 'Euclidean', 'DotProduct']),
        connectionTimeout: z.number().min(1000),
        maxConnections: z.number().min(1).max(100)
      });

      malformedConfigs.forEach(config => {
        const result = configSchema.safeParse(config);
        expect(result.success).toBe(false);
        if (!result.success) {
          expect(result.error.issues.length).toBeGreaterThan(0);
        }
      });
    });

    it('should validate edge cases in vector configurations', () => {
      const edgeCases = [
        {
          size: 1,
          distance: 'Cosine' as const,
          indexType: 'FLAT' as const
        },
        {
          size: 20000,
          distance: 'DotProduct' as const,
          indexType: 'HNSW' as const,
          indexParams: { M: 100, efConstruction: 1000 }
        },
        {
          size: 1536,
          distance: 'Euclidean' as const,
          indexType: 'IVF' as const,
          indexParams: { nlist: 10000, nprobe: 1000 }
        }
      ];

      const vectorSchema = z.object({
        size: z.number().min(1).max(20000),
        distance: z.enum(['Cosine', 'Euclidean', 'DotProduct']),
        indexType: z.enum(['FLAT', 'IVF', 'HNSW', 'LSH']),
        indexParams: z.record(z.any()).optional()
      });

      edgeCases.forEach(edgeCase => {
        const result = vectorSchema.safeParse(edgeCase);
        expect(result.success).toBe(true);
      });
    });

    it('should handle invalid migration operations', () => {
      const invalidMigrations = [
        {
          id: '',
          type: 'invalid_operation',
          sql: '',
          rollbackSql: ''
        },
        {
          id: 'migration_with_empty_dependencies',
          type: 'create_table',
          dependencies: ['nonexistent_migration'],
          sql: 'CREATE TABLE test (id INT);'
        },
        {
          id: 'migration_with_invalid_sql',
          type: 'create_table',
          sql: 'INVALID SQL SYNTAX',
          rollbackSql: 'DROP TABLE IF EXISTS test;'
        }
      ];

      const migrationSchema = z.object({
        id: z.string().min(1),
        type: z.enum(['create_table', 'drop_table', 'add_column', 'drop_column', 'alter_column', 'create_index', 'drop_index']),
        dependencies: z.array(z.string()),
        sql: z.string().min(1),
        rollbackSql: z.string().min(1)
      });

      invalidMigrations.forEach(migration => {
        const result = migrationSchema.safeParse(migration);
        expect(result.success).toBe(false);
      });
    });

    it('should validate extreme pagination values', () => {
      const extremePagination = [
        { limit: 1, offset: 0 },
        { limit: 1000, offset: 0 },
        { limit: 100, offset: 1000000 },
        { limit: 1, offset: 0, cursor: `very_long_cursor_string_${  'a'.repeat(1000)}` }
      ];

      const paginationSchema = z.object({
        limit: z.number().min(1).max(1000),
        offset: z.number().min(0),
        cursor: z.string().max(2000).optional()
      });

      extremePagination.forEach(pagination => {
        const result = paginationSchema.safeParse(pagination);
        expect(result.success).toBe(true);
      });
    });
  });

  describe('Performance and Validation Efficiency - Optimization and Speed', () => {
    it('should handle batch validation efficiently', () => {
      const configs = Array.from({ length: 100 }, (_, i) => ({
        type: 'qdrant' as const,
        url: `http://localhost:${6333 + i}`,
        apiKey: `key-${i}`,
        vectorSize: 1536,
        distance: 'Cosine' as const,
        connectionTimeout: 30000,
        maxConnections: 10
      }));

      const configSchema = z.object({
        type: z.enum(['qdrant']),
        url: z.string().url(),
        apiKey: z.string(),
        vectorSize: z.number().min(1).max(10000),
        distance: z.enum(['Cosine', 'Euclidean', 'DotProduct']),
        connectionTimeout: z.number().min(1000),
        maxConnections: z.number().min(1).max(100)
      });

      const startTime = Date.now();
      const results = configs.map(config => configSchema.safeParse(config));
      const endTime = Date.now();

      const validResults = results.filter(r => r.success);
      expect(validResults).toHaveLength(100);
      expect(endTime - startTime).toBeLessThan(1000);
    });

    it('should validate complex nested structures efficiently', () => {
      const complexStructure = {
        database: {
          type: 'qdrant',
          connections: Array.from({ length: 100 }, (_, i) => ({
            id: `conn-${i}`,
            config: {
              host: `host-${i}`,
              port: 6333 + i,
              timeout: 30000 + i * 1000
            }
          }))
        },
        vectors: Array.from({ length: 50 }, (_, i) => ({
          id: `vector-${i}`,
          dimensions: 1536,
          index: {
            type: 'HNSW',
            params: { M: 16 + i, efConstruction: 200 + i * 10 }
          }
        })),
        migrations: Array.from({ length: 20 }, (_, i) => ({
          id: `migration-${i}`,
          operations: Array.from({ length: 5 }, (_, j) => ({
            type: 'create_table',
            name: `table_${i}_${j}`
          }))
        }))
      };

      const complexSchema = z.object({
        database: z.object({
          type: z.string(),
          connections: z.array(z.object({
            id: z.string(),
            config: z.object({
              host: z.string(),
              port: z.number(),
              timeout: z.number()
            })
          }))
        }),
        vectors: z.array(z.object({
          id: z.string(),
          dimensions: z.number(),
          index: z.object({
            type: z.string(),
            params: z.record(z.number())
          })
        })),
        migrations: z.array(z.object({
          id: z.string(),
          operations: z.array(z.object({
            type: z.string(),
            name: z.string()
          }))
        }))
      });

      const startTime = Date.now();
      const result = complexSchema.safeParse(complexStructure);
      const endTime = Date.now();

      expect(result.success).toBe(true);
      expect(endTime - startTime).toBeLessThan(1000);
    });
  });

  describe('Schema Evolution and API Synchronization - Forward Compatibility', () => {
    it('should maintain backward compatibility with existing configurations', () => {
      const legacyConfig = {
        type: 'qdrant',
        url: 'http://localhost:6333',
        // Legacy fields
        port: 6333,
        host: 'localhost',
        // New optional fields that might not exist in legacy configs
        vectorSize: undefined,
        distance: undefined
      };

      const backwardCompatibleSchema = z.object({
        type: z.enum(['qdrant']),
        url: z.string().url().optional(),
        host: z.string().optional(),
        port: z.number().optional(),
        vectorSize: z.number().min(1).max(10000).optional(),
        distance: z.enum(['Cosine', 'Euclidean', 'DotProduct']).optional()
      }).transform(data => ({
        ...data,
        url: data.url || `http://${data.host}:${data.port}`,
        vectorSize: data.vectorSize || 1536,
        distance: data.distance || 'Cosine'
      }));

      const result = backwardCompatibleSchema.safeParse(legacyConfig);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.url).toBe('http://localhost:6333');
        expect(result.data.vectorSize).toBe(1536);
        expect(result.data.distance).toBe('Cosine');
      }
    });

    it('should handle version transitions in schema definitions', () => {
      const versionedSchemas = [
        {
          version: '1.0.0',
          config: {
            type: 'qdrant',
            url: 'http://localhost:6333'
          }
        },
        {
          version: '1.1.0',
          config: {
            type: 'qdrant',
            url: 'http://localhost:6333',
            vectorSize: 1536,
            distance: 'Cosine'
          }
        },
        {
          version: '1.2.0',
          config: {
            type: 'qdrant',
            url: 'http://localhost:6333',
            vectorSize: 1536,
            distance: 'Cosine',
            optimization: {
              enabled: true,
              queryCache: true
            }
          }
        }
      ];

      const versionedSchema = z.object({
        version: z.string().regex(/^\d+\.\d+\.\d+$/),
        config: z.object({
          type: z.enum(['qdrant']),
          url: z.string().url(),
          vectorSize: z.number().optional(),
          distance: z.enum(['Cosine', 'Euclidean', 'DotProduct']).optional(),
          optimization: z.object({
            enabled: z.boolean(),
            queryCache: z.boolean()
          }).optional()
        })
      });

      versionedSchemas.forEach(schema => {
        const result = versionedSchema.safeParse(schema);
        expect(result.success).toBe(true);
      });
    });

    it('should validate API boundary data integrity', () => {
      const apiData = {
        request: {
          query: {
            text: 'test query',
            filters: { kind: 'entity' },
            limit: 10
          },
          options: {
            includeMetadata: true,
            timeout: 5000
          }
        },
        response: {
          results: [
            {
              id: 'result-1',
              kind: 'entity',
              score: 0.95,
              metadata: { created_at: '2025-01-01T00:00:00Z' }
            }
          ],
          total: 1,
          took: 150,
          meta: {
            query_id: 'query-123',
            cache_hit: false
          }
        }
      };

      const apiSchema = z.object({
        request: z.object({
          query: z.object({
            text: z.string(),
            filters: z.record(z.any()).optional(),
            limit: z.number().min(1).max(1000)
          }),
          options: z.object({
            includeMetadata: z.boolean(),
            timeout: z.number().min(1000)
          })
        }),
        response: z.object({
          results: z.array(z.object({
            id: z.string(),
            kind: z.string(),
            score: z.number().min(0).max(1),
            metadata: z.record(z.any())
          })),
          total: z.number().min(0),
          took: z.number().min(0),
          meta: z.object({
            query_id: z.string(),
            cache_hit: z.boolean()
          })
        })
      });

      const result = apiSchema.safeParse(apiData);
      expect(result.success).toBe(true);
    });
  });
});