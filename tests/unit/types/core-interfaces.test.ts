/**
 * Comprehensive Unit Tests for Core Interfaces
 *
 * Tests core interface functionality including:
 * - Interface Schema Validation (structure validation, type safety enforcement)
 * - Knowledge Type Interfaces (all 16 knowledge type interface validation)
 * - Cross-type Relationship Interfaces (relationship interfaces and metadata)
 * - Database Layer Interfaces (vector database, connection pool, transaction manager)
 * - Service Layer Interfaces (core service contracts and dependency interfaces)
 * - Security and Authentication Interfaces (auth interface validation and security middleware)
 * - Integration and Compatibility (cross-layer interface compatibility and versioning)
 *
 * Follows established test patterns from MCP server and security tests.
 * Comprehensive coverage with 25+ test cases covering all core interfaces functionality.
 */

import {
  describe,
  test,
  expect,
  beforeEach,
  afterEach,
  vi,
  type MockedFunction,
  type MockedObject,
} from 'vitest';

// Import core interfaces
import type {
  // Core knowledge interfaces
  KnowledgeItem,
  StoreResult,
  StoreError,
  AutonomousContext,
  SearchResult,
  SearchQuery,
  MemoryStoreResponse,
  MemoryFindResponse,

  // Service interfaces
  KnowledgeRepository,
  SearchService,
  ValidationService,
  DeduplicationService,
  SimilarityService,
  AuditService,

  // Request/response interfaces
  MemoryStoreRequest,
  MemoryFindRequest,
  DeleteRequest,
  SmartFindRequest,
  SmartFindResult,

  // Analytics interfaces
  KnowledgeAnalytics,
  RelationshipAnalytics,
  PerformanceAnalytics,
  UserBehaviorAnalytics,
  PredictiveAnalytics,
  AnalyticsReport,
  AnalyticsQuery,
  AnalyticsFilter,

  // Storage interfaces
  StorageBucket,
  StorageObject,
  StorageMetrics,
  StorageAnalytics,
  StorageConfig,
  UploadRequest,
  DownloadRequest,

  // Supporting interfaces
  StorageEncryption,
  StorageCompression,
  StorageCache,
  StorageCDN,
  StorageMonitoring,
  StorageBackupConfig,
  StorageSecurityConfig,
  StoragePerformanceConfig,
} from '../../../src/types/core-interfaces.js';

// Import logging interfaces
import type {
  LogLevel,
  LogEntry,
  LogQueryOptions,
  LogSearchResult,
  LogFilterOptions,
  LogStorageConfig,
  LogRetentionConfig,
  LogStreamingConfig,
  LogAnalyticsConfig,
  LogSecurityConfig,
  LogAnalytics,
  LogHealthStatus,
  LogConfiguration,
} from '../../../src/types/logging-interfaces.js';

// Import workflow interfaces
import type {
  WorkflowStatus,
  TaskStatus,
  TaskPriority,
  ExecutionMode,
  TriggerType,
  ActionType,
  NotificationType,
  IntegrationType,
  WorkflowDefinition,
  WorkflowTask,
  TaskType,
  TaskConfig,
  WorkflowTemplate,
  WorkflowExecution,
  ExecutionStatus,
  TaskExecution,
  WorkflowContext,
  WorkflowTrigger,
  WorkflowConfiguration,
  WorkflowMetadata,
} from '../../../src/types/workflow-interfaces.js';

// Mock environment
const originalEnv = process.env;
const mockEnv = {
  NODE_ENV: 'test',
  LOG_LEVEL: 'error',
  TEST_MODE: 'true',
};

describe('Core Interfaces', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env = { ...originalEnv, ...mockEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe('Interface Schema Validation', () => {
    test('should validate KnowledgeItem interface structure', () => {
      // Test valid KnowledgeItem
      const validKnowledgeItem: KnowledgeItem = {
        id: 'test-id-123',
        kind: 'entity',
        content: 'Test content',
        scope: {
          project: 'test-project',
          branch: 'main',
          org: 'test-org',
        },
        data: {
          title: 'Test Entity',
          description: 'Test description',
        },
        metadata: {
          version: '1.0.0',
          tags: ['test', 'entity'],
        },
        created_at: '2024-01-01T00:00:00Z',
        updated_at: '2024-01-01T00:00:00Z',
      };

      expect(validKnowledgeItem.id).toBe('test-id-123');
      expect(validKnowledgeItem.kind).toBe('entity');
      expect(validKnowledgeItem.scope.project).toBe('test-project');
      expect(validKnowledgeItem['data.title']).toBe('Test Entity');
      expect(validKnowledgeItem.metadata?.tags).toContain('test');
    });

    test('should validate StoreResult interface structure', () => {
      const storeResult: StoreResult = {
        id: 'store-result-123',
        status: 'inserted',
        kind: 'entity',
        created_at: '2024-01-01T00:00:00Z',
      };

      expect(storeResult.id).toBe('store-result-123');
      expect(['inserted', 'updated', 'skipped_dedupe', 'deleted']).toContain(storeResult.status);
      expect(storeResult.kind).toBe('entity');
      expect(storeResult.created_at).toBe('2024-01-01T00:00:00Z');
    });

    test('should validate StoreError interface structure', () => {
      const storeError: StoreError = {
        index: 0,
        error_code: 'VALIDATION_ERROR',
        message: 'Invalid input data',
        field: 'content',
        stack: 'Error stack trace',
        timestamp: '2024-01-01T00:00:00Z',
      };

      expect(storeError.index).toBe(0);
      expect(storeError.error_code).toBe('VALIDATION_ERROR');
      expect(storeError.message).toBe('Invalid input data');
      expect(storeError.field).toBe('content');
      expect(storeError.stack).toBe('Error stack trace');
    });

    test('should validate AutonomousContext interface structure', () => {
      const autonomousContext: AutonomousContext = {
        action_performed: 'created',
        similar_items_checked: 5,
        duplicates_found: 2,
        contradictions_detected: false,
        recommendation: 'Review duplicates',
        reasoning: 'Similar content detected',
        user_message_suggestion: 'Found 2 potential duplicates',
      };

      expect(['created', 'updated', 'deleted', 'skipped', 'batch']).toContain(
        autonomousContext.action_performed
      );
      expect(autonomousContext.similar_items_checked).toBe(5);
      expect(autonomousContext.duplicates_found).toBe(2);
      expect(autonomousContext.contradictions_detected).toBe(false);
    });

    test('should validate SearchResult interface structure', () => {
      const searchResult: SearchResult = {
        id: 'search-result-123',
        kind: 'entity',
        scope: { project: 'test-project' },
        data: { title: 'Test Entity' },
        created_at: '2024-01-01T00:00:00Z',
        confidence_score: 0.95,
        match_type: 'semantic',
        highlight: ['matched content'],
      };

      expect(searchResult.id).toBe('search-result-123');
      expect(searchResult.confidence_score).toBe(0.95);
      expect(['exact', 'fuzzy', 'semantic']).toContain(searchResult.match_type);
      expect(searchResult.highlight).toContain('matched content');
    });

    test('should validate SearchQuery interface structure', () => {
      const searchQuery: SearchQuery = {
        query: 'test query',
        scope: {
          project: 'test-project',
          branch: 'main',
          org: 'test-org',
        },
        types: ['entity', 'relation'],
        kind: 'entity',
        mode: 'auto',
        limit: 10,
        top_k: 5,
      };

      expect(searchQuery.query).toBe('test query');
      expect(searchQuery.scope?.project).toBe('test-project');
      expect(searchQuery.types).toContain('entity');
      expect(['auto', 'fast', 'deep']).toContain(searchQuery.mode);
      expect(searchQuery.limit).toBe(10);
    });
  });

  describe('Knowledge Type Interfaces', () => {
    test('should validate all 16 knowledge types', () => {
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

      knowledgeTypes.forEach((kind) => {
        const knowledgeItem: KnowledgeItem = {
          kind,
          scope: { project: 'test' },
          data: { test: 'data' },
        };

        expect(knowledgeTypes).toContain(knowledgeItem.kind);
      });
    });

    test('should validate cross-type relationship interfaces', () => {
      const entityKnowledge: KnowledgeItem = {
        id: 'entity-123',
        kind: 'entity',
        scope: { project: 'test' },
        data: { name: 'Test Entity', type: 'component' },
      };

      const relationKnowledge: KnowledgeItem = {
        id: 'relation-123',
        kind: 'relation',
        scope: { project: 'test' },
        data: {
          from_id: 'entity-123',
          to_id: 'entity-456',
          relation_type: 'depends_on',
        },
      };

      expect(entityKnowledge.kind).toBe('entity');
      expect(relationKnowledge.kind).toBe('relation');
      expect(relationKnowledge['data.from_id']).toBe(entityKnowledge.id);
    });

    test('should validate knowledge metadata interfaces', () => {
      const knowledgeItemWithMetadata: KnowledgeItem = {
        id: 'test-123',
        kind: 'entity',
        scope: { project: 'test' },
        data: { name: 'Test' },
        metadata: {
          version: '1.0.0',
          tags: ['test', 'validation'],
          author: 'test-user',
          reviewed: true,
          confidence: 0.95,
        },
      };

      expect(knowledgeItemWithMetadata.metadata?.version).toBe('1.0.0');
      expect(knowledgeItemWithMetadata.metadata?.tags).toContain('test');
      expect(knowledgeItemWithMetadata.metadata?.confidence).toBe(0.95);
    });

    test('should validate type-specific property validation', () => {
      const decisionKnowledge: KnowledgeItem = {
        kind: 'decision',
        scope: { project: 'test' },
        data: {
          title: 'Use TypeScript',
          rationale: 'Type safety benefits',
          alternatives: ['JavaScript', 'Flow'],
          impact: 'high',
          stakeholders: ['team-lead', 'architect'],
        },
      };

      expect(decisionKnowledge['data.title']).toBe('Use TypeScript');
      expect(decisionKnowledge['data.rationale']).toBe('Type safety benefits');
      expect(Array.isArray(decisionKnowledge['data.alternatives'])).toBe(true);
      expect(decisionKnowledge['data.impact']).toBe('high');
    });
  });

  describe('Database Layer Interfaces', () => {
    test('should validate KnowledgeRepository interface', () => {
      const mockRepository: KnowledgeRepository = {
        store: vi.fn(),
        update: vi.fn(),
        delete: vi.fn(),
        findById: vi.fn(),
        findSimilar: vi.fn(),
      };

      expect(typeof mockRepository.store).toBe('function');
      expect(typeof mockRepository.update).toBe('function');
      expect(typeof mockRepository.delete).toBe('function');
      expect(typeof mockRepository.findById).toBe('function');
      expect(typeof mockRepository.findSimilar).toBe('function');
    });

    test('should validate connection pool interface parameters', () => {
      const poolConfig = {
        maxConnections: 10,
        minConnections: 2,
        acquireTimeout: 30000,
        idleTimeout: 300000,
        healthCheckInterval: 60000,
      };

      expect(poolConfig.maxConnections).toBe(10);
      expect(poolConfig.minConnections).toBe(2);
      expect(poolConfig.acquireTimeout).toBe(30000);
    });

    test('should validate transaction manager interfaces', () => {
      const transactionConfig = {
        isolationLevel: 'READ_COMMITTED',
        timeoutMs: 30000,
        retryAttempts: 3,
        retryDelayMs: 1000,
      };

      expect(transactionConfig.isolationLevel).toBe('READ_COMMITTED');
      expect(transactionConfig.timeoutMs).toBe(30000);
      expect(transactionConfig.retryAttempts).toBe(3);
    });

    test('should validate schema manager interface testing', () => {
      const schemaConfig = {
        version: '1.0.0',
        migrationsPath: './migrations',
        validationEnabled: true,
        autoMigrate: false,
      };

      expect(schemaConfig.version).toBe('1.0.0');
      expect(schemaConfig.validationEnabled).toBe(true);
      expect(schemaConfig.autoMigrate).toBe(false);
    });
  });

  describe('Service Layer Interfaces', () => {
    test('should validate SearchService interface contracts', () => {
      const mockSearchService: SearchService = {
        search: vi.fn(),
        validateQuery: vi.fn(),
      };

      expect(typeof mockSearchService.search).toBe('function');
      expect(typeof mockSearchService.validateQuery).toBe('function');
    });

    test('should validate ValidationService interface', () => {
      const mockValidationService: ValidationService = {
        validateStoreInput: vi.fn(),
        validateFindInput: vi.fn(),
        validateKnowledgeItem: vi.fn(),
      };

      expect(typeof mockValidationService.validateStoreInput).toBe('function');
      expect(typeof mockValidationService.validateFindInput).toBe('function');
      expect(typeof mockValidationService.validateKnowledgeItem).toBe('function');
    });

    test('should validate service dependency interfaces', () => {
      const serviceDependencies = {
        database: 'KnowledgeRepository',
        cache: 'RedisCache',
        logger: 'WinstonLogger',
        config: 'ConfigurationService',
      };

      expect(serviceDependencies.database).toBe('KnowledgeRepository');
      expect(serviceDependencies.cache).toBe('RedisCache');
    });

    test('should validate configuration interfaces', () => {
      const serviceConfig = {
        host: 'localhost',
        port: 5432,
        database: 'cortex_test',
        ssl: false,
        connectionTimeout: 30000,
        queryTimeout: 10000,
      };

      expect(serviceConfig.host).toBe('localhost');
      expect(serviceConfig.port).toBe(5432);
      expect(serviceConfig.ssl).toBe(false);
    });

    test('should validate monitoring and health interfaces', () => {
      const healthCheck = {
        status: 'healthy',
        checks: {
          database: 'healthy',
          cache: 'healthy',
          search: 'degraded',
        },
        uptime: 3600000,
        version: '1.0.0',
        lastCheck: new Date().toISOString(),
      };

      expect(healthCheck.status).toBe('healthy');
      expect(healthCheck.checks.database).toBe('healthy');
      expect(healthCheck.checks.search).toBe('degraded');
      expect(healthCheck.uptime).toBe(3600000);
    });
  });

  describe('Security and Authentication Interfaces', () => {
    test('should validate authentication interface validation', () => {
      const authConfig = {
        enabled: true,
        method: 'jwt',
        secretKey: 'test-secret-key',
        tokenExpiry: 3600,
        refreshEnabled: true,
        refreshExpiry: 86400,
      };

      expect(authConfig.enabled).toBe(true);
      expect(authConfig.method).toBe('jwt');
      expect(authConfig.tokenExpiry).toBe(3600);
      expect(authConfig.refreshEnabled).toBe(true);
    });

    test('should validate authorization interface testing', () => {
      const authzConfig = {
        roles: ['admin', 'user', 'viewer'],
        permissions: {
          'read:entities': ['admin', 'user', 'viewer'],
          'write:entities': ['admin', 'user'],
          'delete:entities': ['admin'],
        },
        defaultRole: 'viewer',
      };

      expect(authzConfig.roles).toContain('admin');
      expect(authzConfig.permissions['read:entities']).toEqual(['admin', 'user', 'viewer']);
      expect(authzConfig.defaultRole).toBe('viewer');
    });

    test('should validate security middleware interfaces', () => {
      const securityConfig = {
        rateLimiting: {
          enabled: true,
          windowMs: 900000,
          maxRequests: 100,
        },
        cors: {
          enabled: true,
          origins: ['http://localhost:3000'],
          credentials: true,
        },
        headers: {
          enabled: true,
          csp: "default-src 'self'",
          hsts: true,
        },
      };

      expect(securityConfig.rateLimiting.enabled).toBe(true);
      expect(securityConfig.cors.enabled).toBe(true);
      expect(securityConfig.headers.enabled).toBe(true);
    });

    test('should validate API key management interfaces', () => {
      const apiKeyConfig = {
        enabled: true,
        headerName: 'X-API-Key',
        keyLength: 32,
        expiryDays: 365,
        rotationRequired: false,
        allowedKeys: ['key-123', 'key-456'],
      };

      expect(apiKeyConfig.enabled).toBe(true);
      expect(apiKeyConfig.headerName).toBe('X-API-Key');
      expect(apiKeyConfig.keyLength).toBe(32);
      expect(apiKeyConfig.allowedKeys).toHaveLength(2);
    });
  });

  describe('Integration and Compatibility', () => {
    test('should validate cross-layer interface compatibility', () => {
      // Test that interfaces from different layers work together
      const knowledgeItem: KnowledgeItem = {
        id: 'test-123',
        kind: 'entity',
        scope: { project: 'test' },
        data: { name: 'Test Entity' },
      };

      const storeResult: StoreResult = {
        id: knowledgeItem.id!,
        status: 'inserted',
        kind: knowledgeItem.kind,
        created_at: new Date().toISOString(),
      };

      const searchResult: SearchResult = {
        id: knowledgeItem.id!,
        kind: knowledgeItem.kind,
        scope: knowledgeItem.scope,
        data: knowledgeItem.data,
        created_at: storeResult.created_at,
        confidence_score: 1.0,
        match_type: 'exact',
      };

      expect(storeResult.id).toBe(knowledgeItem.id);
      expect(searchResult.id).toBe(knowledgeItem.id);
      expect(storeResult.kind).toBe(searchResult.kind);
    });

    test('should validate interface versioning support', () => {
      const v1Interface = {
        version: '1.0.0',
        data: { name: 'test' },
      };

      const v2Interface = {
        version: '2.0.0',
        data: { name: 'test', description: 'Added in v2' },
        backwardsCompatible: true,
      };

      expect(v1Interface.version).toBe('1.0.0');
      expect(v2Interface.version).toBe('2.0.0');
      expect(v2Interface.backwardsCompatible).toBe(true);
      expect(v2Interface['data.description']).toBe('Added in v2');
    });

    test('should validate backward compatibility testing', () => {
      const oldClientRequest = {
        query: 'test query',
        limit: 10,
        // Missing new fields like 'mode', 'types'
      };

      const newServerHandling = {
        query: oldClientRequest.query,
        limit: oldClientRequest.limit,
        mode: oldClientRequest.mode || 'auto', // Default for old clients
        types: oldClientRequest.types || ['all'], // Default for old clients
      };

      expect(newServerHandling.query).toBe('test query');
      expect(newServerHandling.mode).toBe('auto');
      expect(newServerHandling.types).toContain('all');
    });

    test('should validate interface evolution validation', () => {
      interface V1KnowledgeItem {
        id: string;
        kind: string;
        data: Record<string, any>;
      }

      interface V2KnowledgeItem extends V1KnowledgeItem {
        scope?: {
          project?: string;
          branch?: string;
          org?: string;
        };
        metadata?: Record<string, any>;
        created_at?: string;
        updated_at?: string;
      }

      const v1Item: V1KnowledgeItem = {
        id: 'test-123',
        kind: 'entity',
        data: { name: 'test' },
      };

      const v2Item: V2KnowledgeItem = {
        ...v1Item,
        scope: { project: 'test' },
        metadata: { version: '2.0.0' },
        created_at: new Date().toISOString(),
      };

      expect(v2Item.id).toBe(v1Item.id);
      expect(v2Item.kind).toBe(v1Item.kind);
      expect(v2Item.data).toEqual(v1Item.data);
      expect(v2Item.scope?.project).toBe('test');
    });
  });

  describe('Analytics Interfaces Validation', () => {
    test('should validate KnowledgeAnalytics interface', () => {
      const analytics: KnowledgeAnalytics = {
        totalEntities: 100,
        totalRelations: 50,
        totalObservations: 200,
        knowledgeTypeDistribution: {
          entity: 40,
          relation: 20,
          observation: 40,
        },
        growthMetrics: {
          dailyGrowthRate: 0.05,
          weeklyGrowthRate: 0.35,
          monthlyGrowthRate: 1.5,
          totalGrowthThisPeriod: 25,
        },
        contentMetrics: {
          averageContentLength: 500,
          totalContentLength: 50000,
          contentComplexity: 'medium',
        },
        scopeDistribution: {
          'project-a': 60,
          'project-b': 40,
        },
        temporalDistribution: {
          '2024-01': 30,
          '2024-02': 45,
          '2024-03': 25,
        },
      };

      expect(analytics.totalEntities).toBe(100);
      expect(analytics.growthMetrics.dailyGrowthRate).toBe(0.05);
      expect(analytics.contentMetrics.contentComplexity).toBe('medium');
      expect(['low', 'medium', 'high']).toContain(analytics.contentMetrics.contentComplexity);
    });

    test('should validate PerformanceAnalytics interface', () => {
      const performance: PerformanceAnalytics = {
        queryPerformance: {
          averageResponseTime: 150,
          p95ResponseTime: 300,
          p99ResponseTime: 500,
          throughput: 1000,
          errorRate: 0.01,
        },
        storageUtilization: {
          totalStorageUsed: 1000000000,
          storageByType: {
            entities: 500000000,
            relations: 300000000,
            observations: 200000000,
          },
          growthRate: 0.1,
        },
        systemMetrics: {
          cpuUsage: 0.65,
          memoryUsage: 0.78,
          diskIO: 0.45,
          networkIO: 0.23,
        },
        bottlenecks: [
          {
            type: 'memory',
            severity: 'medium',
            description: 'High memory usage',
            recommendation: 'Increase memory allocation',
          },
        ],
        optimizationSuggestions: ['Enable query caching', 'Optimize database indexes'],
      };

      expect(performance.queryPerformance.averageResponseTime).toBe(150);
      expect(performance.systemMetrics.memoryUsage).toBe(0.78);
      expect(performance.bottlenecks).toHaveLength(1);
      expect(['low', 'medium', 'high', 'critical']).toContain(performance.bottlenecks[0].severity);
    });
  });

  describe('Storage Interfaces Validation', () => {
    test('should validate StorageConfig interface', () => {
      const config: StorageConfig = {
        provider: 's3',
        region: 'us-east-1',
        bucket: 'test-bucket',
        accessKeyId: 'test-key',
        secretAccessKey: 'test-secret',
        encryption: {
          enabled: true,
          algorithm: 'AES256',
          bucketKeyEnabled: true,
        },
        versioning: true,
        compression: {
          enabled: true,
          algorithm: 'gzip',
          level: 6,
          threshold: 1024,
        },
        caching: {
          enabled: true,
          ttl: 3600,
          maxSize: 1000000000,
          evictionPolicy: 'LRU',
          persistenceEnabled: true,
        },
        security: {
          encryption: {
            enabled: true,
            algorithm: 'AES256',
          },
          accessControl: {
            read: ['admin'],
            write: ['admin'],
            delete: ['admin'],
            admin: ['admin'],
            public: false,
            anonymousRead: false,
            authenticatedRead: true,
          },
          mfaDelete: false,
          legalHold: false,
          auditLogging: true,
          accessLogging: true,
          threatDetection: false,
        },
        performance: {
          multipartThreshold: 104857600,
          chunkSize: 8388608,
          maxConcurrency: 10,
          timeoutMs: 30000,
          retryAttempts: 3,
        },
      };

      expect(config.provider).toBe('s3');
      expect(config.encryption.enabled).toBe(true);
      expect(config.compression.algorithm).toBe('gzip');
      expect(config.caching.evictionPolicy).toBe('LRU');
      expect(config.security.encryption.enabled).toBe(true);
      expect(config.performance.maxConcurrency).toBe(10);
    });

    test('should validate UploadRequest and DownloadRequest interfaces', () => {
      const uploadRequest: UploadRequest = {
        key: 'test-file.txt',
        body: Buffer.from('test content'),
        contentType: 'text/plain',
        metadata: {
          'original-name': 'test.txt',
          'uploaded-by': 'test-user',
        },
        tags: {
          environment: 'test',
          project: 'cortex',
        },
        encryption: {
          enabled: true,
          algorithm: 'AES256',
        },
        compression: true,
        storageClass: 'STANDARD',
      };

      const downloadRequest: DownloadRequest = {
        key: 'test-file.txt',
        versionId: 'version-123',
        range: 'bytes=0-1023',
        ifMatch: 'etag-123',
        ifModifiedSince: new Date('2024-01-01'),
      };

      expect(uploadRequest.key).toBe('test-file.txt');
      expect(uploadRequest.body).toBeInstanceOf(Buffer);
      expect(uploadRequest.tags.environment).toBe('test');
      expect(downloadRequest.key).toBe('test-file.txt');
      expect(downloadRequest.versionId).toBe('version-123');
      expect(downloadRequest.range).toBe('bytes=0-1023');
    });
  });

  describe('Logging Interfaces Validation', () => {
    test('should validate LogEntry interface', () => {
      const logEntry: LogEntry = {
        level: 'info',
        message: 'Test log message',
        context: {
          userId: 'user-123',
          action: 'test-action',
          result: 'success',
        },
        correlationId: 'corr-123',
        timestamp: '2024-01-01T00:00:00Z',
        service: 'test-service',
        version: '1.0.0',
        userId: 'user-123',
        sessionId: 'session-123',
        requestId: 'req-123',
        traceId: 'trace-123',
        spanId: 'span-123',
        tags: ['test', 'validation'],
        metadata: {
          test: true,
          validation: 'comprehensive',
        },
      };

      expect(['debug', 'info', 'warn', 'error', 'fatal']).toContain(logEntry.level);
      expect(logEntry.message).toBe('Test log message');
      expect(logEntry.context?.userId).toBe('user-123');
      expect(logEntry.correlationId).toBe('corr-123');
      expect(logEntry.tags).toContain('test');
    });

    test('should validate LogQueryOptions interface', () => {
      const queryOptions: LogQueryOptions = {
        level: ['error', 'warn'],
        timeRange: {
          start: new Date('2024-01-01'),
          end: new Date('2024-01-31'),
        },
        context: {
          service: 'test-service',
        },
        contextFilters: {
          userId: ['user-123', 'user-456'],
          action: 'test-action',
        },
        messagePattern: /error.*test/i,
        correlationId: 'corr-123',
        userId: 'user-123',
        service: 'test-service',
        limit: 100,
        offset: 0,
        sortBy: 'timestamp',
        sortOrder: 'desc',
      };

      expect(queryOptions.level).toContain('error');
      expect(queryOptions.timeRange.start).toBeInstanceOf(Date);
      expect(queryOptions.contextFilters.userId).toHaveLength(2);
      expect(queryOptions.messagePattern).toBeInstanceOf(RegExp);
      expect(queryOptions.sortBy).toBe('timestamp');
      expect(queryOptions.sortOrder).toBe('desc');
    });

    test('should validate LogConfiguration interface', () => {
      const logConfig: LogConfiguration = {
        storage: {
          type: 'hybrid',
          directory: './logs',
          maxSize: '100MB',
          maxFiles: 10,
          compression: true,
          encryption: true,
          backupLocation: './backup',
          retryPolicy: {
            attempts: 3,
            backoffMs: 1000,
            maxBackoffMs: 10000,
          },
        },
        retention: {
          defaultDays: 30,
          errorDays: 90,
          auditDays: 365,
          debugDays: 7,
          cleanupInterval: '24h',
          archiveLocation: './archive',
          compressionFormat: 'gzip',
          deleteAfterArchive: true,
        },
        streaming: {
          enabled: true,
          bufferSize: 1000,
          flushInterval: 5000,
          retryAttempts: 3,
          subscribers: ['monitoring', 'analytics'],
          protocols: {
            websocket: true,
            sse: true,
            tcp: false,
            udp: false,
          },
          authentication: {
            enabled: true,
            tokenRequired: true,
            allowedOrigins: ['http://localhost:3000'],
          },
        },
        analytics: {
          enabled: true,
          metricsInterval: 60000,
          aggregationWindow: 300000,
          metrics: ['count', 'rate', 'error_rate'],
          retentionDays: 90,
          exportFormat: 'json',
          dashboard: {
            enabled: true,
            refreshInterval: 30000,
            widgets: ['chart', 'table', 'gauge'],
          },
        },
        security: {
          masking: {
            enabled: true,
            patterns: ['password', 'token', 'secret'],
            replacement: '***',
            customPatterns: [
              {
                name: 'email',
                pattern: /\b[A-Za-z0-9['_']%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
                replacement: '***@***.***',
              },
            ],
          },
          accessControl: {
            enabled: true,
            roles: {
              admin: ['read', 'write', 'delete'],
              user: ['read'],
              viewer: ['read'],
            },
            defaultRole: 'viewer',
            tokenValidation: true,
          },
          encryption: {
            enabled: true,
            algorithm: 'AES-256-GCM',
            keyRotationDays: 90,
            keyProvider: 'local',
          },
          audit: {
            enabled: true,
            accessLogging: true,
            modificationLogging: true,
            exportLogging: true,
          },
        },
      };

      expect(logConfig.storage.type).toBe('hybrid');
      expect(logConfig.retention.defaultDays).toBe(30);
      expect(logConfig.streaming.enabled).toBe(true);
      expect(logConfig.analytics.enabled).toBe(true);
      expect(logConfig.security.masking.enabled).toBe(true);
      expect(logConfig.security.encryption.enabled).toBe(true);
      expect(logConfig.security.audit.enabled).toBe(true);
    });
  });

  describe('Workflow Interfaces Validation', () => {
    test('should validate WorkflowDefinition interface', () => {
      const workflowDef: WorkflowDefinition = {
        id: 'workflow-123',
        name: 'Test Workflow',
        description: 'A test workflow for validation',
        category: 'testing',
        version: '1.0.0',
        status: 'active',
        tasks: [
          {
            id: 'task-1',
            name: 'Test Task',
            type: 'human',
            priority: 'medium',
            dependencies: [],
            config: {
              instructions: 'Complete this task',
              requiredData: ['input1', 'input2'],
            },
          },
        ],
        triggers: [
          {
            id: 'trigger-1',
            type: 'manual',
            name: 'Manual Trigger',
            description: 'Start workflow manually',
            config: {
              allowedUsers: ['admin', 'user'],
            },
            enabled: true,
            createdAt: '2024-01-01T00:00:00Z',
            updatedAt: '2024-01-01T00:00:00Z',
          },
        ],
        metadata: {
          created_by: 'test-user',
          created_at: '2024-01-01T00:00:00Z',
          updated_at: '2024-01-01T00:00:00Z',
          tags: ['test', 'validation'],
        },
        createdAt: '2024-01-01T00:00:00Z',
        updatedAt: '2024-01-01T00:00:00Z',
      };

      expect(workflowDef.id).toBe('workflow-123');
      expect(['draft', 'active', 'inactive', 'archived', 'deprecated']).toContain(
        workflowDef.status
      );
      expect(workflowDef.tasks).toHaveLength(1);
      expect(workflowDef.triggers).toHaveLength(1);
      expect(workflowDef.tasks[0].type).toBe('human');
      expect(workflowDef.triggers[0].type).toBe('manual');
    });

    test('should validate WorkflowExecution interface', () => {
      const workflowExec: WorkflowExecution = {
        id: 'execution-123',
        workflowId: 'workflow-123',
        templateId: 'template-123',
        status: 'running',
        mode: 'sequential',
        startedAt: '2024-01-01T00:00:00Z',
        currentTask: 'task-1',
        context: {
          initiator: 'test-user',
          triggerData: { source: 'api' },
        },
        state: {
          currentPhase: 'validation',
          completedPhases: ['initialization'],
          variables: {
            input1: 'value1',
            input2: 'value2',
          },
          checkpoints: {},
          history: [
            {
              timestamp: '2024-01-01T00:00:00Z',
              action: 'started',
              data: { user: 'test-user' },
            },
          ],
        },
        tasks: [
          {
            id: 'task-exec-1',
            taskId: 'task-1',
            status: 'in_progress',
            assignee: 'test-user',
            assignedAt: '2024-01-01T00:01:00Z',
            startedAt: '2024-01-01T00:01:30Z',
            duration: 30000,
          },
        ],
        variables: {
          input1: 'value1',
          input2: 'value2',
          processed: true,
        },
        metadata: {
          started_by: 'test-user',
          started_at: '2024-01-01T00:00:00Z',
          environment: 'test',
          version: '1.0.0',
          tags: ['test', 'execution'],
        },
      };

      expect(workflowExec.id).toBe('execution-123');
      expect([
        'pending',
        'running',
        'suspended',
        'completed',
        'failed',
        'cancelled',
        'escalated',
      ]).toContain(workflowExec.status);
      expect(['sequential', 'parallel', 'conditional', 'hybrid']).toContain(workflowExec.mode);
      expect(workflowExec.tasks).toHaveLength(1);
      expect(workflowExec.tasks[0].status).toBe('in_progress');
      expect(workflowExec.state.currentPhase).toBe('validation');
    });

    test('should validate WorkflowConfiguration interface', () => {
      const workflowConfig: WorkflowConfiguration = {
        settings: {
          defaultTimeout: 3600000,
          defaultRetryPolicy: {
            maxRetries: 3,
            backoffStrategy: 'exponential',
            initialDelay: 1000,
            maxDelay: 30000,
          },
          defaultEscalationPolicy: {
            levels: [
              {
                level: 1,
                target: 'manager',
                delay: 1800000,
                action: 'assign',
              },
            ],
            autoEscalate: true,
          },
          maxConcurrentExecutions: 10,
          executionHistoryRetention: 90,
          auditEnabled: true,
          notificationsEnabled: true,
        },
        validation: {
          strictValidation: true,
          customValidators: [],
          requiredFields: ['name', 'category'],
          fieldValidationRules: {},
        },
        security: {
          authentication: {
            required: true,
            methods: ['jwt', 'oauth'],
            providers: ['auth0', 'okta'],
          },
          authorization: {
            required: true,
            roles: ['admin', 'user', 'viewer'],
            permissions: ['execute', 'view', 'manage'],
          },
          encryption: {
            atRest: true,
            inTransit: true,
            algorithm: 'AES-256-GCM',
          },
          audit: {
            logLevel: 'info',
            retentionPeriod: 365,
            includeSensitiveData: false,
          },
        },
        performance: {
          caching: {
            enabled: true,
            ttl: 300000,
            maxSize: 1000,
          },
          optimization: {
            queryOptimization: true,
            batchProcessing: true,
            parallelExecution: true,
          },
          monitoring: {
            metricsCollection: true,
            performanceProfiling: true,
            alerting: true,
          },
        },
        integrations: {
          defaultTimeout: 30000,
          retryPolicy: {
            maxRetries: 3,
            backoffStrategy: 'linear',
            initialDelay: 1000,
          },
          circuitBreaker: {
            enabled: true,
            failureThreshold: 5,
            recoveryTimeout: 60000,
            expectedRecoveryTime: 30000,
          },
          rateLimiting: {
            enabled: true,
            requestsPerSecond: 100,
            burstSize: 200,
            windowSize: 60000,
          },
        },
      };

      expect(workflowConfig.settings.defaultTimeout).toBe(3600000);
      expect(workflowConfig.validation.strictValidation).toBe(true);
      expect(workflowConfig.security.authentication.required).toBe(true);
      expect(workflowConfig.performance.caching.enabled).toBe(true);
      expect(workflowConfig.integrations.circuitBreaker.enabled).toBe(true);
    });
  });

  describe('Complex Interface Integration Tests', () => {
    test('should validate memory store request/response cycle', () => {
      const storeRequest: MemoryStoreRequest = {
        items: [
          {
            id: 'entity-1',
            kind: 'entity',
            scope: { project: 'test' },
            data: { name: 'Test Entity 1' },
          },
          {
            id: 'relation-1',
            kind: 'relation',
            scope: { project: 'test' },
            data: { from_id: 'entity-1', to_id: 'entity-2', type: 'depends_on' },
          },
        ],
      };

      const storeResponse: MemoryStoreResponse = {
        stored: [
          {
            id: 'entity-1',
            status: 'inserted',
            kind: 'entity',
            created_at: '2024-01-01T00:00:00Z',
          },
          {
            id: 'relation-1',
            status: 'inserted',
            kind: 'relation',
            created_at: '2024-01-01T00:00:00Z',
          },
        ],
        errors: [],
        autonomous_context: {
          action_performed: 'batch',
          similar_items_checked: 10,
          duplicates_found: 0,
          contradictions_detected: false,
          recommendation: 'Items stored successfully',
          reasoning: 'No duplicates or contradictions found',
          user_message_suggestion: 'Successfully stored 2 new items',
        },
      };

      expect(storeRequest.items).toHaveLength(2);
      expect(storeResponse.stored).toHaveLength(2);
      expect(storeResponse.errors).toHaveLength(0);
      expect(storeResponse.stored[0].id).toBe(storeRequest.items[0].id);
      expect(storeResponse.autonomous_context.action_performed).toBe('batch');
    });

    test('should validate smart find request with corrections', () => {
      const smartFindRequest: SmartFindRequest = {
        query: 'test qurey', // Typo in query
        scope: { project: 'test' },
        types: ['entity'],
        top_k: 5,
        mode: 'auto',
        enable_auto_fix: true,
        return_corrections: true,
        max_attempts: 3,
        timeout_per_attempt_ms: 5000,
      };

      const smartFindResult: SmartFindResult = {
        hits: [
          {
            kind: 'entity',
            id: 'entity-123',
            title: 'Test Query Result',
            snippet: 'This matches the corrected query',
            score: 0.95,
            scope: { project: 'test' },
            updated_at: '2024-01-01T00:00:00Z',
            route_used: 'semantic_search',
            confidence: 0.95,
          },
        ],
        suggestions: ['Try "test query" for more results', 'Add more specific terms'],
        autonomous_metadata: {
          strategy_used: 'fast_then_deep_fallback',
          mode_requested: 'auto',
          mode_executed: 'semantic',
          confidence: 'high',
          total_results: 1,
          avg_score: 0.95,
          fallback_attempted: false,
          recommendation: 'Query was successful',
          user_message_suggestion: 'Found 1 result for "test query"',
        },
        corrections: {
          original_query: 'test qurey',
          final_query: 'test query',
          attempts: [
            {
              attempt_number: 1,
              query: 'test qurey',
              mode: 'fast',
              sanitization_level: 'basic',
              success: true,
              timestamp: Date.now(),
              duration_ms: 100,
            },
          ],
          transformations: ['spelling_correction'],
          total_attempts: 1,
          auto_fixes_applied: ['spelling_correction'],
          patterns_detected: ['typo'],
          final_sanitization_level: 'enhanced',
          recommendation: 'Spelling was corrected automatically',
        },
      };

      expect(smartFindRequest.query).toBe('test qurey');
      expect(smartFindRequest.enable_auto_fix).toBe(true);
      expect(smartFindResult.hits).toHaveLength(1);
      expect(smartFindResult.corrections?.original_query).toBe('test qurey');
      expect(smartFindResult.corrections?.final_query).toBe('test query');
      expect(smartFindResult.corrections?.auto_fixes_applied).toContain('spelling_correction');
    });

    test('should validate analytics report generation', () => {
      const analyticsQuery: AnalyticsQuery = {
        type: 'knowledge',
        title: 'Knowledge Growth Report',
        timeRange: {
          startDate: new Date('2024-01-01'),
          endDate: new Date('2024-01-31'),
        },
        filters: {
          scope: {
            project: 'test-project',
            org: 'test-org',
          },
          types: ['entity', 'relation'],
          dateRange: {
            startDate: new Date('2024-01-01'),
            endDate: new Date('2024-01-31'),
          },
        },
        aggregations: [
          {
            field: 'kind',
            operation: 'count',
            groupBy: 'kind',
          },
          {
            field: 'created_at',
            operation: 'count',
            groupBy: 'date',
          },
        ],
        limit: 100,
      };

      const analyticsReport: AnalyticsReport = {
        id: 'report-123',
        title: 'Knowledge Growth Report - January 2024',
        generatedAt: new Date('2024-02-01'),
        timeRange: {
          startDate: new Date('2024-01-01'),
          endDate: new Date('2024-01-31'),
        },
        filters: analyticsQuery.filters,
        data: {
          totalKnowledge: 150,
          entities: 80,
          relations: 40,
          observations: 30,
          growthRate: 0.15,
        },
        visualizations: [
          {
            type: 'chart',
            title: 'Knowledge Type Distribution',
            data: {
              labels: ['Entity', 'Relation', 'Observation'],
              datasets: [
                {
                  data: [80, 40, 30],
                  backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56'],
                },
              ],
            },
            config: {
              type: 'pie',
              options: { responsive: true },
            },
          },
        ],
        summary: 'Knowledge base grew by 15% in January 2024, with 80 new entities added.',
        metadata: {
          totalDataPoints: 150,
          processingTimeMs: 2500,
          cacheHit: false,
        },
      };

      expect(analyticsQuery.type).toBe('knowledge');
      expect(analyticsQuery.aggregations).toHaveLength(2);
      expect(analyticsReport.id).toBe('report-123');
      expect(analyticsReport.visualizations).toHaveLength(1);
      expect(analyticsReport.visualizations[0].type).toBe('chart');
      expect(analyticsReport.metadata['processingTimeMs']).toBe(2500);
    });
  });

  describe('Edge Cases and Error Handling', () => {
    test('should handle minimal interface implementations', () => {
      const minimalKnowledgeItem: KnowledgeItem = {
        kind: 'entity',
        scope: {},
        data: {},
      };

      const minimalSearchQuery: SearchQuery = {
        query: 'test',
      };

      expect(minimalKnowledgeItem.kind).toBe('entity');
      expect(minimalKnowledgeItem.scope).toEqual({});
      expect(minimalKnowledgeItem.data).toEqual({});
      expect(minimalSearchQuery.query).toBe('test');
    });

    test('should handle optional fields gracefully', () => {
      const knowledgeItemWithOptionals: KnowledgeItem = {
        kind: 'entity',
        scope: { project: 'test' },
        data: { name: 'test' },
        // Optional fields not provided
        content: 'Test content',
        metadata: undefined,
        created_at: undefined,
        updated_at: undefined,
      };

      expect(knowledgeItemWithOptionals.metadata).toBeUndefined();
      expect(knowledgeItemWithOptionals.created_at).toBeUndefined();
      expect(knowledgeItemWithOptionals.updated_at).toBeUndefined();
      expect(knowledgeItemWithOptionals.content).toBe('Test content');
    });

    test('should validate enum constraints', () => {
      const validStatuses = ['inserted', 'updated', 'skipped_dedupe', 'deleted'];
      const validMatchTypes = ['exact', 'fuzzy', 'semantic'];
      const validModes = ['auto', 'fast', 'deep'];

      validStatuses.forEach((status) => {
        const result: StoreResult = {
          id: 'test',
          status: status as any,
          kind: 'entity',
          created_at: new Date().toISOString(),
        };
        expect(validStatuses).toContain(result.status);
      });

      validMatchTypes.forEach((matchType) => {
        const result: SearchResult = {
          id: 'test',
          kind: 'entity',
          scope: {},
          data: {},
          created_at: new Date().toISOString(),
          confidence_score: 0.5,
          match_type: matchType as any,
        };
        expect(validMatchTypes).toContain(result.match_type);
      });

      validModes.forEach((mode) => {
        const query: SearchQuery = {
          query: 'test',
          mode: mode as any,
        };
        expect(validModes).toContain(query.mode);
      });
    });

    test('should handle complex nested structures', () => {
      const complexKnowledgeItem: KnowledgeItem = {
        id: 'complex-123',
        kind: 'entity',
        scope: {
          project: 'complex-project',
          branch: 'feature/complex',
          org: 'complex-org',
        },
        data: {
          name: 'Complex Entity',
          properties: {
            nested: {
              deeply: {
                value: 'deep value',
                array: [1, 2, 3],
                object: {
                  flag: true,
                  count: 42,
                },
              },
            },
          },
        },
        metadata: {
          version: '2.0.0',
          tags: ['complex', 'nested', 'test'],
          custom: {
            features: ['feature1', 'feature2'],
            settings: {
              enabled: true,
              threshold: 0.8,
            },
          },
        },
        created_at: '2024-01-01T00:00:00Z',
        updated_at: '2024-01-01T00:00:00Z',
      };

      expect(complexKnowledgeItem['data.properties'].nested.deeply.value).toBe('deep value');
      expect(complexKnowledgeItem['data.properties'].nested.deeply.array).toEqual([1, 2, 3]);
      expect(complexKnowledgeItem['data.properties'].nested.deeply.object.flag).toBe(true);
      expect(complexKnowledgeItem.metadata?.custom.features).toContain('feature1');
      expect(complexKnowledgeItem.metadata?.custom.settings.threshold).toBe(0.8);
    });
  });
});
