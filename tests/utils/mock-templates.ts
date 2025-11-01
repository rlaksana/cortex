/**
 * Standardized Mock Templates for MCP Cortex Tests
 *
 * This file provides reusable mock implementations for the most commonly
 * mocked dependencies in the MCP Cortex test suite, ensuring consistency
 * and reducing boilerplate across test files.
 */

// import { vi } from 'vitest';
// import type { QdrantClient } from '@qdrant/js-client-rest';
// import type { Logger } from 'pino';
// import type { Environment } from '../src/config/environment';
import { MockEmbeddingService, type MockEmbeddingConfig } from './mock-embedding-service.js';

/**
 * Environment Mock Template
 *
 * Mocks the Environment.getInstance() pattern with commonly used configurations
 */
export interface MockEnvironmentConfig {
  NODE_ENV?: 'development' | 'production' | 'test';
  LOG_LEVEL?: 'error' | 'warn' | 'info' | 'debug' | 'trace';
  ENABLE_AUTH?: boolean;
  ENABLE_CACHING?: boolean;
  ENABLE_METRICS?: boolean;
  QDRANT_URL?: string;
  OPENAI_API_KEY?: string;
  VECTOR_SIZE?: 384 | 768 | 1024 | 1536 | 2048 | 3072;
  SEARCH_LIMIT?: number;
  SEARCH_THRESHOLD?: number;
  JWT_SECRET?: string;
  ENCRYPTION_KEY?: string;
  MOCK_EXTERNAL_SERVICES?: boolean;
}

export const createMockEnvironment = (overrides: MockEnvironmentConfig = {}) => {
  const defaultConfig: Required<MockEnvironmentConfig> = {
    NODE_ENV: 'test',
    LOG_LEVEL: 'error',
    ENABLE_AUTH: false,
    ENABLE_CACHING: false,
    ENABLE_METRICS: false,
    QDRANT_URL: 'http://localhost:6333',
    OPENAI_API_KEY: 'test-api-key',
    VECTOR_SIZE: 1536,
    SEARCH_LIMIT: 50,
    SEARCH_THRESHOLD: 0.7,
    JWT_SECRET: 'test-jwt-secret-32-characters-long',
    ENCRYPTION_KEY: 'test-encryption-key-32-chars-long',
    MOCK_EXTERNAL_SERVICES: true,
  };

  const config = { ...defaultConfig, ...overrides };

  return {
    getInstance: vi.fn(() => ({
      getQdrantConfig: vi.fn(() => ({
        type: 'qdrant',
        url: config.QDRANT_URL,
        apiKey: config.NODE_ENV === 'test' ? undefined : 'test-api-key',
        vectorSize: config.VECTOR_SIZE,
        distance: 'Cosine',
        collectionName: 'test-cortex-memory',
        logQueries: false,
        connectionTimeout: 30000,
        maxConnections: 20,
        poolMin: 1,
        poolMax: 5,
        idleTimeoutMs: 30000,
      })),
      getEmbeddingConfig: vi.fn(() => ({
        apiKey: config.OPENAI_API_KEY,
        model: 'text-embedding-ada-002',
        batchSize: 10,
        vectorSize: config.VECTOR_SIZE,
      })),
      getSearchConfig: vi.fn(() => ({
        limit: config.SEARCH_LIMIT,
        threshold: config.SEARCH_THRESHOLD,
        timeout: 30000,
      })),
      getCacheConfig: vi.fn(() => ({
        enabled: config.ENABLE_CACHING,
        ttl: 3600,
        maxSize: 1000,
      })),
      getMonitoringConfig: vi.fn(() => ({
        enabled: config.ENABLE_METRICS,
        healthCheckInterval: 60000,
        logLevel: config.LOG_LEVEL,
      })),
      getApiConfig: vi.fn(() => ({
        rateLimit: 100,
        timeout: 30000,
        authEnabled: config.ENABLE_AUTH,
      })),
      getBatchConfig: vi.fn(() => ({
        size: 50,
        timeout: 30000,
        retryAttempts: 3,
        retryDelay: 1000,
      })),
      getAppMetadata: vi.fn(() => ({
        name: 'Cortex Memory MCP',
        version: '2.0.0',
        description: 'Test Environment',
        environment: config.NODE_ENV,
        database: 'qdrant',
      })),
      isProductionMode: vi.fn(() => config.NODE_ENV === 'production'),
      isDevelopmentMode: vi.fn(() => config.NODE_ENV === 'development'),
      isTestMode: vi.fn(() => config.NODE_ENV === 'test'),
      getFeatureFlag: vi.fn((flag: string) => {
        switch (flag) {
          case 'auth': return config.ENABLE_AUTH;
          case 'caching': return config.ENABLE_CACHING;
          case 'metrics': return config.ENABLE_METRICS;
          case 'logging': return true;
          default: return false;
        }
      }),
      validateRequiredConfig: vi.fn(() => ({ valid: true, errors: [] })),
      generateConfigHash: vi.fn(() => 'test-config-hash'),
      getMcpConfig: vi.fn(() => ({
        transport: 'stdio',
        serverName: 'cortex-test',
        serverVersion: '2.0.0',
      })),
      getScopeConfig: vi.fn(() => ({
        org: 'test-org',
        project: 'test-project',
        branch: 'test-branch',
      })),
      getSecurityConfig: vi.fn(() => ({
        jwtSecret: config.JWT_SECRET,
        jwtRefreshSecret: `${config.JWT_SECRET}-refresh`,
        encryptionKey: config.ENCRYPTION_KEY,
      })),
      getRawConfig: vi.fn(() => config),
    })),
  };
};

/**
 * Logger Mock Template
 *
 * Mocks Pino logger with all commonly used methods
 */
export const createMockLogger = () => {
  const childLogger = {
    info: vi.fn(),
    error: vi.fn(),
    warn: vi.fn(),
    debug: vi.fn(),
    trace: vi.fn(),
    fatal: vi.fn(),
    child: vi.fn(() => childLogger),
  };

  return {
    info: vi.fn(),
    error: vi.fn(),
    warn: vi.fn(),
    debug: vi.fn(),
    trace: vi.fn(),
    fatal: vi.fn(),
    child: vi.fn(() => childLogger),
    level: 'error',
  };
};

/**
 * Qdrant Client Mock Template
 *
 * Mocks QdrantClient with all the extended methods used in the codebase
 */
export interface MockQdrantConfig {
  shouldFail?: boolean;
  failMethods?: string[];
  collections?: any[];
  points?: any[];
  searchResults?: any[];
  _healthStatus?: boolean;
}

export const createMockQdrantClient = (config: MockQdrantConfig = {}) => {
  const {
    shouldFail = false,
    failMethods = [],
    collections = [{ name: 'test-collection', points_count: 0 }],
    points = [],
    searchResults = [],
  } = config;

  const createAsyncMethod = <T extends any[], R>(
    returnValue: R,
    shouldFailThis: boolean = false
  ) => vi.fn(async (..._args: T) => {
    if (shouldFail || shouldFailThis) {
      throw new Error(`Mock Qdrant method failed`);
    }
    return returnValue;
  });

  const client = {
    // Core Qdrant methods
    getCollections: createAsyncMethod([], { collections: { collections } }),
    createCollection: createAsyncMethod([{}], true),
    deleteCollection: createAsyncMethod([{}], true),
    getCollection: createAsyncMethod([{}], true),
    collectionExists: createAsyncMethod([false], true),

    // Point operations
    upsert: createAsyncMethod([{ status: 'ok' }]),
    search: createAsyncMethod([{ result: searchResults }]),
    retrieve: createAsyncMethod([{ result: points }]),
    delete: createAsyncMethod([{ status: 'ok' }]),

    // Scroll and count
    scroll: createAsyncMethod([{ result: { points } }]),
    count: createAsyncMethod([{ result: { count: points.length } }]),

    // Extended methods for knowledge entities (as declared in qdrant-client.ts)
    eventAudit: {
      create: createAsyncMethod([{ id: 'audit-stub' }]),
      find: createAsyncMethod([]),
      update: createAsyncMethod([{ id: 'audit-stub' }]),
      delete: createAsyncMethod(true),
    },

    user: {
      findUnique: createAsyncMethod([null]),
      update: createAsyncMethod([null]),
      create: createAsyncMethod([null]),
      delete: createAsyncMethod([null]),
      findMany: createAsyncMethod([]),
    },

    apiKey: {
      findUnique: createAsyncMethod([null]),
      findMany: createAsyncMethod([]),
      create: createAsyncMethod([null]),
      update: createAsyncMethod([null]),
      delete: createAsyncMethod([null]),
    },

    tokenRevocationList: {
      findUnique: createAsyncMethod([null]),
      findMany: createAsyncMethod([]),
      create: createAsyncMethod([null]),
      delete: createAsyncMethod([null]),
    },

    securityEvent: {
      create: createAsyncMethod([{ id: 'security-stub' }]),
      findMany: createAsyncMethod([]),
    },

    authInstance: {
      findUnique: createAsyncMethod([null]),
      create: createAsyncMethod([null]),
    },

    // Knowledge-related methods
    adrDecision: {
      create: createAsyncMethod([{ id: 'decision-stub' }]),
      find: createAsyncMethod([]),
      update: createAsyncMethod([{ id: 'decision-stub' }]),
      delete: createAsyncMethod(true),
    },

    section: {
      create: createAsyncMethod([{ id: 'section-stub' }]),
      find: createAsyncMethod([]),
      update: createAsyncMethod([{ id: 'section-stub' }]),
      delete: createAsyncMethod(true),
    },

    runbook: {
      create: createAsyncMethod([{ id: 'runbook-stub' }]),
      find: createAsyncMethod([]),
      update: createAsyncMethod([{ id: 'runbook-stub' }]),
      delete: createAsyncMethod(true),
    },

    changeLog: {
      create: createAsyncMethod([{ id: 'change-stub' }]),
      find: createAsyncMethod([]),
      update: createAsyncMethod([{ id: 'change-stub' }]),
      delete: createAsyncMethod(true),
    },

    issueLog: {
      create: createAsyncMethod([{ id: 'issue-stub' }]),
      find: createAsyncMethod([]),
      update: createAsyncMethod([{ id: 'issue-stub' }]),
      delete: createAsyncMethod(true),
    },

    todoLog: {
      create: createAsyncMethod([{ id: 'todo-stub' }]),
      find: createAsyncMethod([]),
      update: createAsyncMethod([{ id: 'todo-stub' }]),
      delete: createAsyncMethod(true),
    },

    releaseNote: {
      create: createAsyncMethod([{ id: 'release-stub' }]),
      find: createAsyncMethod([]),
      update: createAsyncMethod([{ id: 'release-stub' }]),
      delete: createAsyncMethod(true),
    },

    ddlHistory: {
      create: createAsyncMethod([{ id: 'ddl-stub' }]),
      find: createAsyncMethod([]),
      update: createAsyncMethod([{ id: 'ddl-stub' }]),
      delete: createAsyncMethod(true),
    },

    prContext: {
      create: createAsyncMethod([{ id: 'pr-stub' }]),
      find: createAsyncMethod([]),
      update: createAsyncMethod([{ id: 'pr-stub' }]),
      delete: createAsyncMethod(true),
    },

    incidentLog: {
      create: createAsyncMethod([{ id: 'incident-stub' }]),
      find: createAsyncMethod([]),
      update: createAsyncMethod([{ id: 'incident-stub' }]),
      delete: createAsyncMethod(true),
    },

    releaseLog: {
      create: createAsyncMethod([{ id: 'release-stub' }]),
      find: createAsyncMethod([]),
      update: createAsyncMethod([{ id: 'release-stub' }]),
      delete: createAsyncMethod(true),
    },

    riskLog: {
      create: createAsyncMethod([{ id: 'risk-stub' }]),
      find: createAsyncMethod([]),
      update: createAsyncMethod([{ id: 'risk-stub' }]),
      delete: createAsyncMethod(true),
    },

    assumptionLog: {
      create: createAsyncMethod([{ id: 'assumption-stub' }]),
      find: createAsyncMethod([]),
      update: createAsyncMethod([{ id: 'assumption-stub' }]),
      delete: createAsyncMethod(true),
    },

    knowledgeEntity: {
      create: createAsyncMethod([{ id: 'entity-stub' }]),
      find: createAsyncMethod([]),
      update: createAsyncMethod([{ id: 'entity-stub' }]),
      delete: createAsyncMethod(true),
    },

    knowledgeRelation: {
      create: createAsyncMethod([{ id: 'relation-stub' }]),
      find: createAsyncMethod([]),
      update: createAsyncMethod([{ id: 'relation-stub' }]),
      delete: createAsyncMethod(true),
    },

    knowledgeObservation: {
      create: createAsyncMethod([{ id: 'observation-stub' }]),
      find: createAsyncMethod([]),
      update: createAsyncMethod([{ id: 'observation-stub' }]),
      delete: createAsyncMethod(true),
    },
  };

  // Apply failures to specified methods
  failMethods.forEach(methodName => {
    const path = methodName.split('.');
    let target = client;
    for (let i = 0; i < path.length - 1; i++) {
      target = target[path[i]];
    }
    const finalMethod = path[path.length - 1];
    if (target[finalMethod] && typeof target[finalMethod].mockImplementation === 'function') {
      target[finalMethod].mockImplementation(async () => {
        throw new Error(`Mock method ${methodName} configured to fail`);
      });
    }
  });

  return client as QdrantClient & typeof client;
};

/**
 * Database Adapter Mock Template
 *
 * Mocks the database adapter layer with common operations
 */
export interface MockDatabaseConfig {
  shouldFail?: boolean;
  failOperations?: string[];
  connectionStatus?: 'connected' | 'disconnected' | 'error';
  latency?: number;
}

export const createMockDatabaseAdapter = (config: MockDatabaseConfig = {}) => {
  const {
    shouldFail = false,
    failOperations = [],
    connectionStatus = 'connected',
    latency = 0,
  } = config;

  const createAsyncOperation = <T>(returnValue: T, operationName: string) =>
    vi.fn(async (..._args: any[]) => {
      if (latency > 0) {
        await new Promise(resolve => setTimeout(resolve, latency));
      }
      if (shouldFail || failOperations.includes(operationName)) {
        throw new Error(`Database operation ${operationName} failed`);
      }
      return returnValue;
    });

  return {
    connect: createAsyncOperation(undefined, 'connect'),
    disconnect: createAsyncOperation(undefined, 'disconnect'),
    healthCheck: createAsyncOperation(connectionStatus === 'connected', 'healthCheck'),

    // Memory operations
    store: createAsyncOperation({ id: 'test-id', status: 'stored' }, 'store'),
    find: createAsyncOperation({ results: [], total: 0 }, 'find'),
    update: createAsyncOperation({ id: 'test-id', status: 'updated' }, 'update'),
    delete: createAsyncOperation({ deleted: true }, 'delete'),

    // Batch operations
    batchStore: createAsyncOperation({ stored: 0, skipped: 0 }, 'batchStore'),
    batchDelete: createAsyncOperation({ deleted: 0 }, 'batchDelete'),

    // Search operations
    semanticSearch: createAsyncOperation({ results: [], scores: [] }, 'semanticSearch'),
    hybridSearch: createAsyncOperation({ results: [], scores: [] }, 'hybridSearch'),

    // Connection info
    getConnectionInfo: vi.fn(() => ({
      status: connectionStatus,
      url: 'http://localhost:6333',
      connectedAt: new Date(),
      poolSize: 5,
    })),
  };
};

/**
 * Auth Service Mock Template
 *
 * Mocks authentication service with JWT and user management
 */
export interface MockAuthServiceConfig {
  shouldFail?: boolean;
  failOperations?: string[];
  validUsers?: any[];
  validApiKeys?: any[];
  _tokens?: Record<string, any>;
}

export const createMockAuthService = (config: MockAuthServiceConfig = {}) => {
  const {
    shouldFail = false,
    failOperations = [],
    validUsers = [
      {
        id: 'test-user-1',
        username: 'testuser',
        email: 'test@example.com',
        role: 'user',
        is_active: true,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      },
    ],
    validApiKeys = [
      {
        id: 'test-key-1',
        key_id: 'ck_test_1234567890abcdef',
        key_hash: 'test-hash',
        user_id: 'test-user-1',
        name: 'Test API Key',
        scopes: ['memory:read', 'memory:write'],
        is_active: true,
        created_at: new Date().toISOString(),
      },
    ],
    _tokens = {},
  } = config;

  const createAsyncOperation = <T>(returnValue: T, operationName: string) =>
    vi.fn(async (..._args: any[]) => {
      if (shouldFail || failOperations.includes(operationName)) {
        throw new Error(`Auth operation ${operationName} failed`);
      }
      return returnValue;
    });

  return {
    // User operations
    validateUserWithDatabase: createAsyncOperation(validUsers[0], 'validateUserWithDatabase'),
    hashPassword: createAsyncOperation('hashed-password', 'hashPassword'),
    verifyPassword: createAsyncOperation(true, 'verifyPassword'),

    // Token operations
    generateAccessToken: vi.fn(() => 'test-access-token'),
    generateRefreshToken: vi.fn(() => 'test-refresh-token'),
    verifyAccessToken: createAsyncOperation({
      sub: 'test-user-1',
      username: 'testuser',
      role: 'user',
      scopes: ['memory:read', 'memory:write'],
      jti: 'test-token-id',
      session_id: 'test-session-id',
    }, 'verifyAccessToken'),
    verifyRefreshToken: vi.fn(() => ({
      sub: 'test-user-1',
      session_id: 'test-session-id',
      type: 'refresh',
    })),
    revokeToken: createAsyncOperation(undefined, 'revokeToken'),

    // API Key operations
    generateApiKey: vi.fn(() => ({
      keyId: 'ck_test_1234567890abcdef',
      key: 'ck_test_1234567890abcdef1234567890abcdef',
    })),
    hashApiKey: createAsyncOperation('hashed-api-key', 'hashApiKey'),
    verifyApiKey: createAsyncOperation(true, 'verifyApiKey'),
    validateApiKeyWithDatabase: createAsyncOperation({
      user: validUsers[0],
      scopes: ['memory:read', 'memory:write'],
      apiKeyInfo: validApiKeys[0],
    }, 'validateApiKeyWithDatabase'),

    // Session operations
    createSession: vi.fn(() => ({
      id: 'test-session-id',
      user_id: 'test-user-1',
      session_token: 'test-session-token',
      ip_address: '127.0.0.1',
      user_agent: 'test-agent',
      created_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 3600_000).toISOString(),
      is_active: true,
    })),
    getSession: vi.fn(() => ({
      id: 'test-session-id',
      user_id: 'test-user-1',
      is_active: true,
    })),
    revokeSession: createAsyncOperation(undefined, 'revokeSession'),

    // Authorization operations
    getUserScopes: vi.fn(() => ['memory:read', 'memory:write']),
    validateScopes: vi.fn(() => true),
    canAccessResource: vi.fn(() => true),

    // Health check
    getHealthStatus: vi.fn(() => ({
      status: 'healthy',
      details: {
        active_sessions: 1,
        blacklisted_tokens: 0,
        circuit_breaker_open: false,
      },
    })),
  };
};

/**
 * Memory Store Mock Template
 *
 * Mocks the memory store operations for knowledge items
 */
export interface MockMemoryStoreConfig {
  shouldFail?: boolean;
  failOperations?: string[];
  storedItems?: any[];
  searchResults?: any[];
}

export const createMockMemoryStore = (config: MockMemoryStoreConfig = {}) => {
  const {
    shouldFail = false,
    failOperations = [],
    storedItems = [],
    searchResults = [],
  } = config;

  const createAsyncOperation = <T>(returnValue: T, operationName: string) =>
    vi.fn(async (..._args: any[]) => {
      if (shouldFail || failOperations.includes(operationName)) {
        throw new Error(`Memory store operation ${operationName} failed`);
      }
      return returnValue;
    });

  return {
    store: createAsyncOperation({
      id: 'test-memory-id',
      status: 'stored',
      created_at: new Date().toISOString(),
    }, 'store'),

    find: createAsyncOperation({
      results: searchResults,
      total: searchResults.length,
      query: 'test',
      strategy: 'semantic',
    }, 'find'),

    update: createAsyncOperation({
      id: 'test-memory-id',
      status: 'updated',
      updated_at: new Date().toISOString(),
    }, 'update'),

    delete: createAsyncOperation({
      deleted: true,
      id: 'test-memory-id',
    }, 'delete'),

    batchStore: createAsyncOperation({
      stored: storedItems.length,
      skipped: 0,
      errors: [],
    }, 'batchStore'),

    batchDelete: createAsyncOperation({
      deleted: 1,
      errors: [],
    }, 'batchDelete'),

    // Deduplication
    checkDuplicates: createAsyncOperation([], 'checkDuplicates'),

    // Similarity
    findSimilar: createAsyncOperation([], 'findSimilar'),

    // Analytics
    getStats: createAsyncOperation({
      totalItems: storedItems.length,
      itemsByType: {},
      recentActivity: [],
    }, 'getStats'),
  };
};

/**
 * Embedding Service Mock Template
 *
 * Mocks the embedding service with deterministic vectors
 */
export const createMockEmbeddingService = (config: MockEmbeddingConfig = {}) => {
  return new MockEmbeddingService(config);
};

/**
 * Utility function to create a complete mock environment
 *
 * Creates mocks for all commonly used dependencies in one call
 */
export const createMockTestEnvironment = (overrides: {
  environment?: MockEnvironmentConfig;
  qdrant?: MockQdrantConfig;
  database?: MockDatabaseConfig;
  auth?: MockAuthServiceConfig;
  memoryStore?: MockMemoryStoreConfig;
  embedding?: MockEmbeddingConfig;
} = {}) => {
  const mockEnvironment = createMockEnvironment(overrides.environment);
  const mockQdrantClient = createMockQdrantClient(overrides.qdrant);
  const mockDatabaseAdapter = createMockDatabaseAdapter(overrides.database);
  const mockAuthService = createMockAuthService(overrides.auth);
  const mockMemoryStore = createMockMemoryStore(overrides.memoryStore);
  const mockEmbeddingService = createMockEmbeddingService(overrides.embedding);
  const mockLogger = createMockLogger();

  return {
    environment: mockEnvironment,
    qdrantClient: mockQdrantClient,
    databaseAdapter: mockDatabaseAdapter,
    authService: mockAuthService,
    memoryStore: mockMemoryStore,
    embeddingService: mockEmbeddingService,
    logger: mockLogger,

    // Helper methods for common test patterns
    resetAllMocks: () => {
      mockEnvironment.getInstance.mockClear();
      Object.values(mockQdrantClient).forEach(method => {
        if (method && typeof method.mockClear === 'function') {
          method.mockClear();
        }
      });
      Object.values(mockDatabaseAdapter).forEach(method => {
        if (method && typeof method.mockClear === 'function') {
          method.mockClear();
        }
      });
      Object.values(mockAuthService).forEach(method => {
        if (method && typeof method.mockClear === 'function') {
          method.mockClear();
        }
      });
      Object.values(mockMemoryStore).forEach(method => {
        if (method && typeof method.mockClear === 'function') {
          method.mockClear();
        }
      });
      Object.values(mockLogger).forEach(method => {
        if (method && typeof method.mockClear === 'function') {
          method.mockClear();
        }
      });
    },

    // Helper to verify no unexpected calls were made
    expectNoUnexpectedCalls: () => {
      // Implementation depends on specific test requirements
    },
  };
};

/**
 * Mock data generators for common test scenarios
 */
export const MockDataGenerators = {
  user: (overrides = {}) => ({
    id: 'test-user-id',
    username: 'testuser',
    email: 'test@example.com',
    role: 'user',
    is_active: true,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    last_login: new Date().toISOString(),
    ...overrides,
  }),

  knowledgeItem: (overrides = {}) => ({
    id: 'test-knowledge-id',
    kind: 'entity',
    content: 'Test knowledge content',
    scope: {
      project: 'test-project',
      branch: 'test-branch',
      org: 'test-org',
    },
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    metadata: {
      source: 'test',
      confidence: 0.9,
    },
    ...overrides,
  }),

  memoryQuery: (overrides = {}) => ({
    query: 'test query',
    limit: 10,
    mode: 'auto',
    scope: {
      project: 'test-project',
      branch: 'test-branch',
    },
    types: ['entity', 'observation'],
    ...overrides,
  }),

  searchResult: (overrides = {}) => ({
    id: 'test-result-id',
    score: 0.95,
    kind: 'entity',
    content: 'Test result content',
    snippet: 'Test snippet...',
    metadata: {
      confidence: 0.95,
      match_type: 'semantic',
    },
    ...overrides,
  }),
};

export default {
  createMockEnvironment,
  createMockLogger,
  createMockQdrantClient,
  createMockDatabaseAdapter,
  createMockAuthService,
  createMockMemoryStore,
  createMockTestEnvironment,
  MockDataGenerators,
};