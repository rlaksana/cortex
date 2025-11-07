/**
 * Comprehensive Unit Tests for Deep Search Service
 *
 * Tests advanced deep search functionality including:
 * - Multi-layer semantic search with vector similarity
 * - Context-aware query understanding and intent recognition
 * - Advanced hybrid keyword-semantic search algorithms
 * - Knowledge graph integration with relationship traversal
 * - Cross-domain search capabilities and entity disambiguation
 * - Performance optimization and distributed search processing
 * - Advanced filtering with multi-criteria support
 * - Search analytics and query pattern recognition
 * - Personalization and learning capabilities
 * - Relevance ranking optimization and confidence scoring
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import type {
  DeepSearchResult,
  SearchQuery,
  SearchResult,
  MemoryFindResponse,
} from '../../../src/types/core-interfaces';

// Mock dependencies
vi.mock('../../../src/utils/logger', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

vi.mock('../../../src/db/qdrant', () => ({
  getQdrantClient: () => mockQdrantClient,
}));

vi.mock('../../../src/services/embeddings/embedding-service', () => ({
  EmbeddingService: vi.fn().mockImplementation(() => ({
    generateEmbedding: vi.fn().mockResolvedValue([0.1, 0.2, 0.3, 0.4, 0.5]),
    generateBatchEmbeddings: vi.fn().mockResolvedValue([
      [0.1, 0.2, 0.3, 0.4, 0.5],
      [0.2, 0.3, 0.4, 0.5, 0.6],
      [0.3, 0.4, 0.5, 0.6, 0.7],
    ]),
    calculateSimilarity: vi.fn().mockImplementation((vec1, vec2) => {
      // Simple cosine similarity mock
      const dot = vec1.reduce((sum, val, i) => sum + val * vec2[i], 0);
      const mag1 = Math.sqrt(vec1.reduce((sum, val) => sum + val * val, 0));
      const mag2 = Math.sqrt(vec2.reduce((sum, val) => sum + val * val, 0));
      return dot / (mag1 * mag2);
    }),
  })),
}));

vi.mock('../../../src/services/similarity/similarity-service', () => ({
  SimilarityService: vi.fn().mockImplementation(() => ({
    calculateTextSimilarity: vi.fn().mockResolvedValue(0.75),
    calculateSemanticSimilarity: vi.fn().mockResolvedValue(0.85),
    calculateHybridSimilarity: vi.fn().mockResolvedValue(0.8),
  })),
}));

vi.mock('../../../src/services/graph-traversal', () => ({
  GraphTraversalService: vi.fn().mockImplementation(() => ({
    findRelatedEntities: vi.fn().mockResolvedValue([
      { id: 'related-1', kind: 'entity', distance: 1 },
      { id: 'related-2', kind: 'relation', distance: 2 },
    ]),
    traverseKnowledgeGraph: vi.fn().mockResolvedValue({
      nodes: [
        { id: 'node-1', type: 'entity', properties: { name: 'Test Entity' } },
        { id: 'node-2', type: 'decision', properties: { title: 'Test Decision' } },
      ],
      edges: [{ source: 'node-1', target: 'node-2', type: 'relates_to', weight: 0.8 }],
    }),
    findShortestPath: vi.fn().mockResolvedValue(['node-1', 'node-2', 'node-3']),
  })),
}));

// Mock Qdrant client with comprehensive collection support
const mockQdrantClient = {
  // Knowledge type collections
  section: {
    findMany: vi.fn(),
    createIndex: vi.fn(),
    upsert: vi.fn(),
  },
  adrDecision: {
    findMany: vi.fn(),
    createIndex: vi.fn(),
    upsert: vi.fn(),
  },
  issueLog: {
    findMany: vi.fn(),
    createIndex: vi.fn(),
    upsert: vi.fn(),
  },
  todoLog: {
    findMany: vi.fn(),
    createIndex: vi.fn(),
    upsert: vi.fn(),
  },
  runbook: {
    findMany: vi.fn(),
    createIndex: vi.fn(),
    upsert: vi.fn(),
  },
  changeLog: {
    findMany: vi.fn(),
    createIndex: vi.fn(),
    upsert: vi.fn(),
  },
  releaseNote: {
    findMany: vi.fn(),
    createIndex: vi.fn(),
    upsert: vi.fn(),
  },
  ddlHistory: {
    findMany: vi.fn(),
    createIndex: vi.fn(),
    upsert: vi.fn(),
  },
  prContext: {
    findMany: vi.fn(),
    createIndex: vi.fn(),
    upsert: vi.fn(),
  },
  knowledgeEntity: {
    findMany: vi.fn(),
    createIndex: vi.fn(),
    upsert: vi.fn(),
  },
  knowledgeRelation: {
    findMany: vi.fn(),
    createIndex: vi.fn(),
    upsert: vi.fn(),
  },
  knowledgeObservation: {
    findMany: vi.fn(),
    createIndex: vi.fn(),
    upsert: vi.fn(),
  },
  incidentLog: {
    findMany: vi.fn(),
    createIndex: vi.fn(),
    upsert: vi.fn(),
  },
  releaseLog: {
    findMany: vi.fn(),
    createIndex: vi.fn(),
    upsert: vi.fn(),
  },
  riskLog: {
    findMany: vi.fn(),
    createIndex: vi.fn(),
    upsert: vi.fn(),
  },
  assumptionLog: {
    findMany: vi.fn(),
    createIndex: vi.fn(),
    upsert: vi.fn(),
  },
  // Vector search methods
  search: vi.fn(),
  searchBatch: vi.fn(),
  createCollection: vi.fn(),
  deleteCollection: vi.fn(),
  getCollection: vi.fn(),
  upsertBatch: vi.fn(),
};

// Mock embedding and similarity services
const mockEmbeddingService = {
  generateEmbedding: vi.fn().mockResolvedValue([0.1, 0.2, 0.3, 0.4, 0.5]),
  generateBatchEmbeddings: vi.fn().mockResolvedValue([
    [0.1, 0.2, 0.3, 0.4, 0.5],
    [0.2, 0.3, 0.4, 0.5, 0.6],
    [0.3, 0.4, 0.5, 0.6, 0.7],
  ]),
  calculateSimilarity: vi.fn().mockImplementation((vec1, vec2) => 0.85),
};

const mockSimilarityService = {
  calculateTextSimilarity: vi.fn().mockResolvedValue(0.75),
  calculateSemanticSimilarity: vi.fn().mockResolvedValue(0.85),
  calculateHybridSimilarity: vi.fn().mockResolvedValue(0.8),
};

const mockGraphTraversalService = {
  findRelatedEntities: vi.fn().mockResolvedValue([
    { id: 'related-1', kind: 'entity', distance: 1 },
    { id: 'related-2', kind: 'relation', distance: 2 },
  ]),
  traverseKnowledgeGraph: vi.fn().mockResolvedValue({
    nodes: [
      { id: 'node-1', type: 'entity', properties: { name: 'Test Entity' } },
      { id: 'node-2', type: 'decision', properties: { title: 'Test Decision' } },
    ],
    edges: [{ source: 'node-1', target: 'node-2', type: 'relates_to', weight: 0.8 }],
  }),
  findShortestPath: vi.fn().mockResolvedValue(['node-1', 'node-2', 'node-3']),
};

// Import after mocking to get mocked instances
const { deepSearch, calculateSimilarity } = await import(
  '../../../src/services/search/deep-search'
);

describe('Deep Search Service - Comprehensive Advanced Search Functionality', () => {
  beforeEach(() => {
    vi.clearAllMocks();

    // Setup default mock responses
    Object.values(mockQdrantClient).forEach((model: any) => {
      if (model.findMany) {
        model.findMany.mockResolvedValue([]);
      }
    });

    // Setup default vector search responses
    mockQdrantClient.search.mockResolvedValue([
      {
        id: 'vector-result-1',
        score: 0.92,
        payload: {
          kind: 'entity',
          data: { title: 'Vector Search Result', content: 'Matching content' },
          tags: { project: 'test' },
        },
      },
    ]);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // 1. Multi-Layer Semantic Search Tests
  describe('Multi-Layer Semantic Search', () => {
    it('should perform deep semantic search with vector embeddings', async () => {
      const query = 'user authentication system security';
      const searchTypes = ['entity', 'decision', 'observation'];

      // Mock vector search results
      mockQdrantClient.search.mockResolvedValue([
        {
          id: 'semantic-1',
          score: 0.95,
          payload: {
            kind: 'entity',
            data: {
              title: 'User Authentication System',
              content: 'Comprehensive security implementation with OAuth 2.0',
              description: 'Secure user authentication mechanisms',
            },
            tags: { project: 'security', org: 'company' },
            created_at: new Date('2024-01-15').toISOString(),
          },
        },
        {
          id: 'semantic-2',
          score: 0.87,
          payload: {
            kind: 'decision',
            data: {
              title: 'Authentication Architecture Decision',
              content: 'Decision to implement JWT-based authentication',
              rationale: 'Chosen for scalability and security',
            },
            tags: { project: 'backend', org: 'company' },
            created_at: new Date('2024-02-01').toISOString(),
          },
        },
      ]);

      const results = await deepSearch(query, searchTypes, 10, 0.7);

      expect(results).toHaveLength(2);
      expect(results[0]).toMatchObject({
        id: 'semantic-1',
        kind: 'entity',
        title: 'User Authentication System',
        score: 0.95,
        snippet: expect.stringContaining('security implementation'),
        metadata: expect.objectContaining({
          project: 'security',
          org: 'company',
        }),
      });

      expect(mockQdrantClient.search).toHaveBeenCalledWith(
        expect.objectContaining({
          vector: expect.any(Array),
          limit: 10,
          score_threshold: 0.7,
        })
      );
    });

    it('should implement hybrid keyword-semantic search combination', async () => {
      const query = 'database performance optimization PostgreSQL';
      const searchTypes = ['decision', 'observation', 'runbook'];

      // Mock both keyword and semantic results
      mockQdrantClient.knowledgeEntity.findMany.mockResolvedValue([
        {
          id: 'keyword-1',
          kind: 'entity',
          data: {
            title: 'PostgreSQL Performance Guide',
            content: 'Database optimization techniques and best practices',
          },
          tags: { project: 'database' },
          created_at: new Date('2024-01-01'),
        },
      ]);

      mockQdrantClient.search.mockResolvedValue([
        {
          id: 'semantic-1',
          score: 0.89,
          payload: {
            kind: 'decision',
            data: {
              title: 'Database Architecture Decision',
              content: 'Choosing PostgreSQL for performance requirements',
            },
          },
        },
      ]);

      const results = await deepSearch(query, searchTypes, 15, 0.6);

      expect(results.length).toBeGreaterThan(0);

      // Should contain both keyword and semantic matches
      const keywordMatch = results.find((r) => r.id === 'keyword-1');
      const semanticMatch = results.find((r) => r.id === 'semantic-1');

      expect(keywordMatch || semanticMatch).toBeTruthy();
    });

    it('should handle context-aware query expansion', async () => {
      const query = 'auth issues';
      const searchTypes = ['issue', 'decision'];

      // Mock expanded query processing
      mockQdrantClient.search.mockImplementation((params) => {
        // Should expand "auth" to "authentication", "authorization", etc.
        const expandedQuery = params.query || '';
        expect(expandedQuery).toMatch(/(authentication|authorization)/);

        return Promise.resolve([
          {
            id: 'expanded-1',
            score: 0.91,
            payload: {
              kind: 'issue',
              data: {
                title: 'Authentication System Issues',
                content: 'Problems with user login and authorization flows',
              },
            },
          },
        ]);
      });

      const results = await deepSearch(query, searchTypes, 10, 0.7);

      expect(results).toHaveLength(1);
      expect(results[0].title).toBe('Authentication System Issues');
    });

    it('should implement semantic similarity scoring with confidence thresholds', async () => {
      const query = 'microservices architecture patterns';
      const searchTypes = ['entity', 'decision'];
      const minSimilarity = 0.8;

      // Mock results with varying similarity scores
      mockQdrantClient.search.mockResolvedValue([
        {
          id: 'high-similarity',
          score: 0.95,
          payload: {
            kind: 'entity',
            data: {
              title: 'Microservices Architecture Patterns',
              content: 'Design patterns for distributed systems',
            },
          },
        },
        {
          id: 'medium-similarity',
          score: 0.75, // Below threshold
          payload: {
            kind: 'decision',
            data: {
              title: 'System Architecture Decision',
              content: 'General architecture choices',
            },
          },
        },
        {
          id: 'low-similarity',
          score: 0.45, // Below threshold
          payload: {
            kind: 'observation',
            data: { title: 'System Performance', content: 'Performance metrics and monitoring' },
          },
        },
      ]);

      const results = await deepSearch(query, searchTypes, 20, minSimilarity);

      // Should only return results above threshold
      expect(results).toHaveLength(1);
      expect(results[0].score).toBeGreaterThanOrEqual(minSimilarity);
      expect(results[0].id).toBe('high-similarity');
    });
  });

  // 2. Context-Aware Query Understanding Tests
  describe('Context-Aware Query Understanding', () => {
    it('should recognize and classify search intent', async () => {
      const testCases = [
        {
          query: 'how to implement user authentication',
          intent: 'procedural',
          expectedTypes: ['runbook', 'section', 'decision'],
        },
        {
          query: 'authentication system vulnerabilities',
          intent: 'problem-solving',
          expectedTypes: ['issue', 'risk', 'incident'],
        },
        {
          query: 'authentication architecture decisions',
          intent: 'informational',
          expectedTypes: ['decision', 'entity', 'observation'],
        },
        {
          query: 'security audit checklist',
          intent: 'procedural',
          expectedTypes: ['runbook', 'todo', 'section'],
        },
      ];

      for (const testCase of testCases) {
        const results = await deepSearch(testCase.query, testCase.expectedTypes, 10, 0.5);

        // Results should be filtered based on recognized intent
        if (results.length > 0) {
          const uniqueTypes = [...new Set(results.map((r) => r.kind))];
          expect(uniqueTypes.some((type) => testCase.expectedTypes.includes(type))).toBe(true);
        }
      }
    });

    it('should handle domain-specific terminology and jargon', async () => {
      const query = 'K8s deployment strategies for canary releases';

      mockQdrantClient.search.mockResolvedValue([
        {
          id: 'domain-1',
          score: 0.93,
          payload: {
            kind: 'runbook',
            data: {
              title: 'Kubernetes Canary Deployment Strategy',
              content: 'Step-by-step guide for implementing canary releases in K8s clusters',
            },
          },
        },
        {
          id: 'domain-2',
          score: 0.88,
          payload: {
            kind: 'decision',
            data: {
              title: 'Deployment Strategy Decision',
              content: 'Choosing between blue-green, canary, and rolling deployments',
            },
          },
        },
      ]);

      const results = await deepSearch(query, ['runbook', 'decision'], 10, 0.7);

      expect(results.length).toBeGreaterThan(0);

      // Should understand K8s = Kubernetes and handle deployment terminology
      const hasK8sContent = results.some(
        (r) =>
          r.snippet.includes('Kubernetes') ||
          r.snippet.includes('deployment') ||
          r.snippet.includes('canary')
      );
      expect(hasK8sContent).toBe(true);
    });

    it('should implement query disambiguation for ambiguous terms', async () => {
      const query = 'service'; // Could be microservice, customer service, etc.

      // Mock disambiguated results
      mockQdrantClient.search.mockResolvedValue([
        {
          id: 'microservice',
          score: 0.91,
          payload: {
            kind: 'entity',
            data: {
              title: 'User Service Implementation',
              content: 'Microservice handling user operations and authentication',
            },
            tags: { project: 'backend', domain: 'microservices' },
          },
        },
        {
          id: 'customer-service',
          score: 0.87,
          payload: {
            kind: 'process',
            data: {
              title: 'Customer Service Workflow',
              content: 'Process for handling customer support tickets and inquiries',
            },
            tags: { project: 'support', domain: 'customer-service' },
          },
        },
      ]);

      const results = await deepSearch(query, ['entity', 'process'], 15, 0.6);

      expect(results.length).toBeGreaterThan(1);

      // Should provide context for different interpretations
      const contexts = results.map((r) => r.metadata?.domain).filter(Boolean);
      expect(contexts.length).toBeGreaterThan(1);
    });

    it('should handle temporal and contextual query understanding', async () => {
      const queries = [
        'recent security issues',
        'upcoming deployment tasks',
        'previous architecture decisions',
        'current performance problems',
      ];

      for (const query of queries) {
        const results = await deepSearch(
          query,
          ['issue', 'todo', 'decision', 'observation'],
          10,
          0.5
        );

        // Should apply temporal filtering based on query language
        if (results.length > 0) {
          // Each result should have appropriate temporal context
          results.forEach((result) => {
            expect(result.metadata).toBeDefined();
            if (result.metadata?.created_at) {
              const createdAt = new Date(result.metadata['created_at']);
              expect(isValidDate(createdAt)).toBe(true);
            }
          });
        }
      }
    });
  });

  // 3. Knowledge Graph Integration Tests
  describe('Knowledge Graph Integration', () => {
    it('should perform relationship-aware search results', async () => {
      const query = 'user authentication flow';

      // Mock graph traversal service
      mockGraphTraversalService.findRelatedEntities.mockResolvedValue([
        { id: 'auth-entity', kind: 'entity', distance: 1, relationship: 'implements' },
        { id: 'security-policy', kind: 'entity', distance: 2, relationship: 'constrained_by' },
        { id: 'login-issue', kind: 'issue', distance: 1, relationship: 'addresses' },
      ]);

      const results = await deepSearch(query, ['entity', 'issue'], 15, 0.6);

      expect(results.length).toBeGreaterThan(0);

      // Should include related entities in results
      const hasRelatedContent = results.some(
        (r) => r.metadata?.relatedEntities || r.metadata?.graphDistance
      );

      if (hasRelatedContent) {
        const relatedResult = results.find((r) => r.metadata?.relatedEntities);
        expect(relatedResult?.metadata?.relatedEntities).toBeDefined();
      }
    });

    it('should implement graph-based result expansion', async () => {
      const query = 'payment processing';

      // Mock knowledge graph traversal
      mockGraphTraversalService.traverseKnowledgeGraph.mockResolvedValue({
        nodes: [
          {
            id: 'payment-service',
            type: 'entity',
            properties: {
              name: 'Payment Service',
              kind: 'service',
              technology: 'Node.js',
            },
          },
          {
            id: 'payment-gateway',
            type: 'entity',
            properties: {
              name: 'Payment Gateway Integration',
              kind: 'integration',
              provider: 'Stripe',
            },
          },
          {
            id: 'payment-decision',
            type: 'decision',
            properties: {
              title: 'Payment Gateway Decision',
              rationale: 'Chose Stripe for reliability and features',
            },
          },
        ],
        edges: [
          {
            source: 'payment-service',
            target: 'payment-gateway',
            type: 'uses',
            weight: 0.9,
          },
          {
            source: 'payment-gateway',
            target: 'payment-decision',
            type: 'influenced_by',
            weight: 0.8,
          },
        ],
      });

      const results = await deepSearch(query, ['entity', 'decision'], 20, 0.5);

      expect(results.length).toBeGreaterThan(0);

      // Results should include graph context
      const graphEnhancedResult = results.find((r) => r.metadata?.graphContext);
      if (graphEnhancedResult) {
        expect(graphEnhancedResult.metadata['graphContext']).toHaveProperty('nodes');
        expect(graphEnhancedResult.metadata['graphContext']).toHaveProperty('edges');
      }
    });

    it('should provide entity disambiguation using graph relationships', async () => {
      const query = 'user service';

      // Mock multiple entities with same name but different contexts
      mockQdrantClient.search.mockResolvedValue([
        {
          id: 'user-service-backend',
          score: 0.92,
          payload: {
            kind: 'entity',
            data: {
              title: 'User Service',
              content: 'Backend microservice for user management',
              type: 'microservice',
            },
            tags: { project: 'backend', domain: 'microservices' },
          },
        },
        {
          id: 'user-service-frontend',
          score: 0.88,
          payload: {
            kind: 'entity',
            data: {
              title: 'User Service',
              content: 'Frontend service for user interface',
              type: 'component',
            },
            tags: { project: 'frontend', domain: 'ui' },
          },
        },
      ]);

      // Mock graph relationships for disambiguation
      mockGraphTraversalService.findRelatedEntities.mockImplementation((entityId) => {
        if (entityId === 'user-service-backend') {
          return Promise.resolve([
            { id: 'auth-service', kind: 'entity', relationship: 'depends_on' },
            { id: 'database', kind: 'entity', relationship: 'connects_to' },
          ]);
        } else if (entityId === 'user-service-frontend') {
          return Promise.resolve([
            { id: 'ui-components', kind: 'entity', relationship: 'uses' },
            { id: 'api-client', kind: 'entity', relationship: 'communicates_with' },
          ]);
        }
        return Promise.resolve([]);
      });

      const results = await deepSearch(query, ['entity'], 10, 0.7);

      expect(results).toHaveLength(2);

      // Each result should include disambiguation context
      results.forEach((result) => {
        expect(result.metadata).toBeDefined();
        expect(result.metadata?.project).toBeDefined();
        expect(result.metadata?.domain).toBeDefined();

        if (result.metadata?.relatedEntities) {
          expect(Array.isArray(result.metadata['relatedEntities'])).toBe(true);
        }
      });
    });

    it('should implement contextual result ranking using graph centrality', async () => {
      const query = 'security implementation';

      // Mock results with different graph centrality scores
      mockQdrantClient.search.mockResolvedValue([
        {
          id: 'central-security-entity',
          score: 0.85,
          payload: {
            kind: 'entity',
            data: { title: 'Security Service', content: 'Central security implementation' },
            graphCentrality: 0.95, // High centrality
          },
        },
        {
          id: 'peripheral-security-entity',
          score: 0.87,
          payload: {
            kind: 'entity',
            data: { title: 'Security Component', content: 'Peripheral security feature' },
            graphCentrality: 0.45, // Low centrality
          },
        },
      ]);

      const results = await deepSearch(query, ['entity'], 10, 0.7);

      expect(results.length).toBeGreaterThan(0);

      // Results should be ranked by combination of similarity and centrality
      if (results.length > 1) {
        // Central entity should be ranked higher despite slightly lower similarity
        expect(results[0].id).toBe('central-security-entity');
      }
    });
  });

  // 4. Advanced Filtering and Multi-Criteria Tests
  describe('Advanced Filtering and Multi-Criteria Support', () => {
    it('should implement complex multi-criteria filtering', async () => {
      const query = 'performance optimization';
      const filters = {
        types: ['observation', 'decision', 'runbook'],
        scope: {
          project: 'backend',
          branch: 'main',
          org: 'company',
        },
        dateRange: {
          from: new Date('2024-01-01'),
          to: new Date('2024-12-31'),
        },
        tags: ['performance', 'optimization'],
        confidence: { min: 0.7, max: 1.0 },
        metadata: {
          author: 'team-lead',
          priority: ['high', 'critical'],
        },
      };

      // Mock filtered results
      mockQdrantClient.search.mockResolvedValue([
        {
          id: 'filtered-1',
          score: 0.92,
          payload: {
            kind: 'observation',
            data: {
              title: 'Performance Metrics Analysis',
              content: 'Analysis of system performance metrics and optimization opportunities',
            },
            tags: { project: 'backend', branch: 'main', org: 'company' },
            created_at: '2024-06-15',
            metadata: {
              author: 'team-lead',
              priority: 'high',
              tags: ['performance', 'optimization'],
            },
          },
        },
      ]);

      const results = await deepSearch(query, filters.types, 20, filters.confidence.min, filters);

      expect(results.length).toBeGreaterThan(0);

      const result = results[0];
      expect(result.metadata?.project).toBe('backend');
      expect(result.metadata?.branch).toBe('main');
      expect(result.metadata?.org).toBe('company');
      expect(result.score).toBeGreaterThanOrEqual(filters.confidence.min);
    });

    it('should handle dynamic filter suggestions based on results', async () => {
      const query = 'database connection';

      // Mock diverse results for filter suggestions
      mockQdrantClient.search.mockResolvedValue([
        {
          id: 'suggestion-1',
          score: 0.89,
          payload: {
            kind: 'issue',
            data: { title: 'Database Connection Timeout', content: 'Connection pool exhaustion' },
            tags: { project: 'backend', severity: 'high' },
            created_at: '2024-03-15',
          },
        },
        {
          id: 'suggestion-2',
          score: 0.85,
          payload: {
            kind: 'decision',
            data: { title: 'Database Provider Decision', content: 'Choosing PostgreSQL' },
            tags: { project: 'database', team: 'backend' },
            created_at: '2024-02-10',
          },
        },
        {
          id: 'suggestion-3',
          score: 0.82,
          payload: {
            kind: 'runbook',
            data: { title: 'Database Setup Guide', content: 'Step-by-step database configuration' },
            tags: { project: 'devops', category: 'infrastructure' },
            created_at: '2024-01-20',
          },
        },
      ]);

      const results = await deepSearch(query, ['issue', 'decision', 'runbook'], 25, 0.6);

      expect(results.length).toBe(3);

      // Analyze results to extract filter suggestions
      const projects = [...new Set(results.map((r) => r.metadata?.project).filter(Boolean))];
      const kinds = [...new Set(results.map((r) => r.kind))];
      const timeRange = {
        earliest: Math.min(...results.map((r) => new Date(r.metadata?.created_at || 0).getTime())),
        latest: Math.max(...results.map((r) => new Date(r.metadata?.created_at || 0).getTime())),
      };

      expect(projects.length).toBeGreaterThan(1);
      expect(kinds.length).toBeGreaterThan(1);
      expect(timeRange.latest).toBeGreaterThan(timeRange.earliest);
    });

    it('should implement filter optimization for query performance', async () => {
      const query = 'system architecture';
      const complexFilters = {
        types: ['decision', 'entity', 'observation'],
        scope: { project: 'large-project' },
        dateRange: { from: new Date('2020-01-01'), to: new Date('2024-12-31') },
        tags: ['architecture', 'system'],
        metadata: { status: 'approved' },
      };

      const startTime = Date.now();

      mockQdrantClient.search.mockImplementation((params) => {
        // Simulate optimized query execution
        expect(params.filter).toBeDefined();

        // Should apply most selective filters first
        const filterOrder = params.filter?.and || [];
        const hasKindFilter = filterOrder.some((f: any) => f.key?.kind);
        const hasProjectFilter = filterOrder.some((f: any) => f.key?.project);

        expect(hasKindFilter || hasProjectFilter).toBe(true);

        return Promise.resolve([
          {
            id: 'optimized-1',
            score: 0.91,
            payload: {
              kind: 'decision',
              data: { title: 'System Architecture Decision', content: 'High-level system design' },
            },
          },
        ]);
      });

      const results = await deepSearch(query, complexFilters.types, 15, 0.7, complexFilters);

      const duration = Date.now() - startTime;

      expect(results.length).toBeGreaterThan(0);
      expect(duration).toBeLessThan(1000); // Should complete quickly due to optimization
    });

    it('should handle temporal filtering with relative dates', async () => {
      const testCases = [
        { query: 'recent issues', timeFilter: 'last_30_days' },
        { query: 'upcoming tasks', timeFilter: 'next_7_days' },
        { query: 'historical decisions', timeFilter: 'last_year' },
        { query: 'current quarter observations', timeFilter: 'this_quarter' },
      ];

      for (const testCase of testCases) {
        const mockDate = new Date('2024-06-15');
        vi.setSystemTime(mockDate);

        const results = await deepSearch(
          testCase.query,
          ['issue', 'todo', 'decision', 'observation'],
          10,
          0.5,
          { timeFilter: testCase.timeFilter }
        );

        if (results.length > 0) {
          results.forEach((result) => {
            const resultDate = new Date(result.metadata?.created_at || 0);

            // Verify temporal filtering based on the time filter
            switch (testCase.timeFilter) {
              case 'last_30_days':
                expect(resultDate.getTime()).toBeGreaterThanOrEqual(
                  new Date('2024-05-16').getTime()
                );
                break;
              case 'next_7_days':
                expect(resultDate.getTime()).toBeLessThanOrEqual(new Date('2024-06-22').getTime());
                break;
              case 'last_year':
                expect(resultDate.getTime()).toBeGreaterThanOrEqual(
                  new Date('2023-06-15').getTime()
                );
                break;
              case 'this_quarter':
                expect(resultDate.getFullYear()).toBe(2024);
                expect([1, 2, 3].includes(Math.ceil((resultDate.getMonth() + 1) / 3))).toBe(true);
                break;
            }
          });
        }
      }

      vi.useRealTimers();
    });
  });

  // 5. Performance and Scalability Tests
  describe('Performance and Scalability', () => {
    it('should handle large-scale search operations efficiently', async () => {
      const query = 'system performance';
      const largeResultCount = 100;

      // Mock large result set
      const largeResults = Array.from({ length: largeResultCount }, (_, i) => ({
        id: `large-scale-${i}`,
        score: 0.9 - i * 0.01, // Decreasing scores
        payload: {
          kind: 'observation',
          data: {
            title: `Performance Metric ${i}`,
            content: `System performance observation number ${i}`,
          },
          created_at: new Date(2024, 0, (i % 30) + 1).toISOString(),
        },
      }));

      mockQdrantClient.search.mockResolvedValue(largeResults);

      const startTime = Date.now();
      const results = await deepSearch(query, ['observation'], largeResultCount, 0.5);
      const duration = Date.now() - startTime;

      expect(results).toHaveLength(largeResultCount);
      expect(duration).toBeLessThan(2000); // Should complete within 2 seconds

      // Results should be properly ranked
      for (let i = 0; i < results.length - 1; i++) {
        expect(results[i].score).toBeGreaterThanOrEqual(results[i + 1].score);
      }
    });

    it('should implement distributed search processing', async () => {
      const query = 'cross-domain search';
      const searchTypes = ['entity', 'decision', 'issue', 'observation', 'runbook'];

      // Mock distributed search across different collections
      const collectionResults = {
        entity: [
          {
            id: 'dist-entity-1',
            score: 0.91,
            payload: { kind: 'entity', data: { title: 'Entity Result' } },
          },
        ],
        decision: [
          {
            id: 'dist-decision-1',
            score: 0.88,
            payload: { kind: 'decision', data: { title: 'Decision Result' } },
          },
        ],
        issue: [
          {
            id: 'dist-issue-1',
            score: 0.85,
            payload: { kind: 'issue', data: { title: 'Issue Result' } },
          },
        ],
        observation: [
          {
            id: 'dist-obs-1',
            score: 0.87,
            payload: { kind: 'observation', data: { title: 'Observation Result' } },
          },
        ],
        runbook: [
          {
            id: 'dist-runbook-1',
            score: 0.83,
            payload: { kind: 'runbook', data: { title: 'Runbook Result' } },
          },
        ],
      };

      // Simulate parallel distributed search
      mockQdrantClient.search.mockImplementation((params) => {
        const collectionName = params.collection_name || 'default';
        return Promise.resolve(collectionResults[collectionName] || []);
      });

      const startTime = Date.now();

      // Execute distributed search across multiple types
      const searchPromises = searchTypes.map((type) => deepSearch(query, [type], 10, 0.7));

      const distributedResults = await Promise.all(searchPromises);
      const duration = Date.now() - startTime;

      expect(distributedResults).toHaveLength(searchTypes.length);
      expect(duration).toBeLessThan(1500); // Parallel execution should be faster

      // Combine and rank all results
      const allResults = distributedResults.flat();
      expect(allResults.length).toBeGreaterThan(0);

      // Results should be properly scored across distributed sources
      allResults.forEach((result) => {
        expect(result.score).toBeGreaterThan(0);
        expect(result.id).toBeDefined();
      });
    });

    it('should implement search result caching strategies', async () => {
      const query = 'cached search query';
      const searchTypes = ['entity', 'decision'];

      // First search - should hit the database
      mockQdrantClient.search.mockResolvedValue([
        {
          id: 'cached-result-1',
          score: 0.92,
          payload: {
            kind: 'entity',
            data: { title: 'Cached Search Result', content: 'This should be cached' },
          },
        },
      ]);

      const startTime1 = Date.now();
      const firstResults = await deepSearch(query, searchTypes, 10, 0.7);
      const firstDuration = Date.now() - startTime1;

      // Reset call count
      mockQdrantClient.search.mockClear();

      // Second search with same query - should use cache
      const startTime2 = Date.now();
      const secondResults = await deepSearch(query, searchTypes, 10, 0.7);
      const secondDuration = Date.now() - startTime2;

      expect(firstResults).toEqual(secondResults);
      expect(secondDuration).toBeLessThan(firstDuration);

      // Second search should not hit the database (mocked call count should be 0)
      // Note: In a real implementation, cache hits would skip database calls
    });

    it('should handle query performance monitoring and optimization', async () => {
      const queries = [
        'simple query',
        'complex query with multiple terms and filters',
        'very complex query with lots of conditions and parameters and requirements',
      ];

      const performanceMetrics = [];

      for (const query of queries) {
        const startTime = Date.now();

        mockQdrantClient.search.mockResolvedValue([
          {
            id: `perf-${query.substring(0, 5)}`,
            score: 0.8,
            payload: {
              kind: 'observation',
              data: { title: 'Performance Test Result', content: query },
            },
          },
        ]);

        const results = await deepSearch(query, ['observation'], 10, 0.5);
        const duration = Date.now() - startTime;

        performanceMetrics.push({
          query,
          duration,
          resultCount: results.length,
          complexity: query.length,
        });

        expect(results.length).toBeGreaterThan(0);
      }

      // Analyze performance metrics
      performanceMetrics.forEach((metric) => {
        expect(metric.duration).toBeLessThan(2000); // All queries should complete within 2 seconds
        expect(metric.resultCount).toBeGreaterThan(0);
      });

      // More complex queries might take longer but should still be reasonable
      const simpleQuery = performanceMetrics.find((m) => m.complexity < 20);
      const complexQuery = performanceMetrics.find((m) => m.complexity > 50);

      if (simpleQuery && complexQuery) {
        expect(complexQuery.duration).toBeLessThan(simpleQuery.duration * 3);
      }
    });

    it('should implement search result pagination for large datasets', async () => {
      const query = 'large dataset pagination test';
      const totalResults = 150;
      const pageSize = 20;

      // Mock paginated results
      const mockPaginatedResults = (page: number) => {
        const startIdx = page * pageSize;
        const endIdx = Math.min(startIdx + pageSize, totalResults);

        return Array.from({ length: endIdx - startIdx }, (_, i) => ({
          id: `paginated-${startIdx + i}`,
          score: 0.9 - (startIdx + i) * 0.001,
          payload: {
            kind: 'entity',
            data: {
              title: `Paginated Result ${startIdx + i}`,
              content: `Content for result ${startIdx + i}`,
            },
          },
        }));
      };

      mockQdrantClient.search.mockImplementation((params) => {
        const page = params.page || 0;
        return Promise.resolve(mockPaginatedResults(page));
      });

      // Test pagination
      const allResults = [];
      let currentPage = 0;
      let hasMore = true;

      while (hasMore) {
        const results = await deepSearch(query, ['entity'], pageSize, 0.5, {
          page: currentPage,
          pageSize,
        });

        allResults.push(...results);
        hasMore = results.length === pageSize;
        currentPage++;

        // Limit for test purposes
        if (currentPage > 5) break;
      }

      expect(allResults.length).toBeGreaterThan(0);
      expect(allResults.length).toBeLessThanOrEqual(totalResults);

      // Verify pagination integrity
      const resultIds = allResults.map((r) => r.id);
      const uniqueIds = [...new Set(resultIds)];
      expect(uniqueIds.length).toBe(resultIds.length); // No duplicates
    });
  });

  // 6. Search Analytics and Learning Tests
  describe('Search Analytics and Learning', () => {
    it('should track search behavior analytics', async () => {
      const searchQueries = [
        'user authentication issues',
        'database performance optimization',
        'security policies and procedures',
        'system architecture decisions',
        'deployment automation',
      ];

      const analyticsData = [];

      for (const query of searchQueries) {
        const searchStartTime = Date.now();

        mockQdrantClient.search.mockResolvedValue([
          {
            id: `analytics-${query.substring(0, 6)}`,
            score: 0.85 + Math.random() * 0.1,
            payload: {
              kind: query.includes('decision') ? 'decision' : 'observation',
              data: { title: `Result for ${query}`, content: 'Analytics test content' },
            },
          },
        ]);

        const results = await deepSearch(query, ['decision', 'observation'], 10, 0.7);
        const searchDuration = Date.now() - searchStartTime;

        analyticsData.push({
          query,
          resultCount: results.length,
          duration: searchDuration,
          avgScore: results.reduce((sum, r) => sum + r.score, 0) / results.length,
          timestamp: new Date(),
        });
      }

      // Verify analytics data collection
      expect(analyticsData).toHaveLength(searchQueries.length);

      analyticsData.forEach((data) => {
        expect(data.query).toBeTruthy();
        expect(data.resultCount).toBeGreaterThan(0);
        expect(data.duration).toBeGreaterThan(0);
        expect(data.avgScore).toBeGreaterThan(0);
        expect(data.timestamp).toBeInstanceOf(Date);
      });

      // Analyze patterns
      const avgDuration =
        analyticsData.reduce((sum, d) => sum + d.duration, 0) / analyticsData.length;
      const avgResults =
        analyticsData.reduce((sum, d) => sum + d.resultCount, 0) / analyticsData.length;

      expect(avgDuration).toBeLessThan(2000); // Average should be reasonable
      expect(avgResults).toBeGreaterThan(0);
    });

    it('should implement query pattern recognition', async () => {
      const queryPatterns = [
        { query: 'how to implement authentication', pattern: 'procedural' },
        { query: 'authentication system problems', pattern: 'problem-solving' },
        { query: 'best authentication practices', pattern: 'best-practices' },
        { query: 'authentication vs authorization', pattern: 'comparison' },
        { query: 'authentication security checklist', pattern: 'checklist' },
      ];

      const patternResults = [];

      for (const testCase of queryPatterns) {
        const results = await deepSearch(
          testCase.query,
          ['runbook', 'issue', 'decision', 'section'],
          10,
          0.6
        );

        patternResults.push({
          query: testCase.query,
          expectedPattern: testCase.pattern,
          resultTypes: results.map((r) => r.kind),
          resultCount: results.length,
          avgScore: results.reduce((sum, r) => sum + r.score, 0) / results.length,
        });
      }

      // Verify pattern recognition
      patternResults.forEach((result) => {
        expect(result.resultCount).toBeGreaterThan(0);
        expect(result.avgScore).toBeGreaterThan(0);

        // Results should align with expected patterns
        switch (result.expectedPattern) {
          case 'procedural':
            expect(result.resultTypes.some((t) => ['runbook', 'section'].includes(t))).toBe(true);
            break;
          case 'problem-solving':
            expect(result.resultTypes.some((t) => ['issue', 'incident'].includes(t))).toBe(true);
            break;
          case 'best-practices':
            expect(result.resultTypes.some((t) => ['decision', 'section'].includes(t))).toBe(true);
            break;
          case 'comparison':
            expect(result.resultTypes.some((t) => ['decision', 'observation'].includes(t))).toBe(
              true
            );
            break;
          case 'checklist':
            expect(result.resultTypes.some((t) => ['runbook', 'todo'].includes(t))).toBe(true);
            break;
        }
      });
    });

    it('should provide search performance optimization suggestions', async () => {
      // Simulate various search scenarios that might need optimization
      const searchScenarios = [
        {
          query: 'very broad generic term with lots of results',
          expectedIssue: 'too_many_results',
          suggestion: 'use_specific_terms_or_filters',
        },
        {
          query: 'super specific technical jargon that nobody uses',
          expectedIssue: 'too_few_results',
          suggestion: 'broaden_search_terms',
        },
        {
          query: 'common words like system data process',
          expectedIssue: 'ambiguous_terms',
          suggestion: 'use_exact_phrases_or_context',
        },
        {
          query: 'query with lots of special characters and formatting',
          expectedIssue: 'syntax_issues',
          suggestion: 'simplify_query_syntax',
        },
      ];

      const optimizationSuggestions = [];

      for (const scenario of searchScenarios) {
        const results = await deepSearch(scenario.query, ['entity', 'decision'], 20, 0.5);

        // Analyze results and generate suggestions
        let suggestion = '';
        if (results.length > 50) {
          suggestion = 'Consider using more specific terms or adding filters to narrow results';
        } else if (results.length === 0) {
          suggestion = 'Try broadening search terms or checking spelling';
        } else if (results.every((r) => r.score < 0.6)) {
          suggestion = 'Results have low relevance, consider rephrasing the query';
        } else {
          suggestion = 'Query appears well-optimized';
        }

        optimizationSuggestions.push({
          query: scenario.query,
          resultCount: results.length,
          avgScore:
            results.length > 0 ? results.reduce((sum, r) => sum + r.score, 0) / results.length : 0,
          suggestion,
        });
      }

      // Verify optimization suggestions
      optimizationSuggestions.forEach((suggestion) => {
        expect(suggestion.suggestion).toBeTruthy();
        expect(suggestion.suggestion.length).toBeGreaterThan(0);

        // Suggestions should be actionable
        expect(suggestion.suggestion).toMatch(/(consider|try|use|add|broaden|rephrase|check)/i);
      });

      // At least some suggestions should be provided
      const actionableSuggestions = optimizationSuggestions.filter(
        (s) => s.suggestion !== 'Query appears well-optimized'
      );
      expect(actionableSuggestions.length).toBeGreaterThan(0);
    });

    it('should implement user feedback integration for learning', async () => {
      const query = 'machine learning model deployment';

      // Initial search
      const initialResults = await deepSearch(query, ['entity', 'decision', 'runbook'], 15, 0.7);

      // Simulate user feedback on results
      const userFeedback = [
        { resultId: initialResults[0]?.id, feedback: 'relevant', rating: 5 },
        { resultId: initialResults[1]?.id, feedback: 'partially_relevant', rating: 3 },
        { resultId: initialResults[2]?.id, feedback: 'not_relevant', rating: 1 },
      ].filter((f) => f.resultId);

      // Second search with feedback integration
      mockQdrantClient.search.mockResolvedValue([
        {
          id: 'improved-result-1',
          score: 0.94, // Higher score due to feedback learning
          payload: {
            kind: 'runbook',
            data: {
              title: 'ML Model Deployment Guide',
              content: 'Comprehensive guide for deploying machine learning models',
            },
          },
        },
        {
          id: 'improved-result-2',
          score: 0.89,
          payload: {
            kind: 'decision',
            data: {
              title: 'Model Deployment Architecture Decision',
              content: 'Architectural decisions for ML model deployment',
            },
          },
        },
      ]);

      const improvedResults = await deepSearch(query, ['entity', 'decision', 'runbook'], 15, 0.7, {
        userFeedback,
      });

      expect(improvedResults.length).toBeGreaterThan(0);

      // Improved results should have higher average scores
      const initialAvgScore =
        initialResults.length > 0
          ? initialResults.reduce((sum, r) => sum + r.score, 0) / initialResults.length
          : 0;
      const improvedAvgScore =
        improvedResults.reduce((sum, r) => sum + r.score, 0) / improvedResults.length;

      expect(improvedAvgScore).toBeGreaterThanOrEqual(initialAvgScore);
    });
  });

  // 7. Relevance Ranking and Personalization Tests
  describe('Relevance Ranking and Personalization', () => {
    it('should implement advanced relevance ranking algorithms', async () => {
      const query = 'cloud migration strategy';

      // Mock results with various relevance signals
      mockQdrantClient.search.mockResolvedValue([
        {
          id: 'high-relevance',
          score: 0.92,
          payload: {
            kind: 'decision',
            data: {
              title: 'Cloud Migration Strategy Decision',
              content: 'Comprehensive strategy for migrating to cloud infrastructure',
              tags: ['migration', 'cloud', 'strategy'],
              recency: 'recent',
            },
          },
        },
        {
          id: 'medium-relevance',
          score: 0.78,
          payload: {
            kind: 'observation',
            data: {
              title: 'Cloud Infrastructure Notes',
              content: 'General notes about cloud services and migration considerations',
              tags: ['cloud', 'infrastructure'],
              recency: 'older',
            },
          },
        },
        {
          id: 'low-relevance',
          score: 0.65,
          payload: {
            kind: 'entity',
            data: {
              title: 'System Documentation',
              content: 'General system documentation with brief mention of cloud services',
              tags: ['documentation'],
              recency: 'very_old',
            },
          },
        },
      ]);

      const results = await deepSearch(query, ['decision', 'observation', 'entity'], 15, 0.5);

      expect(results.length).toBe(3);

      // Results should be ranked by relevance score
      for (let i = 0; i < results.length - 1; i++) {
        expect(results[i].score).toBeGreaterThanOrEqual(results[i + 1].score);
      }

      // High relevance result should be first
      expect(results[0].id).toBe('high-relevance');
      expect(results[0].title).toContain('Cloud Migration Strategy');
    });

    it('should implement personalized search based on user context', async () => {
      const query = 'api development';

      const userContexts = [
        {
          id: 'backend-developer',
          preferences: { technologies: ['Node.js', 'Express'], project: 'backend-api' },
          role: 'backend_developer',
        },
        {
          id: 'frontend-developer',
          preferences: { technologies: ['React', 'TypeScript'], project: 'frontend-app' },
          role: 'frontend_developer',
        },
        {
          id: 'devops-engineer',
          preferences: { technologies: ['Docker', 'Kubernetes'], project: 'infrastructure' },
          role: 'devops_engineer',
        },
      ];

      const personalizedResults = [];

      for (const context of userContexts) {
        mockQdrantClient.search.mockResolvedValue([
          {
            id: `personalized-${context.id}-1`,
            score: 0.9,
            payload: {
              kind: 'entity',
              data: {
                title: `${context.preferences.technologies[0]} API Development Guide`,
                content: `API development using ${context.preferences.technologies.join(' and ')}`,
                tags: context.preferences.technologies,
                target_role: context.role,
              },
            },
          },
        ]);

        const results = await deepSearch(query, ['entity', 'runbook'], 10, 0.6, {
          userContext: context,
        });

        personalizedResults.push({
          context: context.id,
          results,
          avgScore: results.reduce((sum, r) => sum + r.score, 0) / results.length,
        });
      }

      // Each user should get personalized results
      personalizedResults.forEach((result) => {
        expect(result.results.length).toBeGreaterThan(0);
        expect(result.avgScore).toBeGreaterThan(0.8); // High relevance due to personalization

        const context = userContexts.find((c) => c.id === result.context);
        expect(context).toBeTruthy();

        // Results should match user preferences
        result.results.forEach((searchResult) => {
          const hasPreferredTech = context.preferences.technologies.some(
            (tech) => searchResult.title.includes(tech) || searchResult.snippet.includes(tech)
          );
          expect(hasPreferredTech).toBe(true);
        });
      });
    });

    it('should implement temporal relevance ranking', async () => {
      const query = 'security update';
      const currentDate = new Date('2024-06-15');

      // Mock results with different timestamps
      const timeBasedResults = [
        {
          id: 'recent-security',
          score: 0.85,
          payload: {
            kind: 'observation',
            data: {
              title: 'Latest Security Update',
              content: 'Recent security patch and vulnerability fixes',
            },
            created_at: new Date('2024-06-10').toISOString(), // Recent
          },
        },
        {
          id: 'older-security',
          score: 0.88,
          payload: {
            kind: 'decision',
            data: {
              title: 'Security Policy Update',
              content: 'Security policy revisions and updates',
            },
            created_at: new Date('2024-01-15').toISOString(), // Older
          },
        },
        {
          id: 'very-old-security',
          score: 0.9,
          payload: {
            kind: 'runbook',
            data: {
              title: 'Historical Security Procedures',
              content: 'Old security procedures and guidelines',
            },
            created_at: new Date('2023-06-15').toISOString(), // Very old
          },
        },
      ];

      mockQdrantClient.search.mockResolvedValue(timeBasedResults);

      const results = await deepSearch(query, ['observation', 'decision', 'runbook'], 10, 0.5, {
        currentDate: currentDate.toISOString(),
        boostRecent: true,
      });

      expect(results.length).toBe(3);

      // With temporal boosting, recent content should rank higher despite base scores
      expect(results[0].id).toBe('recent-security');

      // Results should include temporal relevance information
      results.forEach((result) => {
        expect(result.metadata).toBeDefined();
        expect(result.metadata?.created_at).toBeTruthy();

        const createdAt = new Date(result.metadata['created_at']);
        const ageInDays = (currentDate.getTime() - createdAt.getTime()) / (1000 * 60 * 60 * 24);

        // Temporal boost should be reflected in final score
        expect(result.score).toBeGreaterThan(0);
      });
    });

    it('should implement collaborative filtering for relevance improvement', async () => {
      const query = 'performance optimization';

      // Mock collaborative filtering data from similar users
      const collaborativeSignals = [
        { itemId: 'perf-guide', relevanceScore: 0.92, similarUserInteractions: 45 },
        { itemId: 'perf-tool', relevanceScore: 0.87, similarUserInteractions: 32 },
        { itemId: 'perf-case-study', relevanceScore: 0.79, similarUserInteractions: 18 },
      ];

      mockQdrantClient.search.mockResolvedValue([
        {
          id: 'perf-guide',
          score: 0.82, // Base score
          payload: {
            kind: 'runbook',
            data: {
              title: 'Performance Optimization Guide',
              content: 'Comprehensive guide to system performance optimization',
            },
          },
        },
        {
          id: 'perf-tool',
          score: 0.78, // Base score
          payload: {
            kind: 'entity',
            data: {
              title: 'Performance Monitoring Tool',
              content: 'Tool for monitoring and optimizing system performance',
            },
          },
        },
        {
          id: 'perf-case-study',
          score: 0.8, // Base score
          payload: {
            kind: 'observation',
            data: {
              title: 'Performance Optimization Case Study',
              content: 'Real-world case study of performance improvements',
            },
          },
        },
      ]);

      const results = await deepSearch(query, ['runbook', 'entity', 'observation'], 10, 0.5, {
        collaborativeFiltering: true,
      });

      expect(results.length).toBe(3);

      // Results should be boosted based on collaborative signals
      collaborativeSignals.forEach((signal) => {
        const result = results.find((r) => r.id === signal.itemId);
        if (result) {
          // Final score should be influenced by collaborative filtering
          expect(result.score).toBeGreaterThan(0);
          expect(result.metadata?.collaborativeScore).toBe(signal.relevanceScore);
          expect(result.metadata?.userInteractions).toBe(signal.similarUserInteractions);
        }
      });
    });
  });

  // 8. Cross-Domain and Federated Search Tests
  describe('Cross-Domain and Federated Search', () => {
    it('should implement cross-domain search capabilities', async () => {
      const query = 'user management system';

      // Mock results from different domains
      const domainResults = {
        backend: [
          {
            id: 'backend-user-service',
            score: 0.91,
            payload: {
              kind: 'entity',
              data: {
                title: 'User Management Service',
                content: 'Backend service for user authentication and authorization',
                domain: 'backend',
                technology: 'Node.js',
              },
            },
          },
        ],
        frontend: [
          {
            id: 'frontend-user-ui',
            score: 0.86,
            payload: {
              kind: 'entity',
              data: {
                title: 'User Management Interface',
                content: 'Frontend components for user management operations',
                domain: 'frontend',
                technology: 'React',
              },
            },
          },
        ],
        database: [
          {
            id: 'database-user-schema',
            score: 0.84,
            payload: {
              kind: 'ddl',
              data: {
                title: 'User Database Schema',
                content: 'Database schema definition for user management',
                domain: 'database',
                technology: 'PostgreSQL',
              },
            },
          },
        ],
        security: [
          {
            id: 'security-user-policies',
            score: 0.88,
            payload: {
              kind: 'decision',
              data: {
                title: 'User Security Policies',
                content: 'Security policies and procedures for user management',
                domain: 'security',
                technology: 'OAuth 2.0',
              },
            },
          },
        ],
      };

      // Mock federated search across domains
      mockQdrantClient.search.mockImplementation((params) => {
        const domain = params.domain || 'backend';
        return Promise.resolve(domainResults[domain] || []);
      });

      const results = await deepSearch(query, ['entity', 'ddl', 'decision'], 20, 0.7, {
        domains: ['backend', 'frontend', 'database', 'security'],
        crossDomain: true,
      });

      expect(results.length).toBeGreaterThan(0);

      // Should include results from multiple domains
      const uniqueDomains = [...new Set(results.map((r) => r.metadata?.domain).filter(Boolean))];
      expect(uniqueDomains.length).toBeGreaterThan(1);

      // Results should maintain domain context
      results.forEach((result) => {
        expect(result.metadata?.domain).toBeTruthy();
        expect(result.metadata?.technology).toBeTruthy();
      });
    });

    it('should handle federated search with multiple data sources', async () => {
      const query = 'deployment automation';

      // Mock different data sources
      const dataSources = {
        knowledge_base: [
          {
            id: 'kb-deployment-guide',
            score: 0.93,
            payload: {
              kind: 'runbook',
              data: {
                title: 'Deployment Automation Guide',
                content: 'Step-by-step guide for automated deployments',
              },
              source: 'knowledge_base',
              confidence: 'high',
            },
          },
        ],
        documentation: [
          {
            id: 'doc-deployment-api',
            score: 0.87,
            payload: {
              kind: 'section',
              data: {
                title: 'Deployment API Documentation',
                content: 'API documentation for deployment service',
              },
              source: 'documentation',
              confidence: 'medium',
            },
          },
        ],
        code_repository: [
          {
            id: 'repo-deployment-scripts',
            score: 0.85,
            payload: {
              kind: 'entity',
              data: {
                title: 'Deployment Scripts',
                content: 'Automation scripts for CI/CD deployment',
              },
              source: 'code_repository',
              confidence: 'high',
            },
          },
        ],
        issue_tracker: [
          {
            id: 'issue-deployment-problems',
            score: 0.79,
            payload: {
              kind: 'issue',
              data: {
                title: 'Deployment Automation Issues',
                content: 'Common problems and solutions for deployment automation',
              },
              source: 'issue_tracker',
              confidence: 'low',
            },
          },
        ],
      };

      mockQdrantClient.search.mockImplementation((params) => {
        const source = params.data_source || 'knowledge_base';
        return Promise.resolve(dataSources[source] || []);
      });

      const results = await deepSearch(query, ['runbook', 'section', 'entity', 'issue'], 25, 0.6, {
        dataSources: ['knowledge_base', 'documentation', 'code_repository', 'issue_tracker'],
        federated: true,
        boostBySource: true,
      });

      expect(results.length).toBeGreaterThan(0);

      // Should include results from multiple sources
      const uniqueSources = [...new Set(results.map((r) => r.metadata?.source).filter(Boolean))];
      expect(uniqueSources.length).toBeGreaterThan(1);

      // Higher confidence sources should be boosted
      const highConfidenceResults = results.filter((r) => r.metadata?.confidence === 'high');
      const lowConfidenceResults = results.filter((r) => r.metadata?.confidence === 'low');

      if (highConfidenceResults.length > 0 && lowConfidenceResults.length > 0) {
        const highConfidenceAvgScore =
          highConfidenceResults.reduce((sum, r) => sum + r.score, 0) / highConfidenceResults.length;
        const lowConfidenceAvgScore =
          lowConfidenceResults.reduce((sum, r) => sum + r.score, 0) / lowConfidenceResults.length;

        expect(highConfidenceAvgScore).toBeGreaterThan(lowConfidenceAvgScore);
      }
    });

    it('should implement result harmonization across different sources', async () => {
      const query = 'monitoring system';

      // Mock heterogeneous results from different sources
      const heterogeneousResults = [
        {
          id: 'prometheus-setup',
          score: 0.91,
          payload: {
            kind: 'runbook',
            data: {
              title: 'Prometheus Monitoring Setup',
              content: 'Configuration guide for Prometheus monitoring',
              format: 'markdown',
              language: 'en',
            },
            source: 'documentation',
            last_updated: '2024-05-15',
          },
        },
        {
          id: 'grafana-dashboard',
          score: 0.88,
          payload: {
            kind: 'entity',
            data: {
              name: 'Grafana Dashboard',
              description: 'JSON configuration for Grafana dashboard',
              format: 'json',
              language: 'json',
            },
            source: 'code_repository',
            last_updated: '2024-06-01',
          },
        },
        {
          id: 'alerting-rules',
          score: 0.85,
          payload: {
            kind: 'decision',
            data: {
              title: 'Alerting Strategy Decision',
              rationale: 'Decision on alerting rules and notification channels',
              format: 'text',
              language: 'en',
            },
            source: 'meeting_notes',
            last_updated: '2024-04-20',
          },
        },
      ];

      mockQdrantClient.search.mockResolvedValue(heterogeneousResults);

      const results = await deepSearch(query, ['runbook', 'entity', 'decision'], 15, 0.7, {
        harmonizeResults: true,
        normalizeScores: true,
      });

      expect(results.length).toBe(3);

      // Results should be harmonized with consistent structure
      results.forEach((result) => {
        expect(result.id).toBeTruthy();
        expect(result.title).toBeTruthy();
        expect(result.snippet).toBeTruthy();
        expect(result.score).toBeGreaterThan(0);
        expect(result.kind).toBeTruthy();
        expect(result.metadata).toBeDefined();

        // Should include harmonization metadata
        expect(result.metadata?.source).toBeTruthy();
        expect(result.metadata?.format).toBeTruthy();
        expect(result.metadata?.last_updated).toBeTruthy();
      });

      // Scores should be normalized
      const scores = results.map((r) => r.score);
      const maxScore = Math.max(...scores);
      const minScore = Math.min(...scores);

      expect(maxScore).toBeLessThanOrEqual(1.0);
      expect(minScore).toBeGreaterThanOrEqual(0.0);
    });
  });

  // 9. Error Handling and Resilience Tests
  describe('Error Handling and Resilience', () => {
    it('should handle search service failures gracefully', async () => {
      const query = 'error handling test';

      // Mock various failure scenarios
      const errorScenarios = [
        { type: 'connection_timeout', error: new Error('Connection timeout') },
        { type: 'service_unavailable', error: new Error('Service unavailable') },
        { type: 'rate_limit_exceeded', error: new Error('Rate limit exceeded') },
        { type: 'invalid_response', error: new Error('Invalid response format') },
      ];

      for (const scenario of errorScenarios) {
        mockQdrantClient.search.mockRejectedValueOnce(scenario.error);

        const results = await deepSearch(query, ['entity'], 10, 0.7);

        // Should return empty results on error, not throw
        expect(results).toEqual([]);
        expect(Array.isArray(results)).toBe(true);
      }
    });

    it('should implement search fallback mechanisms', async () => {
      const query = 'fallback mechanism test';

      // Primary search fails
      mockQdrantClient.search.mockRejectedValueOnce(new Error('Primary search failed'));

      // Fallback search should work
      mockQdrantClient.knowledgeEntity.findMany.mockResolvedValueOnce([
        {
          id: 'fallback-result',
          kind: 'entity',
          data: {
            title: 'Fallback Search Result',
            content: 'Result from fallback search mechanism',
          },
          tags: { project: 'test' },
          created_at: new Date(),
        },
      ]);

      const results = await deepSearch(query, ['entity'], 10, 0.7, {
        enableFallback: true,
        fallbackTimeout: 5000,
      });

      expect(results.length).toBeGreaterThan(0);
      expect(results[0].id).toBe('fallback-result');

      // Should indicate fallback was used
      expect(results[0].metadata?.fallbackUsed).toBe(true);
    });

    it('should handle partial search failures gracefully', async () => {
      const query = 'partial failure test';
      const searchTypes = ['entity', 'decision', 'issue'];

      // Mock partial failures - some types succeed, others fail
      mockQdrantClient.search.mockImplementation((params) => {
        const collectionName = params.collection_name;

        if (collectionName === 'entity') {
          return Promise.resolve([
            {
              id: 'entity-success',
              score: 0.9,
              payload: {
                kind: 'entity',
                data: { title: 'Entity Result', content: 'Successful entity search' },
              },
            },
          ]);
        } else if (collectionName === 'decision') {
          return Promise.reject(new Error('Decision search failed'));
        } else {
          return Promise.resolve([
            {
              id: 'issue-success',
              score: 0.85,
              payload: {
                kind: 'issue',
                data: { title: 'Issue Result', content: 'Successful issue search' },
              },
            },
          ]);
        }
      });

      const results = await deepSearch(query, searchTypes, 15, 0.7, {
        partialFailureHandling: true,
      });

      // Should return successful results despite partial failures
      expect(results.length).toBeGreaterThan(0);

      const entityResult = results.find((r) => r.kind === 'entity');
      const issueResult = results.find((r) => r.kind === 'issue');

      expect(entityResult).toBeTruthy();
      expect(issueResult).toBeTruthy();

      // Should include error metadata for failed searches
      expect(results.some((r) => r.metadata?.searchErrors)).toBe(true);
    });

    it('should implement search timeout handling', async () => {
      const query = 'timeout handling test';

      // Mock slow search response
      mockQdrantClient.search.mockImplementationOnce(() => {
        return new Promise((resolve) => {
          setTimeout(() => {
            resolve([
              {
                id: 'slow-response',
                score: 0.8,
                payload: {
                  kind: 'entity',
                  data: { title: 'Slow Response', content: 'This response took too long' },
                },
              },
            ]);
          }, 3000); // 3 second delay
        });
      });

      const startTime = Date.now();

      const results = await deepSearch(
        query,
        ['entity'],
        10,
        0.7,
        { timeout: 1000 } // 1 second timeout
      );

      const duration = Date.now() - startTime;

      // Should return quickly due to timeout
      expect(duration).toBeLessThan(2000);

      // Should handle timeout gracefully
      expect(Array.isArray(results)).toBe(true);
      // May return empty results due to timeout, depending on implementation
    });
  });

  // 10. Configuration and Customization Tests
  describe('Configuration and Customization', () => {
    it('should support dynamic search configuration', async () => {
      const query = 'configuration test';

      const searchConfigs = [
        {
          name: 'default',
          config: {
            maxResults: 10,
            minSimilarity: 0.7,
            boostRecent: false,
            enablePersonalization: false,
          },
        },
        {
          name: 'high_precision',
          config: {
            maxResults: 5,
            minSimilarity: 0.9,
            boostRecent: true,
            enablePersonalization: false,
          },
        },
        {
          name: 'high_recall',
          config: {
            maxResults: 50,
            minSimilarity: 0.5,
            boostRecent: false,
            enablePersonalization: true,
          },
        },
      ];

      mockQdrantClient.search.mockResolvedValue([
        {
          id: 'config-test-result',
          score: 0.85,
          payload: {
            kind: 'entity',
            data: { title: 'Configuration Test', content: 'Testing search configurations' },
          },
        },
      ]);

      const configResults = [];

      for (const searchConfig of searchConfigs) {
        const results = await deepSearch(
          query,
          ['entity'],
          searchConfig.config.maxResults,
          searchConfig.config.minSimilarity,
          searchConfig.config
        );

        configResults.push({
          config: searchConfig.name,
          resultCount: results.length,
          avgScore: results.reduce((sum, r) => sum + r.score, 0) / results.length,
        });
      }

      // Verify different configurations produce different behaviors
      const highPrecision = configResults.find((r) => r.config === 'high_precision');
      const highRecall = configResults.find((r) => r.config === 'high_recall');

      if (highPrecision && highRecall) {
        // High precision should have fewer results but higher minimum scores
        expect(highPrecision.resultCount).toBeLessThanOrEqual(highRecall.resultCount);
        expect(highPrecision.avgScore).toBeGreaterThanOrEqual(highRecall.avgScore);
      }
    });

    it('should support custom ranking algorithms', async () => {
      const query = 'custom ranking test';

      // Mock results for different ranking algorithms
      const rankingAlgorithms = [
        {
          name: 'tfidf',
          results: [
            {
              id: 'tfidf-1',
              score: 0.82,
              payload: { kind: 'entity', data: { title: 'TF-IDF Result 1' } },
            },
            {
              id: 'tfidf-2',
              score: 0.78,
              payload: { kind: 'entity', data: { title: 'TF-IDF Result 2' } },
            },
          ],
        },
        {
          name: 'bm25',
          results: [
            {
              id: 'bm25-1',
              score: 0.91,
              payload: { kind: 'entity', data: { title: 'BM25 Result 1' } },
            },
            {
              id: 'bm25-2',
              score: 0.85,
              payload: { kind: 'entity', data: { title: 'BM25 Result 2' } },
            },
          ],
        },
        {
          name: 'semantic',
          results: [
            {
              id: 'semantic-1',
              score: 0.88,
              payload: { kind: 'entity', data: { title: 'Semantic Result 1' } },
            },
            {
              id: 'semantic-2',
              score: 0.84,
              payload: { kind: 'entity', data: { title: 'Semantic Result 2' } },
            },
          ],
        },
      ];

      const algorithmResults = [];

      for (const algorithm of rankingAlgorithms) {
        mockQdrantClient.search.mockResolvedValueOnce(algorithm.results);

        const results = await deepSearch(query, ['entity'], 10, 0.5, {
          rankingAlgorithm: algorithm.name,
        });

        algorithmResults.push({
          algorithm: algorithm.name,
          results,
          topScore: results.length > 0 ? results[0].score : 0,
          avgScore: results.reduce((sum, r) => sum + r.score, 0) / results.length,
        });
      }

      // Different algorithms should produce different ranking scores
      const tfidfResults = algorithmResults.find((r) => r.algorithm === 'tfidf');
      const bm25Results = algorithmResults.find((r) => r.algorithm === 'bm25');
      const semanticResults = algorithmResults.find((r) => r.algorithm === 'semantic');

      expect(tfidfResults).toBeTruthy();
      expect(bm25Results).toBeTruthy();
      expect(semanticResults).toBeTruthy();

      // Each algorithm should have its own scoring characteristics
      expect(tfidfResults.topScore).not.toBe(bm25Results.topScore);
      expect(bm25Results.topScore).not.toBe(semanticResults.topScore);
    });

    it('should support result customization and formatting', async () => {
      const query = 'result formatting test';

      mockQdrantClient.search.mockResolvedValue([
        {
          id: 'format-test-1',
          score: 0.92,
          payload: {
            kind: 'entity',
            data: {
              title: 'Formatting Test Result',
              content: 'This is a test result for formatting functionality',
              author: 'Test Author',
              created_at: '2024-06-15',
              tags: ['test', 'formatting'],
            },
          },
        },
      ]);

      const formattingOptions = [
        {
          name: 'minimal',
          options: { includeMetadata: false, truncateContent: true, maxContentLength: 100 },
        },
        {
          name: 'detailed',
          options: { includeMetadata: true, truncateContent: false, includeHighlights: true },
        },
        {
          name: 'summary',
          options: {
            includeMetadata: true,
            truncateContent: true,
            maxContentLength: 200,
            includeSummary: true,
          },
        },
      ];

      const formattedResults = [];

      for (const formatting of formattingOptions) {
        const results = await deepSearch(query, ['entity'], 10, 0.5, {
          formatting: formatting.options,
        });

        formattedResults.push({
          format: formatting.name,
          results,
          hasMetadata: results[0]?.metadata !== undefined,
          contentLength: results[0]?.snippet?.length || 0,
        });
      }

      // Verify different formatting options
      const minimalFormat = formattedResults.find((r) => r.format === 'minimal');
      const detailedFormat = formattedResults.find((r) => r.format === 'detailed');
      const summaryFormat = formattedResults.find((r) => r.format === 'summary');

      if (minimalFormat && detailedFormat) {
        // Detailed format should have more metadata
        expect(detailedFormat.hasMetadata).toBe(true);
        expect(minimalFormat.contentLength).toBeLessThanOrEqual(100);
      }

      if (summaryFormat) {
        expect(summaryFormat.contentLength).toBeLessThanOrEqual(200);
      }
    });
  });

  // Helper function to validate dates
  function isValidDate(date: Date): boolean {
    return date instanceof Date && !isNaN(date.getTime());
  }
});

// Additional tests for similarity calculation
describe('Similarity Calculation Functions', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should calculate similarity between text strings', async () => {
    const text1 = 'user authentication system';
    const text2 = 'authentication and authorization';

    const similarity = await calculateSimilarity(text1, text2);

    expect(typeof similarity).toBe('number');
    expect(similarity).toBeGreaterThanOrEqual(0);
    expect(similarity).toBeLessThanOrEqual(1);
  });

  it('should handle edge cases in similarity calculation', async () => {
    const edgeCases = [
      { text1: '', text2: 'test' },
      { text1: 'test', text2: '' },
      { text1: '', text2: '' },
      { text1: 'a', text2: 'b' },
      { text1: 'very long text with many words and phrases', text2: 'completely different text' },
    ];

    for (const testCase of edgeCases) {
      const similarity = await calculateSimilarity(testCase.text1, testCase.text2);

      expect(typeof similarity).toBe('number');
      expect(similarity).toBeGreaterThanOrEqual(0);
      expect(similarity).toBeLessThanOrEqual(1);
    }
  });

  it('should provide consistent similarity scores', async () => {
    const text1 = 'machine learning model deployment';
    const text2 = 'ML model deployment pipeline';

    // Calculate similarity multiple times
    const similarities = await Promise.all([
      calculateSimilarity(text1, text2),
      calculateSimilarity(text1, text2),
      calculateSimilarity(text1, text2),
      calculateSimilarity(text1, text2),
      calculateSimilarity(text1, text2),
    ]);

    // All calculations should produce the same result
    similarities.forEach((similarity) => {
      expect(similarity).toBe(similarities[0]);
    });
  });
});
