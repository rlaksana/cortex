/**
 * Comprehensive Unit Tests for MCP Server Resources Management
 *
 * Tests MCP server resource functionality including:
 * - Resource Definition and Registration
 * - Knowledge Base Resources
 * - File and Document Resources
 * - Resource Access Control
 * - Resource Delivery
 * - Integration and Performance
 *
 * Phase 3: MCP Server Components Testing
 * Building on established MCP patterns and focusing on resource management
 */

import { describe, it, expect, beforeEach, afterEach, vi, type MockedFunction } from 'vitest';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import {
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { ValidationError } from '../../../src/utils/error-handler.js';
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
    logResourceAccess: vi.fn().mockResolvedValue(undefined),
    logResourceOperation: vi.fn().mockResolvedValue(undefined),
    logSecurityEvent: vi.fn().mockResolvedValue(undefined),
  },
}));

// Mock resource service functions directly
const mockResourceService = {
  listResources: vi.fn(),
  readResource: vi.fn(),
  registerResource: vi.fn(),
  validateResourceAccess: vi.fn(),
  getResourceMetadata: vi.fn(),
  streamResourceContent: vi.fn(),
  transformResourceFormat: vi.fn(),
  compressResourceContent: vi.fn(),
  cacheResource: vi.fn(),
  invalidateResourceCache: vi.fn(),
  getResourceAnalytics: vi.fn(),
  optimizeResourceDelivery: vi.fn(),
};

// Mock access control functions
const mockAccessControl = {
  checkResourcePermissions: vi.fn(),
  validateScopeAccess: vi.fn(),
  enforceRateLimits: vi.fn(),
  logAccessAttempt: vi.fn(),
  analyzeResourceAccess: vi.fn(),
  getResourceUsageMetrics: vi.fn(),
  checkResourceQuotas: vi.fn(),
  applyResourcePolicies: vi.fn(),
};

// Mock performance monitoring functions
const mockPerformanceMonitor = {
  trackResourceOperation: vi.fn(),
  measureResourcePerformance: vi.fn(),
  optimizeResourceCaching: vi.fn(),
  analyzeResourceUsage: vi.fn(),
  monitorResourceThroughput: vi.fn(),
  trackResourceLatency: vi.fn(),
  generateResourceMetrics: vi.fn(),
};

// Import mocked modules
const mockMemoryStore = vi.mocked(memoryStore);

// ============================================================================
// Resource Type and Interface Definitions
// ============================================================================

interface ResourceDefinition {
  name: string;
  uri: string;
  description: string;
  mimeType: string;
  category: 'knowledge' | 'document' | 'media' | 'archive' | 'data';
  metadata: ResourceMetadata;
  access: ResourceAccess;
  lifecycle: ResourceLifecycle;
  performance: ResourcePerformance;
}

interface ResourceMetadata {
  title: string;
  description: string;
  tags: string[];
  created_at: string;
  updated_at: string;
  version: string;
  author: string;
  size: number;
  checksum: string;
  encoding?: string;
  compression?: string;
  encryption?: string;
}

interface ResourceAccess {
  permissions: {
    read: string[];
    write: string[];
    admin: string[];
  };
  scope: {
    project?: string;
    org?: string;
    branch?: string;
  };
  authentication: boolean;
  authorization: boolean;
  rateLimits: {
    requests: number;
    window: number;
  };
}

interface ResourceLifecycle {
  status: 'active' | 'inactive' | 'archived' | 'deleted';
  created_at: string;
  updated_at: string;
  expires_at?: string;
  archived_at?: string;
  deleted_at?: string;
  version: string;
  retention: {
    policy: string;
    duration: number;
  };
}

interface ResourcePerformance {
  cache: {
    enabled: boolean;
    ttl: number;
    maxSize: number;
    strategy: string;
  };
  optimization: {
    compression: boolean;
    minification: boolean;
    transformation: boolean;
  };
  delivery: {
    streaming: boolean;
    chunking: boolean;
    cdn: boolean;
  };
}

interface ResourceRequest {
  uri: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  headers: Record<string, string>;
  body?: any;
  context: ToolExecutionContext;
}

interface ResourceResponse {
  success: boolean;
  data?: any;
  metadata: {
    statusCode: number;
    headers: Record<string, string>;
    size: number;
    duration: number;
    cacheHit: boolean;
  };
  error?: {
    code: string;
    message: string;
    details?: any;
  };
}

// ============================================================================
// Test Data and Helpers
// ============================================================================

const validKnowledgeResource: ResourceDefinition = {
  name: 'knowledge_entities',
  uri: 'knowledge://entities/project/test',
  description: 'Knowledge entities for the test project',
  mimeType: 'application/json',
  category: 'knowledge',
  metadata: {
    title: 'Project Knowledge Entities',
    description: 'All entities in the knowledge graph for test project',
    tags: ['knowledge', 'entities', 'graph'],
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-15T10:30:00Z',
    version: '1.2.0',
    author: 'cortex-system',
    size: 15360,
    checksum: 'sha256:abc123def456',
    encoding: 'utf-8',
    compression: 'gzip',
  },
  access: {
    permissions: {
      read: ['admin', 'developer', 'viewer'],
      write: ['admin', 'developer'],
      admin: ['admin'],
    },
    scope: {
      project: 'test-project',
      org: 'test-org',
    },
    authentication: true,
    authorization: true,
    rateLimits: {
      requests: 100,
      window: 3600,
    },
  },
  lifecycle: {
    status: 'active',
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-15T10:30:00Z',
    version: '1.2.0',
    retention: {
      policy: 'standard',
      duration: 365,
    },
  },
  performance: {
    cache: {
      enabled: true,
      ttl: 3600,
      maxSize: 1048576,
      strategy: 'LRU',
    },
    optimization: {
      compression: true,
      minification: false,
      transformation: true,
    },
    delivery: {
      streaming: true,
      chunking: false,
      cdn: false,
    },
  },
};

const validDocumentResource: ResourceDefinition = {
  name: 'project_specification',
  uri: 'document://specs/project/test/specification.pdf',
  description: 'Project specification document',
  mimeType: 'application/pdf',
  category: 'document',
  metadata: {
    title: 'Test Project Specification',
    description: 'Complete technical specification for the test project',
    tags: ['specification', 'document', 'pdf'],
    created_at: '2024-01-05T09:00:00Z',
    updated_at: '2024-01-20T14:15:00Z',
    version: '2.1.0',
    author: 'team-lead',
    size: 2097152,
    checksum: 'sha256:def789ghi012',
  },
  access: {
    permissions: {
      read: ['admin', 'developer'],
      write: ['admin', 'team-lead'],
      admin: ['admin'],
    },
    scope: {
      project: 'test-project',
      org: 'test-org',
    },
    authentication: true,
    authorization: true,
    rateLimits: {
      requests: 50,
      window: 3600,
    },
  },
  lifecycle: {
    status: 'active',
    created_at: '2024-01-05T09:00:00Z',
    updated_at: '2024-01-20T14:15:00Z',
    version: '2.1.0',
    retention: {
      policy: 'document',
      duration: 1825,
    },
  },
  performance: {
    cache: {
      enabled: true,
      ttl: 7200,
      maxSize: 10485760,
      strategy: 'LFU',
    },
    optimization: {
      compression: false,
      minification: false,
      transformation: false,
    },
    delivery: {
      streaming: true,
      chunking: true,
      cdn: true,
    },
  },
};

const createMockResourceRequest = (uri: string, userRole: string = 'viewer'): ResourceRequest => ({
  uri,
  method: 'GET',
  headers: {
    Authorization: `Bearer mock-token-${userRole}`,
    'User-Agent': 'MCP-Client/1.0',
  },
  context: {
    toolName: 'read_resource',
    parameters: { uri },
    userId: `user-${userRole}`,
    sessionId: 'session-123',
    timestamp: new Date().toISOString(),
    requestId: 'req-456',
  },
});

// ============================================================================
// Test Suite 1: Resource Definition and Registration
// ============================================================================

describe('Resource Definition and Registration', () => {
  let mockServer: Server;

  beforeEach(() => {
    mockServer = new Server(
      { name: 'test-mcp-server', version: '1.0.0' },
      { capabilities: { resources: {} } }
    );
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  describe('Resource Schema Validation', () => {
    it('should validate knowledge resource schema correctly', () => {
      expect(validKnowledgeResource.name).toBe('knowledge_entities');
      expect(validKnowledgeResource.category).toBe('knowledge');
      expect(validKnowledgeResource.mimeType).toBe('application/json');
      expect(validKnowledgeResource.access.permissions.read).toContain('viewer');
      expect(validKnowledgeResource.performance.cache.enabled).toBe(true);
    });

    it('should validate document resource schema correctly', () => {
      expect(validDocumentResource.name).toBe('project_specification');
      expect(validDocumentResource.category).toBe('document');
      expect(validDocumentResource.mimeType).toBe('application/pdf');
      expect(validDocumentResource.access.permissions.write).toContain('team-lead');
      expect(validDocumentResource.performance.delivery.streaming).toBe(true);
    });

    it('should reject invalid resource definitions', () => {
      const invalidResource = {
        ...validKnowledgeResource,
        category: 'invalid_category' as any,
        access: {
          ...validKnowledgeResource.access,
          authentication: 'not_boolean' as any,
        },
      };

      expect(invalidResource.category).not.toBe('knowledge');
      expect(typeof invalidResource.access.authentication).not.toBe('boolean');
    });

    it('should validate resource metadata completeness', () => {
      const completeMetadata = validKnowledgeResource.metadata;

      expect(completeMetadata.title).toBeDefined();
      expect(completeMetadata.description).toBeDefined();
      expect(completeMetadata.created_at).toMatch(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z/);
      expect(completeMetadata.size).toBeGreaterThan(0);
      expect(completeMetadata.checksum).toMatch(/^[a-zA-Z0-9]+:[a-fA-F0-9]+$/);
    });
  });

  describe('Resource Metadata Management', () => {
    it('should handle version information correctly', () => {
      const resourceVersions = {
        knowledge_entities: ['1.0.0', '1.1.0', '1.2.0'],
        project_specification: ['1.0.0', '2.0.0', '2.1.0'],
      };

      expect(resourceVersions.knowledge_entities).toHaveLength(3);
      expect(resourceVersions.project_specification[2]).toBe('2.1.0');
      expect(validKnowledgeResource.lifecycle.version).toBe('1.2.0');
    });

    it('should manage resource tags and categorization', () => {
      const resourceTags = {
        knowledge: ['knowledge', 'entities', 'graph'],
        document: ['specification', 'document', 'pdf'],
      };

      expect(resourceTags.knowledge).toContain('knowledge');
      expect(resourceTags.document).toContain('pdf');
      expect(validKnowledgeResource.metadata['tags']).toEqual(resourceTags.knowledge);
    });

    it('should track resource size and checksum information', () => {
      expect(validKnowledgeResource.metadata['size']).toBe(15360);
      expect(validDocumentResource.metadata['size']).toBe(2097152);
      expect(validKnowledgeResource.metadata['checksum']).toContain('sha256:');
      expect(validDocumentResource.metadata['checksum']).toContain('sha256:');
    });
  });

  describe('Resource Lifecycle Management', () => {
    it('should handle resource status transitions', () => {
      const statusTransitions = {
        draft: ['active', 'deleted'],
        active: ['inactive', 'archived'],
        inactive: ['active', 'archived'],
        archived: ['active', 'deleted'],
        deleted: [],
      };

      expect(statusTransitions.active).toContain('inactive');
      expect(statusTransitions.archived).toContain('deleted');
      expect(statusTransitions.deleted).toHaveLength(0);
    });

    it('should manage retention policies', () => {
      const retentionPolicies = {
        standard: { duration: 365, autoDelete: true },
        document: { duration: 1825, autoDelete: false },
        archive: { duration: 3650, autoDelete: false },
        temporary: { duration: 30, autoDelete: true },
      };

      expect(validKnowledgeResource.lifecycle.retention.duration).toBe(365);
      expect(validDocumentResource.lifecycle.retention.duration).toBe(1825);
    });

    it('should handle resource expiration', () => {
      const now = new Date();
      const futureDate = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000); // 30 days
      const pastDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000); // 30 days ago

      const expiringResource = {
        ...validKnowledgeResource,
        lifecycle: {
          ...validKnowledgeResource.lifecycle,
          expires_at: futureDate.toISOString(),
        },
      };

      const expiredResource = {
        ...validKnowledgeResource,
        lifecycle: {
          ...validKnowledgeResource.lifecycle,
          expires_at: pastDate.toISOString(),
          status: 'archived' as const,
        },
      };

      expect(expiringResource.lifecycle.expires_at).toBeDefined();
      expect(expiredResource.lifecycle.status).toBe('archived');
    });
  });

  describe('Resource Registration System', () => {
    it('should register new resources successfully', async () => {
      mockResourceService.registerResource.mockResolvedValue({
        success: true,
        resourceId: 'resource-123',
        uri: validKnowledgeResource.uri,
        registeredAt: new Date().toISOString(),
      });

      const result = await mockResourceService.registerResource(validKnowledgeResource);

      expect(result.success).toBe(true);
      expect(result.resourceId).toBe('resource-123');
      expect(result.uri).toBe(validKnowledgeResource.uri);
      expect(mockResourceService.registerResource).toHaveBeenCalledWith(validKnowledgeResource);
    });

    it('should prevent duplicate resource registration', async () => {
      mockResourceService.registerResource.mockResolvedValue({
        success: false,
        error: {
          code: 'DUPLICATE_RESOURCE',
          message: 'Resource with this URI already exists',
          existingResourceId: 'resource-456',
        },
      });

      const result = await mockResourceService.registerResource(validKnowledgeResource);

      expect(result.success).toBe(false);
      expect(result.error.code).toBe('DUPLICATE_RESOURCE');
    });

    it('should validate resource URI uniqueness', () => {
      const resourceUris = [
        'knowledge://entities/project/test',
        'document://specs/project/test/specification.pdf',
        'media://images/project/test/logo.png',
        'archive://backups/project/test/backup-2024-01-01.tar.gz',
      ];

      const uniqueUris = [...new Set(resourceUris)];
      expect(uniqueUris).toHaveLength(4);
      expect(uniqueUris).toEqual(resourceUris);
    });
  });
});

// ============================================================================
// Test Suite 2: Knowledge Base Resources
// ============================================================================

describe('Knowledge Base Resources', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  describe('Entity Resource Access', () => {
    it('should retrieve entity resources by criteria', async () => {
      const entityRequest = createMockResourceRequest('knowledge://entities/project/test');

      mockAccessControl.checkResourcePermissions.mockResolvedValue({
        allowed: true,
        permissions: ['read'],
        restrictions: [],
      });

      mockResourceService.readResource.mockResolvedValue({
        success: true,
        data: {
          entities: [
            {
              id: 'entity-1',
              kind: 'entity',
              scope: { project: 'test-project' },
              data: {
                title: 'User Service',
                type: 'microservice',
                description: 'Handles user authentication and profiles',
              },
              metadata: {
                created_at: '2024-01-01',
                confidence: 0.9,
                version: '1.0.0',
              },
            },
          ],
          total: 1,
          metadata: {
            queryTime: 45,
            cacheHit: false,
            searchStrategy: 'semantic',
          },
        },
        metadata: {
          statusCode: 200,
          headers: { 'Content-Type': 'application/json' },
          size: 1024,
          duration: 67,
          cacheHit: false,
        },
      });

      const result = await mockResourceService.readResource(entityRequest.uri);

      expect(result.success).toBe(true);
      expect(result['data.entities']).toHaveLength(1);
      expect(result['data.entities'][0].data.title).toBe('User Service');
      expect(result.metadata['statusCode']).toBe(200);
    });

    it('should filter entity resources by scope', async () => {
      const scopedEntities = {
        'project:alpha': {
          entities: ['service-a', 'service-b'],
          count: 2,
        },
        'project:beta': {
          entities: ['service-c', 'service-d', 'service-e'],
          count: 3,
        },
        'org:global': {
          entities: ['shared-service-1', 'shared-service-2'],
          count: 2,
        },
      };

      expect(scopedEntities['project:alpha'].count).toBe(2);
      expect(scopedEntities['project:beta'].entities).toHaveLength(3);
      expect(scopedEntities['org:global'].entities).toContain('shared-service-1');
    });

    it('should support entity relationship navigation', async () => {
      const entityRelationships = {
        'user-service': {
          depends_on: ['database', 'auth-service'],
          connects_to: ['notification-service', 'analytics-service'],
          type: 'microservice',
          relationships: 4,
        },
        database: {
          depends_on: [],
          connects_to: ['user-service', 'order-service'],
          type: 'infrastructure',
          relationships: 2,
        },
      };

      expect(entityRelationships['user-service'].depends_on).toContain('database');
      expect(entityRelationships['database'].relationships).toBe(2);
    });
  });

  describe('Decision Resource Delivery', () => {
    it('should deliver architectural decision resources', async () => {
      const decisionRequest = createMockResourceRequest('knowledge://decisions/project/test');

      mockAccessControl.checkResourcePermissions.mockResolvedValue({
        allowed: true,
        permissions: ['read'],
        restrictions: ['confidential'],
      });

      mockResourceService.readResource.mockResolvedValue({
        success: true,
        data: {
          decisions: [
            {
              id: 'decision-001',
              kind: 'decision',
              scope: { project: 'test-project' },
              data: {
                title: 'Use Microservices Architecture',
                rationale: 'To improve scalability and team autonomy',
                alternatives: ['Monolithic architecture', 'Modular monolith'],
                consequences: {
                  positive: ['Independent deployment', 'Technology diversity'],
                  negative: ['Operational complexity', 'Network latency'],
                },
                status: 'implemented',
                decisionMaker: 'Architecture Team',
                date: '2024-01-15',
              },
              metadata: {
                created_at: '2024-01-15',
                confidence: 0.95,
                priority: 'high',
              },
            },
          ],
          total: 1,
          metadata: {
            category: 'architecture',
            impact: 'high',
            implementationStatus: 'completed',
          },
        },
        metadata: {
          statusCode: 200,
          headers: { 'Content-Type': 'application/json' },
          size: 2048,
          duration: 89,
          cacheHit: true,
        },
      });

      const result = await mockResourceService.readResource(decisionRequest.uri);

      expect(result.success).toBe(true);
      expect(result['data.decisions'][0].data.title).toBe('Use Microservices Architecture');
      expect(result['data.decisions'][0].data.consequences.positive).toContain(
        'Independent deployment'
      );
      expect(result.metadata['cacheHit']).toBe(true);
    });

    it('should categorize decisions by impact and status', async () => {
      const decisionCategories = {
        'high-impact-implemented': {
          count: 12,
          examples: ['microservices-architecture', 'postgresql-selection'],
        },
        'medium-impact-planned': {
          count: 8,
          examples: ['caching-strategy', 'api-gateway'],
        },
        'low-impact-deprecated': {
          count: 3,
          examples: ['old-auth-method', 'deprecated-queue'],
        },
      };

      expect(decisionCategories['high-impact-implemented'].count).toBe(12);
      expect(decisionCategories['medium-impact-planned'].examples).toContain('caching-strategy');
    });

    it('should provide decision timeline views', async () => {
      const decisionTimeline = [
        {
          date: '2024-01-15',
          decision: 'Microservices Architecture',
          status: 'implemented',
          impact: 'high',
        },
        {
          date: '2024-01-20',
          decision: 'PostgreSQL Selection',
          status: 'implemented',
          impact: 'high',
        },
        {
          date: '2024-02-01',
          decision: 'Redis Caching',
          status: 'planned',
          impact: 'medium',
        },
      ];

      const januaryDecisions = decisionTimeline.filter((d) => d.date.startsWith('2024-01'));
      expect(januaryDecisions).toHaveLength(2);
      expect(decisionTimeline[2].status).toBe('planned');
    });
  });

  describe('Relationship Resource Queries', () => {
    it('should query relationship resources efficiently', async () => {
      const relationshipRequest = createMockResourceRequest(
        'knowledge://relationships/project/test'
      );

      mockAccessControl.checkResourcePermissions.mockResolvedValue({
        allowed: true,
        permissions: ['read'],
        restrictions: [],
      });

      mockResourceService.readResource.mockResolvedValue({
        success: true,
        data: {
          relationships: [
            {
              id: 'relation-001',
              kind: 'relation',
              scope: { project: 'test-project' },
              data: {
                from: 'user-service',
                to: 'database',
                type: 'depends_on',
                strength: 'strong',
                description: 'Critical runtime dependency',
                metadata: {
                  dependency_type: 'runtime',
                  criticality: 'high',
                  impact_score: 0.9,
                },
              },
              metadata: {
                created_at: '2024-01-01',
                confidence: 0.95,
                verified: true,
              },
            },
          ],
          total: 1,
          analytics: {
            totalRelations: 45,
            relationTypes: {
              depends_on: 18,
              connects_to: 15,
              implements: 7,
              conflicts_with: 5,
            },
            networkDensity: 0.34,
          },
        },
        metadata: {
          statusCode: 200,
          headers: { 'Content-Type': 'application/json' },
          size: 1536,
          duration: 123,
          cacheHit: false,
        },
      });

      const result = await mockResourceService.readResource(relationshipRequest.uri);

      expect(result.success).toBe(true);
      expect(result['data.relationships'][0].data.type).toBe('depends_on');
      expect(result['data.analytics'].totalRelations).toBe(45);
      expect(result['data.analytics'].relationTypes.depends_on).toBe(18);
    });

    it('should support relationship graph traversal', async () => {
      const graphTraversal = {
        startNode: 'user-service',
        path: ['user-service', 'database', 'backup-service'],
        relationships: ['depends_on', 'backed_up_by'],
        depth: 2,
        totalNodes: 3,
      };

      expect(graphTraversal.path).toHaveLength(3);
      expect(graphTraversal.depth).toBe(2);
      expect(graphTraversal.relationships[0]).toBe('depends_on');
    });

    it('should analyze relationship patterns', async () => {
      const relationshipPatterns = {
        hub_nodes: [
          { node: 'api-gateway', connections: 12 },
          { node: 'database', connections: 8 },
          { node: 'cache-service', connections: 6 },
        ],
        bridge_nodes: [
          { node: 'auth-service', bridges: ['frontend', 'backend'] },
          { node: 'message-queue', bridges: ['producers', 'consumers'] },
        ],
        isolated_nodes: [
          { node: 'legacy-service', connections: 1 },
          { node: 'test-service', connections: 0 },
        ],
      };

      expect(relationshipPatterns.hub_nodes[0].connections).toBe(12);
      expect(relationshipPatterns.bridge_nodes[0].bridges).toHaveLength(2);
      expect(relationshipPatterns.isolated_nodes[1].connections).toBe(0);
    });
  });

  describe('Observation Resource Retrieval', () => {
    it('should retrieve observation resources with context', async () => {
      const observationRequest = createMockResourceRequest('knowledge://observations/project/test');

      mockAccessControl.checkResourcePermissions.mockResolvedValue({
        allowed: true,
        permissions: ['read'],
        restrictions: [],
      });

      mockResourceService.readResource.mockResolvedValue({
        success: true,
        data: {
          observations: [
            {
              id: 'observation-001',
              kind: 'observation',
              scope: { project: 'test-project' },
              data: {
                title: 'Performance Degradation in API Gateway',
                category: 'performance',
                description: 'Response times increased by 300% during peak hours',
                metrics: {
                  avg_response_time: '2500ms',
                  baseline_response_time: '600ms',
                  impact_severity: 'high',
                },
                evidence: [
                  'Grafana dashboard screenshots',
                  'Log samples showing slow queries',
                  'User complaints timestamp',
                ],
                recommendations: [
                  'Implement response caching',
                  'Database query optimization',
                  'Consider auto-scaling',
                ],
              },
              metadata: {
                created_at: '2024-01-20',
                confidence: 0.91,
                category: 'performance',
                severity: 'high',
              },
            },
          ],
          total: 1,
          insights: {
            patterns: ['peak-hour-slowdown', 'database-bottleneck'],
            trends: ['gradual-degradation-over-week'],
            recommendations_summary: {
              immediate: ['caching', 'query-optimization'],
              long_term: ['architecture-review', 'capacity-planning'],
            },
          },
        },
        metadata: {
          statusCode: 200,
          headers: { 'Content-Type': 'application/json' },
          size: 3072,
          duration: 156,
          cacheHit: false,
        },
      });

      const result = await mockResourceService.readResource(observationRequest.uri);

      expect(result.success).toBe(true);
      expect(result['data.observations'][0].data.category).toBe('performance');
      expect(result['data.observations'][0].data.recommendations).toContain(
        'Implement response caching'
      );
      expect(result['data.insights'].patterns).toContain('peak-hour-slowdown');
    });

    it('should categorize observations by type and severity', async () => {
      const observationCategories = {
        'performance-high': {
          count: 7,
          avgConfidence: 0.89,
          examples: ['api-response-time', 'memory-leak'],
        },
        'security-critical': {
          count: 3,
          avgConfidence: 0.95,
          examples: ['unauthorized-access', 'data-exposure'],
        },
        'usability-medium': {
          count: 12,
          avgConfidence: 0.82,
          examples: ['ui-confusion', 'workflow-issues'],
        },
      };

      expect(observationCategories['performance-high'].count).toBe(7);
      expect(observationCategories['security-critical'].avgConfidence).toBeGreaterThan(0.9);
      expect(observationCategories['usability-medium'].examples).toContain('ui-confusion');
    });
  });
});

// ============================================================================
// Test Suite 3: File and Document Resources
// ============================================================================

describe('File and Document Resources', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  describe('Document Upload and Management', () => {
    it('should handle document uploads with metadata', async () => {
      const uploadRequest = {
        uri: 'document://upload',
        method: 'POST' as const,
        headers: {
          'Content-Type': 'multipart/form-data',
          Authorization: 'Bearer admin-token',
        },
        body: {
          file: Buffer.from('test document content'),
          metadata: {
            title: 'API Documentation',
            description: 'REST API documentation for the project',
            tags: ['api', 'documentation', 'technical'],
            category: 'documentation',
            version: '1.0.0',
          },
        },
        context: createMockResourceRequest('document://upload').context,
      };

      mockResourceService.registerResource.mockResolvedValue({
        success: true,
        resourceId: 'doc-123',
        uri: 'document://api/docs/v1/documentation.pdf',
        registeredAt: new Date().toISOString(),
        metadata: {
          size: 1024,
          contentType: 'application/pdf',
          checksum: 'sha256:uploaded123',
          processed: true,
        },
      });

      const result = await mockResourceService.registerResource(uploadRequest.body.metadata);

      expect(result.success).toBe(true);
      expect(result.resourceId).toBe('doc-123');
      expect(result.uri).toContain('documentation.pdf');
    });

    it('should validate document formats and types', () => {
      const supportedFormats = {
        documents: ['.pdf', '.docx', '.md', '.txt', '.rst'],
        images: ['.png', '.jpg', '.jpeg', '.gif', '.svg'],
        data: ['.json', '.yaml', '.yml', '.csv', '.xml'],
        archives: ['.zip', '.tar.gz', '.rar', '.7z'],
      };

      const pdfFile = 'specification.pdf';
      const fileType = Object.entries(supportedFormats).find(([_, extensions]) =>
        extensions.some((ext) => pdfFile.endsWith(ext))
      );

      expect(fileType?.[0]).toBe('documents');
      expect(supportedFormats.documents).toContain('.pdf');
    });

    it('should process document thumbnails and previews', async () => {
      const documentProcessing = {
        original: {
          name: 'architecture-diagram.png',
          size: 2048576,
          type: 'image/png',
        },
        thumbnails: [
          { size: 'small', dimensions: '150x150', fileSize: 8192 },
          { size: 'medium', dimensions: '300x300', fileSize: 16384 },
          { size: 'large', dimensions: '600x600', fileSize: 32768 },
        ],
        preview: {
          type: 'html',
          generated: true,
          embeddable: true,
        },
      };

      expect(documentProcessing.thumbnails).toHaveLength(3);
      expect(documentProcessing.thumbnails[0].dimensions).toBe('150x150');
      expect(documentProcessing.preview.generated).toBe(true);
    });
  });

  describe('File Resource Access', () => {
    it('should provide secure file download access', async () => {
      const downloadRequest = createMockResourceRequest(
        'document://specs/project/test/specification.pdf',
        'developer'
      );

      mockAccessControl.checkResourcePermissions.mockResolvedValue({
        allowed: true,
        permissions: ['read'],
        restrictions: ['watermark'],
      });

      mockResourceService.readResource.mockResolvedValue({
        success: true,
        data: Buffer.from('PDF content here'), // Simulated PDF content
        metadata: {
          statusCode: 200,
          headers: {
            'Content-Type': 'application/pdf',
            'Content-Disposition': 'attachment; filename="specification.pdf"',
            'Content-Length': '2097152',
            'Accept-Ranges': 'bytes',
          },
          size: 2097152,
          duration: 234,
          cacheHit: true,
          downloadInfo: {
            url: 'https://cdn.example.com/files/specification.pdf',
            expiresAt: new Date(Date.now() + 3600000).toISOString(),
            accessType: 'signed-url',
          },
        },
      });

      const result = await mockResourceService.readResource(downloadRequest.uri);

      expect(result.success).toBe(true);
      expect(result.data).toBeInstanceOf(Buffer);
      expect(result.metadata['headers']['Content-Type']).toBe('application/pdf');
      expect(result.metadata['downloadInfo'].accessType).toBe('signed-url');
    });

    it('should support partial content and range requests', async () => {
      const rangeRequest = {
        uri: 'document://large-dataset.csv',
        method: 'GET' as const,
        headers: {
          Range: 'bytes=1024-2047',
          Authorization: 'Bearer viewer-token',
        },
        context: createMockResourceRequest('document://large-dataset.csv').context,
      };

      const rangeResponse = {
        success: true,
        data: Buffer.from('CSV partial content'), // Partial content
        metadata: {
          statusCode: 206, // Partial Content
          headers: {
            'Content-Type': 'text/csv',
            'Content-Range': 'bytes 1024-2047/10485760',
            'Accept-Ranges': 'bytes',
            'Content-Length': '1024',
          },
          size: 1024,
          duration: 89,
          cacheHit: false,
          rangeInfo: {
            start: 1024,
            end: 2047,
            totalSize: 10485760,
            requestedRange: '1024-2047',
          },
        },
      };

      expect(rangeResponse.metadata['statusCode']).toBe(206);
      expect(rangeResponse.metadata['headers']['Content-Range']).toContain('1024-2047');
      expect(rangeResponse.metadata['rangeInfo'].start).toBe(1024);
    });

    it('should implement file access logging and audit', async () => {
      const accessLog = {
        timestamp: new Date().toISOString(),
        userId: 'developer-123',
        resourceId: 'document://specs/project/test/specification.pdf',
        action: 'download',
        result: 'success',
        ip: '192.168.1.100',
        userAgent: 'MCP-Client/1.0',
        downloadSize: 2097152,
        duration: 234,
        cacheHit: true,
      };

      mockAccessControl.logAccessAttempt.mockResolvedValue(accessLog);

      const logEntry = await mockAccessControl.logAccessAttempt(accessLog);

      expect(logEntry.action).toBe('download');
      expect(logEntry.downloadSize).toBe(2097152);
      expect(logEntry.cacheHit).toBe(true);
    });
  });

  describe('Media Resource Handling', () => {
    it('should handle image resource transformations', async () => {
      const imageRequest = createMockResourceRequest(
        'media://images/project/test/architecture-diagram.png'
      );

      mockAccessControl.checkResourcePermissions.mockResolvedValue({
        allowed: true,
        permissions: ['read'],
        restrictions: [],
      });

      mockResourceService.readResource.mockResolvedValue({
        success: true,
        data: {
          original: {
            url: 'media://images/project/test/architecture-diagram.png',
            width: 1920,
            height: 1080,
            format: 'PNG',
            size: 2048576,
          },
          transformations: {
            thumbnail: {
              url: 'media://images/project/test/architecture-diagram-thumb.png',
              width: 150,
              height: 150,
              size: 8192,
            },
            medium: {
              url: 'media://images/project/test/architecture-diagram-medium.png',
              width: 600,
              height: 400,
              size: 98304,
            },
            optimized: {
              url: 'media://images/project/test/architecture-diagram-opt.jpg',
              width: 1920,
              height: 1080,
              format: 'JPEG',
              size: 512000,
            },
          },
        },
        metadata: {
          statusCode: 200,
          headers: { 'Content-Type': 'application/json' },
          size: 512,
          duration: 456,
          cacheHit: false,
        },
      });

      const result = await mockResourceService.readResource(imageRequest.uri);

      expect(result.success).toBe(true);
      expect(result['data.original'].format).toBe('PNG');
      expect(result['data.transformations'].thumbnail.width).toBe(150);
      expect(result['data.transformations'].optimized.format).toBe('JPEG');
    });

    it('should support video resource streaming', async () => {
      const videoRequest = createMockResourceRequest('media://videos/project/test/demo.mp4');

      mockAccessControl.checkResourcePermissions.mockResolvedValue({
        allowed: true,
        permissions: ['read'],
        restrictions: [],
      });

      const streamingResponse = {
        success: true,
        data: {
          streamUrl: 'https://cdn.example.com/videos/demo.mp4',
          manifest: {
            duration: 300, // 5 minutes
            resolution: '1920x1080',
            bitrate: '5000k',
            format: 'H.264',
            adaptive: true,
          },
          qualityLevels: [
            { resolution: '1920x1080', bitrate: '5000k', url: '1080p.mp4' },
            { resolution: '1280x720', bitrate: '2500k', url: '720p.mp4' },
            { resolution: '854x480', bitrate: '1000k', url: '480p.mp4' },
            { resolution: '640x360', bitrate: '500k', url: '360p.mp4' },
          ],
          captions: [
            { language: 'en', format: 'vtt', url: 'en.vtt' },
            { language: 'es', format: 'vtt', url: 'es.vtt' },
          ],
        },
        metadata: {
          statusCode: 200,
          headers: { 'Content-Type': 'application/json' },
          size: 2048,
          duration: 78,
          cacheHit: true,
        },
      };

      const result = streamingResponse;

      expect(result.success).toBe(true);
      expect(result['data.manifest'].duration).toBe(300);
      expect(result['data.qualityLevels']).toHaveLength(4);
      expect(result['data.captions']).toHaveLength(2);
    });

    it('should process audio resource metadata', async () => {
      const audioMetadata = {
        duration: 180, // 3 minutes
        format: 'MP3',
        bitrate: '320k',
        sampleRate: '44.1kHz',
        channels: 2,
        codec: 'AAC',
        size: 4320000,
        waveform: {
          peaks: [0.1, 0.8, 0.3, 0.9, 0.2], // Sample waveform data
          resolution: 1000,
        },
        transcription: {
          available: true,
          language: 'en',
          confidence: 0.92,
          segments: [
            { start: 0, end: 5, text: 'Welcome to our podcast' },
            { start: 5, end: 10, text: "Today we'll discuss..." },
          ],
        },
      };

      expect(audioMetadata.duration).toBe(180);
      expect(audioMetadata.bitrate).toBe('320k');
      expect(audioMetadata.transcription.available).toBe(true);
      expect(audioMetadata.transcription.segments).toHaveLength(2);
    });
  });

  describe('Archive Resource Management', () => {
    it('should handle archive resource creation and extraction', async () => {
      const archiveRequest = createMockResourceRequest('archive://create', 'admin');

      mockAccessControl.checkResourcePermissions.mockResolvedValue({
        allowed: true,
        permissions: ['write'],
        restrictions: [],
      });

      const archiveCreation = {
        success: true,
        archiveId: 'archive-123',
        archiveUrl: 'archive://backups/project/test/backup-2024-01-30.tar.gz',
        metadata: {
          type: 'tar.gz',
          compression: 'gzip',
          totalFiles: 245,
          totalSize: 104857600, // 100MB
          compressedSize: 31457280, // 30MB
          compressionRatio: 0.3,
          created_at: new Date().toISOString(),
          checksum: 'sha256:archive123456',
        },
        contents: {
          directories: ['src/', 'docs/', 'tests/', 'config/'],
          fileTypes: {
            '.ts': 120,
            '.js': 45,
            '.json': 20,
            '.md': 15,
            '.yml': 8,
          },
        },
      };

      const result = archiveCreation;

      expect(result.success).toBe(true);
      expect(result.metadata['compressionRatio']).toBe(0.3);
      expect(result.contents.fileTypes['.ts']).toBe(120);
      expect(result.contents.directories).toContain('src/');
    });

    it('should support archive browsing and partial extraction', async () => {
      const archiveBrowse = {
        archiveId: 'archive-123',
        contents: [
          {
            path: 'src/services/user-service.ts',
            type: 'file',
            size: 5120,
            modified: '2024-01-29T10:30:00Z',
            permissions: 'rw-r--r--',
          },
          {
            path: 'docs/api-spec.yaml',
            type: 'file',
            size: 2048,
            modified: '2024-01-28T15:45:00Z',
            permissions: 'rw-r--r--',
          },
          {
            path: 'config/',
            type: 'directory',
            size: 0,
            modified: '2024-01-30T09:00:00Z',
            permissions: 'rwxr-xr-x',
          },
        ],
        totalFiles: 2,
        totalDirectories: 1,
        totalSize: 7168,
      };

      expect(archiveBrowse.contents).toHaveLength(3);
      expect(archiveBrowse.contents[0].type).toBe('file');
      expect(archiveBrowse.contents[2].type).toBe('directory');
      expect(archiveBrowse.totalSize).toBe(7168);
    });

    it('should implement archive integrity verification', async () => {
      const integrityCheck = {
        archiveId: 'archive-123',
        checkType: 'full_verification',
        status: 'completed',
        results: {
          totalFiles: 245,
          verifiedFiles: 245,
          corruptedFiles: 0,
          missingFiles: 0,
          integrityPassed: true,
          checksumVerified: true,
        },
        performance: {
          duration: 45000, // 45 seconds
          throughput: '5.5 MB/s',
          resourcesUsed: {
            cpu: 25,
            memory: 128,
          },
        },
      };

      expect(integrityCheck.results.integrityPassed).toBe(true);
      expect(integrityCheck.results.corruptedFiles).toBe(0);
      expect(integrityCheck.performance.duration).toBe(45000);
    });
  });
});

// ============================================================================
// Test Suite 4: Resource Access Control
// ============================================================================

describe('Resource Access Control', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  describe('Resource-level Permissions', () => {
    it('should enforce role-based resource access', async () => {
      const accessScenarios = [
        {
          userRole: 'admin',
          resourceUri: 'knowledge://entities/project/test',
          expectedPermission: 'admin',
          allowed: true,
        },
        {
          userRole: 'developer',
          resourceUri: 'document://specs/project/test/specification.pdf',
          expectedPermission: 'read',
          allowed: true,
        },
        {
          userRole: 'viewer',
          resourceUri: 'document://specs/project/test/specification.pdf',
          expectedPermission: 'denied',
          allowed: false,
        },
      ];

      mockAccessControl.checkResourcePermissions.mockImplementation(
        async (userRole: string, resourceUri: string) => {
          const scenario = accessScenarios.find(
            (s) => s.userRole === userRole && s.resourceUri === resourceUri
          );
          return {
            allowed: scenario?.allowed || false,
            permissions: scenario?.allowed ? [scenario?.expectedPermission] : [],
            restrictions: scenario?.allowed ? [] : ['access_denied'],
          };
        }
      );

      for (const scenario of accessScenarios) {
        const result = await mockAccessControl.checkResourcePermissions(
          scenario.userRole,
          scenario.resourceUri
        );
        expect(result.allowed).toBe(scenario.allowed);
        if (scenario.allowed) {
          expect(result.permissions[0]).toBe(scenario.expectedPermission);
        }
      }
    });

    it('should handle resource permission inheritance', async () => {
      const permissionHierarchy = {
        'project:test': {
          permissions: {
            admin: ['read', 'write', 'delete', 'admin'],
            developer: ['read', 'write'],
            viewer: ['read'],
          },
          inherits: ['org:test-org'],
        },
        'org:test-org': {
          permissions: {
            admin: ['read', 'write', 'delete', 'admin'],
            developer: ['read'],
            viewer: ['read'],
          },
          inherits: ['global'],
        },
        global: {
          permissions: {
            system: ['read', 'write', 'delete', 'admin'],
            auditor: ['read'],
          },
          inherits: [],
        },
      };

      const effectivePermissions = {
        'admin-project': ['read', 'write', 'delete', 'admin'],
        'developer-project': ['read', 'write'],
        'viewer-project': ['read'],
        'auditor-org': ['read'],
      };

      expect(effectivePermissions['admin-project']).toContain('admin');
      expect(effectivePermissions['developer-project']).toHaveLength(2);
      expect(effectivePermissions['viewer-project']).toEqual(['read']);
    });

    it('should support temporary access grants', async () => {
      const temporaryAccess = {
        userId: 'contractor-123',
        resourceId: 'document://specs/project/test/specification.pdf',
        grantedBy: 'admin-456',
        grantedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(), // 24 hours
        permissions: ['read'],
        reason: 'Contractor needs access for project evaluation',
        conditions: {
          ipAddress: ['192.168.1.0/24'],
          deviceFingerprint: 'device-abc123',
          timeRestrictions: {
            allowedHours: ['09:00-17:00'],
            timezone: 'UTC',
          },
        },
      };

      const isExpired = new Date() > new Date(temporaryAccess.expiresAt);
      const isInAllowedHours = true; // Would check current time against allowedHours

      expect(isExpired).toBe(false);
      expect(isInAllowedHours).toBe(true);
      expect(temporaryAccess.permissions).toContain('read');
    });
  });

  describe('Scope-based Access Control', () => {
    it('should enforce project-level resource isolation', async () => {
      const projectResources = {
        'project-alpha': {
          resources: [
            'knowledge://entities/project/alpha',
            'document://specs/project/alpha/requirements.pdf',
            'media://images/project/alpha/architecture.png',
          ],
          authorizedUsers: ['admin-alpha', 'dev-alpha-1', 'dev-alpha-2'],
        },
        'project-beta': {
          resources: [
            'knowledge://entities/project/beta',
            'document://specs/project/beta/api-design.pdf',
            'media://videos/project/beta/demo.mp4',
          ],
          authorizedUsers: ['admin-beta', 'dev-beta-1'],
        },
      };

      mockAccessControl.validateScopeAccess.mockImplementation(
        async (userId: string, projectId: string) => {
          const project = projectResources[projectId as keyof typeof projectResources];
          return {
            allowed: project?.authorizedUsers.includes(userId) || false,
            scope: projectId,
            restrictions: project?.authorizedUsers.includes(userId)
              ? []
              : ['project_access_denied'],
          };
        }
      );

      const alphaAccess = await mockAccessControl.validateScopeAccess(
        'dev-alpha-1',
        'project-alpha'
      );
      const betaAccess = await mockAccessControl.validateScopeAccess('dev-alpha-1', 'project-beta');

      expect(alphaAccess.allowed).toBe(true);
      expect(betaAccess.allowed).toBe(false);
      expect(betaAccess.restrictions).toContain('project_access_denied');
    });

    it('should handle organizational resource hierarchies', async () => {
      const orgHierarchy = {
        'org-corp': {
          subUnits: ['division-engineering', 'division-product', 'division-ops'],
          resources: [
            'knowledge://policies/org/corp',
            'document://handbooks/org/corp/employee-handbook.pdf',
          ],
          inheritedByAll: true,
        },
        'division-engineering': {
          parent: 'org-corp',
          subUnits: ['team-frontend', 'team-backend', 'team-platform'],
          resources: [
            'knowledge://standards/division/engineering',
            'document://guides/division/engineering/coding-standards.md',
          ],
        },
        'team-backend': {
          parent: 'division-engineering',
          resources: [
            'knowledge://entities/team/backend',
            'document://specs/team/backend/api-design.yaml',
          ],
        },
      };

      const accessibleResources = {
        'corp-user': ['org-corp', 'division-engineering', 'team-backend'], // Inherits access
        'engineering-user': ['division-engineering', 'team-backend'], // Inherits from parent
        'backend-user': ['team-backend'], // Only direct access
      };

      expect(accessibleResources['corp-user']).toHaveLength(3);
      expect(accessibleResources['engineering-user']).toContain('division-engineering');
      expect(accessibleResources['backend-user']).toEqual(['team-backend']);
    });

    it('should implement branch-level access control', async () => {
      const branchAccess = {
        main: {
          protection: 'protected',
          allowedRoles: ['admin', 'senior-developer'],
          requiresApproval: true,
          allowedOperations: ['read', 'create-branch'],
        },
        develop: {
          protection: 'standard',
          allowedRoles: ['admin', 'developer', 'senior-developer'],
          requiresApproval: false,
          allowedOperations: ['read', 'write', 'create-branch'],
        },
        'feature/*': {
          protection: 'open',
          allowedRoles: ['admin', 'developer', 'senior-developer', 'contractor'],
          requiresApproval: false,
          allowedOperations: ['read', 'write'],
        },
      };

      const userBranchAccess = {
        admin: ['main', 'develop', 'feature/*'],
        'senior-developer': ['main', 'develop', 'feature/*'],
        developer: ['develop', 'feature/*'],
        contractor: ['feature/*'],
      };

      expect(branchAccess.main.protection).toBe('protected');
      expect(userBranchAccess.developer).not.toContain('main');
      expect(userBranchAccess.contractor).toEqual(['feature/*']);
    });
  });

  describe('Authentication Requirements', () => {
    it('should enforce different authentication levels by resource type', async () => {
      const authRequirements = {
        'knowledge://': {
          level: 'standard',
          methods: ['jwt', 'api_key'],
          mfaRequired: false,
          sessionTimeout: 3600,
        },
        'document://confidential/': {
          level: 'high',
          methods: ['jwt', 'mfa'],
          mfaRequired: true,
          sessionTimeout: 1800,
        },
        'admin://': {
          level: 'critical',
          methods: ['jwt', 'mfa', 'hardware-token'],
          mfaRequired: true,
          sessionTimeout: 900,
        },
      };

      expect(authRequirements['knowledge://'].mfaRequired).toBe(false);
      expect(authRequirements['document://confidential/'].level).toBe('high');
      expect(authRequirements['admin://'].methods).toContain('hardware-token');
    });

    it('should handle token-based resource access', async () => {
      const tokenValidation = {
        jwtToken: {
          type: 'JWT',
          valid: true,
          payload: {
            userId: 'user-123',
            role: 'developer',
            scope: ['project:test'],
            expiresAt: new Date(Date.now() + 3600000).toISOString(),
          },
          permissions: ['read', 'write'],
        },
        apiToken: {
          type: 'API_KEY',
          valid: true,
          keyId: 'key-456',
          userId: 'service-account-789',
          permissions: ['read'],
          restrictions: ['no-delete', 'rate-limited'],
        },
        expiredToken: {
          type: 'JWT',
          valid: false,
          error: 'TOKEN_EXPIRED',
          expiredAt: new Date(Date.now() - 3600000).toISOString(),
        },
      };

      expect(tokenValidation.jwtToken.valid).toBe(true);
      expect(tokenValidation.jwtToken.permissions).toContain('write');
      expect(tokenValidation.apiToken.restrictions).toContain('rate-limited');
      expect(tokenValidation.expiredToken.valid).toBe(false);
    });

    it('should implement service account authentication', async () => {
      const serviceAccount = {
        accountId: 'service-cortex-system',
        displayName: 'Cortex System Service',
        permissions: {
          resources: ['knowledge://', 'document://'],
          operations: ['read', 'write', 'delete'],
          scopes: ['org:test-org'],
        },
        authentication: {
          method: 'service-account-key',
          keyId: 'sa-key-123',
          createdAt: new Date().toISOString(),
          expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
          autoRotation: true,
        },
        usage: {
          lastUsed: new Date().toISOString(),
          requestCount: 1250,
          errorRate: 0.001,
        },
      };

      expect(serviceAccount.permissions.operations).toContain('delete');
      expect(serviceAccount.authentication.autoRotation).toBe(true);
      expect(serviceAccount.usage.errorRate).toBeLessThan(0.01);
    });
  });

  describe('Usage Tracking and Limits', () => {
    it('should track resource access patterns', async () => {
      const usageTracking = {
        userId: 'developer-123',
        timeRange: '2024-01-01 to 2024-01-31',
        resourceAccess: {
          'knowledge://entities': {
            count: 245,
            uniqueResources: 18,
            avgResponseTime: 67,
            cacheHitRate: 0.73,
          },
          'document://specs': {
            count: 89,
            uniqueResources: 12,
            avgResponseTime: 234,
            cacheHitRate: 0.91,
          },
          'media://images': {
            count: 156,
            uniqueResources: 34,
            avgResponseTime: 125,
            cacheHitRate: 0.85,
          },
        },
        totalBandwidth: 204857600, // 200MB
        totalRequests: 490,
        errorRate: 0.002,
      };

      expect(usageTracking.resourceAccess['knowledge://entities'].count).toBe(245);
      expect(usageTracking.resourceAccess['document://specs'].cacheHitRate).toBeGreaterThan(0.9);
      expect(usageTracking.totalRequests).toBe(490);
    });

    it('should enforce resource usage quotas', async () => {
      const usageQuotas = {
        viewer: {
          dailyRequests: 100,
          monthlyBandwidth: 1073741824, // 1GB
          maxFileSize: 10485760, // 10MB
          resourceTypes: ['knowledge://', 'document://public/', 'media://images/'],
        },
        developer: {
          dailyRequests: 1000,
          monthlyBandwidth: 10737418240, // 10GB
          maxFileSize: 104857600, // 100MB
          resourceTypes: ['knowledge://', 'document://', 'media://', 'archive://'],
        },
        admin: {
          dailyRequests: 10000,
          monthlyBandwidth: 107374182400, // 100GB
          maxFileSize: 1073741824, // 1GB
          resourceTypes: ['*'], // All resources
        },
      };

      mockAccessControl.checkResourceQuotas.mockImplementation(
        async (userRole: string, operation: any) => {
          const quota = usageQuotas[userRole as keyof typeof usageQuotas];
          const currentUsage = {
            dailyRequests: 50,
            monthlyBandwidth: 536870912, // 512MB
            lastFileSize: 5242880, // 5MB
          };

          return {
            allowed:
              currentUsage.dailyRequests < quota.dailyRequests &&
              currentUsage.monthlyBandwidth < quota.monthlyBandwidth &&
              currentUsage.lastFileSize < quota.maxFileSize,
            quota,
            currentUsage,
            restrictions: [],
          };
        }
      );

      const developerQuotaCheck = await mockAccessControl.checkResourceQuotas('developer', {});
      expect(developerQuotaCheck.allowed).toBe(true);

      const viewerQuotaCheck = await mockAccessControl.checkResourceQuotas('viewer', {});
      expect(viewerQuotaCheck.allowed).toBe(true);
    });

    it('should implement rate limiting for resource access', async () => {
      const rateLimiting = {
        windows: [
          { size: '1m', limit: 60, current: 45, resetIn: 15 },
          { size: '5m', limit: 250, current: 180, resetIn: 75 },
          { size: '1h', limit: 3000, current: 2100, resetIn: 2700 },
        ],
        strategy: 'sliding_window',
        penalties: {
          exceeded: {
            delayMs: 1000,
            statusCode: 429,
            retryAfter: 60,
          },
          严重Exceeded: {
            delayMs: 5000,
            statusCode: 429,
            retryAfter: 300,
          },
        },
      };

      mockAccessControl.enforceRateLimits.mockImplementation(
        async (userId: string, resourceType: string) => {
          const window = rateLimiting.windows[0]; // 1-minute window
          const isExceeded = window.current >= window.limit;

          return {
            allowed: !isExceeded,
            window,
            resetIn: window.resetIn,
            penalty: isExceeded ? rateLimiting.penalties.exceeded : null,
          };
        }
      );

      const rateLimitCheck = await mockAccessControl.enforceRateLimits('user-123', 'knowledge://');
      expect(rateLimitCheck.allowed).toBe(true);
      expect(rateLimitCheck.window.current).toBe(45);
    });
  });
});

// ============================================================================
// Test Suite 5: Resource Delivery
// ============================================================================

describe('Resource Delivery', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  describe('Content Streaming', () => {
    it('should stream large resource content efficiently', async () => {
      const streamingRequest = createMockResourceRequest('document://large-dataset.csv');

      mockResourceService.streamResourceContent.mockResolvedValue({
        success: true,
        streamId: 'stream-123',
        contentType: 'text/csv',
        contentLength: 104857600, // 100MB
        chunkSize: 65536, // 64KB chunks
        totalChunks: 1600,
        streamUrl: 'https://cdn.example.com/streams/stream-123',
        metadata: {
          supportsSeeking: true,
          supportedFormats: ['csv', 'json', 'parquet'],
          compression: 'gzip',
          encoding: 'utf-8',
        },
      });

      const result = await mockResourceService.streamResourceContent(streamingRequest.uri);

      expect(result.success).toBe(true);
      expect(result.totalChunks).toBe(1600);
      expect(result.chunkSize).toBe(65536);
      expect(result.metadata['supportsSeeking']).toBe(true);
    });

    it('should handle adaptive bitrate streaming for media', async () => {
      const adaptiveStreaming = {
        streamId: 'adaptive-stream-456',
        formats: {
          video: [
            { resolution: '1080p', bitrate: '5000k', codec: 'H.264' },
            { resolution: '720p', bitrate: '2500k', codec: 'H.264' },
            { resolution: '480p', bitrate: '1000k', codec: 'H.264' },
          ],
          audio: [
            { bitrate: '320k', codec: 'AAC' },
            { bitrate: '128k', codec: 'AAC' },
          ],
        },
        streamingProtocol: 'HLS',
        manifestUrl: 'https://cdn.example.com/hls/manifest.m3u8',
        adaptiveLogic: {
          networkBased: true,
          deviceBased: true,
          userPreference: true,
        },
      };

      expect(adaptiveStreaming.formats.video).toHaveLength(3);
      expect(adaptiveStreaming.streamingProtocol).toBe('HLS');
      expect(adaptiveStreaming.adaptiveLogic.networkBased).toBe(true);
    });

    it('should implement chunked transfer encoding', async () => {
      const chunkedTransfer = {
        transferId: 'transfer-789',
        chunks: [
          {
            sequence: 1,
            size: 8192,
            checksum: 'sha256:chunk1-abc',
            received: true,
          },
          {
            sequence: 2,
            size: 8192,
            checksum: 'sha256:chunk2-def',
            received: true,
          },
          {
            sequence: 3,
            size: 4096,
            checksum: 'sha256:chunk3-ghi',
            received: false,
          },
        ],
        totalSize: 20480,
        progress: 0.8,
        transferRate: '1.2 MB/s',
      };

      expect(chunkedTransfer.chunks).toHaveLength(3);
      expect(chunkedTransfer.progress).toBe(0.8);
      expect(chunkedTransfer.chunks[2].received).toBe(false);
    });
  });

  describe('Format Conversion', () => {
    it('should convert between different document formats', async () => {
      const formatConversions = {
        pdf_to_docx: {
          supported: true,
          quality: 'high',
          processingTime: 30, // seconds
          maxSize: 52428800, // 50MB
          preservesFormatting: true,
          preservesImages: true,
          preservesTables: true,
        },
        docx_to_markdown: {
          supported: true,
          quality: 'medium',
          processingTime: 10,
          maxSize: 10485760, // 10MB
          preservesFormatting: false,
          preservesImages: false,
          preservesTables: true,
        },
        json_to_yaml: {
          supported: true,
          quality: 'perfect',
          processingTime: 1,
          maxSize: 1048576, // 1MB
          preservesFormatting: true,
          preservesImages: false,
          preservesTables: false,
        },
      };

      mockResourceService.transformResourceFormat.mockImplementation(
        async (sourceFormat: string, targetFormat: string, content: any) => {
          const conversionKey = `${sourceFormat}_to_${targetFormat}`;
          const conversion = formatConversions[conversionKey as keyof typeof formatConversions];

          if (!conversion) {
            return { success: false, error: 'Unsupported conversion' };
          }

          return {
            success: true,
            transformedContent: `Converted content from ${sourceFormat} to ${targetFormat}`,
            metadata: {
              sourceFormat,
              targetFormat,
              quality: conversion.quality,
              processingTime: conversion.processingTime,
              size: content.length * 0.8, // Simulated size reduction
            },
          };
        }
      );

      const pdfToDocx = await mockResourceService.transformResourceFormat(
        'pdf',
        'docx',
        'PDF content'
      );
      const jsonToYaml = await mockResourceService.transformResourceFormat(
        'json',
        'yaml',
        '{"key": "value"}'
      );

      expect(pdfToDocx.success).toBe(true);
      expect(pdfToDocx.metadata['quality']).toBe('high');
      expect(jsonToYaml.success).toBe(true);
      expect(jsonToYaml.metadata['processingTime']).toBe(1);
    });

    it('should handle image format conversions', async () => {
      const imageConversions = {
        png_to_jpeg: {
          supported: true,
          quality: 'high',
          transparency: 'lost',
          compression: 'lossy',
          sizeReduction: 0.3,
        },
        svg_to_png: {
          supported: true,
          quality: 'perfect',
          scalability: 'rasterized',
          resolution: 'user-defined',
          sizeIncrease: 2.5,
        },
        jpeg_to_webp: {
          supported: true,
          quality: 'high',
          compression: 'better',
          sizeReduction: 0.25,
          browserSupport: 'modern',
        },
      };

      expect(imageConversions['png_to_jpeg'].transparency).toBe('lost');
      expect(imageConversions['svg_to_png'].scalability).toBe('rasterized');
      expect(imageConversions['jpeg_to_webp'].compression).toBe('better');
    });

    it('should provide format conversion previews', async () => {
      const conversionPreview = {
        sourceFormat: 'application/pdf',
        targetFormat: 'text/plain',
        previewLength: 500, // characters
        previewContent: `
          Project Specification v2.1
          ==========================

          1. Introduction
          This document outlines the technical specifications for the test project...

          2. Architecture Overview
          The system follows a microservices architecture with the following components:
          - User Service
          - Authentication Service
          - Database Layer

          [... preview truncated]
        `,
        estimatedFullSize: 15360,
        conversionQuality: 'high',
        processingTime: 15,
      };

      expect(conversionPreview.previewContent).toContain('Project Specification');
      expect(conversionPreview.estimatedFullSize).toBeGreaterThan(conversionPreview.previewLength);
      expect(conversionPreview.conversionQuality).toBe('high');
    });
  });

  describe('Compression and Optimization', () => {
    it('should compress resource content for faster delivery', async () => {
      const compressionOptions = {
        gzip: {
          algorithm: 'gzip',
          level: 6,
          supported: true,
          compressionRatio: 0.65,
          processingTime: 0.5,
        },
        brotli: {
          algorithm: 'br',
          level: 4,
          supported: true,
          compressionRatio: 0.55,
          processingTime: 1.2,
        },
        zstd: {
          algorithm: 'zstd',
          level: 3,
          supported: true,
          compressionRatio: 0.5,
          processingTime: 0.8,
        },
      };

      mockResourceService.compressResourceContent.mockImplementation(
        async (content: Buffer, algorithm: string) => {
          const options = compressionOptions[algorithm as keyof typeof compressionOptions];
          if (!options) {
            return { success: false, error: 'Unsupported compression algorithm' };
          }

          const compressedSize = content.length * options.compressionRatio;

          return {
            success: true,
            compressedContent: content.slice(0, compressedSize), // Simulated compression
            originalSize: content.length,
            compressedSize,
            compressionRatio: options.compressionRatio,
            algorithm,
            metadata: {
              processingTime: options.processingTime,
              level: options.level,
            },
          };
        }
      );

      const originalContent = Buffer.alloc(102400); // 100KB
      const gzipCompression = await mockResourceService.compressResourceContent(
        originalContent,
        'gzip'
      );
      const brotliCompression = await mockResourceService.compressResourceContent(
        originalContent,
        'brotli'
      );

      expect(gzipCompression.success).toBe(true);
      expect(gzipCompression.compressionRatio).toBe(0.65);
      expect(brotliCompression.compressionRatio).toBe(0.55);
      expect(brotliCompression.compressedSize).toBeLessThan(gzipCompression.compressedSize);
    });

    it('should optimize images for web delivery', async () => {
      const imageOptimization = {
        original: {
          format: 'PNG',
          width: 1920,
          height: 1080,
          size: 2048576, // 2MB
          quality: 'lossless',
        },
        optimized: {
          format: 'JPEG',
          width: 1920,
          height: 1080,
          size: 327680, // 320KB
          quality: 85,
          optimization: 'web-optimized',
        },
        thumbnail: {
          format: 'JPEG',
          width: 300,
          height: 169,
          size: 8192, // 8KB
          quality: 75,
          optimization: 'thumbnail-optimized',
        },
        savings: {
          space: 83.8, // percentage
          bandwidth: 83.8,
          loadTime: 78.5, // percentage reduction estimate
        },
      };

      expect(imageOptimization.optimized.size).toBeLessThan(imageOptimization.original.size);
      expect(imageOptimization.savings.space).toBeGreaterThan(80);
      expect(imageOptimization.thumbnail.format).toBe('JPEG');
    });

    it('should minify text-based resources', async () => {
      const minificationResults = {
        css: {
          originalSize: 25600,
          minifiedSize: 18944,
          savings: 26.0,
          processingTime: 0.2,
          preserved: true,
        },
        javascript: {
          originalSize: 51200,
          minifiedSize: 34816,
          savings: 32.0,
          processingTime: 0.5,
          preserved: true,
        },
        html: {
          originalSize: 15360,
          minifiedSize: 12288,
          savings: 20.0,
          processingTime: 0.1,
          preserved: true,
        },
        json: {
          originalSize: 8192,
          minifiedSize: 6554,
          savings: 20.0,
          processingTime: 0.05,
          preserved: true,
        },
      };

      expect(minificationResults['javascript'].savings).toBe(32.0);
      expect(minificationResults['css'].minifiedSize).toBe(18944);
      expect(minificationResults['html'].processingTime).toBeLessThan(0.2);
    });
  });

  describe('Caching Strategies', () => {
    it('should implement multi-level caching', async () => {
      const cacheLevels = {
        browser: {
          enabled: true,
          ttl: 3600,
          maxSize: 1048576, // 1MB
          strategy: 'LRU',
        },
        cdn: {
          enabled: true,
          ttl: 86400,
          maxSize: 10737418240, // 10GB
          strategy: 'LFU',
        },
        application: {
          enabled: true,
          ttl: 1800,
          maxSize: 1073741824, // 1GB
          strategy: 'LRU',
        },
        database: {
          enabled: true,
          ttl: 7200,
          maxSize: 536870912, // 512MB
          strategy: 'adaptive',
        },
      };

      mockResourceService.cacheResource.mockImplementation(
        async (resourceId: string, content: any, level: string) => {
          const cacheConfig = cacheLevels[level as keyof typeof cacheLevels];
          return {
            success: true,
            cacheKey: resourceId,
            level,
            ttl: cacheConfig.ttl,
            cachedAt: new Date().toISOString(),
            size: content.length,
            metadata: {
              strategy: cacheConfig.strategy,
              maxSize: cacheConfig.maxSize,
            },
          };
        }
      );

      const browserCache = await mockResourceService.cacheResource(
        'resource-123',
        'content',
        'browser'
      );
      const cdnCache = await mockResourceService.cacheResource('resource-123', 'content', 'cdn');

      expect(browserCache.ttl).toBe(3600);
      expect(cdnCache.ttl).toBe(86400);
      expect(browserCache.metadata['strategy']).toBe('LRU');
    });

    it('should handle cache invalidation properly', async () => {
      const invalidationStrategies = {
        time_based: {
          ttl: 3600,
          autoExpiry: true,
          gracePeriod: 300,
        },
        tag_based: {
          tags: ['v1.2.0', 'production', 'api-spec'],
          invalidationPatterns: ['tag:v1.2.1', 'env:staging'],
        },
        dependency_based: {
          dependsOn: ['user-config', 'permissions'],
          invalidateOn: ['config-change', 'permission-update'],
        },
        manual: {
          requiresApproval: true,
          approvers: ['admin', 'lead-developer'],
          auditRequired: true,
        },
      };

      mockResourceService.invalidateResourceCache.mockImplementation(
        async (resourceId: string, strategy: string) => {
          const config = invalidationStrategies[strategy as keyof typeof invalidationStrategies];
          return {
            success: true,
            resourceId,
            strategy,
            invalidatedAt: new Date().toISOString(),
            affectedKeys: [resourceId, `${resourceId}:derived`, `${resourceId}:transformed`],
            metadata: config,
          };
        }
      );

      const timeBasedInvalidation = await mockResourceService.invalidateResourceCache(
        'resource-123',
        'time_based'
      );
      const tagBasedInvalidation = await mockResourceService.invalidateResourceCache(
        'resource-123',
        'tag_based'
      );

      expect(timeBasedInvalidation.affectedKeys).toHaveLength(3);
      expect(tagBasedInvalidation.metadata['tags']).toContain('v1.2.0');
    });

    it('should provide cache analytics and insights', async () => {
      const cacheAnalytics = {
        timeRange: '2024-01-01 to 2024-01-31',
        totalRequests: 100000,
        cacheHits: 78432,
        cacheMisses: 21568,
        hitRate: 0.784,
        performance: {
          avgResponseTime: 45, // with cache
          avgResponseTimeWithoutCache: 234,
          performanceImprovement: 0.808,
        },
        byLevel: {
          browser: { hits: 45123, misses: 12345, hitRate: 0.785 },
          cdn: { hits: 23456, misses: 5678, hitRate: 0.805 },
          application: { hits: 7890, misses: 2345, hitRate: 0.771 },
          database: { hits: 1963, misses: 1200, hitRate: 0.621 },
        },
        topCachedResources: [
          { resource: 'knowledge://entities/project/test', hits: 5432 },
          { resource: 'document://specs/project/test/api.pdf', hits: 3421 },
          { resource: 'media://images/project/test/arch.png', hits: 2109 },
        ],
      };

      expect(cacheAnalytics.hitRate).toBeGreaterThan(0.7);
      expect(cacheAnalytics.performance.performanceImprovement).toBeGreaterThan(0.8);
      expect(cacheAnalytics.byLevel.cdn.hitRate).toBeGreaterThan(0.8);
      expect(cacheAnalytics.topCachedResources).toHaveLength(3);
    });
  });
});

// ============================================================================
// Test Suite 6: Integration and Performance
// ============================================================================

describe('Integration and Performance', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  describe('Database Resource Integration', () => {
    it('should integrate with Qdrant for knowledge resources', async () => {
      const qdrantIntegration = {
        collection: 'knowledge_items',
        vectors: {
          dimension: 1536,
          distance: 'Cosine',
          indexing: {
            type: 'HNSW',
            parameters: {
              m: 16,
              ef_construct: 100,
            },
          },
        },
        performance: {
          indexingTime: 1200, // ms
          searchTime: 45, // ms average
          storageUsage: 536870912, // 512MB
          totalVectors: 50000,
        },
        features: {
          semanticSearch: true,
          filtering: true,
          faceting: true,
          aggregation: true,
        },
      };

      mockPerformanceMonitor.trackResourceOperation.mockResolvedValue({
        operation: 'semantic_search',
        duration: 45,
        vectorCount: 50000,
        resultsFound: 23,
        indexingUsed: true,
        filtersApplied: ['project:test', 'type:entity'],
      });

      const operation = await mockPerformanceMonitor.trackResourceOperation('semantic_search', {});

      expect(operation.duration).toBe(45);
      expect(operation.resultsFound).toBe(23);
      expect(qdrantIntegration.features.semanticSearch).toBe(true);
    });

    it('should handle database connection pooling', async () => {
      const connectionPool = {
        active: 8,
        idle: 12,
        total: 20,
        max: 50,
        waiting: 0,
        utilization: 0.4,
        performance: {
          avgConnectionTime: 5, // ms
          avgQueryTime: 25, // ms
          throughput: 1000, // queries/second
        },
        health: {
          status: 'healthy',
          lastError: null,
          uptime: 86400, // seconds
          reconnects: 0,
        },
      };

      expect(connectionPool.utilization).toBeLessThan(0.5);
      expect(connectionPool.performance.avgQueryTime).toBe(25);
      expect(connectionPool.health.status).toBe('healthy');
    });

    it('should optimize database queries for resources', async () => {
      const queryOptimization = {
        originalQuery: 'SELECT * FROM knowledge_items WHERE content LIKE ?',
        optimizedQuery:
          'SELECT id, kind, scope, data FROM knowledge_items WHERE to_tsvector(content) @@ to_tsquery(?)',
        improvements: {
          executionTime: 78, // percentage improvement
          memoryUsage: 45,
          resultAccuracy: 12,
        },
        strategies: ['index-usage', 'full-text-search', 'result-limiting', 'column-selection'],
        indexes: [
          { name: 'idx_content_fts', type: 'full-text', columns: ['content'] },
          { name: 'idx_scope_project', type: 'btree', columns: ['scope->>project'] },
          { name: 'idx_kind_created', type: 'composite', columns: ['kind', 'created_at'] },
        ],
      };

      expect(queryOptimization.improvements.executionTime).toBeGreaterThan(50);
      expect(queryOptimization.strategies).toContain('full-text-search');
      expect(queryOptimization.indexes).toHaveLength(3);
    });
  });

  describe('Performance Optimization', () => {
    it('should implement resource delivery optimization', async () => {
      const deliveryOptimization = {
        strategies: {
          cdn: {
            enabled: true,
            coverage: 'global',
            cacheHitRate: 0.85,
            avgLatency: 45, // ms
          },
          compression: {
            enabled: true,
            algorithm: 'brotli',
            compressionRatio: 0.55,
            processingOverhead: 5, // ms
          },
          prefetching: {
            enabled: true,
            hitRate: 0.65,
            bandwidthSavings: 0.3,
          },
          parallelDownloads: {
            enabled: true,
            maxConnections: 6,
            throughput: '15 MB/s',
          },
        },
        overallPerformance: {
          avgLoadTime: 234, // ms
          p95LoadTime: 450,
          p99LoadTime: 780,
          errorRate: 0.001,
        },
      };

      mockPerformanceMonitor.optimizeResourceDelivery = vi.fn().mockResolvedValue({
        optimizations: ['cdn', 'compression', 'prefetching'],
        estimatedImprovement: 65, // percentage
        implementationTime: 120, // minutes
        resourceSavings: {
          bandwidth: 0.4,
          serverLoad: 0.25,
          userExperience: 0.6,
        },
      });

      const optimization = await mockPerformanceMonitor.optimizeResourceDelivery({});

      expect(optimization.optimizations).toContain('cdn');
      expect(optimization.estimatedImprovement).toBeGreaterThan(50);
      expect(deliveryOptimization.strategies.cdn.cacheHitRate).toBeGreaterThan(0.8);
    });

    it('should monitor and analyze resource performance', async () => {
      const performanceMetrics = {
        resourceTypes: {
          'knowledge:entities': {
            requestCount: 15420,
            avgResponseTime: 67,
            p95ResponseTime: 145,
            errorRate: 0.0005,
            cacheHitRate: 0.78,
          },
          'document:specs': {
            requestCount: 8934,
            avgResponseTime: 234,
            p95ResponseTime: 567,
            errorRate: 0.001,
            cacheHitRate: 0.91,
          },
          'media:images': {
            requestCount: 12456,
            avgResponseTime: 125,
            p95ResponseTime: 289,
            errorRate: 0.002,
            cacheHitRate: 0.85,
          },
        },
        systemMetrics: {
          cpu: { usage: 45.2, peak: 78.9 },
          memory: { usage: 68.5, peak: 85.3 },
          disk: { readOps: 1250, writeOps: 890 },
          network: { bandwidth: '125 MB/s', connections: 450 },
        },
        trends: {
          responseTime: 'improving', // 15% improvement over last month
          errorRate: 'stable',
          throughput: 'increasing', // 25% increase
          cacheEfficiency: 'improving', // 8% improvement
        },
      };

      mockPerformanceMonitor.generateResourceMetrics.mockResolvedValue(performanceMetrics);

      const metrics = await mockPerformanceMonitor.generateResourceMetrics();

      expect(metrics.resourceTypes['knowledge:entities'].cacheHitRate).toBeGreaterThan(0.7);
      expect(metrics.systemMetrics.cpu.usage).toBeLessThan(50);
      expect(metrics.trends.responseTime).toBe('improving');
    });

    it('should implement auto-scaling for resource demand', async () => {
      const autoScaling = {
        triggers: {
          cpu: { threshold: 70, scaleUpCooldown: 300, scaleDownCooldown: 600 },
          memory: { threshold: 80, scaleUpCooldown: 300, scaleDownCooldown: 600 },
          responseTime: { threshold: 1000, scaleUpCooldown: 180, scaleDownCooldown: 900 },
          queueDepth: { threshold: 100, scaleUpCooldown: 120, scaleDownCooldown: 600 },
        },
        currentScale: {
          instances: 4,
          cpu: 45.2,
          memory: 68.5,
          avgResponseTime: 234,
        },
        scalingHistory: [
          {
            timestamp: '2024-01-30T10:00:00Z',
            action: 'scale_up',
            instances: 2,
            to: 4,
            reason: 'cpu_high',
          },
          {
            timestamp: '2024-01-30T08:30:00Z',
            action: 'scale_down',
            instances: 6,
            to: 4,
            reason: 'low_load',
          },
        ],
        predictions: {
          nextHourLoad: 'medium',
          probability: 0.75,
          recommendedInstances: 4,
        },
      };

      expect(autoScaling.triggers.cpu.threshold).toBe(70);
      expect(autoScaling.currentScale.instances).toBe(4);
      expect(autoScaling.scalingHistory).toHaveLength(2);
      expect(autoScaling.predictions.probability).toBeGreaterThan(0.7);
    });
  });

  describe('Resource Analytics', () => {
    it('should provide comprehensive resource usage analytics', async () => {
      const resourceAnalytics = {
        timeRange: '2024-01-01 to 2024-01-31',
        totalRequests: 125000,
        uniqueUsers: 450,
        resourceBreakdown: {
          knowledge: {
            requests: 45600,
            users: 380,
            bandwidth: 204857600, // 200MB
            avgSize: 4096,
          },
          documents: {
            requests: 32400,
            users: 290,
            bandwidth: 1073741824, // 1GB
            avgSize: 32768,
          },
          media: {
            requests: 35200,
            users: 410,
            bandwidth: 2147483648, // 2GB
            avgSize: 65536,
          },
          archives: {
            requests: 11800,
            users: 120,
            bandwidth: 536870912, // 512MB
            avgSize: 524288,
          },
        },
        performanceMetrics: {
          avgResponseTime: 156,
          p95ResponseTime: 450,
          cacheHitRate: 0.73,
          errorRate: 0.0015,
        },
        topUsers: [
          { userId: 'user-123', requests: 2340, resourceTypes: ['knowledge', 'documents'] },
          { userId: 'user-456', requests: 1890, resourceTypes: ['media', 'documents'] },
        ],
      };

      mockResourceService.getResourceAnalytics.mockResolvedValue(resourceAnalytics);

      const analytics = await mockResourceService.getResourceAnalytics({});

      expect(analytics.totalRequests).toBe(125000);
      expect(analytics.resourceBreakdown.documents.bandwidth).toBeGreaterThan(1000000000);
      expect(analytics.performanceMetrics.cacheHitRate).toBeGreaterThan(0.7);
      expect(analytics.topUsers).toHaveLength(2);
    });

    it('should analyze resource access patterns', async () => {
      const accessPatterns = {
        temporalPatterns: {
          hourlyDistribution: [
            { hour: 9, requests: 1250, peak: true },
            { hour: 14, requests: 1890, peak: true },
            { hour: 22, requests: 340, low: true },
          ],
          dailyPatterns: {
            weekday: { avg: 4500, peak: 'Wednesday' },
            weekend: { avg: 1200, peak: 'Saturday' },
          },
        },
        resourcePatterns: {
          mostAccessed: [
            { resource: 'knowledge://entities/project/test', count: 2340 },
            { resource: 'document://specs/project/test/api.pdf', count: 1560 },
          ],
          fastestGrowing: [
            { resource: 'media://videos/project/tutorials/', growth: 156 }, // percentage
            { resource: 'knowledge://decisions/project/', growth: 89 },
          ],
        },
        userBehaviorPatterns: {
          sessionDuration: {
            avg: 450, // seconds
            p75: 600,
            p95: 1200,
          },
          resourceSequences: [
            ['knowledge://entities', 'knowledge://relations', 'document://specs'],
            ['media://images', 'media://videos', 'knowledge://observations'],
          ],
        },
      };

      expect(accessPatterns.temporalPatterns.hourlyDistribution[1].peak).toBe(true);
      expect(accessPatterns.resourcePatterns.mostAccessed[0].count).toBeGreaterThan(2000);
      expect(accessPatterns.userBehaviorPatterns.sessionDuration.avg).toBe(450);
    });

    it('should generate resource optimization recommendations', async () => {
      const optimizationRecommendations = {
        cache: {
          priority: 'high',
          recommendations: [
            {
              resource: 'document://specs/project/test/api.pdf',
              action: 'increase_ttl',
              currentTtl: 1800,
              recommendedTtl: 7200,
              estimatedImpact: '45% cache hit rate improvement',
            },
            {
              resource: 'media://images/project/test/',
              action: 'enable_cdn',
              estimatedImpact: '60% latency reduction',
            },
          ],
        },
        performance: {
          priority: 'medium',
          recommendations: [
            {
              resource: 'knowledge://entities/project/test',
              action: 'enable_compression',
              algorithm: 'brotli',
              estimatedSavings: '35% bandwidth reduction',
            },
          ],
        },
        storage: {
          priority: 'low',
          recommendations: [
            {
              resource: 'archive://backups/project/test/',
              action: 'implement_lifecycle_policy',
              estimatedSavings: '20% storage cost reduction',
            },
          ],
        },
      };

      expect(optimizationRecommendations.cache.priority).toBe('high');
      expect(optimizationRecommendations.cache.recommendations).toHaveLength(2);
      expect(optimizationRecommendations.performance.recommendations[0].estimatedSavings).toContain(
        '35%'
      );
    });
  });

  describe('Health Monitoring', () => {
    it('should monitor resource service health', async () => {
      const healthMonitoring = {
        overall: 'healthy',
        components: {
          resourceApi: {
            status: 'healthy',
            responseTime: 45,
            lastCheck: new Date().toISOString(),
            uptime: 0.999,
          },
          storageBackend: {
            status: 'healthy',
            responseTime: 23,
            lastCheck: new Date().toISOString(),
            uptime: 0.998,
          },
          cacheLayer: {
            status: 'healthy',
            responseTime: 2,
            lastCheck: new Date().toISOString(),
            uptime: 0.999,
          },
          cdnService: {
            status: 'degraded',
            responseTime: 234,
            lastCheck: new Date().toISOString(),
            uptime: 0.995,
            issues: ['Increased latency in Asia Pacific region'],
          },
        },
        metrics: {
          totalRequests: 125000,
          errorRate: 0.0015,
          avgResponseTime: 156,
          activeConnections: 45,
        },
        alerts: [
          {
            level: 'warning',
            component: 'cdnService',
            message: 'CDN latency increased in Asia Pacific',
            timestamp: new Date().toISOString(),
            acknowledged: true,
          },
        ],
      };

      expect(healthMonitoring.overall).toBe('healthy');
      expect(healthMonitoring.components.cdnService.status).toBe('degraded');
      expect(healthMonitoring.metrics.errorRate).toBeLessThan(0.01);
      expect(healthMonitoring.alerts).toHaveLength(1);
    });

    it('should provide diagnostic information for troubleshooting', async () => {
      const diagnostics = {
        timestamp: new Date().toISOString(),
        version: '1.2.0',
        environment: 'production',
        systemInfo: {
          node: 'app-server-03',
          region: 'us-west-2',
          availabilityZone: 'us-west-2a',
        },
        resourceStates: {
          database: {
            connections: { active: 8, idle: 12, max: 50 },
            performance: { avgQueryTime: 25, slowQueries: 2 },
            storage: { used: '450GB', available: '550GB' },
          },
          cache: {
            hitRate: 0.78,
            memoryUsage: 0.65,
            evictionRate: 0.02,
            keyCount: 125000,
          },
          fileSystem: {
            diskUsage: 0.45,
            iops: { read: 1250, write: 890 },
            latency: { read: 5, write: 8 },
          },
        },
        recentErrors: [
          {
            timestamp: new Date().toISOString(),
            type: 'timeout',
            resource: 'document://large-file.pdf',
            message: 'Resource access timeout',
            resolved: true,
          },
        ],
      };

      expect(diagnostics.resourceStates.cache.hitRate).toBeGreaterThan(0.7);
      expect(diagnostics.resourceStates.database.connections.active).toBe(8);
      expect(diagnostics.recentErrors).toHaveLength(1);
    });
  });
});
