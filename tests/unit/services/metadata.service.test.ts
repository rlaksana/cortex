/**
 * Comprehensive Unit Tests for Metadata Service
 *
 * Tests advanced metadata service functionality including:
 * - Automatic metadata generation and content-based extraction
 * - Temporal metadata management and provenance tracking
 * - Efficient metadata storage, retrieval, and indexing strategies
 * - Metadata enrichment services and external data integration
 * - Content analysis, tagging, and semantic metadata generation
 * - Privacy-compliant metadata, access control, and data anonymization
 * - Metadata caching, query optimization, and batch operations
 * - Type-specific metadata handling, cross-type consistency, and inheritance
 * - Relationship metadata and performance optimization
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// Mock the metadata service imports
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

// Mock Qdrant client for metadata operations
const mockQdrantClient = {
  knowledgeEntity: {
    create: vi.fn(),
    update: vi.fn(),
    findMany: vi.fn(),
    findUnique: vi.fn(),
    delete: vi.fn()
  },
  knowledgeRelation: {
    create: vi.fn(),
    update: vi.fn(),
    findMany: vi.fn(),
    findUnique: vi.fn(),
    delete: vi.fn()
  },
  knowledgeObservation: {
    create: vi.fn(),
    update: vi.fn(),
    findMany: vi.fn(),
    findUnique: vi.fn(),
    delete: vi.fn()
  },
  section: {
    create: vi.fn(),
    update: vi.fn(),
    findMany: vi.fn(),
    findUnique: vi.fn(),
    delete: vi.fn()
  },
  adrDecision: {
    create: vi.fn(),
    update: vi.fn(),
    findMany: vi.fn(),
    findUnique: vi.fn(),
    delete: vi.fn()
  },
  issueLog: {
    create: vi.fn(),
    update: vi.fn(),
    findMany: vi.fn(),
    findUnique: vi.fn(),
    delete: vi.fn()
  },
  todoLog: {
    create: vi.fn(),
    update: vi.fn(),
    findMany: vi.fn(),
    findUnique: vi.fn(),
    delete: vi.fn()
  },
  runbook: {
    create: vi.fn(),
    update: vi.fn(),
    findMany: vi.fn(),
    findUnique: vi.fn(),
    delete: vi.fn()
  },
  changeLog: {
    create: vi.fn(),
    update: vi.fn(),
    findMany: vi.fn(),
    findUnique: vi.fn(),
    delete: vi.fn()
  },
  releaseNote: {
    create: vi.fn(),
    update: vi.fn(),
    findMany: vi.fn(),
    findUnique: vi.fn(),
    delete: vi.fn()
  },
  ddlHistory: {
    create: vi.fn(),
    update: vi.fn(),
    findMany: vi.fn(),
    findUnique: vi.fn(),
    delete: vi.fn()
  },
  prContext: {
    create: vi.fn(),
    update: vi.fn(),
    findMany: vi.fn(),
    findUnique: vi.fn(),
    delete: vi.fn()
  },
  incidentLog: {
    create: vi.fn(),
    update: vi.fn(),
    findMany: vi.fn(),
    findUnique: vi.fn(),
    delete: vi.fn()
  },
  releaseLog: {
    create: vi.fn(),
    update: vi.fn(),
    findMany: vi.fn(),
    findUnique: vi.fn(),
    delete: vi.fn()
  },
  riskLog: {
    create: vi.fn(),
    update: vi.fn(),
    findMany: vi.fn(),
    findUnique: vi.fn(),
    delete: vi.fn()
  },
  assumptionLog: {
    create: vi.fn(),
    update: vi.fn(),
    findMany: vi.fn(),
    findUnique: vi.fn(),
    delete: vi.fn()
  }
};

// Mock embedding service for content analysis
vi.mock('../../../src/services/embeddings/embedding-service', () => ({
  EmbeddingService: vi.fn().mockImplementation(() => ({
    generateEmbedding: vi.fn().mockResolvedValue([0.1, 0.2, 0.3]),
    analyzeContent: vi.fn().mockResolvedValue({
      keywords: ['authentication', 'security', 'user'],
      sentiment: 'neutral',
      complexity: 'medium',
      entities: ['User', 'System', 'Database']
    })
  }))
}));

// Mock cache factory for metadata caching
vi.mock('../../../src/utils/lru-cache', () => ({
  CacheFactory: {
    createMetadataCache: () => ({
      get: vi.fn(),
      set: vi.fn(),
      clear: vi.fn(),
      delete: vi.fn(),
      getStats: vi.fn(() => ({
        itemCount: 0,
        memoryUsageBytes: 0,
        maxMemoryBytes: 52428800,
        hitRate: 0,
        totalHits: 0,
        totalMisses: 0,
        expiredItems: 0,
        evictedItems: 0
      }))
    })
  }
}));

// Import the service after mocking
import { MetadataService } from '../../../src/services/metadata/metadata-service';
import type { KnowledgeItem, SearchResult } from '../../../src/types/core-interfaces';

describe('MetadataService - Comprehensive Metadata Management', () => {
  let metadataService: MetadataService;

  beforeEach(() => {
    metadataService = new MetadataService();
    vi.clearAllMocks();

    // Setup default mock responses
    Object.values(mockQdrantClient).forEach((model: any) => {
      if (model.create) model.create.mockResolvedValue({ id: 'test-id', created_at: new Date().toISOString() });
      if (model.findMany) model.findMany.mockResolvedValue([]);
      if (model.findUnique) model.findUnique.mockResolvedValue(null);
      if (model.update) model.update.mockResolvedValue({ id: 'test-id', updated_at: new Date().toISOString() });
      if (model.delete) model.delete.mockResolvedValue(true);
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // 1. Metadata Generation and Extraction Tests
  describe('Metadata Generation and Extraction', () => {
    it('should generate automatic metadata from content', async () => {
      const content = 'User authentication system requires secure password hashing';
      const metadata = await metadataService.generateAutomaticMetadata(content);

      expect(metadata).toHaveProperty('content_length');
      expect(metadata).toHaveProperty('keywords');
      expect(metadata).toHaveProperty('content_hash');
      expect(metadata).toHaveProperty('generated_at');
      expect(metadata.keywords).toContain('authentication');
      expect(metadata.keywords).toContain('secure');
    });

    it('should extract content-based metadata efficiently', async () => {
      const item: KnowledgeItem = {
        kind: 'entity',
        content: 'Complex system architecture with microservices',
        data: { title: 'System Design', component: 'backend' },
        scope: { project: 'myapp' }
      };

      const extractedMetadata = await metadataService.extractContentMetadata(item);

      expect(extractedMetadata).toHaveProperty('word_count');
      expect(extractedMetadata).toHaveProperty('readability_score');
      expect(extractedMetadata).toHaveProperty('technical_terms');
      expect(extractedMetadata.technical_terms).toContain('microservices');
    });

    it('should manage temporal metadata correctly', async () => {
      const item: KnowledgeItem = {
        kind: 'decision',
        content: 'Architecture decision for database selection',
        data: { title: 'Database Choice', component: 'data-layer' },
        scope: { project: 'myapp' },
        created_at: '2024-01-15T10:00:00Z'
      };

      const temporalMetadata = await metadataService.generateTemporalMetadata(item);

      expect(temporalMetadata).toHaveProperty('created_timestamp');
      expect(temporalMetadata).toHaveProperty('time_of_day');
      expect(temporalMetadata).toHaveProperty('day_of_week');
      expect(temporalMetadata).toHaveProperty('age_in_days');
      expect(temporalMetadata.age_in_days).toBeGreaterThan(0);
    });

    it('should track provenance metadata accurately', async () => {
      const provenance = {
        source: 'user-input',
        author: 'john.doe',
        tool: 'cli-interface',
        session_id: 'session-123',
        correlation_id: 'corr-456'
      };

      const provenanceMetadata = await metadataService.generateProvenanceMetadata(provenance);

      expect(provenanceMetadata).toHaveProperty('source');
      expect(provenanceMetadata).toHaveProperty('author');
      expect(provenanceMetadata).toHaveProperty('tool');
      expect(provenanceMetadata).toHaveProperty('creation_chain');
      expect(provenanceMetadata.creation_chain).toContain('cli-interface');
    });

    it('should handle content analysis for different formats', async () => {
      const formats = [
        { type: 'markdown', content: '# Title\n\nSome **bold** text.' },
        { type: 'json', content: '{"key": "value", "nested": {"data": true}}' },
        { type: 'plain', content: 'Simple plain text content.' }
      ];

      for (const format of formats) {
        const analysis = await metadataService.analyzeContentFormat(format.content, format.type);

        expect(analysis).toHaveProperty('format_type');
        expect(analysis).toHaveProperty('structure_metadata');
        expect(analysis).toHaveProperty('format_specific_fields');
        expect(analysis.format_type).toBe(format.type);
      }
    });
  });

  // 2. Metadata Storage and Retrieval Tests
  describe('Metadata Storage and Retrieval', () => {
    it('should store metadata efficiently', async () => {
      const metadata = {
        content_hash: 'abc123',
        keywords: ['test', 'metadata'],
        content_length: 150,
        extracted_at: new Date().toISOString()
      };

      const itemId = 'item-123';
      const result = await metadataService.storeMetadata(itemId, metadata);

      expect(result).toHaveProperty('success');
      expect(result).toHaveProperty('metadata_id');
      expect(result.success).toBe(true);
      expect(mockQdrantClient.knowledgeObservation.create).toHaveBeenCalled();
    });

    it('should retrieve metadata with filtering', async () => {
      const mockMetadataResults = [
        {
          id: 'meta-1',
          kind: 'observation',
          data: {
            content_hash: 'hash1',
            keywords: ['authentication', 'security'],
            content_type: 'decision'
          },
          tags: { project: 'security' },
          created_at: new Date('2024-01-01')
        }
      ];

      mockQdrantClient.knowledgeObservation.findMany.mockResolvedValue(mockMetadataResults);

      const filters = {
        content_type: 'decision',
        keywords: ['security'],
        project: 'security'
      };

      const results = await metadataService.retrieveMetadata(filters);

      expect(results).toHaveLength(1);
      expect(results[0].data.keywords).toContain('security');
      expect(mockQdrantClient.knowledgeObservation.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            AND: expect.arrayContaining([
              expect.objectContaining({ data: expect.objectContaining({ content_type: 'decision' }) })
            ])
          })
        })
      );
    });

    it('should implement metadata indexing strategies', async () => {
      const metadataItems = [
        { id: '1', keywords: ['api', 'rest'], content_length: 200 },
        { id: '2', keywords: ['database', 'sql'], content_length: 150 },
        { id: '3', keywords: ['api', 'graphql'], content_length: 300 }
      ];

      const indexResult = await metadataService.buildMetadataIndex(metadataItems);

      expect(indexResult).toHaveProperty('keyword_index');
      expect(indexResult).toHaveProperty('length_index');
      expect(indexResult).toHaveProperty('composite_index');
      expect(indexResult.keyword_index['api']).toContain('1');
      expect(indexResult.keyword_index['api']).toContain('3');
    });

    it('should handle metadata versioning correctly', async () => {
      const itemId = 'versioned-item';
      const versions = [
        { version: 1, keywords: ['initial'], content_hash: 'hash1' },
        { version: 2, keywords: ['updated', 'enhanced'], content_hash: 'hash2' }
      ];

      for (const version of versions) {
        await metadataService.storeMetadataVersion(itemId, version);
      }

      const versionHistory = await metadataService.getMetadataVersionHistory(itemId);

      expect(versionHistory).toHaveLength(2);
      expect(versionHistory[0].version).toBe(1);
      expect(versionHistory[1].version).toBe(2);
    });

    it('should optimize metadata queries', async () => {
      const complexQuery = {
        keywords: ['security', 'authentication'],
        content_length_range: { min: 100, max: 1000 },
        date_range: { start: '2024-01-01', end: '2024-12-31' },
        project: 'security-app'
      };

      const optimizedQuery = await metadataService.optimizeMetadataQuery(complexQuery);

      expect(optimizedQuery).toHaveProperty('optimized_filters');
      expect(optimizedQuery).toHaveProperty('execution_plan');
      expect(optimizedQuery).toHaveProperty('estimated_results');
      expect(optimizedQuery.optimized_filters).toBeDefined();
    });
  });

  // 3. Enrichment and Enhancement Tests
  describe('Enrichment and Enhancement', () => {
    it('should enrich metadata with external data', async () => {
      const baseMetadata = {
        content: 'User login with OAuth 2.0',
        keywords: ['oauth', 'login']
      };

      const enrichedMetadata = await metadataService.enrichWithExternalData(baseMetadata);

      expect(enrichedMetadata).toHaveProperty('external_references');
      expect(enrichedMetadata).toHaveProperty('related_standards');
      expect(enrichedMetadata).toHaveProperty('best_practices');
      expect(enrichedMetadata.related_standards).toContain('RFC 6749');
    });

    it('should integrate with external APIs for enhancement', async () => {
      const content = 'Payment processing with PCI DSS compliance';

      const enhancement = await metadataService.enhanceWithExternalAPIs(content);

      expect(enhancement).toHaveProperty('compliance_standards');
      expect(enhancement).toHaveProperty('security_recommendations');
      expect(enhancement).toHaveProperty('industry_references');
      expect(enhancement.compliance_standards).toContain('PCI-DSS');
    });

    it('should perform semantic metadata generation', async () => {
      const content = 'Implementing microservices architecture with Docker containers';

      const semanticMetadata = await metadataService.generateSemanticMetadata(content);

      expect(semanticMetadata).toHaveProperty('semantic_tags');
      expect(semanticMetadata).toHaveProperty('domain_classification');
      expect(semanticMetadata).toHaveProperty('concept_relations');
      expect(semanticMetadata.semantic_tags).toContain('microservices');
      expect(semanticMetadata.semantic_tags).toContain('docker');
    });

    it('should analyze and tag content automatically', async () => {
      const content = 'Critical security vulnerability in authentication module';

      const taggingResult = await metadataService.analyzeAndTagContent(content);

      expect(taggingResult).toHaveProperty('auto_tags');
      expect(taggingResult).toHaveProperty('confidence_scores');
      expect(taggingResult).toHaveProperty('suggested_categories');
      expect(taggingResult.auto_tags).toContain('security');
      expect(taggingResult.auto_tags).toContain('vulnerability');
    });

    it('should suggest related content and connections', async () => {
      const metadata = {
        keywords: ['authentication', 'jwt', 'tokens'],
        domain: 'security',
        component: 'auth-service'
      };

      const suggestions = await metadataService.suggestRelatedContent(metadata);

      expect(suggestions).toHaveProperty('related_items');
      expect(suggestions).toHaveProperty('missing_connections');
      expect(suggestions).toHaveProperty('knowledge_gaps');
      expect(suggestions.related_items.length).toBeGreaterThan(0);
    });
  });

  // 4. Privacy and Security Tests
  describe('Privacy and Security', () => {
    it('should detect sensitive data in metadata', async () => {
      const sensitiveContent = 'User SSN: 123-45-6789 and Credit Card: 4111-1111-1111-1111';

      const detection = await metadataService.detectSensitiveData(sensitiveContent);

      expect(detection).toHaveProperty('has_sensitive_data');
      expect(detection).toHaveProperty('detected_types');
      expect(detection).toHaveProperty('confidence_level');
      expect(detection.has_sensitive_data).toBe(true);
      expect(detection.detected_types).toContain('ssn');
      expect(detection.detected_types).toContain('credit_card');
    });

    it('should generate privacy-compliant metadata', async () => {
      const personalData = {
        name: 'John Doe',
        email: 'john.doe@company.com',
        phone: '+1-555-0123',
        address: '123 Main St, City, State'
      };

      const privacyCompliant = await metadataService.generatePrivacyCompliantMetadata(personalData);

      expect(privacyCompliant).toHaveProperty('original_data_hash');
      expect(privacyCompliant).toHaveProperty('pseudonymized_data');
      expect(privacyCompliant).toHaveProperty('retention_policy');
      expect(privacyCompliant).toHaveProperty('processing_lawful_basis');
      expect(privacyCompliant.pseudonymized_data.name).not.toBe('John Doe');
    });

    it('should implement access control for metadata', async () => {
      const accessContext = {
        user_role: 'developer',
        project_access: ['myapp'],
        team_membership: ['backend'],
        clearance_level: 'confidential'
      };

      const metadata = {
        sensitivity_level: 'confidential',
        project: 'myapp',
        team: 'backend'
      };

      const accessResult = await metadataService.checkMetadataAccess(metadata, accessContext);

      expect(accessResult).toHaveProperty('access_granted');
      expect(accessResult).toHaveProperty('access_level');
      expect(accessResult).toHaveProperty('restrictions');
      expect(accessResult.access_granted).toBe(true);
    });

    it('should anonymize data while preserving structure', async () => {
      const structuredData = {
        user: {
          name: 'Alice Johnson',
          email: 'alice@company.com',
          department: 'Engineering'
        },
        session: {
          ip_address: '192.168.1.100',
          duration: 3600,
          actions: ['login', 'view_dashboard']
        }
      };

      const anonymized = await metadataService.anonymizeStructuredData(structuredData);

      expect(anonymized.user.name).not.toBe('Alice Johnson');
      expect(anonymized.user.email).not.toBe('alice@company.com');
      expect(anonymized.session.duration).toBe(3600); // Preserve non-sensitive data
      expect(anonymized.session.actions).toEqual(['login', 'view_dashboard']);
    });

    it('should handle GDPR and compliance requirements', async () => {
      const gdprRequest = {
        type: 'right_to_be_forgotten',
        user_identifier: 'user-123',
        data_categories: ['personal', 'behavioral', 'transactional']
      };

      const complianceResult = await metadataService.handleGDPRRequest(gdprRequest);

      expect(complianceResult).toHaveProperty('request_processed');
      expect(complianceResult).toHaveProperty('data_affected');
      expect(complianceResult).toHaveProperty('retention_exceptions');
      expect(complianceResult).toHaveProperty('compliance_report');
      expect(complianceResult.request_processed).toBe(true);
    });
  });

  // 5. Performance and Optimization Tests
  describe('Performance and Optimization', () => {
    it('should implement metadata caching strategies', async () => {
      const metadataKey = 'metadata-key-123';
      const metadata = { keywords: ['test'], content_length: 500 };

      // Set up cache mock
      const mockCache = {
        get: vi.fn().mockResolvedValue(null),
        set: vi.fn().mockResolvedValue(true),
        delete: vi.fn().mockResolvedValue(true),
        clear: vi.fn().mockResolvedValue(true),
        getStats: vi.fn().mockResolvedValue({
          hitRate: 85,
          totalHits: 100,
          totalMisses: 15,
          memoryUsageBytes: 1024000
        })
      };

      (metadataService as any).metadataCache = mockCache;

      // Test cache miss and set
      const result = await metadataService.getCachedMetadata(metadataKey);
      expect(mockCache.get).toHaveBeenCalledWith(metadataKey);
      expect(mockCache.set).toHaveBeenCalled();
    });

    it('should optimize query performance', async () => {
      const complexQuery = {
        keywords: ['performance', 'optimization'],
        filters: {
          date_range: { start: '2024-01-01', end: '2024-12-31' },
          content_types: ['decision', 'observation']
        },
        aggregations: ['keyword_frequency', 'temporal_distribution']
      };

      const startTime = Date.now();
      const optimizedResult = await metadataService.performOptimizedQuery(complexQuery);
      const duration = Date.now() - startTime;

      expect(optimizedResult).toHaveProperty('results');
      expect(optimizedResult).toHaveProperty('execution_metadata');
      expect(optimizedResult).toHaveProperty('performance_metrics');
      expect(duration).toBeLessThan(1000); // Should complete quickly
      expect(optimizedResult.execution_metadata.query_plan_used).toBe(true);
    });

    it('should handle batch metadata operations efficiently', async () => {
      const batchItems = Array.from({ length: 100 }, (_, i) => ({
        id: `item-${i}`,
        content: `Content for item ${i}`,
        keywords: [`keyword-${i % 10}`]
      }));

      const batchResult = await metadataService.processBatchMetadata(batchItems);

      expect(batchResult).toHaveProperty('processed_count');
      expect(batchResult).toHaveProperty('failed_count');
      expect(batchResult).toHaveProperty('processing_time_ms');
      expect(batchResult).toHaveProperty('batch_id');
      expect(batchResult.processed_count).toBe(100);
      expect(batchResult.processing_time_ms).toBeLessThan(5000);
    });

    it('should implement memory-efficient operations', async () => {
      const largeDataset = Array.from({ length: 10000 }, (_, i) => ({
        id: `large-item-${i}`,
        metadata: {
          keywords: [`kw-${i % 100}`],
          content_length: i * 10,
          created_at: new Date(Date.now() - i * 1000).toISOString()
        }
      }));

      const memoryStatsBefore = process.memoryUsage();
      const result = await metadataService.processLargeDataset(largeDataset);
      const memoryStatsAfter = process.memoryUsage();

      expect(result).toHaveProperty('processed_items');
      expect(result).toHaveProperty('memory_efficiency_score');
      expect(result.memory_efficiency_score).toBeGreaterThan(0.8);

      const memoryIncrease = memoryStatsAfter.heapUsed - memoryStatsBefore.heapUsed;
      expect(memoryIncrease).toBeLessThan(100 * 1024 * 1024); // Less than 100MB increase
    });

    it('should provide performance monitoring and metrics', async () => {
      const metrics = await metadataService.getPerformanceMetrics();

      expect(metrics).toHaveProperty('cache_hit_rate');
      expect(metrics).toHaveProperty('average_query_time_ms');
      expect(metrics).toHaveProperty('concurrent_operations');
      expect(metrics).toHaveProperty('memory_usage_mb');
      expect(metrics).toHaveProperty('operations_per_second');
      expect(metrics.cache_hit_rate).toBeGreaterThanOrEqual(0);
      expect(metrics.cache_hit_rate).toBeLessThanOrEqual(1);
    });
  });

  // 6. Integration with Knowledge Types Tests
  describe('Integration with Knowledge Types', () => {
    it('should handle type-specific metadata for all knowledge types', async () => {
      const knowledgeTypes = [
        'entity', 'relation', 'observation', 'section', 'runbook', 'change',
        'issue', 'decision', 'todo', 'release_note', 'ddl', 'pr_context',
        'incident', 'release', 'risk', 'assumption'
      ];

      for (const kind of knowledgeTypes) {
        const item: KnowledgeItem = {
          kind,
          content: `Test content for ${kind}`,
          data: { title: `${kind} Test Item` },
          scope: { project: 'test-project' }
        };

        const typeSpecificMetadata = await metadataService.generateTypeSpecificMetadata(item, kind);

        expect(typeSpecificMetadata).toHaveProperty('kind_specific_fields');
        expect(typeSpecificMetadata).toHaveProperty('type_validation_rules');
        expect(typeSpecificMetadata).toHaveProperty('recommended_actions');
        expect(typeSpecificMetadata.kind_specific_fields).toBeDefined();
      }
    });

    it('should maintain cross-type metadata consistency', async () => {
      const relatedItems = [
        { kind: 'entity', id: 'entity-1', data: { name: 'User Service' } },
        { kind: 'decision', id: 'decision-1', data: { component: 'User Service' } },
        { kind: 'observation', id: 'obs-1', data: { subject: 'User Service' } }
      ];

      const consistencyCheck = await metadataService.checkCrossTypeConsistency(relatedItems);

      expect(consistencyCheck).toHaveProperty('is_consistent');
      expect(consistencyCheck).toHaveProperty('inconsistencies');
      expect(consistencyCheck).toHaveProperty('suggested_fixes');
      expect(consistencyCheck).toHaveProperty('consistency_score');
      expect(consistencyCheck.consistency_score).toBeGreaterThan(0.5);
    });

    it('should implement metadata inheritance patterns', async () => {
      const parentMetadata = {
        project: 'myapp',
        domain: 'security',
        tags: ['authentication', 'backend'],
        classification: 'confidential'
      };

      const childItem = {
        kind: 'observation',
        content: 'Security observation about authentication',
        parent_id: 'parent-123'
      };

      const inheritedMetadata = await metadataService.applyMetadataInheritance(childItem, parentMetadata);

      expect(inheritedMetadata).toHaveProperty('inherited_fields');
      expect(inheritedMetadata).toHaveProperty('overridden_fields');
      expect(inheritedMetadata).toHaveProperty('combined_metadata');
      expect(inheritedMetadata.inherited_fields.project).toBe('myapp');
      expect(inheritedMetadata.inherited_fields.domain).toBe('security');
    });

    it('should manage relationship metadata effectively', async () => {
      const relationships = [
        {
          from_id: 'entity-1',
          to_id: 'decision-1',
          relation_type: 'influences',
          metadata: { strength: 0.8, context: 'architecture decision' }
        },
        {
          from_id: 'decision-1',
          to_id: 'observation-1',
          relation_type: 'results_in',
          metadata: { outcome: 'implementation', timeline: '2-weeks' }
        }
      ];

      const relationshipAnalysis = await metadataService.analyzeRelationshipMetadata(relationships);

      expect(relationshipAnalysis).toHaveProperty('relationship_graph');
      expect(relationshipAnalysis).toHaveProperty('influence_paths');
      expect(relationshipAnalysis).toHaveProperty('critical_relationships');
      expect(relationshipAnalysis).toHaveProperty('relationship_strengths');
      expect(relationshipAnalysis.critical_relationships.length).toBeGreaterThan(0);
    });

    it('should handle complex metadata transformations', async () => {
      const sourceMetadata = {
        legacy_format: {
          author_name: 'John Doe',
          creation_date: '2024-01-15',
          category: 'technical',
          tags: ['api', 'rest', 'backend']
        },
        custom_fields: {
          priority: 'high',
          reviewed: true,
          approval_status: 'approved'
        }
      };

      const transformation = await metadataService.transformMetadata(sourceMetadata, 'standard_v2');

      expect(transformation).toHaveProperty('standardized_metadata');
      expect(transformation).toHaveProperty('transformation_log');
      expect(transformation).toHaveProperty('field_mappings');
      expect(transformation).toHaveProperty('data_loss_report');
      expect(transformation.standardized_metadata.author).toBe('John Doe');
      expect(transformation.standardized_metadata.tags).toEqual(['api', 'rest', 'backend']);
    });
  });

  // Error Handling and Edge Cases
  describe('Error Handling and Edge Cases', () => {
    it('should handle malformed metadata gracefully', async () => {
      const malformedData = {
        content: null,
        keywords: 'not-an-array',
        metadata: undefined,
        nested: {
          invalid_field: Buffer.from('binary-data')
        }
      };

      const result = await metadataService.processMalformedMetadata(malformedData);

      expect(result).toHaveProperty('processing_successful');
      expect(result).toHaveProperty('error_details');
      expect(result).toHaveProperty('cleaned_data');
      expect(result).toHaveProperty('warnings');
      expect(result.processing_successful).toBe(false);
      expect(result.error_details.length).toBeGreaterThan(0);
    });

    it('should handle concurrent metadata operations', async () => {
      const concurrentOperations = Array.from({ length: 10 }, (_, i) =>
        metadataService.generateAutomaticMetadata(`Concurrent test content ${i}`)
      );

      const results = await Promise.all(concurrentOperations);

      expect(results).toHaveLength(10);
      results.forEach((result, index) => {
        expect(result).toHaveProperty('content_hash');
        expect(result).toHaveProperty('keywords');
        expect(result.content_hash).toBeDefined();
      });
    });

    it('should handle resource exhaustion scenarios', async () => {
      // Simulate memory pressure
      const originalMemoryUsage = process.memoryUsage();

      // Create many large metadata objects
      const largeMetadataRequests = Array.from({ length: 1000 }, (_, i) =>
        metadataService.generateAutomaticMetadata('x'.repeat(10000) + ` content ${i}`)
      );

      const results = await Promise.allSettled(largeMetadataRequests);

      const successful = results.filter(r => r.status === 'fulfilled').length;
      const failed = results.filter(r => r.status === 'rejected').length;

      expect(successful + failed).toBe(1000);
      expect(successful).toBeGreaterThan(900); // Most should succeed

      // Memory usage should be reasonable
      const finalMemoryUsage = process.memoryUsage();
      const memoryIncrease = finalMemoryUsage.heapUsed - originalMemoryUsage.heapUsed;
      expect(memoryIncrease).toBeLessThan(500 * 1024 * 1024); // Less than 500MB
    });

    it('should validate metadata integrity', async () => {
      const metadata = {
        content_hash: 'invalid-hash',
        content_length: -100,
        created_at: 'invalid-date',
        keywords: ['valid', 'keyword'],
        metadata: {
          nested_field: { deep: { value: 'test' } }
        }
      };

      const validation = await metadataService.validateMetadataIntegrity(metadata);

      expect(validation).toHaveProperty('is_valid');
      expect(validation).toHaveProperty('validation_errors');
      expect(validation).toHaveProperty('warnings');
      expect(validation).toHaveProperty('integrity_score');
      expect(validation.is_valid).toBe(false);
      expect(validation.validation_errors.length).toBeGreaterThan(0);
    });
  });

  // Configuration and Service Management
  describe('Configuration and Service Management', () => {
    it('should update metadata service configuration', () => {
      const newConfig = {
        cache_size_mb: 100,
        enable_external_enrichment: true,
        sensitivity_detection_threshold: 0.8,
        max_batch_size: 500,
        retention_policy_days: 365
      };

      metadataService.updateConfiguration(newConfig);

      const config = metadataService.getConfiguration();
      expect(config.cache_size_mb).toBe(100);
      expect(config.enable_external_enrichment).toBe(true);
      expect(config.sensitivity_detection_threshold).toBe(0.8);
    });

    it('should initialize metadata service with custom settings', async () => {
      const customSettings = {
        cache_config: { max_size: 200, ttl_seconds: 3600 },
        enrichment_apis: { enabled: ['nlp', 'semantic', 'external'] },
        privacy_settings: { auto_anonymize: true, retention_days: 90 }
      };

      const customService = new MetadataService(customSettings);
      const status = await customService.getServiceStatus();

      expect(status).toHaveProperty('initialized');
      expect(status).toHaveProperty('cache_status');
      expect(status).toHaveProperty('enrichment_status');
      expect(status).toHaveProperty('privacy_status');
      expect(status.initialized).toBe(true);
    });

    it('should provide comprehensive service health check', async () => {
      const healthCheck = await metadataService.performHealthCheck();

      expect(healthCheck).toHaveProperty('overall_status');
      expect(healthCheck).toHaveProperty('components');
      expect(healthCheck).toHaveProperty('performance_metrics');
      expect(healthCheck).toHaveProperty('recommendations');
      expect(healthCheck.components.cache).toHaveProperty('status');
      expect(healthCheck.components.database).toHaveProperty('status');
      expect(healthCheck.components.enrichment).toHaveProperty('status');
    });
  });
});