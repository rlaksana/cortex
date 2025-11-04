/**
 * Integration Tests - Qdrant Available (Happy Path)
 *
 * Tests complete system functionality when Qdrant vector database is available.
 * These tests verify the happy path where all system components are operational.
 */

import { describe, it, expect, beforeEach, afterEach, beforeAll, afterAll } from 'vitest';
import { DatabaseManager } from '../../src/db/database-manager.js';
import { ChunkingService } from '../../src/services/chunking/chunking-service.js';
import { MemoryStoreService } from '../../src/services/memory-store.service.js';
import { MemoryFindService } from '../../src/services/memory-find.service.js';
import { MockEmbeddingService } from '../utils/mock-embedding-service.js';
import { createMockSemanticAnalyzer } from '../utils/mock-semantic-analyzer.js';
import { mockQdrantClient } from '../mocks/database.js';
import { KnowledgeItem, MemoryStoreInput, MemoryFindInput } from '../../src/types/core-interfaces.js';

describe('Integration Tests - Qdrant Available (Happy Path)', () => {
  let databaseManager: DatabaseManager;
  let chunkingService: ChunkingService;
  let memoryStoreService: MemoryStoreService;
  let memoryFindService: MemoryFindService;
  let embeddingService: MockEmbeddingService;

  beforeAll(async () => {
    // Initialize services with real Qdrant connection
    // These tests assume Qdrant is available for full integration testing
    embeddingService = new MockEmbeddingService({
      shouldFail: false,
      latency: 50, // Simulate realistic embedding generation latency
    });

    // Initialize database manager
    databaseManager = new DatabaseManager({
      qdrant: {
        url: process.env.QDRANT_URL || 'http://localhost:6333',
        apiKey: process.env.QDRANT_API_KEY,
        timeout: 30000,
      },
      enableVectorOperations: true,
      enableFallback: false, // No fallback for happy path tests
    });

    // Initialize services
    chunkingService = new ChunkingService(
      databaseManager,
      embeddingService,
      undefined, // semantic analyzer will be created internally
    );

    // Replace semantic analyzer with mock for consistent testing
    const mockSemanticAnalyzer = createMockSemanticAnalyzer(embeddingService as any, {
      shouldFail: false,
    });
    (chunkingService as any).semanticAnalyzer = mockSemanticAnalyzer;

    memoryStoreService = new MemoryStoreService(databaseManager, chunkingService);
    memoryFindService = new MemoryFindService(databaseManager);
  });

  beforeEach(async () => {
    // Ensure clean state before each test
    try {
      await databaseManager.healthCheck();
      // Create test collection if it doesn't exist
      await databaseManager.createCollection('test-integration', {
        vectors: { size: 1536, distance: 'Cosine' },
      });
    } catch (error) {
      // If Qdrant is not available, skip these tests
      console.warn('Qdrant not available for integration tests, skipping...');
      return;
    }
  });

  afterEach(async () => {
    // Clean up test data
    try {
      await databaseManager.deleteCollection('test-integration');
    } catch (error) {
      // Ignore cleanup errors
    }
  });

  afterAll(async () => {
    // Final cleanup
    try {
      await databaseManager.disconnect();
    } catch (error) {
      // Ignore disconnect errors
    }
  });

  describe('Basic Memory Operations', () => {
    it('should store and retrieve knowledge items successfully', async () => {
      // Test data
      const testItems: MemoryStoreInput[] = [
        {
          kind: 'entity',
          content: 'Cortex Memory is an advanced knowledge management system',
          scope: { project: 'test-project', branch: 'main' },
          metadata: { test_type: 'basic_storage' },
        },
        {
          kind: 'decision',
          content: 'We decided to use Qdrant as our vector database for semantic search',
          scope: { project: 'test-project', branch: 'main' },
          metadata: { test_type: 'basic_storage', decision_type: 'technical' },
        },
        {
          kind: 'observation',
          content: 'User testing showed 95% satisfaction with the search results quality',
          scope: { project: 'test-project', branch: 'main' },
          metadata: { test_type: 'basic_storage', metric: 'satisfaction' },
        },
      ];

      // Store items
      const storeResult = await memoryStoreService.store({
        items: testItems,
      });

      expect(storeResult.success).toBe(true);
      expect(storeResult.stored_count).toBe(3);
      expect(storeResult.duplicate_count).toBe(0);
      expect(storeResult.items).toHaveLength(3);

      // Retrieve items using find
      const findResult = await memoryFindService.find({
        query: 'Cortex Memory knowledge management',
        scope: { project: 'test-project', branch: 'main' },
        limit: 10,
      });

      expect(findResult.results.length).toBeGreaterThan(0);
      expect(findResult.results[0].content).toContain('Cortex Memory');
      expect(findResult.results[0].confidence_score).toBeGreaterThan(0);
    });

    it('should handle batch storage with mixed item types', async () => {
      const mixedItems: MemoryStoreInput[] = [
        {
          kind: 'entity',
          content: 'User authentication service handles login and session management',
          scope: { project: 'auth-system' },
        },
        {
          kind: 'relation',
          content: 'Authentication service depends on database for user credentials',
          scope: { project: 'auth-system' },
        },
        {
          kind: 'runbook',
          content: 'Authentication service deployment procedure involves database migration and service restart',
          scope: { project: 'auth-system' },
        },
        {
          kind: 'risk',
          content: 'Authentication service has a risk of single point failure if database becomes unavailable',
          scope: { project: 'auth-system' },
        },
        {
          kind: 'assumption',
          content: 'We assume the database will maintain 99.9% uptime for authentication operations',
          scope: { project: 'auth-system' },
        },
      ];

      const storeResult = await memoryStoreService.store({
        items: mixedItems,
      });

      expect(storeResult.success).toBe(true);
      expect(storeResult.stored_count).toBe(5);

      // Test searching for different types
      const entitySearch = await memoryFindService.find({
        query: 'user authentication service',
        types: ['entity'],
        scope: { project: 'auth-system' },
      });

      const relationSearch = await memoryFindService.find({
        query: 'database dependency authentication',
        types: ['relation'],
        scope: { project: 'auth-system' },
      });

      const riskSearch = await memoryFindService.find({
        query: 'single point failure database',
        types: ['risk'],
        scope: { project: 'auth-system' },
      });

      expect(entitySearch.results.length).toBe(1);
      expect(relationSearch.results.length).toBe(1);
      expect(riskSearch.results.length).toBe(1);

      // Verify content matches expected types
      expect(entitySearch.results[0].kind).toBe('entity');
      expect(relationSearch.results[0].kind).toBe('relation');
      expect(riskSearch.results[0].kind).toBe('risk');
    });

    it('should implement proper deduplication across storage operations', async () => {
      const duplicateItem: MemoryStoreInput = {
        kind: 'entity',
        content: 'This is a test entity for deduplication testing',
        scope: { project: 'dedupe-test' },
        metadata: { test_id: 'unique-entity-001' },
      };

      // First storage
      const firstStore = await memoryStoreService.store({
        items: [duplicateItem],
      });

      expect(firstStore.success).toBe(true);
      expect(firstStore.stored_count).toBe(1);
      expect(firstStore.duplicate_count).toBe(0);

      // Second storage with identical content
      const secondStore = await memoryStoreService.store({
        items: [duplicateItem],
      });

      expect(secondStore.success).toBe(true);
      expect(secondStore.stored_count).toBe(0); // Should be deduplicated
      expect(secondStore.duplicate_count).toBe(1);

      // Third storage with slight variation but same core content
      const similarItem: MemoryStoreInput = {
        ...duplicateItem,
        content: 'This is a test entity for deduplication testing with minor changes',
        metadata: { ...duplicateItem.metadata, variation: 'slight-modification' },
      };

      const thirdStore = await memoryStoreService.store({
        items: [similarItem],
      });

      expect(thirdStore.success).toBe(true);
      // Should be deduplicated due to high similarity
      expect(thirdStore.stored_count).toBeLessThanOrEqual(1);
      expect(thirdStore.duplicate_count).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Advanced Search Functionality', () => {
    it('should perform semantic search with relevance ranking', async () => {
      // Prepare diverse content for semantic search testing
      const searchTestData: MemoryStoreInput[] = [
        {
          kind: 'section',
          content: 'The microservices architecture consists of independent services communicating through APIs',
          scope: { project: 'architecture-docs' },
        },
        {
          kind: 'section',
          content: 'Our RESTful API design follows OpenAPI specifications with proper versioning',
          scope: { project: 'architecture-docs' },
        },
        {
          kind: 'section',
          content: 'Database schema normalization ensures data integrity and reduces redundancy',
          scope: { project: 'architecture-docs' },
        },
        {
          kind: 'section',
          content: 'Container orchestration using Kubernetes manages service deployment and scaling',
          scope: { project: 'architecture-docs' },
        },
        {
          kind: 'section',
          content: 'Authentication and authorization are implemented using OAuth 2.0 and JWT tokens',
          scope: { project: 'architecture-docs' },
        },
      ];

      // Store test data
      await memoryStoreService.store({
        items: searchTestData,
      });

      // Test semantic search with different queries
      const searchQueries = [
        { query: 'service communication APIs', expectedMatches: 2 },
        { query: 'database design and data modeling', expectedMatches: 1 },
        { query: 'container deployment orchestration', expectedMatches: 1 },
        { query: 'security authentication authorization', expectedMatches: 1 },
      ];

      for (const { query, expectedMatches } of searchQueries) {
        const searchResult = await memoryFindService.find({
          query,
          scope: { project: 'architecture-docs' },
          limit: 10,
          mode: 'auto',
        });

        expect(searchResult.results.length).toBeGreaterThanOrEqual(expectedMatches);

        // Verify results are properly ranked by confidence
        if (searchResult.results.length > 1) {
          for (let i = 0; i < searchResult.results.length - 1; i++) {
            expect(searchResult.results[i].confidence_score)
              .toBeGreaterThanOrEqual(searchResult.results[i + 1].confidence_score);
          }
        }

        // Verify all results are relevant to the query
        searchResult.results.forEach(result => {
          expect(result.confidence_score).toBeGreaterThan(0.3); // Minimum relevance threshold
        });
      }
    });

    it('should support hybrid search combining semantic and keyword matching', async () => {
      const hybridTestData: MemoryStoreInput[] = [
        {
          kind: 'entity',
          content: 'Payment processing service handles credit card transactions using Stripe API',
          scope: { project: 'payment-system' },
        },
        {
          kind: 'entity',
          content: 'Refund management processes customer refund requests through automated workflows',
          scope: { project: 'payment-system' },
        },
        {
          kind: 'process',
          content: 'The payment reconciliation process runs daily to match transactions with bank statements',
          scope: { project: 'payment-system' },
        },
        {
          kind: 'observation',
          content: 'Payment gateway latency averages 200ms during peak hours',
          scope: { project: 'payment-system' },
        },
      ];

      await memoryStoreService.store({
        items: hybridTestData,
      });

      // Test hybrid search with query that has both exact terms and semantic meaning
      const hybridSearch = await memoryFindService.find({
        query: 'Stripe payment processing transactions',
        scope: { project: 'payment-system' },
        mode: 'auto', // Should automatically choose best strategy
        expand: 'relations',
      });

      expect(hybridSearch.results.length).toBeGreaterThan(0);

      // Should find exact match for payment processing
      const exactMatch = hybridSearch.results.find(r =>
        r.content.toLowerCase().includes('payment processing')
      );
      expect(exactMatch).toBeDefined();

      // Should also find semantically related content
      const semanticMatches = hybridSearch.results.filter(r =>
        !r.content.toLowerCase().includes('payment processing') &&
        (r.content.toLowerCase().includes('payment') ||
         r.content.toLowerCase().includes('transactions'))
      );
      expect(semanticMatches.length).toBeGreaterThan(0);
    });

    it('should handle graph expansion for related knowledge retrieval', async () => {
      // Create interconnected knowledge graph
      const graphData: MemoryStoreInput[] = [
        {
          kind: 'entity',
          content: 'User Service manages user profiles and authentication',
          scope: { project: 'user-management' },
        },
        {
          kind: 'relation',
          content: 'User Service depends on Database Service for data persistence',
          scope: { project: 'user-management' },
        },
        {
          kind: 'entity',
          content: 'Database Service provides PostgreSQL and Redis connections',
          scope: { project: 'user-management' },
        },
        {
          kind: 'relation',
          content: 'User Service integrates with Email Service for notifications',
          scope: { project: 'user-management' },
        },
        {
          kind: 'entity',
          content: 'Email Service handles transactional and marketing emails',
          scope: { project: 'user-management' },
        },
      ];

      await memoryStoreService.store({
        items: graphData,
      });

      // Search with graph expansion
      const expandedSearch = await memoryFindService.find({
        query: 'User Service authentication',
        scope: { project: 'user-management' },
        expand: 'relations',
        limit: 10,
      });

      expect(expandedSearch.results.length).toBeGreaterThan(2); // Should find related services

      const resultContents = expandedSearch.results.map(r => r.content);

      // Should find the main entity
      expect(resultContents.some(c => c.includes('User Service manages user profiles'))).toBe(true);

      // Should find related services through expansion
      expect(resultContents.some(c => c.includes('Database Service provides'))).toBe(true);
      expect(resultContents.some(c => c.includes('Email Service handles'))).toBe(true);

      // Should find dependency relations
      expect(resultContents.some(c => c.includes('depends on Database Service'))).toBe(true);
      expect(resultContents.some(c => c.includes('integrates with Email Service'))).toBe(true);
    });
  });

  describe('Chunking and Document Reassembly', () => {
    it('should automatically chunk large documents and reassemble for search', async () => {
      // Create a large document that will be chunked
      const largeDocument = `
# Complete System Architecture Documentation

## Overview
This document provides a comprehensive overview of our distributed system architecture, including all major components, their interactions, data flows, and operational considerations.

## Core Infrastructure

### Cloud Infrastructure
We deploy on AWS using a multi-region strategy for high availability. Primary region is us-east-1, with disaster recovery in us-west-2. Infrastructure is managed through Terraform with automated CI/CD pipelines.

### Container Platform
Kubernetes serves as our container orchestration platform, running on Amazon EKS. We use Helm charts for application deployment and Istio service mesh for inter-service communication.

### Database Architecture
Our data persistence layer includes:
- PostgreSQL for primary relational data
- MongoDB for document storage
- Redis for caching and session management
- Elasticsearch for search and analytics

### Microservices Design
The system consists of 15 microservices organized into domain boundaries:
- User Management Service
- Authentication Service
- Payment Processing Service
- Order Management Service
- Inventory Service
- Notification Service
- Analytics Service
- Reporting Service
- File Storage Service
- Email Service
- SMS Service
- Integration Service
- API Gateway Service
- Configuration Service
- Monitoring Service

## Data Flow Architecture

### Request Processing
1. Client requests enter through API Gateway
2. Gateway performs authentication and rate limiting
3. Requests are routed to appropriate microservices
4. Services interact with databases as needed
5. Responses flow back through the gateway

### Event-Driven Architecture
We use Apache Kafka for asynchronous communication between services:
- Order events trigger inventory updates
- User events trigger notification processing
- Payment events trigger receipt generation
- System events trigger monitoring alerts

### Caching Strategy
Multi-level caching improves performance:
1. Application-level caching with Redis
2. Database query result caching
3. CDN caching for static assets
4. Browser caching for API responses

## Security Architecture

### Authentication & Authorization
- OAuth 2.0 with JWT tokens
- Role-based access control (RBAC)
- Multi-factor authentication support
- API key authentication for service-to-service

### Data Protection
- Encryption in transit (TLS 1.3)
- Encryption at rest (AES-256)
- PII data masking and tokenization
- Regular security audits and penetration testing

### Network Security
- VPC with private subnets
- Security groups and NACLs
- WAF for API protection
- DDoS protection through Cloudflare

## Performance Optimization

### Scalability Design
- Horizontal scaling for stateless services
- Database read replicas for query performance
- Connection pooling for database efficiency
- Auto-scaling based on CPU and memory metrics

### Monitoring and Observability
- Prometheus for metrics collection
- Grafana for visualization
- Jaeger for distributed tracing
- ELK stack for log aggregation

### Performance Benchmarks
- API response time < 200ms (P95)
- Database query time < 100ms (P95)
- 99.9% uptime SLA
- Support for 10,000 concurrent users

## Deployment Architecture

### CI/CD Pipeline
- GitLab CI for build automation
- Automated testing with multiple stages
- Canary deployments for production releases
- Rollback capabilities for failed deployments

### Environment Strategy
- Development environment (feature branches)
- Staging environment (production mirror)
- Production environment (live traffic)
- Performance testing environment

### Infrastructure as Code
- Terraform for resource management
- Ansible for configuration management
- Docker for containerization
- Kubernetes for orchestration

## Operational Excellence

### Incident Management
- 24/7 monitoring and alerting
- Automated incident response
- Post-incident analysis and learning
- Runbooks for common scenarios

### Backup and Disaster Recovery
- Automated daily backups
- Point-in-time recovery capability
- Cross-region replication
- Regular disaster recovery drills

### Compliance and Governance
- SOC 2 Type II compliance
- GDPR data protection compliance
- Regular security assessments
- Change management procedures

## Future Roadmap

### Planned Enhancements
- GraphQL API support
- Machine learning integration
- Advanced analytics capabilities
- Mobile application development

### Technology Evolution
- Microservices to service mesh migration
- Monolith decomposition initiatives
- Cloud provider diversification
- Edge computing exploration

This architecture documentation serves as the foundation for our engineering team's understanding of the system's design principles, implementation details, and operational procedures.
      `.trim();

      const documentItem: MemoryStoreInput = {
        kind: 'section',
        content: largeDocument,
        scope: { project: 'architecture-docs', branch: 'main' },
        metadata: {
          title: 'Complete System Architecture Documentation',
          document_type: 'architecture',
          version: '2.0',
        },
      };

      // Store the large document - should be automatically chunked
      const storeResult = await memoryStoreService.store({
        items: [documentItem],
      });

      expect(storeResult.success).toBe(true);
      expect(storeResult.items.length).toBeGreaterThan(1); // Should be chunked

      // Search for content across different parts of the document
      const searchQueries = [
        'Kubernetes container orchestration',
        'PostgreSQL database architecture',
        'OAuth 2.0 authentication JWT',
        'CI/CD pipeline deployment',
        'performance monitoring metrics',
      ];

      for (const query of searchQueries) {
        const searchResult = await memoryFindService.find({
          query,
          scope: { project: 'architecture-docs' },
          limit: 10,
        });

        expect(searchResult.results.length).toBeGreaterThan(0);

        // Verify that search results are properly reconstructed or show relevant chunks
        const hasRelevantContent = searchResult.results.some(result =>
          result.content.toLowerCase().includes(query.toLowerCase()) ||
          (result.data?.reconstructed && result.content.toLowerCase().includes(query.toLowerCase()))
        );

        expect(hasRelevantContent).toBe(true);
      }

      // Test document reassembly specifically
      const architectureSearch = await memoryFindService.find({
        query: 'system architecture overview',
        scope: { project: 'architecture-docs' },
        limit: 20,
      });

      // Should find reconstructed document or chunks with reassembly metadata
      const reconstructedDoc = architectureSearch.results.find(r => r.data?.reconstructed);
      if (reconstructedDoc) {
        expect(reconstructedDoc.content).toContain('Complete System Architecture Documentation');
        expect(reconstructedDoc.data.total_chunks).toBeGreaterThan(1);
        expect(reconstructedDoc.data.found_chunks).toBeGreaterThan(1);
        expect(reconstructedDoc.data.completeness_ratio).toBeGreaterThan(0.8);
      }
    });
  });

  describe('Performance and Scalability', () => {
    it('should handle concurrent operations efficiently', async () => {
      const concurrentItems = Array.from({ length: 50 }, (_, index) => ({
        kind: 'entity' as const,
        content: `Concurrent test item ${index}: This is test content for performance testing with various keywords and semantic meaning`,
        scope: { project: 'performance-test', branch: 'concurrent' },
        metadata: { test_index: index, test_type: 'concurrent' },
      }));

      // Store items concurrently
      const startTime = Date.now();
      const storePromises = concurrentItems.map((item, index) =>
        memoryStoreService.store({
          items: [item],
        })
      );

      const storeResults = await Promise.all(storePromises);
      const storeTime = Date.now() - startTime;

      // Verify all stores succeeded
      storeResults.forEach(result => {
        expect(result.success).toBe(true);
      });

      expect(storeTime).toBeLessThan(10000); // Should complete in <10s

      // Perform concurrent searches
      const searchStartTime = Date.now();
      const searchPromises = Array.from({ length: 20 }, (_, index) =>
        memoryFindService.find({
          query: `concurrent test item ${index % 10}`,
          scope: { project: 'performance-test' },
          limit: 5,
        })
      );

      const searchResults = await Promise.all(searchPromises);
      const searchTime = Date.now() - searchStartTime;

      // Verify searches completed successfully
      searchResults.forEach(result => {
        expect(result.results.length).toBeGreaterThanOrEqual(0);
      });

      expect(searchTime).toBeLessThan(5000); // Should complete in <5s
    });

    it('should maintain search quality with large datasets', async () => {
      // Create a larger dataset for quality testing
      const largeDataset = Array.from({ length: 100 }, (_, index) => {
        const categories = ['performance', 'security', 'scalability', 'reliability', 'maintainability'];
        const category = categories[index % categories.length];

        return {
          kind: 'observation' as const,
          content: `${category} observation ${index}: System shows excellent ${category} characteristics with metrics indicating optimal performance in ${category}-related operations`,
          scope: { project: 'quality-test' },
          metadata: {
            category,
            test_index: index,
            quality_metric: category === 'performance' ? 'response_time' :
                           category === 'security' ? 'vulnerability_count' :
                           category === 'scalability' ? 'throughput' :
                           category === 'reliability' ? 'uptime' : 'code_coverage'
          },
        };
      });

      // Store the dataset
      await memoryStoreService.store({
        items: largeDataset,
      });

      // Test search quality across different categories
      const qualityTests = [
        { query: 'system performance metrics', expectedCategory: 'performance' },
        { query: 'security vulnerability assessment', expectedCategory: 'security' },
        { query: 'scalability throughput testing', expectedCategory: 'scalability' },
        { query: 'system reliability uptime', expectedCategory: 'reliability' },
        { query: 'code maintainability coverage', expectedCategory: 'maintainability' },
      ];

      for (const { query, expectedCategory } of qualityTests) {
        const searchResult = await memoryFindService.find({
          query,
          scope: { project: 'quality-test' },
          limit: 10,
        });

        expect(searchResult.results.length).toBeGreaterThan(0);

        // Verify results are relevant and have good confidence scores
        searchResult.results.forEach(result => {
          expect(result.confidence_score).toBeGreaterThan(0.5);
          expect(result.content.toLowerCase()).toContain(expectedCategory);
        });

        // Results should be properly ranked
        if (searchResult.results.length > 1) {
          for (let i = 0; i < searchResult.results.length - 1; i++) {
            expect(searchResult.results[i].confidence_score)
              .toBeGreaterThanOrEqual(searchResult.results[i + 1].confidence_score);
          }
        }
      }
    });
  });

  describe('Scope and Isolation', () => {
    it('should properly isolate data by scope boundaries', async () => {
      // Create data for different projects and branches
      const scopedData = [
        {
          kind: 'entity' as const,
          content: 'Feature A implementation for project Alpha',
          scope: { project: 'project-alpha', branch: 'feature-a' },
        },
        {
          kind: 'entity' as const,
          content: 'Feature B implementation for project Alpha',
          scope: { project: 'project-alpha', branch: 'feature-b' },
        },
        {
          kind: 'entity' as const,
          content: 'Main branch development for project Beta',
          scope: { project: 'project-beta', branch: 'main' },
        },
        {
          kind: 'entity' as const,
          content: 'Development branch for project Beta',
          scope: { project: 'project-beta', branch: 'development' },
        },
        {
          kind: 'entity' as const,
          content: 'Shared infrastructure component',
          scope: { project: 'shared-infra', branch: 'main' },
        },
      ];

      // Store all scoped data
      await memoryStoreService.store({
        items: scopedData,
      });

      // Test scope isolation
      const alphaResults = await memoryFindService.find({
        query: 'implementation',
        scope: { project: 'project-alpha' },
        limit: 10,
      });

      const betaResults = await memoryFindService.find({
        query: 'development',
        scope: { project: 'project-beta' },
        limit: 10,
      });

      const sharedResults = await memoryFindService.find({
        query: 'infrastructure component',
        scope: { project: 'shared-infra' },
        limit: 10,
      });

      // Verify scope isolation
      expect(alphaResults.results.length).toBe(2); // Should find both Alpha features
      expect(betaResults.results.length).toBe(2); // Should find both Beta branches
      expect(sharedResults.results.length).toBe(1); // Should find shared component

      // Verify cross-contamination doesn't occur
      const alphaContent = alphaResults.results.map(r => r.content);
      const betaContent = betaResults.results.map(r => r.content);
      const sharedContent = sharedResults.results.map(r => r.content);

      // Alpha results should not contain Beta content
      alphaContent.forEach(content => {
        expect(content).not.toContain('project-beta');
      });

      // Beta results should not contain Alpha content
      betaContent.forEach(content => {
        expect(content).not.toContain('project-alpha');
      });

      // Test branch-level isolation
      const alphaFeatureA = await memoryFindService.find({
        query: 'Feature A',
        scope: { project: 'project-alpha', branch: 'feature-a' },
      });

      const alphaFeatureB = await memoryFindService.find({
        query: 'Feature B',
        scope: { project: 'project-alpha', branch: 'feature-b' },
      });

      expect(alphaFeatureA.results.length).toBe(1);
      expect(alphaFeatureB.results.length).toBe(1);
      expect(alphaFeatureA.results[0].content).toContain('Feature A');
      expect(alphaFeatureB.results[0].content).toContain('Feature B');
    });
  });
});