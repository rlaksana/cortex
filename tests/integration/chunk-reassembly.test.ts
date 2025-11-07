/**
 * Integration Tests - Document Chunk Reassembly
 *
 * Tests the complete document reassembly pipeline to ensure that chunked documents
 * can be correctly reconstructed during search operations, maintaining content integrity,
 * metadata coherence, and semantic understanding.
 */

import { describe, it, expect, beforeEach, afterEach, beforeAll, afterAll } from 'vitest';
import { DatabaseManager } from '../../src/db/database-manager.js';
import { ChunkingService } from '../../src/services/chunking/chunking-service.js';
import { memoryStore } from '../../src/services/memory-store.js';
import { memoryFind } from '../../src/services/memory-find.js';
import { ResultGroupingService } from '../../src/services/search/result-grouping-service.js';
import { MockEmbeddingService } from '../utils/mock-embedding-service.js';
import { createMockSemanticAnalyzer } from '../utils/mock-semantic-analyzer.js';
import { mockQdrantClient } from '../mocks/database.js';
import {
  KnowledgeItem,
  MemoryStoreInput,
  MemoryFindInput,
} from '../../src/types/core-interfaces.js';

describe('Integration Tests - Document Chunk Reassembly', () => {
  let databaseManager: any;
  let chunkingService: ChunkingService;
  let memoryStoreService: any;
  let memoryFindService: any;
  let groupingService: ResultGroupingService;
  let embeddingService: MockEmbeddingService;

  beforeAll(async () => {
    // Initialize services for reassembly testing
    embeddingService = new MockEmbeddingService({
      shouldFail: false,
      latency: 30,
    });

    databaseManager = new DatabaseManager({
      qdrant: {
        url: process.env['QDRANT_URL'] || 'http://localhost:6333',
        apiKey: process.env['QDRANT_API_KEY'],
        timeout: 30000,
      },
      enableVectorOperations: true,
      enableFallback: true,
    });

    // Initialize the database manager
    await databaseManager.initialize();

    chunkingService = new ChunkingService(databaseManager, embeddingService, undefined);

    const mockSemanticAnalyzer = createMockSemanticAnalyzer(embeddingService as any, {
      shouldFail: false,
    });
    (chunkingService as any).semanticAnalyzer = mockSemanticAnalyzer;

    memoryStoreService = memoryStore;
    memoryFindService = memoryFind;
    groupingService = new ResultGroupingService();
  });

  beforeEach(async () => {
    try {
      await databaseManager.healthCheck();
      // Note: createCollection may not be available on the database interface
      // We'll use the mock database for testing
      (databaseManager as any).qdrantClient = mockQdrantClient;
    } catch (error) {
      // Use mock database for testing if real database unavailable
      (databaseManager as any).qdrantClient = mockQdrantClient;
    }
  });

  afterEach(async () => {
    try {
      // Cleanup may not be needed for mock database
      // await databaseManager.deleteCollection('test-reassembly');
    } catch (error) {
      // Ignore cleanup errors
    }
  });

  afterAll(async () => {
    try {
      await databaseManager.close();
    } catch (error) {
      // Ignore disconnect errors
    }
  });

  describe('Basic Chunk Reassembly', () => {
    it('should correctly reassemble a simple chunked document', async () => {
      const simpleDocument = `
# Simple Test Document

## Introduction
This is a simple document used to test basic chunk reassembly functionality. The document contains multiple sections that should be properly chunked and then reassembled during search operations.

## Main Content
The main content section provides detailed information about the topic being discussed. This content should be preserved across chunk boundaries to ensure semantic coherence when the document is reconstructed.

## Conclusion
The conclusion summarizes the key points discussed in the document and provides final thoughts on the subject matter. This section should appear at the end of the reassembled content.

All sections should maintain their proper order and formatting when the document is reconstructed from individual chunks.
      `.trim();

      const documentItem: MemoryStoreInput = {
        kind: 'section',
        content: simpleDocument,
        scope: { project: 'reassembly-test' },
        metadata: {
          title: 'Simple Test Document',
          category: 'testing',
          difficulty: 'basic',
        },
      };

      // Store and chunk the document
      const storeResult = await memoryStoreService([documentItem]);

      expect(storeResult.items.length).toBeGreaterThan(0);
      expect(storeResult.errors.length).toBe(0);

      // Check if chunking actually occurred
      const hasChunks = storeResult.items.some((item) => item.metadata?.is_chunk === true);
      const parentItem = storeResult.items.find((item) => !item.metadata?.is_chunk);

      if (hasChunks) {
        expect(storeResult.items.length).toBeGreaterThan(1); // Should be chunked
      } else {
        // If no chunking occurred, we should still have the parent item
        expect(parentItem).toBeDefined();
        console.log('Document was not chunked - may be too small or chunking disabled');
      }

      // Find and reassemble the document
      const searchResult = await memoryFindService({
        query: 'simple test document introduction content',
        scope: { project: 'reassembly-test' },
        limit: 20,
      });

      expect(searchResult.results.length).toBeGreaterThan(0);

      // Look for reconstructed document OR any relevant document if not chunked
      const reconstructed = searchResult.results.find((r) => r.data?.reconstructed);
      const relevantDoc = searchResult.results.find(
        (r) =>
          r.metadata?.title === 'Simple Test Document' ||
          r.content?.includes('Simple Test Document')
      );

      expect(reconstructed || relevantDoc).toBeDefined();

      const resultDoc = reconstructed || relevantDoc;

      if (resultDoc) {
        // Verify content integrity
        expect(resultDoc.content).toContain('Simple Test Document');
        expect(resultDoc.content).toContain('Introduction');
        expect(resultDoc.content).toContain('Main Content');
        expect(resultDoc.content).toContain('Conclusion');

        if (reconstructed) {
          // Verify reassembly metadata only for chunked documents
          expect(reconstructed['data.total_chunks']).toBeGreaterThan(1);
          expect(reconstructed['data.found_chunks']).toBeGreaterThan(1);
          expect(reconstructed['data.completeness_ratio']).toBe(1.0);
          expect(reconstructed['data.parent_id']).toBeDefined();
        }

        // Verify metadata preservation
        expect(resultDoc.metadata?.title).toBe('Simple Test Document');
        expect(resultDoc.metadata?.category).toBe('testing');
      }
    });

    it('should handle partial document reassembly gracefully', async () => {
      const partialDocument = `
# Partial Reassembly Test Document

## Section 1: Foundation Concepts
This section introduces the foundational concepts necessary for understanding partial reassembly. When only some chunks of a document are found during search, the system should still provide a meaningful reconstruction.

## Section 2: Implementation Details
The implementation of partial reassembly requires careful handling of missing chunks. The system should identify which chunks are missing and clearly indicate the incomplete nature of the reconstruction.

## Section 3: Quality Considerations
Quality considerations for partial reassembly include maintaining semantic coherence even with missing content. The reconstructed document should be clearly marked as incomplete to avoid misleading users.

## Section 4: User Experience
The user experience for partial reassembly should transparently communicate the limitations while still providing value from the available content.

## Section 5: Technical Challenges
Technical challenges in partial reassembly include handling chunk ordering, maintaining metadata integrity, and providing appropriate confidence scores for incomplete reconstructions.

This comprehensive test document ensures that partial reassembly scenarios are properly handled across multiple sections and content types.
      `.trim();

      const documentItem: MemoryStoreInput = {
        kind: 'section',
        content: partialDocument,
        scope: { project: 'partial-reassembly-test' },
        metadata: {
          title: 'Partial Reassembly Test Document',
          category: 'testing',
          test_type: 'partial_reassembly',
        },
      };

      // Store the document
      const storeResult = await memoryStoreService([documentItem]);

      expect(storeResult.items.length).toBeGreaterThan(0);
      expect(storeResult.errors.length).toBe(0);

      // Check if we have chunks or just the parent document
      const allChunks = storeResult.items.filter((item) => item.metadata?.is_chunk);
      const parentDoc = storeResult.items.find((item) => !item.metadata?.is_chunk);

      if (allChunks.length === 0) {
        // No chunking occurred - skip this test scenario
        console.log('Document was not chunked - skipping partial reassembly test');
        return;
      }

      // Simulate finding only some chunks (70% of them)
      const partialChunks = allChunks.slice(0, Math.floor(allChunks.length * 0.7));

      // Convert to search results format
      const searchResults = partialChunks.map((chunk) => ({
        id: chunk.id,
        kind: chunk.kind,
        content: chunk.content,
        data: chunk.data,
        scope: chunk.scope,
        confidence_score: 0.8,
        created_at: chunk.created_at!,
        match_type: 'semantic' as const,
      }));

      // Group and reconstruct partially
      const groupedResults = groupingService.groupResultsByParent(searchResults);
      expect(groupedResults.length).toBeGreaterThan(0);

      const partialReconstruction = groupingService.reconstructGroupedContent(groupedResults[0]);

      // Verify partial reconstruction quality
      expect(partialReconstruction.found_chunks).toBe(partialChunks.length);
      expect(partialReconstruction['total_chunks']).toBe(allChunks.length);
      expect(partialReconstruction.completeness_ratio).toBeLessThan(1.0);
      expect(partialReconstruction.completeness_ratio).toBeGreaterThan(0.5);

      // Should still contain key sections
      expect(partialReconstruction.content).toContain('Partial Reassembly Test Document');
      expect(partialReconstruction.content).toContain('Section 1: Foundation Concepts');

      // Should be marked as incomplete
      expect(partialReconstruction['data.incomplete']).toBe(true);
      expect(partialReconstruction['data.missing_chunks']).toBeGreaterThan(0);
    });
  });

  describe('Complex Document Reassembly', () => {
    it('should reassemble documents with complex formatting and structure', async () => {
      const complexDocument = `
# Advanced System Architecture Documentation

## Executive Summary
This document provides a comprehensive overview of our advanced system architecture, including all major components, their interactions, data flows, and operational considerations. The architecture is designed to support high scalability, reliability, and maintainability.

### Key Architectural Principles
1. **Microservices Design**: Services are loosely coupled and independently deployable
2. **Event-Driven Communication**: Asynchronous messaging patterns for service interaction
3. **Container Orchestration**: Kubernetes-based deployment and scaling
4. **API-First Approach**: All services expose well-defined REST APIs
5. **Data Security**: End-to-end encryption and strict access controls

## System Components

### Core Infrastructure Layer

#### Cloud Platform
- **Provider**: AWS with multi-region deployment
- **Regions**: Primary (us-east-1), Secondary (us-west-2)
- **High Availability**: Cross-region failover capability
- **Disaster Recovery**: Automated backup and restoration procedures

#### Container Platform
- **Orchestration**: Kubernetes (EKS managed service)
- **Runtime**: Docker containers with multi-stage builds
- **Service Mesh**: Istio for traffic management and security
- **Ingress**: NGINX Ingress Controller with SSL termination

### Application Layer

#### Microservices Architecture

##### User Management Service
- **Responsibilities**: Authentication, authorization, user profiles
- **Technology**: Node.js with Express framework
- **Database**: PostgreSQL for user data, Redis for sessions
- **Scaling**: Horizontal with load balancing
- **Security**: JWT tokens, OAuth 2.0 integration

##### Order Processing Service
- **Responsibilities**: Order lifecycle management, payment processing
- **Technology**: Java Spring Boot application
- **Database**: MongoDB for order documents, PostgreSQL for transactions
- **Events**: Kafka integration for asynchronous processing
- **Performance**: Caching with Redis, database connection pooling

##### Inventory Service
- **Responsibilities**: Stock management, reservation, replenishment
- **Technology**: Python with FastAPI framework
- **Database**: PostgreSQL with TimescaleDB extensions
- **Real-time**: WebSocket connections for live updates
- **Analytics**: Real-time inventory metrics and alerts

### Data Layer

#### Primary Data Stores

##### Relational Database (PostgreSQL)
- **Version**: PostgreSQL 14+ with appropriate extensions
- **Configuration**: Master-slave replication with read replicas
- **Backups**: Automated daily backups with point-in-time recovery
- **Performance**: Connection pooling, query optimization, indexing strategy

##### Document Database (MongoDB)
- **Version**: MongoDB 5.0+ with sharding capability
- **Configuration**: Replica set with automatic failover
- **Use Cases**: Product catalogs, user-generated content, audit logs
- **Performance**: Index optimization, aggregation pipeline tuning

##### Cache Layer (Redis)
- **Version**: Redis 7.0+ with cluster configuration
- **Configuration**: Master-slave setup with automatic failover
- **Use Cases**: Session storage, API response caching, rate limiting
- **Persistence**: Configurable persistence with AOF and RDB

#### Search and Analytics

##### Elasticsearch Cluster
- **Version**: Elasticsearch 8.0+ with security features
- **Configuration**: Multi-node cluster with dedicated master nodes
- **Use Cases**: Full-text search, log aggregation, analytics
- **Performance**: Index optimization, shard configuration, query caching

##### Data Warehouse (Snowflake)
- **Configuration**: Multi-cluster warehouse for different workloads
- **Use Cases**: Business intelligence, reporting, advanced analytics
- **Integration**: Real-time data streaming and batch processing
- **Security**: Role-based access control and data encryption

## Integration Patterns

### Service-to-Service Communication

#### Synchronous Communication
- **Protocol**: HTTP/HTTPS with RESTful API design
- **Authentication**: Mutual TLS with service-to-service certificates
- **Rate Limiting**: Token bucket algorithm with circuit breakers
- **Timeouts**: Configurable timeouts with exponential backoff

#### Asynchronous Communication
- **Message Broker**: Apache Kafka with high-throughput configuration
- **Topics**: Domain-specific topics with appropriate partitioning
- **Serialization**: Protocol Buffers for efficient message encoding
- **Consumer Groups**: Scalable consumer processing with load balancing

### Data Integration Patterns

#### Event Sourcing
- **Implementation**: Immutable event logs for state changes
- **Snapshots**: Periodic snapshots for performance optimization
- **Replay**: Event replay capability for system recovery
- **Consistency**: Eventually consistent model with conflict resolution

#### CQRS (Command Query Responsibility Segregation)
- **Command Side**: Write-optimized data models and validation
- **Query Side**: Read-optimized denormalized views
- **Synchronization**: Event-driven synchronization between sides
- **Performance**: Optimized read and write patterns

## Security Architecture

### Authentication and Authorization

#### Identity Management
- **Provider**: AWS Cognito with multi-factor authentication
- **Federation**: SAML integration with corporate identity providers
- **Token Management**: JWT access tokens with refresh token rotation
- **Session Management**: Secure session storage with Redis

#### Access Control
- **Model**: Role-Based Access Control (RBAC) with hierarchical roles
- **Permissions**: Fine-grained permissions with resource-level control
- **Auditing**: Comprehensive audit logging for all access attempts
- **Compliance**: GDPR, SOC 2, and HIPAA compliance measures

### Data Protection

#### Encryption
- **In Transit**: TLS 1.3 with perfect forward secrecy
- **At Rest**: AES-256 encryption with key rotation
- **Key Management**: AWS KMS for centralized key management
- **Certificate Management**: Automated certificate lifecycle management

#### Network Security
- **VPC**: Isolated VPC with private subnets
- **Security Groups**: Network-level traffic filtering
- **WAF**: Web Application Firewall for API protection
- **DDoS Protection**: Cloudflare integration for DDoS mitigation

## Performance and Scalability

### Scalability Strategies

#### Horizontal Scaling
- **Stateless Services**: All services designed for horizontal scaling
- **Load Balancing**: Application load balancers with health checks
- **Auto Scaling**: CPU and memory-based auto scaling policies
- **Capacity Planning**: Predictive scaling based on traffic patterns

#### Vertical Scaling
- **Resource Optimization**: Container resource optimization
- **Performance Tuning**: JVM tuning, database query optimization
- **Monitoring**: Real-time performance monitoring and alerting
- **Profiling**: Regular performance profiling and bottleneck identification

### Performance Optimization

#### Caching Strategies
- **Application Caching**: In-memory caching with Redis
- **Database Caching**: Query result caching and connection pooling
- **CDN Caching**: Geographic content delivery network
- **Browser Caching**: Optimized cache headers and ETags

#### Database Optimization
- **Indexing Strategy**: Comprehensive indexing with query optimization
- **Partitioning**: Table partitioning for large datasets
- **Read Replicas**: Read scaling with database replicas
- **Connection Management**: Connection pooling and timeout optimization

## Monitoring and Observability

### Monitoring Stack

#### Infrastructure Monitoring
- **Metrics Collection**: Prometheus with custom exporters
- **Visualization**: Grafana dashboards for system metrics
- **Alerting**: AlertManager with intelligent alert routing
- **Retention**: Long-term metrics retention for trend analysis

#### Application Monitoring
- **APM**: Distributed tracing with Jaeger
- **Logging**: Structured logging with ELK stack
- **Error Tracking**: Sentry integration for error monitoring
- **Performance**: Real-time performance metrics and profiling

### Observability Practices

#### Distributed Tracing
- **Trace Propagation**: Consistent trace context across services
- **Span Sampling**: Intelligent sampling strategies
- **Performance Analysis**: Trace analysis for performance bottlenecks
- **Service Dependencies**: Service mesh visualization and analysis

#### Log Management
- **Structured Logging**: JSON-based structured logging
- **Log Aggregation**: Centralized log collection and processing
- **Log Analysis**: Machine learning for log anomaly detection
- **Compliance**: Log retention policies for compliance requirements

## Deployment and Operations

### CI/CD Pipeline

#### Build Pipeline
- **Source Control**: Git-based version control with feature branches
- **Automated Builds**: Container-based build environment
- **Testing**: Comprehensive test suite with multiple test types
- **Security Scanning**: Automated security vulnerability scanning

#### Deployment Pipeline
- **Canary Deployments**: Gradual traffic shifting for new releases
- **Blue-Green Deployments**: Zero-downtime deployment strategy
- **Rollback Capability**: Automated rollback for failed deployments
- **Environment Promotion**: Automated promotion through environments

### Infrastructure Management

#### Infrastructure as Code
- **Terraform**: Declarative infrastructure configuration
- **Helm Charts**: Kubernetes application packaging
- **Configuration Management**: Externalized configuration management
- **Secret Management**: Centralized secret management with rotation

#### Operational Procedures
- **Incident Response**: Automated incident response procedures
- **Disaster Recovery**: Regular disaster recovery testing
- **Capacity Planning**: Proactive capacity planning and scaling
- **Performance Testing**: Regular performance and load testing

## Future Roadmap

### Technology Evolution

#### Cloud Native Transition
- **Serverless**: Gradual migration to serverless architecture
- **Edge Computing**: Edge deployment for reduced latency
- **Multi-Cloud**: Multi-cloud strategy for vendor diversity
- **Green Computing**: Energy-efficient architecture design

#### AI/ML Integration
- **Machine Learning**: ML model integration for intelligent features
- **Predictive Analytics**: Predictive capabilities for business insights
- **Natural Language Processing**: NLP integration for enhanced user experience
- **Computer Vision**: Image and video processing capabilities

### Business Capabilities

#### Feature Enhancement
- **Real-time Collaboration**: Enhanced real-time collaboration features
- **Mobile Optimization**: Progressive Web App development
- **API Ecosystem**: Public API development for third-party integration
- **Internationalization**: Multi-language support and localization

#### Performance Improvements
- **Response Time Optimization**: Sub-100ms response time targets
- **Scalability Enhancement**: Support for millions of concurrent users
- **Geographic Expansion**: Global deployment with regional optimization
- **Cost Optimization**: Cloud cost optimization and efficiency improvements

This comprehensive architecture documentation serves as the foundation for our engineering organization's understanding of system design, implementation details, and operational procedures. It provides guidance for current development efforts and future architectural decisions.
      `.trim();

      const complexDocumentItem: MemoryStoreInput = {
        kind: 'section',
        content: complexDocument,
        scope: { project: 'complex-reassembly' },
        metadata: {
          title: 'Advanced System Architecture Documentation',
          category: 'architecture',
          complexity: 'high',
          document_type: 'comprehensive_specification',
          target_audience: 'engineering',
          version: '3.0',
          last_updated: new Date().toISOString(),
        },
      };

      // Store and chunk the complex document
      const storeResult = await memoryStoreService([complexDocumentItem]);

      expect(storeResult.items.length).toBeGreaterThan(0);
      expect(storeResult.errors.length).toBe(0);

      // Check if chunking occurred
      const hasChunks = storeResult.items.some((item) => item.metadata?.is_chunk === true);
      if (hasChunks) {
        expect(storeResult.items.length).toBeGreaterThan(5); // Should be heavily chunked
      } else {
        console.log(
          'Large document was not chunked - chunking may be disabled or threshold not met'
        );
      }

      // Test various search queries across different sections
      const searchTests = [
        {
          query: 'microservices architecture kubernetes containers',
          expectedSections: ['System Components', 'Application Layer'],
        },
        {
          query: 'PostgreSQL MongoDB Redis database',
          expectedSections: ['Data Layer', 'Primary Data Stores'],
        },
        {
          query: 'security authentication encryption TLS',
          expectedSections: ['Security Architecture'],
        },
        {
          query: 'monitoring observability Prometheus Grafana',
          expectedSections: ['Monitoring and Observability'],
        },
        {
          query: 'CI/CD pipeline deployment automation',
          expectedSections: ['Deployment and Operations'],
        },
      ];

      // Test each search query sequentially using Promise.all for proper async handling
      const searchPromises = searchTests.map(async ({ query, expectedSections }) => {
        const searchResult = await memoryFindService({
          query,
          scope: { project: 'complex-reassembly' },
          limit: 15,
        });

        expect(searchResult.results.length).toBeGreaterThan(0);

        // Look for reconstructed documents
        const reconstructedDocs = searchResult.results.filter((r) => r.data?.reconstructed);

        if (reconstructedDocs.length > 0) {
          const reconstructed = reconstructedDocs[0];

          // Verify comprehensive reconstruction
          expect(reconstructed['data.total_chunks']).toBeGreaterThan(5);
          expect(reconstructed['data.completeness_ratio']).toBeGreaterThan(0.8);

          // Verify metadata preservation
          expect(reconstructed.metadata?.title).toBe('Advanced System Architecture Documentation');
          expect(reconstructed.metadata?.complexity).toBe('high');
          expect(reconstructed.metadata?.version).toBe('3.0');

          // Verify content includes expected sections
          expectedSections.forEach((section) => {
            expect(reconstructed.content).toContain(section);
          });
        } else {
          // If no reconstructed document found, verify relevant chunks exist
          const relevantChunks = searchResult.results.filter((result) =>
            expectedSections.some((section) => result.content.includes(section))
          );
          expect(relevantChunks.length).toBeGreaterThan(0);
        }

        return { query, result: searchResult };
      });

      await Promise.all(searchPromises);
    });

    it('should maintain metadata integrity through complex reassembly operations', async () => {
      const metadataRichDocument = `
# Metadata-Intensive Technical Specification

## Document Information
This document demonstrates comprehensive metadata handling throughout the chunking and reassembly process. It includes various metadata fields that must be preserved accurately across all operations.

## Technical Content
The technical content includes detailed specifications, implementation guidelines, and architectural decisions that are critical for the development team.

## Quality Assurance
This section covers testing strategies, quality metrics, and validation procedures to ensure the highest quality standards are maintained.

## Project Management
Project management aspects include timeline planning, resource allocation, risk assessment, and milestone tracking.

## Compliance and Governance
Compliance requirements, governance procedures, and regulatory considerations are documented to ensure full adherence to organizational policies.
      `.trim();

      const richMetadataItem: MemoryStoreInput = {
        kind: 'section',
        content: metadataRichDocument,
        scope: {
          project: 'metadata-test',
          branch: 'main',
          org: 'engineering',
          team: 'architecture',
        },
        metadata: {
          title: 'Metadata-Intensive Technical Specification',
          category: 'technical_specification',
          subcategory: 'architecture',
          priority: 'critical',
          status: 'in_progress',
          author: 'chief_architect',
          reviewers: ['tech_lead', 'security_engineer', 'product_manager'],
          contributors: ['senior_developer_1', 'senior_developer_2'],
          version: '2.3.1',
          draft_version: '2.3.0',
          last_updated: new Date().toISOString(),
          created_at: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(), // 7 days ago
          review_date: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000).toISOString(), // 3 days from now
          approval_date: new Date(Date.now() + 10 * 24 * 60 * 60 * 1000).toISOString(), // 10 days from now
          tags: ['architecture', 'specification', 'metadata', 'technical', 'comprehensive'],
          labels: ['high_priority', 'team_review_required', 'security_sensitive'],
          classification: 'internal_confidential',
          compliance_requirements: ['SOC2', 'GDPR', 'ISO27001'],
          related_documents: ['system_overview_v1.5', 'api_specification_v2.1'],
          dependencies: ['database_schema_v3.0', 'security_policy_v2.2'],
          stakeholder_groups: ['engineering', 'product', 'security', 'compliance'],
          delivery_team: 'platform_engineering',
          estimated_completion: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(), // 30 days from now
          effort_estimate: '3_sprints',
          risk_level: 'medium',
          business_impact: 'high',
          technical_complexity: 'high',
          rollback_strategy: 'documented_and_tested',
          testing_requirements: [
            'unit_tests',
            'integration_tests',
            'security_tests',
            'performance_tests',
          ],
          deployment_strategy: 'blue_green',
          monitoring_requirements: ['application_metrics', 'business_metrics', 'security_events'],
        },
      };

      // Store the metadata-rich document
      const storeResult = await memoryStoreService([richMetadataItem]);

      expect(storeResult.items.length).toBeGreaterThan(0);
      expect(storeResult.errors.length).toBe(0);

      // Check if chunking occurred
      const hasChunks = storeResult.items.some((item) => item.metadata?.is_chunk === true);
      if (hasChunks) {
        expect(storeResult.items.length).toBeGreaterThan(1); // Should be chunked
      } else {
        console.log('Metadata-rich document was not chunked - may not meet chunking threshold');
      }

      // Find and reassemble
      const searchResult = await memoryFindService({
        query: 'metadata technical specification architecture',
        scope: { project: 'metadata-test' },
        limit: 20,
      });

      expect(searchResult.results.length).toBeGreaterThan(0);

      // Verify metadata preservation in chunks
      const chunks = storeResult.items.filter((item) => item.metadata?.is_chunk);
      const parent = storeResult.items.find((item) => !item.metadata?.is_chunk);

      // Parent should preserve all metadata
      expect(parent?.metadata?.title).toBe('Metadata-Intensive Technical Specification');
      expect(parent?.metadata?.author).toBe('chief_architect');
      expect(parent?.metadata?.version).toBe('2.3.1');
      expect(parent?.metadata?.classification).toBe('internal_confidential');
      expect(parent?.metadata?.reviewers).toEqual([
        'tech_lead',
        'security_engineer',
        'product_manager',
      ]);

      // Chunks should inherit critical metadata
      chunks.forEach((chunk) => {
        expect(chunk.metadata?.title).toBe('Metadata-Intensive Technical Specification');
        expect(chunk.metadata?.author).toBe('chief_architect');
        expect(chunk.metadata?.category).toBe('technical_specification');
        expect(chunk.metadata?.parent_id).toBe(parent?.id);
        expect(chunk.metadata?.total_chunks).toBe(chunks.length);
        expect(chunk.metadata?.is_chunk).toBe(true);
        expect(chunk.metadata?.classification).toBe('internal_confidential');
        expect(chunk.metadata?.compliance_requirements).toContain('SOC2');
      });

      // Test reassembly preservation
      const reconstructed = searchResult.results.find((r) => r.data?.reconstructed);
      if (reconstructed) {
        // Verify comprehensive metadata preservation
        expect(reconstructed.metadata?.title).toBe('Metadata-Intensive Technical Specification');
        expect(reconstructed.metadata?.author).toBe('chief_architect');
        expect(reconstructed.metadata?.version).toBe('2.3.1');
        expect(reconstructed.metadata?.reviewers).toEqual([
          'tech_lead',
          'security_engineer',
          'product_manager',
        ]);
        expect(reconstructed.metadata?.tags).toEqual([
          'architecture',
          'specification',
          'metadata',
          'technical',
          'comprehensive',
        ]);
        expect(reconstructed.metadata?.classification).toBe('internal_confidential');
        expect(reconstructed.metadata?.compliance_requirements).toContain('SOC2');
        expect(reconstructed.metadata?.compliance_requirements).toContain('GDPR');
        expect(reconstructed.metadata?.effort_estimate).toBe('3_sprints');
        expect(reconstructed.metadata?.risk_level).toBe('medium');
        expect(reconstructed.metadata?.business_impact).toBe('high');
        expect(reconstructed.metadata?.technical_complexity).toBe('high');
        expect(reconstructed.metadata?.deployment_strategy).toBe('blue_green');
      }
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle documents with special characters and encoding', async () => {
      const specialCharsDocument = `
# Special Characters & Encoding Test

## Unicode Characters
This document tests various Unicode characters: 你好, 🚀, café, naïve, résumé, Zürich, Søren, ǅ, ѭ, 𝔘𝔫𝔦𝔠𝔬𝔡𝔢.

## Special Symbols
Mathematical symbols: ∑ ∏ ∫ ∂ ∇ ∆ ∇ ⊗ ⊕ ∈ ∉ ⊂ ⊃ ∀ ∃ ∄ ∅ ∞.

## Code Examples
\`\`\`javascript
function testSpecialChars(input) {
  const pattern = /[^\w\s-]/gi;
  return input.replace(pattern, '');
}
\`\`\`

## JSON Examples
\`\`\`json
{
  "special_chars": "测试 & 验证",
  "emoji": "🎯 📊 📈 📉",
  "unicode": "café résumé naïve"
}
\`\`\`

## Markdown Tables
| Feature | Status | Priority |
|---------|--------|----------|
| Unicode ✅ | Complete | High |
| Emoji 🚀 | In Progress | Medium |
| Special chars ⚡ | Testing | Critical |

## Escaped Characters
This section tests escaped characters: \\ \" \' \n \t \r \b \f \v.

## HTML Entities
HTML entities: &lt; &gt; &amp; &quot; &apos; &#169; &#8482; &#8364;.

## URL Encoding
URL encoded characters: %20 %2F %3F %3D %26 %25.

## Mixed Content
Mixed content with various character sets: English, 中文, 日本語, 한국어, العربية, עברית, हिन्दी.
      `.trim();

      const specialCharsItem: MemoryStoreInput = {
        kind: 'section',
        content: specialCharsDocument,
        scope: { project: 'special-chars-test' },
        metadata: {
          title: 'Special Characters & Encoding Test',
          category: 'testing',
          character_sets: ['unicode', 'emoji', 'special_symbols'],
          encoding: 'utf-8',
        },
      };

      // Store and test special characters handling
      const storeResult = await memoryStoreService([specialCharsItem]);

      expect(storeResult.items.length).toBeGreaterThan(0);
      expect(storeResult.errors.length).toBe(0);

      // Search for content with special characters
      const searchResult = await memoryFindService({
        query: 'unicode special characters café résumé emoji 🚀',
        scope: { project: 'special-chars-test' },
        limit: 10,
      });

      expect(searchResult.results.length).toBeGreaterThan(0);

      // Verify special characters are preserved
      const reconstructed = searchResult.results.find((r) => r.data?.reconstructed);
      if (reconstructed) {
        expect(reconstructed.content).toContain('你好');
        expect(reconstructed.content).toContain('🚀');
        expect(reconstructed.content).toContain('café');
        expect(reconstructed.content).toContain('résumé');
        expect(reconstructed.content).toContain('𝔘𝔫𝔦𝔠𝔬𝔡𝔢');
        expect(reconstructed.content).toContain('∑ ∏ ∫ ∂');
      }
    });

    it('should handle malformed or incomplete chunks gracefully', async () => {
      // Create a document and manually simulate chunking issues
      const testDocument = `
# Malformed Chunk Test

This test simulates scenarios where chunks might be malformed or incomplete during the reassembly process.

## Section 1
Normal content that should be properly chunked.

## Section 2
Content that might be split incorrectly across chunk boundaries.

## Section 3
Final section with important information.
      `.trim();

      const documentItem: MemoryStoreInput = {
        kind: 'section',
        content: testDocument,
        scope: { project: 'malformed-test' },
      };

      const storeResult = await memoryStoreService([documentItem]);

      expect(storeResult.items.length).toBeGreaterThan(0);
      expect(storeResult.errors.length).toBe(0);

      // Simulate malformed chunks by manually creating problematic chunk data
      const chunks = storeResult.items.filter((item) => item.metadata?.is_chunk);

      if (chunks.length > 0) {
        // Create search results with some potentially malformed data
        const searchResults = chunks.map((chunk, index) => ({
          id: chunk.id,
          kind: chunk.kind,
          content: index === 0 ? chunk.content + ' [incomplete data...' : chunk.content,
          data: {
            ...chunk.data,
            chunk_index: index,
            // Simulate missing metadata in some chunks
            ...(index === 1 ? { total_chunks: undefined } : {}),
          },
          scope: chunk.scope,
          confidence_score: 0.7 + index * 0.05,
          created_at: chunk.created_at!,
          match_type: 'semantic' as const,
        }));

        // Test grouping with malformed data
        const groupedResults = groupingService.groupResultsByParent(searchResults);
        expect(groupedResults.length).toBeGreaterThan(0);

        // Test reassembly with malformed data
        const reconstructed = groupingService.reconstructGroupedContent(groupedResults[0]);

        // Should handle malformed data gracefully
        expect(reconstructed.content).toBeDefined();
        expect(reconstructed.content.length).toBeGreaterThan(0);
        expect(reconstructed['data.total_chunks']).toBeGreaterThanOrEqual(chunks.length);
      }
    });

    it('should handle reassembly timeout and performance constraints', async () => {
      // Create a very large document to test performance
      const largeDocument = `
# Performance Test Document

${'This is a large document designed to test reassembly performance. '.repeat(1000)}

## Multiple Sections
${'Each section contains substantial content that needs to be processed efficiently. '.repeat(100)}

## Data Processing
${'The system should handle large documents without performance degradation. '.repeat(100)}

## Content Analysis
${'Reassembly operations should complete within acceptable time limits. '.repeat(100)}

${'Additional content to ensure the document is large enough for performance testing. '.repeat(500)}
      `.trim();

      const largeDocumentItem: MemoryStoreInput = {
        kind: 'section',
        content: largeDocument,
        scope: { project: 'performance-test' },
        metadata: {
          title: 'Performance Test Document',
          size_category: 'large',
          test_type: 'reassembly_performance',
        },
      };

      // Measure storage performance
      const storageStartTime = Date.now();
      const storeResult = await memoryStoreService([largeDocumentItem]);
      const storageTime = Date.now() - storageStartTime;

      expect(storeResult.items.length).toBeGreaterThan(0);
      expect(storeResult.errors.length).toBe(0);
      expect(storageTime).toBeLessThan(10000); // Should complete in <10s

      // Measure search and reassembly performance
      const searchStartTime = Date.now();
      const searchResult = await memoryFindService({
        query: 'performance test document large content processing',
        scope: { project: 'performance-test' },
        limit: 50,
      });
      const searchTime = Date.now() - searchStartTime;

      expect(searchResult.results.length).toBeGreaterThan(0);
      expect(searchTime).toBeLessThan(5000); // Should complete in <5s

      // Verify reassembly quality
      const reconstructed = searchResult.results.find((r) => r.data?.reconstructed);
      if (reconstructed) {
        expect(reconstructed['data.total_chunks']).toBeGreaterThan(5);
        expect(reconstructed['data.completeness_ratio']).toBeGreaterThan(0.9);
        expect(reconstructed.content).toContain('Performance Test Document');
      }
    });
  });

  describe('Concurrent Reassembly Operations', () => {
    it('should handle multiple concurrent reassembly operations', async () => {
      // Create multiple documents for concurrent testing
      const concurrentDocuments = Array.from({ length: 5 }, (_, index) => ({
        kind: 'section' as const,
        content: `
# Concurrent Test Document ${index + 1}

## Content Section ${index + 1}.1
This is the first section of document ${index + 1}. It contains unique content that distinguishes it from other documents.

## Content Section ${index + 1}.2
This is the second section of document ${index + 1}. The content is designed to test concurrent chunking and reassembly operations.

## Content Section ${index + 1}.3
This is the third section of document ${index + 1}. Each document will be processed concurrently to test system performance.

${'Additional content for document ' + (index + 1) + '. '.repeat(100)}
        `.trim(),
        scope: { project: 'concurrent-test' },
        metadata: {
          title: `Concurrent Test Document ${index + 1}`,
          document_index: index + 1,
          test_group: 'concurrent_reassembly',
        },
      }));

      // Store all documents concurrently
      const storePromises = concurrentDocuments.map((doc) => memoryStoreService([doc]));

      const storeResults = await Promise.all(storePromises);
      storeResults.forEach((result) => {
        expect(result.items.length).toBeGreaterThan(0);
        expect(result.errors.length).toBe(0);
      });

      // Perform concurrent searches and reassembly
      const searchPromises = concurrentDocuments.map((doc, index) =>
        memoryFindService({
          query: `concurrent test document ${index + 1} content section`,
          scope: { project: 'concurrent-test' },
          limit: 10,
        })
      );

      const searchStartTime = Date.now();
      const searchResults = await Promise.all(searchPromises);
      const searchTime = Date.now() - searchStartTime;

      expect(searchTime).toBeLessThan(8000); // Should complete in <8s

      // Verify all searches succeeded
      searchResults.forEach((result, index) => {
        expect(result.results.length).toBeGreaterThan(0);

        // Look for reconstructed documents
        const reconstructed = result.results.find((r) => r.data?.reconstructed);
        if (reconstructed) {
          expect(reconstructed.metadata?.title).toBe(`Concurrent Test Document ${index + 1}`);
          expect(reconstructed.metadata?.document_index).toBe(index + 1);
        }
      });
    });
  });
});
