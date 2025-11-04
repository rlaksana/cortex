/**
 * Integration Tests - Qdrant Unavailable (Degraded Path)
 *
 * Tests system resilience and graceful degradation when Qdrant vector database
 * is unavailable. These tests verify fallback mechanisms and core functionality
 * remains operational even without vector search capabilities.
 */

import { describe, it, expect, beforeEach, afterEach, beforeAll, afterAll, vi } from 'vitest';
import { DatabaseManager } from '../../src/db/database-manager.js';
import { ChunkingService } from '../../src/services/chunking/chunking-service.js';
import { MemoryStoreService } from '../../src/services/memory-store.service.js';
import { MemoryFindService } from '../../src/services/memory-find.service.js';
import { MockEmbeddingService } from '../utils/mock-embedding-service.js';
import { createMockSemanticAnalyzer } from '../utils/mock-semantic-analyzer.js';
import { mockQdrantClient } from '../mocks/database.js';
import { MemoryStoreInput, MemoryFindInput } from '../../src/types/core-interfaces.js';

// Mock Qdrant client to simulate failures
const mockFailingQdrantClient = {
  ...mockQdrantClient,
  // Simulate connection failures
  healthCheck: vi.fn().mockRejectedValue(new Error('Connection refused: Qdrant unavailable')),
  getCollections: vi.fn().mockRejectedValue(new Error('Connection timeout')),
  createCollection: vi.fn().mockRejectedValue(new Error('Database unavailable')),
  upsert: vi.fn().mockRejectedValue(new Error('Write operation failed')),
  search: vi.fn().mockRejectedValue(new Error('Search operation failed')),
  retrieve: vi.fn().mockRejectedValue(new Error('Read operation failed')),
  delete: vi.fn().mockRejectedValue(new Error('Delete operation failed')),
  count: vi.fn().mockRejectedValue(new Error('Count operation failed')),
  scroll: vi.fn().mockRejectedValue(new Error('Scroll operation failed')),
  update: vi.fn().mockRejectedValue(new Error('Update operation failed')),
};

describe('Integration Tests - Qdrant Unavailable (Degraded Path)', () => {
  let databaseManager: DatabaseManager;
  let chunkingService: ChunkingService;
  let memoryStoreService: MemoryStoreService;
  let memoryFindService: MemoryFindService;
  let embeddingService: MockEmbeddingService;

  beforeAll(async () => {
    // Initialize services with degraded path configuration
    embeddingService = new MockEmbeddingService({
      shouldFail: false,
      latency: 10, // Lower latency for fallback testing
    });

    // Initialize database manager with fallback enabled
    databaseManager = new DatabaseManager({
      qdrant: {
        url: 'http://localhost:6334', // Non-existent port to simulate failure
        apiKey: process.env.QDRANT_API_KEY,
        timeout: 5000, // Short timeout for faster failure detection
      },
      enableVectorOperations: true,
      enableFallback: true, // Critical for degraded path testing
      fallbackStore: {
        type: 'memory', // In-memory fallback
        maxSize: 10000,
      },
    });

    // Override the Qdrant client with failing mock
    (databaseManager as any).qdrantClient = mockFailingQdrantClient;

    // Initialize services
    chunkingService = new ChunkingService(
      databaseManager,
      embeddingService,
      undefined,
    );

    // Replace semantic analyzer with mock
    const mockSemanticAnalyzer = createMockSemanticAnalyzer(embeddingService as any, {
      shouldFail: false,
    });
    (chunkingService as any).semanticAnalyzer = mockSemanticAnalyzer;

    memoryStoreService = new MemoryStoreService(databaseManager, chunkingService);
    memoryFindService = new MemoryFindService(databaseManager);
  });

  beforeEach(async () => {
    // Reset mocks before each test
    vi.clearAllMocks();

    // Ensure we're in degraded mode
    try {
      const healthCheck = await databaseManager.healthCheck();
      // If health check passes, we're not properly simulating failure
      if (healthCheck) {
        console.warn('Database health check passed - degraded path test may not be accurate');
      }
    } catch (error) {
      // Expected - database should be unavailable
    }
  });

  afterEach(async () => {
    // Clean up fallback storage if needed
    try {
      if ((databaseManager as any).fallbackStore) {
        await (databaseManager as any).fallbackStore.clear();
      }
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

  describe('Degraded Mode Detection and Fallback', () => {
    it('should detect Qdrant unavailability and activate fallback mode', async () => {
      // Health check should fail
      await expect(databaseManager.healthCheck()).rejects.toThrow();

      // Database manager should be in degraded mode
      const connectionInfo = await databaseManager.getConnectionInfo();
      expect(connectionInfo.status).toBe('degraded');
      expect(connectionInfo.fallback_active).toBe(true);
    });

    it('should gracefully handle storage operations in degraded mode', async () => {
      const testItems: MemoryStoreInput[] = [
        {
          kind: 'entity',
          content: 'Test entity stored in degraded mode',
          scope: { project: 'degraded-test' },
          metadata: { test_mode: 'degraded_storage' },
        },
        {
          kind: 'decision',
          content: 'Technical decision made during system degradation',
          scope: { project: 'degraded-test' },
          metadata: { test_mode: 'degraded_storage', decision_type: 'contingency' },
        },
      ];

      // Storage should succeed using fallback mechanism
      const storeResult = await memoryStoreService.store({
        items: testItems,
      });

      expect(storeResult.success).toBe(true);
      expect(storeResult.stored_count).toBe(2);
      expect(storeResult.fallback_used).toBe(true);
      expect(storeResult.items).toHaveLength(2);

      // Items should have fallback-specific metadata
      storeResult.items.forEach(item => {
        expect(item.metadata?.fallback_storage).toBe(true);
        expect(item.metadata?.storage_timestamp).toBeDefined();
      });
    });

    it('should handle search operations with keyword-based fallback', async () => {
      // Store test data first
      const testData: MemoryStoreInput[] = [
        {
          kind: 'entity',
          content: 'User authentication system with OAuth 2.0 implementation',
          scope: { project: 'search-test' },
        },
        {
          kind: 'process',
          content: 'Database backup and recovery procedures for disaster scenarios',
          scope: { project: 'search-test' },
        },
        {
          kind: 'observation',
          content: 'Performance metrics show 95th percentile response time under 200ms',
          scope: { project: 'search-test' },
        },
      ];

      await memoryStoreService.store({
        items: testData,
      });

      // Search should fall back to keyword matching
      const searchResult = await memoryFindService.find({
        query: 'OAuth authentication user',
        scope: { project: 'search-test' },
        limit: 10,
      });

      expect(searchResult.results.length).toBeGreaterThan(0);
      expect(searchResult.fallback_mode).toBe(true);
      expect(searchResult.search_strategy).toBe('keyword');

      // Results should be based on keyword matching, not semantic similarity
      const relevantResult = searchResult.results.find(r =>
        r.content.toLowerCase().includes('oauth') ||
        r.content.toLowerCase().includes('authentication')
      );
      expect(relevantResult).toBeDefined();

      // Confidence scores should be based on keyword matching, not vector similarity
      searchResult.results.forEach(result => {
        expect(result.confidence_score).toBeGreaterThan(0);
        expect(result.confidence_score).toBeLessThanOrEqual(1.0);
      });
    });

    it('should preserve data consistency across storage and retrieval in degraded mode', async () => {
      const consistencyTestItem: MemoryStoreInput = {
        kind: 'section',
        content: `
# Consistency Test Document

This document tests data consistency preservation in degraded mode.

## Section 1: Content Preservation
All content should be preserved exactly as stored, without data loss or corruption.

## Section 2: Metadata Integrity
Metadata fields should be maintained accurately throughout storage and retrieval operations.

## Section 3: Scope Isolation
Scope boundaries should be respected even in degraded mode to prevent data leakage.

## Section 4: Type Information
Knowledge item types should be preserved for proper categorization and filtering.

This comprehensive test ensures that even without vector database capabilities, the system maintains data integrity and provides reliable knowledge management functionality.
        `.trim(),
        scope: { project: 'consistency-test', branch: 'main' },
        metadata: {
          title: 'Consistency Test Document',
          category: 'testing',
          priority: 'high',
          tags: ['consistency', 'integrity', 'degraded-mode'],
          test_timestamp: new Date().toISOString(),
        },
      };

      // Store the document
      const storeResult = await memoryStoreService.store({
        items: [consistencyTestItem],
      });

      expect(storeResult.success).toBe(true);
      const storedItem = storeResult.items[0];

      // Retrieve the document
      const retrieveResult = await memoryFindService.find({
        query: 'consistency test document content preservation',
        scope: { project: 'consistency-test' },
        limit: 1,
      });

      expect(retrieveResult.results.length).toBe(1);
      const retrievedItem = retrieveResult.results[0];

      // Verify content consistency
      expect(retrievedItem.content).toBe(storedItem.content);
      expect(retrievedItem.kind).toBe(storedItem.kind);
      expect(retrievedItem.scope).toEqual(storedItem.scope);

      // Verify metadata consistency
      expect(retrievedItem.metadata?.title).toBe('Consistency Test Document');
      expect(retrievedItem.metadata?.category).toBe('testing');
      expect(retrievedItem.metadata?.priority).toBe('high');
      expect(retrievedItem.metadata?.tags).toEqual(['consistency', 'integrity', 'degraded-mode']);
      expect(retrievedItem.metadata?.test_timestamp).toBeDefined();
    });
  });

  describe('Search Capabilities in Degraded Mode', () => {
    it('should provide meaningful search results using keyword matching', async () => {
      // Prepare diverse content for keyword search testing
      const keywordTestData: MemoryStoreInput[] = [
        {
          kind: 'entity',
          content: 'Payment processing gateway integration with Stripe API for credit card transactions',
          scope: { project: 'payment-system' },
        },
        {
          kind: 'process',
          content: 'User registration flow with email verification and password strength validation',
          scope: { project: 'payment-system' },
        },
        {
          kind: 'observation',
          content: 'System performance metrics show average response time of 150ms for API endpoints',
          scope: { project: 'payment-system' },
        },
        {
          kind: 'decision',
          content: 'Technical decision to migrate from monolithic to microservices architecture',
          scope: { project: 'payment-system' },
        },
        {
          kind: 'risk',
          content: 'Security risk assessment identifies potential SQL injection vulnerabilities',
          scope: { project: 'payment-system' },
        },
      ];

      await memoryStoreService.store({
        items: keywordTestData,
      });

      // Test various keyword search scenarios
      const keywordSearches = [
        { query: 'payment processing stripe', expectedKeywords: ['payment', 'stripe'] },
        { query: 'user registration email', expectedKeywords: ['user', 'registration', 'email'] },
        { query: 'performance response time', expectedKeywords: ['performance', 'response', 'time'] },
        { query: 'microservices architecture migration', expectedKeywords: ['microservices', 'architecture'] },
        { query: 'security sql injection', expectedKeywords: ['security', 'sql', 'injection'] },
      ];

      for (const { query, expectedKeywords } of keywordSearches) {
        const searchResult = await memoryFindService.find({
          query,
          scope: { project: 'payment-system' },
          limit: 5,
        });

        expect(searchResult.results.length).toBeGreaterThan(0);
        expect(searchResult.fallback_mode).toBe(true);

        // Verify keyword matching worked correctly
        const hasExpectedKeywords = searchResult.results.some(result =>
          expectedKeywords.some(keyword =>
            result.content.toLowerCase().includes(keyword.toLowerCase())
          )
        );
        expect(hasExpectedKeywords).toBe(true);

        // Verify results are ranked by keyword relevance
        if (searchResult.results.length > 1) {
          const firstResult = searchResult.results[0];
          const firstContent = firstResult.content.toLowerCase();

          // First result should contain more query keywords
          const firstKeywordCount = expectedKeywords.filter(keyword =>
            firstContent.includes(keyword.toLowerCase())
          ).length;

          expect(firstKeywordCount).toBeGreaterThan(0);
        }
      }
    });

    it('should handle complex queries with multiple search terms', async () => {
      const complexTestData: MemoryStoreInput[] = [
        {
          kind: 'section',
          content: 'The system architecture follows event-driven design patterns with Kafka message queues',
          scope: { project: 'architecture-docs' },
        },
        {
          kind: 'section',
          content: 'Database design uses PostgreSQL for relational data and MongoDB for document storage',
          scope: { project: 'architecture-docs' },
        },
        {
          kind: 'section',
          content: 'API gateway implements rate limiting and authentication using JWT tokens',
          scope: { project: 'architecture-docs' },
        },
        {
          kind: 'section',
          content: 'Container orchestration managed by Kubernetes with Helm chart deployments',
          scope: { project: 'architecture-docs' },
        },
        {
          kind: 'section',
          content: 'Monitoring and logging implemented using Prometheus, Grafana, and ELK stack',
          scope: { project: 'architecture-docs' },
        },
      ];

      await memoryStoreService.store({
        items: complexTestData,
      });

      // Test complex multi-term queries
      const complexQueries = [
        'kubernetes container orchestration helm deployments',
        'postgresql mongodb database design storage',
        'prometheus grafana monitoring logging elk',
        'kafka event-driven message queues architecture',
        'api gateway rate limiting authentication jwt',
      ];

      for (const query of complexQueries) {
        const searchResult = await memoryFindService.find({
          query,
          scope: { project: 'architecture-docs' },
          limit: 3,
        });

        expect(searchResult.results.length).toBeGreaterThan(0);

        // Verify query terms are found in results
        const queryTerms = query.toLowerCase().split(' ');
        const resultContents = searchResult.results.map(r => r.content.toLowerCase());

        // Each query should find at least one matching term
        const hasMatchingTerms = queryTerms.some(term =>
          resultContents.some(content => content.includes(term))
        );
        expect(hasMatchingTerms).toBe(true);
      }
    });

    it('should support type-based filtering in degraded mode', async () => {
      const filteredTestData: MemoryStoreInput[] = [
        {
          kind: 'entity',
          content: 'User service manages authentication and authorization',
          scope: { project: 'filter-test' },
        },
        {
          kind: 'relation',
          content: 'User service depends on database for user data storage',
          scope: { project: 'filter-test' },
        },
        {
          kind: 'runbook',
          content: 'User service deployment procedures and troubleshooting steps',
          scope: { project: 'filter-test' },
        },
        {
          kind: 'risk',
          content: 'User service has single point of failure risk with database',
          scope: { project: 'filter-test' },
        },
        {
          kind: 'assumption',
          content: 'We assume database maintains high availability for user operations',
          scope: { project: 'filter-test' },
        },
      ];

      await memoryStoreService.store({
        items: filteredTestData,
      });

      // Test filtering by different types
      const typeFilters = ['entity', 'relation', 'runbook', 'risk', 'assumption'];

      for (const type of typeFilters) {
        const filteredResult = await memoryFindService.find({
          query: 'user service database',
          types: [type],
          scope: { project: 'filter-test' },
          limit: 10,
        });

        expect(filteredResult.results.length).toBeGreaterThan(0);
        expect(filteredResult.results.length).toBeLessThanOrEqual(1); // Should find at most 1 item per type

        // Verify all results are of the specified type
        filteredResult.results.forEach(result => {
          expect(result.kind).toBe(type);
        });
      }
    });
  });

  describe('Chunking and Document Handling in Degraded Mode', () => {
    it('should handle document chunking without vector embeddings', async () => {
      const largeDocument = `
# System Administration Guide

## User Management
User accounts are managed through the admin panel with role-based access control. Administrators can create, modify, and delete user accounts. Users are assigned roles that determine their access permissions to various system resources.

## Security Policies
All users must comply with security policies including password complexity requirements, multi-factor authentication, and regular security training. System access logs are monitored for unusual activity patterns.

## Backup Procedures
Automated backups are performed daily with incremental backups every hour. Full system backups are retained for 30 days, while incremental backups are retained for 7 days. Backup integrity is verified weekly.

## Monitoring and Alerting
System health is monitored 24/7 with automated alerts for critical issues. Performance metrics are collected and analyzed to identify potential problems before they impact users.

## Maintenance Windows
Scheduled maintenance is performed during off-peak hours to minimize user impact. Emergency maintenance may be required for critical security updates or system failures.

## Incident Response
All incidents are documented and analyzed to prevent recurrence. Critical incidents trigger immediate response procedures with dedicated on-call personnel.

## Compliance and Auditing
Regular compliance audits ensure adherence to regulatory requirements. Access logs and system changes are audited quarterly for security and governance purposes.

## Training and Documentation
Comprehensive training materials and documentation are maintained for all system users. Regular training sessions ensure users are aware of system capabilities and security best practices.
      `.trim();

      const documentItem: MemoryStoreInput = {
        kind: 'section',
        content: largeDocument,
        scope: { project: 'admin-guide' },
        metadata: {
          title: 'System Administration Guide',
          category: 'documentation',
          target_audience: 'administrators',
        },
      };

      // Store large document in degraded mode
      const storeResult = await memoryStoreService.store({
        items: [documentItem],
      });

      expect(storeResult.success).toBe(true);
      expect(storeResult.fallback_used).toBe(true);

      // Should still chunk the document even without vector capabilities
      expect(storeResult.items.length).toBeGreaterThan(1);

      // Verify chunking metadata is preserved
      const chunks = storeResult.items.filter(item => item.metadata?.is_chunk);
      const parent = storeResult.items.find(item => !item.metadata?.is_chunk);

      expect(chunks.length).toBeGreaterThan(0);
      expect(parent).toBeDefined();
      expect(parent?.metadata?.total_chunks).toBe(chunks.length);

      // Test search across chunks
      const searchResult = await memoryFindService.find({
        query: 'user management security policies',
        scope: { project: 'admin-guide' },
        limit: 10,
      });

      expect(searchResult.results.length).toBeGreaterThan(0);

      // Should find relevant chunks
      const relevantChunks = searchResult.results.filter(result =>
        result.content.toLowerCase().includes('user management') ||
        result.content.toLowerCase().includes('security policies')
      );
      expect(relevantChunks.length).toBeGreaterThan(0);
    });

    it('should handle metadata inheritance in chunked documents during degradation', async () => {
      const richMetadataDocument = `
# Project Requirements Specification

## Functional Requirements
The system shall provide user authentication, role-based access control, and audit logging capabilities. Users must be able to create, read, update, and delete resources based on their assigned permissions.

## Non-Functional Requirements
The system shall respond to user requests within 200ms for 95% of operations. The system shall maintain 99.9% uptime availability and support 1000 concurrent users.

## Technical Requirements
The system shall be built using Node.js with TypeScript, PostgreSQL for data storage, and Redis for caching. The frontend shall use React with TypeScript for type safety.

## Security Requirements
All communications shall be encrypted using TLS 1.3. User passwords shall be hashed using bcrypt with a minimum of 12 rounds. Two-factor authentication shall be required for administrative access.
      `.trim();

      const richMetadataItem: MemoryStoreInput = {
        kind: 'section',
        content: richMetadataDocument,
        scope: {
          project: 'requirements-spec',
          branch: 'main',
          org: 'engineering',
        },
        metadata: {
          title: 'Project Requirements Specification',
          category: 'requirements',
          priority: 'high',
          tags: ['requirements', 'specification', 'project'],
          author: 'product-team',
          review_status: 'approved',
          version: '2.1.0',
          last_updated: new Date().toISOString(),
        },
      };

      // Store with rich metadata
      const storeResult = await memoryStoreService.store({
        items: [richMetadataItem],
      });

      expect(storeResult.success).toBe(true);

      // Verify metadata is preserved in parent and chunks
      const parent = storeResult.items.find(item => !item.metadata?.is_chunk);
      const chunks = storeResult.items.filter(item => item.metadata?.is_chunk);

      expect(parent?.metadata?.title).toBe('Project Requirements Specification');
      expect(parent?.metadata?.category).toBe('requirements');
      expect(parent?.metadata?.author).toBe('product-team');
      expect(parent?.metadata?.version).toBe('2.1.0');

      // Chunks should inherit key metadata
      chunks.forEach(chunk => {
        expect(chunk.metadata?.category).toBe('requirements');
        expect(chunk.metadata?.author).toBe('product-team');
        expect(chunk.metadata?.parent_id).toBe(parent?.id);
        expect(chunk.metadata?.total_chunks).toBe(chunks.length);
        expect(chunk.metadata?.is_chunk).toBe(true);
      });

      // Search should preserve metadata context
      const searchResult = await memoryFindService.find({
        query: 'functional requirements authentication role-based',
        scope: { project: 'requirements-spec' },
        limit: 5,
      });

      expect(searchResult.results.length).toBeGreaterThan(0);

      // Results should contain metadata context
      searchResult.results.forEach(result => {
        if (result.metadata?.is_chunk) {
          expect(result.metadata?.parent_id).toBeDefined();
          expect(result.metadata?.total_chunks).toBeGreaterThan(0);
        }
      });
    });
  });

  describe('Performance and Reliability in Degraded Mode', () => {
    it('should maintain acceptable performance without vector operations', async () => {
      const performanceTestData = Array.from({ length: 50 }, (_, index) => ({
        kind: 'entity' as const,
        content: `Performance test entity ${index}: System handles degraded mode operations efficiently with keyword-based search and in-memory storage`,
        scope: { project: 'performance-degraded' },
        metadata: {
          test_index: index,
          test_category: 'performance',
          timestamp: new Date().toISOString(),
        },
      }));

      // Measure storage performance
      const storageStartTime = Date.now();
      const storeResult = await memoryStoreService.store({
        items: performanceTestData,
      });
      const storageTime = Date.now() - storageStartTime;

      expect(storeResult.success).toBe(true);
      expect(storeResult.stored_count).toBe(50);
      expect(storageTime).toBeLessThan(5000); // Should complete in <5s

      // Measure search performance
      const searchStartTime = Date.now();
      const searchPromises = Array.from({ length: 10 }, (_, index) =>
        memoryFindService.find({
          query: `performance test entity ${index % 5}`,
          scope: { project: 'performance-degraded' },
          limit: 10,
        })
      );

      const searchResults = await Promise.all(searchPromises);
      const searchTime = Date.now() - searchStartTime;

      expect(searchTime).toBeLessThan(2000); // Should complete in <2s

      // Verify search quality
      searchResults.forEach(result => {
        expect(result.results.length).toBeGreaterThan(0);
        expect(result.fallback_mode).toBe(true);
      });
    });

    it('should handle memory constraints gracefully in degraded mode', async () => {
      // Test with larger dataset to stress memory management
      const memoryStressData = Array.from({ length: 200 }, (_, index) => ({
        kind: 'observation' as const,
        content: `Memory stress test observation ${index}: System demonstrates robust memory management during extended degraded mode operations with large datasets and concurrent access patterns`,
        scope: { project: 'memory-stress-test' },
        metadata: {
          test_id: index,
          category: 'memory-stress',
          data_size: 'large',
          created_at: new Date().toISOString(),
        },
      }));

      // Store in batches to test memory management
      const batchSize = 50;
      const batches = [];

      for (let i = 0; i < memoryStressData.length; i += batchSize) {
        batches.push(memoryStressData.slice(i, i + batchSize));
      }

      const batchResults = [];
      for (const batch of batches) {
        const batchResult = await memoryStoreService.store({
          items: batch,
        });
        batchResults.push(batchResult);
        expect(batchResult.success).toBe(true);
      }

      // Verify total storage count
      const totalStored = batchResults.reduce((sum, result) => sum + result.stored_count, 0);
      expect(totalStored).toBe(200);

      // Test search performance with large dataset
      const largeDatasetSearch = await memoryFindService.find({
        query: 'memory stress test observation',
        scope: { project: 'memory-stress-test' },
        limit: 20,
      });

      expect(largeDatasetSearch.results.length).toBe(20); // Should return requested limit
      expect(largeDatasetSearch.fallback_mode).toBe(true);

      // Results should be properly ranked
      if (largeDatasetSearch.results.length > 1) {
        for (let i = 0; i < largeDatasetSearch.results.length - 1; i++) {
          expect(largeDatasetSearch.results[i].confidence_score)
            .toBeGreaterThanOrEqual(largeDatasetSearch.results[i + 1].confidence_score);
        }
      }
    });

    it('should recover gracefully when vector database becomes available', async () => {
      // Start in degraded mode
      expect(databaseManager.healthCheck()).rejects.toThrow();

      // Store some data in degraded mode
      const degradedData: MemoryStoreInput[] = [
        {
          kind: 'entity',
          content: 'Data stored during degraded mode operation',
          scope: { project: 'recovery-test' },
          metadata: { stored_during: 'degraded_mode' },
        },
      ];

      const degradedStoreResult = await memoryStoreService.store({
        items: degradedData,
      });

      expect(degradedStoreResult.success).toBe(true);
      expect(degradedStoreResult.fallback_used).toBe(true);

      // Simulate database recovery by restoring mock functionality
      (databaseManager as any).qdrantClient = mockQdrantClient;

      // Wait a moment for recovery detection
      await new Promise(resolve => setTimeout(resolve, 100));

      // Test that system recovers and can use both fallback and primary storage
      const recoveryData: MemoryStoreInput[] = [
        {
          kind: 'entity',
          content: 'Data stored after recovery to primary storage',
          scope: { project: 'recovery-test' },
          metadata: { stored_during: 'recovered_mode' },
        },
      ];

      const recoveryStoreResult = await memoryStoreService.store({
        items: recoveryData,
      });

      expect(recoveryStoreResult.success).toBe(true);

      // Search should work across both storage mechanisms
      const searchResult = await memoryFindService.find({
        query: 'data stored recovery test',
        scope: { project: 'recovery-test' },
        limit: 10,
      });

      expect(searchResult.results.length).toBe(2); // Should find both items
    });
  });

  describe('Error Handling and Resilience', () => {
    it('should handle storage failures gracefully without data corruption', async () => {
      // Simulate intermittent storage failures
      const originalStore = (databaseManager as any).store;
      let callCount = 0;

      (databaseManager as any).store = vi.fn().mockImplementation(async (items) => {
        callCount++;
        if (callCount % 3 === 0) {
          throw new Error('Simulated storage failure');
        }
        return originalStore.call(databaseManager, items);
      });

      const testData: MemoryStoreInput[] = Array.from({ length: 10 }, (_, index) => ({
        kind: 'entity' as const,
        content: `Resilience test item ${index}: System handles intermittent failures gracefully`,
        scope: { project: 'resilience-test' },
        metadata: { test_index: index, resilience_test: true },
      }));

      // Store should handle failures gracefully
      const storeResult = await memoryStoreService.store({
        items: testData,
      });

      expect(storeResult.success).toBe(true);
      expect(storeResult.stored_count).toBeGreaterThan(0); // Some items should be stored
      expect(storeResult.failed_count).toBeGreaterThan(0); // Some should fail

      // Verify stored data integrity
      const searchResult = await memoryFindService.find({
        query: 'resilience test item',
        scope: { project: 'resilience-test' },
        limit: 20,
      });

      expect(searchResult.results.length).toBe(storeResult.stored_count);

      // Restore original store function
      (databaseManager as any).store = originalStore;
    });

    it('should provide meaningful error messages and degradation status', async () => {
      // Test detailed error reporting
      const healthStatus = await databaseManager.getDetailedHealthStatus();

      expect(healthStatus.status).toBe('degraded');
      expect(healthStatus.qdrant_connected).toBe(false);
      expect(healthStatus.fallback_active).toBe(true);
      expect(healthStatus.degradation_reason).toBeDefined();
      expect(healthStatus.available_operations).toContain('store');
      expect(healthStatus.available_operations).toContain('find');
      expect(healthStatus.limited_operations).toContain('semantic_search');
      expect(healthStatus.limited_operations).toContain('vector_operations');

      // Test operations with detailed status
      const testItem: MemoryStoreInput = {
        kind: 'entity',
        content: 'Status test item',
        scope: { project: 'status-test' },
      };

      const storeResult = await memoryStoreService.store({
        items: [testItem],
      });

      expect(storeResult.operation_status).toBeDefined();
      expect(storeResult.operation_status.mode).toBe('degraded');
      expect(storeResult.operation_status.fallback_used).toBe(true);
      expect(storeResult.operation_status.performance_impact).toBeDefined();
    });
  });
});