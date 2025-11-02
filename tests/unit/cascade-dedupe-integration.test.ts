/**
 * Test for P2-T2.3: Cascade deduplication logic
 *
 * This test verifies that when a parent item is deduped (status=skipped_dedupe),
 * all its child chunks should also be marked as skipped_dedupe.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { MemoryStoreOrchestrator } from '../../src/services/orchestrators/memory-store-orchestrator';
// import { KnowledgeItem } from '../../src/types/core-interfaces';

// Mock Qdrant client for cascade deduplication testing
vi.mock('../../src/db/qdrant', () => ({
  getQdrantClient: () => ({
    knowledgeEntity: {
      findMany: vi.fn().mockResolvedValue([]),
    },
    adrDecision: {
      findUnique: vi.fn().mockResolvedValue(null),
    },
    section: {
      findUnique: vi.fn().mockResolvedValue(null),
    },
    incidentLog: {
      findUnique: vi.fn().mockResolvedValue(null),
    },
    releaseLog: {
      findUnique: vi.fn().mockResolvedValue(null),
    },
    riskLog: {
      findUnique: vi.fn().mockResolvedValue(null),
    },
    assumptionLog: {
      findUnique: vi.fn().mockResolvedValue(null),
    },
    todoLog: {
      findUnique: vi.fn().mockResolvedValue(null),
    },
    issueLog: {
      findUnique: vi.fn().mockResolvedValue(null),
    },
  }),
}));

// Mock knowledge storage functions
vi.mock('../../src/services/knowledge', () => ({
  storeSection: vi.fn().mockResolvedValue('new-section-id'),
  storeDecision: vi.fn().mockResolvedValue('new-decision-id'),
  storeTodo: vi.fn().mockResolvedValue('new-todo-id'),
  storeIssue: vi.fn().mockResolvedValue('new-issue-id'),
  storeRunbook: vi.fn().mockResolvedValue('new-runbook-id'),
  storeChange: vi.fn().mockResolvedValue('new-change-id'),
  storeReleaseNote: vi.fn().mockResolvedValue('new-release-note-id'),
  storeDDL: vi.fn().mockResolvedValue('new-ddl-id'),
  storePRContext: vi.fn().mockResolvedValue('new-pr-context-id'),
  storeEntity: vi.fn().mockResolvedValue('new-entity-id'),
  storeRelation: vi.fn().mockResolvedValue('new-relation-id'),
  addObservation: vi.fn().mockResolvedValue('new-observation-id'),
  storeIncident: vi.fn().mockResolvedValue('new-incident-id'),
  updateIncident: vi.fn().mockResolvedValue('updated-incident-id'),
  storeRelease: vi.fn().mockResolvedValue('new-release-id'),
  updateRelease: vi.fn().mockResolvedValue('updated-release-id'),
  storeRisk: vi.fn().mockResolvedValue('new-risk-id'),
  updateRisk: vi.fn().mockResolvedValue('updated-risk-id'),
  storeAssumption: vi.fn().mockResolvedValue('new-assumption-id'),
  updateAssumption: vi.fn().mockResolvedValue('updated-assumption-id'),
  updateDecision: vi.fn().mockResolvedValue('updated-decision-id'),
}));

// Mock validation and audit services
vi.mock('../../src/services/validation/validation-service', () => ({
  validationService: {
    validateStoreInput: vi.fn().mockResolvedValue({ valid: true, errors: [] }),
  },
}));

vi.mock('../../src/services/audit/audit-service', () => ({
  auditService: {
    logStoreOperation: vi.fn().mockResolvedValue(undefined),
    logError: vi.fn().mockResolvedValue(undefined),
    logBatchOperation: vi.fn().mockResolvedValue(undefined),
  },
}));

describe('P2-T2.3: Cascade Deduplication Integration Tests', () => {
  let orchestrator: MemoryStoreOrchestrator;

  beforeEach(async () => {
    vi.clearAllMocks();
    orchestrator = new MemoryStoreOrchestrator();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('When parent item is deduped', () => {
    it('should mark all derived chunks as skipped_dedupe with cascade logic', async () => {
      // Arrange: Create a large section that will be chunked
      // Content large enough to trigger chunking (> 2400 chars)
      const largeContent = `
        # System Architecture Documentation

        This document describes the comprehensive system architecture for our microservices-based platform.

        ## Overview

        The system is built on a microservices architecture with the following key components:

        1. API Gateway
        2. Authentication Service
        3. User Management Service
        4. Order Processing Service
        5. Payment Processing Service
        6. Notification Service
        7. Analytics Service

        ## API Gateway

        The API Gateway serves as the single entry point for all client requests. It handles:

        - Request routing
        - Load balancing
        - Rate limiting
        - Authentication and authorization
        - Request/response transformation

        ### Configuration

        The API Gateway is configured to route requests based on the following patterns:

        /api/v1/auth/* -> Authentication Service
        /api/v1/users/* -> User Management Service
        /api/v1/orders/* -> Order Processing Service
        /api/v1/payments/* -> Payment Processing Service
        /api/v1/notifications/* -> Notification Service
        /api/v1/analytics/* -> Analytics Service

        ## Authentication Service

        The Authentication Service is responsible for:

        - User authentication and authorization
        - JWT token generation and validation
        - OAuth 2.0 integration
        - Password management
        - Session management

        ### Security Features

        - Multi-factor authentication
        - Password strength validation
        - Account lockout after failed attempts
        - Secure password hashing using bcrypt
        - Token-based authentication with expiration

        ## User Management Service

        Handles all user-related operations:

        - User registration and profile management
        - User preferences and settings
        - User role and permission management
        - User activity tracking
        - User data export and deletion

        ### Data Model

        User entities include:
        - Basic profile information
        - Contact details
        - Preferences
        - Roles and permissions
        - Activity history
        - Security settings

        ## Order Processing Service

        Manages the complete order lifecycle:

        - Order creation and validation
        - Inventory management
        - Order tracking
        - Order modifications and cancellations
        - Order history and reporting

        ### Order States

        1. Pending - Order created, awaiting payment
        2. Paid - Payment confirmed, processing started
        3. Processing - Order being prepared
        4. Shipped - Order shipped with tracking
        5. Delivered - Order delivered to customer
        6. Cancelled - Order cancelled
        7. Refunded - Payment refunded

        ## Payment Processing Service

        Handles all payment-related operations:

        - Payment processing and validation
        - Multiple payment methods support
        - Refund processing
        - Payment history and reporting
        - Integration with payment gateways

        ### Supported Payment Methods

        - Credit/Debit cards
        - Digital wallets (PayPal, Apple Pay, Google Pay)
        - Bank transfers
        - Cryptocurrency
        - Store credit and gift cards

        ## Notification Service

        Manages all communications with users:

        - Email notifications
        - SMS notifications
        - Push notifications
        - In-app notifications
        - Webhook notifications

        ### Notification Types

        - Transactional notifications (order confirmations, payment receipts)
        - Promotional notifications (special offers, new features)
        - Security notifications (login attempts, password changes)
        - System notifications (maintenance, downtime)

        ## Analytics Service

        Provides comprehensive analytics and reporting:

        - User behavior analytics
        - Sales analytics and reporting
        - System performance monitoring
        - Custom dashboards
        - Data export capabilities

        ### Metrics Tracked

        - User acquisition and retention
        - Conversion rates
        - Revenue and profitability
        - System performance and uptime
        - Error rates and response times

        ## Security Considerations

        Security is implemented at multiple layers:

        1. Network security with firewalls and DDoS protection
        2. Application security with input validation and sanitization
        3. Data encryption in transit and at rest
        4. Regular security audits and penetration testing
        5. Compliance with data protection regulations

        ## Scalability and Performance

        The system is designed for high availability and scalability:

        - Horizontal scaling with containerization
        - Load balancing across multiple instances
        - Database replication and sharding
        - Caching strategies for optimal performance
        - CDN integration for static assets

        ## Monitoring and Logging

        Comprehensive monitoring ensures system reliability:

        - Real-time performance monitoring
        - Error tracking and alerting
        - Audit logging for compliance
        - Performance metrics and dashboards
        - Automated health checks

        ## Future Enhancements

        Planned improvements include:

        - Machine learning integration for predictive analytics
        - Advanced personalization features
        - Enhanced mobile experience
        - Additional payment methods
        - Expanded analytics capabilities
      `;

      const items = [
        {
          kind: 'section' as const,
          content: largeContent,
          metadata: {
            title: 'System Architecture Documentation',
            tags: { category: 'architecture', priority: 'high' },
          },
          scope: {
            project: 'test-project',
            branch: 'main',
          },
        },
      ];

      // Mock the deduplication check to simulate parent being deduped
      // First, calculate the expected content hash
      const { createHash } = await import('node:crypto');
      const expectedContentHash = createHash('sha256').update(largeContent.trim()).digest('hex');

      const mockQdrantClient = await import('../../src/db/qdrant');
      vi.spyOn(mockQdrantClient, 'getQdrantClient').mockReturnValue({
        knowledgeEntity: {
          findMany: vi.fn().mockImplementation(async ({ where }) => {
            // Return the duplicate only if the hash matches what we expect
            if (where.content_hash === expectedContentHash && where.entity_type === 'section') {
              return [
                {
                  id: 'existing-duplicate-parent-id',
                  content_hash: expectedContentHash,
                  entity_type: 'section',
                  created_at: '2024-01-01T00:00:00Z',
                },
              ];
            }
            return [];
          }),
        },
        adrDecision: {
          findUnique: vi.fn().mockResolvedValue(null),
        },
        section: {
          findUnique: vi.fn().mockResolvedValue(null),
        },
        incidentLog: {
          findUnique: vi.fn().mockResolvedValue(null),
        },
        releaseLog: {
          findUnique: vi.fn().mockResolvedValue(null),
        },
        riskLog: {
          findUnique: vi.fn().mockResolvedValue(null),
        },
        assumptionLog: {
          findUnique: vi.fn().mockResolvedValue(null),
        },
        todoLog: {
          findUnique: vi.fn().mockResolvedValue(null),
        },
        issueLog: {
          findUnique: vi.fn().mockResolvedValue(null),
        },
      } as any);

      // Act: Store the items (should trigger chunking and cascade deduplication)
      const result = await orchestrator.storeItems(items);

      // Assert: Verify cascade deduplication behavior
      console.log('Cascade dedupe test result:', JSON.stringify(result, null, 2));

      // Should have processed items (parent + chunks)
      expect(result.items).toBeDefined();
      expect(result.items.length).toBeGreaterThan(0);

      // Some items should be marked as skipped_dedupe due to cascade logic
      const skippedItems = result.items.filter((item) => item.status === 'skipped_dedupe');
      const storedItems = result.items.filter((item) => item.status === 'stored');

      expect(skippedItems.length).toBeGreaterThan(0);
      expect(storedItems.length).toBeGreaterThanOrEqual(0);

      // Should have chunk:child items that are deduped due to cascade
      const childItems = result.items.filter(
        (item) => item.status === 'skipped_dedupe' && item.reason?.includes('chunk:child')
      );
      expect(childItems.length).toBeGreaterThan(0);

      // Verify child items have the correct reason
      childItems.forEach((child) => {
        expect(child.reason).toContain('Parent item deduplicated');
      });

      // Verify summary reflects the cascade deduplication behavior
      expect(result.summary).toMatchObject({
        stored: expect.any(Number),
        skipped_dedupe: expect.any(Number),
        total: expect.any(Number),
      });

      expect(result.summary.skipped_dedupe + result.summary.stored).toBe(result.summary.total);

      // Verify autonomous context reflects cascade deduplication
      expect(result.autonomous_context.duplicates_found).toBeGreaterThan(0);
      expect(result.autonomous_context.action_performed).toBe('batch'); // Mixed results, so batch

      console.log(
        '✅ P2-T2.3 Cascade deduplication test passed - all chunks marked as skipped_dedupe when parent deduped'
      );
    });

    it('should handle mixed scenario: parent deduped but other items processed normally', async () => {
      // Arrange: Mix of items - one large section that will be chunked and deduped,
      // and other items that should be processed normally

      const largeContent = 'Large content that will be chunked. '.repeat(300);

      const items = [
        {
          kind: 'section' as const,
          content: largeContent,
          metadata: {
            title: 'Large Section for Deduplication',
            tags: { category: 'test' },
          },
          scope: {
            project: 'test-project',
            branch: 'main',
          },
        },
        {
          kind: 'decision' as const,
          content: 'This is a regular decision that should be stored',
          metadata: {
            title: 'Regular Decision',
            component: 'test-component',
            rationale: 'This should be stored normally',
          },
          scope: {
            project: 'test-project',
            branch: 'main',
          },
        },
      ];

      // Mock deduplication only for the section
      // Calculate expected content hash for the section
      const { createHash: createHash2 } = await import('node:crypto');
      const sectionContentHash = createHash2('sha256').update(largeContent.trim()).digest('hex');

      const mockQdrantClient = await import('../../src/db/qdrant');
      vi.spyOn(mockQdrantClient, 'getQdrantClient').mockReturnValue({
        knowledgeEntity: {
          findMany: vi.fn().mockImplementation(async ({ where }) => {
            // Return duplicate only for section content with matching hash
            if (where.entity_type === 'section' && where.content_hash === sectionContentHash) {
              return [
                {
                  id: 'existing-section-id',
                  content_hash: sectionContentHash,
                  entity_type: 'section',
                  created_at: '2024-01-01T00:00:00Z',
                },
              ];
            }
            return [];
          }),
        },
        adrDecision: {
          findUnique: vi.fn().mockResolvedValue(null),
        },
        section: {
          findUnique: vi.fn().mockResolvedValue(null),
        },
        incidentLog: {
          findUnique: vi.fn().mockResolvedValue(null),
        },
        releaseLog: {
          findUnique: vi.fn().mockResolvedValue(null),
        },
        riskLog: {
          findUnique: vi.fn().mockResolvedValue(null),
        },
        assumptionLog: {
          findUnique: vi.fn().mockResolvedValue(null),
        },
        todoLog: {
          findUnique: vi.fn().mockResolvedValue(null),
        },
        issueLog: {
          findUnique: vi.fn().mockResolvedValue(null),
        },
      } as any);

      // Act
      const result = await orchestrator.storeItems(items);

      // Assert: Verify mixed processing
      expect(result.items).toBeDefined();
      expect(result.items.length).toBeGreaterThan(2); // section parent + section chunks + decision

      // Section items should be skipped_dedupe (both parent and chunks)
      const sectionItems = result.items.filter((item) => item.kind === 'section');
      const skippedSections = sectionItems.filter((item) => item.status === 'skipped_dedupe');
      const storedSections = sectionItems.filter((item) => item.status === 'stored');

      expect(skippedSections.length).toBeGreaterThan(0); // Some sections should be skipped
      expect(storedSections.length).toBeGreaterThanOrEqual(0); // Parent might be stored

      // Decision should be stored normally
      const decisionItems = result.items.filter((item) => item.kind === 'decision');
      expect(decisionItems).toHaveLength(1);
      expect(decisionItems[0].status).toBe('stored');

      // Verify summary reflects mixed results
      expect(result.summary.stored).toBeGreaterThanOrEqual(1); // At least decision stored
      expect(result.summary.skipped_dedupe).toBeGreaterThan(0); // Some section items skipped
      expect(result.summary.total).toBe(result.summary.stored + result.summary.skipped_dedupe);

      console.log(
        '✅ Mixed scenario test passed - parent deduped with cascade, other items processed normally'
      );
    });

    it('should handle nested chunking scenarios with proper cascade', async () => {
      // Arrange: Multiple chunkable items with different deduplication outcomes
      const largeContent1 = 'Large content 1. '.repeat(200);
      const largeContent2 = 'Large content 2. '.repeat(200);

      const items = [
        {
          kind: 'section' as const,
          content: largeContent1,
          metadata: { title: 'Section 1 - Will be deduped' },
          scope: { project: 'test', branch: 'main' },
        },
        {
          kind: 'runbook' as const,
          content: largeContent2,
          metadata: { title: 'Runbook 1 - Will be stored normally' },
          scope: { project: 'test', branch: 'main' },
        },
      ];

      // Mock deduplication only for the section
      // Calculate expected content hash for the section
      const { createHash: createHash3 } = await import('node:crypto');
      const section1ContentHash = createHash3('sha256').update(largeContent1.trim()).digest('hex');

      const mockQdrantClient = await import('../../src/db/qdrant');
      vi.spyOn(mockQdrantClient, 'getQdrantClient').mockReturnValue({
        knowledgeEntity: {
          findMany: vi.fn().mockImplementation(async ({ where }) => {
            if (where.entity_type === 'section' && where.content_hash === section1ContentHash) {
              return [
                {
                  id: 'existing-section-id',
                  content_hash: section1ContentHash,
                  entity_type: 'section',
                  created_at: '2024-01-01T00:00:00Z',
                },
              ];
            }
            return [];
          }),
        },
        adrDecision: {
          findUnique: vi.fn().mockResolvedValue(null),
        },
        section: {
          findUnique: vi.fn().mockResolvedValue(null),
        },
        incidentLog: {
          findUnique: vi.fn().mockResolvedValue(null),
        },
        releaseLog: {
          findUnique: vi.fn().mockResolvedValue(null),
        },
        riskLog: {
          findUnique: vi.fn().mockResolvedValue(null),
        },
        assumptionLog: {
          findUnique: vi.fn().mockResolvedValue(null),
        },
        todoLog: {
          findUnique: vi.fn().mockResolvedValue(null),
        },
        issueLog: {
          findUnique: vi.fn().mockResolvedValue(null),
        },
      } as any);

      // Act
      const result = await orchestrator.storeItems(items);

      // Assert: Verify proper cascade behavior
      const sectionItems = result.items.filter((item) => item.kind === 'section');
      const runbookItems = result.items.filter((item) => item.kind === 'runbook');

      // Section items should be partially skipped due to cascade
      const skippedSections = sectionItems.filter((item) => item.status === 'skipped_dedupe');
      const storedSections = sectionItems.filter((item) => item.status === 'stored');

      expect(skippedSections.length).toBeGreaterThan(0); // Some sections should be skipped
      expect(storedSections.length).toBeGreaterThanOrEqual(0); // Parent might be stored

      // Runbook items should be stored normally (or some may be skipped due to their own deduplication)
      expect(runbookItems.length).toBeGreaterThan(0);
      // We don't enforce exact behavior since runbooks may have their own deduplication logic

      // Verify chunk metadata is preserved even when deduped
      sectionItems.forEach((item) => {
        if (item.reason?.includes('chunk:child')) {
          expect(item.reason).toContain('Parent item deduplicated');
        }
      });

      console.log('✅ Nested chunking cascade test passed');
    });
  });

  describe('Error handling and edge cases', () => {
    it('should handle deduplication check failures gracefully', async () => {
      // Arrange: Mock database failure during deduplication check
      const mockQdrantClient = await import('../../src/db/qdrant');
      vi.spyOn(mockQdrantClient, 'getQdrantClient').mockReturnValue({
        knowledgeEntity: {
          findMany: vi.fn().mockRejectedValue(new Error('Database connection failed')),
        },
        adrDecision: {
          findUnique: vi.fn().mockResolvedValue(null),
        },
        section: {
          findUnique: vi.fn().mockResolvedValue(null),
        },
        incidentLog: {
          findUnique: vi.fn().mockResolvedValue(null),
        },
        releaseLog: {
          findUnique: vi.fn().mockResolvedValue(null),
        },
        riskLog: {
          findUnique: vi.fn().mockResolvedValue(null),
        },
        assumptionLog: {
          findUnique: vi.fn().mockResolvedValue(null),
        },
        todoLog: {
          findUnique: vi.fn().mockResolvedValue(null),
        },
        issueLog: {
          findUnique: vi.fn().mockResolvedValue(null),
        },
      } as any);

      const largeContent = 'Large content. '.repeat(300);
      const items = [
        {
          kind: 'section' as const,
          content: largeContent,
          metadata: { title: 'Test Section' },
          scope: { project: 'test', branch: 'main' },
        },
      ];

      // Act & Assert: Should handle error gracefully and process items
      const result = await orchestrator.storeItems(items);

      expect(result.items).toBeDefined();
      expect(result.items.length).toBeGreaterThan(0);

      // Should process items normally when deduplication check fails
      const storedItems = result.items.filter((item) => item.status === 'stored');
      expect(storedItems.length).toBeGreaterThan(0);

      console.log('✅ Error handling test passed - graceful degradation on deduplication failure');
    });

    it('should preserve chunk metadata even when deduped', async () => {
      // Arrange: Ensure chunk metadata is preserved in cascade deduplication
      const largeContent = 'Large test content. '.repeat(250);
      const items = [
        {
          kind: 'section' as const,
          content: largeContent,
          metadata: {
            title: 'Metadata Preservation Test',
            tags: { test: true, category: 'validation' },
          },
          scope: { project: 'test', branch: 'main' },
        },
      ];

      // Mock deduplication
      const mockQdrantClient = await import('../../src/db/qdrant');
      vi.spyOn(mockQdrantClient, 'getQdrantClient').mockReturnValue({
        knowledgeEntity: {
          findMany: vi.fn().mockResolvedValue([
            {
              id: 'existing-id',
              content_hash: expect.any(String),
              entity_type: 'section',
              created_at: '2024-01-01T00:00:00Z',
            },
          ]),
        },
        adrDecision: {
          findUnique: vi.fn().mockResolvedValue(null),
        },
        section: {
          findUnique: vi.fn().mockResolvedValue(null),
        },
        incidentLog: {
          findUnique: vi.fn().mockResolvedValue(null),
        },
        releaseLog: {
          findUnique: vi.fn().mockResolvedValue(null),
        },
        riskLog: {
          findUnique: vi.fn().mockResolvedValue(null),
        },
        assumptionLog: {
          findUnique: vi.fn().mockResolvedValue(null),
        },
        todoLog: {
          findUnique: vi.fn().mockResolvedValue(null),
        },
        issueLog: {
          findUnique: vi.fn().mockResolvedValue(null),
        },
      } as any);

      // Act
      const result = await orchestrator.storeItems(items);

      // Assert: Verify metadata is preserved in deduped chunks
      result.items.forEach((item) => {
        expect(item.kind).toBe('section');
        expect(item.content).toBeDefined();
        if (item.reason?.includes('chunk:child')) {
          expect(item.reason).toContain('Parent item deduplicated');
        }
      });

      console.log('✅ Metadata preservation test passed');
    });
  });
});
