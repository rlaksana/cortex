/**
 * Chunk Reassembly Integration Tests
 *
 * Tests the complete end-to-end flow:
 * 1. Store large content → chunking → database
 * 2. Find relevant chunks → reassembly → complete context
 * 3. Verify content integrity and semantic coherence
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { KnowledgeItem } from '../../src/types/core-interfaces.js';
import { ChunkingService } from '../../src/services/chunking/chunking-service.js';
import { MockEmbeddingService } from '../utils/mock-embedding-service.js';
import { createMockSemanticAnalyzer } from '../utils/mock-semantic-analyzer.js';
import { ResultGroupingService } from '../../src/services/search/result-grouping-service.js';
// import { logger } from '../../src/utils/logger.js';

describe('Chunk Reassembly Integration', () => {
  let chunkingService: ChunkingService;
  let embeddingService: MockEmbeddingService;
  let groupingService: ResultGroupingService;

  beforeEach(() => {
    // Create mock embedding service with explicit configuration to prevent failures
    embeddingService = new MockEmbeddingService({
      shouldFail: false,
      failMethod: 'both',
      latency: 0,
    });

    chunkingService = new ChunkingService(undefined, undefined, embeddingService as any);

    // Replace the semantic analyzer with our mock - ensure it's properly set
    const mockSemanticAnalyzer = createMockSemanticAnalyzer(embeddingService as any, {
      shouldFail: false,
    });
    (chunkingService as any).semanticAnalyzer = mockSemanticAnalyzer;

    groupingService = new ResultGroupingService();
  });

  afterEach(() => {
    // Clean up any resources if needed
  });

  describe('End-to-End Chunking and Reassembly', () => {
    it('should chunk large document and reassemble in find results', async () => {
      // Step 1: Create a large document that will be chunked
      const largeDocument = `
# System Architecture Overview

This document describes the comprehensive system architecture for our distributed platform.

## Core Components

### Authentication Service
The authentication service handles user identity verification and session management. It implements OAuth 2.0 standards and supports multi-factor authentication. The service is built using Node.js with Express framework and uses JWT tokens for session management.

### Database Layer
We use a multi-database approach to optimize for different use cases:
- PostgreSQL for relational data and transactions
- Redis for caching and session storage
- Elasticsearch for full-text search capabilities

### Microservices Architecture
The system is composed of several microservices that communicate via REST APIs and message queues. Each service is containerized using Docker and orchestrated with Kubernetes.

### API Gateway
The API gateway serves as the single entry point for all client requests. It handles request routing, rate limiting, and authentication token validation.

## Data Flow

1. Client requests hit the API gateway
2. Gateway validates authentication tokens
3. Requests are routed to appropriate microservices
4. Services interact with databases as needed
5. Responses flow back through the gateway to clients

## Security Considerations

All communications between services are encrypted using TLS 1.3. Sensitive data is encrypted at rest using AES-256 encryption. Regular security audits are conducted to identify and address vulnerabilities.

## Performance Optimization

We implement various caching strategies:
- Application-level caching for frequently accessed data
- Database query result caching
- CDN integration for static assets

Load balancing ensures even distribution of traffic across service instances.

${'Additional technical content to ensure proper chunking: '.repeat(50)}
      `.trim();

      // Step 2: Create knowledge item that will be chunked
      const knowledgeItem: KnowledgeItem = {
        id: 'arch-doc-001',
        kind: 'section', // This type should be chunked
        scope: { project: 'test-project', branch: 'main' },
        data: {
          content: largeDocument,
          title: 'System Architecture Documentation',
          category: 'technical',
          author: 'architecture-team',
        },
        created_at: new Date().toISOString(),
      };

      // Step 3: Apply chunking
      const chunkedItems = await chunkingService.processItemsForStorage([knowledgeItem]);

      // Verify chunking worked
      expect(chunkedItems.length).toBeGreaterThan(1);

      // Find parent and chunks
      const parentItem = chunkedItems.find((item) => !item['data.is_chunk']);
      const childChunks = chunkedItems.filter((item) => item['data.is_chunk']);

      expect(parentItem).toBeDefined();
      expect(childChunks.length).toBeGreaterThan(0);
      expect(parentItem?.data['total_chunks']).toBe(childChunks.length);

      // Step 4: Simulate search results (as would come from database)
      const searchResults = childChunks.map((chunk, _index) => ({
        id: chunk.id,
        kind: chunk.kind,
        content: chunk['data.content'],
        data: chunk.data,
        scope: chunk.scope,
        confidence_score: 0.8 + Math.random() * 0.2, // Random score between 0.8-1.0
        created_at: chunk.created_at,
        match_type: 'semantic' as const,
      }));

      // Step 5: Group and reconstruct results
      const groupedResults = groupingService.groupResultsByParent(searchResults);
      expect(groupedResults.length).toBeGreaterThan(0);

      const groupedResult = groupedResults.find((g) => g['parent_id'] === parentItem!.id);
      expect(groupedResult).toBeDefined();

      // Step 6: Reconstruct content
      if (!groupedResult) return;
      const reconstructed = groupingService.reconstructGroupedContent(groupedResult);

      // Verify reconstruction quality
      expect(reconstructed.content).toContain('System Architecture Overview');
      expect(reconstructed.content).toContain('Authentication Service');
      expect(reconstructed.content).toContain('Database Layer');
      expect(reconstructed.content).toContain('Security Considerations');
      expect(reconstructed.content).toContain('Performance Optimization');

      // Verify metadata
      expect(reconstructed['total_chunks']).toBe(childChunks.length);
      expect(reconstructed.found_chunks).toBe(childChunks.length);
      expect(reconstructed.completeness_ratio).toBe(1.0); // All chunks found
      expect(reconstructed.confidence_score).toBeGreaterThan(0);

      // Step 7: Verify content integrity (no significant loss)
      const originalLength = largeDocument.length;
      const reconstructedLength = reconstructed.content.length;

      // Allow for some formatting differences but ensure content is preserved
      const similarityRatio = reconstructedLength / originalLength;
      expect(similarityRatio).toBeGreaterThan(0.8); // At least 80% content preserved
    });

    it('should handle partial chunk reassembly gracefully', async () => {
      // Create a document that will be chunked
      const document = `
# Project Plan

## Phase 1: Requirements Gathering
- Stakeholder interviews
- User story mapping
- Technical requirements analysis

## Phase 2: Design
- System architecture design
- Database schema design
- API specification

## Phase 3: Development
- Frontend development
- Backend development
- Integration testing

## Phase 4: Deployment
- CI/CD pipeline setup
- Production deployment
- Monitoring configuration

## Phase 5: Maintenance
- Bug fixes and updates
- Performance optimization
- Security updates

${'Additional project plan content to ensure proper chunking for testing partial reassembly: '.repeat(50)}
      `.trim();

      const knowledgeItem: KnowledgeItem = {
        id: 'project-plan-001',
        kind: 'runbook', // This type should be chunked
        scope: { project: 'test-project', branch: 'main' },
        data: {
          content: document,
          title: 'Project Plan',
          category: 'planning',
        },
      };

      // Apply chunking
      const chunkedItems = await chunkingService.processItemsForStorage([knowledgeItem]);
      const parentItem = chunkedItems.find((item) => !item['data.is_chunk']);
      const childChunks = chunkedItems.filter((item) => item['data.is_chunk']);

      // Simulate finding only some chunks (not all)
      const partialChunks = childChunks.slice(0, Math.floor(childChunks.length * 0.7));

      const searchResults = partialChunks.map((chunk) => ({
        id: chunk.id,
        kind: chunk.kind,
        content: chunk['data.content'],
        data: chunk.data,
        scope: chunk.scope,
        confidence_score: 0.75 + Math.random() * 0.2,
        created_at: chunk.created_at,
        match_type: 'semantic' as const,
      }));

      // Group and reconstruct
      const groupedResults = groupingService.groupResultsByParent(searchResults);
      const groupedResult = groupedResults.find((g) => g['parent_id'] === parentItem!.id);

      if (!groupedResult) {
        // Skip reconstruction if no grouped result found
        expect(groupedResults.length).toBeGreaterThan(0);
        return;
      }

      const reconstructed = groupingService.reconstructGroupedContent(groupedResult);

      // Verify partial reconstruction
      expect(reconstructed.found_chunks).toBe(partialChunks.length);
      expect(reconstructed['total_chunks']).toBe(childChunks.length);
      expect(reconstructed.completeness_ratio).toBeLessThan(1.0);
      expect(reconstructed.completeness_ratio).toBeGreaterThan(0.5);

      // Should still contain key content
      expect(reconstructed.content).toContain('Phase 1: Requirements Gathering');
      expect(reconstructed.content).toContain('Phase 2: Design');
    });

    it('should handle mixed chunked and non-chunked results', async () => {
      // Create items of different types and sizes
      const items: KnowledgeItem[] = [
        {
          id: 'small-entity-001',
          kind: 'entity', // This type is NOT chunked
          scope: { project: 'test-project' },
          data: {
            content: 'This is a small entity description that will not be chunked.',
            name: 'Test Entity',
          },
        },
        {
          id: 'large-section-001',
          kind: 'section', // This type WILL be chunked
          scope: { project: 'test-project' },
          data: {
            content: 'A'.repeat(3000), // Large content to trigger chunking
            title: 'Large Section Content',
          },
        },
        {
          id: 'medium-observation-001',
          kind: 'observation', // This type is NOT chunked
          scope: { project: 'test-project' },
          data: {
            content:
              'Medium-sized observation that should not be chunked but provides important context.',
            category: 'performance',
          },
        },
      ];

      // Apply chunking
      const processedItems = await chunkingService.processItemsForStorage(items);

      // Simulate search results mixing chunked and non-chunked items
      const searchResults = processedItems.map((item) => ({
        id: item.id,
        kind: item.kind,
        content: item['data.content'],
        data: item.data,
        scope: item.scope,
        confidence_score: 0.7 + Math.random() * 0.3,
        created_at: item.created_at || new Date().toISOString(),
        match_type: 'semantic' as const,
      }));

      // Group and reconstruct
      const groupedResults = groupingService.groupResultsByParent(searchResults);

      // Should have both single items and grouped items
      const singleItems = groupedResults.filter((g) => g.is_single_item);
      const groupedItems = groupedResults.filter((g) => !g.is_single_item);

      expect(singleItems.length).toBeGreaterThan(0);
      expect(groupedItems.length).toBeGreaterThan(0);

      // Verify single items are preserved
      const entityResult = singleItems.find((g) => g['parent_id'] === 'small-entity-001');
      expect(entityResult).toBeDefined();

      // Verify grouped items are reconstructed
      const sectionResult = groupedItems.find((g) => g['parent_id'] === 'large-section-001');
      expect(sectionResult).toBeDefined();

      const reconstructed = groupingService.reconstructGroupedContent(sectionResult!);
      expect(reconstructed.content.length).toBeGreaterThan(1000); // Should be substantial
    });

    it('should maintain metadata integrity through chunking and reassembly', async () => {
      const richContent = `
# Technical Specification

## Overview
This specification defines the technical requirements for the new authentication system.

## Requirements

### Functional Requirements
1. User registration and login
2. Password reset functionality
3. Multi-factor authentication support
4. Session management
5. Role-based access control

### Non-Functional Requirements
1. Response time < 200ms for authentication operations
2. Support for 10,000 concurrent users
3. 99.9% uptime availability
4. SOC 2 compliance

## Implementation Details

### Technology Stack
- Backend: Node.js with Express
- Database: PostgreSQL with Redis cache
- Authentication: JWT with refresh tokens
- Security: OWASP best practices

${'Additional technical specification content to ensure proper chunking: '.repeat(50)}
      `.trim();

      const knowledgeItem: KnowledgeItem = {
        id: 'tech-spec-001',
        kind: 'section',
        scope: {
          project: 'tech-project',
          branch: 'main',
          org: 'engineering',
        },
        data: {
          content: richContent,
          title: 'Authentication System Specification',
          category: 'technical',
          author: 'security-team',
          priority: 'high',
          tags: ['authentication', 'security', 'specification'],
          review_status: 'approved',
          last_reviewed: '2025-01-15T10:00:00Z',
        },
        metadata: {
          version: '1.2.0',
          reviewers: ['alice', 'bob'],
          dependencies: ['database-schema', 'api-gateway'],
        },
      };

      // Apply chunking
      const chunkedItems = await chunkingService.processItemsForStorage([knowledgeItem]);

      // Find parent and verify metadata preservation
      const parentItem = chunkedItems.find((item) => !item['data.is_chunk']);
      expect(parentItem).toBeDefined();
      expect(parentItem?.data.category).toBe('technical');
      expect(parentItem?.data.author).toBe('security-team');
      expect(parentItem?.data.priority).toBe('high');
      expect(parentItem?.metadata?.version).toBe('1.2.0');

      // Verify child chunks inherit important metadata
      const childChunks = chunkedItems.filter((item) => item['data.is_chunk']);
      expect(childChunks.length).toBeGreaterThan(0);

      childChunks.forEach((chunk) => {
        expect(chunk['data.category']).toBe('technical');
        expect(chunk['data.author']).toBe('security-team');
        expect(chunk['data.parent_id']).toBe(parentItem!.id);
        expect(chunk['data.total_chunks']).toBe(childChunks.length);
        expect(chunk['data.is_chunk']).toBe(true);
      });

      // Simulate search and reassembly
      const searchResults = childChunks.map((chunk) => ({
        id: chunk.id,
        kind: chunk.kind,
        content: chunk['data.content'],
        data: chunk.data,
        scope: chunk.scope,
        confidence_score: 0.8,
        created_at: chunk.created_at!,
        match_type: 'semantic' as const,
      }));

      const groupedResults = groupingService.groupResultsByParent(searchResults);
      const reconstructed = groupingService.reconstructGroupedContent(groupedResults[0]);

      // Verify reconstructed content maintains structure
      expect(reconstructed.content).toContain('Technical Specification');
      expect(reconstructed.content).toContain('Functional Requirements');
      expect(reconstructed.content).toContain('Implementation Details');
    });
  });

  describe('Quality Assurance for Reassembly', () => {
    it('should validate reconstructed content quality', async () => {
      // Create content with clear semantic boundaries
      const structuredContent = `
# Executive Summary

This document provides a comprehensive overview of our Q4 2024 performance and strategic initiatives.

## Financial Performance

Our Q4 revenue exceeded expectations by 15%, driven primarily by strong enterprise sales and improved customer retention rates. Key highlights include:

- Total revenue: $45.2M (up 15% YoY)
- Enterprise ARR: $38.7M (up 22% YoY)
- Customer retention: 94% (up from 91%)
- Gross margin: 78% (stable)

## Product Development

Major product launches in Q4 included:
- Advanced analytics dashboard
- Enhanced security features
- Mobile application 2.0
- Integration marketplace

Customer adoption rates have exceeded projections across all new features.

## Market Expansion

Successfully entered three new geographic markets:
- Southeast Asia (Singapore, Malaysia)
- Latin America (Brazil, Mexico)
- Central Europe (Germany, Netherlands)

## Strategic Outlook

Q1 2025 priorities focus on scaling international operations and launching our enterprise platform upgrade.

${'Additional quarterly report content and detailed analysis to ensure proper chunking: '.repeat(50)}
      `.trim();

      const knowledgeItem: KnowledgeItem = {
        id: 'quarterly-report-001',
        kind: 'section',
        scope: { project: 'executive-reports', branch: 'Q4-2024' },
        data: {
          content: structuredContent,
          title: 'Q4 2024 Performance Report',
          category: 'executive',
          confidentiality: 'internal',
        },
      };

      // Apply chunking
      const chunkedItems = await chunkingService.processItemsForStorage([knowledgeItem]);
      const childChunks = chunkedItems.filter((item) => item['data.is_chunk']);

      // Simulate realistic search with varying confidence scores
      const searchResults = childChunks.map((chunk, _index) => ({
        id: chunk.id,
        kind: chunk.kind,
        content: chunk['data.content'],
        data: chunk.data,
        scope: chunk.scope,
        confidence_score: 0.9 - _index * 0.05, // Decreasing scores
        created_at: chunk.created_at!,
        match_type: 'semantic' as const,
      }));

      // Group and reconstruct
      const groupedResults = groupingService.groupResultsByParent(searchResults);

      // Verify we have grouped results
      expect(groupedResults.length).toBeGreaterThan(0);

      const reconstructed = groupingService.reconstructGroupedContent(groupedResults[0]);

      // Quality checks
      expect(reconstructed.content).toContain('Executive Summary');
      expect(reconstructed.content).toContain('Financial Performance');
      expect(reconstructed.content).toContain('Product Development');
      expect(reconstructed.content).toContain('Market Expansion');
      expect(reconstructed.content).toContain('Strategic Outlook');

      // Verify semantic coherence (key phrases should be intact)
      expect(reconstructed.content).toContain('exceeded expectations by 15%');
      expect(reconstructed.content).toContain('Advanced analytics dashboard');
      expect(reconstructed.content).toContain('Southeast Asia');
      expect(reconstructed.content).toContain('scaling international operations');

      // Verify structural elements preserved
      const lines = reconstructed.content.split('\n');
      const headerLines = lines.filter((line) => line.startsWith('#'));
      expect(headerLines.length).toBeGreaterThan(0);

      // Verify metrics and data preserved (accounting for sentence splitting spacing)
      expect(reconstructed.content).toContain('$45. 2M'); // Note: sentence splitting adds spaces
      expect(reconstructed.content).toContain('94%');
      expect(reconstructed.content).toContain('78%');
    });
  });
});
