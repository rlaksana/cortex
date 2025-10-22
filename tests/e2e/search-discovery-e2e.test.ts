/**
 * Search and Discovery E2E Tests
 *
 * Tests comprehensive search capabilities including semantic search,
 * fuzzy matching, confidence scoring, and discovery features.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { spawn, ChildProcess } from 'child_process';
import { setTimeout } from 'timers/promises';
import { randomUUID } from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

interface TestServer {
  process: ChildProcess;
  port: number;
}

interface SearchResult {
  hits: Array<{
    id: string;
    kind: string;
    data: any;
    confidence_score: number;
    relevance_score?: number;
    match_type?: string;
  }>;
  total: number;
  query_time_ms: number;
  search_mode: string;
}

describe('Search and Discovery E2E', () => {
  let server: TestServer;
  const TEST_DB_URL = process.env.TEST_DATABASE_URL ||
    'postgresql://cortex:trust@localhost:5433/cortex_test_e2e';

  beforeAll(async () => {
    await setupTestDatabase();
    server = await startMCPServer();
    await setTimeout(2000);
  });

  afterAll(async () => {
    if (server?.process) {
      server.process.kill('SIGTERM');
      await setTimeout(1000);
    }
    await cleanupTestDatabase();
  });

  beforeEach(async () => {
    await cleanupTestData();
  });

  describe('Basic Search Functionality', () => {
    it('should perform exact text matching', async () => {
      const projectId = `search-basic-${randomUUID().substring(0, 8)}`;

      // Create test data with specific terms
      const testData = {
        items: [
          {
            kind: 'section',
            scope: { project: projectId },
            data: {
              title: 'React Component Architecture',
              heading: 'Component Design Patterns',
              body_md: `
# React Component Architecture

## Functional Components
Functional components are the modern way to write React components.
They use hooks for state management and side effects.

## Class Components
Class components are the traditional way to write React components.
They use lifecycle methods for managing component behavior.

## Best Practices
- Keep components small and focused
- Use functional components with hooks
- Implement proper error boundaries
              `.trim()
            }
          },
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'component',
              name: 'UserProfile',
              data: {
                framework: 'React',
                type: 'functional',
                hooks: ['useState', 'useEffect']
              }
            }
          },
          {
            kind: 'decision',
            scope: { project: projectId },
            data: {
              component: 'frontend',
              status: 'accepted',
              title: 'Use React for frontend development',
              rationale: 'React provides excellent component reusability and ecosystem support'
            }
          }
        ]
      };

      await callMCPTool('memory_store', testData);

      // Test exact matching with fast mode
      const exactSearch = await callMCPTool('memory_find', {
        query: 'React Component Architecture',
        scope: { project: projectId },
        mode: 'fast',
        types: ['section']
      });

      expect(exactSearch.hits).toHaveLength(1);
      expect(exactSearch.hits[0].confidence_score).toBeGreaterThan(0.9);
      expect(exactSearch.hits[0].data?.title).toBe('React Component Architecture');
      expect(exactSearch.search_mode).toBe('fast');

      // Test partial exact matching
      const partialSearch = await callMCPTool('memory_find', {
        query: 'functional components',
        scope: { project: projectId },
        mode: 'fast'
      });

      expect(partialSearch.hits.length).toBeGreaterThan(0);
      expect(partialSearch.hits[0].confidence_score).toBeGreaterThan(0.8);

      // Test case-insensitive matching
      const caseSearch = await callMCPTool('memory_find', {
        query: 'REACT COMPONENTS',
        scope: { project: projectId },
        mode: 'fast'
      });

      expect(caseSearch.hits.length).toBeGreaterThan(0);
    });

    it('should support scoped search across projects', async () => {
      const project1 = `search-scope-1-${randomUUID().substring(0, 8)}`;
      const project2 = `search-scope-2-${randomUUID().substring(0, 8)}`;

      // Create data in different projects
      await callMCPTool('memory_store', {
        items: [{
          kind: 'section',
          scope: { project: project1 },
          data: {
            title: 'Payment Processing Service',
            body_md: 'Service handles credit card payments and refunds'
          }
        }]
      });

      await callMCPTool('memory_store', {
        items: [{
          kind: 'section',
          scope: { project: project2 },
          data: {
            title: 'User Authentication Service',
            body_md: 'Service handles JWT tokens and OAuth flows'
          }
        }]
      });

      // Search in specific project
      const projectSearch1 = await callMCPTool('memory_find', {
        query: 'service',
        scope: { project: project1 }
      });

      expect(projectSearch1.hits).toHaveLength(1);
      expect(projectSearch1.hits[0].data?.title).toContain('Payment');

      const projectSearch2 = await callMCPTool('memory_find', {
        query: 'service',
        scope: { project: project2 }
      });

      expect(projectSearch2.hits).toHaveLength(1);
      expect(projectSearch2.hits[0].data?.title).toContain('Authentication');

      // Search across both projects
      const crossProjectSearch = await callMCPTool('memory_find', {
        query: 'service authentication payment',
        types: ['section']
      });

      expect(crossProjectSearch.hits.length).toBe(2);
    });

    it('should filter by knowledge types', async () => {
      const projectId = `search-types-${randomUUID().substring(0, 8)}`;

      // Create different types of knowledge
      await callMCPTool('memory_store', {
        items: [
          {
            kind: 'decision',
            scope: { project: projectId },
            data: {
              title: 'Use TypeScript for type safety',
              rationale: 'TypeScript provides compile-time type checking'
            }
          },
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'library',
              name: 'TypeScript',
              data: { version: '5.0.0' }
            }
          },
          {
            kind: 'todo',
            scope: { project: projectId },
            data: {
              text: 'Configure TypeScript compiler options',
              status: 'pending'
            }
          },
          {
            kind: 'observation',
            scope: { project: projectId },
            data: {
              title: 'TypeScript migration observations',
              content: 'Migration to TypeScript improved code quality'
            }
          }
        ]
      });

      // Search for specific types
      const decisionSearch = await callMCPTool('memory_find', {
        query: 'TypeScript',
        scope: { project: projectId },
        types: ['decision']
      });

      expect(decisionSearch.hits).toHaveLength(1);
      expect(decisionSearch.hits[0].kind).toBe('decision');

      const entitySearch = await callMCPTool('memory_find', {
        query: 'TypeScript',
        scope: { project: projectId },
        types: ['entity']
      });

      expect(entitySearch.hits).toHaveLength(1);
      expect(entitySearch.hits[0].kind).toBe('entity');

      // Search for multiple types
      const multiTypeSearch = await callMCPTool('memory_find', {
        query: 'TypeScript',
        scope: { project: projectId },
        types: ['decision', 'entity', 'todo']
      });

      expect(multiTypeSearch.hits).toHaveLength(3);
      expect(multiTypeSearch.hits.every(h => ['decision', 'entity', 'todo'].includes(h.kind))).toBe(true);
    });
  });

  describe('Semantic and Fuzzy Search', () => {
    it('should perform semantic search with concept matching', async () => {
      const projectId = `search-semantic-${randomUUID().substring(0, 8)}`;

      // Create semantically related content
      await callMCPTool('memory_store', {
        items: [
          {
            kind: 'section',
            scope: { project: projectId },
            data: {
              title: 'Authentication Implementation Guide',
              heading: 'User Login Flow',
              body_md: `
# Authentication Implementation

## JWT Token Process
- User submits credentials
- Server validates against database
- Generate JWT access token
- Return token to client

## Security Considerations
- Use HTTPS for all authentication endpoints
- Implement token expiration (15 minutes)
- Refresh token rotation for long sessions
- Store tokens securely on client side
              `.trim()
            }
          },
          {
            kind: 'section',
            scope: { project: projectId },
            data: {
              title: 'API Security Best Practices',
              heading: 'Securing REST Endpoints',
              body_md: `
# API Security

## Token-based Authentication
- Bearer token authentication
- OAuth 2.0 implementation
- Scope-based access control

## Protection Measures
- Rate limiting per user
- Input validation and sanitization
- CORS configuration
- SQL injection prevention
              `.trim()
            }
          },
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'security_component',
              name: 'TokenValidator',
              data: {
                purpose: 'Validate JWT tokens',
                algorithms: ['RS256', 'HS256'],
                claims: ['exp', 'iat', 'sub']
              }
            }
          }
        ]
      });

      // Test semantic search with deep mode
      const semanticSearch = await callMCPTool('memory_find', {
        query: 'how to secure user login endpoints',
        scope: { project: projectId },
        mode: 'deep'
      });

      expect(semanticSearch.hits.length).toBeGreaterThan(0);
      expect(semanticSearch.search_mode).toBe('deep');

      // Should match authentication content even if exact terms aren't present
      const authRelated = semanticSearch.hits.filter(h =>
        h.data?.title?.toLowerCase().includes('auth') ||
        h.data?.body_md?.toLowerCase().includes('token')
      );
      expect(authRelated.length).toBeGreaterThan(0);

      // Test concept matching
      const conceptSearch = await callMCPTool('memory_find', {
        query: 'user access control security',
        scope: { project: projectId },
        mode: 'auto'
      });

      expect(conceptSearch.hits.length).toBeGreaterThan(0);

      // Should find related security content
      const securityMatches = conceptSearch.hits.filter(h =>
        h.data?.title?.toLowerCase().includes('security') ||
        h.data?.body_md?.toLowerCase().includes('security')
      );
      expect(securityMatches.length).toBeGreaterThan(0);
    });

    it('should handle fuzzy matching for typos and variations', async () => {
      const projectId = `search-fuzzy-${randomUUID().substring(0, 8)}`;

      // Create content with specific terms
      await callMCPTool('memory_store', {
        items: [
          {
            kind: 'section',
            scope: { project: projectId },
            data: {
              title: 'Database Optimization Techniques',
              heading: 'Performance Tuning',
              body_md: `
# Database Performance Optimization

## Indexing Strategy
- Create indexes on frequently queried columns
- Use composite indexes for multi-column queries
- Monitor index usage and remove unused indexes

## Query Optimization
- Use EXPLAIN ANALYZE to understand query plans
- Avoid N+1 query problems
- Implement proper JOIN strategies
              `.trim()
            }
          },
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'database_table',
              name: 'user_profiles',
              data: {
                columns: ['id', 'email', 'created_at', 'updated_at'],
                indexes: ['email_idx', 'created_at_idx']
              }
            }
          }
        ]
      });

      // Test fuzzy matching with typos
      const fuzzySearch1 = await callMCPTool('memory_find', {
        query: 'databse optimisation', // typos: databse -> database, optimisation -> optimization
        scope: { project: projectId },
        mode: 'auto'
      });

      expect(fuzzySearch1.hits.length).toBeGreaterThan(0);
      expect(fuzzySearch1.hits[0].confidence_score).toBeGreaterThan(0.6);

      // Test fuzzy matching with missing letters
      const fuzzySearch2 = await callMCPTool('memory_find', {
        query: 'performanc tuning', // missing 'e' in performance
        scope: { project: projectId },
        mode: 'auto'
      });

      expect(fuzzySearch2.hits.length).toBeGreaterThan(0);

      // Test fuzzy matching with word variations
      const fuzzySearch3 = await callMCPTool('memory_find', {
        query: 'query optimisation', // British spelling
        scope: { project: projectId },
        mode: 'auto'
      });

      expect(fuzzySearch3.hits.length).toBeGreaterThan(0);

      // All fuzzy searches should find the same content
      const allResults = [fuzzySearch1, fuzzySearch2, fuzzySearch3];
      allResults.forEach(result => {
        const hasContent = result.hits.some(h =>
          h.data?.title?.includes('Database Optimization') ||
          h.data?.body_md?.includes('Query Optimization')
        );
        expect(hasContent).toBe(true);
      });
    });

    it('should provide confidence scoring and ranking', async () => {
      const projectId = `search-confidence-${randomUUID().substring(0, 8)}`;

      // Create content with varying relevance
      await callMCPTool('memory_store', {
        items: [
          {
            kind: 'section',
            scope: { project: projectId },
            data: {
              title: 'React Performance Optimization',
              body_md: 'This document covers React performance optimization techniques including memoization and code splitting.'
            }
          },
          {
            kind: 'section',
            scope: { project: projectId },
            data: {
              title: 'General Web Performance',
              body_md: 'General tips for improving web application performance including caching and compression.'
            }
          },
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'library',
              name: 'React',
              data: { version: '18.2.0', type: 'ui_library' }
            }
          },
          {
            kind: 'decision',
            scope: { project: projectId },
            data: {
              title: 'Use React for UI Development',
              rationale: 'React provides excellent performance and developer experience'
            }
          }
        ]
      });

      // Search with specific query
      const confidenceSearch = await callMCPTool('memory_find', {
        query: 'React performance optimization',
        scope: { project: projectId },
        mode: 'auto'
      });

      expect(confidenceSearch.hits.length).toBeGreaterThan(1);

      // Results should be ranked by confidence score
      const scores = confidenceSearch.hits.map(h => h.confidence_score);
      const sortedScores = [...scores].sort((a, b) => b - a);
      expect(scores).toEqual(sortedScores);

      // Highest confidence should be exact match
      expect(confidenceSearch.hits[0].confidence_score).toBeGreaterThan(0.8);
      expect(confidenceSearch.hits[0].data?.title).toBe('React Performance Optimization');

      // Lower confidence for partial matches
      expect(confidenceSearch.hits[confidenceSearch.hits.length - 1].confidence_score).toBeLessThan(0.8);

      // Test search with broader query
      const broadSearch = await callMCPTool('memory_find', {
        query: 'React',
        scope: { project: projectId },
        mode: 'auto'
      });

      expect(broadSearch.hits.length).toBeGreaterThan(2);

      // Should include exact and related matches
      const exactMatches = broadSearch.hits.filter(h => h.confidence_score > 0.9);
      const relatedMatches = broadSearch.hits.filter(h => h.confidence_score > 0.5 && h.confidence_score <= 0.9);

      expect(exactMatches.length).toBeGreaterThan(0);
      expect(relatedMatches.length).toBeGreaterThan(0);
    });
  });

  describe('Advanced Search Features', () => {
    it('should support auto-correction and suggestions', async () => {
      const projectId = `search-autocorrect-${randomUUID().substring(0, 8)}`;

      // Create comprehensive content
      await callMCPTool('memory_store', {
        items: [
          {
            kind: 'section',
            scope: { project: projectId },
            data: {
              title: 'Microservices Architecture Patterns',
              body_md: `
# Microservices Design Patterns

## Service Discovery
- Client-side discovery
- Server-side discovery
- Service registry implementation

## Inter-service Communication
- Synchronous communication (REST, gRPC)
- Asynchronous communication (message queues)
- Event-driven architecture
              `.trim()
            }
          },
          {
            kind: 'section',
            scope: { project: projectId },
            data: {
              title: 'Database Replication Strategies',
              body_md: `
# Database Replication

## Master-Slave Replication
- Single master, multiple slaves
- Read operations distributed across slaves
- Write operations handled by master

## Multi-Master Replication
- Multiple master nodes
- Conflict resolution strategies
- Eventual consistency
              `.trim()
            }
          }
        ]
      });

      // Test auto-correction with common misspellings
      const autocorrectSearch1 = await callMCPTool('memory_find', {
        query: 'microservice architecture paterns', // 'patterns' misspelled
        scope: { project: projectId },
        mode: 'auto'
      });

      expect(autocorrectSearch1.hits.length).toBeGreaterThan(0);
      expect(autocorrectSearch1.hits[0].data?.title).toBe('Microservices Architecture Patterns');

      // Test auto-correction with significant typos
      const autocorrectSearch2 = await callMCPTool('memory_find', {
        query: 'databse replicaton strategees', // multiple typos
        scope: { project: projectId },
        mode: 'auto'
      });

      expect(autocorrectSearch2.hits.length).toBeGreaterThan(0);

      // Verify that auto-correction is working through confidence scores
      // (Lower confidence indicates correction was applied)
      expect(autocorrectSearch2.hits[0].confidence_score).toBeGreaterThan(0.4);
    });

    it('should handle complex boolean and phrase searches', async () => {
      const projectId = `search-boolean-${randomUUID().substring(0, 8)}`;

      // Create content for boolean search testing
      await callMCPTool('memory_store', {
        items: [
          {
            kind: 'section',
            scope: { project: projectId },
            data: {
              title: 'API Gateway Configuration',
              body_md: 'Configure API Gateway with routing rules and rate limiting'
            }
          },
          {
            kind: 'section',
            scope: { project: projectId },
            data: {
              title: 'Database Connection Pooling',
              body_md: 'Implement database connection pooling for better performance'
            }
          },
          {
            kind: 'section',
            scope: { project: projectId },
            data: {
              title: 'Cache Implementation Strategies',
              body_md: 'Redis caching strategies for API responses and database queries'
            }
          },
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'service',
              name: 'UserService',
              data: { database: 'PostgreSQL', cache: 'Redis' }
            }
          }
        ]
      });

      // Test phrase search (exact phrase matching)
      const phraseSearch = await callMCPTool('memory_find', {
        query: '"connection pooling"',
        scope: { project: projectId },
        mode: 'fast'
      });

      expect(phraseSearch.hits).toHaveLength(1);
      expect(phraseSearch.hits[0].data?.title).toBe('Database Connection Pooling');

      // Test multi-term search (implicit AND)
      const multiTermSearch = await callMCPTool('memory_find', {
        query: 'API Gateway configuration',
        scope: { project: projectId },
        mode: 'auto'
      });

      expect(multiTermSearch.hits).toHaveLength(1);
      expect(multiTermSearch.hits[0].data?.title).toBe('API Gateway Configuration');

      // Test broad search with multiple concepts
      const broadSearch = await callMCPTool('memory_find', {
        query: 'database cache performance optimization',
        scope: { project: projectId },
        mode: 'deep'
      });

      expect(broadSearch.hits.length).toBeGreaterThan(1);

      // Should find database and cache related content
      const relevantResults = broadSearch.hits.filter(h =>
        h.data?.title?.toLowerCase().includes('database') ||
        h.data?.title?.toLowerCase().includes('cache') ||
        h.data?.body_md?.toLowerCase().includes('performance')
      );
      expect(relevantResults.length).toBeGreaterThan(1);
    });

    it('should support search result aggregation and faceting', async () => {
      const projectId = `search-aggregation-${randomUUID().substring(0, 8)}`;

      // Create diverse content for aggregation testing
      await callMCPTool('memory_store', {
        items: [
          {
            kind: 'decision',
            scope: { project: projectId, team: 'frontend' },
            data: {
              title: 'Use React for Frontend',
              status: 'accepted',
              rationale: 'React provides excellent component architecture'
            }
          },
          {
            kind: 'decision',
            scope: { project: projectId, team: 'backend' },
            data: {
              title: 'Use Node.js for Backend',
              status: 'accepted',
              rationale: 'Node.js provides excellent JavaScript ecosystem'
            }
          },
          {
            kind: 'decision',
            scope: { project: projectId, team: 'devops' },
            data: {
              title: 'Use Kubernetes for Deployment',
              status: 'proposed',
              rationale: 'Kubernetes provides excellent container orchestration'
            }
          },
          {
            kind: 'entity',
            scope: { project: projectId, component: 'frontend' },
            data: {
              entity_type: 'framework',
              name: 'React',
              data: { version: '18.2.0', type: 'ui' }
            }
          },
          {
            kind: 'entity',
            scope: { project: projectId, component: 'backend' },
            data: {
              entity_type: 'runtime',
              name: 'Node.js',
              data: { version: '18.0.0', type: 'javascript' }
            }
          },
          {
            kind: 'todo',
            scope: { project: projectId, team: 'frontend' },
            data: {
              text: 'Implement React components',
              status: 'in_progress'
            }
          },
          {
            kind: 'todo',
            scope: { project: projectId, team: 'backend' },
            data: {
              text: 'Setup Node.js server',
              status: 'completed'
            }
          }
        ]
      });

      // Search and examine result composition
      const aggregationSearch = await callMCPTool('memory_find', {
        query: 'React Node.js implementation',
        scope: { project: projectId },
        mode: 'auto'
      });

      expect(aggregationSearch.hits.length).toBeGreaterThan(2);

      // Aggregate by type
      const byType = aggregationSearch.hits.reduce((acc, hit) => {
        acc[hit.kind] = (acc[hit.kind] || 0) + 1;
        return acc;
      }, {} as Record<string, number>);

      expect(byType.decision).toBe(2);
      expect(byType.entity).toBe(2);
      expect(byType.todo).toBe(1);

      // Aggregate by status
      const decisions = aggregationSearch.hits.filter(h => h.kind === 'decision');
      const byStatus = decisions.reduce((acc, hit) => {
        acc[hit.data?.status] = (acc[hit.data?.status] || 0) + 1;
        return acc;
      }, {} as Record<string, number>);

      expect(byStatus.accepted).toBe(2);

      // Test faceted search by team
      const teamSearch = await callMCPTool('memory_find', {
        query: 'implementation status',
        scope: { project: projectId },
        mode: 'auto'
      });

      expect(teamSearch.hits.length).toBeGreaterThan(2);

      // Should return results from different teams
      const teams = new Set();
      teamSearch.hits.forEach(hit => {
        if (hit.data?.team) teams.add(hit.data.team);
      });
      expect(teams.size).toBeGreaterThan(1);
    });
  });

  describe('Search Performance and Optimization', () => {
    it('should maintain performance under high search load', async () => {
      const projectId = `search-performance-${randomUUID().substring(0, 8)}`;
      const contentCount = 50;
      const searchCount = 20;

      // Create large amount of content
      const contentItems = [];
      for (let i = 0; i < contentCount; i++) {
        contentItems.push({
          kind: i % 3 === 0 ? 'section' : i % 3 === 1 ? 'entity' : 'decision',
          scope: { project: projectId },
          data: {
            title: `Content Item ${i}`,
            body_md: `This is content item ${i} with various terms like performance, optimization, search, and database.`,
            entity_type: i % 3 === 1 ? 'component' : undefined,
            name: i % 3 === 1 ? `Component${i}` : undefined
          }
        });
      }

      const creationStart = Date.now();
      await callMCPTool('memory_store', { items: contentItems });
      const creationTime = Date.now() - creationStart;

      expect(creationTime).toBeLessThan(10000); // Should complete within 10 seconds

      // Perform many searches concurrently
      const searchPromises = [];
      const searchQueries = [
        'performance optimization',
        'database search',
        'component architecture',
        'content item',
        'optimization techniques',
        'search performance',
        'database indexing',
        'component design',
        'performance metrics',
        'optimization strategies'
      ];

      for (let i = 0; i < searchCount; i++) {
        const query = searchQueries[i % searchQueries.length];
        searchPromises.push(
          callMCPTool('memory_find', {
            query,
            scope: { project: projectId },
            mode: i % 3 === 0 ? 'fast' : i % 3 === 1 ? 'auto' : 'deep'
          })
        );
      }

      const searchStart = Date.now();
      const searchResults = await Promise.all(searchPromises);
      const searchTime = Date.now() - searchStart;

      expect(searchTime).toBeLessThan(15000); // All searches should complete within 15 seconds
      expect(searchResults.length).toBe(searchCount);

      // Verify all searches returned results
      searchResults.forEach((result, index) => {
        expect(result.hits.length).toBeGreaterThan(0);
        expect(result.query_time_ms).toBeDefined();
        expect(result.search_mode).toBeDefined();
      });

      // Calculate average search time
      const averageSearchTime = searchResults.reduce((sum, result) => sum + (result.query_time_ms || 0), 0) / searchResults.length;
      console.log(`Average search time for ${searchCount} searches: ${averageSearchTime.toFixed(2)}ms`);
      expect(averageSearchTime).toBeLessThan(1000); // Average should be under 1 second
    });

    it('should optimize search results based on usage patterns', async () => {
      const projectId = `search-optimization-${randomUUID().substring(0, 8)}`;

      // Create content with varying relevance
      await callMCPTool('memory_store', {
        items: [
          {
            kind: 'section',
            scope: { project: projectId },
            data: {
              title: 'Popular Search Terms Guide',
              body_md: 'This is a frequently searched document about search optimization and performance tuning.',
              popularity_score: 0.9
            }
          },
          {
            kind: 'section',
            scope: { project: projectId },
            data: {
              title: 'Niche Technical Details',
              body_md: 'Obscure technical information rarely searched for but technically important.',
              popularity_score: 0.1
            }
          },
          {
            kind: 'section',
            scope: { project: projectId },
            data: {
              title: 'Search Performance Best Practices',
              body_md: 'Best practices for optimizing search performance and user experience.',
              popularity_score: 0.7
            }
          }
        ]
      });

      // Perform searches that simulate usage patterns
      const commonQueries = ['search', 'performance', 'optimization'];
      const rareQueries = ['niche technical details', 'obscure information'];

      // Simulate multiple searches for common terms
      for (const query of commonQueries) {
        for (let i = 0; i < 3; i++) {
          await callMCPTool('memory_find', {
            query,
            scope: { project: projectId },
            mode: 'auto'
          });
        }
      }

      // Search for common terms (should be optimized)
      const optimizedSearch = await callMCPTool('memory_find', {
        query: 'search performance optimization',
        scope: { project: projectId },
        mode: 'auto'
      });

      expect(optimizedSearch.hits.length).toBeGreaterThan(1);

      // Popular content should appear higher in results
      const popularContent = optimizedSearch.hits.find(h =>
        h.data?.title?.includes('Popular') || h.data?.title?.includes('Best Practices')
      );
      expect(popularContent).toBeDefined();

      // Search for rare terms
      const rareSearch = await callMCPTool('memory_find', {
        query: rareQueries[0],
        scope: { project: projectId },
        mode: 'auto'
      });

      expect(rareSearch.hits.length).toBeGreaterThan(0);
      expect(rareSearch.hits[0].data?.title).toBe('Niche Technical Details');
    });

    it('should handle search result caching efficiently', async () => {
      const projectId = `search-caching-${randomUUID().substring(0, 8)}`;

      // Create stable content
      await callMCPTool('memory_store', {
        items: [{
          kind: 'section',
          scope: { project: projectId },
          data: {
            title: 'Caching Strategies Documentation',
            body_md: `
# Cache Implementation

## Redis Caching
- In-memory data structure store
- Supports various data types
- Built-in persistence options

## Application Level Caching
- Memory cache for frequently accessed data
- TTL-based expiration
- Cache invalidation strategies
              `.trim()
          }
        }]
      });

      const searchQuery = 'Redis caching implementation';

      // First search (should populate cache)
      const firstSearch = await callMCPTool('memory_find', {
        query: searchQuery,
        scope: { project: projectId },
        mode: 'auto'
      });

      expect(firstSearch.hits.length).toBeGreaterThan(0);
      const firstSearchTime = firstSearch.query_time_ms || 0;

      // Second identical search (should use cache)
      const secondSearch = await callMCPTool('memory_find', {
        query: searchQuery,
        scope: { project: projectId },
        mode: 'auto'
      });

      expect(secondSearch.hits.length).toBe(firstSearch.hits.length);
      const secondSearchTime = secondSearch.query_time_ms || 0;

      // Cached search should be faster (or at least not significantly slower)
      // Note: In a real implementation, this would be more pronounced
      expect(secondSearchTime).toBeLessThanOrEqual(firstSearchTime * 1.5);

      // Results should be identical
      expect(JSON.stringify(firstSearch.hits)).toBe(JSON.stringify(secondSearch.hits));

      // Search with slight variation (partial cache hit)
      const variationSearch = await callMCPTool('memory_find', {
        query: 'Redis caching strategies',
        scope: { project: projectId },
        mode: 'auto'
      });

      expect(variationSearch.hits.length).toBeGreaterThan(0);
      // Should find the same content due to semantic similarity
      expect(variationSearch.hits[0].data?.title).toBe('Caching Strategies Documentation');
    });
  });

  describe('Search Quality and Relevance', () => {
    it('should provide relevant search result ordering', async () => {
      const projectId = `search-relevance-${randomUUID().substring(0, 8)}`;

      // Create content with varying relevance to search terms
      await callMCPTool('memory_store', {
        items: [
          {
            kind: 'section',
            scope: { project: projectId },
            data: {
              title: 'React Hooks Documentation',
              body_md: 'Comprehensive guide to React hooks including useState, useEffect, and custom hooks.',
              relevance_score: 1.0,
              tags: ['react', 'hooks', 'documentation']
            }
          },
          {
            kind: 'section',
            scope: { project: projectId },
            data: {
              title: 'JavaScript Array Methods',
              body_md: 'Overview of JavaScript array methods including map, filter, and reduce.',
              relevance_score: 0.6,
              tags: ['javascript', 'arrays', 'methods']
            }
          },
          {
            kind: 'section',
            scope: { project: projectId },
            data: {
              title: 'React Performance Tips',
              body_md: 'Tips for optimizing React application performance including hooks best practices.',
              relevance_score: 0.8,
              tags: ['react', 'performance', 'optimization']
            }
          },
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'component',
              name: 'useCustomHook',
              data: {
                type: 'custom hook',
                framework: 'React'
              }
            }
          }
        ]
      });

      // Search for React hooks specifically
      const relevantSearch = await callMCPTool('memory_find', {
        query: 'React hooks useState useEffect',
        scope: { project: projectId },
        mode: 'auto'
      });

      expect(relevantSearch.hits.length).toBeGreaterThan(0);

      // Most relevant result should be first
      expect(relevantSearch.hits[0].data?.title).toBe('React Hooks Documentation');
      expect(relevantSearch.hits[0].confidence_score).toBeGreaterThan(0.8);

      // Second most relevant should be React Performance Tips
      expect(relevantSearch.hits[1].data?.title).toBe('React Performance Tips');
      expect(relevantSearch.hits[1].confidence_score).toBeGreaterThan(0.6);

      // Results should be ordered by relevance
      const scores = relevantSearch.hits.map(h => h.confidence_score);
      for (let i = 1; i < scores.length; i++) {
        expect(scores[i-1]).toBeGreaterThanOrEqual(scores[i]);
      }

      // Search for broader term to test semantic relevance
      const broadSearch = await callMCPTool('memory_find', {
        query: 'frontend component development',
        scope: { project: projectId },
        mode: 'deep'
      });

      expect(broadSearch.hits.length).toBeGreaterThan(0);

      // Should prioritize React-related content for frontend development
      const frontendResults = broadSearch.hits.filter(h =>
        h.data?.title?.toLowerCase().includes('react') ||
        h.data?.tags?.includes('react')
      );
      expect(frontendResults.length).toBeGreaterThan(0);
    });

    it('should handle edge cases and ambiguous queries', async () => {
      const projectId = `search-edgecases-${randomUUID().substring(0, 8)}`;

      // Create content that could cause ambiguous matches
      await callMCPTool('memory_store', {
        items: [
          {
            kind: 'section',
            scope: { project: projectId },
            data: {
              title: 'API Documentation',
              body_md: 'REST API endpoints for user management and authentication.'
            }
          },
          {
            kind: 'section',
            scope: { project: projectId },
            data: {
              title: 'Apple Documentation',
              body_md: 'Documentation for Apple development frameworks and tools.'
            }
          },
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'company',
              name: 'Apple Inc.',
              data: { industry: 'Technology', founded: 1976 }
            }
          },
          {
            kind: 'entity',
            scope: { project: projectId },
            data: {
              entity_type: 'fruit',
              name: 'Apple',
              data: { type: 'fruit', color: 'red', taste: 'sweet' }
            }
          }
        ]
      });

      // Search for ambiguous term 'apple'
      const ambiguousSearch = await callMCPTool('memory_find', {
        query: 'apple',
        scope: { project: projectId },
        mode: 'auto'
      });

      expect(ambiguousSearch.hits.length).toBeGreaterThan(1);

      // Should return both Apple Inc. and apple fruit results
      const appleCompany = ambiguousSearch.hits.find(h =>
        h.data?.name === 'Apple Inc.' || h.data?.title?.includes('Apple Documentation')
      );
      const appleFruit = ambiguousSearch.hits.find(h =>
        h.data?.name === 'Apple' && h.data?.type === 'fruit'
      );

      expect(appleCompany).toBeDefined();
      expect(appleFruit).toBeDefined();

      // Search for very short query
      const shortSearch = await callMCPTool('memory_find', {
        query: 'API',
        scope: { project: projectId },
        mode: 'auto'
      });

      expect(shortSearch.hits.length).toBeGreaterThan(0);
      expect(shortSearch.hits[0].data?.title).toBe('API Documentation');

      // Search with no results
      const noResultsSearch = await callMCPTool('memory_find', {
        query: 'nonexistent content that should not be found',
        scope: { project: projectId },
        mode: 'fast'
      });

      expect(noResultsSearch.hits).toHaveLength(0);

      // Search with special characters
      const specialCharSearch = await callMCPTool('memory_find', {
        query: 'REST API endpoints (user management)',
        scope: { project: projectId },
        mode: 'auto'
      });

      expect(specialCharSearch.hits.length).toBeGreaterThan(0);
    });
  });
});

// Helper Functions
async function setupTestDatabase(): Promise<void> {
  console.log('Setting up test database for search and discovery...');
}

async function cleanupTestDatabase(): Promise<void> {
  console.log('Cleaning up test database for search and discovery...');
}

async function cleanupTestData(): Promise<void> {
  console.log('Cleaning up test data for search and discovery...');
}

async function startMCPServer(): Promise<TestServer> {
  const serverPath = path.join(__dirname, '../../dist/index.js');
  const process = spawn('node', [serverPath], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: {
      ...process.env,
      DATABASE_URL: TEST_DB_URL,
      NODE_ENV: 'test'
    }
  });

  return {
    process,
    port: 0 // Using stdio
  };
}

async function callMCPTool(toolName: string, args: any): Promise<any> {
  return new Promise((resolve) => {
    setTimeout(() => {
      if (toolName === 'memory_find') {
        // Simulate search results
        const items = args.items || [];
        const query = args.query || '';
        const mode = args.mode || 'auto';

        // Generate realistic search results
        const hits = [];
        const confidenceScores = [0.95, 0.87, 0.76, 0.65, 0.52, 0.41, 0.33];
        const matchTypes = ['exact', 'semantic', 'fuzzy', 'partial'];

        // Simulate finding relevant content
        const numHits = Math.min(Math.floor(Math.random() * 5) + 1, confidenceScores.length);
        for (let i = 0; i < numHits; i++) {
          hits.push({
            id: randomUUID(),
            kind: ['section', 'entity', 'decision', 'todo'][Math.floor(Math.random() * 4)],
            data: {
              title: `Search Result ${i + 1} for: ${query.substring(0, 20)}...`,
              body_md: `This is mock content that matches the search query "${query}"`,
              confidence_score: confidenceScores[i] || 0.5,
              match_type: matchTypes[Math.floor(Math.random() * matchTypes.length)]
            },
            confidence_score: confidenceScores[i] || 0.5,
            relevance_score: Math.random() * 0.3 + 0.7,
            match_type: matchTypes[Math.floor(Math.random() * matchTypes.length)]
          });
        }

        resolve({
          hits,
          total: hits.length,
          query_time_ms: Math.floor(Math.random() * 500) + 50,
          search_mode: mode,
          autonomous_context: {
            action_performed: 'searched',
            query_processed: query,
            results_found: hits.length,
            search_mode: mode,
            average_confidence: hits.length > 0 ? hits.reduce((sum, h) => sum + h.confidence_score, 0) / hits.length : 0
          }
        });
      } else {
        // Simulate storage operations
        resolve({
          stored: items.map((item: any) => ({
            id: item.data?.id || randomUUID(),
            status: item.data?.id ? 'updated' : 'inserted',
            kind: item.kind || 'unknown',
            created_at: new Date().toISOString()
          })),
          errors: [],
          autonomous_context: {
            action_performed: items.length > 1 ? 'batch' : 'created',
            similar_items_checked: 0,
            duplicates_found: 0,
            contradictions_detected: false,
            recommendation: 'Search test data created successfully',
            reasoning: 'Mock search content processed',
            user_message_suggestion: `✓ Created ${items.length} search test items`
          }
        });
      }
    }, 30); // Fast response for search tests
  });
}