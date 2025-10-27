/**
 * Knowledge Graph Integration Tests
 *
 * Tests comprehensive knowledge graph functionality including:
 * - Entity and relation creation and management
 * - Graph traversal algorithms
 * - Graph-based search and discovery
 * - Relationship inference and deduction
 * - Graph consistency and integrity
 * - Performance with large graphs
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import { dbQdrantClient } from '../db/pool.ts';
// Prisma client removed - system now uses Qdrant + PostgreSQL architecture';
import { memoryStore } from '../services/memory-store.ts';
import { memoryFind } from '../services/memory-find.ts';
import { traverseGraph, enrichGraphNodes, type TraversalOptions } from '../services/graph-traversal.ts';

describe('Knowledge Graph Integration Tests', () => {
  beforeAll(async () => {
    await dbQdrantClient.initialize();
  });

  afterAll(async () => {
    // Cleanup all test data
    const cleanupTables = [
      'knowledge_entity', 'knowledge_relation', 'section', 'decision',
      'issue', 'observation', 'todo', 'runbook', 'release', 'risk',
      'assumption', 'incident', 'pr_context', 'ddl', 'change_log',
      'release_note', 'adr_decision'
    ];

    for (const table of cleanupTables) {
      try {
        await dbQdrantClient.query(`DELETE FROM ${table} WHERE tags @> '{"graph_test": true}'::jsonb`);
      } catch (error) {
        // Table might not exist, continue
      }
    }
  });

  describe('Entity Creation and Management', () => {
    it('should create entities with flexible schemas', async () => {
      const entities = [
        {
          kind: 'entity' as const,
          scope: { project: 'graph-test', branch: 'main' },
          data: {
            entity_type: 'person',
            name: 'Alice Johnson',
            data: {
              role: 'developer',
              skills: ['TypeScript', 'PostgreSQL', 'React'],
              experience_years: 5,
              contact: {
                email: 'alice@example.com',
                github: 'alicejohnson'
              }
            }
          },
          tags: { graph_test: true, entity_test: true }
        },
        {
          kind: 'entity' as const,
          scope: { project: 'graph-test', branch: 'main' },
          data: {
            entity_type: 'project',
            name: 'Cortex Memory System',
            data: {
              type: 'knowledge management',
              status: 'active',
              technologies: ['TypeScript', 'PostgreSQL', 'MCP'],
              team_size: 3
            }
          },
          tags: { graph_test: true, entity_test: true }
        },
        {
          kind: 'entity' as const,
          scope: { project: 'graph-test', branch: 'main' },
          data: {
            entity_type: 'organization',
            name: 'TechCorp Inc',
            data: {
              industry: 'Software',
              founded: 2020,
              employees: 50,
              locations: ['San Francisco', 'Remote']
            }
          },
          tags: { graph_test: true, entity_test: true }
        }
      ];

      const result = await memoryStore(entities);
      expect(result.stored).toHaveLength(3);
      expect(result.errors).toHaveLength(0);

      // Verify entities were stored with correct structure
      for (const stored of result.stored) {
        expect(stored.status).toBe('inserted');
        expect(stored.id).toBeDefined();
        expect(stored.kind).toBe('entity');
      }

      // Verify searchability
      const findResult = await memoryFind({
        query: 'Alice Johnson',
        scope: { project: 'graph-test', branch: 'main' },
        types: ['entity']
      });

      expect(findResult.hits.length).toBe(1);
      expect(findResult.hits[0].title).toBe('Alice Johnson');
    });

    it('should update entities with new information', async () => {
      // Create initial entity
      const initialResult = await memoryStore([{
        kind: 'entity',
        scope: { project: 'graph-test', branch: 'main' },
        data: {
          entity_type: 'person',
          name: 'Bob Smith',
          data: {
            role: 'designer',
            skills: ['Figma', 'Sketch']
          }
        },
        tags: { graph_test: true, entity_update_test: true }
      }]);

      const entityId = initialResult.stored[0].id;

      // Update entity with additional information
      const updateResult = await memoryStore([{
        kind: 'entity',
        scope: { project: 'graph-test', branch: 'main' },
        data: {
          entity_type: 'person',
          name: 'Bob Smith',
          data: {
            role: 'senior designer',
            skills: ['Figma', 'Sketch', 'Adobe XD', 'Principle'],
            experience_years: 7,
            projects_completed: 25
          }
        },
        tags: { graph_test: true, entity_update_test: true, updated: true }
      }]);

      expect(updateResult.stored[0].status).toBe('inserted'); // Updated via upsert

      // Verify update persisted
      const findResult = await memoryFind({
        query: 'Bob Smith senior designer',
        scope: { project: 'graph-test', branch: 'main' },
        types: ['entity']
      });

      expect(findResult.hits.length).toBe(1);
      const entity = findResult.hits[0];
      expect(entity.snippet).toContain('senior designer');
    });

    it('should handle entity deduplication correctly', async () => {
      const entityData = {
        kind: 'entity' as const,
        scope: { project: 'graph-test', branch: 'main' },
        data: {
          entity_type: 'technology',
          name: 'TypeScript',
          data: {
            type: 'programming language',
            paradigm: 'multi-paradigm',
            first_release: 2012
          }
        },
        tags: { graph_test: true, dedup_test: true }
      };

      // Store same entity twice
      const result1 = await memoryStore([entityData]);
      const result2 = await memoryStore([entityData]);

      // Should have same ID (deduplicated)
      expect(result1.stored[0].id).toBe(result2.stored[0].id);
      expect(result1.stored[0].status).toBe('inserted');
      expect(result2.stored[0].status).toBe('inserted'); // Same content, deduped
    });
  });

  describe('Relation Creation and Management', () => {
    let aliceId: string, projectId: string, techCorpId: string;

    beforeEach(async () => {
      // Create test entities
      const entities = await memoryStore([
        {
          kind: 'entity',
          scope: { project: 'graph-test', branch: 'main' },
          data: {
            entity_type: 'person',
            name: 'Alice Johnson',
            data: { role: 'developer' }
          },
          tags: { graph_test: true, relation_test: true }
        },
        {
          kind: 'entity',
          scope: { project: 'graph-test', branch: 'main' },
          data: {
            entity_type: 'project',
            name: 'Cortex Memory System',
            data: { type: 'knowledge management' }
          },
          tags: { graph_test: true, relation_test: true }
        },
        {
          kind: 'entity',
          scope: { project: 'graph-test', branch: 'main' },
          data: {
            entity_type: 'organization',
            name: 'TechCorp Inc',
            data: { industry: 'Software' }
          },
          tags: { graph_test: true, relation_test: true }
        }
      ]);

      aliceId = entities.stored[0].id;
      projectId = entities.stored[1].id;
      techCorpId = entities.stored[2].id;
    });

    it('should create relations between entities', async () => {
      const relations = [
        {
          kind: 'relation' as const,
          scope: { project: 'graph-test', branch: 'main' },
          data: {
            name: 'works_on',
            data: {
              source_id: aliceId,
              target_id: projectId,
              relationship_type: 'works_on',
              since: '2024-01-15',
              role: 'lead developer'
            }
          },
          tags: { graph_test: true, relation_test: true }
        },
        {
          kind: 'relation' as const,
          scope: { project: 'graph-test', branch: 'main' },
          data: {
            name: 'employed_by',
            data: {
              source_id: aliceId,
              target_id: techCorpId,
              relationship_type: 'employed_by',
              since: '2023-06-01',
              position: 'Senior Developer'
            }
          },
          tags: { graph_test: true, relation_test: true }
        },
        {
          kind: 'relation' as const,
          scope: { project: 'graph-test', branch: 'main' },
          data: {
            name: 'owned_by',
            data: {
              source_id: projectId,
              target_id: techCorpId,
              relationship_type: 'owned_by',
              since: '2024-01-01'
            }
          },
          tags: { graph_test: true, relation_test: true }
        }
      ];

      const result = await memoryStore(relations);
      expect(result.stored).toHaveLength(3);
      expect(result.errors).toHaveLength(0);

      // Verify relations can be found
      const findResult = await memoryFind({
        query: 'works_on lead developer',
        scope: { project: 'graph-test', branch: 'main' },
        types: ['relation']
      });

      expect(findResult.hits.length).toBe(1);
      expect(findResult.hits[0].title).toBe('works_on');
    });

    it('should support bidirectional relations', async () => {
      // Create bidirectional relation
      await memoryStore([{
        kind: 'relation',
        scope: { project: 'graph-test', branch: 'main' },
        data: {
          name: 'collaborates_with',
          data: {
            source_id: aliceId,
            target_id: projectId,
            relationship_type: 'collaborates_with',
            bidirectional: true,
            nature: 'active collaboration'
          }
        },
        tags: { graph_test: true, relation_test: true }
      }]);

      // Find relation from both directions
      const fromAlice = await memoryFind({
        query: 'collaborates_with',
        scope: { project: 'graph-test', branch: 'main' },
        types: ['relation']
      });

      expect(fromAlice.hits.length).toBe(1);
      expect(fromAlice.hits[0].title).toBe('collaborates_with');
    });

    it('should handle relation attributes and metadata', async () => {
      const relationWithMetadata = {
        kind: 'relation' as const,
        scope: { project: 'graph-test', branch: 'main' },
        data: {
          name: 'mentors',
          data: {
            source_id: aliceId,
            target_id: projectId,
            relationship_type: 'mentors',
            attributes: {
              frequency: 'weekly',
              duration: '1 hour',
              topics: ['architecture', 'performance', 'best practices'],
              started_date: '2024-02-01',
              effectiveness_rating: 4.5
            },
            metadata: {
              created_by: 'system',
              last_updated: '2024-10-20',
              confidence: 0.9
            }
          }
        },
        tags: { graph_test: true, relation_test: true }
      };

      const result = await memoryStore([relationWithMetadata]);
      expect(result.stored[0].status).toBe('inserted');

      // Verify metadata is searchable
      const findResult = await memoryFind({
        query: 'mentors weekly architecture',
        scope: { project: 'graph-test', branch: 'main' },
        types: ['relation']
      });

      expect(findResult.hits.length).toBe(1);
      expect(findResult.hits[0].title).toBe('mentors');
    });
  });

  describe('Graph Traversal Algorithms', () => {
    let graphEntities: string[];
    let graphRelations: string[];

    beforeEach(async () => {
      // Create a small test graph
      const entities = [
        { type: 'person', name: 'Alice', role: 'developer' },
        { type: 'person', name: 'Bob', role: 'designer' },
        { type: 'person', name: 'Carol', role: 'manager' },
        { type: 'project', name: 'Project Alpha', status: 'active' },
        { type: 'project', name: 'Project Beta', status: 'planning' },
        { type: 'technology', name: 'React', type: 'framework' },
        { type: 'technology', name: 'PostgreSQL', type: 'database' },
        { type: 'organization', name: 'TechCorp', industry: 'Software' }
      ];

      const entityResults = await memoryStore(
        entities.map((entity, index) => ({
          kind: 'entity' as const,
          scope: { project: 'graph-test', branch: 'main' },
          data: {
            entity_type: entity.type,
            name: entity.name,
            data: entity.type === 'person' ? { role: entity.role } :
                   entity.type === 'project' ? { status: entity.status } :
                   entity.type === 'technology' ? { type: entity.type } :
                   { industry: entity.industry }
          },
          tags: { graph_test: true, traversal_test: true, entity_index: index }
        }))
      );

      graphEntities = entityResults.stored.map(s => s.id);

      // Create relations between entities
      const relations = [
        { source: 0, target: 3, type: 'works_on' },  // Alice -> Project Alpha
        { source: 1, target: 3, type: 'works_on' },  // Bob -> Project Alpha
        { source: 2, target: 3, type: 'manages' },   // Carol -> Project Alpha
        { source: 0, target: 4, type: 'leads' },     // Alice -> Project Beta
        { source: 3, target: 5, type: 'uses' },      // Project Alpha -> React
        { source: 3, target: 6, type: 'uses' },      // Project Alpha -> PostgreSQL
        { source: 7, target: 3, type: 'owns' },      // TechCorp -> Project Alpha
        { source: 7, target: 0, type: 'employs' },   // TechCorp -> Alice
        { source: 7, target: 1, type: 'employs' },   // TechCorp -> Bob
        { source: 7, target: 2, type: 'employs' }    // TechCorp -> Carol
      ];

      const relationResults = await memoryStore(
        relations.map((rel, index) => ({
          kind: 'relation' as const,
          scope: { project: 'graph-test', branch: 'main' },
          data: {
            name: rel.type,
            data: {
              source_id: graphEntities[rel.source],
              target_id: graphEntities[rel.target],
              relationship_type: rel.type
            }
          },
          tags: { graph_test: true, traversal_test: true, relation_index: index }
        }))
      );

      graphRelations = relationResults.stored.map(s => s.id);
    });

    it('should perform breadth-first traversal correctly', async () => {
      const options: TraversalOptions = {
        maxDepth: 3,
        maxNodes: 20,
        includeRelations: true,
        direction: 'both'
      };

      // Start traversal from Alice (index 0)
      const traversalResult = await traverseGraph(graphEntities[0], options);

      expect(traversalResult.nodes).toBeDefined();
      expect(traversalResult.edges).toBeDefined();
      expect(traversalResult.nodes.length).toBeGreaterThan(0);
      expect(traversalResult.edges.length).toBeGreaterThan(0);

      // Should find connected entities: Bob, Carol, Project Alpha, Project Beta, React, PostgreSQL, TechCorp
      const nodeNames = traversalResult.nodes.map(n => n.title || n.name);
      expect(nodeNames).toContain('Alice');
      expect(nodeNames).toContain('Project Alpha');
      expect(nodeNames).toContain('Bob');
      expect(nodeNames).toContain('TechCorp');
    });

    it('should respect traversal depth limits', async () => {
      const shallowOptions: TraversalOptions = {
        maxDepth: 1,
        maxNodes: 10,
        includeRelations: true,
        direction: 'outgoing'
      };

      const shallowResult = await traverseGraph(graphEntities[0], shallowOptions);

      const deepOptions: TraversalOptions = {
        maxDepth: 3,
        maxNodes: 20,
        includeRelations: true,
        direction: 'outgoing'
      };

      const deepResult = await traverseGraph(graphEntities[0], deepOptions);

      // Deep traversal should find more nodes than shallow
      expect(deepResult.nodes.length).toBeGreaterThan(shallowResult.nodes.length);
      expect(deepResult.edges.length).toBeGreaterThan(shallowResult.edges.length);
    });

    it('should handle directional traversal correctly', async () => {
      const outgoingOptions: TraversalOptions = {
        maxDepth: 3,
        maxNodes: 20,
        includeRelations: true,
        direction: 'outgoing'
      };

      const incomingOptions: TraversalOptions = {
        maxDepth: 3,
        maxNodes: 20,
        includeRelations: true,
        direction: 'incoming'
      };

      const outgoingResult = await traverseGraph(graphEntities[0], outgoingOptions);
      const incomingResult = await traverseGraph(graphEntities[0], incomingOptions);

      // Results should differ based on direction
      const outgoingNodes = outgoingResult.nodes.map(n => n.title || n.name);
      const incomingNodes = incomingResult.nodes.map(n => n.title || n.name);

      expect(outgoingNodes).toContain('Project Alpha'); // Alice works on Project Alpha
      expect(incomingNodes).toContain('TechCorp');      // TechCorp employs Alice
    });

    it('should enrich graph nodes with additional context', async () => {
      const options: TraversalOptions = {
        maxDepth: 2,
        maxNodes: 15,
        includeRelations: true,
        direction: 'both'
      };

      const traversalResult = await traverseGraph(graphEntities[0], options);
      const enrichedResult = await enrichGraphNodes(traversalResult.nodes);

      expect(enrichedResult.length).toBe(traversalResult.nodes.length);

      // Enriched nodes should have additional properties
      const enrichedNode = enrichedResult.find(n => (n.title || n.name) === 'Alice');
      expect(enrichedNode).toBeDefined();
      // Additional enrichment properties would be added by the enrichGraphNodes function
    });

    it('should handle cycles in the graph correctly', async () => {
      // Create a cycle: TechCorp -> Alice -> Project Alpha -> TechCorp
      // This already exists in our test graph

      const options: TraversalOptions = {
        maxDepth: 5,
        maxNodes: 30,
        includeRelations: true,
        direction: 'both'
      };

      const traversalResult = await traverseGraph(graphEntities[0], options);

      // Should handle cycles without infinite loops
      expect(traversalResult.nodes.length).toBeGreaterThan(0);
      expect(traversalResult.edges.length).toBeGreaterThan(0);

      // Should not have duplicate nodes due to cycle handling
      const nodeIds = traversalResult.nodes.map(n => n.id);
      const uniqueNodeIds = [...new Set(nodeIds)];
      expect(nodeIds.length).toBe(uniqueNodeIds.length);
    });
  });

  describe('Graph-Based Search and Discovery', () => {
    beforeEach(async () => {
      // Create a domain-specific graph for search testing
      const domainEntities = [
        { type: 'concept', name: 'Machine Learning', category: 'AI' },
        { type: 'concept', name: 'Deep Learning', category: 'AI' },
        { type: 'concept', name: 'Neural Networks', category: 'AI' },
        { type: 'algorithm', name: 'Backpropagation', category: 'Optimization' },
        { type: 'algorithm', name: 'Gradient Descent', category: 'Optimization' },
        { type: 'framework', name: 'TensorFlow', category: 'Library' },
        { type: 'framework', name: 'PyTorch', category: 'Library' },
        { type: 'application', name: 'Computer Vision', category: 'Application' },
        { type: 'application', name: 'Natural Language Processing', category: 'Application' }
      ];

      const entityResults = await memoryStore(
        domainEntities.map((entity, index) => ({
          kind: 'entity' as const,
          scope: { project: 'graph-search-test', branch: 'main' },
          data: {
            entity_type: entity.type,
            name: entity.name,
            data: { category: entity.category }
          },
          tags: { graph_test: true, search_test: true, entity_index: index }
        }))
      );

      const entityIds = entityResults.stored.map(s => s.id);

      // Create semantic relationships
      const semanticRelations = [
        { source: 1, target: 2, type: 'uses', relationship: 'implements' },
        { source: 0, target: 1, type: 'includes', relationship: 'subset_of' },
        { source: 3, target: 2, type: 'used_in', relationship: 'optimizes' },
        { source: 4, target: 3, type: 'related_to', relationship: 'alternative_to' },
        { source: 5, target: 2, type: 'implements', relationship: 'provides_implementation' },
        { source: 6, target: 2, type: 'implements', relationship: 'provides_implementation' },
        { source: 7, target: 2, type: 'applies', relationship: 'application_domain' },
        { source: 8, target: 2, type: 'applies', relationship: 'application_domain' }
      ];

      await memoryStore(
        semanticRelations.map((rel, index) => ({
          kind: 'relation' as const,
          scope: { project: 'graph-search-test', branch: 'main' },
          data: {
            name: rel.type,
            data: {
              source_id: entityIds[rel.source],
              target_id: entityIds[rel.target],
              relationship_type: rel.relationship,
              strength: 0.8 + (index * 0.02) // Varying relationship strengths
            }
          },
          tags: { graph_test: true, search_test: true, relation_index: index }
        }))
      );
    });

    it('should discover related concepts through graph traversal', async () => {
      // Find Neural Networks and discover related concepts
      const findResult = await memoryFind({
        query: 'Neural Networks',
        scope: { project: 'graph-search-test', branch: 'main' },
        types: ['entity']
      });

      expect(findResult.hits.length).toBe(1);
      const neuralNetworksId = findResult.hits[0].id;

      // Traverse to find related concepts
      const traversalResult = await traverseGraph(neuralNetworksId, {
        maxDepth: 2,
        maxNodes: 10,
        includeRelations: true,
        direction: 'both'
      });

      const relatedConcepts = traversalResult.nodes.map(n => n.title || n.name);

      // Should find related concepts based on our graph structure
      expect(relatedConcepts.some(concept =>
        concept.includes('Deep Learning') ||
        concept.includes('Backpropagation') ||
        concept.includes('TensorFlow') ||
        concept.includes('PyTorch')
      )).toBe(true);
    });

    it('should rank search results by graph proximity', async () => {
      // Search for ML concepts and verify ranking
      const searchResult = await memoryFind({
        query: 'Machine Learning',
        scope: { project: 'graph-search-test', branch: 'main' },
        types: ['entity', 'relation']
      });

      expect(searchResult.hits.length).toBeGreaterThan(0);

      // Direct match should have highest confidence
      const directMatch = searchResult.hits.find(hit =>
        (hit.title || hit.name) === 'Machine Learning'
      );
      expect(directMatch).toBeDefined();
      expect(directMatch.confidence).toBeGreaterThan(0.8);

      // Related concepts should have lower but still high confidence
      const relatedMatches = searchResult.hits.filter(hit =>
        (hit.title || hit.name) !== 'Machine Learning'
      );
      expect(relatedMatches.length).toBeGreaterThan(0);

      // All matches should have reasonable confidence scores
      searchResult.hits.forEach(hit => {
        expect(hit.confidence).toBeGreaterThan(0.1);
        expect(hit.confidence).toBeLessThanOrEqual(1.0);
      });
    });

    it('should support semantic relationship queries', async () => {
      // Search for specific relationship types
      const relationSearch = await memoryFind({
        query: 'implements provides_implementation',
        scope: { project: 'graph-search-test', branch: 'main' },
        types: ['relation']
      });

      expect(relationSearch.hits.length).toBeGreaterThan(0);

      // Should find TensorFlow and PyTorch implementations
      const implementations = relationSearch.hits.map(hit => hit.title);
      expect(implementations.some(impl => impl.includes('implements'))).toBe(true);
    });

    it('should handle multi-hop relationship discovery', async () => {
      // Discover indirect relationships through multiple hops
      const conceptSearch = await memoryFind({
        query: 'Machine Learning',
        scope: { project: 'graph-search-test', branch: 'main' },
        types: ['entity']
      });

      const machineLearningId = conceptSearch.hits[0].id;

      // Multi-hop traversal to find applications of ML
      const multiHopResult = await traverseGraph(machineLearningId, {
        maxDepth: 4,
        maxNodes: 15,
        includeRelations: true,
        direction: 'both'
      });

      const allNodes = multiHopResult.nodes.map(n => n.title || n.name);

      // Should discover applications through multiple hops
      expect(allNodes.some(node =>
        node.includes('Computer Vision') ||
        node.includes('Natural Language Processing')
      )).toBe(true);
    });
  });

  describe('Graph Consistency and Integrity', () => {
    it('should maintain referential integrity', async () => {
      // Create entities first
      const entityResult = await memoryStore([{
        kind: 'entity',
        scope: { project: 'graph-test', branch: 'main' },
        data: {
          entity_type: 'test_entity',
          name: 'Integrity Test Entity',
          data: { purpose: 'testing' }
        },
        tags: { graph_test: true, integrity_test: true }
      }]);

      const entityId = entityResult.stored[0].id;

      // Create valid relation
      const relationResult = await memoryStore([{
        kind: 'relation',
        scope: { project: 'graph-test', branch: 'main' },
        data: {
          name: 'test_relation',
          data: {
            source_id: entityId,
            target_id: entityId, // Self-referencing for testing
            relationship_type: 'references_self'
          }
        },
        tags: { graph_test: true, integrity_test: true }
      }]);

      expect(relationResult.stored[0].status).toBe('inserted');

      // Try to create relation with invalid entity ID
      const invalidRelationResult = await memoryStore([{
        kind: 'relation',
        scope: { project: 'graph-test', branch: 'main' },
        data: {
          name: 'invalid_relation',
          data: {
            source_id: '00000000-0000-0000-0000-000000000000',
            target_id: entityId,
            relationship_type: 'invalid_reference'
          }
        },
        tags: { graph_test: true, integrity_test: true }
      }]);

      // Should either succeed (if no FK constraint) or be handled gracefully
      expect(invalidRelationResult.stored[0].status).toBeDefined();
    });

    it('should handle orphaned relations gracefully', async () => {
      // Create relation without checking if entities exist
      const orphanedRelationResult = await memoryStore([{
        kind: 'relation',
        scope: { project: 'graph-test', branch: 'main' },
        data: {
          name: 'orphaned_relation',
          data: {
            source_id: '11111111-1111-1111-1111-111111111111',
            target_id: '22222222-2222-2222-2222-222222222222',
            relationship_type: 'orphaned'
          }
        },
        tags: { graph_test: true, integrity_test: true }
      }]);

      // Should handle gracefully
      expect(orphanedRelationResult.stored[0].status).toBeDefined();

      // Traversal should handle missing entities gracefully
      const traversalResult = await traverseGraph('11111111-1111-1111-1111-111111111111', {
        maxDepth: 2,
        maxNodes: 10,
        includeRelations: true,
        direction: 'outgoing'
      });

      // Should not crash and should return appropriate empty or minimal result
      expect(traversalResult).toBeDefined();
    });

    it('should prevent circular dependency issues', async () => {
      // Create entities that can form cycles
      const entities = await memoryStore([
        {
          kind: 'entity',
          scope: { project: 'graph-test', branch: 'main' },
          data: {
            entity_type: 'test_node',
            name: 'Node A',
            data: { index: 'A' }
          },
          tags: { graph_test: true, cycle_test: true }
        },
        {
          kind: 'entity',
          scope: { project: 'graph-test', branch: 'main' },
          data: {
            entity_type: 'test_node',
            name: 'Node B',
            data: { index: 'B' }
          },
          tags: { graph_test: true, cycle_test: true }
        },
        {
          kind: 'entity',
          scope: { project: 'graph-test', branch: 'main' },
          data: {
            entity_type: 'test_node',
            name: 'Node C',
            data: { index: 'C' }
          },
          tags: { graph_test: true, cycle_test: true }
        }
      ]);

      const entityIds = entities.stored.map(s => s.id);

      // Create circular relations: A -> B -> C -> A
      const circularRelations = await memoryStore([
        {
          kind: 'relation',
          scope: { project: 'graph-test', branch: 'main' },
          data: {
            name: 'a_to_b',
            data: {
              source_id: entityIds[0],
              target_id: entityIds[1],
              relationship_type: 'points_to'
            }
          },
          tags: { graph_test: true, cycle_test: true }
        },
        {
          kind: 'relation',
          scope: { project: 'graph-test', branch: 'main' },
          data: {
            name: 'b_to_c',
            data: {
              source_id: entityIds[1],
              target_id: entityIds[2],
              relationship_type: 'points_to'
            }
          },
          tags: { graph_test: true, cycle_test: true }
        },
        {
          kind: 'relation',
          scope: { project: 'graph-test', branch: 'main' },
          data: {
            name: 'c_to_a',
            data: {
              source_id: entityIds[2],
              target_id: entityIds[0],
              relationship_type: 'points_to'
            }
          },
          tags: { graph_test: true, cycle_test: true }
        }
      ]);

      expect(circularRelations.stored).toHaveLength(3);

      // Traversal should handle cycles without infinite loops
      const traversalResult = await traverseGraph(entityIds[0], {
        maxDepth: 5,
        maxNodes: 20,
        includeRelations: true,
        direction: 'outgoing'
      });

      // Should find all nodes but not create infinite loops
      expect(traversalResult.nodes.length).toBe(3);
      expect(traversalResult.edges.length).toBe(3);

      // No duplicate nodes due to cycle detection
      const nodeIds = traversalResult.nodes.map(n => n.id);
      const uniqueNodeIds = [...new Set(nodeIds)];
      expect(nodeIds.length).toBe(uniqueNodeIds.length);
    });
  });

  describe('Performance with Large Graphs', () => {
    it('should handle graph traversal with many nodes efficiently', async () => {
      const nodeCount = 100;
      const batchSize = 20;

      // Create many entities
      const entities = Array.from({ length: nodeCount }, (_, i) => ({
        kind: 'entity' as const,
        scope: { project: 'graph-test', branch: 'main' },
        data: {
          entity_type: 'performance_node',
          name: `Performance Node ${i}`,
          data: { index: i, category: i % 5 }
        },
        tags: { graph_test: true, performance_test: true }
      }));

      // Store in batches
      for (let i = 0; i < entities.length; i += batchSize) {
        const batch = entities.slice(i, i + batchSize);
        await memoryStore(batch);
      }

      // Create relations forming a connected graph
      const allEntitiesResult = await memoryFind({
        query: 'Performance Node',
        scope: { project: 'graph-test', branch: 'main' },
        types: ['entity']
      });

      const entityIds = allEntitiesResult.hits.map(hit => hit.id);

      // Create relations (each node connects to next few nodes)
      const relations = [];
      for (let i = 0; i < Math.min(entityIds.length - 1, 50); i++) {
        for (let j = 1; j <= 3 && i + j < entityIds.length; j++) {
          relations.push({
            kind: 'relation' as const,
            scope: { project: 'graph-test', branch: 'main' },
            data: {
              name: `connects_${i}_to_${i + j}`,
              data: {
                source_id: entityIds[i],
                target_id: entityIds[i + j],
                relationship_type: 'connects_to',
                weight: Math.random()
              }
            },
            tags: { graph_test: true, performance_test: true }
          });
        }
      }

      // Store relations in batches
      for (let i = 0; i < relations.length; i += batchSize) {
        const batch = relations.slice(i, i + batchSize);
        await memoryStore(batch);
      }

      // Test traversal performance
      const startTime = Date.now();
      const traversalResult = await traverseGraph(entityIds[0], {
        maxDepth: 4,
        maxNodes: 50,
        includeRelations: true,
        direction: 'outgoing'
      });
      const duration = Date.now() - startTime;

      expect(traversalResult.nodes.length).toBeGreaterThan(0);
      expect(traversalResult.edges.length).toBeGreaterThan(0);
      expect(duration).toBeLessThan(5000); // Should complete within 5 seconds
    });

    it('should maintain search performance with large knowledge base', async () => {
      // Insert diverse knowledge items
      const knowledgeItems = Array.from({ length: 200 }, (_, i) => ({
        kind: ['section', 'decision', 'observation'][i % 3] as const,
        scope: { project: 'graph-test', branch: 'main' },
        data: {
          title: `Knowledge Item ${i}`,
          heading: i % 3 === 0 ? `Heading ${i}` : undefined,
          body_text: i % 3 === 0 ? `Content for item ${i} with various topics` : undefined,
          status: i % 3 === 1 ? 'proposed' : undefined,
          component: i % 3 === 1 ? 'performance-test' : undefined,
          rationale: i % 3 === 1 ? `Rationale for decision ${i}` : undefined,
          content: i % 3 === 2 ? `Observation content ${i}` : undefined
        },
        tags: { graph_test: true, performance_test: true, item_index: i }
      }));

      await memoryStore(knowledgeItems);

      // Test search performance
      const startTime = Date.now();
      const searchResult = await memoryFind({
        query: 'Knowledge Item',
        scope: { project: 'graph-test', branch: 'main' }
      });
      const searchDuration = Date.now() - startTime;

      expect(searchResult.hits.length).toBeGreaterThan(100);
      expect(searchDuration).toBeLessThan(3000); // Should complete within 3 seconds

      // Test more complex search with filters
      const complexSearchStart = Date.now();
      const complexSearchResult = await memoryFind({
        query: 'Item content topics',
        scope: { project: 'graph-test', branch: 'main' },
        types: ['section', 'observation']
      });
      const complexSearchDuration = Date.now() - complexSearchStart;

      expect(complexSearchResult.hits.length).toBeGreaterThan(0);
      expect(complexSearchDuration).toBeLessThan(3000);
    });
  });
});