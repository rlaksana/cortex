/**
 * Schema Integration Tests for All 16 Knowledge Types
 *
 * Comprehensive tests covering CRUD operations, constraints, and performance benchmarks
 * for all 16 knowledge types in the Cortex Memory MCP system.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  KnowledgeItemSchema,
  SectionSchema,
  RunbookSchema,
  ChangeSchema,
  IssueSchema,
  DecisionSchema,
  TodoSchema,
  ReleaseNoteSchema,
  DDLSchema,
  PRContextSchema,
  EntitySchema,
  RelationSchema,
  ObservationSchema,
  IncidentSchema,
  ReleaseSchema,
  RiskSchema,
  AssumptionSchema,
  validateKnowledgeItem,
  safeValidateKnowledgeItem,
  violatesADRImmutability,
  violatesSpecWriteLock,
  type KnowledgeItem,
  type SectionItem,
  type DecisionItem
} from '../schemas/knowledge-types.ts';
import { memoryStore } from '../services/memory-store.ts';
import { memoryFind } from '../services/memory-find.ts';
import { softDelete } from '../services/delete-operations.ts';

describe('Schema Integration Tests - All 16 Knowledge Types', () => {
  const baseScope = {
    project: 'test-project',
    branch: 'main'
  };

  const baseSource = {
    actor: 'test-user',
    timestamp: new Date().toISOString()
  };

  // Test data factories for each knowledge type
  const createSectionData = (overrides = {}) => ({
    title: 'Test Section',
    heading: 'Test Heading',
    body_md: '# Test Content\nThis is test content.',
    ...overrides
  });

  const createRunbookData = (overrides = {}) => ({
    service: 'test-service',
    title: 'Test Runbook',
    steps: [
      {
        step_number: 1,
        description: 'Test step 1',
        command: 'echo "test"',
        expected_outcome: 'Success'
      }
    ],
    ...overrides
  });

  const createChangeData = (overrides = {}) => ({
    change_type: 'feature_add' as const,
    subject_ref: 'commit-123',
    summary: 'Test feature addition',
    details: 'Added new test functionality',
    ...overrides
  });

  const createIssueData = (overrides = {}) => ({
    tracker: 'github',
    external_id: 'GH-123',
    title: 'Test Issue',
    status: 'open' as const,
    description: 'Test issue description',
    ...overrides
  });

  const createDecisionData = (overrides = {}) => ({
    component: 'test-component',
    status: 'proposed' as const,
    title: 'Test Decision',
    rationale: 'This is a test decision with clear rationale',
    ...overrides
  });

  const createTodoData = (overrides = {}) => ({
    scope: 'task',
    todo_type: 'task' as const,
    text: 'Test todo item',
    status: 'open' as const,
    priority: 'medium' as const,
    ...overrides
  });

  const createReleaseNoteData = (overrides = {}) => ({
    version: '1.0.0',
    release_date: new Date().toISOString(),
    summary: 'Initial release',
    new_features: ['Feature 1', 'Feature 2'],
    ...overrides
  });

  const createDDLData = (overrides = {}) => ({
    migration_id: '001_initial',
    ddl_text: 'CREATE TABLE test_table (id SERIAL PRIMARY KEY);',
    checksum: 'a'.repeat(64), // Mock SHA-256 hash
    description: 'Initial migration',
    ...overrides
  });

  const createPRContextData = (overrides = {}) => ({
    pr_number: 123,
    title: 'Test PR',
    author: 'test-user',
    status: 'open' as const,
    base_branch: 'main',
    head_branch: 'feature-branch',
    ...overrides
  });

  const createEntityData = (overrides = {}) => ({
    entity_type: 'user',
    name: 'test-user',
    data: { email: 'test@example.com', role: 'developer' },
    ...overrides
  });

  const createRelationData = (overrides = {}) => ({
    from_entity_type: 'decision',
    from_entity_id: '123e4567-e89b-12d3-a456-426614174000',
    to_entity_type: 'issue',
    to_entity_id: '123e4567-e89b-12d3-a456-426614174001',
    relation_type: 'resolves',
    metadata: { confidence: 0.9 },
    ...overrides
  });

  const createObservationData = (overrides = {}) => ({
    entity_type: 'decision',
    entity_id: '123e4567-e89b-12d3-a456-426614174000',
    observation: 'status: implemented',
    observation_type: 'status',
    ...overrides
  });

  const createIncidentData = (overrides = {}) => ({
    title: 'Test Incident',
    severity: 'medium' as const,
    impact: 'Service degradation',
    resolution_status: 'open' as const,
    timeline: [
      {
        timestamp: new Date().toISOString(),
        event: 'Incident detected',
        actor: 'monitoring-system'
      }
    ],
    ...overrides
  });

  const createReleaseData = (overrides = {}) => ({
    version: '1.0.0',
    release_type: 'major' as const,
    scope: 'Full application release',
    status: 'planned' as const,
    release_date: new Date().toISOString(),
    ...overrides
  });

  const createRiskData = (overrides = {}) => ({
    title: 'Test Risk',
    category: 'technical' as const,
    risk_level: 'medium' as const,
    probability: 'possible' as const,
    impact_description: 'Potential service interruption',
    mitigation_strategies: ['Monitoring', 'Backup systems'],
    ...overrides
  });

  const createAssumptionData = (overrides = {}) => ({
    title: 'Test Assumption',
    description: 'System can handle 1000 concurrent users',
    category: 'technical' as const,
    validation_status: 'assumed' as const,
    impact_if_invalid: 'Performance degradation',
    ...overrides
  });

  // Knowledge type schemas with their corresponding test data factories
  const knowledgeTypes = [
    { schema: SectionSchema, factory: createSectionData, kind: 'section' },
    { schema: RunbookSchema, factory: createRunbookData, kind: 'runbook' },
    { schema: ChangeSchema, factory: createChangeData, kind: 'change' },
    { schema: IssueSchema, factory: createIssueData, kind: 'issue' },
    { schema: DecisionSchema, factory: createDecisionData, kind: 'decision' },
    { schema: TodoSchema, factory: createTodoData, kind: 'todo' },
    { schema: ReleaseNoteSchema, factory: createReleaseNoteData, kind: 'release_note' },
    { schema: DDLSchema, factory: createDDLData, kind: 'ddl' },
    { schema: PRContextSchema, factory: createPRContextData, kind: 'pr_context' },
    { schema: EntitySchema, factory: createEntityData, kind: 'entity' },
    { schema: RelationSchema, factory: createRelationData, kind: 'relation' },
    { schema: ObservationSchema, factory: createObservationData, kind: 'observation' },
    { schema: IncidentSchema, factory: createIncidentData, kind: 'incident' },
    { schema: ReleaseSchema, factory: createReleaseData, kind: 'release' },
    { schema: RiskSchema, factory: createRiskData, kind: 'risk' },
    { schema: AssumptionSchema, factory: createAssumptionData, kind: 'assumption' }
  ];

  describe('Schema Validation', () => {
    knowledgeTypes.forEach(({ schema, factory, kind }) => {
      describe(`${kind} knowledge type`, () => {
        it('should validate valid data', () => {
          const data = factory();
          const item = {
            kind,
            scope: baseScope,
            data,
            source: baseSource
          };

          const result = schema.safeParse(item);
          expect(result.success).toBe(true);
        });

        it('should validate with optional fields', () => {
          const data = factory();
          const item = {
            kind,
            scope: baseScope,
            data,
            tags: { category: 'test' },
            source: baseSource,
            idempotency_key: 'test-key-123',
            ttl_policy: 'long' as const
          };

          const result = schema.safeParse(item);
          expect(result.success).toBe(true);
        });

        it('should reject invalid kind', () => {
          const data = factory();
          const item = {
            kind: 'invalid_kind',
            scope: baseScope,
            data
          };

          const result = schema.safeParse(item);
          expect(result.success).toBe(false);
        });

        it('should reject missing required scope', () => {
          const data = factory();
          const item = {
            kind,
            data
          };

          const result = schema.safeParse(item);
          expect(result.success).toBe(false);
        });

        it('should reject invalid data structure', () => {
          const item = {
            kind,
            scope: baseScope,
            data: { invalid_field: 'test' }
          };

          const result = schema.safeParse(item);
          expect(result.success).toBe(false);
        });
      });
    });
  });

  describe('Discriminated Union Validation', () => {
    it('should validate all 16 knowledge types through discriminated union', () => {
      knowledgeTypes.forEach(({ factory, kind }) => {
        const data = factory();
        const item = {
          kind,
          scope: baseScope,
          data,
          source: baseSource
        };

        const result = KnowledgeItemSchema.safeParse(item);
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.kind).toBe(kind);
        }
      });
    });

    it('should reject invalid knowledge type in discriminated union', () => {
      const item = {
        kind: 'invalid_type',
        scope: baseScope,
        data: { test: 'data' }
      };

      const result = KnowledgeItemSchema.safeParse(item);
      expect(result.success).toBe(false);
    });
  });

  describe('CRUD Operations Integration', () => {
    let storedItems: KnowledgeItem[] = [];

    beforeEach(() => {
      storedItems = [];
    });

    knowledgeTypes.forEach(({ factory, kind }) => {
      describe(`${kind} CRUD operations`, () => {
        it('should store and retrieve item', async () => {
          const data = factory();
          const item = {
            kind,
            scope: baseScope,
            data,
            source: baseSource
          };

          // Store the item
          const storeResult = await memoryStore([item]);
          expect(storeResult.errors).toHaveLength(0);
          expect(storeResult.stored).toHaveLength(1);

          storedItems.push(storeResult.stored[0]);

          // Find the item
          const findResult = await memoryFind({
            query: kind,
            scope: baseScope
          });

          expect(findResult.results).toHaveLength(1);
          expect(findResult.results[0].kind).toBe(kind);
        });

        it('should update existing item', async () => {
          // First store an item
          const data = factory();
          const item = {
            kind,
            scope: baseScope,
            data,
            source: baseSource
          };

          const storeResult = await memoryStore([item]);
          const storedItem = storeResult.stored[0];
          storedItems.push(storedItem);

          // Update the item
          const updatedData = factory({ title: 'Updated Title' });
          const updatedItem = {
            kind,
            scope: baseScope,
            data: { ...updatedData, id: storedItem.id },
            source: baseSource
          };

          const updateResult = await memoryStore([updatedItem]);
          expect(updateResult.errors).toHaveLength(0);

          // Verify update
          const findResult = await memoryFind({
            query: 'Updated Title',
            scope: baseScope
          });

          expect(findResult.results).toHaveLength(1);
        });

        it('should delete item', async () => {
          // Store an item first
          const data = factory();
          const item = {
            kind,
            scope: baseScope,
            data,
            source: baseSource
          };

          const storeResult = await memoryStore([item]);
          const storedItem = storeResult.stored[0];
          storedItems.push(storedItem);

          // Delete the item
          const deleteResult = await softDelete({
            entity_type: kind,
            entity_id: storedItem.id
          } as any);

          expect(['success', 'not_found']).toContain(deleteResult.status);

          // Verify deletion
          const findResult = await memoryFind({
            query: kind,
            scope: baseScope
          });

          // Should not find the deleted item
          const deletedItem = findResult.results.find(r => r.id === storedItem.id);
          expect(deletedItem).toBeUndefined();
        });
      });
    });
  });

  describe('Constraint Validation', () => {
    describe('Section constraints', () => {
      it('should require either body_md or body_text', () => {
        const data = {
          title: 'Test Section',
          heading: 'Test Heading'
          // Missing both body_md and body_text
        };

        const item = {
          kind: 'section' as const,
          scope: baseScope,
          data
        };

        const result = SectionSchema.safeParse(item);
        expect(result.success).toBe(false);
        if (!result.success) {
          expect(result.error.errors[0].message).toContain('Either body_md or body_text must be provided');
        }
      });

      it('should enforce title length limits', () => {
        const data = createSectionData({
          title: 'a'.repeat(501) // Exceeds 500 character limit
        });

        const item = {
          kind: 'section' as const,
          scope: baseScope,
          data
        };

        const result = SectionSchema.safeParse(item);
        expect(result.success).toBe(false);
      });
    });

    describe('Runbook constraints', () => {
      it('should require at least one step', () => {
        const data = {
          service: 'test-service',
          title: 'Test Runbook',
          steps: [] // Empty steps array
        };

        const item = {
          kind: 'runbook' as const,
          scope: baseScope,
          data
        };

        const result = RunbookSchema.safeParse(item);
        expect(result.success).toBe(false);
      });

      it('should validate step structure', () => {
        const data = {
          service: 'test-service',
          title: 'Test Runbook',
          steps: [
            {
              step_number: 1,
              description: 'Test step'
              // Missing required fields
            }
          ]
        };

        const item = {
          kind: 'runbook' as const,
          scope: baseScope,
          data
        };

        const result = RunbookSchema.safeParse(item);
        expect(result.success).toBe(false);
      });
    });

    describe('DDL constraints', () => {
      it('should require 64-character checksum', () => {
        const data = createDDLData({
          checksum: 'invalid-checksum' // Not 64 characters
        });

        const item = {
          kind: 'ddl' as const,
          scope: baseScope,
          data
        };

        const result = DDLSchema.safeParse(item);
        expect(result.success).toBe(false);
      });

      it('should require DDL text', () => {
        const data = createDDLData({
          ddl_text: '' // Empty DDL text
        });

        const item = {
          kind: 'ddl' as const,
          scope: baseScope,
          data
        };

        const result = DDLSchema.safeParse(item);
        expect(result.success).toBe(false);
      });
    });

    describe('Relation constraints', () => {
      it('should require valid UUIDs for entity IDs', () => {
        const data = createRelationData({
          from_entity_id: 'invalid-uuid',
          to_entity_id: 'invalid-uuid'
        });

        const item = {
          kind: 'relation' as const,
          scope: baseScope,
          data
        };

        const result = RelationSchema.safeParse(item);
        expect(result.success).toBe(false);
      });
    });

    describe('Observation constraints', () => {
      it('should require valid UUID for entity ID', () => {
        const data = createObservationData({
          entity_id: 'invalid-uuid'
        });

        const item = {
          kind: 'observation' as const,
          scope: baseScope,
          data
        };

        const result = ObservationSchema.safeParse(item);
        expect(result.success).toBe(false);
      });
    });

    describe('PR Context constraints', () => {
      it('should require positive PR number', () => {
        const data = createPRContextData({
          pr_number: -1 // Invalid negative number
        });

        const item = {
          kind: 'pr_context' as const,
          scope: baseScope,
          data
        };

        const result = PRContextSchema.safeParse(item);
        expect(result.success).toBe(false);
      });

      it('should require valid URLs for URL field', () => {
        const data = createIssueData({
          url: 'invalid-url' // Not a valid URL
        });

        const item = {
          kind: 'issue' as const,
          scope: baseScope,
          data
        };

        const result = IssueSchema.safeParse(item);
        expect(result.success).toBe(false);
      });
    });
  });

  describe('Immutability Constraints', () => {
    describe('ADR Immutability', () => {
      it('should allow updates for non-accepted decisions', () => {
        const existing: DecisionItem = {
          kind: 'decision',
          scope: baseScope,
          data: {
            ...createDecisionData(),
            status: 'proposed'
          }
        };

        const incoming: DecisionItem = {
          kind: 'decision',
          scope: baseScope,
          data: {
            ...createDecisionData(),
            status: 'proposed',
            title: 'Updated Title' // Content change
          }
        };

        expect(violatesADRImmutability(existing, incoming)).toBe(false);
      });

      it('should reject content changes for accepted decisions', () => {
        const existing: DecisionItem = {
          kind: 'decision',
          scope: baseScope,
          data: {
            ...createDecisionData(),
            status: 'accepted'
          }
        };

        const incoming: DecisionItem = {
          kind: 'decision',
          scope: baseScope,
          data: {
            ...createDecisionData(),
            status: 'accepted',
            title: 'Updated Title' // Content change - not allowed
          }
        };

        expect(violatesADRImmutability(existing, incoming)).toBe(true);
      });

      it('should allow metadata updates for accepted decisions', () => {
        const existing: DecisionItem = {
          kind: 'decision',
          scope: baseScope,
          data: {
            ...createDecisionData(),
            status: 'accepted'
          }
        };

        const incoming: DecisionItem = {
          kind: 'decision',
          scope: baseScope,
          data: {
            ...existing.data,
            supersedes: '123e4567-e89b-12d3-a456-426614174000' // Metadata change - allowed
          }
        };

        expect(violatesADRImmutability(existing, incoming)).toBe(false);
      });
    });

    describe('Spec Write-Lock', () => {
      it('should allow updates for non-approved sections', () => {
        const existing: SectionItem = {
          kind: 'section',
          scope: baseScope,
          data: createSectionData(),
          tags: { approved: false }
        };

        const incoming: SectionItem = {
          kind: 'section',
          scope: baseScope,
          data: {
            ...createSectionData(),
            body_md: 'Updated content' // Content change
          },
          tags: { approved: false }
        };

        expect(violatesSpecWriteLock(existing, incoming)).toBe(false);
      });

      it('should reject content changes for approved sections', () => {
        const existing: SectionItem = {
          kind: 'section',
          scope: baseScope,
          data: createSectionData(),
          tags: { approved: true }
        };

        const incoming: SectionItem = {
          kind: 'section',
          scope: baseScope,
          data: {
            ...createSectionData(),
            body_md: 'Updated content' // Content change - not allowed
          },
          tags: { approved: true }
        };

        expect(violatesSpecWriteLock(existing, incoming)).toBe(true);
      });

      it('should allow metadata updates for approved sections', () => {
        const existing: SectionItem = {
          kind: 'section',
          scope: baseScope,
          data: createSectionData(),
          tags: { approved: true }
        };

        const incoming: SectionItem = {
          kind: 'section',
          scope: baseScope,
          data: existing.data, // No content change
          tags: {
            approved: true,
            citation_count: 10 // Metadata change - allowed
          }
        };

        expect(violatesSpecWriteLock(existing, incoming)).toBe(false);
      });
    });
  });

  describe('Performance Benchmarks', () => {
    describe('Validation Performance', () => {
      it('should validate 1000 items within acceptable time limits', () => {
        const startTime = performance.now();

        for (let i = 0; i < 1000; i++) {
          const data = createSectionData({
            title: `Section ${i}`,
            heading: `Heading ${i}`
          });

          const item = {
            kind: 'section' as const,
            scope: baseScope,
            data,
            source: baseSource
          };

          const result = SectionSchema.safeParse(item);
          expect(result.success).toBe(true);
        }

        const endTime = performance.now();
        const duration = endTime - startTime;

        // Should complete within 1 second (1000ms)
        expect(duration).toBeLessThan(1000);
        console.log(`Validated 1000 sections in ${duration.toFixed(2)}ms`);
      });

      it('should handle large batch operations efficiently', async () => {
        const batchSize = 100;
        const items = Array.from({ length: batchSize }, (_, i) => ({
          kind: 'entity' as const,
          scope: baseScope,
          data: createEntityData({
            name: `Entity ${i}`,
            data: { index: i, batch: 'test' }
          }),
          source: baseSource
        }));

        const startTime = performance.now();

        const result = await memoryStore(items);

        const endTime = performance.now();
        const duration = endTime - startTime;

        expect(result.errors).toHaveLength(0);
        expect(result.stored).toHaveLength(batchSize);

        // Should complete within 5 seconds for 100 items
        expect(duration).toBeLessThan(5000);
        console.log(`Stored ${batchSize} entities in ${duration.toFixed(2)}ms`);
      });
    });

    describe('Search Performance', () => {
      let storedItems: KnowledgeItem[] = [];

      beforeEach(async () => {
        // Store test data
        const items = Array.from({ length: 50 }, (_, i) => ({
          kind: 'entity' as const,
          scope: baseScope,
          data: createEntityData({
            name: `Performance Test Entity ${i}`,
            data: {
              type: 'performance-test',
              index: i,
              searchable_field: `searchable content ${i}`,
              tags: [`tag-${i % 5}`, `category-${i % 3}`]
            }
          })
        }));

        const result = await memoryStore(items);
        storedItems = result.stored;
      });

      it('should perform fast text search', async () => {
        const startTime = performance.now();

        const searchResult = await memoryFind({
          query: 'Performance Test Entity',
          scope: baseScope,
          top_k: 10
        });

        const endTime = performance.now();
        const duration = endTime - startTime;

        expect(searchResult.results.length).toBeGreaterThan(0);
        expect(duration).toBeLessThan(1000); // Should complete within 1 second

        console.log(`Text search completed in ${duration.toFixed(2)}ms, found ${searchResult.results.length} results`);
      });

      it('should perform efficient filtering', async () => {
        const startTime = performance.now();

        const searchResult = await memoryFind({
          query: 'entity',
          scope: baseScope,
          top_k: 20,
          filters: {
            kind: 'entity',
            data_fields: {
              'data.type': 'performance-test'
            }
          }
        });

        const endTime = performance.now();
        const duration = endTime - startTime;

        expect(searchResult.results.length).toBe(50); // All entities should match
        expect(duration).toBeLessThan(1000);

        console.log(`Filtered search completed in ${duration.toFixed(2)}ms, found ${searchResult.results.length} results`);
      });
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle circular references in entity data', () => {
      const circular: any = { name: 'test' };
      circular.self = circular;

      const item = {
        kind: 'entity' as const,
        scope: baseScope,
        data: createEntityData({ data: circular })
      };

      // Should handle gracefully without infinite loops
      const result = EntitySchema.safeParse(item);
      expect(result.success).toBe(true);
    });

    it('should handle very large text content', () => {
      const largeContent = 'x'.repeat(100000); // 100KB of text

      const item = {
        kind: 'section' as const,
        scope: baseScope,
        data: createSectionData({
          title: 'Large Content Test',
          body_md: largeContent
        })
      };

      const result = SectionSchema.safeParse(item);
      expect(result.success).toBe(true);
    });

    it('should handle special characters in data', () => {
      const specialChars = '!@#$%^&*()_+-=[]{}|;:,.<>?/~`';

      const item = {
        kind: 'entity' as const,
        scope: baseScope,
        data: createEntityData({
          name: `Special chars: ${specialChars}`,
          data: { special_chars: specialChars }
        })
      };

      const result = EntitySchema.safeParse(item);
      expect(result.success).toBe(true);
    });

    it('should handle Unicode content', () => {
      const unicodeContent = '🚀 Test with emoji: 🎉, Chinese: 中文, Arabic: العربية';

      const item = {
        kind: 'section' as const,
        scope: baseScope,
        data: createSectionData({
          title: 'Unicode Test',
          body_md: unicodeContent
        })
      };

      const result = SectionSchema.safeParse(item);
      expect(result.success).toBe(true);
    });
  });

  describe('Integration with Memory Services', () => {
    it('should validate items before storage', async () => {
      const invalidItem = {
        kind: 'section' as const,
        scope: baseScope,
        data: {
          title: '', // Invalid - empty title
          heading: 'Test'
          // Missing body_md or body_text
        }
      };

      const result = await memoryStore([invalidItem]);
      expect(result.errors).toHaveLength(1);
      expect(result.stored).toHaveLength(0);
    });

    it('should handle batch operations with mixed validity', async () => {
      const validItem = {
        kind: 'entity' as const,
        scope: baseScope,
        data: createEntityData()
      };

      const invalidItem = {
        kind: 'invalid_type' as const,
        scope: baseScope,
        data: {}
      };

      const result = await memoryStore([validItem, invalidItem]);
      expect(result.stored).toHaveLength(1);
      expect(result.errors).toHaveLength(1);
    });

    it('should maintain type safety through find operations', async () => {
      const items = [
        {
          kind: 'section' as const,
          scope: baseScope,
          data: createSectionData({ title: 'Section for search test' })
        },
        {
          kind: 'entity' as const,
          scope: baseScope,
          data: createEntityData({ name: 'Entity for search test' })
        }
      ];

      await memoryStore(items);

      const searchResult = await memoryFind({
        query: 'search test',
        scope: baseScope
      });

      expect(searchResult.results).toHaveLength(2);

      // Verify type safety
      const sectionResult = searchResult.results.find(r => r.kind === 'section');
      const entityResult = searchResult.results.find(r => r.kind === 'entity');

      expect(sectionResult?.kind).toBe('section');
      expect(entityResult?.kind).toBe('entity');
    });
  });

  describe('Schema Evolution Compatibility', () => {
    it('should handle missing optional fields gracefully', () => {
      // Simulate old data format with fewer fields
      const minimalItem = {
        kind: 'decision' as const,
        scope: baseScope,
        data: {
          component: 'test-component',
          status: 'accepted' as const,
          title: 'Test Decision',
          rationale: 'Test rationale'
          // Missing optional fields like alternatives_considered, consequences
        }
      };

      const result = DecisionSchema.safeParse(minimalItem);
      expect(result.success).toBe(true);
    });

    it('should maintain backward compatibility', () => {
      // Test that current schema can handle data from previous versions
      const legacyFormats = [
        {
          kind: 'section' as const,
          scope: baseScope,
          data: {
            title: 'Legacy Section',
            heading: 'Legacy Heading',
            body_md: 'Legacy content'
            // Missing newer optional fields
          }
        },
        {
          kind: 'entity' as const,
          scope: baseScope,
          data: {
            entity_type: 'user',
            name: 'legacy-user',
            data: {} // Empty data object should be valid
          }
        }
      ];

      legacyFormats.forEach(item => {
        const result = KnowledgeItemSchema.safeParse(item);
        expect(result.success).toBe(true);
      });
    });
  });
});