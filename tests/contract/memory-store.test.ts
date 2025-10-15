import { describe, it, expect } from 'vitest';
import {
  validateKnowledgeItem,
  safeValidateKnowledgeItem,
} from '../../src/schemas/knowledge-types.js';

/**
 * T024: Contract test for memory.store
 *
 * Validates input schema compliance:
 * - Valid section with all required fields passes
 * - Missing title/body fails with INVALID_SCHEMA error code
 */
describe('memory.store contract validation', () => {
  it('should accept valid section with all required fields', () => {
    const validSection = {
      kind: 'section' as const,
      scope: {
        project: 'cortex-memory',
        branch: 'main',
      },
      data: {
        document_id: '123e4567-e89b-12d3-a456-426614174000',
        heading: 'Authentication Overview',
        body_jsonb: { content: 'JWT-based authentication system' },
        body_text: 'JWT-based authentication system',
      },
    };

    const result = safeValidateKnowledgeItem(validSection);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.kind).toBe('section');
      expect(result.data.scope.project).toBe('cortex-memory');
    }
  });

  it('should reject section missing required heading field', () => {
    const invalidSection = {
      kind: 'section' as const,
      scope: {
        project: 'cortex-memory',
        branch: 'main',
      },
      data: {
        document_id: '123e4567-e89b-12d3-a456-426614174000',
        // heading missing
        body_jsonb: { content: 'Some content' },
        body_text: 'Some content',
      },
    };

    const result = safeValidateKnowledgeItem(invalidSection);
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.errors).toBeDefined();
      expect(result.error.errors.some((e) => e.path.includes('heading'))).toBe(true);
    }
  });

  it('should reject section missing scope.project', () => {
    const invalidSection = {
      kind: 'section' as const,
      scope: {
        // project missing
        branch: 'main',
      },
      data: {
        document_id: '123e4567-e89b-12d3-a456-426614174000',
        heading: 'Test',
        body_jsonb: { content: 'Test content' },
        body_text: 'Test content',
      },
    };

    const result = safeValidateKnowledgeItem(invalidSection);
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.errors.some((e) => e.path.includes('project'))).toBe(true);
    }
  });

  it('should reject invalid kind discriminator', () => {
    const invalidKind = {
      kind: 'invalid_type',
      scope: {
        project: 'test',
        branch: 'main',
      },
      data: {},
    };

    const result = safeValidateKnowledgeItem(invalidKind as any);
    expect(result.success).toBe(false);
  });

  it('should accept all 9 knowledge types with minimal fields', () => {
    const knowledgeTypes = [
      {
        kind: 'section',
        data: {
          document_id: '123e4567-e89b-12d3-a456-426614174000',
          heading: 'Test',
          body_jsonb: {},
          body_text: 'Test',
        },
      },
      {
        kind: 'runbook',
        data: {
          service: 'api',
          title: 'Restart Service',
          steps_jsonb: [],
        },
      },
      {
        kind: 'change',
        data: {
          summary: 'Updated API',
          change_type: 'feature',
        },
      },
      {
        kind: 'issue',
        data: {
          tracker: 'github',
          external_id: 'GH-123',
          title: 'Bug fix',
        },
      },
      {
        kind: 'decision',
        data: {
          component: 'auth',
          status: 'proposed',
          title: 'Use JWT',
          rationale: 'Industry standard',
          alternatives_considered: [],
        },
      },
      {
        kind: 'todo',
        data: {
          scope: 'BRANCH90d',
          todo_type: 'task',
          text: 'Implement feature',
        },
      },
      {
        kind: 'release_note',
        data: {
          version: '1.0.0',
          release_date: '2025-01-01',
          highlights: 'Initial release',
        },
      },
      {
        kind: 'ddl',
        data: {
          migration_id: '001',
          script_path: 'migrations/001.sql',
          checksum: 'abc123',
          applied_at: '2025-01-01T00:00:00Z',
        },
      },
      {
        kind: 'pr_context',
        data: {
          pr_number: 123,
          title: 'Add feature',
          author: 'dev',
          merged_at: '2025-01-01T00:00:00Z',
        },
      },
    ];

    for (const item of knowledgeTypes) {
      const result = safeValidateKnowledgeItem({
        ...item,
        scope: { project: 'test', branch: 'main' },
      } as any);

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.kind).toBe(item.kind);
      }
    }
  });
});
