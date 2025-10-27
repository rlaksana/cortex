import { describe, it, expect } from 'vitest';
import {
  validateKnowledgeItem,
  safeValidateKnowledgeItem,
} from '../schemas/knowledge-types.ts';

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
        project: 'cortex',
        branch: 'main',
      },
      data: {
        title: 'Authentication Overview',
        heading: 'Authentication Overview',
        body_text: 'JWT-based authentication system',
      },
    };

    const result = safeValidateKnowledgeItem(validSection);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.kind).toBe('section');
      expect(result.data.scope.project).toBe('cortex');
    }
  });

  it('should reject section missing required heading field', () => {
    const invalidSection = {
      kind: 'section' as const,
      scope: {
        project: 'cortex',
        branch: 'main',
      },
      data: {
        title: 'Test Section',
        // heading missing
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
        title: 'Test Section',
        heading: 'Test',
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
        scope: {
          project: 'test',
          branch: 'main',
        },
        data: {
          title: 'Test Section',
          heading: 'Test',
          body_text: 'Test',
        },
      },
      {
        kind: 'runbook',
        scope: {
          project: 'test',
          branch: 'main',
        },
        data: {
          service: 'api',
          title: 'Restart Service',
          steps: [{ step_number: 1, description: 'Stop service' }],
        },
      },
      {
        kind: 'change',
        scope: {
          project: 'test',
          branch: 'main',
        },
        data: {
          subject_ref: 'PR-123',
          summary: 'Updated API',
          change_type: 'feature_add',
        },
      },
      {
        kind: 'issue',
        scope: {
          project: 'test',
          branch: 'main',
        },
        data: {
          tracker: 'github',
          external_id: 'GH-123',
          title: 'Bug fix',
          status: 'resolved',
        },
      },
      {
        kind: 'decision',
        scope: {
          project: 'test',
          branch: 'main',
        },
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
        scope: {
          project: 'test',
          branch: 'main',
        },
        data: {
          scope: 'BRANCH90d',
          todo_type: 'task',
          text: 'Implement feature',
          status: 'open',
        },
      },
      {
        kind: 'release_note',
        scope: {
          project: 'test',
          branch: 'main',
        },
        data: {
          version: '1.0.0',
          release_date: '2025-01-01T00:00:00Z',
          summary: 'Initial release',
        },
      },
      {
        kind: 'ddl',
        scope: {
          project: 'test',
          branch: 'main',
        },
        data: {
          migration_id: '001',
          ddl_text: 'CREATE TABLE test (id UUID);',
          checksum: 'a'.repeat(64),
          applied_at: '2025-01-01T00:00:00Z',
        },
      },
      {
        kind: 'pr_context',
        scope: {
          project: 'test',
          branch: 'main',
        },
        data: {
          pr_number: 123,
          title: 'Add feature',
          author: 'dev',
          status: 'merged',
          base_branch: 'main',
          head_branch: 'feature-branch',
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
