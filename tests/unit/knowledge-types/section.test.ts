/**
 * Comprehensive Unit Tests for Section Knowledge Type
 *
 * Tests section knowledge type functionality including:
 * - Document section validation with markdown/text constraints
 * - Either/or validation (body_md OR body_text required)
 * - Heading and title length constraints
 * - Document reference validation
 * - Citation count handling
 * - Scope isolation for sections
 * - Error handling and edge cases
 * - Integration with document workflows
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { VectorDatabase } from '../../../src/index';
import { SectionSchema, validateKnowledgeItem } from '../../../src/schemas/knowledge-types';

// Mock Qdrant client - reusing pattern from memory-store.test.ts
vi.mock('@qdrant/js-client-rest', () => ({
  QdrantClient: class {
    constructor() {
      this.getCollections = vi.fn().mockResolvedValue({
        collections: [{ name: 'test-collection' }],
      });
      this.createCollection = vi.fn().mockResolvedValue(undefined);
      this.upsert = vi.fn().mockResolvedValue(undefined);
      this.search = vi.fn().mockResolvedValue([]);
      this.getCollection = vi.fn().mockResolvedValue({
        points_count: 0,
        status: 'green',
      });
      this.delete = vi.fn().mockResolvedValue({ status: 'completed' });
      this.count = vi.fn().mockResolvedValue({ count: 0 });
      this.healthCheck = vi.fn().mockResolvedValue(true);
    }
  },
}));

describe('Section Knowledge Type - Comprehensive Testing', () => {
  let db: VectorDatabase;
  let mockQdrant: any;

  beforeEach(() => {
    db = new VectorDatabase();
    mockQdrant = (db as any).client;
  });

  describe('Section Schema Validation', () => {
    it('should validate complete section with markdown body', () => {
      const section = {
        kind: 'section' as const,
        scope: {
          project: 'test-project',
          branch: 'main',
        },
        data: {
          id: '550e8400-e29b-41d4-a716-446655440000',
          title: 'Authentication System Overview',
          body_md:
            '# Authentication System\n\nThis section provides an overview of the authentication system architecture.',
          heading: 'Authentication Overview',
          document_id: '550e8400-e29b-41d4-a716-446655440001',
          citation_count: 5,
        },
        tags: { documentation: true, architecture: true },
        source: {
          actor: 'technical-writer',
          tool: 'documentation-system',
          timestamp: '2025-01-01T00:00:00Z',
        },
      };

      const result = SectionSchema.safeParse(section);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result['data.kind']).toBe('section');
        expect(result['data.data'].title).toBe('Authentication System Overview');
        expect(result['data.data'].body_md).toContain('# Authentication System');
        expect(result['data.data'].heading).toBe('Authentication Overview');
        expect(result['data.data'].citation_count).toBe(5);
      }
    });

    it('should validate complete section with text body', () => {
      const section = {
        kind: 'section' as const,
        scope: {
          project: 'test-project',
          branch: 'main',
        },
        data: {
          title: 'API Reference',
          body_text: 'This section contains comprehensive API reference documentation.',
          heading: 'API Documentation',
        },
      };

      const result = SectionSchema.safeParse(section);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result['data.data'].title).toBe('API Reference');
        expect(result['data.data'].body_text).toContain('API reference');
        expect(result['data.data'].heading).toBe('API Documentation');
        expect(result['data.data'].body_md).toBeUndefined();
      }
    });

    it('should reject section missing required fields', () => {
      const invalidSections = [
        {
          kind: 'section' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            // Missing title
            body_text: 'Test content',
            heading: 'Test heading',
          },
        },
        {
          kind: 'section' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Test section',
            // Missing both body_md and body_text
            heading: 'Test heading',
          },
        },
        {
          kind: 'section' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Test section',
            body_text: 'Test content',
            // Missing heading
          },
        },
      ];

      invalidSections.forEach((section, index) => {
        const result = SectionSchema.safeParse(section);
        expect(result.success).toBe(false);
        if (!result.success) {
          expect(result.error.issues.length).toBeGreaterThan(0);
        }
      });
    });

    it('should enforce either body_md OR body_text requirement', () => {
      const sectionWithBoth = {
        kind: 'section' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Test Section',
          body_md: '# Markdown content',
          body_text: 'Plain text content', // Both present is allowed
          heading: 'Test Heading',
        },
      };

      const sectionWithNeither = {
        kind: 'section' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Test Section',
          // Missing both body_md and body_text
          heading: 'Test Heading',
        },
      };

      const resultWithBoth = SectionSchema.safeParse(sectionWithBoth);
      const resultWithNeither = SectionSchema.safeParse(sectionWithNeither);

      expect(resultWithBoth.success).toBe(true);
      expect(resultWithNeither.success).toBe(false);
    });

    it('should enforce title length constraints', () => {
      const section = {
        kind: 'section' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'x'.repeat(501), // Exceeds 500 character limit
          body_text: 'Test content',
          heading: 'Test heading',
        },
      };

      const result = SectionSchema.safeParse(section);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('500 characters or less');
      }
    });

    it('should enforce heading length constraints', () => {
      const section = {
        kind: 'section' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Test Section',
          body_text: 'Test content',
          heading: 'x'.repeat(301), // Exceeds 300 character limit
        },
      };

      const result = SectionSchema.safeParse(section);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('300 characters or less');
      }
    });
  });

  describe('Section Storage Operations', () => {
    it('should store section successfully using memory_store pattern', async () => {
      const section = {
        kind: 'section' as const,
        scope: {
          project: 'test-project',
          branch: 'main',
        },
        data: {
          title: 'Installation Guide',
          body_md: '## Installation\n\nFollow these steps to install the application.',
          heading: 'Installation',
        },
        content: 'Section: Installation Guide with installation steps', // Required for embedding generation
      };

      const result = await db.storeItems([section]);

      expect(result.stored).toHaveLength(1);
      expect(result.errors).toHaveLength(0);
      expect(result.stored[0]).toHaveProperty('id');
      expect(result.stored[0].kind).toBe('section');
      expect(result.stored[0].data.title).toBe('Installation Guide');
      expect(result.stored[0].data.heading).toBe('Installation');

      // Verify Qdrant client was called
      expect(mockQdrant.upsert).toHaveBeenCalled();
    });

    it('should handle batch section storage successfully', async () => {
      const sections = Array.from({ length: 5 }, (_, i) => ({
        kind: 'section' as const,
        scope: {
          project: 'test-project',
          branch: 'main',
        },
        data: {
          title: `Section ${i + 1}`,
          body_text: `Content for section ${i + 1}`,
          heading: `Heading ${i + 1}`,
        },
        content: `Section: ${i + 1} content overview`,
      }));

      const result = await db.storeItems(sections);

      expect(result.stored).toHaveLength(5);
      expect(result.errors).toHaveLength(0);
      expect(mockQdrant.upsert).toHaveBeenCalledTimes(5);
    });

    it('should handle mixed valid and invalid sections in batch', async () => {
      const items = [
        {
          kind: 'section' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Valid Section',
            body_text: 'Valid content',
            heading: 'Valid Heading',
          },
          content: 'Valid section content',
        },
        {
          kind: 'section' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Invalid Section',
            // Missing body content
            heading: 'Invalid Heading',
          },
          content: 'Invalid section content',
        },
        {
          kind: 'section' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Another Valid Section',
            body_md: '# Valid Markdown',
            heading: 'Another Valid Heading',
          },
          content: 'Another valid section content',
        },
      ];

      const result = await db.storeItems(items);

      expect(result.stored).toHaveLength(2); // 2 valid sections
      expect(result.errors).toHaveLength(1); // 1 invalid section
    });
  });

  describe('Section Search Operations', () => {
    beforeEach(() => {
      // Setup search mock for sections
      mockQdrant.search.mockResolvedValue([
        {
          id: 'section-id-1',
          score: 0.9,
          payload: {
            kind: 'section',
            data: {
              title: 'User Authentication',
              body_md: '# Authentication Flow\n\nDetailed authentication process.',
              heading: 'Authentication Flow',
              document_id: 'doc-123',
            },
            scope: { project: 'test-project', branch: 'main' },
          },
        },
        {
          id: 'section-id-2',
          score: 0.8,
          payload: {
            kind: 'section',
            data: {
              title: 'API Reference',
              body_text: 'Comprehensive API documentation.',
              heading: 'API Documentation',
            },
            scope: { project: 'test-project', branch: 'main' },
          },
        },
      ]);
    });

    it('should find sections by query', async () => {
      const query = 'authentication API flow';

      const result = await db.searchItems(query);

      expect(result.items).toHaveLength(2);
      expect(result.items[0].data.title).toBe('User Authentication');
      expect(result.items[0].data.heading).toBe('Authentication Flow');
      expect(result.items[1].data.title).toBe('API Reference');
      expect(mockQdrant.search).toHaveBeenCalled();
    });

    it('should handle empty section search results', async () => {
      mockQdrant.search.mockResolvedValue([]);

      const result = await db.searchItems('nonexistent section');

      expect(result.items).toHaveLength(0);
      expect(result.total).toBe(0);
    });
  });

  describe('Document Body Formats', () => {
    it('should handle markdown body content', async () => {
      const markdownSections = [
        {
          title: 'Markdown Overview',
          body_md:
            '# Overview\n\nThis is a **markdown** section with `code` and [links](http://example.com).',
        },
        {
          title: 'Complex Markdown',
          body_md:
            '```javascript\nconsole.log("Hello World");\n```\n\n- Item 1\n- Item 2\n- Item 3',
        },
        {
          title: 'Mathematical Content',
          body_md: 'E = mc²\n\nInline math: $x^2 + y^2 = z^2$',
        },
      ];

      for (const sectionData of markdownSections) {
        const section = {
          kind: 'section' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            ...sectionData,
            heading: sectionData.title,
          },
          content: `Section: ${sectionData.title}`,
        };

        const result = SectionSchema.safeParse(section);
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result['data.data'].body_md).toContain(sectionData.title);
        }
      }
    });

    it('should handle plain text body content', async () => {
      const textSections = [
        {
          title: 'Plain Text Overview',
          body_text: 'This is a plain text section with no markdown formatting.',
        },
        {
          title: 'Technical Documentation',
          body_text: 'The system uses RESTful APIs with JSON responses.',
        },
        {
          title: 'User Guide',
          body_text: 'Follow these steps: 1. Login 2. Navigate 3. Complete action',
        },
      ];

      for (const sectionData of textSections) {
        const section = {
          kind: 'section' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            ...sectionData,
            heading: sectionData.title,
          },
          content: `Section: ${sectionData.title}`,
        };

        const result = SectionSchema.safeParse(section);
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result['data.data'].body_text).toContain(sectionData.title);
        }
      }
    });

    it('should handle sections with both markdown and text body', async () => {
      const section = {
        kind: 'section' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Dual Format Section',
          body_md: '# Dual Format\n\n**Markdown** content here.',
          body_text: 'Plain text content here.',
          heading: 'Dual Format Example',
        },
        content: 'Section with both markdown and text',
      };

      const result = SectionSchema.safeParse(section);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result['data.data'].body_md).toContain('# Dual Format');
        expect(result['data.data'].body_text).toContain('Plain text content');
      }
    });
  });

  describe('Document Structure Features', () => {
    it('should handle sections with document references', async () => {
      const sections = [
        {
          kind: 'section' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Chapter 1',
            body_text: 'First chapter content',
            heading: 'Chapter 1',
            document_id: '550e8400-e29b-41d4-a716-446655440000',
          },
          content: 'Section with document reference',
        },
        {
          kind: 'section' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Appendix A',
            body_text: 'Appendix content',
            heading: 'Appendix',
            document_id: '550e8400-e29b-41d4-a716-446655440001',
          },
          content: 'Section with different document reference',
        },
      ];

      const results = sections.map((section) => SectionSchema.safeParse(section));
      results.forEach((result) => {
        expect(result.success).toBe(true);
      });
    });

    it('should handle sections with citation counts', async () => {
      const citationCounts = [0, 1, 5, 10, 25, 100];

      for (const count of citationCounts) {
        const section = {
          kind: 'section' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: `Section with ${count} citations`,
            body_text: `Content cited ${count} times`,
            heading: `Citation Example ${count}`,
            citation_count: count,
          },
          content: `Section with ${count} citations`,
        };

        const result = SectionSchema.safeParse(section);
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result['data.data'].citation_count).toBe(count);
        }
      }
    });

    it('should handle hierarchical section structures', async () => {
      const hierarchicalSections = [
        {
          title: '1.0 Introduction',
          heading: 'Introduction',
          level: 1,
        },
        {
          title: '1.1 Background',
          heading: 'Background',
          level: 2,
        },
        {
          title: '1.1.1 Historical Context',
          heading: 'Historical Context',
          level: 3,
        },
      ];

      for (const sectionData of hierarchicalSections) {
        const section = {
          kind: 'section' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            ...sectionData,
            body_text: `Content for ${sectionData.title}`,
          },
          content: `Section: ${sectionData.title}`,
        };

        const result = SectionSchema.safeParse(section);
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result['data.data'].title).toBe(sectionData.title);
        }
      }
    });
  });

  describe('Section Scope Isolation', () => {
    it('should isolate sections by project scope', async () => {
      const sectionProjectA = {
        kind: 'section' as const,
        scope: {
          project: 'project-A',
          branch: 'main',
        },
        data: {
          title: 'Project A Documentation',
          body_text: 'Content for Project A',
          heading: 'Project A',
        },
        content: 'Section in project-A',
      };

      const sectionProjectB = {
        kind: 'section' as const,
        scope: {
          project: 'project-B',
          branch: 'main',
        },
        data: {
          title: 'Project B Documentation',
          body_text: 'Content for Project B',
          heading: 'Project B',
        },
        content: 'Section in project-B',
      };

      // Store both sections
      await db.storeItems([sectionProjectA, sectionProjectB]);

      // Verify both were stored
      expect(mockQdrant.upsert).toHaveBeenCalledTimes(2);
    });

    it('should handle sections with different branch scopes', async () => {
      const sections = [
        {
          kind: 'section' as const,
          scope: {
            project: 'test-project',
            branch: 'main',
          },
          data: {
            title: 'Main Branch Documentation',
            body_text: 'Stable documentation',
            heading: 'Main Branch',
          },
          content: 'Section in main branch',
        },
        {
          kind: 'section' as const,
          scope: {
            project: 'test-project',
            branch: 'develop',
          },
          data: {
            title: 'Development Documentation',
            body_text: 'Work in progress',
            heading: 'Development',
          },
          content: 'Section in develop branch',
        },
      ];

      await db.storeItems(sections);
      expect(mockQdrant.upsert).toHaveBeenCalledTimes(2);
    });
  });

  describe('Section Edge Cases and Error Handling', () => {
    it('should handle sections with special characters', async () => {
      const sections = [
        {
          kind: 'section' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'API Endpoint: /api/v1/users/{userId}',
            body_text: 'Handles user operations with special characters: !@#$%^&*()',
            heading: 'API Reference',
          },
          content: 'Section with special characters',
        },
        {
          kind: 'section' as const,
          scope: { project: 'test-project', branch: 'main' },
          data: {
            title: 'Multi-language Section: English, 中文, 日本語, Español',
            body_text: 'Content in multiple languages with Unicode support',
            heading: 'Internationalization',
          },
          content: 'Section with Unicode content',
        },
      ];

      const results = sections.map((section) => SectionSchema.safeParse(section));
      results.forEach((result) => {
        expect(result.success).toBe(true);
      });
    });

    it('should handle very long section content', async () => {
      const longBodyText = 'x'.repeat(5000); // 5000 character content
      const section = {
        kind: 'section' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Long Section Content',
          body_text: longBodyText,
          heading: 'Long Content Example',
        },
        content: `Section with ${longBodyText.length} characters`,
      };

      const result = SectionSchema.safeParse(section);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result['data.data'].body_text).toHaveLength(5000);
      }
    });

    it('should handle section storage errors gracefully', async () => {
      const section = {
        kind: 'section' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Test Section',
          body_text: 'Test content',
          heading: 'Test heading',
        },
        content: 'Test section',
      };

      // Mock upsert to throw an error
      mockQdrant.upsert.mockRejectedValue(new Error('Storage quota exceeded'));

      const result = await db.storeItems([section]);

      expect(result.stored).toHaveLength(0);
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0].error).toContain('Storage quota exceeded');
    });
  });

  describe('Section Integration with Knowledge System', () => {
    it('should integrate with knowledge item validation', () => {
      const section = {
        kind: 'section' as const,
        scope: {
          project: 'test-project',
          branch: 'main',
        },
        data: {
          title: 'System Architecture',
          body_md: '# Architecture Overview\n\nDetailed system architecture documentation.',
          heading: 'Architecture',
          document_id: 'doc-architecture',
          citation_count: 12,
        },
        tags: { documentation: true, architecture: true, reviewed: true },
        source: {
          actor: 'senior-architect',
          tool: 'documentation-platform',
          timestamp: '2025-01-01T00:00:00Z',
        },
        ttl_policy: 'long' as const,
      };

      const result = validateKnowledgeItem(section);
      expect(result.kind).toBe('section');
      expect(result['data.citation_count']).toBe(12);
      expect(result.tags.architecture).toBe(true);
      expect(result.source.actor).toBe('senior-architect');
      expect(result['ttl_policy']).toBe('long');
    });

    it('should handle TTL policy for sections', async () => {
      const section = {
        kind: 'section' as const,
        scope: { project: 'test-project', branch: 'main' },
        data: {
          title: 'Temporary Documentation',
          body_text: 'Temporary section content',
          heading: 'Temporary',
        },
        ttl_policy: 'short' as const,
        content: 'Temporary section with short TTL',
      };

      const result = await db.storeItems([section]);

      expect(result.stored).toHaveLength(1);
      expect(result.stored[0].ttl_policy).toBe('short');
    });
  });
});
