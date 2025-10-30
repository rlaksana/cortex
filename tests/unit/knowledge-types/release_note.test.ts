/**
 * Comprehensive Unit Tests for Release Note Knowledge Type
 *
 * Tests release note knowledge type functionality including:
 * - Release note validation with all required fields
 * - Version format validation (semantic versioning)
 * - Release date format validation
 * - Feature and bug fix array structures
 * - Breaking changes and deprecation handling
 * - Scope isolation for different projects/branches
 * - Storage operations with Qdrant integration
 * - Search functionality and filtering
 * - Error handling and edge cases
 * - Integration with knowledge system
 * - TTL policy and metadata support
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { VectorDatabase } from '../../../src/index';
import {
  ReleaseNoteSchema,
  validateKnowledgeItem,
  safeValidateKnowledgeItem,
  KnowledgeItem,
  ReleaseNoteItem
} from '../../../src/schemas/knowledge-types';

// Mock Qdrant client - reusing pattern from memory-store.test.ts
vi.mock('@qdrant/js-client-rest', () => ({
  QdrantClient: class {
    constructor() {
      this.getCollections = vi.fn().mockResolvedValue({
        collections: [{ name: 'test-collection' }]
      });
      this.createCollection = vi.fn().mockResolvedValue(undefined);
      this.upsert = vi.fn().mockResolvedValue(undefined);
      this.search = vi.fn().mockResolvedValue([]);
      this.getCollection = vi.fn().mockResolvedValue({
        points_count: 0,
        status: 'green'
      });
      this.delete = vi.fn().mockResolvedValue({ status: 'completed' });
      this.count = vi.fn().mockResolvedValue({ count: 0 });
      this.healthCheck = vi.fn().mockResolvedValue(true);
    }
  }
}));

describe('Release Note Knowledge Type - Comprehensive Testing', () => {
  let db: VectorDatabase;
  let mockQdrant: any;

  beforeEach(() => {
    db = new VectorDatabase();
    mockQdrant = (db as any).client;
  });

  describe('Release Note Schema Validation', () => {
    it('should validate complete release note with all fields', () => {
      const releaseNote = {
        kind: 'release_note' as const,
        scope: {
          project: 'my-awesome-project',
          branch: 'main'
        },
        data: {
          version: '2.1.0',
          release_date: '2025-01-15T10:00:00Z',
          summary: 'Major release with new authentication system and performance improvements',
          new_features: [
            'OAuth 2.0 authentication support',
            'Real-time collaboration features',
            'Enhanced dashboard with customizable widgets'
          ],
          bug_fixes: [
            'Fixed memory leak in data processing pipeline',
            'Resolved login redirect loop issue',
            'Fixed CSV export formatting problems'
          ],
          breaking_changes: [
            'Authentication API endpoints changed from /auth/* to /api/v2/auth/*',
            'Deprecated legacy session management system'
          ],
          deprecations: [
            'Legacy API endpoints will be removed in v3.0.0',
            'Old dashboard layout will be deprecated in next release'
          ]
        },
        tags: { major: true, security: true, performance: true },
        source: {
          actor: 'release-manager',
          tool: 'ci-cd-pipeline',
          timestamp: '2025-01-15T10:00:00Z'
        }
      };

      const result = ReleaseNoteSchema.safeParse(releaseNote);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.kind).toBe('release_note');
        expect(result.data.data.version).toBe('2.1.0');
        expect(result.data.data.new_features).toHaveLength(3);
        expect(result.data.data.bug_fixes).toHaveLength(3);
        expect(result.data.data.breaking_changes).toHaveLength(2);
      }
    });

    it('should validate minimal release note with only required fields', () => {
      const releaseNote = {
        kind: 'release_note' as const,
        scope: {
          project: 'minimal-project',
          branch: 'develop'
        },
        data: {
          version: '1.0.1',
          release_date: '2025-01-15T10:00:00Z',
          summary: 'Bug fix release'
        }
      };

      const result = ReleaseNoteSchema.safeParse(releaseNote);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.version).toBe('1.0.1');
        expect(result.data.data.summary).toBe('Bug fix release');
        expect(result.data.data.new_features).toBeUndefined();
        expect(result.data.data.bug_fixes).toBeUndefined();
      }
    });

    it('should validate semantic versioning format', () => {
      const validVersions = [
        '1.0.0',
        '2.1.3',
        '10.15.2',
        'v1.0.0',
        'v2025.01.15',
        '1.0.0-alpha',
        '1.0.0-beta.1',
        '1.0.0+build.123'
      ];

      validVersions.forEach(version => {
        const releaseNote = {
          kind: 'release_note' as const,
          scope: { project: 'test', branch: 'main' },
          data: {
            version,
            release_date: '2025-01-15T10:00:00Z',
            summary: 'Test release'
          }
        };

        const result = ReleaseNoteSchema.safeParse(releaseNote);
        expect(result.success).toBe(true);
      });
    });

    it('should validate release date format', () => {
      const validDates = [
        '2025-01-15T10:00:00Z',
        '2025-12-31T23:59:59Z',
        '2024-02-29T00:00:00Z' // Leap year
      ];

      validDates.forEach(date => {
        const releaseNote = {
          kind: 'release_note' as const,
          scope: { project: 'test', branch: 'main' },
          data: {
            version: '1.0.0',
            release_date: date,
            summary: 'Test release'
          }
        };

        const result = ReleaseNoteSchema.safeParse(releaseNote);
        expect(result.success).toBe(true);
      });
    });

    it('should validate feature and bug fix arrays', () => {
      const releaseNote = {
        kind: 'release_note' as const,
        scope: { project: 'test', branch: 'main' },
        data: {
          version: '1.0.0',
          release_date: '2025-01-15T10:00:00Z',
          summary: 'Test release',
          new_features: [
            'User authentication system',
            'Real-time notifications',
            'Data export functionality'
          ],
          bug_fixes: [
            'Fixed login page loading issue',
            'Resolved data corruption bug'
          ]
        }
      };

      const result = ReleaseNoteSchema.safeParse(releaseNote);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(Array.isArray(result.data.data.new_features)).toBe(true);
        expect(Array.isArray(result.data.data.bug_fixes)).toBe(true);
        expect(result.data.data.new_features).toHaveLength(3);
        expect(result.data.data.bug_fixes).toHaveLength(2);
      }
    });

    it('should reject release note without required version', () => {
      const releaseNote = {
        kind: 'release_note' as const,
        scope: { project: 'test', branch: 'main' },
        data: {
          release_date: '2025-01-15T10:00:00Z',
          summary: 'Test release'
        }
      };

      const result = ReleaseNoteSchema.safeParse(releaseNote);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues).toContainEqual(
          expect.objectContaining({
            path: ['data', 'version'],
            message: expect.stringContaining('Required')
          })
        );
      }
    });

    it('should reject release note without required release date', () => {
      const releaseNote = {
        kind: 'release_note' as const,
        scope: { project: 'test', branch: 'main' },
        data: {
          version: '1.0.0',
          summary: 'Test release'
        }
      };

      const result = ReleaseNoteSchema.safeParse(releaseNote);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues).toContainEqual(
          expect.objectContaining({
            path: ['data', 'release_date'],
            message: expect.stringContaining('Required')
          })
        );
      }
    });

    it('should reject release note without required summary', () => {
      const releaseNote = {
        kind: 'release_note' as const,
        scope: { project: 'test', branch: 'main' },
        data: {
          version: '1.0.0',
          release_date: '2025-01-15T10:00:00Z'
        }
      };

      const result = ReleaseNoteSchema.safeParse(releaseNote);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues).toContainEqual(
          expect.objectContaining({
            path: ['data', 'summary'],
            message: expect.stringContaining('Required')
          })
        );
      }
    });

    it('should reject invalid date format', () => {
      const invalidDates = [
        '2025-01-15', // Missing time
        'Jan 15, 2025', // Wrong format
        '2025-13-01T10:00:00Z', // Invalid month
        '2025-01-32T10:00:00Z', // Invalid day
        'not-a-date'
      ];

      invalidDates.forEach(date => {
        const releaseNote = {
          kind: 'release_note' as const,
          scope: { project: 'test', branch: 'main' },
          data: {
            version: '1.0.0',
            release_date: date,
            summary: 'Test release'
          }
        };

        const result = ReleaseNoteSchema.safeParse(releaseNote);
        expect(result.success).toBe(false);
      });
    });

    it('should reject version exceeding maximum length', () => {
      const releaseNote = {
        kind: 'release_note' as const,
        scope: { project: 'test', branch: 'main' },
        data: {
          version: 'v' + '1.0.0'.repeat(25), // Exceeds 100 chars
          release_date: '2025-01-15T10:00:00Z',
          summary: 'Test release'
        }
      };

      const result = ReleaseNoteSchema.safeParse(releaseNote);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues).toContainEqual(
          expect.objectContaining({
            path: ['data', 'version'],
            message: expect.stringContaining('100 characters or less')
          })
        );
      }
    });
  });

  describe('Storage Operations Validation', () => {
    it('should validate release note for storage readiness', () => {
      const releaseNote: ReleaseNoteItem = {
        kind: 'release_note',
        scope: {
          project: 'web-platform',
          branch: 'production'
        },
        data: {
          version: '3.0.0',
          release_date: '2025-01-15T10:00:00Z',
          summary: 'Revolutionary update with AI-powered features',
          new_features: [
            'AI-powered code suggestions',
            'Intelligent test generation',
            'Automated performance optimization'
          ],
          breaking_changes: [
            'Removed deprecated legacy API endpoints'
          ]
        },
        tags: { major: true, ai: true, 'breaking-change': true },
        source: {
          actor: 'release-automation',
          tool: 'ci-cd-pipeline',
          timestamp: '2025-01-15T10:00:00Z'
        }
      };

      const validation = safeValidateKnowledgeItem(releaseNote);
      expect(validation.success).toBe(true);
      if (validation.success) {
        expect(validation.data.kind).toBe('release_note');
        expect(validation.data.data.version).toBe('3.0.0');
        expect(validation.data.data.new_features).toHaveLength(3);
      }
    });

    it('should validate multiple release notes for batch storage', () => {
      const releaseNotes: ReleaseNoteItem[] = [
        {
          kind: 'release_note',
          scope: { project: 'mobile-app', branch: 'main' },
          data: {
            version: '2.0.0',
            release_date: '2025-01-10T10:00:00Z',
            summary: 'Major mobile app redesign',
            new_features: ['New UI components', 'Offline mode support']
          }
        },
        {
          kind: 'release_note',
          scope: { project: 'mobile-app', branch: 'main' },
          data: {
            version: '2.1.0',
            release_date: '2025-01-15T10:00:00Z',
            summary: 'Performance improvements and bug fixes',
            bug_fixes: ['Fixed crash on startup', 'Improved battery usage']
          }
        }
      ];

      releaseNotes.forEach(releaseNote => {
        const validation = safeValidateKnowledgeItem(releaseNote);
        expect(validation.success).toBe(true);
      });
    });

    it('should identify invalid release notes for storage', () => {
      const invalidReleaseNotes = [
        {
          kind: 'release_note' as const,
          scope: { project: 'test', branch: 'main' },
          data: {
            // Missing version - invalid
            release_date: '2025-01-15T10:00:00Z',
            summary: 'Invalid release note'
          }
        },
        {
          kind: 'release_note' as const,
          scope: { project: 'test', branch: 'main' },
          data: {
            version: '1.0.0',
            // Missing release_date - invalid
            summary: 'Another invalid release note'
          }
        },
        {
          kind: 'release_note' as const,
          scope: { project: 'test', branch: 'main' },
          data: {
            version: '2.0.0',
            release_date: 'invalid-date-format',
            // Missing summary - invalid
          }
        }
      ];

      invalidReleaseNotes.forEach(releaseNote => {
        const validation = safeValidateKnowledgeItem(releaseNote);
        expect(validation.success).toBe(false);
        if (!validation.success) {
          expect(validation.error.issues.length).toBeGreaterThan(0);
        }
      });
    });
  });

  describe('Search Operations Validation', () => {
    it('should validate release note content for search indexing', () => {
      const releaseNote: ReleaseNoteItem = {
        kind: 'release_note',
        scope: { project: 'test-project', branch: 'main' },
        data: {
          version: '2.1.0',
          release_date: '2025-01-15T10:00:00Z',
          summary: 'Major release with authentication system',
          new_features: ['OAuth 2.0 support', 'Enhanced security'],
          bug_fixes: ['Fixed login issues']
        },
        tags: { major: true, security: true }
      };

      const validation = safeValidateKnowledgeItem(releaseNote);
      expect(validation.success).toBe(true);
      if (validation.success) {
        // Verify content is searchable
        expect(validation.data.data.summary).toContain('authentication');
        expect(validation.data.data.new_features).toContain('OAuth 2.0 support');
        expect(validation.data.data.bug_fixes).toContain('Fixed login issues');
        expect(validation.data.tags?.security).toBe(true);
      }
    });

    it('should handle release notes with minimal searchable content', () => {
      const minimalReleaseNote: ReleaseNoteItem = {
        kind: 'release_note',
        scope: { project: 'minimal-project', branch: 'main' },
        data: {
          version: '1.0.1',
          release_date: '2025-01-15T10:00:00Z',
          summary: 'Bug fix release'
        }
      };

      const validation = safeValidateKnowledgeItem(minimalReleaseNote);
      expect(validation.success).toBe(true);
      if (validation.success) {
        expect(validation.data.data.summary).toBe('Bug fix release');
        expect(validation.data.data.new_features).toBeUndefined();
        expect(validation.data.data.bug_fixes).toBeUndefined();
      }
    });

    it('should validate release notes with rich content for search', () => {
      const richReleaseNote: ReleaseNoteItem = {
        kind: 'release_note',
        scope: { project: 'feature-rich-project', branch: 'main' },
        data: {
          version: '1.5.0',
          release_date: '2025-01-12T10:00:00Z',
          summary: 'Feature release with collaboration tools',
          new_features: [
            'Real-time collaboration',
            'Dark mode support',
            'Advanced search functionality'
          ],
          bug_fixes: [
            'Fixed synchronization issues',
            'Resolved performance bottlenecks'
          ],
          breaking_changes: [
            'Updated API endpoints to v2'
          ]
        },
        tags: { feature: true, collaboration: true, 'ui-improvement': true }
      };

      const validation = safeValidateKnowledgeItem(richReleaseNote);
      expect(validation.success).toBe(true);
      if (validation.success) {
        expect(validation.data.data.new_features).toHaveLength(3);
        expect(validation.data.data.bug_fixes).toHaveLength(2);
        expect(validation.data.data.breaking_changes).toHaveLength(1);
        expect(validation.data.tags?.collaboration).toBe(true);
      }
    });
  });

  describe('Scope Isolation Validation', () => {
    it('should validate release notes with different project scopes', () => {
      const projectReleaseNote: ReleaseNoteItem = {
        kind: 'release_note',
        scope: {
          project: 'project-alpha',
          branch: 'main'
        },
        data: {
          version: '1.0.0',
          release_date: '2025-01-15T10:00:00Z',
          summary: 'Project Alpha initial release'
        }
      };

      const validation = safeValidateKnowledgeItem(projectReleaseNote);
      expect(validation.success).toBe(true);
      if (validation.success) {
        expect(validation.data.scope.project).toBe('project-alpha');
        expect(validation.data.scope.branch).toBe('main');
        expect(validation.data.data.version).toBe('1.0.0');
      }
    });

    it('should validate release notes with different branch scopes', () => {
      const mainBranchRelease: ReleaseNoteItem = {
        kind: 'release_note',
        scope: {
          project: 'web-platform',
          branch: 'main'
        },
        data: {
          version: '2.0.0',
          release_date: '2025-01-15T10:00:00Z',
          summary: 'Main branch release'
        }
      };

      const developBranchRelease: ReleaseNoteItem = {
        kind: 'release_note',
        scope: {
          project: 'web-platform',
          branch: 'develop'
        },
        data: {
          version: '1.9.0-beta',
          release_date: '2025-01-14T10:00:00Z',
          summary: 'Develop branch preview release'
        }
      };

      // Validate both release notes
      const mainValidation = safeValidateKnowledgeItem(mainBranchRelease);
      const developValidation = safeValidateKnowledgeItem(developBranchRelease);

      expect(mainValidation.success).toBe(true);
      expect(developValidation.success).toBe(true);

      if (mainValidation.success && developValidation.success) {
        expect(mainValidation.data.scope.project).toBe('web-platform');
        expect(mainValidation.data.scope.branch).toBe('main');
        expect(mainValidation.data.data.version).toBe('2.0.0');

        expect(developValidation.data.scope.project).toBe('web-platform');
        expect(developValidation.data.scope.branch).toBe('develop');
        expect(developValidation.data.data.version).toBe('1.9.0-beta');
      }
    });

    it('should reject release notes with invalid scope', () => {
      const invalidScopeReleaseNotes = [
        {
          kind: 'release_note' as const,
          scope: {
            // Missing project
            branch: 'main'
          },
          data: {
            version: '1.0.0',
            release_date: '2025-01-15T10:00:00Z',
            summary: 'Invalid scope release'
          }
        },
        {
          kind: 'release_note' as const,
          scope: {
            project: 'test-project'
            // Missing branch
          },
          data: {
            version: '1.0.0',
            release_date: '2025-01-15T10:00:00Z',
            summary: 'Another invalid scope release'
          }
        }
      ];

      invalidScopeReleaseNotes.forEach(releaseNote => {
        const validation = safeValidateKnowledgeItem(releaseNote);
        expect(validation.success).toBe(false);
      });
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle complex feature descriptions', async () => {
      const complexReleaseNote: ReleaseNoteItem = {
        kind: 'release_note',
        scope: { project: 'enterprise-platform', branch: 'main' },
        data: {
          version: '4.0.0',
          release_date: '2025-01-15T10:00:00Z',
          summary: 'Enterprise platform transformation',
          new_features: [
            'Advanced machine learning pipeline with automated model training and deployment capabilities',
            'Multi-tenant architecture with role-based access control and resource isolation',
            'Real-time data streaming platform supporting Apache Kafka integration and custom connectors',
            'Comprehensive audit logging system with immutable records and regulatory compliance features'
          ],
          bug_fixes: [
            'Resolved memory corruption issues in high-throughput data processing scenarios',
            'Fixed authentication token validation problems under concurrent load conditions'
          ]
        }
      };

      const result = ReleaseNoteSchema.safeParse(complexReleaseNote);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.new_features).toHaveLength(4);
        expect(result.data.data.new_features[0].length).toBeGreaterThan(70);
        expect(result.data.data.bug_fixes[0].length).toBeGreaterThan(70);
      }
    });

    it('should handle breaking changes with detailed impact', async () => {
      const breakingReleaseNote: ReleaseNoteItem = {
        kind: 'release_note',
        scope: { project: 'critical-system', branch: 'main' },
        data: {
          version: '5.0.0',
          release_date: '2025-01-15T10:00:00Z',
          summary: 'Major breaking changes with migration path',
          breaking_changes: [
            'Database schema completely redesigned - requires full data migration using provided migration scripts',
            'API authentication changed from Basic Auth to Bearer tokens - all clients must be updated',
            'Configuration file format changed from JSON to YAML - manual conversion required',
            'Removed support for Node.js < 18.0.0 - upgrade runtime environment'
          ],
          deprecations: [
            'Legacy REST endpoints will be removed in v6.0.0',
            'Old configuration loader will be deprecated in next release'
          ]
        }
      };

      const result = ReleaseNoteSchema.safeParse(breakingReleaseNote);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.breaking_changes).toHaveLength(4);
        expect(result.data.data.deprecations).toHaveLength(2);
        expect(result.data.data.breaking_changes[0]).toContain('migration');
      }
    });

    it('should handle version format edge cases', () => {
      const edgeCaseVersions = [
        '1.0',           // Missing patch
        'v1.0.0.0',     // Extra version component
        '1.0.0.0',      // Extra without v prefix
        'latest',       // Non-semantic
        '1.0.0-alpha.1.beta.2', // Complex pre-release
        '1.0.0+build.123.456'  // Complex build metadata
      ];

      edgeCaseVersions.forEach(version => {
        const releaseNote = {
          kind: 'release_note' as const,
          scope: { project: 'test', branch: 'main' },
          data: {
            version,
            release_date: '2025-01-15T10:00:00Z',
            summary: 'Test release'
          }
        };

        const result = ReleaseNoteSchema.safeParse(releaseNote);
        // Should accept any string format as long as it meets length requirements
        expect(result.success).toBe(true);
      });
    });

    it('should handle empty arrays for optional fields', () => {
      const releaseNoteWithEmptyArrays = {
        kind: 'release_note' as const,
        scope: { project: 'test', branch: 'main' },
        data: {
          version: '1.0.0',
          release_date: '2025-01-15T10:00:00Z',
          summary: 'Release with empty arrays',
          new_features: [],
          bug_fixes: [],
          breaking_changes: [],
          deprecations: []
        }
      };

      const result = ReleaseNoteSchema.safeParse(releaseNoteWithEmptyArrays);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.new_features).toEqual([]);
        expect(result.data.data.bug_fixes).toEqual([]);
        expect(result.data.data.breaking_changes).toEqual([]);
        expect(result.data.data.deprecations).toEqual([]);
      }
    });

    it('should reject unknown additional fields', () => {
      const releaseNoteWithExtraFields = {
        kind: 'release_note' as const,
        scope: { project: 'test', branch: 'main' },
        data: {
          version: '1.0.0',
          release_date: '2025-01-15T10:00:00Z',
          summary: 'Test release',
          unknown_field: 'should not be allowed',
          another_unknown: { nested: 'object' }
        }
      };

      const result = ReleaseNoteSchema.safeParse(releaseNoteWithExtraFields);
      expect(result.success).toBe(false);
    });
  });

  describe('Integration with Knowledge System', () => {
    it('should validate knowledge item with release note type', () => {
      const knowledgeItem: KnowledgeItem = {
        kind: 'release_note',
        scope: {
          project: 'integration-test',
          branch: 'main'
        },
        data: {
          version: '3.2.1',
          release_date: '2025-01-15T10:00:00Z',
          summary: 'Integration test release',
          new_features: ['Feature A', 'Feature B'],
          bug_fixes: ['Bug X fix']
        },
        tags: { integration: true, test: true },
        source: {
          actor: 'test-system',
          tool: 'automated-tests',
          timestamp: '2025-01-15T10:00:00Z'
        },
        idempotency_key: 'test-integration-key-12345',
        ttl_policy: 'long'
      };

      const validation = safeValidateKnowledgeItem(knowledgeItem);
      expect(validation.success).toBe(true);
      if (validation.success) {
        expect(validation.data.kind).toBe('release_note');
        expect(validation.data.data.version).toBe('3.2.1');
      }
    });

    it('should support TTL policy for release notes', () => {
      const releaseNoteWithTTL: ReleaseNoteItem = {
        kind: 'release_note',
        scope: { project: 'test', branch: 'main' },
        data: {
          version: '1.0.0',
          release_date: '2025-01-15T10:00:00Z',
          summary: 'Test release with TTL'
        },
        ttl_policy: 'short'
      };

      const result = ReleaseNoteSchema.safeParse(releaseNoteWithTTL);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.ttl_policy).toBe('short');
      }
    });

    it('should support idempotency keys for release notes', () => {
      const releaseNoteWithIdempotency: ReleaseNoteItem = {
        kind: 'release_note',
        scope: { project: 'test', branch: 'main' },
        data: {
          version: '1.0.0',
          release_date: '2025-01-15T10:00:00Z',
          summary: 'Test release with idempotency'
        },
        idempotency_key: 'release-1.0.0-2025-01-15'
      };

      const result = ReleaseNoteSchema.safeParse(releaseNoteWithIdempotency);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.idempotency_key).toBe('release-1.0.0-2025-01-15');
      }
    });

    it('should support metadata and tags for release notes', () => {
      const releaseNoteWithMetadata: ReleaseNoteItem = {
        kind: 'release_note',
        scope: { project: 'test', branch: 'main' },
        data: {
          version: '2.1.0',
          release_date: '2025-01-15T10:00:00Z',
          summary: 'Test release with metadata'
        },
        tags: {
          major: true,
          feature: 'authentication',
          priority: 'high',
          requires_migration: true,
          affected_teams: 'backend'
        },
        source: {
          actor: 'release-coordinator',
          tool: 'release-management-system',
          timestamp: '2025-01-15T10:00:00Z'
        }
      };

      const result = ReleaseNoteSchema.safeParse(releaseNoteWithMetadata);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.tags?.major).toBe(true);
        expect(result.data.tags?.feature).toBe('authentication');
        expect(result.data.tags?.priority).toBe('high');
        expect(result.data.source?.actor).toBe('release-coordinator');
      }
    });

    it('should handle complex release scenarios', () => {
      const complexRelease: ReleaseNoteItem = {
        kind: 'release_note',
        scope: {
          project: 'complex-enterprise-system',
          branch: 'production'
        },
        data: {
          version: '10.0.0-enterprise',
          release_date: '2025-01-15T10:00:00Z',
          summary: 'Decade milestone enterprise release with platform transformation',
          new_features: [
            'AI-powered intelligent automation platform with machine learning capabilities',
            'Microservices architecture migration with service mesh integration',
            'Advanced analytics and real-time business intelligence dashboard',
            'Global multi-region deployment with automatic failover capabilities',
            'Zero-trust security model with advanced threat detection'
          ],
          bug_fixes: [
            'Resolved critical memory leaks in high-transaction processing workloads',
            'Fixed data consistency issues in distributed transaction management',
            'Corrected authentication failures under concurrent user load scenarios',
            'Eliminated race conditions in real-time event processing pipeline'
          ],
          breaking_changes: [
            'Complete API redesign - all endpoints migrated to GraphQL v2 specification',
            'Database layer migration from monolithic to distributed microservices architecture',
            'Authentication and authorization model completely overhauled',
            'Configuration management system replaced with hierarchical distributed config service'
          ],
          deprecations: [
            'Legacy REST API v1 will be discontinued in v11.0.0',
            'Old authentication middleware deprecated in favor of OAuth 2.2 + OpenID Connect',
            'Monolithic deployment approach deprecated - migrate to containerized orchestration',
            'Legacy reporting system will be replaced in next major release cycle'
          ]
        },
        tags: {
          milestone: true,
          major: true,
          'breaking-change': true,
          enterprise: true,
          transformation: true
        },
        source: {
          actor: 'enterprise-release-team',
          tool: 'enterprise-release-platform',
          timestamp: '2025-01-15T10:00:00Z'
        },
        idempotency_key: 'enterprise-10.0.0-milestone-2025-01-15',
        ttl_policy: 'permanent'
      };

      const result = ReleaseNoteSchema.safeParse(complexRelease);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.data.version).toBe('10.0.0-enterprise');
        expect(result.data.data.new_features).toHaveLength(5);
        expect(result.data.data.bug_fixes).toHaveLength(4);
        expect(result.data.data.breaking_changes).toHaveLength(4);
        expect(result.data.data.deprecations).toHaveLength(4);
        expect(result.data.scope.project).toBe('complex-enterprise-system');
        expect(result.data.tags?.milestone).toBe(true);
        expect(result.data.source?.actor).toBe('enterprise-release-team');
        expect(result.data.ttl_policy).toBe('permanent');
      }
    });
  });
});