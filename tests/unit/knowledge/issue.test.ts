import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  validateQdrantSchemaCompliance,
  storeIssue
} from '../../../src/services/knowledge/issue';

// Mock the UnifiedDatabaseLayer
const mockDb = {
  initialize: vi.fn().mockResolvedValue(undefined),
  create: vi.fn(),
  update: vi.fn(),
  find: vi.fn(),
};

// Mock qdrant for issue service
const mockQdrant = {
  issueLog: {
    create: vi.fn(),
  },
};

vi.mock('../../../src/db/unified-database-layer-v2', () => ({
  UnifiedDatabaseLayer: vi.fn().mockImplementation(() => mockDb),
}));

vi.mock('../../../src/db/qdrant-client', () => ({
  getQdrantClient: vi.fn().mockReturnValue(mockQdrant),
}));

describe('Issue Service', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('validateQdrantSchemaCompliance', () => {
    const validIssueData = {
      title: 'Login button not working',
      description: 'Users cannot click the login button',
      status: 'open',
      tracker: 'github',
      external_id: 'GH-123',
      url: 'https://github.com/repo/issues/123',
      assignee: 'john.doe@example.com',
      labels: ['bug', 'ui', 'critical'],
    };

    it('should pass validation for valid issue data', () => {
      // Act & Assert
      expect(() => validateQdrantSchemaCompliance(validIssueData)).not.toThrow();
    });

    it('should reject when tracker field is in metadata', () => {
      // Arrange
      const invalidData = {
        ...validIssueData,
        metadata: { tracker: 'jira' },
      };

      // Act & Assert
      expect(() => validateQdrantSchemaCompliance(invalidData)).toThrow(
        "qdrant SCHEMA VIOLATION: Field 'tracker' must use direct field access (data.tracker) " +
        "instead of metadata workaround (data.metadata.tracker). " +
        "Database fields must use direct field mapping."
      );
    });

    it('should reject when external_id field is in metadata', () => {
      // Arrange
      const invalidData = {
        ...validIssueData,
        metadata: { external_id: 'JIRA-456' },
      };

      // Act & Assert
      expect(() => validateQdrantSchemaCompliance(invalidData)).toThrow(
        "qdrant SCHEMA VIOLATION: Field 'external_id' must use direct field access (data.external_id) " +
        "instead of metadata workaround (data.metadata.external_id). " +
        "Database fields must use direct field mapping."
      );
    });

    it('should reject when url field is in metadata', () => {
      // Arrange
      const invalidData = {
        ...validIssueData,
        metadata: { url: 'https://example.com/issue/123' },
      };

      // Act & Assert
      expect(() => validateQdrantSchemaCompliance(invalidData)).toThrow(
        "qdrant SCHEMA VIOLATION: Field 'url' must use direct field access (data.url) " +
        "instead of metadata workaround (data.metadata.url). " +
        "Database fields must use direct field mapping."
      );
    });

    it('should reject when assignee field is in metadata', () => {
      // Arrange
      const invalidData = {
        ...validIssueData,
        metadata: { assignee: 'jane.doe@example.com' },
      };

      // Act & Assert
      expect(() => validateQdrantSchemaCompliance(invalidData)).toThrow(
        "qdrant SCHEMA VIOLATION: Field 'assignee' must use direct field access (data.assignee) " +
        "instead of metadata workaround (data.metadata.assignee). " +
        "Database fields must use direct field mapping."
      );
    });

    it('should reject when labels field is in metadata', () => {
      // Arrange
      const invalidData = {
        ...validIssueData,
        metadata: { labels: ['bug', 'urgent'] },
      };

      // Act & Assert
      expect(() => validateQdrantSchemaCompliance(invalidData)).toThrow(
        "qdrant SCHEMA VIOLATION: Field 'labels' must use direct field access (data.labels) " +
        "instead of metadata workaround (data.metadata.labels). " +
        "Database fields must use direct field mapping."
      );
    });

    it('should reject when tracker field is in tags', () => {
      // Arrange
      const invalidData = {
        ...validIssueData,
        tags: { tracker: 'jira' },
      };

      // Act & Assert
      expect(() => validateQdrantSchemaCompliance(invalidData)).toThrow(
        "qdrant SCHEMA VIOLATION: Field 'tracker' must use direct field access (data.tracker) " +
        "instead of tags workaround (data.tags.tracker). " +
        "Database fields must use direct field mapping."
      );
    });

    it('should reject when external_id field is in tags', () => {
      // Arrange
      const invalidData = {
        ...validIssueData,
        tags: { external_id: 'JIRA-456' },
      };

      // Act & Assert
      expect(() => validateQdrantSchemaCompliance(invalidData)).toThrow(
        "qdrant SCHEMA VIOLATION: Field 'external_id' must use direct field access (data.external_id) " +
        "instead of tags workaround (data.tags.external_id). " +
        "Database fields must use direct field mapping."
      );
    });

    it('should reject when url field is in tags', () => {
      // Arrange
      const invalidData = {
        ...validIssueData,
        tags: { url: 'https://example.com/issue/123' },
      };

      // Act & Assert
      expect(() => validateQdrantSchemaCompliance(invalidData)).toThrow(
        "qdrant SCHEMA VIOLATION: Field 'url' must use direct field access (data.url) " +
        "instead of tags workaround (data.tags.url). " +
        "Database fields must use direct field mapping."
      );
    });

    it('should reject when assignee field is in tags', () => {
      // Arrange
      const invalidData = {
        ...validIssueData,
        tags: { assignee: 'jane.doe@example.com' },
      };

      // Act & Assert
      expect(() => validateQdrantSchemaCompliance(invalidData)).toThrow(
        "qdrant SCHEMA VIOLATION: Field 'assignee' must use direct field access (data.assignee) " +
        "instead of tags workaround (data.tags.assignee). " +
        "Database fields must use direct field mapping."
      );
    });

    it('should reject when labels field is in tags', () => {
      // Arrange
      const invalidData = {
        ...validIssueData,
        tags: { labels: ['bug', 'urgent'] },
      };

      // Act & Assert
      expect(() => validateQdrantSchemaCompliance(invalidData)).toThrow(
        "qdrant SCHEMA VIOLATION: Field 'labels' must use direct field mapping. " +
        "Database fields must use direct field mapping."
      );
    });

    it('should reject when tracker field exceeds maximum length', () => {
      // Arrange
      const invalidData = {
        ...validIssueData,
        tracker: 'a'.repeat(101), // 101 characters, max is 100
      };

      // Act & Assert
      expect(() => validateQdrantSchemaCompliance(invalidData)).toThrow(
        'Tracker field exceeds maximum length of 100 characters'
      );
    });

    it('should reject when external_id field exceeds maximum length', () => {
      // Arrange
      const invalidData = {
        ...validIssueData,
        external_id: 'a'.repeat(101), // 101 characters, max is 100
      };

      // Act & Assert
      expect(() => validateQdrantSchemaCompliance(invalidData)).toThrow(
        'External ID field exceeds maximum length of 100 characters'
      );
    });

    it('should reject when assignee field exceeds maximum length', () => {
      // Arrange
      const invalidData = {
        ...validIssueData,
        assignee: 'a'.repeat(201), // 201 characters, max is 200
      };

      // Act & Assert
      expect(() => validateQdrantSchemaCompliance(invalidData)).toThrow(
        'Assignee field exceeds maximum length of 200 characters'
      );
    });

    it('should reject when title field exceeds maximum length', () => {
      // Arrange
      const invalidData = {
        ...validIssueData,
        title: 'a'.repeat(501), // 501 characters, max is 500
      };

      // Act & Assert
      expect(() => validateQdrantSchemaCompliance(invalidData)).toThrow(
        'Title field exceeds maximum length of 500 characters'
      );
    });

    it('should pass validation when fields are at maximum length', () => {
      // Arrange
      const validMaxLengthData = {
        ...validIssueData,
        tracker: 'a'.repeat(100), // Exactly 100 characters
        external_id: 'a'.repeat(100), // Exactly 100 characters
        assignee: 'a'.repeat(200), // Exactly 200 characters
        title: 'a'.repeat(500), // Exactly 500 characters
      };

      // Act & Assert
      expect(() => validateQdrantSchemaCompliance(validMaxLengthData)).not.toThrow();
    });

    it('should pass validation with null metadata', () => {
      // Arrange
      const dataWithNullMetadata = {
        ...validIssueData,
        metadata: null,
      };

      // Act & Assert
      expect(() => validateQdrantSchemaCompliance(dataWithNullMetadata)).not.toThrow();
    });

    it('should pass validation with undefined metadata', () => {
      // Arrange
      const dataWithUndefinedMetadata = {
        ...validIssueData,
        metadata: undefined,
      };

      // Act & Assert
      expect(() => validateQdrantSchemaCompliance(dataWithUndefinedMetadata)).not.toThrow();
    });

    it('should pass validation with null tags', () => {
      // Arrange
      const dataWithNullTags = {
        ...validIssueData,
        tags: null,
      };

      // Act & Assert
      expect(() => validateQdrantSchemaCompliance(dataWithNullTags)).not.toThrow();
    });

    it('should pass validation with undefined tags', () => {
      // Arrange
      const dataWithUndefinedTags = {
        ...validIssueData,
        tags: undefined,
      };

      // Act & Assert
      expect(() => validateQdrantSchemaCompliance(dataWithUndefinedTags)).not.toThrow();
    });

    it('should pass validation with empty metadata object', () => {
      // Arrange
      const dataWithEmptyMetadata = {
        ...validIssueData,
        metadata: {},
      };

      // Act & Assert
      expect(() => validateQdrantSchemaCompliance(dataWithEmptyMetadata)).not.toThrow();
    });

    it('should pass validation with empty tags object', () => {
      // Arrange
      const dataWithEmptyTags = {
        ...validIssueData,
        tags: {},
      };

      // Act & Assert
      expect(() => validateQdrantSchemaCompliance(dataWithEmptyTags)).not.toThrow();
    });

    it('should pass validation with metadata containing allowed fields', () => {
      // Arrange
      const dataWithAllowedMetadata = {
        ...validIssueData,
        metadata: {
          priority: 'high',
          component: 'AuthService',
          environment: 'production',
          custom_field: 'custom_value',
        },
      };

      // Act & Assert
      expect(() => validateQdrantSchemaCompliance(dataWithAllowedMetadata)).not.toThrow();
    });

    it('should pass validation with tags containing allowed fields', () => {
      // Arrange
      const dataWithAllowedTags = {
        ...validIssueData,
        tags: {
          project: 'test-project',
          team: 'backend',
          sprint: 'sprint-12',
        },
      };

      // Act & Assert
      expect(() => validateQdrantSchemaCompliance(dataWithAllowedTags)).not.toThrow();
    });

    it('should handle multiple violations in metadata', () => {
      // Arrange
      const invalidData = {
        ...validIssueData,
        metadata: {
          tracker: 'jira',
          external_id: 'JIRA-123',
          url: 'https://jira.example.com/browse/JIRA-123',
        },
      };

      // Act & Assert - Should throw on first violation found
      expect(() => validateQdrantSchemaCompliance(invalidData)).toThrow(
        "qdrant SCHEMA VIOLATION: Field 'tracker' must use direct field access"
      );
    });

    it('should handle multiple violations in tags', () => {
      // Arrange
      const invalidData = {
        ...validIssueData,
        tags: {
          assignee: 'jane.doe@example.com',
          labels: ['bug', 'urgent'],
        },
      };

      // Act & Assert - Should throw on first violation found
      expect(() => validateQdrantSchemaCompliance(invalidData)).toThrow(
        "qdrant SCHEMA VIOLATION: Field 'assignee' must use direct field access"
      );
    });

    it('should pass validation with empty strings for fields', () => {
      // Arrange
      const dataWithEmptyStrings = {
        title: '',
        description: '',
        status: '',
        tracker: '',
        external_id: '',
        url: '',
        assignee: '',
        labels: [],
      };

      // Act & Assert
      expect(() => validateQdrantSchemaCompliance(dataWithEmptyStrings)).not.toThrow();
    });

    it('should pass validation with unicode content', () => {
      // Arrange
      const unicodeData = {
        title: 'Problème: 测试 中文 🧠',
        description: 'Description with ñoño and العربية characters',
        status: 'ouvert',
        tracker: 'système français',
        external_id: 'FR-测试-123',
        assignee: 'usuario@ejemplo.español',
        labels: ['étiquette', '标签', 'etiqueta'],
      };

      // Act & Assert
      expect(() => validateQdrantSchemaCompliance(unicodeData)).not.toThrow();
    });
  });

  describe('storeIssue', () => {
    const mockIssueData = {
      title: 'Login button not working',
      description: 'Users cannot click the login button on the homepage',
      status: 'open',
      tracker: 'github',
      external_id: 'GH-123',
      url: 'https://github.com/repo/issues/123',
      assignee: 'john.doe@example.com',
      labels: ['bug', 'ui', 'critical'],
    };
    const mockScope = { project: 'test-project', org: 'test-org' };

    it('should store issue successfully with all fields', async () => {
      // Arrange
      const expectedId = 'issue-uuid-123';
      mockQdrant.issueLog.create.mockResolvedValue({ id: expectedId });

      // Act
      const result = await storeIssue(mockIssueData, mockScope);

      // Assert
      expect(result).toBe(expectedId);
      expect(mockQdrant.issueLog.create).toHaveBeenCalledWith({
        data: {
          title: mockIssueData.title,
          description: mockIssueData.description,
          status: mockIssueData.status,
          tracker: mockIssueData.tracker,
          external_id: mockIssueData.external_id,
          labels: JSON.stringify(mockIssueData.labels),
          url: mockIssueData.url,
          assignee: mockIssueData.assignee,
          tags: mockScope,
        },
      });
    });

    it('should store issue with null optional fields', async () => {
      // Arrange
      const issueWithNulls = {
        title: 'Issue with null fields',
        description: null,
        status: 'open',
        tracker: null,
        external_id: null,
        url: null,
        assignee: null,
        labels: null,
      };
      const expectedId = 'issue-nulls';
      mockQdrant.issueLog.create.mockResolvedValue({ id: expectedId });

      // Act
      const result = await storeIssue(issueWithNulls, mockScope);

      // Assert
      expect(result).toBe(expectedId);
      expect(mockQdrant.issueLog.create).toHaveBeenCalledWith({
        data: {
          title: issueWithNulls.title,
          description: null,
          status: issueWithNulls.status,
          tracker: null,
          external_id: null,
          labels: JSON.stringify(null),
          url: null,
          assignee: null,
          tags: mockScope,
        },
      });
    });

    it('should store issue with undefined optional fields', async () => {
      // Arrange
      const issueWithUndefined = {
        title: 'Issue with undefined fields',
        status: 'open',
        // description, tracker, external_id, url, assignee, labels are undefined
      };
      const expectedId = 'issue-undefined';
      mockQdrant.issueLog.create.mockResolvedValue({ id: expectedId });

      // Act
      const result = await storeIssue(issueWithUndefined, mockScope);

      // Assert
      expect(result).toBe(expectedId);
      expect(mockQdrant.issueLog.create).toHaveBeenCalledWith({
        data: {
          title: issueWithUndefined.title,
          description: undefined,
          status: issueWithUndefined.status,
          tracker: undefined,
          external_id: undefined,
          labels: JSON.stringify(undefined),
          url: undefined,
          assignee: undefined,
          tags: mockScope,
        },
      });
    });

    it('should handle empty scope', async () => {
      // Arrange
      const expectedId = 'issue-empty-scope';
      mockQdrant.issueLog.create.mockResolvedValue({ id: expectedId });

      // Act
      const result = await storeIssue(mockIssueData, {});

      // Assert
      expect(result).toBe(expectedId);
      expect(mockQdrant.issueLog.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          tags: {},
        }),
      });
    });

    it('should handle database create errors', async () => {
      // Arrange
      mockQdrant.issueLog.create.mockRejectedValue(new Error('Database insert failed'));

      // Act & Assert
      await expect(storeIssue(mockIssueData, mockScope)).rejects.toThrow(
        'Database insert failed'
      );
    });

    it('should handle validation errors', async () => {
      // Arrange
      const invalidIssueData = {
        ...mockIssueData,
        title: 'a'.repeat(501), // Exceeds max length
      };

      // Act & Assert
      await expect(storeIssue(invalidIssueData, mockScope)).rejects.toThrow(
        'Title field exceeds maximum length of 500 characters'
      );
      expect(mockQdrant.issueLog.create).not.toHaveBeenCalled();
    });

    it('should handle unicode content in issue data', async () => {
      // Arrange
      const unicodeIssueData = {
        title: 'Problème: 测试 中文 🧠',
        description: 'Description with ñoño and العربية content',
        status: 'ouvert',
        tracker: 'système français',
        external_id: 'FR-测试-123',
        url: 'https://example.com/fr/issuée/测试',
        assignee: 'usuario@ejemplo.español',
        labels: ['étiquette', '标签', 'etiqueta', '🐛'],
      };
      const expectedId = 'unicode-issue';
      mockQdrant.issueLog.create.mockResolvedValue({ id: expectedId });

      // Act
      const result = await storeIssue(unicodeIssueData, mockScope);

      // Assert
      expect(result).toBe(expectedId);
      expect(mockQdrant.issueLog.create).toHaveBeenCalledWith({
        data: {
          title: 'Problème: 测试 中文 🧠',
          description: 'Description with ñoño and العربية content',
          status: 'ouvert',
          tracker: 'système français',
          external_id: 'FR-测试-123',
          labels: JSON.stringify(['étiquette', '标签', 'etiqueta', '🐛']),
          url: 'https://example.com/fr/issuée/测试',
          assignee: 'usuario@ejemplo.español',
          tags: mockScope,
        },
      });
    });

    it('should handle very long description', async () => {
      // Arrange
      const longDescription = 'This is a very long issue description. '.repeat(1000);
      const issueWithLongDesc = {
        ...mockIssueData,
        description: longDescription,
      };
      const expectedId = 'issue-long-desc';
      mockQdrant.issueLog.create.mockResolvedValue({ id: expectedId });

      // Act
      const result = await storeIssue(issueWithLongDesc, mockScope);

      // Assert
      expect(result).toBe(expectedId);
    });

    it('should handle complex labels array', async () => {
      // Arrange
      const complexLabels = [
        'bug',
        'ui/critical',
        'priority-high',
        'component:auth',
        'sprint:12',
        'team:backend',
        'env:production',
        'test',
        'review-needed',
        'blocked-by:dependency'
      ];
      const issueWithComplexLabels = {
        ...mockIssueData,
        labels: complexLabels,
      };
      const expectedId = 'issue-complex-labels';
      mockQdrant.issueLog.create.mockResolvedValue({ id: expectedId });

      // Act
      const result = await storeIssue(issueWithComplexLabels, mockScope);

      // Assert
      expect(result).toBe(expectedId);
      expect(mockQdrant.issueLog.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          labels: JSON.stringify(complexLabels),
        }),
      });
    });

    it('should handle empty labels array', async () => {
      // Arrange
      const issueWithEmptyLabels = {
        ...mockIssueData,
        labels: [],
      };
      const expectedId = 'issue-empty-labels';
      mockQdrant.issueLog.create.mockResolvedValue({ id: expectedId });

      // Act
      const result = await storeIssue(issueWithEmptyLabels, mockScope);

      // Assert
      expect(result).toBe(expectedId);
      expect(mockQdrant.issueLog.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          labels: JSON.stringify([]),
        }),
      });
    });

    it('should handle different issue statuses', async () => {
      // Arrange
      const statuses = ['open', 'in_progress', 'resolved', 'closed', 'rejected', 'duplicate'];

      for (const status of statuses) {
        mockQdrant.issueLog.create.mockClear();
        const issueWithStatus = { ...mockIssueData, status };
        const expectedId = `issue-${status}`;
        mockQdrant.issueLog.create.mockResolvedValue({ id: expectedId });

        // Act
        const result = await storeIssue(issueWithStatus, mockScope);

        // Assert
        expect(result).toBe(expectedId);
        expect(mockQdrant.issueLog.create).toHaveBeenCalledWith({
          data: expect.objectContaining({ status }),
        });
      }
    });

    it('should handle different trackers', async () => {
      // Arrange
      const trackers = ['github', 'jira', 'gitlab', 'bitbucket', 'azure-devops', 'linear'];

      for (const tracker of trackers) {
        mockQdrant.issueLog.create.mockClear();
        const issueWithTracker = { ...mockIssueData, tracker };
        const expectedId = `issue-${tracker}`;
        mockQdrant.issueLog.create.mockResolvedValue({ id: expectedId });

        // Act
        const result = await storeIssue(issueWithTracker, mockScope);

        // Assert
        expect(result).toBe(expectedId);
        expect(mockQdrant.issueLog.create).toHaveBeenCalledWith({
          data: expect.objectContaining({ tracker }),
        });
      }
    });

    it('should handle URL validation (store as-is, validation happens at database level)', async () => {
      // Arrange
      const issueWithInvalidUrl = {
        ...mockIssueData,
        url: 'not-a-valid-url',
      };
      const expectedId = 'issue-invalid-url';
      mockQdrant.issueLog.create.mockResolvedValue({ id: expectedId });

      // Act
      const result = await storeIssue(issueWithInvalidUrl, mockScope);

      // Assert
      expect(result).toBe(expectedId);
      expect(mockQdrant.issueLog.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          url: 'not-a-valid-url',
        }),
      });
    });

    it('should handle email validation in assignee (store as-is, validation happens at database level)', async () => {
      // Arrange
      const issueWithInvalidEmail = {
        ...mockIssueData,
        assignee: 'not-an-email',
      };
      const expectedId = 'issue-invalid-email';
      mockQdrant.issueLog.create.mockResolvedValue({ id: expectedId });

      // Act
      const result = await storeIssue(issueWithInvalidEmail, mockScope);

      // Assert
      expect(result).toBe(expectedId);
      expect(mockQdrant.issueLog.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          assignee: 'not-an-email',
        }),
      });
    });

    it('should serialize complex labels correctly', async () => {
      // Arrange
      const complexLabels = [
        { type: 'bug', severity: 'critical' }, // Object in labels array
        'simple-label',
        123, // Number in labels array
        null, // null in labels array
        undefined, // undefined in labels array
      ];
      const issueWithComplexLabels = {
        ...mockIssueData,
        labels: complexLabels as any,
      };
      const expectedId = 'issue-complex-serialization';
      mockQdrant.issueLog.create.mockResolvedValue({ id: expectedId });

      // Act
      const result = await storeIssue(issueWithComplexLabels, mockScope);

      // Assert
      expect(result).toBe(expectedId);
      expect(mockQdrant.issueLog.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          labels: JSON.stringify(complexLabels),
        }),
      });
    });

    it('should handle issue with metadata (allowed fields only)', async () => {
      // Arrange
      const issueWithMetadata = {
        ...mockIssueData,
        metadata: {
          priority: 'high',
          component: 'AuthService',
          environment: 'production',
          custom_field: 'custom_value',
          story_points: 5,
          team_velocity: 25.5,
        },
      };
      const expectedId = 'issue-with-metadata';
      mockQdrant.issueLog.create.mockResolvedValue({ id: expectedId });

      // Act
      const result = await storeIssue(issueWithMetadata, mockScope);

      // Assert
      expect(result).toBe(expectedId);
      // Metadata should not be stored directly, only scope tags are stored
      expect(mockQdrant.issueLog.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          tags: mockScope, // Only scope is stored as tags
        }),
      });
    });

    it('should handle issue with tags (allowed fields only)', async () => {
      // Arrange
      const issueWithTags = {
        ...mockIssueData,
        tags: {
          project: 'existing-project',
          team: 'backend',
          sprint: 'sprint-12',
          custom_tag: 'custom_value',
        },
      };
      const expectedId = 'issue-with-tags';
      mockQdrant.issueLog.create.mockResolvedValue({ id: expectedId });

      // Act
      const result = await storeIssue(issueWithTags, { project: 'new-project' });

      // Assert
      expect(result).toBe(expectedId);
      // Only scope tags should be stored, not the issue's own tags
      expect(mockQdrant.issueLog.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          tags: { project: 'new-project' },
        }),
      });
    });
  });

  describe('Integration Tests', () => {
    it('should handle complete issue lifecycle with validation', async () => {
      // Arrange
      const issueData = {
        title: 'Critical security vulnerability',
        description: 'SQL injection vulnerability in user authentication',
        status: 'open',
        tracker: 'jira',
        external_id: 'SEC-2023-001',
        url: 'https://company.atlassian.net/browse/SEC-2023-001',
        assignee: 'security-team@example.com',
        labels: ['security', 'critical', 'sql-injection', 'authentication'],
      };
      const scope = { project: 'security-audit', org: 'company' };

      // Store
      const storedId = 'security-issue-001';
      mockQdrant.issueLog.create.mockResolvedValue({ id: storedId });
      const result = await storeIssue(issueData, scope);

      // Assert
      expect(result).toBe(storedId);
      expect(mockQdrant.issueLog.create).toHaveBeenCalledWith({
        data: {
          title: issueData.title,
          description: issueData.description,
          status: issueData.status,
          tracker: issueData.tracker,
          external_id: issueData.external_id,
          labels: JSON.stringify(issueData.labels),
          url: issueData.url,
          assignee: issueData.assignee,
          tags: scope,
        },
      });
    });

    it('should handle batch issue storage simulation', async () => {
      // Arrange
      const issues = [
        {
          title: 'Bug 1: Login fails',
          status: 'open',
          tracker: 'github',
          external_id: 'GH-001',
        },
        {
          title: 'Bug 2: Password reset not working',
          status: 'open',
          tracker: 'github',
          external_id: 'GH-002',
        },
        {
          title: 'Feature Request: Add 2FA',
          status: 'proposed',
          tracker: 'github',
          external_id: 'GH-003',
        },
      ];
      const scope = { project: 'auth-system' };

      // Store multiple issues
      for (let i = 0; i < issues.length; i++) {
        mockQdrant.issueLog.create.mockClear();
        const expectedId = `issue-${i + 1}`;
        mockQdrant.issueLog.create.mockResolvedValue({ id: expectedId });

        // Act
        const result = await storeIssue(issues[i], scope);

        // Assert
        expect(result).toBe(expectedId);
        expect(mockQdrant.issueLog.create).toHaveBeenCalledWith({
          data: expect.objectContaining({
            title: issues[i].title,
            status: issues[i].status,
            tracker: issues[i].tracker,
            external_id: issues[i].external_id,
            tags: scope,
          }),
        });
      }
    });

    it('should reject issues with schema violations', async () => {
      // Arrange - Try multiple schema violations
      const invalidIssues = [
        {
          title: 'Issue with metadata violation',
          metadata: { tracker: 'should-be-direct-field' },
        },
        {
          title: 'Issue with tags violation',
          tags: { assignee: 'should-be-direct-field' },
        },
        {
          title: 'a'.repeat(501), // Title too long
          status: 'open',
        },
        {
          title: 'Valid title',
          assignee: 'a'.repeat(201), // Assignee too long
        },
      ];

      // Act & Assert
      for (const invalidIssue of invalidIssues) {
        await expect(storeIssue(invalidIssue as any, { project: 'test' })).rejects.toThrow();
        expect(mockQdrant.issueLog.create).not.toHaveBeenCalled();
        mockQdrant.issueLog.create.mockClear();
      }
    });

    it('should handle issues from different tracking systems', async () => {
      // Arrange
      const trackingSystemIssues = [
        {
          title: 'GitHub Issue',
          tracker: 'github',
          external_id: 'owner/repo#123',
          url: 'https://github.com/owner/repo/issues/123',
        },
        {
          title: 'Jira Issue',
          tracker: 'jira',
          external_id: 'PROJ-456',
          url: 'https://company.atlassian.net/browse/PROJ-456',
        },
        {
          title: 'GitLab Issue',
          tracker: 'gitlab',
          external_id: '789',
          url: 'https://gitlab.com/group/project/-/issues/789',
        },
        {
          title: 'Linear Issue',
          tracker: 'linear',
          external_id: 'LIN-101',
          url: 'https://linear.app/team/issue/LIN-101',
        },
      ];
      const scope = { project: 'multi-tracker-test' };

      // Act & Assert
      for (let i = 0; i < trackingSystemIssues.length; i++) {
        mockQdrant.issueLog.create.mockClear();
        const expectedId = `tracker-issue-${i + 1}`;
        mockQdrant.issueLog.create.mockResolvedValue({ id: expectedId });

        const result = await storeIssue(trackingSystemIssues[i], scope);

        expect(result).toBe(expectedId);
        expect(mockQdrant.issueLog.create).toHaveBeenCalledWith({
          data: expect.objectContaining({
            title: trackingSystemIssues[i].title,
            tracker: trackingSystemIssues[i].tracker,
            external_id: trackingSystemIssues[i].external_id,
            url: trackingSystemIssues[i].url,
            tags: scope,
          }),
        });
      }
    });
  });
});