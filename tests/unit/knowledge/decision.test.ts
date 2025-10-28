import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  storeDecision,
  updateDecision
} from '../../../src/services/knowledge/decision';

// Mock the UnifiedDatabaseLayer and related dependencies
const mockDb = {
  initialize: vi.fn().mockResolvedValue(undefined),
  create: vi.fn(),
  update: vi.fn(),
  find: vi.fn(),
};

const mockQdrantClient = {
  adrDecision: {
    update: vi.fn(),
  },
};

// Create a proper mock class that can be instantiated
class MockUnifiedDatabaseLayer {
  initialize = mockDb.initialize;
  create = mockDb.create;
  update = mockDb.update;
  find = mockDb.find;
}

vi.mock('../../../src/db/unified-database-layer-v2', () => ({
  UnifiedDatabaseLayer: MockUnifiedDatabaseLayer,
}));

vi.mock('../../../src/utils/immutability', () => ({
  validateADRImmutability: vi.fn(),
}));

vi.mock('../../../src/db/qdrant-client', () => ({
  getQdrantClient: vi.fn().mockReturnValue(mockQdrantClient),
}));

describe('Decision Service', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('storeDecision', () => {
    const mockDecisionData = {
      component: 'AuthService',
      status: 'proposed',
      title: 'Implement OAuth 2.0 Authentication',
      rationale: 'OAuth 2.0 provides industry-standard authentication with better security and user experience',
      alternatives_considered: ['Basic Auth', 'JWT-only', 'Session-based'],
    };
    const mockScope = { project: 'test-project', org: 'test-org' };

    it('should store decision successfully', async () => {
      // Arrange
      const expectedId = 'decision-uuid-123';
      mockDb.create.mockResolvedValue({ id: expectedId });

      // Act
      const result = await storeDecision(mockDecisionData, mockScope);

      // Assert
      expect(result).toBe(expectedId);
      expect(mockDb.initialize).toHaveBeenCalled();
      expect(mockDb.create).toHaveBeenCalledWith('adr_decision', {
        component: mockDecisionData.component,
        status: mockDecisionData.status,
        title: mockDecisionData.title,
        rationale: mockDecisionData.rationale,
        alternatives_considered: mockDecisionData.alternatives_considered,
        tags: mockScope,
        created_at: expect.any(String),
        updated_at: expect.any(String),
      });
    });

    it('should handle decision with empty alternatives', async () => {
      // Arrange
      const decisionWithEmptyAlternatives = {
        ...mockDecisionData,
        alternatives_considered: [],
      };
      const expectedId = 'decision-no-alts';
      mockDb.create.mockResolvedValue({ id: expectedId });

      // Act
      const result = await storeDecision(decisionWithEmptyAlternatives, mockScope);

      // Assert
      expect(result).toBe(expectedId);
      expect(mockDb.create).toHaveBeenCalledWith('adr_decision',
        expect.objectContaining({
          alternatives_considered: [],
        }),
        undefined
      );
    });

    it('should handle decision with null alternatives', async () => {
      // Arrange
      const decisionWithNullAlternatives = {
        ...mockDecisionData,
        alternatives_considered: null as any,
      };
      const expectedId = 'decision-null-alts';
      mockDb.create.mockResolvedValue({ id: expectedId });

      // Act
      const result = await storeDecision(decisionWithNullAlternatives, mockScope);

      // Assert
      expect(result).toBe(expectedId);
      expect(mockDb.create).toHaveBeenCalledWith('adr_decision',
        expect.objectContaining({
          alternatives_considered: [],
        }),
        undefined
      );
    });

    it('should handle decision with undefined alternatives', async () => {
      // Arrange
      const decisionWithUndefinedAlternatives = {
        ...mockDecisionData,
        alternatives_considered: undefined,
      };
      const expectedId = 'decision-undef-alts';
      mockDb.create.mockResolvedValue({ id: expectedId });

      // Act
      const result = await storeDecision(decisionWithUndefinedAlternatives, mockScope);

      // Assert
      expect(result).toBe(expectedId);
      expect(mockDb.create).toHaveBeenCalledWith('adr_decision',
        expect.objectContaining({
          alternatives_considered: [],
        }),
        undefined
      );
    });

    it('should handle database initialization errors', async () => {
      // Arrange
      mockDb.initialize.mockRejectedValue(new Error('Database connection failed'));

      // Act & Assert
      await expect(storeDecision(mockDecisionData, mockScope)).rejects.toThrow(
        'Database connection failed'
      );
    });

    it('should handle database creation errors', async () => {
      // Arrange
      mockDb.create.mockRejectedValue(new Error('Insert failed'));

      // Act & Assert
      await expect(storeDecision(mockDecisionData, mockScope)).rejects.toThrow(
        'Insert failed'
      );
    });

    it('should handle empty scope', async () => {
      // Arrange
      const expectedId = 'decision-empty-scope';
      mockDb.create.mockResolvedValue({ id: expectedId });

      // Act
      const result = await storeDecision(mockDecisionData, {});

      // Assert
      expect(result).toBe(expectedId);
      expect(mockDb.create).toHaveBeenCalledWith('adr_decision',
        expect.objectContaining({
          tags: {},
        }),
        undefined
      );
    });

    it('should handle complex rationale with special characters', async () => {
      // Arrange
      const decisionWithComplexRationale = {
        ...mockDecisionData,
        rationale: 'Complex decision involving OAuth 2.0, JWT tokens, & security implications. Consider scalability & performance.',
      };
      const expectedId = 'decision-complex';
      mockDb.create.mockResolvedValue({ id: expectedId });

      // Act
      const result = await storeDecision(decisionWithComplexRationale, mockScope);

      // Assert
      expect(result).toBe(expectedId);
      expect(mockDb.create).toHaveBeenCalledWith('adr_decision',
        expect.objectContaining({
          rationale: decisionWithComplexRationale.rationale,
        }),
        undefined
      );
    });

    it('should handle unicode content in decision data', async () => {
      // Arrange
      const unicodeDecision = {
        component: 'Entité Français',
        status: 'proposé',
        title: 'Décision: 测试 中文 🧠',
        rationale: 'Rationale with ñoño and العربية content',
        alternatives_considered: ['Opción A', '选项 B', 'الخيار C'],
      };
      const expectedId = 'unicode-decision';
      mockDb.create.mockResolvedValue({ id: expectedId });

      // Act
      const result = await storeDecision(unicodeDecision, mockScope);

      // Assert
      expect(result).toBe(expectedId);
      expect(mockDb.create).toHaveBeenCalledWith('adr_decision',
        expect.objectContaining({
          component: 'Entité Français',
          status: 'proposé',
          title: 'Décision: 测试 中文 🧠',
          rationale: 'Rationale with ñoño and العربية content',
          alternatives_considered: ['Opción A', '选项 B', 'الخيار C'],
        }),
        undefined
      );
    });

    it('should handle very long rationale', async () => {
      // Arrange
      const longRationale = 'This is a very long rationale. '.repeat(1000);
      const decisionWithLongRationale = {
        ...mockDecisionData,
        rationale: longRationale,
      };
      const expectedId = 'decision-long';
      mockDb.create.mockResolvedValue({ id: expectedId });

      // Act
      const result = await storeDecision(decisionWithLongRationale, mockScope);

      // Assert
      expect(result).toBe(expectedId);
    });

    it('should validate required fields are present', async () => {
      // Arrange - Test missing component
      const invalidDecision1 = {
        status: 'proposed',
        title: 'Test Decision',
        rationale: 'Test rationale',
        alternatives_considered: [],
      };

      // Act & Assert
      await expect(storeDecision(invalidDecision1 as any, mockScope)).rejects.toThrow();
    });

    it('should create timestamp strings in ISO format', async () => {
      // Arrange
      const expectedId = 'decision-timestamp';
      mockDb.create.mockResolvedValue({ id: expectedId });

      // Act
      await storeDecision(mockDecisionData, mockScope);

      // Assert
      const createCall = mockDb.create.mock.calls[0];
      expect(createCall[1].created_at).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
      expect(createCall[1].updated_at).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    });

    it('should handle different decision statuses', async () => {
      // Arrange
      const statuses = ['proposed', 'accepted', 'rejected', 'deprecated', 'superseded'];

      for (const status of statuses) {
        mockDb.create.mockClear();
        const decisionWithStatus = { ...mockDecisionData, status };
        const expectedId = `decision-${status}`;
        mockDb.create.mockResolvedValue({ id: expectedId });

        // Act
        const result = await storeDecision(decisionWithStatus, mockScope);

        // Assert
        expect(result).toBe(expectedId);
        expect(mockDb.create).toHaveBeenCalledWith('adr_decision',
          expect.objectContaining({ status }),
          undefined
        );
      }
    });
  });

  describe('updateDecision', () => {
    const decisionId = 'decision-to-update';

    it('should update decision component successfully', async () => {
      // Arrange
      const updateData = { component: 'UpdatedAuthService' };
      mockQdrantClient.adrDecision.update.mockResolvedValue({ id: decisionId });

      // Act
      await updateDecision(decisionId, updateData);

      // Assert
      expect(validateADRImmutability).toHaveBeenCalledWith(decisionId);
      expect(mockQdrantClient.adrDecision.update).toHaveBeenCalledWith({
        where: { id: decisionId },
        data: { component: 'UpdatedAuthService' },
      });
    });

    it('should update decision status successfully', async () => {
      // Arrange
      const updateData = { status: 'accepted' };
      mockQdrantClient.adrDecision.update.mockResolvedValue({ id: decisionId });

      // Act
      await updateDecision(decisionId, updateData);

      // Assert
      expect(validateADRImmutability).toHaveBeenCalledWith(decisionId);
      expect(mockQdrantClient.adrDecision.update).toHaveBeenCalledWith({
        where: { id: decisionId },
        data: { status: 'accepted' },
      });
    });

    it('should update decision title successfully', async () => {
      // Arrange
      const updateData = { title: 'Updated Decision Title' };
      mockQdrantClient.adrDecision.update.mockResolvedValue({ id: decisionId });

      // Act
      await updateDecision(decisionId, updateData);

      // Assert
      expect(validateADRImmutability).toHaveBeenCalledWith(decisionId);
      expect(mockQdrantClient.adrDecision.update).toHaveBeenCalledWith({
        where: { id: decisionId },
        data: { title: 'Updated Decision Title' },
      });
    });

    it('should update decision rationale successfully', async () => {
      // Arrange
      const updateData = { rationale: 'Updated rationale for better understanding' };
      mockQdrantClient.adrDecision.update.mockResolvedValue({ id: decisionId });

      // Act
      await updateDecision(decisionId, updateData);

      // Assert
      expect(validateADRImmutability).toHaveBeenCalledWith(decisionId);
      expect(mockQdrantClient.adrDecision.update).toHaveBeenCalledWith({
        where: { id: decisionId },
        data: { rationale: 'Updated rationale for better understanding' },
      });
    });

    it('should update decision alternatives successfully', async () => {
      // Arrange
      const updateData = {
        alternatives_considered: ['New Alternative A', 'New Alternative B']
      };
      mockQdrantClient.adrDecision.update.mockResolvedValue({ id: decisionId });

      // Act
      await updateDecision(decisionId, updateData);

      // Assert
      expect(validateADRImmutability).toHaveBeenCalledWith(decisionId);
      expect(mockQdrantClient.adrDecision.update).toHaveBeenCalledWith({
        where: { id: decisionId },
        data: { alternativesConsidered: ['New Alternative A', 'New Alternative B'] },
      });
    });

    it('should update multiple fields simultaneously', async () => {
      // Arrange
      const updateData = {
        component: 'NewComponent',
        status: 'accepted',
        title: 'New Title',
        rationale: 'New rationale',
        alternatives_considered: ['Alt 1', 'Alt 2'],
      };
      mockQdrantClient.adrDecision.update.mockResolvedValue({ id: decisionId });

      // Act
      await updateDecision(decisionId, updateData);

      // Assert
      expect(validateADRImmutability).toHaveBeenCalledWith(decisionId);
      expect(mockQdrantClient.adrDecision.update).toHaveBeenCalledWith({
        where: { id: decisionId },
        data: {
          component: 'NewComponent',
          status: 'accepted',
          title: 'New Title',
          rationale: 'New rationale',
          alternativesConsidered: ['Alt 1', 'Alt 2'],
        },
      });
    });

    it('should handle empty alternatives array in update', async () => {
      // Arrange
      const updateData = { alternatives_considered: [] };
      mockQdrantClient.adrDecision.update.mockResolvedValue({ id: decisionId });

      // Act
      await updateDecision(decisionId, updateData);

      // Assert
      expect(mockQdrantClient.adrDecision.update).toHaveBeenCalledWith({
        where: { id: decisionId },
        data: { alternativesConsidered: [] },
      });
    });

    it('should handle null alternatives in update', async () => {
      // Arrange
      const updateData = { alternatives_considered: null as any };
      mockQdrantClient.adrDecision.update.mockResolvedValue({ id: decisionId });

      // Act
      await updateDecision(decisionId, updateData);

      // Assert
      expect(mockQdrantClient.adrDecision.update).toHaveBeenCalledWith({
        where: { id: decisionId },
        data: { alternativesConsidered: [] },
      });
    });

    it('should handle undefined alternatives in update', async () => {
      // Arrange
      const updateData = { alternatives_considered: undefined };
      mockQdrantClient.adrDecision.update.mockResolvedValue({ id: decisionId });

      // Act
      await updateDecision(decisionId, updateData);

      // Assert
      expect(mockQdrantClient.adrDecision.update).toHaveBeenCalledWith({
        where: { id: decisionId },
        data: { alternativesConsidered: [] },
      });
    });

    it('should return early when no update data provided', async () => {
      // Arrange
      const updateData = {};

      // Act
      await updateDecision(decisionId, updateData);

      // Assert
      expect(validateADRImmutability).toHaveBeenCalledWith(decisionId);
      expect(mockQdrantClient.adrDecision.update).not.toHaveBeenCalled();
    });

    it('should return early when only undefined values provided', async () => {
      // Arrange
      const updateData = {
        component: undefined,
        status: undefined,
        title: undefined,
        rationale: undefined,
        alternatives_considered: undefined,
      };

      // Act
      await updateDecision(decisionId, updateData);

      // Assert
      expect(validateADRImmutability).toHaveBeenCalledWith(decisionId);
      expect(mockQdrantClient.adrDecision.update).not.toHaveBeenCalled();
    });

    it('should handle immutability validation errors', async () => {
      // Arrange
      const updateData = { status: 'accepted' };
      const { validateADRImmutability } = await import('../../../src/utils/immutability');
      (validateADRImmutability as any).mockRejectedValue(
        new Error('Decision is immutable - status is accepted')
      );

      // Act & Assert
      await expect(updateDecision(decisionId, updateData)).rejects.toThrow(
        'Decision is immutable - status is accepted'
      );
      expect(mockQdrantClient.adrDecision.update).not.toHaveBeenCalled();
    });

    it('should handle database update errors', async () => {
      // Arrange
      const updateData = { title: 'New Title' };
      mockQdrantClient.adrDecision.update.mockRejectedValue(
        new Error('Database update failed')
      );

      // Act & Assert
      await expect(updateDecision(decisionId, updateData)).rejects.toThrow(
        'Database update failed'
      );
    });

    it('should handle empty decision ID', async () => {
      // Arrange
      const updateData = { title: 'New Title' };

      // Act & Assert
      await expect(updateDecision('', updateData)).rejects.toThrow();
      await expect(updateDecision(null as any, updateData)).rejects.toThrow();
      await expect(updateDecision(undefined as any, updateData)).rejects.toThrow();
    });

    it('should handle partial updates with mixed defined/undefined values', async () => {
      // Arrange
      const updateData = {
        component: 'UpdatedComponent',
        status: undefined,
        title: 'Updated Title',
        rationale: undefined,
        alternatives_considered: ['New Alt'],
      };
      mockQdrantClient.adrDecision.update.mockResolvedValue({ id: decisionId });

      // Act
      await updateDecision(decisionId, updateData);

      // Assert
      expect(mockQdrantClient.adrDecision.update).toHaveBeenCalledWith({
        where: { id: decisionId },
        data: {
          component: 'UpdatedComponent',
          title: 'Updated Title',
          alternativesConsidered: ['New Alt'],
        },
      });
    });

    it('should handle unicode content in update data', async () => {
      // Arrange
      const unicodeUpdateData = {
        title: 'Décision: 测试 中文 🧠',
        rationale: 'Rationale updated with ñoño and العربية',
        alternatives_considered: ['Nouvelle opción', '新选项'],
      };
      mockQdrantClient.adrDecision.update.mockResolvedValue({ id: decisionId });

      // Act
      await updateDecision(decisionId, unicodeUpdateData);

      // Assert
      expect(mockQdrantClient.adrDecision.update).toHaveBeenCalledWith({
        where: { id: decisionId },
        data: {
          title: 'Décision: 测试 中文 🧠',
          rationale: 'Rationale updated with ñoño and العربية',
          alternativesConsidered: ['Nouvelle opción', '新选项'],
        },
      });
    });

    it('should handle very long content in update data', async () => {
      // Arrange
      const longContent = 'This is very long content. '.repeat(1000);
      const updateData = { rationale: longContent };
      mockQdrantClient.adrDecision.update.mockResolvedValue({ id: decisionId });

      // Act
      await updateDecision(decisionId, updateData);

      // Assert
      expect(mockQdrantClient.adrDecision.update).toHaveBeenCalledWith({
        where: { id: decisionId },
        data: { rationale: longContent },
      });
    });
  });

  describe('Integration Tests', () => {
    it('should handle complete decision lifecycle', async () => {
      // Arrange
      const decisionData = {
        component: 'AuthService',
        status: 'proposed',
        title: 'Implement OAuth 2.0',
        rationale: 'OAuth 2.0 provides better security',
        alternatives_considered: ['Basic Auth', 'JWT-only'],
      };
      const scope = { project: 'lifecycle-test' };

      // Store
      const storedId = 'decision-lifecycle';
      mockDb.create.mockResolvedValue({ id: storedId });
      const result1 = await storeDecision(decisionData, scope);

      // Update
      const updateData = { status: 'accepted', rationale: 'Updated rationale after review' };
      mockQdrantClient.adrDecision.update.mockResolvedValue({ id: storedId });
      await updateDecision(storedId, updateData);

      // Assert
      expect(result1).toBe(storedId);
      expect(mockDb.create).toHaveBeenCalledWith('adr_decision',
        expect.objectContaining({
          component: decisionData.component,
          status: decisionData.status,
        }),
        undefined
      );
      expect(mockQdrantClient.adrDecision.update).toHaveBeenCalledWith({
        where: { id: storedId },
        data: {
          status: 'accepted',
          rationale: 'Updated rationale after review',
        },
      });
    });

    it('should handle multiple updates to same decision', async () => {
      // Arrange
      const decisionId = 'multi-update-decision';

      // First update
      const update1 = { component: 'NewComponent' };
      mockQdrantClient.adrDecision.update.mockResolvedValue({ id: decisionId });
      await updateDecision(decisionId, update1);

      // Second update
      const update2 = { status: 'accepted' };
      await updateDecision(decisionId, update2);

      // Third update - multiple fields
      const update3 = {
        title: 'Final Title',
        rationale: 'Final rationale',
        alternatives_considered: ['Final Alt 1', 'Final Alt 2'],
      };
      await updateDecision(decisionId, update3);

      // Assert
      expect(mockQdrantClient.adrDecision.update).toHaveBeenCalledTimes(3);
      expect(mockQdrantClient.adrDecision.update).toHaveBeenNthCalledWith(1, {
        where: { id: decisionId },
        data: { component: 'NewComponent' },
      });
      expect(mockQdrantClient.adrDecision.update).toHaveBeenNthCalledWith(2, {
        where: { id: decisionId },
        data: { status: 'accepted' },
      });
      expect(mockQdrantClient.adrDecision.update).toHaveBeenNthCalledWith(3, {
        where: { id: decisionId },
        data: {
          title: 'Final Title',
          rationale: 'Final rationale',
          alternativesConsidered: ['Final Alt 1', 'Final Alt 2'],
        },
      });
    });

    it('should handle decisions with no alternatives', async () => {
      // Arrange
      const decisionNoAlts = {
        component: 'SimpleService',
        status: 'accepted',
        title: 'Simple Decision',
        rationale: 'No alternatives needed',
        alternatives_considered: null as any,
      };
      const scope = { project: 'simple-test' };

      // Store
      const storedId = 'no-alts-decision';
      mockDb.create.mockResolvedValue({ id: storedId });
      const result = await storeDecision(decisionNoAlts, scope);

      // Update
      const updateData = { rationale: 'Updated rationale still no alternatives' };
      mockQdrantClient.adrDecision.update.mockResolvedValue({ id: storedId });
      await updateDecision(storedId, updateData);

      // Assert
      expect(result).toBe(storedId);
      expect(mockDb.create).toHaveBeenCalledWith('adr_decision',
        expect.objectContaining({
          alternatives_considered: [],
        }),
        undefined
      );
      expect(mockQdrantClient.adrDecision.update).toHaveBeenCalledWith({
        where: { id: storedId },
        data: { rationale: 'Updated rationale still no alternatives' },
      });
    });
  });
});