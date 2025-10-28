/**
 * Comprehensive Unit Tests for Observation Service
 *
 * Tests observation storage and retrieval functionality including:
 * - Adding observations to entities
 * - Soft delete operations
 * - Text-based search (FTS and LIKE)
 * - Entity observation retrieval
 * - Recent observations and activity feeds
 * - Observation counting
 * - Error handling and edge cases
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  addObservation,
  deleteObservation,
  deleteObservationsByText,
  getObservations,
  searchObservations,
  getObservationCount,
  getRecentObservations
} from '../../../src/services/knowledge/observation';

// Mock the UnifiedDatabaseLayer
const mockDb = {
  initialize: vi.fn().mockResolvedValue(undefined),
  create: vi.fn(),
  find: vi.fn(),
  update: vi.fn(),
  updateMany: vi.fn(),
  query: vi.fn(),
  fullTextSearch: vi.fn(),
};

// Mock the Qdrant client for raw SQL queries
const mockQdrant = {
  knowledgeObservation: {
    create: vi.fn(),
    updateMany: vi.fn(),
  },
  $queryRaw: vi.fn(),
};

// Create a proper mock constructor
const MockUnifiedDatabaseLayer = vi.fn().mockImplementation(() => mockDb);

vi.mock('../../../src/db/unified-database-layer-v2', () => ({
  UnifiedDatabaseLayer: MockUnifiedDatabaseLayer,
}));

vi.mock('../../../src/db/qdrant-client', () => ({
  getQdrantClient: vi.fn().mockReturnValue(mockQdrant),
}));

describe('Observation Service', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('addObservation', () => {
    const mockObservationData = {
      entity_type: 'component',
      entity_id: 'entity-uuid-123',
      observation: 'Service is responding slowly during peak hours',
      observation_type: 'performance',
      metadata: { response_time: '500ms', timestamp: '2023-10-28T14:00:00Z' },
    };

    it('should add observation successfully', async () => {
      // Arrange
      const expectedId = 'observation-uuid-123';
      mockQdrant.knowledgeObservation.create.mockResolvedValue({ id: expectedId });

      // Act
      const result = await addObservation(mockObservationData);

      // Assert
      expect(result).toBe(expectedId);
      expect(mockDb.initialize).toHaveBeenCalled();
      expect(mockQdrant.knowledgeObservation.create).toHaveBeenCalledWith({
        data: {
          entity_type: mockObservationData.entity_type,
          entity_id: mockObservationData.entity_id,
          observation: mockObservationData.observation,
          observation_type: mockObservationData.observation_type,
          metadata: mockObservationData.metadata,
          tags: {},
        },
      });
    });

    it('should add observation without optional fields', async () => {
      // Arrange
      const minimalObservationData = {
        entity_type: 'component',
        entity_id: 'entity-uuid-456',
        observation: 'Simple observation',
      };
      const expectedId = 'minimal-observation-uuid';
      mockQdrant.knowledgeObservation.create.mockResolvedValue({ id: expectedId });

      // Act
      const result = await addObservation(minimalObservationData);

      // Assert
      expect(result).toBe(expectedId);
      expect(mockQdrant.knowledgeObservation.create).toHaveBeenCalledWith({
        data: {
          entity_type: minimalObservationData.entity_type,
          entity_id: minimalObservationData.entity_id,
          observation: minimalObservationData.observation,
          observation_type: undefined,
          metadata: undefined,
          tags: {},
        },
      });
    });

    it('should handle database initialization errors', async () => {
      // Arrange
      mockDb.initialize.mockRejectedValue(new Error('Database connection failed'));

      // Act & Assert
      await expect(addObservation(mockObservationData)).rejects.toThrow(
        'Database connection failed'
      );
    });

    it('should handle database creation errors', async () => {
      // Arrange
      mockQdrant.knowledgeObservation.create.mockRejectedValue(new Error('Insert failed'));

      // Act & Assert
      await expect(addObservation(mockObservationData)).rejects.toThrow('Insert failed');
    });

    it('should handle observation with null observation_type', async () => {
      // Arrange
      const observationWithNullType = {
        ...mockObservationData,
        observation_type: null as any,
      };
      const expectedId = 'observation-null-type';
      mockQdrant.knowledgeObservation.create.mockResolvedValue({ id: expectedId });

      // Act
      const result = await addObservation(observationWithNullType);

      // Assert
      expect(result).toBe(expectedId);
      expect(mockQdrant.knowledgeObservation.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          observation_type: undefined,
        }),
      });
    });

    it('should handle observation with empty metadata', async () => {
      // Arrange
      const observationWithEmptyMetadata = {
        ...mockObservationData,
        metadata: {} as any,
      };
      const expectedId = 'observation-empty-metadata';
      mockQdrant.knowledgeObservation.create.mockResolvedValue({ id: expectedId });

      // Act
      const result = await addObservation(observationWithEmptyMetadata);

      // Assert
      expect(result).toBe(expectedId);
    });

    it('should handle unicode content in observation', async () => {
      // Arrange
      const unicodeObservation = {
        entity_type: 'component',
        entity_id: 'unicode-entity',
        observation: 'Observación con ñoño and العربية and 中文 characters 🧠',
        observation_type: 'internationalización',
        metadata: { locale: 'es-ES' },
      };
      const expectedId = 'unicode-observation';
      mockQdrant.knowledgeObservation.create.mockResolvedValue({ id: expectedId });

      // Act
      const result = await addObservation(unicodeObservation);

      // Assert
      expect(result).toBe(expectedId);
      expect(mockQdrant.knowledgeObservation.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          observation: 'Observación con ñoño and العربية and 中文 characters 🧠',
        }),
      });
    });

    it('should handle very long observation text', async () => {
      // Arrange
      const longObservationText = 'This is a very long observation. '.repeat(1000);
      const longObservation = {
        ...mockObservationData,
        observation: longObservationText,
      };
      const expectedId = 'long-observation';
      mockQdrant.knowledgeObservation.create.mockResolvedValue({ id: expectedId });

      // Act
      const result = await addObservation(longObservation);

      // Assert
      expect(result).toBe(expectedId);
    });

    it('should validate required entity_type field', async () => {
      // Arrange
      const invalidObservation = {
        entity_id: 'entity-123',
        observation: 'Missing entity_type',
      };

      // Act & Assert
      await expect(addObservation(invalidObservation as any)).rejects.toThrow();
    });

    it('should validate required entity_id field', async () => {
      // Arrange
      const invalidObservation = {
        entity_type: 'component',
        observation: 'Missing entity_id',
      };

      // Act & Assert
      await expect(addObservation(invalidObservation as any)).rejects.toThrow();
    });

    it('should validate required observation field', async () => {
      // Arrange
      const invalidObservation = {
        entity_type: 'component',
        entity_id: 'entity-123',
      };

      // Act & Assert
      await expect(addObservation(invalidObservation as any)).rejects.toThrow();
    });

    it('should handle complex nested metadata', async () => {
      // Arrange
      const complexMetadata = {
        performance: {
          response_time: '500ms',
          memory_usage: '256MB',
          cpu_usage: '75%',
        },
        context: {
          request_id: 'req-123',
          user_id: 'user-456',
          session_id: 'sess-789',
        },
        tags: ['performance', 'slow-response', 'peak-hours'],
      };
      const observationWithComplexMetadata = {
        ...mockObservationData,
        metadata: complexMetadata,
      };
      const expectedId = 'complex-metadata-observation';
      mockQdrant.knowledgeObservation.create.mockResolvedValue({ id: expectedId });

      // Act
      const result = await addObservation(observationWithComplexMetadata);

      // Assert
      expect(result).toBe(expectedId);
      expect(mockQdrant.knowledgeObservation.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          metadata: complexMetadata,
        }),
      });
    });
  });

  describe('deleteObservation', () => {
    const observationId = 'observation-to-delete';

    it('should soft delete observation successfully', async () => {
      // Arrange
      mockQdrant.knowledgeObservation.updateMany.mockResolvedValue({ count: 1 });

      // Act
      const result = await deleteObservation(observationId);

      // Assert
      expect(result).toBe(true);
      expect(mockDb.initialize).toHaveBeenCalled();
      expect(mockQdrant.knowledgeObservation.updateMany).toHaveBeenCalledWith({
        where: {
          id: observationId,
          deleted_at: null,
        },
        data: {
          deleted_at: expect.any(Date),
        },
      });
    });

    it('should return false when observation not found', async () => {
      // Arrange
      mockQdrant.knowledgeObservation.updateMany.mockResolvedValue({ count: 0 });

      // Act
      const result = await deleteObservation(observationId);

      // Assert
      expect(result).toBe(false);
    });

    it('should handle database initialization errors', async () => {
      // Arrange
      mockDb.initialize.mockRejectedValue(new Error('Database connection failed'));

      // Act & Assert
      await expect(deleteObservation(observationId)).rejects.toThrow(
        'Database connection failed'
      );
    });

    it('should handle database deletion errors', async () => {
      // Arrange
      mockQdrant.knowledgeObservation.updateMany.mockRejectedValue(new Error('Delete failed'));

      // Act & Assert
      await expect(deleteObservation(observationId)).rejects.toThrow('Delete failed');
    });

    it('should handle empty observation ID', async () => {
      // Act & Assert
      await expect(deleteObservation('')).rejects.toThrow();
      await expect(deleteObservation(null as any)).rejects.toThrow();
      await expect(deleteObservation(undefined as any)).rejects.toThrow();
    });

    it('should handle invalid UUID format', async () => {
      // Arrange
      const invalidId = 'not-a-uuid';
      mockQdrant.knowledgeObservation.updateMany.mockRejectedValue(new Error('Invalid UUID'));

      // Act & Assert
      await expect(deleteObservation(invalidId)).rejects.toThrow('Invalid UUID');
    });
  });

  describe('deleteObservationsByText', () => {
    const entityType = 'component';
    const entityId = 'entity-uuid-123';
    const observationText = 'Service is responding slowly';

    it('should delete observations by exact text match successfully', async () => {
      // Arrange
      const deletedCount = 3;
      mockQdrant.knowledgeObservation.updateMany.mockResolvedValue({ count: deletedCount });

      // Act
      const result = await deleteObservationsByText(entityType, entityId, observationText);

      // Assert
      expect(result).toBe(deletedCount);
      expect(mockDb.initialize).toHaveBeenCalled();
      expect(mockQdrant.knowledgeObservation.updateMany).toHaveBeenCalledWith({
        where: {
          entity_type: entityType,
          entity_id: entityId,
          observation: observationText,
          deleted_at: null,
        },
        data: {
          deleted_at: expect.any(Date),
        },
      });
    });

    it('should return 0 when no matching observations found', async () => {
      // Arrange
      mockQdrant.knowledgeObservation.updateMany.mockResolvedValue({ count: 0 });

      // Act
      const result = await deleteObservationsByText(entityType, entityId, 'Non-matching observation');

      // Assert
      expect(result).toBe(0);
    });

    it('should handle database errors', async () => {
      // Arrange
      mockQdrant.knowledgeObservation.updateMany.mockRejectedValue(new Error('Database error'));

      // Act & Assert
      await expect(deleteObservationsByText(entityType, entityId, observationText)).rejects.toThrow(
        'Database error'
      );
    });

    it('should handle empty observation text', async () => {
      // Arrange
      mockQdrant.knowledgeObservation.updateMany.mockResolvedValue({ count: 0 });

      // Act
      const result = await deleteObservationsByText(entityType, entityId, '');

      // Assert
      expect(result).toBe(0);
      expect(mockQdrant.knowledgeObservation.updateMany).toHaveBeenCalledWith({
        where: {
          entity_type: entityType,
          entity_id: entityId,
          observation: '',
          deleted_at: null,
        },
        data: {
          deleted_at: expect.any(Date),
        },
      });
    });

    it('should handle unicode observation text', async () => {
      // Arrange
      const unicodeText = 'Observación con caracteres especiales: ñoño, 中文, العربية';
      mockQdrant.knowledgeObservation.updateMany.mockResolvedValue({ count: 1 });

      // Act
      const result = await deleteObservationsByText(entityType, entityId, unicodeText);

      // Assert
      expect(result).toBe(1);
      expect(mockQdrant.knowledgeObservation.updateMany).toHaveBeenCalledWith({
        where: {
          entity_type: entityType,
          entity_id: entityId,
          observation: unicodeText,
          deleted_at: null,
        },
        data: {
          deleted_at: expect.any(Date),
        },
      });
    });

    it('should handle very long observation text', async () => {
      // Arrange
      const longText = 'This is a very long observation text. '.repeat(1000);
      mockQdrant.knowledgeObservation.updateMany.mockResolvedValue({ count: 1 });

      // Act
      const result = await deleteObservationsByText(entityType, entityId, longText);

      // Assert
      expect(result).toBe(1);
    });

    it('should handle special characters in observation text', async () => {
      // Arrange
      const specialText = 'Observation with "quotes" & <angles> and {brackets}';
      mockQdrant.knowledgeObservation.updateMany.mockResolvedValue({ count: 1 });

      // Act
      const result = await deleteObservationsByText(entityType, entityId, specialText);

      // Assert
      expect(result).toBe(1);
    });
  });

  describe('getObservations', () => {
    const entityType = 'component';
    const entityId = 'entity-uuid-123';

    it('should get observations for entity successfully', async () => {
      // Arrange
      const mockObservations = [
        {
          id: 'obs-1',
          observation: 'First observation',
          observation_type: 'info',
          metadata: { source: 'system' },
          created_at: new Date('2023-10-28T14:00:00Z'),
        },
        {
          id: 'obs-2',
          observation: 'Second observation',
          observation_type: 'warning',
          metadata: { source: 'user' },
          created_at: new Date('2023-10-28T13:00:00Z'),
        },
      ];
      mockDb.find.mockResolvedValue(mockObservations);

      // Act
      const result = await getObservations(entityType, entityId);

      // Assert
      expect(result).toHaveLength(2);
      expect(result[0]).toEqual({
        id: 'obs-1',
        observation: 'First observation',
        observation_type: 'info',
        metadata: { source: 'system' },
        created_at: mockObservations[0].created_at,
      });
      expect(mockDb.find).toHaveBeenCalledWith('knowledgeObservation', {
        where: {
          entity_type: entityType,
          entity_id: entityId,
          deleted_at: null,
        },
        orderBy: { created_at: 'desc' },
        select: {
          id: true,
          observation: true,
          observation_type: true,
          metadata: true,
          created_at: true,
        },
      });
    });

    it('should get observations filtered by type', async () => {
      // Arrange
      const mockObservations = [
        {
          id: 'obs-1',
          observation: 'Performance observation',
          observation_type: 'performance',
          metadata: { response_time: '500ms' },
          created_at: new Date('2023-10-28T14:00:00Z'),
        },
      ];
      mockDb.find.mockResolvedValue(mockObservations);

      // Act
      const result = await getObservations(entityType, entityId, 'performance');

      // Assert
      expect(result).toHaveLength(1);
      expect(mockDb.find).toHaveBeenCalledWith('knowledgeObservation', {
        where: {
          entity_type: entityType,
          entity_id: entityId,
          deleted_at: null,
          observation_type: 'performance',
        },
        orderBy: { created_at: 'desc' },
        select: {
          id: true,
          observation: true,
          observation_type: true,
          metadata: true,
          created_at: true,
        },
      });
    });

    it('should return empty array when no observations found', async () => {
      // Arrange
      mockDb.find.mockResolvedValue([]);

      // Act
      const result = await getObservations(entityType, entityId);

      // Assert
      expect(result).toHaveLength(0);
    });

    it('should handle database errors', async () => {
      // Arrange
      mockDb.find.mockRejectedValue(new Error('Database query failed'));

      // Act & Assert
      await expect(getObservations(entityType, entityId)).rejects.toThrow('Database query failed');
    });

    it('should handle observations with null metadata', async () => {
      // Arrange
      const mockObservations = [
        {
          id: 'obs-1',
          observation: 'Observation without metadata',
          observation_type: null,
          metadata: null,
          created_at: new Date('2023-10-28T14:00:00Z'),
        },
      ];
      mockDb.find.mockResolvedValue(mockObservations);

      // Act
      const result = await getObservations(entityType, entityId);

      // Assert
      expect(result).toHaveLength(1);
      expect(result[0].metadata).toBeNull();
      expect(result[0].observation_type).toBeNull();
    });

    it('should handle empty entity type', async () => {
      // Arrange
      mockDb.find.mockResolvedValue([]);

      // Act
      const result = await getObservations('', entityId);

      // Assert
      expect(result).toHaveLength(0);
    });

    it('should handle empty entity ID', async () => {
      // Arrange
      mockDb.find.mockResolvedValue([]);

      // Act
      const result = await getObservations(entityType, '');

      // Assert
      expect(result).toHaveLength(0);
    });

    it('should handle malformed observation data', async () => {
      // Arrange
      const malformedObservations = [
        {
          id: 'obs-1',
          observation: 'Valid observation',
          observation_type: 'info',
          metadata: { valid: true },
          created_at: new Date('2023-10-28T14:00:00Z'),
        },
        {
          id: 'obs-2',
          // Missing required fields
          observation: null,
          observation_type: undefined,
          metadata: 'not an object',
          created_at: 'invalid-date',
        },
      ];
      mockDb.find.mockResolvedValue(malformedObservations);

      // Act
      const result = await getObservations(entityType, entityId);

      // Assert - Should handle gracefully without crashing
      expect(result).toHaveLength(2);
      expect(result[1].observation).toBeNull();
      expect(result[1].metadata).toBe('not an object');
    });
  });

  describe('searchObservations', () => {
    const searchQuery = 'slow performance';

    it('should search observations using FTS for multi-word queries', async () => {
      // Arrange
      const mockResults = [
        {
          id: 'obs-1',
          entity_type: 'component',
          entity_id: 'entity-1',
          observation: 'Service showing slow performance during peak hours',
          observation_type: 'performance',
          metadata: { response_time: '500ms' },
          created_at: new Date('2023-10-28T14:00:00Z'),
        },
      ];
      mockQdrant.$queryRaw.mockResolvedValue([mockResults]);

      // Act
      const result = await searchObservations(searchQuery);

      // Assert
      expect(result).toHaveLength(1);
      expect(result[0]).toEqual({
        id: 'obs-1',
        entity_type: 'component',
        entity_id: 'entity-1',
        observation: 'Service showing slow performance during peak hours',
        observation_type: 'performance',
        metadata: { response_time: '500ms' },
        created_at: mockResults[0].created_at,
      });
      expect(mockQdrant.$queryRaw).toHaveBeenCalledWith(
        expect.stringContaining('to_tsvector') &&
        expect.stringContaining('plainto_tsquery') &&
        expect.stringContaining('slow') &&
        expect.stringContaining('performance')
      );
    });

    it('should search observations using LIKE for single-word queries', async () => {
      // Arrange
      const singleWordQuery = 'slow';
      const mockResults = [
        {
          id: 'obs-1',
          entity_type: 'component',
          entity_id: 'entity-1',
          observation: 'Service running slow',
          observation_type: 'performance',
          metadata: null,
          created_at: new Date('2023-10-28T14:00:00Z'),
        },
      ];
      mockQdrant.$queryRaw.mockResolvedValue([mockResults]);

      // Act
      const result = await searchObservations(singleWordQuery);

      // Assert
      expect(result).toHaveLength(1);
      expect(mockQdrant.$queryRaw).toHaveBeenCalledWith(
        expect.stringContaining('ILIKE') &&
        expect.stringContaining('%slow%')
      );
    });

    it('should search observations with entity type filter', async () => {
      // Arrange
      const entityTypeFilter = 'component';
      const mockResults = [
        {
          id: 'obs-1',
          entity_type: entityTypeFilter,
          entity_id: 'entity-1',
          observation: 'Component performance issue',
          observation_type: 'performance',
          metadata: null,
          created_at: new Date('2023-10-28T14:00:00Z'),
        },
      ];
      mockQdrant.$queryRaw.mockResolvedValue([mockResults]);

      // Act
      const result = await searchObservations(searchQuery, entityTypeFilter);

      // Assert
      expect(result).toHaveLength(1);
      expect(mockQdrant.$queryRaw).toHaveBeenCalledWith(
        expect.stringContaining('entity_type = ') &&
        expect.stringContaining(entityTypeFilter)
      );
    });

    it('should handle empty search query', async () => {
      // Arrange
      mockQdrant.$queryRaw.mockResolvedValue([]);

      // Act
      const result = await searchObservations('');

      // Assert
      expect(result).toHaveLength(0);
    });

    it('should handle custom limit', async () => {
      // Arrange
      const customLimit = 10;
      mockQdrant.$queryRaw.mockResolvedValue([]);

      // Act
      await searchObservations(searchQuery, undefined, customLimit);

      // Assert
      expect(mockQdrant.$queryRaw).toHaveBeenCalledWith(
        expect.stringContaining(`LIMIT ${customLimit}`)
      );
    });

    it('should handle database errors during FTS search', async () => {
      // Arrange
      mockQdrant.$queryRaw.mockRejectedValue(new Error('FTS search failed'));

      // Act & Assert
      await expect(searchObservations('multi word query')).rejects.toThrow('FTS search failed');
    });

    it('should handle database errors during LIKE search', async () => {
      // Arrange
      mockQdrant.$queryRaw.mockRejectedValue(new Error('LIKE search failed'));

      // Act & Assert
      await expect(searchObservations('single')).rejects.toThrow('LIKE search failed');
    });

    it('should handle special characters in search query', async () => {
      // Arrange
      const specialQuery = 'search & (test) | "phrase"';
      mockQdrant.$queryRaw.mockResolvedValue([]);

      // Act
      await searchObservations(specialQuery);

      // Assert - Should escape special characters properly for FTS
      expect(mockQdrant.$queryRaw).toHaveBeenCalledWith(
        expect.stringContaining('to_tsvector')
      );
    });

    it('should handle unicode search queries', async () => {
      // Arrange
      const unicodeQuery = 'búsqueda 中文';
      mockQdrant.$queryRaw.mockResolvedValue([]);

      // Act
      await searchObservations(unicodeQuery);

      // Assert
      expect(mockQdrant.$queryRaw).toHaveBeenCalled();
    });

    it('should handle empty results from nested array structure', async () => {
      // Arrange
      mockQdrant.$queryRaw.mockResolvedValue([[]]); // Nested empty array

      // Act
      const result = await searchObservations('single word query');

      // Assert
      expect(result).toHaveLength(0);
    });

    it('should handle malformed database results', async () => {
      // Arrange
      const malformedResults = [
        {
          id: 'obs-1',
          entity_type: 'component',
          entity_id: 'entity-1',
          observation: 'Valid observation',
          observation_type: 'info',
          metadata: { valid: true },
          created_at: new Date('2023-10-28T14:00:00Z'),
        },
        {
          // Missing required fields
          id: 'obs-2',
          entity_type: null,
          entity_id: undefined,
          observation: '',
          observation_type: '',
          metadata: '',
          created_at: '',
        },
      ];
      mockQdrant.$queryRaw.mockResolvedValue([malformedResults]);

      // Act
      const result = await searchObservations('query');

      // Assert - Should handle gracefully
      expect(result).toHaveLength(2);
    });
  });

  describe('getObservationCount', () => {
    const entityType = 'component';
    const entityId = 'entity-uuid-123';

    it('should get observation count successfully', async () => {
      // Arrange
      const mockCount = 5;
      mockQdrant.$queryRaw.mockResolvedValue([{ count: BigInt(mockCount) }]);

      // Act
      const result = await getObservationCount(entityType, entityId);

      // Assert
      expect(result).toBe(mockCount);
      expect(mockDb.initialize).toHaveBeenCalled();
      expect(mockQdrant.$queryRaw).toHaveBeenCalledWith(
        expect.stringContaining('SELECT COUNT(*) as count') &&
        expect.stringContaining('FROM knowledge_observation') &&
        expect.stringContaining(`entity_type = ${entityType}`) &&
        expect.stringContaining(`entity_id = ${entityId}`) &&
        expect.stringContaining('deleted_at IS NULL')
      );
    });

    it('should return 0 when no observations found', async () => {
      // Arrange
      mockQdrant.$queryRaw.mockResolvedValue([{ count: BigInt(0) }]);

      // Act
      const result = await getObservationCount(entityType, entityId);

      // Assert
      expect(result).toBe(0);
    });

    it('should handle empty query results', async () => {
      // Arrange
      mockQdrant.$queryRaw.mockResolvedValue([]);

      // Act
      const result = await getObservationCount(entityType, entityId);

      // Assert
      expect(result).toBe(0);
    });

    it('should handle database errors', async () => {
      // Arrange
      mockQdrant.$queryRaw.mockRejectedValue(new Error('Count query failed'));

      // Act & Assert
      await expect(getObservationCount(entityType, entityId)).rejects.toThrow('Count query failed');
    });

    it('should handle large counts', async () => {
      // Arrange
      const largeCount = 1000000;
      mockQdrant.$queryRaw.mockResolvedValue([{ count: BigInt(largeCount) }]);

      // Act
      const result = await getObservationCount(entityType, entityId);

      // Assert
      expect(result).toBe(largeCount);
    });

    it('should handle empty entity type', async () => {
      // Arrange
      mockQdrant.$queryRaw.mockResolvedValue([{ count: BigInt(0) }]);

      // Act
      const result = await getObservationCount('', entityId);

      // Assert
      expect(result).toBe(0);
    });

    it('should handle empty entity ID', async () => {
      // Arrange
      mockQdrant.$queryRaw.mockResolvedValue([{ count: BigInt(0) }]);

      // Act
      const result = await getObservationCount(entityType, '');

      // Assert
      expect(result).toBe(0);
    });
  });

  describe('getRecentObservations', () => {
    it('should get recent observations without entity type filter', async () => {
      // Arrange
      const mockObservations = [
        {
          id: 'obs-1',
          entity_type: 'component',
          entity_id: 'entity-1',
          observation: 'Recent observation 1',
          observation_type: 'info',
          metadata: null,
          created_at: new Date('2023-10-28T14:00:00Z'),
        },
        {
          id: 'obs-2',
          entity_type: 'service',
          entity_id: 'entity-2',
          observation: 'Recent observation 2',
          observation_type: 'warning',
          metadata: { source: 'monitor' },
          created_at: new Date('2023-10-28T13:00:00Z'),
        },
      ];
      mockQdrant.$queryRaw.mockResolvedValue([mockObservations]);

      // Act
      const result = await getRecentObservations();

      // Assert
      expect(result).toHaveLength(2);
      expect(result[0]).toEqual({
        id: 'obs-1',
        entity_type: 'component',
        entity_id: 'entity-1',
        observation: 'Recent observation 1',
        observation_type: 'info',
        metadata: null,
        created_at: mockObservations[0].created_at,
      });
      expect(mockQdrant.$queryRaw).toHaveBeenCalledWith(
        expect.stringContaining('SELECT id, entity_type, entity_id') &&
        expect.stringContaining('FROM knowledge_observation') &&
        expect.stringContaining('WHERE deleted_at IS NULL') &&
        expect.stringContaining('ORDER BY created_at DESC LIMIT 50')
      );
    });

    it('should get recent observations with entity type filter', async () => {
      // Arrange
      const entityTypeFilter = 'component';
      const mockObservations = [
        {
          id: 'obs-1',
          entity_type: entityTypeFilter,
          entity_id: 'entity-1',
          observation: 'Recent component observation',
          observation_type: 'performance',
          metadata: { response_time: '300ms' },
          created_at: new Date('2023-10-28T14:00:00Z'),
        },
      ];
      mockQdrant.$queryRaw.mockResolvedValue([mockObservations]);

      // Act
      const result = await getRecentObservations(25, entityTypeFilter);

      // Assert
      expect(result).toHaveLength(1);
      expect(mockQdrant.$queryRaw).toHaveBeenCalledWith(
        expect.stringContaining('entity_type = component') &&
        expect.stringContaining('LIMIT 25')
      );
    });

    it('should handle custom limit', async () => {
      // Arrange
      const customLimit = 10;
      mockQdrant.$queryRaw.mockResolvedValue([]);

      // Act
      await getRecentObservations(customLimit);

      // Assert
      expect(mockQdrant.$queryRaw).toHaveBeenCalledWith(
        expect.stringContaining(`LIMIT ${customLimit}`)
      );
    });

    it('should handle empty results', async () => {
      // Arrange
      mockQdrant.$queryRaw.mockResolvedValue([[]]);

      // Act
      const result = await getRecentObservations();

      // Assert
      expect(result).toHaveLength(0);
    });

    it('should handle database errors', async () => {
      // Arrange
      mockQdrant.$queryRaw.mockRejectedValue(new Error('Recent observations query failed'));

      // Act & Assert
      await expect(getRecentObservations()).rejects.toThrow('Recent observations query failed');
    });

    it('should handle very large limit', async () => {
      // Arrange
      const largeLimit = 1000;
      mockQdrant.$queryRaw.mockResolvedValue([]);

      // Act
      await getRecentObservations(largeLimit);

      // Assert
      expect(mockQdrant.$queryRaw).toHaveBeenCalledWith(
        expect.stringContaining(`LIMIT ${largeLimit}`)
      );
    });

    it('should handle limit of 0', async () => {
      // Arrange
      mockQdrant.$queryRaw.mockResolvedValue([]);

      // Act
      const result = await getRecentObservations(0);

      // Assert
      expect(result).toHaveLength(0);
    });

    it('should handle malformed observation data in results', async () => {
      // Arrange
      const malformedObservations = [
        {
          id: 'obs-1',
          entity_type: 'component',
          entity_id: 'entity-1',
          observation: 'Valid observation',
          observation_type: 'info',
          metadata: { valid: true },
          created_at: new Date('2023-10-28T14:00:00Z'),
        },
        {
          id: 'obs-2',
          entity_type: null,
          entity_id: undefined,
          observation: '',
          observation_type: '',
          metadata: '',
          created_at: 'invalid-date',
        },
      ];
      mockQdrant.$queryRaw.mockResolvedValue([malformedObservations]);

      // Act
      const result = await getRecentObservations();

      // Assert - Should handle gracefully
      expect(result).toHaveLength(2);
    });
  });

  describe('Integration Tests', () => {
    it('should handle complete observation lifecycle', async () => {
      // Arrange
      const observationData = {
        entity_type: 'component',
        entity_id: 'lifecycle-entity',
        observation: 'Test observation for lifecycle',
        observation_type: 'test',
        metadata: { test: true },
      };

      // Add observation
      const observationId = 'lifecycle-obs-1';
      mockQdrant.knowledgeObservation.create.mockResolvedValue({ id: observationId });
      const addResult = await addObservation(observationData);

      // Get observations
      const mockObservations = [
        {
          id: observationId,
          observation: observationData.observation,
          observation_type: observationData.observation_type,
          metadata: observationData.metadata,
          created_at: new Date('2023-10-28T14:00:00Z'),
        },
      ];
      mockDb.find.mockResolvedValue(mockObservations);
      const getResults = await getObservations(observationData.entity_type, observationData.entity_id);

      // Search observations
      mockQdrant.$queryRaw.mockResolvedValue([mockObservations]);
      const searchResults = await searchObservations('lifecycle');

      // Get count
      mockQdrant.$queryRaw.mockResolvedValue([{ count: BigInt(1) }]);
      const count = await getObservationCount(observationData.entity_type, observationData.entity_id);

      // Delete observation
      mockQdrant.knowledgeObservation.updateMany.mockResolvedValue({ count: 1 });
      const deleted = await deleteObservation(observationId);

      // Assert
      expect(addResult).toBe(observationId);
      expect(getResults).toHaveLength(1);
      expect(searchResults).toHaveLength(1);
      expect(count).toBe(1);
      expect(deleted).toBe(true);
    });

    it('should handle multiple observations for same entity', async () => {
      // Arrange
      const entityType = 'component';
      const entityId = 'multi-obs-entity';
      const observations = [
        { observation: 'First observation', type: 'info' },
        { observation: 'Second observation', type: 'warning' },
        { observation: 'Third observation', type: 'error' },
      ];

      // Add multiple observations
      for (let i = 0; i < observations.length; i++) {
        mockQdrant.knowledgeObservation.create.mockResolvedValue({ id: `obs-${i}` });
        await addObservation({
          entity_type: entityType,
          entity_id: entityId,
          observation: observations[i].observation,
          observation_type: observations[i].type,
        });
      }

      // Get all observations
      const mockObservations = observations.map((obs, index) => ({
        id: `obs-${index}`,
        observation: obs.observation,
        observation_type: obs.type,
        metadata: null,
        created_at: new Date(`2023-10-28T${14 - index}:00:00Z`),
      }));
      mockDb.find.mockResolvedValue(mockObservations);

      // Act
      const results = await getObservations(entityType, entityId);

      // Assert
      expect(results).toHaveLength(3);
      expect(results[0].observation).toBe('First observation'); // Most recent first
      expect(results[2].observation).toBe('Third observation');
    });

    it('should handle observation search with mixed FTS and LIKE queries', async () => {
      // Arrange
      const multiWordQuery = 'performance issue';
      const singleWordQuery = 'slow';

      // Multi-word should use FTS
      mockQdrant.$queryRaw.mockResolvedValue([]);
      await searchObservations(multiWordQuery);

      const ftsCall = mockQdrant.$queryRaw.mock.calls[0][0];
      expect(ftsCall).toContain('to_tsvector');

      // Single-word should use LIKE
      mockQdrant.$queryRaw.mockClear();
      mockQdrant.$queryRaw.mockResolvedValue([]);
      await searchObservations(singleWordQuery);

      const likeCall = mockQdrant.$queryRaw.mock.calls[0][0];
      expect(likeCall).toContain('ILIKE');
    });

    it('should handle text-based deletion for multiple matching observations', async () => {
      // Arrange
      const entityType = 'service';
      const entityId = 'text-delete-entity';
      const observationText = 'Repeated error message';
      const deletedCount = 3;

      mockQdrant.knowledgeObservation.updateMany.mockResolvedValue({ count: deletedCount });

      // Act
      const result = await deleteObservationsByText(entityType, entityId, observationText);

      // Assert
      expect(result).toBe(deletedCount);
      expect(mockQdrant.knowledgeObservation.updateMany).toHaveBeenCalledWith({
        where: {
          entity_type: entityType,
          entity_id: entityId,
          observation: observationText,
          deleted_at: null,
        },
        data: {
          deleted_at: expect.any(Date),
        },
      });
    });
  });
});