/**
 * Comprehensive Unit Tests for Delete Operations Service
 *
 * Tests delete operations functionality including:
 * - Soft delete for graph entities
 * - Hard delete for typed knowledge types
 * - Cascade delete for relations
 * - Immutability constraints
 * - Bulk operations
 * - Error handling and validation
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// Mock the dependencies
vi.mock('../../src/utils/logger.js', () => ({
  logger: {
    debug: vi.fn(),
    error: vi.fn(),
    warn: vi.fn(),
  },
}));

vi.mock('../../src/db/unified-database-layer.js', () => ({
  UnifiedDatabaseLayer: vi.fn().mockImplementation(() => mockUnifiedDatabaseLayer),
}));

vi.mock('../../src/services/knowledge/entity.js', () => ({
  softDeleteEntity: vi.fn(),
}));

vi.mock('../../src/services/knowledge/relation.js', () => ({
  softDeleteRelation: vi.fn(),
}));

vi.mock('../../src/services/knowledge/observation.js', () => ({
  deleteObservation: vi.fn(),
}));

// Mock UnifiedDatabaseLayer
const mockUnifiedDatabaseLayer = {
  initialize: vi.fn().mockResolvedValue(undefined),
  create: vi.fn(),
  find: vi.fn(),
  findUnique: vi.fn(),
  update: vi.fn(),
  delete: vi.fn(),
  query: vi.fn(),
};

import type { DeleteRequest, DeleteResult } from '../../src/services/delete-operations';

describe('Delete Operations Service', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.resetAllMocks();

    // Default successful mocks
    const { softDeleteEntity, softDeleteRelation, deleteObservation } = require('../../src/services/knowledge/entity.js');
    softDeleteEntity.mockResolvedValue(true);
    softDeleteRelation.mockResolvedValue(true);
    deleteObservation.mockResolvedValue(true);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('softDelete', () => {
    describe('Graph Extension Types', () => {
      it('should soft delete entity successfully', async () => {
        const { softDelete } = await import('../../src/services/delete-operations.js');
        const { softDeleteEntity } = require('../../src/services/knowledge/entity.js');

        const request: DeleteRequest = {
          entity_type: 'entity',
          entity_id: '123e4567-e89b-12d3-a456-426614174000',
        };

        softDeleteEntity.mockResolvedValue(true);

        const result = await softDelete(request);

        expect(softDeleteEntity).toHaveBeenCalledWith(request.entity_id);
        expect(result).toEqual({
          id: request.entity_id,
          entity_type: 'entity',
          status: 'deleted',
          cascaded_relations: 0,
        });
      });

      it('should handle entity not found', async () => {
        const { softDelete } = await import('../../src/services/delete-operations.js');
        const { softDeleteEntity } = require('../../src/services/knowledge/entity.js');

        const request: DeleteRequest = {
          entity_type: 'entity',
          entity_id: '123e4567-e89b-12d3-a456-426614174000',
        };

        softDeleteEntity.mockResolvedValue(false);

        const result = await softDelete(request);

        expect(result).toEqual({
          id: request.entity_id,
          entity_type: 'entity',
          status: 'not_found',
          message: 'Entity not found or already deleted',
        });
      });

      it('should soft delete relation successfully', async () => {
        const { softDelete } = await import('../../src/services/delete-operations.js');
        const { softDeleteRelation } = require('../../src/services/knowledge/relation.js');

        const request: DeleteRequest = {
          entity_type: 'relation',
          entity_id: '123e4567-e89b-12d3-a456-426614174000',
        };

        softDeleteRelation.mockResolvedValue(true);

        const result = await softDelete(request);

        expect(softDeleteRelation).toHaveBeenCalledWith(request.entity_id);
        expect(result).toEqual({
          id: request.entity_id,
          entity_type: 'relation',
          status: 'deleted',
        });
      });

      it('should delete observation successfully', async () => {
        const { softDelete } = await import('../../src/services/delete-operations.js');
        const { deleteObservation } = require('../../src/services/knowledge/observation.js');

        const request: DeleteRequest = {
          entity_type: 'observation',
          entity_id: '123e4567-e89b-12d3-a456-426614174000',
        };

        deleteObservation.mockResolvedValue(true);

        const result = await softDelete(request);

        expect(deleteObservation).toHaveBeenCalledWith(request.entity_id);
        expect(result).toEqual({
          id: request.entity_id,
          entity_type: 'observation',
          status: 'deleted',
        });
      });

      it('should cascade delete relations when requested for entity', async () => {
        const { softDelete } = await import('../../src/services/delete-operations.js');
        const { softDeleteEntity } = require('../../src/services/knowledge/entity.js');

        const request: DeleteRequest = {
          entity_type: 'entity',
          entity_id: '123e4567-e89b-12d3-a456-426614174000',
          cascade_relations: true,
        };

        softDeleteEntity.mockResolvedValue(true);
        mockPrismaClient.knowledgeRelation.updateMany.mockResolvedValue({ count: 3 });

        const result = await softDelete(request);

        expect(result.cascaded_relations).toBe(3);
        expect(mockPrismaClient.knowledgeRelation.updateMany).toHaveBeenCalledWith({
          where: {
            AND: [
              {
                OR: [
                  {
                    from_entity_type: 'entity',
                    from_entity_id: request.entity_id,
                  },
                  {
                    to_entity_type: 'entity',
                    to_entity_id: request.entity_id,
                  },
                ],
              },
              {
                deleted_at: null,
              },
            ],
          },
          data: {
            deleted_at: expect.any(Date),
          },
        });
      });
    });

    describe('Typed Knowledge Types', () => {
      it('should delete section successfully', async () => {
        const { softDelete } = await import('../../src/services/delete-operations.js');

        const request: DeleteRequest = {
          entity_type: 'section',
          entity_id: '123e4567-e89b-12d3-a456-426614174000',
        };

        mockPrismaClient.section.findUnique.mockResolvedValue({ id: request.entity_id });
        mockPrismaClient.section.delete.mockResolvedValue({ id: request.entity_id });

        const result = await softDelete(request);

        expect(mockPrismaClient.section.findUnique).toHaveBeenCalledWith({
          where: { id: request.entity_id },
          select: { id: true },
        });
        expect(mockPrismaClient.section.delete).toHaveBeenCalledWith({
          where: { id: request.entity_id },
        });
        expect(result).toEqual({
          id: request.entity_id,
          entity_type: 'section',
          status: 'deleted',
          cascaded_relations: 0,
        });
      });

      it('should handle decision immutability constraint', async () => {
        const { softDelete } = await import('../../src/services/delete-operations.js');

        const request: DeleteRequest = {
          entity_type: 'decision',
          entity_id: '123e4567-e89b-12d3-a456-426614174000',
        };

        // Mock accepted decision
        mockPrismaClient.adrDecision.findUnique.mockResolvedValue({
          id: request.entity_id,
          status: 'accepted',
        });

        const result = await softDelete(request);

        expect(result).toEqual({
          id: request.entity_id,
          entity_type: 'decision',
          status: 'immutable',
          message: 'Cannot delete accepted ADR (immutability constraint)',
        });

        // Should not attempt deletion
        expect(mockPrismaClient.adrDecision.delete).not.toHaveBeenCalled();
      });

      it('should allow deletion of non-accepted decisions', async () => {
        const { softDelete } = await import('../../src/services/delete-operations.js');

        const request: DeleteRequest = {
          entity_type: 'decision',
          entity_id: '123e4567-e89b-12d3-a456-426614174000',
        };

        // Mock draft decision
        mockPrismaClient.adrDecision.findUnique
          .mockResolvedValueOnce({ id: request.entity_id, status: 'draft' }) // For immutability check
          .mockResolvedValueOnce({ id: request.entity_id }); // For existence check
        mockPrismaClient.adrDecision.delete.mockResolvedValue({ id: request.entity_id });

        const result = await softDelete(request);

        expect(result.status).toBe('deleted');
        expect(mockPrismaClient.adrDecision.delete).toHaveBeenCalledWith({
          where: { id: request.entity_id },
        });
      });

      it('should handle entity not found for typed knowledge types', async () => {
        const { softDelete } = await import('../../src/services/delete-operations.js');

        const request: DeleteRequest = {
          entity_type: 'section',
          entity_id: '123e4567-e89b-12d3-a456-426614174000',
        };

        mockPrismaClient.section.findUnique.mockResolvedValue(null);

        const result = await softDelete(request);

        expect(result).toEqual({
          id: request.entity_id,
          entity_type: 'section',
          status: 'not_found',
          message: 'Entity not found',
        });

        expect(mockPrismaClient.section.delete).not.toHaveBeenCalled();
      });

      it('should handle unknown entity type', async () => {
        const { softDelete } = await import('../../src/services/delete-operations.js');

        const request: DeleteRequest = {
          entity_type: 'unknown_type',
          entity_id: '123e4567-e89b-12d3-a456-426614174000',
        };

        const result = await softDelete(request);

        expect(result).toEqual({
          id: request.entity_id,
          entity_type: 'unknown_type',
          status: 'not_found',
          message: 'Unknown entity type: unknown_type',
        });
      });

      it('should handle database errors gracefully', async () => {
        const { softDelete } = await import('../../src/services/delete-operations.js');
        const { logger } = require('../../src/utils/logger.js');

        const request: DeleteRequest = {
          entity_type: 'section',
          entity_id: '123e4567-e89b-12d3-a456-426614174000',
        };

        mockPrismaClient.section.findUnique.mockRejectedValue(new Error('Database connection failed'));

        const result = await softDelete(request);

        expect(logger.error).toHaveBeenCalledWith(
          expect.objectContaining({
            error: expect.any(Error),
            id: request.entity_id,
            entity_type: 'section',
          }),
          'Failed to delete entity'
        );

        expect(result).toEqual({
          id: request.entity_id,
          entity_type: 'section',
          status: 'not_found',
          message: 'Database connection failed',
        });
      });
    });

    describe('Cascade Delete Relations', () => {
      it('should cascade delete relations for typed knowledge types', async () => {
        const { softDelete } = await import('../../src/services/delete-operations.js');

        const request: DeleteRequest = {
          entity_type: 'section',
          entity_id: '123e4567-e89b-12d3-a456-426614174000',
          cascade_relations: true,
        };

        mockPrismaClient.section.findUnique.mockResolvedValue({ id: request.entity_id });
        mockPrismaClient.section.delete.mockResolvedValue({ id: request.entity_id });
        mockPrismaClient.knowledgeRelation.updateMany.mockResolvedValue({ count: 2 });

        const result = await softDelete(request);

        expect(result.cascaded_relations).toBe(2);
        expect(mockPrismaClient.knowledgeRelation.updateMany).toHaveBeenCalledWith({
          where: {
            AND: [
              {
                OR: [
                  {
                    from_entity_type: 'section',
                    from_entity_id: request.entity_id,
                  },
                  {
                    to_entity_type: 'section',
                    to_entity_id: request.entity_id,
                  },
                ],
              },
              {
                deleted_at: null,
              },
            ],
          },
          data: {
            deleted_at: expect.any(Date),
          },
        });
      });

      it('should handle cascade delete errors gracefully', async () => {
        const { softDelete } = await import('../../src/services/delete-operations.js');
        const { logger } = require('../../src/utils/logger.js');

        const request: DeleteRequest = {
          entity_type: 'entity',
          entity_id: '123e4567-e89b-12d3-a456-426614174000',
          cascade_relations: true,
        };

        const { softDeleteEntity } = require('../../src/services/knowledge/entity.js');
        softDeleteEntity.mockResolvedValue(true);
        mockPrismaClient.knowledgeRelation.updateMany.mockRejectedValue(new Error('Relation table locked'));

        const result = await softDelete(request);

        expect(logger.error).toHaveBeenCalledWith(
          expect.objectContaining({
            error: expect.any(Error),
            entity_type: 'entity',
            entity_id: request.entity_id,
          }),
          'Failed to cascade delete relations'
        );

        // Entity should still be deleted despite cascade failure
        expect(result.status).toBe('deleted');
        expect(result.cascaded_relations).toBe(0);
      });
    });
  });

  describe('bulkDelete', () => {
    it('should delete multiple entities successfully', async () => {
      const { bulkDelete } = await import('../../src/services/delete-operations.js');
      const { softDeleteEntity } = require('../../src/services/knowledge/entity.js');

      const requests: DeleteRequest[] = [
        {
          entity_type: 'entity',
          entity_id: '123e4567-e89b-12d3-a456-426614174000',
        },
        {
          entity_type: 'entity',
          entity_id: '123e4567-e89b-12d3-a456-426614174001',
        },
        {
          entity_type: 'relation',
          entity_id: '123e4567-e89b-12d3-a456-426614174002',
        },
      ];

      softDeleteEntity.mockResolvedValue(true);

      const results = await bulkDelete(requests);

      expect(results).toHaveLength(3);
      expect(results.every(r => r.status === 'deleted')).toBe(true);
      expect(softDeleteEntity).toHaveBeenCalledTimes(2);
    });

    it('should handle mixed success and failure in bulk operations', async () => {
      const { bulkDelete } = await import('../../src/services/delete-operations.js');
      const { softDeleteEntity } = require('../../src/services/knowledge/entity.js');

      const requests: DeleteRequest[] = [
        {
          entity_type: 'entity',
          entity_id: '123e4567-e89b-12d3-a456-426614174000',
        },
        {
          entity_type: 'unknown_type',
          entity_id: '123e4567-e89b-12d3-a456-426614174001',
        },
        {
          entity_type: 'entity',
          entity_id: '123e4567-e89b-12d3-a456-426614174002',
        },
      ];

      softDeleteEntity
        .mockResolvedValueOnce(true)
        .mockResolvedValueOnce(false);

      const results = await bulkDelete(requests);

      expect(results).toHaveLength(3);
      expect(results[0].status).toBe('deleted');
      expect(results[1].status).toBe('not_found');
      expect(results[2].status).toBe('not_found');
    });

    it('should handle empty bulk delete request', async () => {
      const { bulkDelete } = await import('../../src/services/delete-operations.js');

      const results = await bulkDelete([]);

      expect(results).toHaveLength(0);
    });

    it('should process bulk operations sequentially', async () => {
      const { bulkDelete } = await import('../../src/services/delete-operations.js');
      const { softDeleteEntity } = require('../../src/services/knowledge/entity.js');

      const requests: DeleteRequest[] = [
        {
          entity_type: 'entity',
          entity_id: '123e4567-e89b-12d3-a456-426614174000',
        },
        {
          entity_type: 'entity',
          entity_id: '123e4567-e89b-12d3-a456-426614174001',
        },
      ];

      let callOrder = 0;
      softDeleteEntity.mockImplementation(async () => {
        callOrder++;
        await new Promise(resolve => setTimeout(resolve, 10));
        return true;
      });

      const startTime = Date.now();
      const results = await bulkDelete(requests);
      const endTime = Date.now();

      expect(results).toHaveLength(2);
      expect(endTime - startTime).toBeGreaterThan(20); // Should take at least 20ms (2 * 10ms delays)
      expect(callOrder).toBe(2);
    });
  });

  describe('undelete', () => {
    it('should undelete entity successfully', async () => {
      const { undelete } = await import('../../src/services/delete-operations.js');

      mockPrismaClient.knowledgeEntity.updateMany.mockResolvedValue({ count: 1 });

      const result = await undelete('entity', '123e4567-e89b-12d3-a456-426614174000');

      expect(result).toBe(true);
      expect(mockPrismaClient.knowledgeEntity.updateMany).toHaveBeenCalledWith({
        where: {
          id: '123e4567-e89b-12d3-a456-426614174000',
          deleted_at: { not: null },
        },
        data: {
          deleted_at: null,
        },
      });
    });

    it('should undelete relation successfully', async () => {
      const { undelete } = await import('../../src/services/delete-operations.js');

      mockPrismaClient.knowledgeRelation.updateMany.mockResolvedValue({ count: 1 });

      const result = await undelete('relation', '123e4567-e89b-12d3-a456-426614174000');

      expect(result).toBe(true);
      expect(mockPrismaClient.knowledgeRelation.updateMany).toHaveBeenCalledWith({
        where: {
          id: '123e4567-e89b-12d3-a456-426614174000',
          deleted_at: { not: null },
        },
        data: {
          deleted_at: null,
        },
      });
    });

    it('should undelete observation successfully', async () => {
      const { undelete } = await import('../../src/services/delete-operations.js');

      mockPrismaClient.knowledgeObservation.updateMany.mockResolvedValue({ count: 1 });

      const result = await undelete('observation', '123e4567-e89b-12d3-a456-426614174000');

      expect(result).toBe(true);
      expect(mockPrismaClient.knowledgeObservation.updateMany).toHaveBeenCalledWith({
        where: {
          id: '123e4567-e89b-12d3-a456-426614174000',
          deleted_at: { not: null },
        },
        data: {
          deleted_at: null,
        },
      });
    });

    it('should return false when entity not found for undelete', async () => {
      const { undelete } = await import('../../src/services/delete-operations.js');

      mockPrismaClient.knowledgeEntity.updateMany.mockResolvedValue({ count: 0 });

      const result = await undelete('entity', '123e4567-e89b-12d3-a456-426614174000');

      expect(result).toBe(false);
    });

    it('should not support undelete for typed knowledge types', async () => {
      const { undelete } = await import('../../src/services/delete-operations.js');
      const { logger } = require('../../src/utils/logger.js');

      const result = await undelete('section', '123e4567-e89b-12d3-a456-426614174000');

      expect(result).toBe(false);
      expect(logger.warn).toHaveBeenCalledWith(
        expect.objectContaining({
          entity_type: 'section',
          entity_id: '123e4567-e89b-12d3-a456-426614174000',
        }),
        'Undelete not supported for entity type (hard delete only)'
      );
    });

    it('should handle undelete errors gracefully', async () => {
      const { undelete } = await import('../../src/services/delete-operations.js');
      const { logger } = require('../../src/utils/logger.js');

      mockPrismaClient.knowledgeEntity.updateMany.mockRejectedValue(new Error('Database error'));

      const result = await undelete('entity', '123e4567-e89b-12d3-a456-426614174000');

      expect(result).toBe(false);
      expect(logger.error).toHaveBeenCalledWith(
        expect.objectContaining({
          error: expect.any(Error),
          entity_type: 'entity',
          entity_id: '123e4567-e89b-12d3-a456-426614174000',
        }),
        'Failed to undelete entity'
      );
    });
  });

  describe('Table Mapping Validation', () => {
    it('should map all supported entity types correctly', async () => {
      const { softDelete } = await import('../../src/services/delete-operations.js');

      const entityTypes = [
        'section', 'runbook', 'change', 'issue', 'decision',
        'todo', 'release_note', 'ddl', 'pr_context',
        'incident', 'release', 'risk', 'assumption'
      ];

      for (const entityType of entityTypes) {
        const request: DeleteRequest = {
          entity_type: entityType,
          entity_id: '123e4567-e89b-12d3-a456-426614174000',
        };

        // Mock successful find and delete
        const mockModel = mockPrismaClient[entityType === 'change' ? 'changeLog' :
                                       entityType === 'decision' ? 'adrDecision' :
                                       entityType === 'todo' ? 'todoLog' :
                                       entityType === 'release_note' ? 'releaseNote' :
                                       entityType === 'ddl' ? 'ddlHistory' :
                                       entityType === 'pr_context' ? 'prContext' :
                                       entityType === 'incident' ? 'incidentLog' :
                                       entityType === 'release' ? 'releaseLog' :
                                       entityType === 'risk' ? 'riskLog' :
                                       entityType === 'assumption' ? 'assumptionLog' :
                                       entityType];

        if (mockModel) {
          mockModel.findUnique.mockResolvedValue({ id: request.entity_id });
          mockModel.delete.mockResolvedValue({ id: request.entity_id });

          const result = await softDelete(request);

          expect(result.status).toBe('deleted');
          expect(mockModel.delete).toHaveBeenCalled();
        }
      }
    });
  });

  describe('Performance and Scalability', () => {
    it('should handle large bulk delete operations efficiently', async () => {
      const { bulkDelete } = await import('../../src/services/delete-operations.js');
      const { softDeleteEntity } = require('../../src/services/knowledge/entity.js');

      // Create 1000 delete requests
      const requests: DeleteRequest[] = Array.from({ length: 1000 }, (_, i) => ({
        entity_type: 'entity' as const,
        entity_id: `123e4567-e89b-12d3-a456-42661417${i.toString().padStart(4, '0')}`,
      }));

      softDeleteEntity.mockResolvedValue(true);

      const startTime = Date.now();
      const results = await bulkDelete(requests);
      const endTime = Date.now();

      expect(results).toHaveLength(1000);
      expect(results.every(r => r.status === 'deleted')).toBe(true);
      expect(softDeleteEntity).toHaveBeenCalledTimes(1000);

      // Should complete in reasonable time (adjust threshold as needed)
      expect(endTime - startTime).toBeLessThan(5000); // 5 seconds max
    });

    it('should handle concurrent delete operations safely', async () => {
      const { softDelete } = await import('../../src/services/delete-operations.js');
      const { softDeleteEntity } = require('../../src/services/knowledge/entity.js');

      const request: DeleteRequest = {
        entity_type: 'entity',
        entity_id: '123e4567-e89b-12d3-a456-426614174000',
      };

      softDeleteEntity.mockResolvedValue(true);

      // Run multiple concurrent delete operations on the same entity
      const promises = Array(10).fill(null).map(() => softDelete(request));
      const results = await Promise.all(promises);

      // All operations should succeed
      expect(results).toHaveLength(10);
      expect(results.every(r => r.status === 'deleted')).toBe(true);
      expect(softDeleteEntity).toHaveBeenCalledTimes(10);
    });
  });

  describe('Input Validation', () => {
    it('should handle invalid UUID format gracefully', async () => {
      const { softDelete } = await import('../../src/services/delete-operations.js');

      const request: DeleteRequest = {
        entity_type: 'entity',
        entity_id: 'invalid-uuid-format',
      };

      const { softDeleteEntity } = require('../../src/services/knowledge/entity.js');
      softDeleteEntity.mockResolvedValue(false); // Entity not found due to invalid UUID

      const result = await softDelete(request);

      expect(result.status).toBe('not_found');
      expect(result.message).toContain('Entity not found or already deleted');
    });

    it('should handle empty entity ID', async () => {
      const { softDelete } = await import('../../src/services/delete-operations.js');

      const request: DeleteRequest = {
        entity_type: 'entity',
        entity_id: '',
      };

      const { softDeleteEntity } = require('../../src/services/knowledge/entity.js');
      softDeleteEntity.mockResolvedValue(false);

      const result = await softDelete(request);

      expect(result.status).toBe('not_found');
    });

    it('should handle null/undefined entity values', async () => {
      const { softDelete } = await import('../../src/services/delete-operations.js');

      // @ts-expect-error - Testing invalid input
      const request: DeleteRequest = {
        entity_type: null,
        entity_id: undefined,
      };

      const result = await softDelete(request);

      expect(result.status).toBe('not_found');
      expect(result.message).toContain('Unknown entity type');
    });
  });
});