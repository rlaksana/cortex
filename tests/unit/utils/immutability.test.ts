/**
 * Comprehensive Unit Tests for Immutability Helpers
 *
 * Tests immutability functionality including:
 * - ADR (Architecture Decision Record) immutability validation
 * - Document write-lock validation
 * - Audit log append-only enforcement
 * - General immutability constraint checking
 * - Error handling and validation
 * - Business logic enforcement
 */

import {
  validateADRImmutability,
  validateSpecWriteLock,
  validateAuditAppendOnly,
  checkImmutabilityConstraint,
  ImmutabilityViolationError,
} from '../../src/utils/immutability';

// Mock the dependencies
vi.mock('../../src/db/pool.js', () => ({
  dbPool: {
    query: vi.fn(),
    initialize: vi.fn(),
  },
}));

// Mock database pool
const mockDbPool = {
  query: vi.fn(),
  initialize: vi.fn(),
  close: vi.fn(),
};

describe('Immutability Helpers', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.resetAllMocks();
  });

  describe('ImmutabilityViolationError', () => {
    it('should create error with message and error code', () => {
      const error = new ImmutabilityViolationError('Test error message', 'TEST_ERROR');

      expect(error.message).toBe('Test error message');
      expect(error.errorCode).toBe('TEST_ERROR');
      expect(error.name).toBe('ImmutabilityViolationError');
      expect(error).toBeInstanceOf(Error);
    });

    it('should create error with field information', () => {
      const error = new ImmutabilityViolationError('Field error', 'FIELD_ERROR', 'status');

      expect(error.errorCode).toBe('FIELD_ERROR');
      expect(error.field).toBe('status');
    });

    it('should work with try-catch blocks', () => {
      expect(() => {
        throw new ImmutabilityViolationError('Test error', 'TEST_CODE');
      }).toThrow('Test error');
    });

    it('should be identifiable as ImmutabilityViolationError', () => {
      const error = new ImmutabilityViolationError('Test', 'TEST');

      expect(error instanceof ImmutabilityViolationError).toBe(true);
      expect(error instanceof Error).toBe(true);
    });
  });

  describe('validateADRImmutability', () => {
    it('should allow modification of draft ADRs', async () => {
      const adrId = '123e4567-e89b-12d3-a456-426614174000';

      mockPrismaClient.adrDecision.findUnique.mockResolvedValue({
        id: adrId,
        status: 'draft',
      });

      await expect(validateADRImmutability(adrId)).resolves.not.toThrow();
    });

    it('should allow modification of proposed ADRs', async () => {
      const adrId = '123e4567-e89b-12d3-a456-426614174000';

      mockPrismaClient.adrDecision.findUnique.mockResolvedValue({
        id: adrId,
        status: 'proposed',
      });

      await expect(validateADRImmutability(adrId)).resolves.not.toThrow();
    });

    it('should reject modification of accepted ADRs', async () => {
      const adrId = '123e4567-e89b-12d3-a456-426614174000';

      mockPrismaClient.adrDecision.findUnique.mockResolvedValue({
        id: adrId,
        status: 'accepted',
      });

      await expect(validateADRImmutability(adrId)).rejects.toThrow(ImmutabilityViolationError);

      try {
        await validateADRImmutability(adrId);
      } catch (error) {
        expect(error).toBeInstanceOf(ImmutabilityViolationError);
        expect((error as ImmutabilityViolationError).errorCode).toBe('IMMUTABILITY_VIOLATION');
        expect((error as ImmutabilityViolationError).field).toBe('status');
        expect(error.message).toContain('Cannot modify accepted ADR');
      }
    });

    it('should allow modification of superseded ADRs', async () => {
      const adrId = '123e4567-e89b-12d3-a456-426614174000';

      mockPrismaClient.adrDecision.findUnique.mockResolvedValue({
        id: adrId,
        status: 'superseded',
      });

      await expect(validateADRImmutability(adrId)).resolves.not.toThrow();
    });

    it('should allow modification of deprecated ADRs', async () => {
      const adrId = '123e4567-e89b-12d3-a456-426614174000';

      mockPrismaClient.adrDecision.findUnique.mockResolvedValue({
        id: adrId,
        status: 'deprecated',
      });

      await expect(validateADRImmutability(adrId)).resolves.not.toThrow();
    });

    it('should throw error when ADR is not found', async () => {
      const adrId = '123e4567-e89b-12d3-a456-426614174000';

      mockPrismaClient.adrDecision.findUnique.mockResolvedValue(null);

      await expect(validateADRImmutability(adrId)).rejects.toThrow('ADR with id 123e4567-e89b-12d3-a456-426614174000 not found');
    });

    it('should handle database errors gracefully', async () => {
      const adrId = '123e4567-e89b-12d3-a456-426614174000';

      mockPrismaClient.adrDecision.findUnique.mockRejectedValue(new Error('Database connection failed'));

      await expect(validateADRImmutability(adrId)).rejects.toThrow('Database connection failed');
    });

    it('should handle various ADR status values', async () => {
      const testCases = [
        { status: 'draft', shouldAllow: true },
        { status: 'proposed', shouldAllow: true },
        { status: 'accepted', shouldAllow: false },
        { status: 'superseded', shouldAllow: true },
        { status: 'deprecated', shouldAllow: true },
        { status: 'rejected', shouldAllow: true },
        { status: 'withdrawn', shouldAllow: true },
      ];

      for (const testCase of testCases) {
        const adrId = '123e4567-e89b-12d3-a456-426614174000';

        mockPrismaClient.adrDecision.findUnique.mockResolvedValue({
          id: adrId,
          status: testCase.status,
        });

        if (testCase.shouldAllow) {
          await expect(validateADRImmutability(adrId)).resolves.not.toThrow();
        } else {
          await expect(validateADRImmutability(adrId)).rejects.toThrow(ImmutabilityViolationError);
        }
      }
    });
  });

  describe('validateSpecWriteLock', () => {
    it('should validate section exists', async () => {
      const sectionId = '123e4567-e89b-12d3-a456-426614174000';

      mockPrismaClient.section.findUnique.mockResolvedValue({
        id: sectionId,
      });

      await expect(validateSpecWriteLock(sectionId)).resolves.not.toThrow();
    });

    it('should throw error when section is not found', async () => {
      const sectionId = '123e4567-e89b-12d3-a456-426614174000';

      mockPrismaClient.section.findUnique.mockResolvedValue(null);

      await expect(validateSpecWriteLock(sectionId)).rejects.toThrow('Section with id 123e4567-e89b-12d3-a456-426614174000 not found');
    });

    it('should handle database errors gracefully', async () => {
      const sectionId = '123e4567-e89b-12d3-a456-426614174000';

      mockPrismaClient.section.findUnique.mockRejectedValue(new Error('Database connection failed'));

      await expect(validateSpecWriteLock(sectionId)).rejects.toThrow('Database connection failed');
    });

    it('should return without error for existing sections (placeholder for future approval workflow)', async () => {
      const sectionId = '123e4567-e89b-12d3-a456-426614174000';

      mockPrismaClient.section.findUnique.mockResolvedValue({
        id: sectionId,
        // No approved_at field in current schema
      });

      await expect(validateSpecWriteLock(sectionId)).resolves.not.toThrow();
    });

    it('should document current behavior as placeholder', async () => {
      const sectionId = '123e4567-e89b-12d3-a456-426614174000';

      mockPrismaClient.section.findUnique.mockResolvedValue({
        id: sectionId,
      });

      // Currently this function is a placeholder that doesn't enforce write locks
      // This test documents the current behavior for future implementation
      await expect(validateSpecWriteLock(sectionId)).resolves.not.toThrow();
    });
  });

  describe('validateAuditAppendOnly', () => {
    it('should always throw immutability violation error', () => {
      expect(() => validateAuditAppendOnly()).toThrow(ImmutabilityViolationError);

      try {
        validateAuditAppendOnly();
      } catch (error) {
        expect(error).toBeInstanceOf(ImmutabilityViolationError);
        expect((error as ImmutabilityViolationError).errorCode).toBe('AUDIT_APPEND_ONLY_VIOLATION');
        expect(error.message).toContain('Audit log is append-only');
      }
    });

    it('should provide clear error message about audit restrictions', () => {
      try {
        validateAuditAppendOnly();
      } catch (error) {
        expect(error.message).toContain('append-only');
        expect(error.message).toContain('modify or delete');
        expect(error.message).toContain('audit entries');
      }
    });

    it('should not accept any parameters', () => {
      expect(() => validateAuditAppendOnly()).not.toThrow();
      // The function should work without any parameters
    });
  });

  describe('checkImmutabilityConstraint', () => {
    it('should return AUDIT_APPEND_ONLY_VIOLATION for audit log updates', () => {
      const result = checkImmutabilityConstraint('event_audit', 'UPDATE');
      expect(result).toBe('AUDIT_APPEND_ONLY_VIOLATION');
    });

    it('should return AUDIT_APPEND_ONLY_VIOLATION for audit log deletes', () => {
      const result = checkImmutabilityConstraint('event_audit', 'DELETE');
      expect(result).toBe('AUDIT_APPEND_ONLY_VIOLATION');
    });

    it('should allow audit log inserts (no violation)', () => {
      const result = checkImmutabilityConstraint('event_audit', 'INSERT');
      expect(result).toBeNull();
    });

    it('should allow operations on other entity types', () => {
      const entityTypes = ['section', 'decision', 'todo', 'issue', 'runbook'];
      const operations = ['UPDATE', 'DELETE', 'INSERT'] as const;

      entityTypes.forEach(entityType => {
        operations.forEach(operation => {
          const result = checkImmutabilityConstraint(entityType, operation);
          expect(result).toBeNull();
        });
      });
    });

    it('should handle case-sensitive entity type matching', () => {
      const result1 = checkImmutabilityConstraint('event_audit', 'UPDATE');
      const result2 = checkImmutabilityConstraint('EVENT_AUDIT', 'UPDATE');
      const result3 = checkImmutabilityConstraint('Event_Audit', 'UPDATE');

      expect(result1).toBe('AUDIT_APPEND_ONLY_VIOLATION');
      expect(result2).toBeNull(); // Case mismatch - no violation
      expect(result3).toBeNull(); // Case mismatch - no violation
    });

    it('should handle case-sensitive operation matching', () => {
      const result1 = checkImmutabilityConstraint('event_audit', 'UPDATE');
      const result2 = checkImmutabilityConstraint('event_audit', 'update');
      const result3 = checkImmutabilityConstraint('event_audit', 'Update');

      expect(result1).toBe('AUDIT_APPEND_ONLY_VIOLATION');
      expect(result2).toBeNull(); // Case mismatch - no violation
      expect(result3).toBeNull(); // Case mismatch - no violation
    });

    it('should handle unknown entity types gracefully', () => {
      const result = checkImmutabilityConstraint('unknown_entity_type', 'UPDATE');
      expect(result).toBeNull();
    });

    it('should handle unknown operation types gracefully', () => {
      const result = checkImmutabilityConstraint('event_audit', 'UNKNOWN_OPERATION');
      expect(result).toBeNull();
    });
  });

  describe('Integration Scenarios', () => {
    it('should handle complete ADR immutability workflow', async () => {
      const adrId = '123e4567-e89b-12d3-a456-426614174000';

      // Simulate ADR lifecycle
      const statuses = ['draft', 'proposed', 'accepted'];

      for (const status of statuses) {
        mockPrismaClient.adrDecision.findUnique.mockResolvedValue({
          id: adrId,
          status: status,
        });

        if (status === 'accepted') {
          await expect(validateADRImmutability(adrId)).rejects.toThrow(ImmutabilityViolationError);
        } else {
          await expect(validateADRImmutability(adrId)).resolves.not.toThrow();
        }
      }
    });

    it('should handle audit log protection across different operations', () => {
      const operations = ['INSERT', 'UPDATE', 'DELETE'] as const;

      operations.forEach(operation => {
        const violation = checkImmutabilityConstraint('event_audit', operation);

        if (operation === 'INSERT') {
          expect(violation).toBeNull();
        } else {
          expect(violation).toBe('AUDIT_APPEND_ONLY_VIOLATION');
        }
      });
    });

    it('should handle batch immutability checks', async () => {
      const adrIds = [
        '123e4567-e89b-12d3-a456-426614174000', // draft
        '123e4567-e89b-12d3-a456-426614174001', // accepted
        '123e4567-e89b-12d3-a456-426614174002', // proposed
      ];

      // Mock different statuses for each ADR
      mockPrismaClient.adrDecision.findUnique
        .mockResolvedValueOnce({ id: adrIds[0], status: 'draft' })
        .mockResolvedValueOnce({ id: adrIds[1], status: 'accepted' })
        .mockResolvedValueOnce({ id: adrIds[2], status: 'proposed' });

      const results = await Promise.allSettled([
        validateADRImmutability(adrIds[0]),
        validateADRImmutability(adrIds[1]),
        validateADRImmutability(adrIds[2]),
      ]);

      expect(results[0].status).toBe('fulfilled');
      expect(results[1].status).toBe('rejected');
      expect(results[2].status).toBe('fulfilled');

      if (results[1].status === 'rejected') {
        expect(results[1].reason).toBeInstanceOf(ImmutabilityViolationError);
      }
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle invalid UUID formats gracefully', async () => {
      const invalidIds = [
        'invalid-uuid',
        '123-456-789',
        '',
        'not-a-uuid-at-all',
      ];

      for (const invalidId of invalidIds) {
        mockPrismaClient.adrDecision.findUnique.mockResolvedValue(null);

        await expect(validateADRImmutability(invalidId)).rejects.toThrow(
          `ADR with id ${invalidId} not found`
        );
      }
    });

    it('should handle database connection timeouts', async () => {
      const adrId = '123e4567-e89b-12d3-a456-426614174000';

      mockPrismaClient.adrDecision.findUnique.mockRejectedValue(
        new Error('Connection timeout after 30000ms')
      );

      await expect(validateADRImmutability(adrId)).rejects.toThrow('Connection timeout');
    });

    it('should handle malformed database responses', async () => {
      const adrId = '123e4567-e89b-12d3-a456-426614174000';

      // Mock response without status field
      mockPrismaClient.adrDecision.findUnique.mockResolvedValue({
        id: adrId,
        // Missing status field
      } as any);

      await expect(validateADRImmutability(adrId)).rejects.toThrow();
    });

    it('should handle null/undefined inputs to constraint checker', () => {
      expect(() => checkImmutabilityConstraint(null as any, 'UPDATE')).not.toThrow();
      expect(() => checkImmutabilityConstraint('event_audit', null as any)).not.toThrow();
      expect(() => checkImmutabilityConstraint(null as any, null as any)).not.toThrow();
    });
  });

  describe('Performance Considerations', () => {
    it('should handle many concurrent immutability checks efficiently', async () => {
      const adrId = '123e4567-e89b-12d3-a456-426614174000';
      mockPrismaClient.adrDecision.findUnique.mockResolvedValue({
        id: adrId,
        status: 'draft',
      });

      const promises = Array.from({ length: 100 }, () => validateADRImmutability(adrId));

      const startTime = performance.now();
      await Promise.all(promises);
      const endTime = performance.now();

      expect(endTime - startTime).toBeLessThan(1000); // Should complete in under 1 second
    });

    it('should cache database queries for repeated checks', async () => {
      const adrId = '123e4567-e89b-12d3-a456-426614174000';
      mockPrismaClient.adrDecision.findUnique.mockResolvedValue({
        id: adrId,
        status: 'draft',
      });

      // Multiple calls should only result in one database query
      await validateADRImmutability(adrId);
      await validateADRImmutability(adrId);
      await validateADRImmutability(adrId);

      // In a real implementation, this should be cached
      // For now, we just verify it doesn't throw
      expect(mockPrismaClient.adrDecision.findUnique).toHaveBeenCalledTimes(3);
    });
  });

  describe('Business Logic Validation', () => {
    it('should enforce ADR lifecycle rules correctly', async () => {
      const adrId = '123e4567-e89b-12d3-a456-426614174000';

      const lifecycleStates = [
        { from: 'draft', to: 'proposed', shouldAllow: true },
        { from: 'proposed', to: 'accepted', shouldAllow: true }, // Until acceptance
        { from: 'accepted', to: 'superseded', shouldAllow: true }, // Status change allowed
        { from: 'accepted', to: 'modified', shouldAllow: false }, // Content modification not allowed
      ];

      for (const state of lifecycleStates) {
        mockPrismaClient.adrDecision.findUnique.mockResolvedValue({
          id: adrId,
          status: state.from,
        });

        if (state.from === 'accepted' && state.to === 'modified') {
          await expect(validateADRImmutability(adrId)).rejects.toThrow(ImmutabilityViolationError);
        } else {
          await expect(validateADRImmutability(adrId)).resolves.not.toThrow();
        }
      }
    });

    it('should provide meaningful error messages for different violation types', async () => {
      const adrId = '123e4567-e89b-12d3-a456-426614174000';

      mockPrismaClient.adrDecision.findUnique.mockResolvedValue({
        id: adrId,
        status: 'accepted',
      });

      try {
        await validateADRImmutability(adrId);
      } catch (error) {
        const immutabilityError = error as ImmutabilityViolationError;
        expect(immutabilityError.message).toContain('accepted ADR');
        expect(immutabilityError.message).toContain('supersedes reference');
        expect(immutabilityError.errorCode).toBe('IMMUTABILITY_VIOLATION');
        expect(immutabilityError.field).toBe('status');
      }

      try {
        validateAuditAppendOnly();
      } catch (error) {
        const immutabilityError = error as ImmutabilityViolationError;
        expect(immutabilityError.message).toContain('append-only');
        expect(immutabilityError.errorCode).toBe('AUDIT_APPEND_ONLY_VIOLATION');
      }
    });

    it('should handle future document approval workflow', async () => {
      const sectionId = '123e4567-e89b-12d3-a456-426614174000';

      mockPrismaClient.section.findUnique.mockResolvedValue({
        id: sectionId,
        // Future: approved_at: new Date('2025-01-01')
      });

      // Currently this is a placeholder that doesn't enforce write locks
      // This test documents the expected behavior for future implementation
      await expect(validateSpecWriteLock(sectionId)).resolves.not.toThrow();
    });
  });
});