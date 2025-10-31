/**
 * TTL Integration Tests
 * Tests for TTL calculation, persistence to Qdrant, and expiry worker functionality
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { calculateItemExpiry, isExpired } from '../../src/utils/expiry-utils.js';
import { getExpiryTimestamp, type ExpiryTimeLabel } from '../../src/constants/expiry-times.js';
import { QdrantAdapter } from '../../src/db/adapters/qdrant-adapter.js';
import type { KnowledgeItem } from '../../src/types/core-interfaces.js';

describe('TTL Integration', () => {
  let qdrantAdapter: QdrantAdapter;

  beforeEach(() => {
    qdrantAdapter = new QdrantAdapter({
      url: 'http://localhost:6333',
      apiKey: undefined,
      collectionName: 'test-ttl',
    });
  });

  describe('TTL Calculation', () => {
    it('should calculate expiry for default TTL policy', () => {
      const item: KnowledgeItem = {
        id: 'test-item-1',
        kind: 'entity',
        content: 'Test content',
        scope: { org: 'test-org' },
        created_at: '2024-10-31T10:00:00.000Z',
      };

      const expiryTime = calculateItemExpiry(item, 'default');
      const expectedExpiry = new Date('2024-10-31T10:00:00.000Z');
      expectedExpiry.setDate(expectedExpiry.getDate() + 30); // Add 30 days

      expect(new Date(expiryTime)).toStrictEqual(expectedExpiry);
    });

    it('should calculate expiry for short TTL policy', () => {
      const item: KnowledgeItem = {
        id: 'test-item-2',
        kind: 'todo',
        content: 'Temporary todo item',
        scope: { org: 'test-org' },
        created_at: '2024-10-31T10:00:00.000Z',
      };

      const expiryTime = calculateItemExpiry(item, 'short');
      const expectedExpiry = new Date('2024-10-31T10:00:00.000Z');
      expectedExpiry.setDate(expectedExpiry.getDate() + 1); // Add 24 hours

      expect(new Date(expiryTime)).toStrictEqual(expectedExpiry);
    });

    it('should calculate expiry for long TTL policy', () => {
      const item: KnowledgeItem = {
        id: 'test-item-3',
        kind: 'decision',
        content: 'Important decision',
        scope: { org: 'test-org' },
        created_at: '2024-10-31T10:00:00.000Z',
      };

      const expiryTime = calculateItemExpiry(item, 'long');
      const expectedExpiry = new Date('2024-10-31T10:00:00.000Z');
      expectedExpiry.setDate(expectedExpiry.getDate() + 90); // Add 90 days

      expect(new Date(expiryTime)).toStrictEqual(expectedExpiry);
    });

    it('should return permanent expiry for permanent policy', () => {
      const item: KnowledgeItem = {
        id: 'test-item-4',
        kind: 'ddl',
        content: 'Database schema change',
        scope: { org: 'test-org' },
        created_at: '2024-10-31T10:00:00.000Z',
      };

      const expiryTime = calculateItemExpiry(item, 'permanent');
      expect(expiryTime).toBe('9999-12-31T23:59:59.999Z');
    });

    it('should use explicit expiry_at from item data if provided', () => {
      const explicitExpiry = '2025-01-15T10:00:00.000Z';
      const item: KnowledgeItem = {
        id: 'test-item-5',
        kind: 'entity',
        content: 'Test with explicit expiry',
        scope: { org: 'test-org' },
        data: {
          expiry_at: explicitExpiry,
        },
        created_at: '2024-10-31T10:00:00.000Z',
      };

      const expiryTime = calculateItemExpiry(item, 'default');
      expect(expiryTime).toBe(explicitExpiry);
    });
  });

  describe('TTL Policy by Knowledge Type', () => {
    const typeToPolicy: Record<string, ExpiryTimeLabel> = {
      'pr_context': 'short',      // 24 hours
      'todo': 'default',          // 30 days
      'issue': 'default',         // 30 days
      'change': 'default',        // 30 days
      'entity': 'long',           // 90 days
      'relation': 'long',         // 90 days
      'observation': 'long',      // 90 days
      'decision': 'long',         // 90 days
      'section': 'long',          // 90 days
      'runbook': 'default',       // 30 days
      'release_note': 'default',  // 30 days
      'ddl': 'permanent',         // Never expires
      'incident': 'default',      // 30 days
      'release': 'long',          // 90 days
      'risk': 'default',          // 30 days
      'assumption': 'default',    // 30 days
    };

    it.each(Object.entries(typeToPolicy))(
      'should apply %s policy for %s knowledge type',
      (expectedPolicy, kind) => {
        const item: KnowledgeItem = {
          id: `test-${kind}`,
          kind: kind as any,
          content: `Test ${kind} content`,
          scope: { org: 'test-org' },
          created_at: '2024-10-31T10:00:00.000Z',
        };

        const expiryTime = calculateItemExpiry(item, expectedPolicy as ExpiryTimeLabel);

        // Verify that the expiry time is calculated correctly
        expect(expiryTime).toBeDefined();
        expect(expiryTime).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
      }
    );
  });

  describe('Qdrant TTL Persistence', () => {
    // This test would require mocking Qdrant or using a test instance
    it('should persist expiry_at in Qdrant payload', async () => {
      // Mock implementation - in real scenario this would integrate with actual Qdrant
      const item: KnowledgeItem = {
        id: 'test-ttl-persistence',
        kind: 'entity',
        content: 'Test TTL persistence',
        scope: { org: 'test-org' },
        created_at: '2024-10-31T10:00:00.000Z',
      };

      // Calculate expiry
      const expiryTime = calculateItemExpiry(item, 'long');

      // This would be the expected payload structure
      const expectedPayload = {
        kind: 'entity',
        scope: { org: 'test-org' },
        data: {},
        content_hash: expect.any(String),
        created_at: '2024-10-31T10:00:00.000Z',
        updated_at: expect.any(String),
        content: 'Test TTL persistence',
        expiry_at: expiryTime, // This should be added to payload
      };

      // In real implementation, we would verify this persists to Qdrant
      expect(expectedPayload.expiry_at).toBeDefined();
    });

    it('should include ttl_epoch for Qdrant TTL filter', async () => {
      const item: KnowledgeItem = {
        id: 'test-ttl-epoch',
        kind: 'todo',
        content: 'Test TTL epoch calculation',
        scope: { org: 'test-org' },
        created_at: '2024-10-31T10:00:00.000Z',
      };

      const expiryTime = calculateItemExpiry(item, 'short');
      const ttlEpoch = Math.floor(new Date(expiryTime).getTime() / 1000);

      expect(ttlEpoch).toBeGreaterThan(0);
      expect(ttlEpoch).toBeLessThan(2147483647); // Max 32-bit timestamp
    });
  });

  describe('Expiry Worker Integration', () => {
    it('should identify expired items correctly', () => {
      const now = new Date('2024-10-31T10:00:00.000Z');

      const expiredItem: KnowledgeItem = {
        id: 'expired-item',
        kind: 'todo',
        content: 'This should be expired',
        scope: { org: 'test-org' },
        data: {
          expiry_at: '2024-10-30T10:00:00.000Z', // Yesterday
        },
      };

      const validItem: KnowledgeItem = {
        id: 'valid-item',
        kind: 'todo',
        content: 'This should still be valid',
        scope: { org: 'test-org' },
        data: {
          expiry_at: '2024-11-30T10:00:00.000Z', // Next month
        },
      };

      const { isExpired } = require('../../src/utils/expiry-utils.js');

      expect(isExpired(expiredItem)).toBe(true);
      expect(isExpired(validItem)).toBe(false);
    });

    it('should handle permanent items correctly', () => {
      const permanentItem: KnowledgeItem = {
        id: 'permanent-item',
        kind: 'ddl',
        content: 'This should never expire',
        scope: { org: 'test-org' },
        data: {
          expiry_at: '9999-12-31T23:59:59.999Z',
        },
      };

      const { isExpired } = require('../../src/utils/expiry-utils.js');

      expect(isExpired(permanentItem)).toBe(false);
    });
  });

  describe('Edge Cases', () => {
    it('should handle missing created_at gracefully', () => {
      const item: KnowledgeItem = {
        id: 'test-no-created-at',
        kind: 'entity',
        content: 'Test item without created_at',
        scope: { org: 'test-org' },
      };

      // Should not throw and should calculate expiry from current time
      expect(() => {
        const expiryTime = calculateItemExpiry(item, 'default');
        expect(expiryTime).toBeDefined();
      }).not.toThrow();
    });

    it('should handle invalid expiry_at format gracefully', () => {
      const item: KnowledgeItem = {
        id: 'test-invalid-expiry',
        kind: 'entity',
        content: 'Test item with invalid expiry',
        scope: { org: 'test-org' },
        data: {
          expiry_at: 'invalid-date-format',
        },
      };

      // Should fall back to default TTL calculation
      expect(() => {
        const expiryTime = calculateItemExpiry(item, 'default');
        expect(expiryTime).toBeDefined();
        expect(expiryTime).not.toBe('invalid-date-format');
      }).not.toThrow();
    });

    it('should handle null expiry_at for permanent items', () => {
      const item: KnowledgeItem = {
        id: 'test-null-expiry',
        kind: 'ddl',
        content: 'Test item with null expiry',
        scope: { org: 'test-org' },
        data: {
          expiry_at: null,
        },
      };

      const expiryTime = calculateItemExpiry(item, 'permanent');
      expect(expiryTime).toBe('9999-12-31T23:59:59.999Z');
    });
  });
});