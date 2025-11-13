
/**
 * TTL Integration Test Suite
 *
 * Comprehensive integration tests for the TTL policy system,
 * covering all components and their interactions.
 *
 * Test Categories:
 * - TTL Policy Service functionality
 * - Enhanced Expiry Utilities
 * - TTL Management Service
 * - TTL Safety Service
 * - Database integration
 * - End-to-end workflows
 *
 * @author Cortex Team
 * @version 1.0.0
 * @since 2025
 */

import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

import { enhancedExpiryUtils } from '../../../utils/enhanced-expiry-utils.js';
import { createTTLManagementService,type TTLManagementService } from '../ttl-management-service.js';
import type {
  KnowledgeItem,
  TTLBulkOperationOptions,
  TTLPolicyOptions,
} from '../ttl-policy-service.js';
import { ttlPolicyService } from '../ttl-policy-service.js';
import { ttlSafetyService } from '../ttl-safety-service.js';

// Mock database layer for testing
const mockDatabaseLayer = {
  store: jest.fn(),
  findById: jest.fn(),
  search: jest.fn(),
  delete: jest.fn(),
  healthCheck: jest.fn().mockResolvedValue(true),
  generateUUID: jest.fn().mockReturnValue('test-id'),
  getStatistics: jest.fn(),
};

describe('TTL Integration Test Suite', () => {
  let ttlManagementService: TTLManagementService;
  let testItems: KnowledgeItem[];

  beforeEach(() => {
    jest.clearAllMocks();
    ttlManagementService = createTTLManagementService(mockDatabaseLayer as unknown);

    testItems = [
      {
        id: 'test-item-1',
        kind: 'entity',
        scope: { org: 'test-org', project: 'test-project' },
        data: { name: 'Test Entity 1', content: 'Test content 1' },
        created_at: new Date().toISOString(),
      },
      {
        id: 'test-item-2',
        kind: 'decision',
        scope: { org: 'test-org', project: 'test-project' },
        data: { name: 'Test Decision', ttl: 'long' },
        created_at: new Date().toISOString(),
      },
      {
        id: 'test-item-3',
        kind: 'incident',
        scope: { org: 'test-org', project: 'test-project' },
        data: { name: 'Test Incident', severity: 'high' },
        created_at: new Date().toISOString(),
      },
      {
        id: 'test-item-4',
        kind: 'session',
        scope: { org: 'test-org', project: 'test-project' },
        data: { name: 'Test Session', expiry_at: '2024-01-01T00:00:00.000Z' },
        created_at: new Date().toISOString(),
      },
      {
        id: 'test-item-5',
        kind: 'risk',
        scope: { org: 'test-org', project: 'test-project' },
        data: { name: 'Test Risk', probability: 'high' },
        created_at: new Date().toISOString(),
      },
    ];
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('TTL Policy Service Integration', () => {
    it('should apply default TTL policy correctly', () => {
      const item = testItems[0];
      const result = ttlPolicyService.calculateExpiry(item);

      expect(result.policyApplied).toBe('default');
      expect(result.durationMs).toBe(30 * 24 * 60 * 60 * 1000); // 30 days
      expect(result.isPermanent).toBe(false);
      expect(result.validationErrors).toHaveLength(0);
    });

    it('should apply business rule TTL policies', () => {
      const incidentItem = testItems[2]; // incident
      const decisionItem = testItems[1]; // decision

      const incidentResult = ttlPolicyService.calculateExpiry(incidentItem, {
        applyBusinessRules: true,
      });
      const decisionResult = ttlPolicyService.calculateExpiry(decisionItem, {
        applyBusinessRules: true,
      });

      expect(incidentResult.policyApplied).toBe('incident_permanent');
      expect(incidentResult.isPermanent).toBe(true);

      expect(decisionResult.policyApplied).toBe('decision_long');
      expect(decisionResult.isPermanent).toBe(false);
    });

    it('should handle explicit expiry_at overrides', () => {
      const item = testItems[3]; // Has explicit expiry_at
      const result = ttlPolicyService.calculateExpiry(item, { allowOverride: true });

      expect(result.appliedOverrides).toContain('explicit_expiry_at');
      expect(result.expiryAt).toBe('2024-01-01T00:00:00.000Z');
    });

    it('should validate and reject unsafe overrides', () => {
      const item = testItems[0];
      item.data = { ...item.data, expiry_at: '2020-01-01T00:00:00.000Z' }; // Past date

      const result = ttlPolicyService.calculateExpiry(item, { enableValidation: true });

      expect(result.validationErrors.length).toBeGreaterThan(0);
      expect(result.isSafe).toBe(false);
    });

    it('should register and use custom TTL policies', () => {
      const customPolicy = {
        name: 'custom_test',
        description: 'Test custom policy',
        durationMs: 14 * 24 * 60 * 60 * 1000, // 14 days
        isPermanent: false,
        safeOverride: true,
      };

      ttlPolicyService.registerPolicy(customPolicy);

      const item = testItems[0];
      const result = ttlPolicyService.calculateExpiry(item, { forcePolicy: 'custom_test' });

      expect(result.policyApplied).toBe('custom_test');
      expect(result.durationMs).toBe(14 * 24 * 60 * 60 * 1000);
    });
  });

  describe('Enhanced Expiry Utilities Integration', () => {
    it('should calculate expiry with timezone awareness', () => {
      const baseTime = new Date('2025-01-01T12:00:00.000Z');
      const durationMs = 24 * 60 * 60 * 1000; // 1 day

      const expiry = enhancedExpiryUtils.calculateExpiry(baseTime, durationMs, {
        timezone: {
          timezone: 'America/New_York',
          applyDST: true,
        },
      });

      expect(expiry).toBeDefined();
      expect(typeof expiry).toBe('string');
    });

    it('should validate expiry timestamps correctly', () => {
      const validExpiry = '2025-12-31T23:59:59.999Z';
      const invalidExpiry = 'invalid-date';
      const pastExpiry = '2020-01-01T00:00:00.000Z';

      const validResult = enhancedExpiryUtils.validateExpiry(validExpiry, { strictMode: false });
      const invalidResult = enhancedExpiryUtils.validateExpiry(invalidExpiry);
      const pastResult = enhancedExpiryUtils.validateExpiry(pastExpiry, { strictMode: false });

      expect(validResult.isValid).toBe(true);
      expect(validResult.errors).toHaveLength(0);

      expect(invalidResult.isValid).toBe(false);
      expect(invalidResult.errors.length).toBeGreaterThan(0);

      expect(pastResult.isValid).toBe(true);
      expect(pastResult.warnings.length).toBeGreaterThan(0);
      expect(pastResult.suggestedCorrection).toBeDefined();
    });

    it('should check expiry with grace periods', () => {
      const futureItem = {
        ...testItems[0],
        expiry_at: new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString(), // 2 hours
      };

      const graceResult = enhancedExpiryUtils.isExpiredWithGrace(futureItem, 60); // 1 hour grace

      expect(graceResult.isExpired).toBe(false);
      expect(graceResult.timeRemaining).toBeGreaterThan(0);
      expect(graceResult.gracePeriodRemaining).toBeGreaterThan(graceResult.timeRemaining);
    });

    it('should provide human-readable time remaining', () => {
      const futureItem = {
        ...testItems[0],
        expiry_at: new Date(
          Date.now() + 2 * 24 * 60 * 60 * 1000 + 3 * 60 * 60 * 1000 + 45 * 60 * 1000
        ).toISOString(), // 2 days, 3 hours, 45 minutes
      };

      const timeResult = enhancedExpiryUtils.getTimeRemainingExpiry(futureItem);

      expect(timeResult.isExpired).toBe(false);
      expect(timeResult.formatted).toMatch(/2d.*3h.*45m/);
      expect(timeResult.raw.days).toBe(2);
      expect(timeResult.raw.hours).toBe(3);
      expect(timeResult.raw.minutes).toBe(45);
    });
  });

  describe('TTL Management Service Integration', () => {
    it('should apply TTL policies to items in bulk', async () => {
      mockDatabaseLayer.store.mockResolvedValue({});

      const options: TTLPolicyOptions = {
        forcePolicy: 'short',
        enableValidation: true,
      };

      const bulkOptions: TTLBulkOperationOptions = {
        dryRun: true,
        batchSize: 2,
      };

      const result = await ttlManagementService.applyTTLPolicy(testItems, options, bulkOptions);

      expect(result.success).toBe(true);
      expect(result.processed).toBe(testItems.length);
      expect(result.updated).toBe(testItems.length);
      expect(result.details?.expiriesCalculated).toHaveLength(testItems.length);
      expect(mockDatabaseLayer.store).not.toHaveBeenCalled(); // Dry run
    });

    it('should handle TTL policy application errors gracefully', async () => {
      const invalidItems = [{ ...testItems[0], data: { expiry_at: 'invalid-date' } }];

      const options: TTLPolicyOptions = {
        enableValidation: true,
        strictMode: true,
      };

      const bulkOptions: TTLBulkOperationOptions = {
        continueOnError: true,
      };

      const result = await ttlManagementService.applyTTLPolicy(invalidItems, options, bulkOptions);

      expect(result.success).toBe(true);
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.processed).toBe(1);
      expect(result.updated).toBe(0);
    });

    it('should cleanup expired items', async () => {
      const expiredItems = [
        { id: 'expired-1', kind: 'entity' },
        { id: 'expired-2', kind: 'decision' },
      ];

      mockDatabaseLayer.search.mockResolvedValue({
        results: expiredItems,
        total_count: expiredItems.length,
      } as unknown);

      mockDatabaseLayer.delete.mockResolvedValue({ deleted: expiredItems.length, errors: [] });

      const result = await ttlManagementService.cleanupExpiredItems({
        dryRun: false,
        generateAudit: true,
      });

      expect(result.success).toBe(true);
      expect(result.processed).toBe(expiredItems.length);
      expect(result.updated).toBe(expiredItems.length);
      expect(mockDatabaseLayer.delete).toHaveBeenCalledWith(['expired-1', 'expired-2']);
    });

    it('should update TTL for specific items', async () => {
      const itemIds = ['test-item-1', 'test-item-2'];
      const existingItems = testItems.slice(0, 2);

      mockDatabaseLayer.findById.mockResolvedValue({
        results: existingItems.map((item) => ({
          id: item.id,
          kind: item.kind,
          scope: item.scope,
          data: item.data,
          created_at: item.created_at,
        })),
      } as unknown);

      mockDatabaseLayer.store.mockResolvedValue({});

      const newPolicy: TTLPolicyOptions = {
        forcePolicy: 'long',
        enableValidation: true,
      };

      const result = await ttlManagementService.updateItemTTL(itemIds, newPolicy, {
        dryRun: false,
      });

      expect(result.success).toBe(true);
      expect(result.processed).toBe(2);
      expect(result.updated).toBe(2);
      expect(result.details?.expiriesCalculated).toHaveLength(2);
    });

    it('should generate TTL statistics', async () => {
      mockDatabaseLayer.search.mockResolvedValue({
        results: testItems.map((item) => ({
          id: item.id,
          kind: item.kind,
          scope: item.scope,
          data: {
            ...item.data,
            expiry_at: new Date(
              Date.now() + Math.random() * 30 * 24 * 60 * 60 * 1000
            ).toISOString(),
            ttl_policy: 'default',
          },
          created_at: item.created_at,
        })),
      } as unknown);

      const stats = await ttlManagementService.getTTLStatistics();

      expect(stats.totalItems).toBe(testItems.length);
      expect(stats.itemsWithExpiry).toBe(testItems.length);
      expect(stats.averageTTL).toBeGreaterThan(0);
      expect(stats.policyDistribution).toBeDefined();
    });
  });

  describe('TTL Safety Service Integration', () => {
    it('should validate safe TTL operations', async () => {
      const context = {
        operationType: 'apply_policy' as const,
        itemCount: testItems.length,
        affectedScopes: ['test-project'],
        operationDetails: { policy: 'default' },
        userId: 'test-user',
        sessionId: 'test-session',
      };

      const calculationResults = testItems.map((item) => ttlPolicyService.calculateExpiry(item));

      const validationResult = await ttlSafetyService.validateTTLOperation(
        testItems,
        context,
        calculationResults
      );

      expect(validationResult.isSafe).toBe(true);
      expect(validationResult.severity).toBe('low');
      expect(validationResult.errors).toHaveLength(0);
    });

    it('should block unsafe operations with immediate expiry', async () => {
      const itemsWithImmediateExpiry = testItems.map((item) => ({
        ...item,
        data: { ...item.data, expiry_at: new Date(Date.now() - 1000).toISOString() }, // Past date
      }));

      const context = {
        operationType: 'apply_policy' as const,
        itemCount: itemsWithImmediateExpiry.length,
        affectedScopes: ['test-project'],
        operationDetails: { policy: 'short' },
      };

      const validationResult = await ttlSafetyService.validateTTLOperation(
        itemsWithImmediateExpiry,
        context
      );

      expect(validationResult.isSafe).toBe(false);
      expect(validationResult.severity).toBe('critical');
      expect(validationResult.errors.length).toBeGreaterThan(0);
      expect(validationResult.blockedOperations).toContain('apply_policy');
      expect(validationResult.estimatedDataLoss?.itemCount).toBeGreaterThan(0);
    });

    it('should require confirmation for operations on protected types', async () => {
      const protectedItems = testItems.filter((item) =>
        ['incident', 'risk', 'decision'].includes(item.kind)
      );

      const context = {
        operationType: 'update_ttl' as const,
        itemCount: protectedItems.length,
        affectedScopes: ['test-project'],
        operationDetails: { policy: 'short' },
      };

      const validationResult = await ttlSafetyService.validateTTLOperation(protectedItems, context);

      expect(validationResult.requiresConfirmation).toBe(true);
      expect(validationResult.warnings.some((w) => w.includes('Critical knowledge types'))).toBe(
        true
      );
    });

    it('should create and rollback safety checkpoints', async () => {
      const context = {
        operationType: 'apply_policy' as const,
        itemCount: testItems.length,
        affectedScopes: ['test-project'],
        operationDetails: { policy: 'default' },
      };

      const checkpointId = await ttlSafetyService.createSafetyCheckpoint(
        'test_operation',
        context,
        testItems
      );

      expect(checkpointId).toBeDefined();
      expect(checkpointId).toMatch(/^checkpoint_\d+_[a-z0-9]+$/);

      const rollbackResult = await ttlSafetyService.rollbackFromCheckpoint(checkpointId);

      expect(rollbackResult).toBe(true);
    });

    it('should provide safety statistics', () => {
      const stats = ttlSafetyService.getSafetyStatistics();

      expect(stats.totalValidations).toBeGreaterThanOrEqual(0);
      expect(stats.safetyConfig).toBeDefined();
      expect(stats.safetyConfig.enableDataLossPrevention).toBe(true);
      expect(stats.safetyConfig.protectedKnowledgeTypes).toContain('incident');
    });
  });

  describe('End-to-End Integration Workflows', () => {
    it('should handle complete TTL lifecycle: apply -> validate -> store -> cleanup', async () => {
      // Step 1: Apply TTL policies with safety validation
      mockDatabaseLayer.store.mockResolvedValue({});

      const policyOptions: TTLPolicyOptions = {
        applyBusinessRules: true,
        enableValidation: true,
      };

      const safetyContext = {
        operationType: 'apply_policy' as const,
        itemCount: testItems.length,
        affectedScopes: ['test-project'],
        operationDetails: policyOptions,
      };

      // Safety validation
      const safetyResult = await ttlSafetyService.validateTTLOperation(testItems, safetyContext);
      expect(safetyResult.isSafe).toBe(true);

      // Apply policies
      const applyResult = await ttlManagementService.applyTTLPolicy(testItems, policyOptions, {
        dryRun: false,
        generateAudit: true,
        validatePolicies: true,
      });

      expect(applyResult.success).toBe(true);
      expect(applyResult.updated).toBe(testItems.length);

      // Step 2: Verify items have proper expiry
      const itemsWithTTL = testItems.map((item, index) => ({
        ...item,
        expiry_at: applyResult.details?.expiriesCalculated[index]?.newExpiry,
        data: {
          ...item.data,
          ttl_policy: applyResult.details?.expiriesCalculated[index]?.policy,
        },
      }));

      // Step 3: Search for non-expired items (should return all)
      mockDatabaseLayer.search.mockResolvedValue({
        results: itemsWithTTL.map((item) => ({
          id: item.id,
          kind: item.kind,
          scope: item.scope,
          data: item.data,
          created_at: item.created_at,
        })),
      } as unknown);

      const stats = await ttlManagementService.getTTLStatistics();
      expect(stats.itemsWithExpiry).toBe(itemsWithTTL.length);

      // Step 4: Cleanup simulation (dry run)
      mockDatabaseLayer.search.mockResolvedValue({
        results: [], // No expired items
      } as unknown);

      const cleanupResult = await ttlManagementService.cleanupExpiredItems({
        dryRun: true,
      });

      expect(cleanupResult.success).toBe(true);
      expect(cleanupResult.processed).toBe(0);
    });

    it('should handle error recovery and rollback scenarios', async () => {
      // Create checkpoint
      const context = {
        operationType: 'update_ttl' as const,
        itemCount: testItems.length,
        affectedScopes: ['test-project'],
        operationDetails: { policy: 'short' },
      };

      const checkpointId = await ttlSafetyService.createSafetyCheckpoint(
        'error_test',
        context,
        testItems
      );

      // Simulate partial failure during TTL application
      mockDatabaseLayer.store.mockRejectedValue(new Error('Database connection failed'));

      const applyResult = await ttlManagementService.applyTTLPolicy(
        testItems,
        {
          forcePolicy: 'short',
        },
        {
          continueOnError: true,
        }
      );

      expect(applyResult.success).toBe(false);
      expect(applyResult.errors.length).toBeGreaterThan(0);

      // Rollback should restore previous state
      const rollbackResult = await ttlSafetyService.rollbackFromCheckpoint(checkpointId);
      expect(rollbackResult).toBe(true);

      // Verify audit log contains the error and rollback
      const auditLog = ttlSafetyService.getAuditLog(5);
      expect(auditLog.some((entry) => entry.action === 'blocked')).toBe(true);
    });

    it('should handle timezone-aware expiry calculations across different regions', () => {
      const baseTime = new Date('2025-01-01T12:00:00.000Z');
      const durationMs = 7 * 24 * 60 * 60 * 1000; // 1 week

      const timezones = ['UTC', 'America/New_York', 'Europe/London', 'Asia/Tokyo'];
      const expiries = timezones.map((tz) =>
        enhancedExpiryUtils.calculateExpiry(baseTime, durationMs, {
          timezone: { timezone: tz, applyDST: true },
        })
      );

      // All should be valid ISO strings
      expiries.forEach((expiry) => {
        expect(expiry).toBeDefined();
        expect(() => new Date(expiry)).not.toThrow();
      });

      // Should be different times due to timezone adjustments
      const uniqueExpiries = new Set(expiries);
      expect(uniqueExpiries.size).toBeGreaterThan(1);
    });
  });

  describe('Performance and Scalability Tests', () => {
    it('should handle large batch operations efficiently', async () => {
      const largeItemSet = Array.from({ length: 1000 }, (_, index) => ({
        id: `bulk-item-${index}`,
        kind: 'entity',
        scope: { org: 'test-org', project: 'test-project' },
        data: { name: `Bulk Item ${index}` },
        created_at: new Date().toISOString(),
      }));

      mockDatabaseLayer.store.mockResolvedValue({});

      const startTime = Date.now();

      const result = await ttlManagementService.applyTTLPolicy(
        largeItemSet,
        {
          forcePolicy: 'default',
        },
        {
          batchSize: 100,
          dryRun: true,
        }
      );

      const duration = Date.now() - startTime;

      expect(result.success).toBe(true);
      expect(result.processed).toBe(1000);
      expect(duration).toBeLessThan(5000); // Should complete within 5 seconds
      expect(result.details?.expiriesCalculated).toHaveLength(1000);
    });

    it('should validate safety checks scale well with item count', async () => {
      const largeItemSet = Array.from({ length: 5000 }, (_, index) => ({
        id: `safety-test-${index}`,
        kind: index % 2 === 0 ? 'entity' : 'decision',
        scope: { org: 'test-org', project: 'test-project' },
        data: { name: `Safety Test ${index}` },
        created_at: new Date().toISOString(),
      }));

      const context = {
        operationType: 'apply_policy' as const,
        itemCount: largeItemSet.length,
        affectedScopes: ['test-project'],
        operationDetails: { policy: 'default' },
      };

      const startTime = Date.now();

      const validationResult = await ttlSafetyService.validateTTLOperation(largeItemSet, context);

      const duration = Date.now() - startTime;

      expect(validationResult.isSafe).toBe(true);
      expect(duration).toBeLessThan(2000); // Should validate within 2 seconds
    });
  });
});
