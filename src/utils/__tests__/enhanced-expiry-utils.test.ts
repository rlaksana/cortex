/**
 * Enhanced Expiry Utilities Unit Tests
 *
 * Comprehensive unit tests for the enhanced expiry utilities,
 * covering timezone handling, validation, and edge cases.
 *
 * Test Categories:
 * - Expiry calculation with various options
 * - Timestamp validation and normalization
 * - Timezone adjustments
 * - Business hours calculations
 * - Grace period handling
 * - Error scenarios and edge cases
 *
 * @author Cortex Team
 * @version 1.0.0
 * @since 2025
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';

import { enhancedExpiryUtils } from '../enhanced-expiry-utils';

describe('Enhanced Expiry Utils', () => {
  beforeEach(() => {
    jest.useFakeTimers();
    jest.setSystemTime(new Date('2025-01-01T12:00:00.000Z'));
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  describe('Expiry Calculation', () => {
    it('should calculate basic expiry timestamp', () => {
      const baseTime = new Date('2025-01-01T12:00:00.000Z');
      const durationMs = 24 * 60 * 60 * 1000; // 1 day

      const expiry = enhancedExpiryUtils.calculateExpiry(baseTime, durationMs);

      expect(expiry).toBe('2025-01-02T12:00:00.000Z');
    });

    it('should handle permanent expiry correctly', () => {
      const baseTime = new Date('2025-01-01T12:00:00.000Z');
      const permanentDuration = Number.POSITIVE_INFINITY;

      const expiry = enhancedExpiryUtils.calculateExpiry(baseTime, permanentDuration);

      expect(expiry).toBe('9999-12-31T23:59:59.999Z');
    });

    it('should apply timezone adjustments', () => {
      const baseTime = new Date('2025-01-01T12:00:00.000Z');
      const durationMs = 24 * 60 * 60 * 1000;

      const expiry = enhancedExpiryUtils.calculateExpiry(baseTime, durationMs, {
        timezone: {
          timezone: 'America/New_York',
          applyDST: true,
        },
      });

      // Should be adjusted for EST/EDT
      expect(expiry).toBeDefined();
      expect(typeof expiry).toBe('string');
    });

    it('should apply business hours restriction', () => {
      // Test with weekend time
      const saturdayTime = new Date('2025-01-04T20:00:00.000Z'); // Saturday 8 PM
      const durationMs = 2 * 60 * 60 * 1000; // 2 hours

      const expiry = enhancedExpiryUtils.calculateExpiry(saturdayTime, durationMs, {
        businessHoursOnly: true,
      });

      const expiryDate = new Date(expiry);
      // Should be moved to Monday business hours
      expect(expiryDate.getUTCDay()).toBe(1); // Monday
      expect(expiryDate.getUTCHours()).toBeGreaterThanOrEqual(9);
      expect(expiryDate.getUTCHours()).toBeLessThan(17);
    });

    it('should apply minimum and maximum constraints', () => {
      const baseTime = new Date('2025-01-01T12:00:00.000Z');
      const shortDuration = 30 * 60 * 1000; // 30 minutes

      const expiry = enhancedExpiryUtils.calculateExpiry(baseTime, shortDuration, {
        minExpiryDays: 1,
        preventPastExpiry: true,
      });

      const expiryDate = new Date(expiry);
      const diff = expiryDate.getTime() - baseTime.getTime();
      const days = diff / (24 * 60 * 60 * 1000);

      expect(days).toBeGreaterThanOrEqual(1);
    });

    it('should prevent past expiry when configured', () => {
      const baseTime = new Date('2025-01-01T12:00:00.000Z');
      const pastDuration = -24 * 60 * 60 * 1000; // -1 day

      const expiry = enhancedExpiryUtils.calculateExpiry(baseTime, pastDuration, {
        preventPastExpiry: true,
      });

      const expiryDate = new Date(expiry);
      expect(expiryDate.getTime()).toBeGreaterThan(baseTime.getTime());
    });

    it('should format output according to specified format', () => {
      const baseTime = new Date('2025-01-01T12:00:00.000Z');
      const durationMs = 24 * 60 * 60 * 1000;

      const isoFormat = enhancedExpiryUtils.calculateExpiry(baseTime, durationMs, {
        outputFormat: 'iso',
      });

      const unixFormat = enhancedExpiryUtils.calculateExpiry(baseTime, durationMs, {
        outputFormat: 'unix',
      });

      const readableFormat = enhancedExpiryUtils.calculateExpiry(baseTime, durationMs, {
        outputFormat: 'readable',
      });

      expect(isoFormat).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
      expect(unixFormat).toMatch(/^\d+$/);
      expect(readableFormat).toMatch(/\d{1,2}\/\d{1,2}\/\d{4}/);
    });
  });

  describe('Expiry Validation', () => {
    it('should validate valid ISO timestamp', () => {
      const validExpiry = '2025-12-31T23:59:59.999Z';

      const result = enhancedExpiryUtils.validateExpiry(validExpiry);

      expect(result.isValid).toBe(true);
      expect(result.errors).toHaveLength(0);
      expect(result.warnings).toHaveLength(0);
      expect(result.normalizedExpiry).toBe(validExpiry);
    });

    it('should reject invalid date format', () => {
      const invalidExpiry = 'not-a-date';

      const result = enhancedExpiryUtils.validateExpiry(invalidExpiry);

      expect(result.isValid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.errors[0]).toContain('Invalid date format');
    });

    it('should warn about past expiry in non-strict mode', () => {
      const pastExpiry = '2020-01-01T00:00:00.000Z';

      const result = enhancedExpiryUtils.validateExpiry(pastExpiry, { strictMode: false });

      expect(result.isValid).toBe(true);
      expect(result.warnings.length).toBeGreaterThan(0);
      expect(result.warnings[0]).toContain('past');
      expect(result.suggestedCorrection).toBeDefined();
    });

    it('should reject past expiry in strict mode', () => {
      const pastExpiry = '2020-01-01T00:00:00.000Z';

      const result = enhancedExpiryUtils.validateExpiry(pastExpiry, { strictMode: true });

      expect(result.isValid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.errors[0]).toContain('past');
    });

    it('should handle grace period correctly', () => {
      const now = new Date('2025-01-01T12:00:00.000Z');
      const slightlyPastExpiry = new Date(now.getTime() - 30 * 60 * 1000).toISOString(); // 30 minutes ago

      const result = enhancedExpiryUtils.validateExpiry(slightlyPastExpiry, {
        gracePeriodMinutes: 60,
      });

      expect(result.isValid).toBe(true);
      expect(result.warnings.length).toBe(0);
    });

    it('should warn about very far future dates', () => {
      const farFutureExpiry = '2035-01-01T00:00:00.000Z'; // 10 years in future

      const result = enhancedExpiryUtils.validateExpiry(farFutureExpiry, { strictMode: false });

      expect(result.isValid).toBe(true);
      expect(result.warnings.length).toBeGreaterThan(0);
      expect(result.warnings[0]).toContain('far in the future');
    });

    it('should reject very far future dates in strict mode', () => {
      const farFutureExpiry = '2035-01-01T00:00:00.000Z';

      const result = enhancedExpiryUtils.validateExpiry(farFutureExpiry, { strictMode: true });

      expect(result.isValid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.errors[0]).toContain('far in the future');
    });

    it('should validate different input types', () => {
      const dateString = '2025-12-31T23:59:59.999Z';
      const timestamp = Date.parse(dateString);
      const dateObject = new Date(dateString);

      const stringResult = enhancedExpiryUtils.validateExpiry(dateString);
      const numberResult = enhancedExpiryUtils.validateExpiry(timestamp);
      const dateResult = enhancedExpiryUtils.validateExpiry(dateObject);

      expect(stringResult.isValid).toBe(true);
      expect(numberResult.isValid).toBe(true);
      expect(dateResult.isValid).toBe(true);
    });
  });

  describe('Expiry Checking with Grace Period', () => {
    it('should correctly identify non-expired items', () => {
      const futureItem = {
        id: 'future-item',
        kind: 'entity',
        data: {},
        expiry_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
      };

      const result = enhancedExpiryUtils.isExpiredWithGrace(futureItem);

      expect(result.isExpired).toBe(false);
      expect(result.timeRemaining).toBeGreaterThan(0);
      expect(result.expiresAt).toBeDefined();
    });

    it('should correctly identify expired items', () => {
      const expiredItem = {
        id: 'expired-item',
        kind: 'entity',
        data: {},
        expiry_at: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
      };

      const result = enhancedExpiryUtils.isExpiredWithGrace(expiredItem);

      expect(result.isExpired).toBe(true);
      expect(result.timeRemaining).toBeLessThanOrEqual(0);
      expect(result.expiresAt).toBeDefined();
    });

    it('should handle grace period correctly', () => {
      const recentlyExpiredItem = {
        id: 'recently-expired',
        kind: 'entity',
        data: {},
        expiry_at: new Date(Date.now() - 30 * 60 * 1000).toISOString(), // 30 minutes ago
      };

      const result = enhancedExpiryUtils.isExpiredWithGrace(recentlyExpiredItem, 60); // 1 hour grace

      expect(result.isExpired).toBe(false);
      expect(result.timeRemaining).toBeLessThan(0); // Actually expired
      expect(result.gracePeriodRemaining).toBeGreaterThan(0); // But within grace period
    });

    it('should handle items without expiry', () => {
      const itemWithoutExpiry = {
        id: 'no-expiry',
        kind: 'entity',
        data: {},
      };

      const result = enhancedExpiryUtils.isExpiredWithGrace(itemWithoutExpiry);

      expect(result.isExpired).toBe(false);
      expect(result.timeRemaining).toBe(Number.POSITIVE_INFINITY);
      expect(result.expiresAt).toBeNull();
    });

    it('should handle invalid expiry dates gracefully', () => {
      const itemWithInvalidExpiry = {
        id: 'invalid-expiry',
        kind: 'entity',
        data: {},
        expiry_at: 'invalid-date',
      };

      const result = enhancedExpiryUtils.isExpiredWithGrace(itemWithInvalidExpiry);

      expect(result.isExpired).toBe(false);
      expect(result.expiresAt).toBe('invalid-date');
    });

    it('should handle permanent expiry correctly', () => {
      const permanentItem = {
        id: 'permanent-item',
        kind: 'entity',
        data: {},
        expiry_at: '9999-12-31T23:59:59.999Z',
      };

      const result = enhancedExpiryUtils.isExpiredWithGrace(permanentItem);

      expect(result.isExpired).toBe(false);
      expect(result.timeRemaining).toBe(Number.POSITIVE_INFINITY);
      expect(result.expiresAt).toBe('9999-12-31T23:59:59.999Z');
    });
  });

  describe('Time Remaining Calculation', () => {
    it('should provide human-readable time for future expiry', () => {
      const futureItem = {
        id: 'future-item',
        kind: 'entity',
        data: {},
        expiry_at: new Date(
          Date.now() + 2 * 24 * 60 * 60 * 1000 + 3 * 60 * 60 * 1000 + 45 * 60 * 1000
        ).toISOString(),
      };

      const result = enhancedExpiryUtils.getTimeRemainingExpiry(futureItem);

      expect(result.isExpired).toBe(false);
      expect(result.formatted).toMatch(/2d.*3h.*45m/);
      expect(result.raw.days).toBe(2);
      expect(result.raw.hours).toBe(3);
      expect(result.raw.minutes).toBe(45);
      expect(result.raw.totalMilliseconds).toBeGreaterThan(0);
    });

    it('should handle already expired items', () => {
      const expiredItem = {
        id: 'expired-item',
        kind: 'entity',
        data: {},
        expiry_at: new Date(Date.now() - 60 * 60 * 1000).toISOString(), // 1 hour ago
      };

      const result = enhancedExpiryUtils.getTimeRemainingExpiry(expiredItem);

      expect(result.isExpired).toBe(true);
      expect(result.formatted).toBe('Expired');
      expect(result.raw.days).toBe(0);
      expect(result.raw.hours).toBe(0);
      expect(result.raw.minutes).toBe(0);
      expect(result.raw.totalMilliseconds).toBe(0);
    });

    it('should handle items without expiry', () => {
      const itemWithoutExpiry = {
        id: 'no-expiry',
        kind: 'entity',
        data: {},
      };

      const result = enhancedExpiryUtils.getTimeRemainingExpiry(itemWithoutExpiry);

      expect(result.isExpired).toBe(false);
      expect(result.formatted).toBe('Never expires');
      expect(result.raw.days).toBe(Number.POSITIVE_INFINITY);
      expect(result.raw.totalMilliseconds).toBe(Number.POSITIVE_INFINITY);
    });

    it('should handle various time ranges correctly', () => {
      const testCases = [
        { minutes: 5, expected: '5m 0s' },
        { hours: 1, expected: '1h 0m 0s' },
        { hours: 25, expected: '1d 1h 0m 0s' },
        { days: 7, expected: '7d 0h 0m 0s' },
      ];

      testCases.forEach(({ minutes, hours, days, expected }) => {
        const duration =
          (minutes || 0) * 60 * 1000 +
          (hours || 0) * 60 * 60 * 1000 +
          (days || 0) * 24 * 60 * 60 * 1000;

        const item = {
          id: 'test-item',
          kind: 'entity',
          data: {},
          expiry_at: new Date(Date.now() + duration).toISOString(),
        };

        const result = enhancedExpiryUtils.getTimeRemainingExpiry(item);

        expect(result.isExpired).toBe(false);
        expect(result.raw.totalMilliseconds).toBe(duration);
      });
    });
  });

  describe('Timezone Management', () => {
    it('should provide available timezone configurations', () => {
      const timezones = enhancedExpiryUtils.getAvailableTimezones();

      expect(timezones).toHaveProperty('UTC');
      expect(timezones).toHaveProperty('US/Eastern');
      expect(timezones).toHaveProperty('Europe/London');
      expect(timezones).toHaveProperty('Asia/Tokyo');

      expect(timezones.UTC.timezone).toBe('UTC');
      expect(timezones.UTC.applyDST).toBe(false);
    });

    it('should add custom timezone configurations', () => {
      const customConfig = {
        timezone: 'Custom/Timezone',
        applyDST: false,
        businessHoursOnly: true,
        gracePeriodMinutes: 45,
      };

      enhancedExpiryUtils.addTimezoneConfig('Custom', customConfig);

      const timezones = enhancedExpiryUtils.getAvailableTimezones();
      expect(timezones).toHaveProperty('Custom');
      expect(timezones.Custom).toEqual(customConfig);
    });

    it('should clear timezone cache', () => {
      // Use a timezone to populate cache
      enhancedExpiryUtils.calculateExpiry(new Date(), 24 * 60 * 60 * 1000, {
        timezone: { timezone: 'America/New_York', applyDST: true },
      });

      // Clear cache should not throw
      expect(() => enhancedExpiryUtils.clearTimezoneCache()).not.toThrow();
    });

    it('should handle invalid timezones gracefully', () => {
      const baseTime = new Date('2025-01-01T12:00:00.000Z');
      const durationMs = 24 * 60 * 60 * 1000;

      // Should fallback to original time if timezone is invalid
      const expiry = enhancedExpiryUtils.calculateExpiry(baseTime, durationMs, {
        timezone: {
          timezone: 'Invalid/Timezone',
          applyDST: true,
        },
      });

      expect(expiry).toBe(baseTime.getTime() + durationMs);
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle calculation errors gracefully', () => {
      // Force an error by using invalid base time
      const invalidBaseTime = new Date('invalid');
      const durationMs = 24 * 60 * 60 * 1000;

      // Should fallback to simple calculation
      const expiry = enhancedExpiryUtils.calculateExpiry(invalidBaseTime, durationMs);

      expect(expiry).toBeDefined();
      expect(typeof expiry).toBe('string');
    });

    it('should handle extreme duration values', () => {
      const baseTime = new Date('2025-01-01T12:00:00.000Z');

      // Very large duration
      const largeExpiry = enhancedExpiryUtils.calculateExpiry(baseTime, Number.MAX_SAFE_INTEGER);

      // Very small duration
      const smallExpiry = enhancedExpiryUtils.calculateExpiry(baseTime, 1);

      // Zero duration
      const zeroExpiry = enhancedExpiryUtils.calculateExpiry(baseTime, 0);

      expect(largeExpiry).toBeDefined();
      expect(smallExpiry).toBeDefined();
      expect(zeroExpiry).toBeDefined();
    });

    it('should handle malformed input gracefully', () => {
      // Test with undefined, null, empty string
      expect(() => enhancedExpiryUtils.validateExpiry(undefined as unknown)).not.toThrow();
      expect(() => enhancedExpiryUtils.validateExpiry(null as unknown)).not.toThrow();
      expect(() => enhancedExpiryUtils.validateExpiry('')).not.toThrow();

      const undefinedResult = enhancedExpiryUtils.validateExpiry(undefined as unknown);
      const nullResult = enhancedExpiryUtils.validateExpiry(null as unknown);
      const emptyResult = enhancedExpiryUtils.validateExpiry('');

      expect(undefinedResult.isValid).toBe(false);
      expect(nullResult.isValid).toBe(false);
      expect(emptyResult.isValid).toBe(false);
    });

    it('should handle item with data.expiry_at fallback', () => {
      const itemWithNestedExpiry = {
        id: 'nested-expiry',
        kind: 'entity',
        data: {
          expiry_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
        },
      };

      const graceResult = enhancedExpiryUtils.isExpiredWithGrace(itemWithNestedExpiry);
      const timeResult = enhancedExpiryUtils.getTimeRemainingExpiry(itemWithNestedExpiry);

      expect(graceResult.isExpired).toBe(false);
      expect(timeResult.isExpired).toBe(false);
      expect(graceResult.expiresAt).toBe(itemWithNestedExpiry.data.expiry_at);
    });
  });
});
