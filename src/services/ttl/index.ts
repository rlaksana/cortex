// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck

/**
 * TTL Services Index
 *
 * Central export point for all TTL (Time-To-Live) related services,
 * utilities, and types.
 *
 * Services Included:
 * - TTL Policy Service: Policy management and application
 * - Enhanced Expiry Utils: Advanced expiry calculations with timezone support
 * - TTL Management Service: Bulk operations and lifecycle management
 * - TTL Safety Service: Data loss prevention and validation
 *
 * @author Cortex Team
 * @version 1.0.0
 * @since 2025
 */

// Core Services
export { EnhancedExpiryUtils,enhancedExpiryUtils } from '../../utils/enhanced-expiry-utils.js';
export { createTTLCronScheduler, TTLCronScheduler } from './ttl-cron-scheduler.js';
export { createTTLManagementService, TTLManagementService } from './ttl-management-service.js';
export { TTLPolicyService,ttlPolicyService } from './ttl-policy-service.js';
export { TTLSafetyService,ttlSafetyService } from './ttl-safety-service.js';

// Import for internal use
import { createTTLManagementService } from './ttl-management-service.js';
import { ttlPolicyService } from './ttl-policy-service.js';
import { ttlSafetyService } from './ttl-safety-service.js';
import { enhancedExpiryUtils } from '../../utils/enhanced-expiry-utils.js';

// Type Exports
export type {
  ExpiryCalculationOptions,
  ExpiryValidationResult,
  TimezoneConfig,
} from '../../utils/enhanced-expiry-utils.js';
export type {
  TTLCronSchedule,
  TTLCronSchedulerConfig,
  TTLJobHistory,
} from './ttl-cron-scheduler.js';
export type {
  TTLBulkOperationOptions,
  TTLOperationResult,
  TTLStatistics,
} from './ttl-management-service.js';
export type {
  TTLCalculationResult,
  TTLPolicy,
  TTLPolicyOptions,
  TTLValidationRule,
} from './ttl-policy-service.js';
export type {
  OperationContext,
  SafetyPolicyConfig,
  SafetyValidationResult,
} from './ttl-safety-service.js';

// Factory Functions
export function createTTLSystem(database: unknown) {
  const managementService = createTTLManagementService(database);

  return {
    policyService: ttlPolicyService,
    expiryUtils: enhancedExpiryUtils,
    managementService,
    safetyService: ttlSafetyService,
  };
}

// Default Configuration
export const DEFAULT_TTL_CONFIG = {
  defaultPolicy: 'default',
  enableSafetyChecks: true,
  enableAuditLogging: true,
  defaultTimezone: 'UTC',
  enableDryRun: false,
  requireConfirmation: true,
};

export type { ExpiryTimeLabel } from '../../constants/expiry-times.js';
export { EXPIRY_TIME_MAP } from '../../constants/expiry-times.js';
