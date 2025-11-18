/**
 * TTL Policy Service
 *
 * Comprehensive TTL (Time-To-Live) policy management for Cortex Memory.
 * Provides configurable TTL policies with safety mechanisms and validation.
 *
 * Features:
 * - Standard TTL policies (default, short, long, permanent)
 * - Custom TTL duration support
 * - Safe override mechanisms with validation
 * - Timezone-aware expiry calculations
 * - Policy enforcement and validation
 * - Audit logging for policy changes
 *
 * @author Cortex Team
 * @version 1.0.0
 * @since 2025
 */

import { logger } from '@/utils/logger.js';

import {
  EXPIRY_TIME_MAP,
  type ExpiryTimeLabel,
  getExpiryTimestamp,
} from '../../constants/expiry-times.js';
import type { KnowledgeItem } from '../../types/core-interfaces.js';

/**
 * TTL policy configuration interface
 */
export interface TTLPolicy {
  name: string;
  description: string;
  durationMs: number;
  isPermanent: boolean;
  customExpiryAt?: string;
  safeOverride?: boolean;
  maxOverrideDays?: number;
  validationRules?: TTLValidationRule[];
}

/**
 * TTL validation rule interface
 */
export interface TTLValidationRule {
  type: 'min_duration' | 'max_duration' | 'business_hours' | 'timezone' | 'scope_restriction';
  parameter?: unknown;
  message: string;
  enabled: boolean;
}

/**
 * TTL calculation result interface
 */
export interface TTLCalculationResult {
  expiryAt: string;
  policyApplied: string;
  durationMs: number;
  isPermanent: boolean;
  warnings: string[];
  validationErrors: string[];
  appliedOverrides: string[];
}

/**
 * TTL policy application options
 */
export interface TTLPolicyOptions {
  /** Force a specific TTL policy regardless of item configuration */
  forcePolicy?: ExpiryTimeLabel | TTLPolicy;
  /** Allow safe override of existing TTL */
  allowOverride?: boolean;
  /** Enable validation rules */
  enableValidation?: boolean;
  /** Timezone for expiry calculations (default: UTC) */
  timezone?: string;
  /** Include audit information in result */
  includeAudit?: boolean;
  /** Apply business rules for specific knowledge types */
  applyBusinessRules?: boolean;
}

/**
 * Default TTL policies
 */
const DEFAULT_TTL_POLICIES: Record<ExpiryTimeLabel, TTLPolicy> = {
  default: {
    name: 'default',
    description: 'Default TTL policy - 30 days',
    durationMs: EXPIRY_TIME_MAP.default,
    isPermanent: false,
    safeOverride: true,
    maxOverrideDays: 90,
    validationRules: [
      {
        type: 'min_duration',
        parameter: 1 * 24 * 60 * 60 * 1000, // 1 day minimum
        message: 'Default TTL cannot be less than 1 day',
        enabled: true,
      },
      {
        type: 'max_duration',
        parameter: 365 * 24 * 60 * 60 * 1000, // 1 year maximum
        message: 'Default TTL cannot exceed 1 year',
        enabled: true,
      },
    ],
  },
  short: {
    name: 'short',
    description: 'Short TTL policy - 1 day',
    durationMs: EXPIRY_TIME_MAP.short,
    isPermanent: false,
    safeOverride: true,
    maxOverrideDays: 7,
    validationRules: [
      {
        type: 'max_duration',
        parameter: 7 * 24 * 60 * 60 * 1000, // 7 days maximum
        message: 'Short TTL cannot exceed 7 days',
        enabled: true,
      },
    ],
  },
  long: {
    name: 'long',
    description: 'Long TTL policy - 90 days',
    durationMs: EXPIRY_TIME_MAP.long,
    isPermanent: false,
    safeOverride: true,
    maxOverrideDays: 365,
    validationRules: [
      {
        type: 'min_duration',
        parameter: 30 * 24 * 60 * 60 * 1000, // 30 days minimum
        message: 'Long TTL must be at least 30 days',
        enabled: true,
      },
      {
        type: 'max_duration',
        parameter: 365 * 24 * 60 * 60 * 1000, // 1 year maximum
        message: 'Long TTL cannot exceed 1 year',
        enabled: true,
      },
    ],
  },
  permanent: {
    name: 'permanent',
    description: 'Permanent TTL policy - never expires',
    durationMs: EXPIRY_TIME_MAP.permanent,
    isPermanent: true,
    safeOverride: false, // Permanent cannot be overridden
    validationRules: [
      {
        type: 'scope_restriction',
        parameter: ['admin', 'system'],
        message: 'Permanent TTL requires admin or system scope',
        enabled: true,
      },
    ],
  },
};

/**
 * TTL Policy Service
 *
 * Centralized service for managing TTL policies, calculations, and validations.
 */
export class TTLPolicyService {
  private policies: Map<string, TTLPolicy> = new Map();
  private businessRulePolicies: Map<string, TTLPolicy> = new Map();

  constructor() {
    this.initializeDefaultPolicies();
    this.initializeBusinessRulePolicies();
  }

  /**
   * Initialize default TTL policies
   */
  private initializeDefaultPolicies(): void {
    for (const [key, policy] of Object.entries(DEFAULT_TTL_POLICIES)) {
      this.policies.set(key, policy);
    }
    logger.info('TTL policies initialized', {
      policies: Array.from(this.policies.keys()),
    });
  }

  /**
   * Initialize business rule-specific TTL policies
   */
  private initializeBusinessRulePolicies(): void {
    // Business rule policies for specific knowledge types
    const businessPolicies: Record<string, TTLPolicy> = {
      // Incident logs: permanent (for compliance)
      incident: {
        name: 'incident_permanent',
        description: 'Incident logs - permanent retention for compliance',
        durationMs: EXPIRY_TIME_MAP.permanent,
        isPermanent: true,
        safeOverride: false,
        validationRules: [
          {
            type: 'scope_restriction',
            parameter: ['incident', 'compliance'],
            message: 'Incident TTL requires incident or compliance scope',
            enabled: true,
          },
        ],
      },
      // Risk assessments: long retention (365 days)
      risk: {
        name: 'risk_long',
        description: 'Risk assessments - long retention for audit purposes',
        durationMs: 365 * 24 * 60 * 60 * 1000,
        isPermanent: false,
        safeOverride: true,
        maxOverrideDays: 365 * 2, // 2 years max
        validationRules: [
          {
            type: 'min_duration',
            parameter: 90 * 24 * 60 * 60 * 1000, // 90 days minimum
            message: 'Risk assessments must be retained for at least 90 days',
            enabled: true,
          },
        ],
      },
      // Decision logs: long retention (180 days)
      decision: {
        name: 'decision_long',
        description: 'Decision logs - long retention for audit trail',
        durationMs: 180 * 24 * 60 * 60 * 1000,
        isPermanent: false,
        safeOverride: true,
        maxOverrideDays: 365,
        validationRules: [
          {
            type: 'min_duration',
            parameter: 30 * 24 * 60 * 60 * 1000, // 30 days minimum
            message: 'Decision logs must be retained for at least 30 days',
            enabled: true,
          },
        ],
      },
      // Session logs: short retention (7 days)
      session: {
        name: 'session_short',
        description: 'Session logs - short retention for privacy',
        durationMs: 7 * 24 * 60 * 60 * 1000,
        isPermanent: false,
        safeOverride: true,
        maxOverrideDays: 30,
        validationRules: [
          {
            type: 'max_duration',
            parameter: 30 * 24 * 60 * 60 * 1000, // 30 days maximum for privacy
            message: 'Session logs cannot exceed 30 days for privacy compliance',
            enabled: true,
          },
        ],
      },
    };

    for (const [kind, policy] of Object.entries(businessPolicies)) {
      this.businessRulePolicies.set(kind, policy);
    }

    logger.info('Business rule TTL policies initialized', {
      policies: Array.from(this.businessRulePolicies.keys()),
    });
  }

  /**
   * Get a TTL policy by name
   */
  getPolicy(name: string): TTLPolicy | undefined {
    return this.policies.get(name) || this.businessRulePolicies.get(name);
  }

  /**
   * Get all available TTL policies
   */
  getAllPolicies(): TTLPolicy[] {
    return [...this.policies.values(), ...this.businessRulePolicies.values()];
  }

  /**
   * Register a custom TTL policy
   */
  registerPolicy(policy: TTLPolicy): void {
    // Validate policy before registration
    const validation = this.validatePolicy(policy);
    if (!validation.valid) {
      throw new Error(`Invalid TTL policy: ${validation.errors.join(', ')}`);
    }

    this.policies.set(policy.name, policy);
    logger.info('Custom TTL policy registered', {
      policyName: policy.name,
      durationMs: policy.durationMs,
      isPermanent: policy.isPermanent,
    });
  }

  /**
   * Remove a TTL policy
   */
  removePolicy(name: string): boolean {
    const removed = this.policies.delete(name);
    if (removed) {
      logger.info('TTL policy removed', { policyName: name });
    }
    return removed;
  }

  /**
   * Calculate expiry timestamp for a knowledge item
   */
  calculateExpiry(item: KnowledgeItem, options: TTLPolicyOptions = {}): TTLCalculationResult {
    const result: TTLCalculationResult = {
      expiryAt: '',
      policyApplied: '',
      durationMs: 0,
      isPermanent: false,
      warnings: [],
      validationErrors: [],
      appliedOverrides: [],
    };

    try {
      // Step 1: Determine which policy to apply
      const policy = this.determinePolicy(item, options);
      result.policyApplied = policy.name;

      // Step 2: Check for explicit expiry_at override
      if (item.data?.expiry_at && this.isValidExpiryDate(item.data.expiry_at)) {
        const overrideDate = new Date(item.data.expiry_at);
        const now = new Date();
        const overrideDuration = overrideDate.getTime() - now.getTime();

        // Validate override against policy rules
        if (policy.safeOverride && options.allowOverride !== false) {
          if (this.validateOverride(policy, overrideDuration)) {
            result.expiryAt = item.data.expiry_at;
            result.durationMs = overrideDuration;
            result.appliedOverrides.push('explicit_expiry_at');
            result.warnings.push('Using explicit expiry_at override');
          } else {
            result.validationErrors.push(
              `Explicit expiry_at override violates policy constraints for ${policy.name}`
            );
            // Fall back to policy-based calculation
            return this.calculatePolicyBasedExpiry(item, policy, result, options);
          }
        } else {
          result.warnings.push(
            `Explicit expiry_at ignored - policy ${policy.name} does not allow overrides`
          );
          return this.calculatePolicyBasedExpiry(item, policy, result, options);
        }
      } else {
        // Step 3: Calculate expiry based on policy
        return this.calculatePolicyBasedExpiry(item, policy, result, options);
      }

      // Step 4: Apply validation rules if enabled
      if (options.enableValidation !== false) {
        const validation = this.validateExpiryCalculation(result, item, policy);
        result.validationErrors.push(...validation.errors);
        result.warnings.push(...validation.warnings);
      }

      // Step 5: Apply timezone adjustment if specified
      if (options.timezone && options.timezone !== 'UTC') {
        result.expiryAt = this.adjustTimezone(result.expiryAt, options.timezone);
        result.warnings.push(`Adjusted for timezone: ${options.timezone}`);
      }

      // Step 6: Log calculation if audit is enabled
      if (options.includeAudit) {
        this.logTTLCalculation(item, result, policy, options);
      }
    } catch (error) {
      logger.error('TTL calculation failed', { error, itemId: item.id, itemType: item.kind });
      result.validationErrors.push(
        `TTL calculation failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      );

      // Fall back to default policy
      const fallbackPolicy = this.policies.get('default')!;
      return this.calculatePolicyBasedExpiry(item, fallbackPolicy, result, options);
    }

    return result;
  }

  /**
   * Determine which TTL policy to apply to an item
   */
  private determinePolicy(item: KnowledgeItem, options: TTLPolicyOptions): TTLPolicy {
    // Step 1: Check for forced policy
    if (options.forcePolicy) {
      if (typeof options.forcePolicy === 'string') {
        const policy = this.getPolicy(options.forcePolicy);
        if (policy) return policy;
      } else {
        return options.forcePolicy;
      }
    }

    // Step 2: Check business rules for specific knowledge types
    if (options.applyBusinessRules !== false) {
      const businessPolicy = this.businessRulePolicies.get(item.kind);
      if (businessPolicy) {
        return businessPolicy;
      }
    }

    // Step 3: Check item-level TTL preference
    if (item.data?.ttl) {
      const ttlPolicy = this.getPolicy(item.data.ttl);
      if (ttlPolicy) {
        return ttlPolicy;
      }
    }

    // Step 4: Use default policy
    return this.policies.get('default')!;
  }

  /**
   * Calculate expiry based on policy
   */
  private calculatePolicyBasedExpiry(
    item: KnowledgeItem,
    policy: TTLPolicy,
    result: TTLCalculationResult,
    options: TTLPolicyOptions
  ): TTLCalculationResult {
    if (policy.isPermanent) {
      result.expiryAt = '9999-12-31T23:59:59.999Z';
      result.durationMs = EXPIRY_TIME_MAP.permanent;
      result.isPermanent = true;
    } else {
      const expiryTimestamp = getExpiryTimestamp(policy.name as ExpiryTimeLabel);
      result.expiryAt = expiryTimestamp;
      result.durationMs = policy.durationMs;
      result.isPermanent = false;
    }

    return result;
  }

  /**
   * Validate TTL policy
   */
  validatePolicy(policy: TTLPolicy): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!policy.name || policy.name.trim().length === 0) {
      errors.push('Policy name is required');
    }

    if (!policy.description || policy.description.trim().length === 0) {
      errors.push('Policy description is required');
    }

    if (policy.isPermanent) {
      if (policy.durationMs !== EXPIRY_TIME_MAP.permanent) {
        errors.push('Permanent policy must have infinite duration');
      }
    } else {
      if (policy.durationMs <= 0) {
        errors.push('Duration must be positive for non-permanent policies');
      }

      if (policy.durationMs > 365 * 24 * 60 * 60 * 1000) {
        errors.push('Duration cannot exceed 1 year for non-permanent policies');
      }
    }

    return { valid: errors.length === 0, errors };
  }

  /**
   * Validate expiry override against policy
   */
  private validateOverride(policy: TTLPolicy, overrideDuration: number): boolean {
    if (!policy.safeOverride) {
      return false;
    }

    if (policy.maxOverrideDays) {
      const maxOverrideMs = policy.maxOverrideDays * 24 * 60 * 60 * 1000;
      if (overrideDuration > maxOverrideMs) {
        return false;
      }
    }

    // Check validation rules for overrides
    if (policy.validationRules) {
      for (const rule of policy.validationRules) {
        if (!rule.enabled) continue;

        switch (rule.type) {
          case 'min_duration':
            if (overrideDuration < rule.parameter) {
              return false;
            }
            break;
          case 'max_duration':
            if (overrideDuration > rule.parameter) {
              return false;
            }
            break;
        }
      }
    }

    return true;
  }

  /**
   * Validate expiry calculation result
   */
  private validateExpiryCalculation(
    result: TTLCalculationResult,
    item: KnowledgeItem,
    policy: TTLPolicy
  ): { errors: string[]; warnings: string[] } {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Validate expiry date format
    if (!this.isValidExpiryDate(result.expiryAt)) {
      errors.push('Invalid expiry date format');
    }

    // Validate expiry is in the future (unless permanent)
    if (!result.isPermanent) {
      const expiryDate = new Date(result.expiryAt);
      if (expiryDate <= new Date()) {
        errors.push('Expiry date must be in the future');
      }
    }

    // Apply validation rules
    if (policy.validationRules) {
      for (const rule of policy.validationRules) {
        if (!rule.enabled) continue;

        switch (rule.type) {
          case 'scope_restriction':
            const allowedScopes = rule.parameter as string[];
            const itemScopes = [item.scope?.org, item.scope?.project, item.scope?.branch].filter(
              Boolean
            );

            if (!itemScopes.some((scope) => scope && allowedScopes.includes(scope))) {
              errors.push(rule.message);
            }
            break;

          case 'business_hours':
            // Check if expiry is during business hours
            const expiryHour = new Date(result.expiryAt).getHours();
            if (expiryHour < 9 || expiryHour > 17) {
              warnings.push('Expiry outside business hours');
            }
            break;

          case 'timezone':
            // Validate timezone compliance
            const timezone = rule.parameter as string;
            if (timezone) {
              try {
                new Date().toLocaleString('en-US', { timeZone: timezone });
              } catch {
                errors.push(`Invalid timezone: ${timezone}`);
              }
            }
            break;
        }
      }
    }

    return { errors, warnings };
  }

  /**
   * Check if a date string is a valid expiry date
   */
  private isValidExpiryDate(dateString: string): boolean {
    if (!dateString) return false;

    try {
      const date = new Date(dateString);
      return !isNaN(date.getTime()) && dateString === date.toISOString();
    } catch {
      return false;
    }
  }

  /**
   * Adjust expiry timestamp for timezone
   */
  private adjustTimezone(isoString: string, timezone: string): string {
    try {
      const date = new Date(isoString);
      return date.toLocaleString('en-US', { timeZone: timezone });
    } catch {
      return isoString; // Return original if timezone adjustment fails
    }
  }

  /**
   * Log TTL calculation for audit purposes
   */
  private logTTLCalculation(
    item: KnowledgeItem,
    result: TTLCalculationResult,
    policy: TTLPolicy,
    options: TTLPolicyOptions
  ): void {
    logger.info('TTL calculation performed', {
      itemId: item.id,
      itemType: item.kind,
      itemScope: item.scope,
      policyApplied: result.policyApplied,
      expiryAt: result.expiryAt,
      durationMs: result.durationMs,
      isPermanent: result.isPermanent,
      warnings: result.warnings,
      validationErrors: result.validationErrors,
      appliedOverrides: result.appliedOverrides,
      options: {
        forcePolicy: options.forcePolicy,
        allowOverride: options.allowOverride,
        enableValidation: options.enableValidation,
        timezone: options.timezone,
        applyBusinessRules: options.applyBusinessRules,
      },
    });
  }

  /**
   * Get TTL policy statistics
   */
  getPolicyStatistics(): {
    totalPolicies: number;
    defaultPolicies: number;
    businessRulePolicies: number;
    policyDetails: Array<{
      name: string;
      description: string;
      durationMs: number;
      isPermanent: boolean;
      safeOverride: boolean;
    }>;
  } {
    const defaultPolicyDetails = Array.from(this.policies.values()).map((p) => ({
      name: p.name,
      description: p.description,
      durationMs: p.durationMs,
      isPermanent: p.isPermanent,
      safeOverride: p.safeOverride || false,
    }));

    const businessPolicyDetails = Array.from(this.businessRulePolicies.values()).map((p) => ({
      name: p.name,
      description: p.description,
      durationMs: p.durationMs,
      isPermanent: p.isPermanent,
      safeOverride: p.safeOverride || false,
    }));

    return {
      totalPolicies: this.policies.size + this.businessRulePolicies.size,
      defaultPolicies: this.policies.size,
      businessRulePolicies: this.businessRulePolicies.size,
      policyDetails: [...defaultPolicyDetails, ...businessPolicyDetails],
    };
  }
}

// Singleton instance
export const ttlPolicyService = new TTLPolicyService();
