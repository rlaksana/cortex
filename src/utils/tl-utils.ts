/**
 * TTL Utilities for Knowledge Items
 *
 * Provides utilities for managing TTL (Time-To-Live) policies for knowledge items,
 * including inheritance logic for chunked items and TTL calculation.
 *
 * TTL Policies:
 * - 'short': 30 days (for temporary items like PR context)
 * - 'default': 90 days (standard TTL for most items)
 * - 'long': 365 days (for important long-term items)
 * - 'permanent': no expiration (for critical records)
 *
 * @module utils/ttl-utils
 */

import type { KnowledgeItem } from '../types/core-interfaces.js';

// TTL durations in milliseconds
export const TTL_DURATIONS = {
  short: 30 * 24 * 60 * 60 * 1000, // 30 days
  default: 90 * 24 * 60 * 60 * 1000, // 90 days
  long: 365 * 24 * 60 * 60 * 1000, // 365 days
  permanent: Infinity, // No expiration
} as const;

export type TTLPolicy = keyof typeof TTL_DURATIONS;

/**
 * Get default TTL policy for a knowledge type
 */
export function getDefaultTTLPolicy(kind: string): TTLPolicy {
  // Special cases for specific knowledge types
  switch (kind) {
    case 'pr_context':
      return 'short'; // PR contexts expire after 30 days
    case 'entity':
    case 'relation':
    case 'observation':
    case 'decision':
    case 'section':
      return 'long'; // Core graph items and important documents last longer
    default:
      return 'default';
  }
}

/**
 * Calculate TTL expiration date from policy
 */
export function calculateExpirationDate(policy: TTLPolicy): Date | null {
  if (policy === 'permanent') {
    return null;
  }

  const duration = TTL_DURATIONS[policy as keyof typeof TTL_DURATIONS];
  return new Date(Date.now() + duration);
}

/**
 * Get TTL policy from item data or use default for the knowledge type
 */
export function getOrInheritTTLPolicy(item: KnowledgeItem): TTLPolicy {
  // Check if item already has TTL policy
  if (item.data.ttl_policy && isValidTTLPolicy(item.data.ttl_policy)) {
    return item.data.ttl_policy;
  }

  // Check if item has explicit expires_at
  if (item.data.expires_at) {
    // Convert expires_at to TTL policy if possible
    const expiresDate = new Date(item.data.expires_at);
    const now = new Date();
    const daysUntilExpiration = (expiresDate.getTime() - now.getTime()) / (24 * 60 * 60 * 1000);

    if (daysUntilExpiration <= 30) return 'short';
    if (daysUntilExpiration <= 90) return 'default';
    if (daysUntilExpiration <= 365) return 'long';
    return 'permanent';
  }

  // Use default TTL policy for knowledge type
  return getDefaultTTLPolicy(item.kind);
}

/**
 * Validate if a value is a valid TTL policy
 */
export function isValidTTLPolicy(policy: string): policy is TTLPolicy {
  return Object.keys(TTL_DURATIONS).includes(policy);
}

/**
 * Inherit TTL policy from parent item to child chunk
 * Child chunks should use the same TTL policy as their parent
 */
export function inheritTTLFromParent(parentItem: KnowledgeItem): {
  ttl_policy?: TTLPolicy;
  expires_at?: string;
} {
  const parentPolicy = getOrInheritTTLPolicy(parentItem);
  const expirationDate = calculateExpirationDate(parentPolicy);

  const result: { ttl_policy?: TTLPolicy; expires_at?: string } = {
    ttl_policy: parentPolicy,
  };

  if (expirationDate) {
    result.expires_at = expirationDate.toISOString();
  }

  return result;
}

/**
 * Check if an item has expired based on its TTL policy or expires_at
 */
export function isItemExpired(item: KnowledgeItem): boolean {
  // Check explicit expires_at first
  if (item.data.expires_at) {
    return new Date() > new Date(item.data.expires_at);
  }

  // Check TTL policy
  if (item.data.ttl_policy && item.created_at) {
    const policy = item.data.ttl_policy;
    if (policy === 'permanent') {
      return false;
    }

    const duration = TTL_DURATIONS[policy as keyof typeof TTL_DURATIONS];
    const createdAt = new Date(item.created_at);
    const expirationTime = createdAt.getTime() + duration;
    return Date.now() > expirationTime;
  }

  return false;
}

/**
 * Get TTL information for logging and debugging
 */
export function getTTLInfo(item: KnowledgeItem): {
  policy: TTLPolicy;
  expires_at?: string;
  is_expired: boolean;
  days_until_expiration?: number;
} {
  const policy = getOrInheritTTLPolicy(item);
  const expirationDate = calculateExpirationDate(policy);
  const isExpired = isItemExpired(item);

  let daysUntilExpiration: number | undefined;
  if (expirationDate) {
    daysUntilExpiration = Math.ceil(
      (expirationDate.getTime() - Date.now()) / (24 * 60 * 60 * 1000)
    );
  }

  const result: {
    policy: TTLPolicy;
    expires_at?: string;
    is_expired: boolean;
    days_until_expiration?: number;
  } = {
    policy,
    is_expired: isExpired,
  };

  if (expirationDate && daysUntilExpiration !== undefined) {
    result.expires_at = expirationDate.toISOString();
    result.days_until_expiration = daysUntilExpiration;
  }

  return result;
}