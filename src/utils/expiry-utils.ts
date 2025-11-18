// PHASE 2.2A RECOVERY: Expiry utilities synchronization complete
// Recovery Date: 2025-11-14T17:57:00+07:00 (Asia/Jakarta)
// Recovery Method: Sequential file-by-file approach with quality gates
// Dependencies: Time calculation and expiration policies for knowledge items

/**
 * P6-T6.1: Expiry time calculation utilities
 * Handles different time formats and expiration policies
 */

import { type ExpiryTimeLabel, getExpiryTimestamp } from '../constants/expiry-times.js';
import type { KnowledgeItem } from '../types/core-interfaces.js';

/**
 * Calculate expiry timestamp for an item based on its scope and preferred time period
 */
export function calculateItemExpiry(item: KnowledgeItem, defaultTTL?: ExpiryTimeLabel): string {
  // Priority order: explicit expiry_at → scope-level TTL → default
  if (item.data.expiry_at && typeof item.data.expiry_at === 'string') {
    return item.data.expiry_at;
  }

  // Check if scope has TTL configuration (currently not supported)
  // const scopeTTL = item.scope?.ttl;
  // if (scopeTTL) {
  //   return new Date(Date.now() + scopeTTL * 1000).toISOString();
  // }

  // Apply default TTL (default if not specified)
  const expiryTimestamp = getExpiryTimestamp(defaultTTL || 'default');
  return expiryTimestamp;
}

/**
 * Check if an item has expired
 */
export function isExpired(item: KnowledgeItem): boolean {
  const expiryTime = item.expiry_at || item.data.expiry_at;
  if (!expiryTime || typeof expiryTime !== 'string') return false;

  try {
    return new Date(expiryTime) < new Date();
  } catch {
    return false; // Invalid date format
  }
}

/**
 * Get TTL in seconds for an item
 */
export function getItemTTL(item: KnowledgeItem): number {
  const expiryTime = item.expiry_at || item.data.expiry_at;
  if (!expiryTime || typeof expiryTime !== 'string') return 0;

  try {
    const expiryDate = new Date(expiryTime);
    return Math.max(0, (expiryDate.getTime() - new Date().getTime()) / 1000);
  } catch {
    return 0;
  }
}
