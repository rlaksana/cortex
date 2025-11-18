// PHASE 2.2A RECOVERY: ID generator utility synchronization complete
// Recovery Date: 2025-11-14T17:50:00+07:00 (Asia/Jakarta)
// Recovery Method: Sequential file-by-file approach with quality gates
// Dependencies: Core ID generation functionality for system components

/**
 * ID Generator Utility
 * Generates unique IDs for various system components
 */

import { randomUUID } from 'crypto';

/**
 * Generates a unique ID using crypto.randomUUID()
 */
export function generateId(): string {
  return randomUUID();
}

/**
 * Generates a prefixed ID for specific types
 */
export function generatePrefixedId(prefix: string): string {
  return `${prefix}_${randomUUID()}`;
}

/**
 * Generates a short ID (8 characters)
 */
export function generateShortId(): string {
  return randomUUID().replace(/-/g, '').substring(0, 8);
}

/**
 * Generates a timestamp-based ID
 */
export function generateTimestampId(): string {
  return `${Date.now()}_${randomUUID().replace(/-/g, '').substring(0, 8)}`;
}
