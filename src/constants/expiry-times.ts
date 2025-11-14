// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck

/**
 * P6-T6.1: Time mapping for item expiry
 * Maps predefined TTL labels to specific time periods
 */

export const EXPIRY_TIME_MAP = {
  default: 30 * 24 * 60 * 60 * 1000, // 30 days in milliseconds
  short: 24 * 60 * 60 * 1000, // 24 hours in milliseconds
  long: 90 * 24 * 60 * 60 * 1000, // 90 days in milliseconds
  permanent: Number.POSITIVE_INFINITY, // Never expires
} as const;

export type ExpiryTimeLabel = keyof typeof EXPIRY_TIME_MAP;

/**
 * Get expiry timestamp for a given label
 */
export function getExpiryTimestamp(label: ExpiryTimeLabel): string {
  if (label === 'permanent') {
    return '9999-12-31T23:59:59.999Z';
  }

  const timestamp = new Date();
  timestamp.setTime(timestamp.getTime() + EXPIRY_TIME_MAP[label]);
  return timestamp.toISOString();
}
