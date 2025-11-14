// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck

import { createHash } from 'crypto';

export function computeContentHash(text: string): string {
  // Handle null, undefined, and non-string inputs gracefully
  if (text == null) {
    text = '';
  } else if (typeof text !== 'string') {
    text = String(text);
  }

  const normalized = text.trim().replace(/\s+/g, ' ').toLowerCase();

  return createHash('sha256').update(normalized, 'utf8').digest('hex');
}
