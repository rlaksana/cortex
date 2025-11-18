// PHASE 2.2A RECOVERY: Hash utility synchronization complete
// Recovery Date: 2025-11-14T17:30:00+07:00 (Asia/Jakarta)
// Recovery Method: Sequential file-by-file approach with quality gates
// Dependencies: Core hashing functionality for content deduplication

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
