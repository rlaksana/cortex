import { createHash } from 'node:crypto';

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
