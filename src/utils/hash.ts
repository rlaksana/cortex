import { createHash } from 'crypto';

export function computeContentHash(text: string): string {
  const normalized = text.trim().replace(/\s+/g, ' ').toLowerCase();

  return createHash('sha256').update(normalized, 'utf8').digest('hex');
}
