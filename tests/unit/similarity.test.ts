/**
 * Unit tests for similarity detection service
 */

import { describe, it, expect } from 'vitest';
import { detectContradiction } from '../../../src/services/similarity.js';

describe('Similarity Detection Service', () => {
  describe('detectContradiction', () => {
    it('should detect version number contradictions', () => {
      const existing = 'We are using PostgreSQL 17 for the database';
      const newContent = 'Actually, we use PostgreSQL 18 now';

      const result = detectContradiction(existing, newContent);

      expect(result).toBe(true);
    });

    it('should detect boolean contradictions', () => {
      const existing = 'Auto-save is enabled for this feature';
      const newContent = 'Auto-save should be disabled';

      const result = detectContradiction(existing, newContent);

      expect(result).toBe(true);
    });

    it('should NOT detect contradiction for compatible statements', () => {
      const existing = 'We use PostgreSQL for persistence';
      const newContent = 'PostgreSQL handles our data storage efficiently';

      const result = detectContradiction(existing, newContent);

      expect(result).toBe(false);
    });

    it('should detect use/dont-use contradictions', () => {
      const existing = 'We use OAuth 2.0 for authentication';
      const newContent = "We don't use OAuth anymore";

      const result = detectContradiction(existing, newContent);

      expect(result).toBe(true);
    });

    it('should detect true/false contradictions', () => {
      const existing = 'This feature is enabled by default (true)';
      const newContent = 'This feature is disabled (false)';

      const result = detectContradiction(existing, newContent);

      expect(result).toBe(true);
    });

    it('should handle empty strings gracefully', () => {
      const result = detectContradiction('', 'some content');
      expect(result).toBe(false);
    });

    it('should be case-insensitive', () => {
      const existing = 'POSTGRESQL 17';
      const newContent = 'postgresql 18';

      const result = detectContradiction(existing, newContent);

      expect(result).toBe(true);
    });
  });
});
