import {
  sanitizeQuery,
  extractCoreKeywords,
  suggestSanitizationLevel,
  isLikelyToCauseTsqueryError,
  generateSanitizationFeedback,
  generateSanitizationOptions,
  type SanitizationLevel,
  type SanitizationResult
} from '../../../src/utils/query-sanitizer';

describe('Query Sanitizer', () => {
  describe('sanitizeQuery', () => {
    it('should handle simple queries without changes', () => {
      const query = 'database schema design';
      const result = sanitizeQuery(query);

      expect(result.original).toBe(query);
      expect(result.cleaned).toBe(query);
      expect(result.transformations).toEqual(['normalized_whitespace']);
      expect(result.level).toBe('basic');
      expect(result.auto_fixes_applied).toEqual([]);
    });

    it('should normalize whitespace', () => {
      const query = '   database   schema   design   ';
      const result = sanitizeQuery(query);

      expect(result.cleaned).toBe('database schema design');
      expect(result.transformations).toContain('normalized_whitespace');
    });

    it('should handle task ID ranges', () => {
      const query = 'T008-T021 task completion';
      const result = sanitizeQuery(query);

      expect(result.cleaned).toBe('T008 T021 task completion');
      expect(result.patterns_detected).toContain('task_id_range');
      expect(result.auto_fixes_applied).toContain('Convert task ID ranges to space-separated format');
    });

    it('should handle version/phase numbers', () => {
      const query = 'Phase-2 implementation details';
      const result = sanitizeQuery(query, 'moderate');

      expect(result.cleaned).toBe('Phase 2 implementation details');
      expect(result.patterns_detected).toContain('version_numbers');
      expect(result.auto_fixes_applied).toContain('Normalize version/phase number formatting');
    });

    it('should handle special characters', () => {
      const query = 'API#key@special$characters&test';
      const result = sanitizeQuery(query, 'moderate');

      expect(result.cleaned).toBe('API key special characters test');
      expect(result.patterns_detected).toContain('special_chars');
    });

    it('should handle aggressive sanitization with keyword extraction', () => {
      const query = 'the database schema design and implementation plan';
      const result = sanitizeQuery(query, 'aggressive');

      expect(result.cleaned).toBe('database schema design implementation');
      expect(result.level).toBe('aggressive');
      expect(result.transformations).toContain('aggressive_sanitization');
    });

    it('should detect multiple patterns', () => {
      const query = 'T008-T021 Phase-2 API#test implementation';
      const result = sanitizeQuery(query, 'moderate');

      expect(result.patterns_detected).toContain('task_id_range');
      expect(result.patterns_detected).toContain('version_numbers');
      expect(result.patterns_detected).toContain('special_chars');
      expect(result.auto_fixes_applied.length).toBe(3);
    });
  });

  describe('extractCoreKeywords', () => {
    it('should remove stop words', () => {
      const query = 'the database schema design and implementation';
      const keywords = extractCoreKeywords(query, 5);

      expect(keywords).toBe('database schema design implementation');
    });

    it('should respect maxWords limit', () => {
      const query = 'database schema design implementation plan and testing';
      const keywords = extractCoreKeywords(query, 3);

      expect(keywords).toBe('database schema design');
    });

    it('should filter out short words', () => {
      const query = 'a an the db design';
      const keywords = extractCoreKeywords(query, 10);

      expect(keywords).toBe('design');
    });

    it('should handle empty query', () => {
      const keywords = extractCoreKeywords('');

      expect(keywords).toBe('');
    });
  });

  describe('suggestSanitizationLevel', () => {
    it('should suggest basic level for clean queries', () => {
      const query = 'database schema design';
      const level = suggestSanitizationLevel(query);

      expect(level).toBe('basic');
    });

    it('should suggest moderate level for task ID ranges', () => {
      const query = 'T008-T021 task completion';
      const level = suggestSanitizationLevel(query);

      expect(level).toBe('moderate');
    });

    it('should suggest aggressive level for many problematic patterns', () => {
      const query = 'T008-T021 Phase-2 API#test & implementation';
      const level = suggestSanitizationLevel(query);

      expect(level).toBe('aggressive');
    });
  });

  describe('isLikelyToCauseTsqueryError', () => {
    it('should detect task ID ranges as problematic', () => {
      const query = 'T008-T021 task completion';
      const result = isLikelyToCauseTsqueryError(query);

      expect(result).toBe(true);
    });

    it('should detect special characters as problematic', () => {
      const query = 'API#key test';
      const result = isLikelyToCauseTsqueryError(query);

      expect(result).toBe(true);
    });

    it('should not detect clean queries as problematic', () => {
      const query = 'database schema design';
      const result = isLikelyToCauseTsqueryError(query);

      expect(result).toBe(false);
    });
  });

  describe('generateSanitizationFeedback', () => {
    it('should generate feedback for unchanged query', () => {
      const result: SanitizationResult = {
        cleaned: 'database schema design',
        original: 'database schema design',
        transformations: ['normalized_whitespace'],
        level: 'basic',
        patterns_detected: [],
        auto_fixes_applied: []
      };

      const feedback = generateSanitizationFeedback(result);

      expect(feedback).toContain('contains no problematic characters');
    });

    it('should generate feedback for corrected query', () => {
      const result: SanitizationResult = {
        cleaned: 'T008 T021 task completion',
        original: 'T008-T021 task completion',
        transformations: ['moderate_sanitization'],
        level: 'moderate',
        patterns_detected: ['task_id_range'],
        auto_fixes_applied: ['Convert task ID ranges to space-separated format']
      };

      const feedback = generateSanitizationFeedback(result);

      expect(feedback).toContain('T008-T021');
      expect(feedback).toContain('T008 T021');
      expect(feedback).toContain('task_id_range');
    });
  });

  describe('generateSanitizationOptions', () => {
    it('should generate all three sanitization levels', () => {
      const query = 'T008-T021 Phase-2 test';
      const options = generateSanitizationOptions(query);

      expect(options.basic).toBeDefined();
      expect(options.moderate).toBeDefined();
      expect(options.aggressive).toBeDefined();

      expect(options.basic.level).toBe('basic');
      expect(options.moderate.level).toBe('moderate');
      expect(options.aggressive.level).toBe('aggressive');
    });

    it('should show different cleaning levels for the same query', () => {
      const query = 'T008-T021 Phase-2 the implementation';
      const options = generateSanitizationOptions(query);

      expect(options.basic.cleaned).toBe('T008 T021 Phase 2 the implementation');
      expect(options.aggressive.cleaned).toBe('T008 Phase 2 implementation');
    });
  });

  describe('edge cases', () => {
    it('should handle empty query', () => {
      const result = sanitizeQuery('');
      expect(result.original).toBe('');
      expect(result.cleaned).toBe('');
    });

    it('should handle whitespace-only query', () => {
      const result = sanitizeQuery('   ');
      expect(result.cleaned).toBe('');
    });

    it('should handle unicode characters', () => {
      const result = sanitizeQuery('résumé café 设计');
      expect(result.level).toBe('basic');
      expect(result.patterns_detected).toEqual([]);
    });

    it('should handle very long queries', () => {
      const longQuery = 'database schema design implementation'.repeat(10);
      const result = sanitizeQuery(longQuery);

      expect(result.original).toBe(longQuery);
      expect(result.cleaned).toContain('database schema design');
    });
  });
});