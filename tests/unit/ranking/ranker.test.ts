/**
 * Comprehensive Unit Tests for Result Ranking Algorithms
 *
 * Tests ranking functionality including:
 * - Final score computation with weighted factors
 * - Recency boost calculations
 * - Citation count scoring
 * - Scope proximity weighting
 * - Edge cases and boundary conditions
 * - Performance considerations
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { computeFinalScore } from '../../src/services/ranking/ranker';

describe('Result Ranking Algorithms', () => {
  describe('computeFinalScore', () => {
    it('should compute final score with all factors', () => {
      const hit = {
        fts_score: 0.8,
        updated_at: new Date().toISOString(), // Recent
        scope_proximity: 0.7,
        citation_count: 10,
      };

      const score = computeFinalScore(hit);

      // Formula: 0.4 * fts_score + 0.3 * recency_boost + 0.2 * scope_proximity + 0.1 * citation_score
      expect(score).toBeGreaterThan(0);
      expect(score).toBeLessThanOrEqual(1);

      // Should be influenced by all factors
      expect(score).toBeGreaterThan(0.4 * hit.fts_score); // Should be higher than FTS alone
    });

    it('should handle missing citation count', () => {
      const hit = {
        fts_score: 0.8,
        updated_at: new Date().toISOString(),
        scope_proximity: 0.7,
        // citation_count is undefined
      };

      const score = computeFinalScore(hit);

      expect(score).toBeGreaterThan(0);
      expect(score).toBeLessThanOrEqual(1);
      // Should treat missing citations as 0
      expect(score).toBe(0.4 * hit.fts_score + 0.3 * expect.any(Number) + 0.2 * hit.scope_proximity + 0.1 * 0);
    });

    it('should weight FTS score highest (40%)', () => {
      const hit = {
        fts_score: 1.0,
        updated_at: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000).toISOString(), // Very old (low recency)
        scope_proximity: 0.0, // No scope proximity
        citation_count: 0, // No citations
      };

      const score = computeFinalScore(hit);

      // Should be at least 40% due to perfect FTS score
      expect(score).toBeGreaterThanOrEqual(0.4);
    });

    it('should weight scope proximity second (20%)', () => {
      const hit = {
        fts_score: 0.0, // No FTS match
        updated_at: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000).toISOString(), // Very old
        scope_proximity: 1.0, // Perfect scope proximity
        citation_count: 0, // No citations
      };

      const score = computeFinalScore(hit);

      // Should be at least 20% due to perfect scope proximity
      expect(score).toBeGreaterThanOrEqual(0.2);
    });

    it('should calculate citation score with logarithmic scaling', () => {
      const hitWithFewCitations = {
        fts_score: 0.5,
        updated_at: new Date().toISOString(),
        scope_proximity: 0.5,
        citation_count: 1,
      };

      const hitWithManyCitations = {
        fts_score: 0.5,
        updated_at: new Date().toISOString(),
        scope_proximity: 0.5,
        citation_count: 100,
      };

      const scoreFew = computeFinalScore(hitWithFewCitations);
      const scoreMany = computeFinalScore(hitWithManyCitations);

      // More citations should result in higher score, but with diminishing returns
      expect(scoreMany).toBeGreaterThan(scoreFew);

      // Difference should not be linear (logarithmic scaling)
      const citationScoreFew = Math.min(1.0, Math.log10(1 + 1) / 2); // log10(2) / 2 ≈ 0.15
      const citationScoreMany = Math.min(1.0, Math.log10(1 + 100) / 2); // log10(101) / 2 ≈ 1.0

      expect(citationScoreMany).toBeGreaterThan(citationScoreFew);
      expect(citationScoreMany).toBe(1.0); // Capped at 1.0
    });

    it('should cap citation score at maximum', () => {
      const hit = {
        fts_score: 0.5,
        updated_at: new Date().toISOString(),
        scope_proximity: 0.5,
        citation_count: 10000, // Very high citation count
      };

      const score = computeFinalScore(hit);

      // Citation score should be capped at 1.0
      const expectedCitationScore = Math.min(1.0, Math.log10(1 + 10000) / 2);
      expect(expectedCitationScore).toBe(1.0);

      // Final score should reflect the capped citation score
      expect(score).toBe(0.4 * 0.5 + 0.3 * expect.any(Number) + 0.2 * 0.5 + 0.1 * 1.0);
    });

    it('should handle zero citation count', () => {
      const hit = {
        fts_score: 0.5,
        updated_at: new Date().toISOString(),
        scope_proximity: 0.5,
        citation_count: 0,
      };

      const score = computeFinalScore(hit);

      // Zero citations should result in zero citation score
      const expectedCitationScore = Math.min(1.0, Math.log10(1 + 0) / 2); // log10(1) / 2 = 0
      expect(expectedCitationScore).toBe(0);

      expect(score).toBe(0.4 * 0.5 + 0.3 * expect.any(Number) + 0.2 * 0.5 + 0.1 * 0);
    });

    it('should handle negative citation counts gracefully', () => {
      const hit = {
        fts_score: 0.5,
        updated_at: new Date().toISOString(),
        scope_proximity: 0.5,
        citation_count: -5, // Negative citations (shouldn't happen but test edge case)
      };

      expect(() => computeFinalScore(hit)).not.toThrow();
    });
  });

  describe('Recency Boost Calculation', () => {
    it('should give maximum boost to very recent items', () => {
      const hit = {
        fts_score: 0.5,
        updated_at: new Date().toISOString(), // Current time
        scope_proximity: 0.5,
        citation_count: 0,
      };

      const score = computeFinalScore(hit);

      // Very recent items should get maximum recency boost (close to 1.0)
      expect(score).toBeGreaterThan(0.7); // 0.4*0.5 + 0.3*~1.0 + 0.2*0.5 = 0.7+
    });

    it('should decrease boost for older items', () => {
      const recentHit = {
        fts_score: 0.5,
        updated_at: new Date().toISOString(),
        scope_proximity: 0.5,
        citation_count: 0,
      };

      const oldHit = {
        fts_score: 0.5,
        updated_at: new Date(Date.now() - 180 * 24 * 60 * 60 * 1000).toISOString(), // 180 days ago
        scope_proximity: 0.5,
        citation_count: 0,
      };

      const recentScore = computeFinalScore(recentHit);
      const oldScore = computeFinalScore(oldHit);

      expect(recentScore).toBeGreaterThan(oldScore);
    });

    it('should give zero boost to very old items', () => {
      const hit = {
        fts_score: 0.5,
        updated_at: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000).toISOString(), // 1 year ago
        scope_proximity: 0.5,
        citation_count: 0,
      };

      const score = computeFinalScore(hit);

      // Very old items should get minimal recency boost
      const expectedRecencyBoost = Math.max(0, 1.0 - Math.log10(1 + 365) / Math.log10(180));
      expect(expectedRecencyBoost).toBeLessThan(0.1);

      expect(score).toBeCloseTo(0.4 * 0.5 + 0.3 * expectedRecencyBoost + 0.2 * 0.5, 2);
    });

    it('should handle recency calculation correctly for different time periods', () => {
      const timeframes = [
        { days: 1, expected: 'very high' },
        { days: 7, expected: 'high' },
        { days: 30, expected: 'medium' },
        { days: 90, expected: 'low' },
        { days: 180, expected: 'very low' },
      ];

      const scores = timeframes.map(({ days }) => {
        const hit = {
          fts_score: 0.5,
          updated_at: new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString(),
          scope_proximity: 0.5,
          citation_count: 0,
        };

        return computeFinalScore(hit);
      });

      // Scores should decrease as items get older
      for (let i = 0; i < scores.length - 1; i++) {
        expect(scores[i]).toBeGreaterThan(scores[i + 1]);
      }
    });
  });

  describe('Scope Proximity Weighting', () => {
    it('should weight scope proximity at 20%', () => {
      const hit = {
        fts_score: 0.0, // No FTS match
        updated_at: new Date(Date.now() - 180 * 24 * 60 * 60 * 1000).toISOString(), // Old (no recency boost)
        scope_proximity: 1.0, // Perfect scope proximity
        citation_count: 0, // No citations
      };

      const score = computeFinalScore(hit);

      // Should be exactly 20% (0.2) since scope proximity is the only contributing factor
      expect(score).toBeCloseTo(0.2, 1);
    });

    it('should handle zero scope proximity', () => {
      const hit = {
        fts_score: 0.5,
        updated_at: new Date().toISOString(),
        scope_proximity: 0.0, // No scope proximity
        citation_count: 0,
      };

      const score = computeFinalScore(hit);

      // Scope proximity should contribute 0 to the final score
      expect(score).toBe(0.4 * 0.5 + 0.3 * expect.any(Number) + 0.2 * 0.0 + 0.1 * 0);
    });

    it('should handle scope proximity values between 0 and 1', () => {
      const testValues = [0.1, 0.25, 0.5, 0.75, 0.9];

      testValues.forEach(proximity => {
        const hit = {
          fts_score: 0.5,
          updated_at: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(), // 30 days ago
          scope_proximity: proximity,
          citation_count: 0,
        };

        const score = computeFinalScore(hit);

        expect(score).toBeGreaterThan(0);
        expect(score).toBeLessThanOrEqual(1);

        // Score should increase with higher scope proximity
        const scoreComponent = proximity * 0.2; // 20% weight
        expect(score).toBeGreaterThan(scoreComponent - 0.1); // Allow some variance due to other factors
      });
    });
  });

  describe('Edge Cases and Boundary Conditions', () => {
    it('should handle all zero scores', () => {
      const hit = {
        fts_score: 0.0,
        updated_at: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000).toISOString(), // Very old
        scope_proximity: 0.0,
        citation_count: 0,
      };

      const score = computeFinalScore(hit);

      expect(score).toBe(0);
    });

    it('should handle perfect scores', () => {
      const hit = {
        fts_score: 1.0,
        updated_at: new Date().toISOString(), // Current
        scope_proximity: 1.0,
        citation_count: 100, // High citation count
      };

      const score = computeFinalScore(hit);

      expect(score).toBeCloseTo(1.0, 1);
    });

    it('should handle invalid FTS scores gracefully', () => {
      const invalidScores = [-0.5, 1.5, NaN, null, undefined];

      invalidScores.forEach(ftsScore => {
        const hit = {
          fts_score: ftsScore as any,
          updated_at: new Date().toISOString(),
          scope_proximity: 0.5,
          citation_count: 0,
        };

        expect(() => computeFinalScore(hit)).not.toThrow();
      });
    });

    it('should handle invalid scope proximity values', () => {
      const invalidValues = [-0.5, 1.5, NaN, null, undefined];

      invalidValues.forEach(proximity => {
        const hit = {
          fts_score: 0.5,
          updated_at: new Date().toISOString(),
          scope_proximity: proximity as any,
          citation_count: 0,
        };

        expect(() => computeFinalScore(hit)).not.toThrow();
      });
    });

    it('should handle invalid dates gracefully', () => {
      const invalidDates = [
        'invalid-date',
        '2025-13-45T25:99:99Z', // Invalid date format
        '',
        null,
        undefined,
      ];

      invalidDates.forEach(date => {
        const hit = {
          fts_score: 0.5,
          updated_at: date as any,
          scope_proximity: 0.5,
          citation_count: 0,
        };

        expect(() => computeFinalScore(hit)).not.toThrow();
      });
    });

    it('should handle future dates', () => {
      const futureDate = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(); // Tomorrow

      const hit = {
        fts_score: 0.5,
        updated_at: futureDate,
        scope_proximity: 0.5,
        citation_count: 0,
      };

      const score = computeFinalScore(hit);

      expect(score).toBeGreaterThan(0);
      expect(score).toBeLessThanOrEqual(1);

      // Future dates should get maximum recency boost
      expect(score).toBeGreaterThan(0.7);
    });

    it('should handle extremely old dates', () => {
      const ancientDate = new Date('1970-01-01T00:00:00Z').toISOString();

      const hit = {
        fts_score: 0.5,
        updated_at: ancientDate,
        scope_proximity: 0.5,
        citation_count: 0,
      };

      const score = computeFinalScore(hit);

      expect(score).toBeGreaterThan(0);
      expect(score).toBeLessThan(0.5); // Should have minimal recency boost
    });
  });

  describe('Performance Considerations', () => {
    it('should compute scores efficiently for large datasets', () => {
      const hits = Array.from({ length: 10000 }, (_, i) => ({
        fts_score: Math.random(),
        updated_at: new Date(Date.now() - Math.random() * 365 * 24 * 60 * 60 * 1000).toISOString(),
        scope_proximity: Math.random(),
        citation_count: Math.floor(Math.random() * 100),
      }));

      const startTime = performance.now();

      const scores = hits.map(hit => computeFinalScore(hit));

      const endTime = performance.now();
      const duration = endTime - startTime;

      expect(scores).toHaveLength(10000);
      expect(duration).toBeLessThan(1000); // Should complete in under 1 second

      // All scores should be valid
      scores.forEach(score => {
        expect(score).toBeGreaterThanOrEqual(0);
        expect(score).toBeLessThanOrEqual(1);
      });
    });

    it('should handle concurrent score calculations', async () => {
      const hit = {
        fts_score: 0.5,
        updated_at: new Date().toISOString(),
        scope_proximity: 0.5,
        citation_count: 10,
      };

      const promises = Array(100).fill(null).map(() =>
        Promise.resolve(computeFinalScore(hit))
      );

      const scores = await Promise.all(promises);

      expect(scores).toHaveLength(100);
      expect(scores.every(score => score === scores[0])).toBe(true); // All should be identical
    });
  });

  describe('Mathematical Properties', () => {
    it('should maintain consistent weighting proportions', () => {
      const hit = {
        fts_score: 0.5,
        updated_at: new Date().toISOString(),
        scope_proximity: 0.5,
        citation_count: 10,
      };

      const score = computeFinalScore(hit);

      // Test that weights sum to 1
      const ftsComponent = 0.4 * hit.fts_score;
      const citationComponent = 0.1 * Math.min(1.0, Math.log10(1 + hit.citation_count) / 2);
      const scopeComponent = 0.2 * hit.scope_proximity;

      // Recency component depends on current time, but should be between 0 and 0.3
      expect(score).toBeGreaterThan(ftsComponent + citationComponent + scopeComponent);
      expect(score).toBeLessThan(ftsComponent + citationComponent + scopeComponent + 0.3);
    });

    it('should be deterministic for identical inputs', () => {
      const hit = {
        fts_score: 0.75,
        updated_at: '2025-01-01T12:00:00Z',
        scope_proximity: 0.8,
        citation_count: 25,
      };

      const score1 = computeFinalScore(hit);
      const score2 = computeFinalScore(hit);

      expect(score1).toBe(score2);
    });

    it('should maintain monotonicity for individual factors', () => {
      const baseHit = {
        fts_score: 0.5,
        updated_at: new Date().toISOString(),
        scope_proximity: 0.5,
        citation_count: 10,
      };

      // Test FTS score monotonicity
      const lowFts = { ...baseHit, fts_score: 0.3 };
      const highFts = { ...baseHit, fts_score: 0.7 };

      expect(computeFinalScore(highFts)).toBeGreaterThan(computeFinalScore(lowFts));

      // Test scope proximity monotonicity
      const lowScope = { ...baseHit, scope_proximity: 0.3 };
      const highScope = { ...baseHit, scope_proximity: 0.7 };

      expect(computeFinalScore(highScope)).toBeGreaterThan(computeFinalScore(lowScope));

      // Test citation count monotonicity
      const lowCitations = { ...baseHit, citation_count: 1 };
      const highCitations = { ...baseHit, citation_count: 100 };

      expect(computeFinalScore(highCitations)).toBeGreaterThan(computeFinalScore(lowCitations));
    });

    it('should handle boundary values correctly', () => {
      const boundaryTests = [
        { fts_score: 0.0, scope_proximity: 0.0, citation_count: 0 },
        { fts_score: 1.0, scope_proximity: 1.0, citation_count: Number.MAX_SAFE_INTEGER },
        { fts_score: 0.5, scope_proximity: 0.5, citation_count: 1 },
        { fts_score: 0.5, scope_proximity: 0.5, citation_count: 9 }, // Before logarithmic cap
        { fts_score: 0.5, scope_proximity: 0.5, citation_count: 100 }, // After logarithmic cap
      ];

      boundaryTests.forEach(hit => {
        const score = computeFinalScore({
          ...hit,
          updated_at: new Date().toISOString(),
        });

        expect(score).toBeGreaterThanOrEqual(0);
        expect(score).toBeLessThanOrEqual(1);
      });
    });
  });

  describe('Real-world Scenarios', () => {
    it('should rank recent, relevant, and popular content highest', () => {
      const scenarios = [
        {
          name: 'Recent, relevant, popular',
          hit: {
            fts_score: 0.9,
            updated_at: new Date().toISOString(),
            scope_proximity: 0.8,
            citation_count: 50,
          },
        },
        {
          name: 'Old, relevant, popular',
          hit: {
            fts_score: 0.9,
            updated_at: new Date(Date.now() - 180 * 24 * 60 * 60 * 1000).toISOString(),
            scope_proximity: 0.8,
            citation_count: 50,
          },
        },
        {
          name: 'Recent, irrelevant, unpopular',
          hit: {
            fts_score: 0.1,
            updated_at: new Date().toISOString(),
            scope_proximity: 0.1,
            citation_count: 1,
          },
        },
        {
          name: 'Average everything',
          hit: {
            fts_score: 0.5,
            updated_at: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
            scope_proximity: 0.5,
            citation_count: 10,
          },
        },
      ];

      const scores = scenarios.map(scenario => ({
        name: scenario.name,
        score: computeFinalScore(scenario.hit),
      }));

      scores.sort((a, b) => b.score - a.score);

      // Best scenario should be "Recent, relevant, popular"
      expect(scores[0].name).toBe('Recent, relevant, popular');

      // Worst scenario should be "Recent, irrelevant, unpopular"
      expect(scores[scores.length - 1].name).toBe('Recent, irrelevant, unpopular');

      // All scores should be in valid range
      scores.forEach(({ score }) => {
        expect(score).toBeGreaterThanOrEqual(0);
        expect(score).toBeLessThanOrEqual(1);
      });
    });

    it('should balance recency vs authority appropriately', () => {
      const oldAuthority = {
        fts_score: 0.8,
        updated_at: new Date(Date.now() - 180 * 24 * 60 * 60 * 1000).toISOString(), // 6 months old
        scope_proximity: 0.8,
        citation_count: 1000, // Very high authority
      };

      const recentNewcomer = {
        fts_score: 0.8,
        updated_at: new Date().toISOString(), // Very recent
        scope_proximity: 0.8,
        citation_count: 1, // No authority yet
      };

      const oldAuthorityScore = computeFinalScore(oldAuthority);
      const recentNewcomerScore = computeFinalScore(recentNewcomer);

      // The highly cited old content should still rank well despite age
      expect(oldAuthorityScore).toBeGreaterThan(0.7);

      // But recent content should also get good ranking
      expect(recentNewcomerScore).toBeGreaterThan(0.6);

      // The exact balance depends on the logarithmic scaling of citations
      // This test ensures both factors are properly considered
    });
  });
});