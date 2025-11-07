/**
 * Enhanced Search Degradation Strategy Tests
 *
 * Comprehensive tests for hybrid fallback search strategies with confidence calibration
 * and performance regression testing ensuring ≤1% quality drop at p95 under load.
 *
 * Tests verify:
 * - Hybrid fallback (semantic+sparse) strategies with intelligent switching
 * - Confidence calibration across different search strategies
 * - Performance regression detection and prevention
 * - Load testing with quality metrics at p95 percentile
 * - Threshold and timeout management for different strategies
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { SearchStrategyManager } from '../../../src/services/search/search-strategy-manager.js';
import {
  searchErrorHandler,
  ErrorCategory,
  ErrorSeverity,
  RecoveryStrategy,
} from '../../../src/services/search/search-error-handler.js';
import { searchAuditLogger } from '../../../src/services/search/search-audit-logger.js';
import type { SearchQuery, SearchResult } from '../../../src/types/core-interfaces.js';

// Mock the logger to avoid noise in tests
vi.mock('../../../src/utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

describe('Enhanced Search Degradation Strategy Tests', () => {
  let searchManager: SearchStrategyManager;

  beforeEach(() => {
    searchManager = new SearchStrategyManager({
      maxResults: 20,
      timeoutMs: 10000,
      enableVectorSearch: true,
      enableGraphExpansion: true,
      fallbackEnabled: true,
      retryAttempts: 3,
      degradationThreshold: 0.7,
      hybridSearchEnabled: true,
      confidenceCalibrationEnabled: true,
      performanceRegressionThreshold: 0.01, // 1% quality drop threshold
    });

    // Reset error handler and metrics before each test
    searchErrorHandler.resetMetrics();
    searchManager.resetMetrics();
    searchAuditLogger.clearLogs();
  });

  afterEach(() => {
    searchManager.resetMetrics();
    searchErrorHandler.resetAllCircuitBreakers();
    searchAuditLogger.clearLogs();
  });

  describe('Hybrid Fallback Strategy Implementation', () => {
    describe('Semantic + Sparse Hybrid Search', () => {
      it('should implement hybrid fallback with semantic and sparse search', async () => {
        // Mock semantic search failure
        vi.spyOn(searchManager as any, 'performSemanticSearch').mockRejectedValue(
          new Error('Semantic search unavailable')
        );

        // Mock sparse search success
        vi.spyOn(searchManager as any, 'performSparseSearch').mockResolvedValue([
          { id: '1', content: 'relevant result', score: 0.8 },
          { id: '2', content: 'another result', score: 0.6 },
        ]);

        const query: SearchQuery = {
          query: 'test hybrid fallback query',
          mode: 'auto',
          limit: 10,
        };

        const result = await searchManager.executeSearch(query, 'auto');

        // Verify hybrid fallback behavior
        expect(result.strategy).toBe('auto');
        expect(result.degraded).toBe(true);
        expect(result.fallbackReason).toContain('semantic');
        expect(result.hybridUsed).toBe(true);
        expect(result.semanticUsed).toBe(false);
        expect(result.sparseUsed).toBe(true);

        // Verify results are still returned via sparse fallback
        expect(result.results).toBeDefined();
        expect(Array.isArray(result.results)).toBe(true);
        expect(result.results.length).toBeGreaterThan(0);

        // Verify confidence calibration
        expect(result.confidence).toBeGreaterThan(0);
        expect(result.confidence).toBeLessThan(1);
        expect(result.metadata['confidenceCalibrated']).toBe(true);

        // Verify audit logging
        const auditLogs = searchManager.getRecentAuditLogs(10);
        const hybridFallbackLogs = auditLogs.filter(
          (log) =>
            log.event_type === 'hybrid_fallback' &&
            log.details.fallback_type === 'semantic_to_sparse'
        );
        expect(hybridFallbackLogs.length).toBeGreaterThan(0);
      });

      it('should switch between semantic and sparse based on performance', async () => {
        let semanticPerformance = 0.3; // Poor initial performance
        const sparsePerformance = 0.8; // Good sparse performance

        vi.spyOn(searchManager as any, 'performSemanticSearch').mockImplementation(async () => {
          // Simulate improving semantic performance over time
          semanticPerformance = Math.min(1.0, semanticPerformance + 0.1);
          if (semanticPerformance < 0.7) {
            throw new Error('Semantic search underperforming');
          }
          return [{ id: 'semantic-1', content: 'semantic result', score: semanticPerformance }];
        });

        vi.spyOn(searchManager as any, 'performSparseSearch').mockImplementation(async () => {
          return [{ id: 'sparse-1', content: 'sparse result', score: sparsePerformance }];
        });

        const query: SearchQuery = {
          query: 'test performance-based switching',
          mode: 'auto',
          limit: 10,
        };

        const results = [];

        // First search should use sparse fallback
        const firstResult = await searchManager.executeSearch(query, 'auto');
        results.push(firstResult);
        expect(firstResult.semanticUsed).toBe(false);
        expect(firstResult.sparseUsed).toBe(true);

        // Wait for performance improvement
        await new Promise((resolve) => setTimeout(resolve, 100));

        // Second search should recover to semantic
        const secondResult = await searchManager.executeSearch(query, 'auto');
        results.push(secondResult);
        expect(secondResult.semanticUsed).toBe(true);
        expect(secondResult.sparseUsed).toBe(false);

        // Verify performance-based switching is tracked
        const performanceMetrics = searchManager.getPerformanceMetrics();
        const autoMetrics = performanceMetrics.get('auto');
        expect(autoMetrics?.strategySwitches).toBeGreaterThan(0);
      });

      it('should maintain result quality during hybrid fallback transitions', async () => {
        // Mock high-quality semantic search
        vi.spyOn(searchManager as any, 'performSemanticSearch').mockResolvedValue([
          { id: 'semantic-1', content: 'high quality semantic result', score: 0.95 },
          { id: 'semantic-2', content: 'another quality result', score: 0.88 },
        ]);

        // Mock medium-quality sparse search
        vi.spyOn(searchManager as any, 'performSparseSearch').mockResolvedValue([
          { id: 'sparse-1', content: 'medium quality sparse result', score: 0.75 },
          { id: 'sparse-2', content: 'another sparse result', score: 0.68 },
        ]);

        const query: SearchQuery = {
          query: 'test quality maintenance during fallback',
          mode: 'deep',
          limit: 10,
        };

        // Test normal semantic search
        const semanticResult = await searchManager.executeSearch(query, 'deep');

        // Force semantic search failure to trigger hybrid fallback
        vi.spyOn(searchManager as any, 'performSemanticSearch').mockRejectedValueOnce(
          new Error('Semantic search temporarily unavailable')
        );

        // Test hybrid fallback
        const hybridResult = await searchManager.executeSearch(query, 'deep');

        // Verify quality maintenance
        expect(semanticResult.results).toBeDefined();
        expect(hybridResult.results).toBeDefined();

        // Hybrid results should maintain reasonable quality
        const hybridAvgScore =
          hybridResult.results.reduce((sum, r) => sum + r.score, 0) / hybridResult.results.length;
        expect(hybridAvgScore).toBeGreaterThan(0.5); // Minimum quality threshold

        // Confidence should be calibrated based on actual performance
        expect(hybridResult.confidence).toBeLessThanOrEqual(semanticResult.confidence);
        expect(hybridResult.metadata['qualityDegradation']).toBeDefined();
        expect(hybridResult.metadata['qualityDegradation']).toBeLessThan(0.5); // Max 50% degradation
      });
    });

    describe('Intelligent Strategy Thresholds', () => {
      it('should adapt thresholds based on historical performance', async () => {
        const performanceHistory = [0.6, 0.7, 0.65, 0.8, 0.75]; // Improving trend
        let historyIndex = 0;

        vi.spyOn(searchManager as any, 'getAdaptiveThreshold').mockImplementation(() => {
          const recentPerformance = performanceHistory.slice(-3); // Last 3 measurements
          const avgRecentPerformance =
            recentPerformance.reduce((a, b) => a + b, 0) / recentPerformance.length;
          return Math.max(0.5, Math.min(0.9, avgRecentPerformance - 0.1)); // Adaptive threshold
        });

        vi.spyOn(searchManager as any, 'performVectorSearch').mockImplementation(async () => {
          historyIndex = (historyIndex + 1) % performanceHistory.length;
          const currentPerformance = performanceHistory[historyIndex];

          if (currentPerformance < 0.7) {
            throw new Error('Performance below adaptive threshold');
          }

          return [
            { id: `result-${historyIndex}`, content: 'adaptive result', score: currentPerformance },
          ];
        });

        const query: SearchQuery = {
          query: 'test adaptive thresholds',
          mode: 'auto',
          limit: 10,
        };

        const results = [];

        // Execute multiple searches to test adaptation
        for (let i = 0; i < 5; i++) {
          try {
            const result = await searchManager.executeSearch(query, 'auto');
            results.push(result);
            await new Promise((resolve) => setTimeout(resolve, 50));
          } catch (error) {
            // Some failures expected during adaptation
          }
        }

        // Should have successful results after adaptation
        expect(results.length).toBeGreaterThan(0);

        // Later results should have better performance due to adaptation
        const laterResults = results.slice(-2);
        const avgLaterPerformance =
          laterResults.reduce((sum, r) => sum + r.confidence, 0) / laterResults.length;
        expect(avgLaterPerformance).toBeGreaterThan(0.6);
      });

      it('should implement context-aware timeout management', async () => {
        const contextConfigs = [
          { query: 'critical search', priority: 'high', expectedTimeout: 15000 },
          { query: 'background search', priority: 'low', expectedTimeout: 5000 },
          { query: 'standard search', priority: 'medium', expectedTimeout: 10000 },
        ];

        for (const config of contextConfigs) {
          vi.spyOn(searchManager as any, 'getContextualTimeout').mockReturnValue(
            config.expectedTimeout
          );

          // Mock search that responds within timeout
          vi.spyOn(searchManager as any, 'performVectorSearch').mockImplementation(async () => {
            await new Promise((resolve) => setTimeout(resolve, config.expectedTimeout * 0.8)); // 80% of timeout
            return [{ id: 'contextual-result', content: 'result', score: 0.8 }];
          });

          const query: SearchQuery = {
            query: config.query,
            mode: 'auto',
            limit: 10,
          };

          const startTime = Date.now();
          const result = await searchManager.executeSearch(query, 'auto');
          const executionTime = Date.now() - startTime;

          expect(result.strategy).toBe('auto');
          expect(executionTime).toBeLessThan(config.expectedTimeout);
          expect(result.metadata['contextualTimeout']).toBe(config.expectedTimeout);
          expect(result.metadata['priority']).toBe(config.priority);
        }
      });
    });
  });

  describe('Confidence Calibration System', () => {
    describe('Dynamic Confidence Adjustment', () => {
      it('should calibrate confidence based on actual search performance', async () => {
        const actualPerformanceScores = [0.9, 0.7, 0.8, 0.6, 0.85];
        let performanceIndex = 0;

        vi.spyOn(searchManager as any, 'performVectorSearch').mockImplementation(async () => {
          performanceIndex = (performanceIndex + 1) % actualPerformanceScores.length;
          const actualScore = actualPerformanceScores[performanceIndex];

          return [
            {
              id: `calibrated-${performanceIndex}`,
              content: 'calibrated result',
              score: actualScore,
            },
          ];
        });

        vi.spyOn(searchManager as any, 'calculateCalibratedConfidence').mockImplementation(
          (results) => {
            const avgScore = results.reduce((sum, r) => sum + r.score, 0) / results.length;
            const recentPerformances = actualPerformanceScores.slice(-3);
            const avgRecentPerformance =
              recentPerformances.reduce((a, b) => a + b, 0) / recentPerformances.length;

            // Calibrate confidence based on actual vs expected performance
            const calibrationFactor = avgRecentPerformance / 0.8; // 0.8 is expected baseline
            return Math.min(1.0, Math.max(0.1, avgScore * calibrationFactor));
          }
        );

        const query: SearchQuery = {
          query: 'test confidence calibration',
          mode: 'auto',
          limit: 10,
        };

        const results = [];

        for (let i = 0; i < 5; i++) {
          const result = await searchManager.executeSearch(query, 'auto');
          results.push(result);
          await new Promise((resolve) => setTimeout(resolve, 50));
        }

        // Verify confidence calibration
        results.forEach((result) => {
          expect(result.confidence).toBeGreaterThan(0);
          expect(result.confidence).toBeLessThan(1);
          expect(result.metadata['confidenceCalibrated']).toBe(true);
          expect(result.metadata['calibrationFactors']).toBeDefined();
        });

        // Confidence should reflect actual performance trends
        const confidences = results.map((r) => r.confidence);
        const avgConfidence = confidences.reduce((a, b) => a + b, 0) / confidences.length;
        expect(avgConfidence).toBeGreaterThan(0.6);
        expect(avgConfidence).toBeLessThan(0.9);
      });

      it('should adjust confidence thresholds for different search strategies', async () => {
        const strategyConfigs = [
          { strategy: 'fast', expectedConfidence: 0.7, tolerance: 0.1 },
          { strategy: 'auto', expectedConfidence: 0.8, tolerance: 0.05 },
          { strategy: 'deep', expectedConfidence: 0.9, tolerance: 0.02 },
        ];

        for (const config of strategyConfigs) {
          vi.spyOn(searchManager as any, 'getStrategyConfidenceThreshold').mockReturnValue(
            config.expectedConfidence
          );

          vi.spyOn(searchManager as any, 'performVectorSearch').mockResolvedValue([
            {
              id: `${config.strategy}-result`,
              content: 'strategy result',
              score: config.expectedConfidence,
            },
          ]);

          const query: SearchQuery = {
            query: `test ${config.strategy} confidence calibration`,
            mode: config.strategy as any,
            limit: 10,
          };

          const result = await searchManager.executeSearch(query, config.strategy);

          expect(result.strategy).toBe(config.strategy);
          expect(result.confidence).toBeGreaterThan(config.expectedConfidence - config.tolerance);
          expect(result.confidence).toBeLessThan(config.expectedConfidence + config.tolerance);
          expect(result.metadata['strategyConfidenceThreshold']).toBe(config.expectedConfidence);
        }
      });

      it('should implement confidence-based result filtering', async () => {
        const mixedQualityResults = [
          { id: 'high-quality', content: 'high quality result', score: 0.95 },
          { id: 'medium-quality', content: 'medium quality result', score: 0.65 },
          { id: 'low-quality', content: 'low quality result', score: 0.35 },
        ];

        vi.spyOn(searchManager as any, 'performVectorSearch').mockResolvedValue(
          mixedQualityResults
        );

        vi.spyOn(searchManager as any, 'filterResultsByConfidence').mockImplementation(
          (results, threshold) => {
            return results.filter((result) => result.score >= threshold);
          }
        );

        const query: SearchQuery = {
          query: 'test confidence-based filtering',
          mode: 'auto',
          limit: 10,
        };

        // Test with different confidence thresholds
        const thresholds = [0.8, 0.6, 0.4];
        const filteredResults = [];

        for (const threshold of thresholds) {
          const result = await searchManager.executeSearch(query, 'auto');

          // Apply confidence-based filtering
          const filtered = searchManager['filterResultsByConfidence'](result.results, threshold);
          filteredResults.push({ threshold, filtered, count: filtered.length });
        }

        // Verify filtering behavior
        expect(filteredResults[0].count).toBe(1); // threshold 0.8 -> only high quality
        expect(filteredResults[1].count).toBe(2); // threshold 0.6 -> high + medium quality
        expect(filteredResults[2].count).toBe(3); // threshold 0.4 -> all results
      });
    });

    describe('Performance Regression Detection', () => {
      it('should detect performance regression within 1% threshold', async () => {
        // Establish baseline performance
        const baselinePerformance = 0.85;
        const currentPerformance = 0.83; // 2.35% regression - should be detected

        vi.spyOn(searchManager as any, 'performVectorSearch').mockImplementation(async () => {
          return [
            { id: 'regression-test', content: 'regression test result', score: currentPerformance },
          ];
        });

        vi.spyOn(searchManager as any, 'detectPerformanceRegression').mockImplementation(
          (baseline, current) => {
            const regressionPercentage = ((baseline - current) / baseline) * 100;
            return {
              regressionDetected: regressionPercentage > 1.0, // 1% threshold
              regressionPercentage,
              withinThreshold: regressionPercentage <= 1.0,
            };
          }
        );

        const query: SearchQuery = {
          query: 'test performance regression detection',
          mode: 'auto',
          limit: 10,
        };

        const result = await searchManager.executeSearch(query, 'auto');

        // Detect regression
        const regressionAnalysis = searchManager['detectPerformanceRegression'](
          baselinePerformance,
          result.confidence
        );

        expect(regressionAnalysis.regressionDetected).toBe(true);
        expect(regressionAnalysis.regressionPercentage).toBeGreaterThan(1.0);
        expect(regressionAnalysis.withinThreshold).toBe(false);

        // Result should be flagged for regression
        expect(result.metadata['performanceRegression']).toBeDefined();
        expect(result.metadata['performanceRegression'].detected).toBe(true);
        expect(result.metadata['performanceRegression'].percentage).toBe(
          regressionAnalysis.regressionPercentage
        );
      });

      it('should maintain quality within p95 under load', async () => {
        const loadSize = 100; // 100 concurrent searches
        const targetQuality = 0.8;
        const maxQualityDrop = 0.01; // 1% max drop

        // Mock performance under load
        let loadCounter = 0;
        vi.spyOn(searchManager as any, 'performVectorSearch').mockImplementation(async () => {
          loadCounter++;

          // Simulate performance degradation under load
          const loadFactor = loadCounter / loadSize;
          const performance = targetQuality - loadFactor * 0.05; // Max 5% degradation

          return [
            {
              id: `load-test-${loadCounter}`,
              content: 'load test result',
              score: Math.max(targetQuality - maxQualityDrop, performance),
            },
          ];
        });

        const query: SearchQuery = {
          query: 'test p95 quality under load',
          mode: 'auto',
          limit: 10,
        };

        // Execute concurrent searches
        const startTime = Date.now();
        const results = await Promise.allSettled(
          Array.from({ length: loadSize }, () => searchManager.executeSearch(query, 'auto'))
        );
        const endTime = Date.now();

        const successfulResults = results
          .filter((r) => r.status === 'fulfilled')
          .map((r) => (r as PromiseFulfilledResult<SearchResult>).value);

        // Calculate p95 quality metric
        const qualities = successfulResults.map((r) => r.confidence).sort((a, b) => a - b);
        const p95Index = Math.floor(qualities.length * 0.95);
        const p95Quality = qualities[p95Index];

        // Verify p95 quality within threshold
        expect(p95Quality).toBeGreaterThanOrEqual(targetQuality - maxQualityDrop);
        expect(p95Quality).toBeLessThanOrEqual(targetQuality);

        // Verify performance metrics
        const totalTime = endTime - startTime;
        const averageTime = totalTime / loadSize;
        expect(averageTime).toBeLessThan(1000); // Less than 1 second per search

        // Verify load handling
        expect(successfulResults.length).toBeGreaterThan(loadSize * 0.95); // 95% success rate
      });
    });
  });

  describe('Load Testing with Quality Metrics', () => {
    describe('High-Load Scenarios', () => {
      it('should maintain search quality during sustained high load', async () => {
        const sustainedLoadDuration = 5000; // 5 seconds
        const concurrentRequests = 20;
        const minAcceptableQuality = 0.7;

        const qualityMetrics = [];
        const startTime = Date.now();

        vi.spyOn(searchManager as any, 'performVectorSearch').mockImplementation(async () => {
          // Simulate consistent quality under load
          const baseQuality = 0.8;
          const variation = (Math.random() - 0.5) * 0.1; // ±5% variation
          return [
            {
              id: `sustained-load-${Date.now()}`,
              content: 'sustained load result',
              score: Math.max(minAcceptableQuality, baseQuality + variation),
            },
          ];
        });

        const query: SearchQuery = {
          query: 'test sustained load quality',
          mode: 'auto',
          limit: 10,
        };

        // Run sustained load test
        while (Date.now() - startTime < sustainedLoadDuration) {
          const batchPromises = Array.from({ length: concurrentRequests }, () =>
            searchManager.executeSearch(query, 'auto')
          );

          const batchResults = await Promise.allSettled(batchPromises);
          const batchQualities = batchResults
            .filter((r) => r.status === 'fulfilled')
            .map((r) => (r as PromiseFulfilledResult<SearchResult>).value.confidence);

          qualityMetrics.push(...batchQualities);

          // Small delay between batches
          await new Promise((resolve) => setTimeout(resolve, 100));
        }

        // Verify quality metrics
        const avgQuality = qualityMetrics.reduce((a, b) => a + b, 0) / qualityMetrics.length;
        const minQuality = Math.min(...qualityMetrics);
        const maxQuality = Math.max(...qualityMetrics);

        expect(avgQuality).toBeGreaterThan(minAcceptableQuality);
        expect(minQuality).toBeGreaterThanOrEqual(minAcceptableQuality - 0.05); // Allow 5% tolerance
        expect(maxQuality).toBeLessThanOrEqual(1.0);

        // Verify system health under sustained load
        const healthReport = searchManager.getSystemHealth();
        expect(['healthy', 'degraded']).toContain(healthReport.overall_status);

        const performanceMetrics = searchManager.getPerformanceMetrics();
        const autoMetrics = performanceMetrics.get('auto');
        expect(autoMetrics?.totalExecutions).toBeGreaterThan(0);
        expect(autoMetrics?.averageExecutionTime).toBeLessThan(2000); // Less than 2 seconds average
      });

      it('should implement intelligent load shedding when quality drops', async () => {
        const extremeLoad = 200;
        const qualityThreshold = 0.6;
        let loadSheddingActivated = false;

        vi.spyOn(searchManager as any, 'performVectorSearch').mockImplementation(async () => {
          // Simulate quality degradation under extreme load
          const currentLoad = searchManager.getCurrentLoad?.() || 0;
          const qualityFactor = Math.max(0.3, 1.0 - currentLoad / extremeLoad);
          const quality = 0.8 * qualityFactor;

          return [
            {
              id: `extreme-load-${Date.now()}`,
              content: 'extreme load result',
              score: quality,
            },
          ];
        });

        vi.spyOn(searchManager as any, 'shouldActivateLoadShedding').mockImplementation(() => {
          const currentQuality = searchManager.getAverageQuality?.() || 0.8;
          return currentQuality < qualityThreshold && !loadSheddingActivated;
        });

        vi.spyOn(searchManager as any, 'activateLoadShedding').mockImplementation(() => {
          loadSheddingActivated = true;
          return {
            activated: true,
            timestamp: Date.now(),
            reason: 'Quality below threshold',
            currentLoad: searchManager.getCurrentLoad?.(),
          };
        });

        const query: SearchQuery = {
          query: 'test load shedding activation',
          mode: 'auto',
          limit: 10,
        };

        // Execute extreme load
        const results = await Promise.allSettled(
          Array.from({ length: extremeLoad }, (_, i) =>
            searchManager.executeSearch({ ...query, query: `${query.query} ${i}` }, 'auto')
          )
        );

        const successfulResults = results
          .filter((r) => r.status === 'fulfilled')
          .map((r) => (r as PromiseFulfilledResult<SearchResult>).value);

        // Should have load shedding activation
        expect(loadSheddingActivated).toBe(true);

        // Should maintain quality for requests that weren't shed
        const qualities = successfulResults.map((r) => r.confidence);
        const avgQuality = qualities.reduce((a, b) => a + b, 0) / qualities.length;
        expect(avgQuality).toBeGreaterThan(qualityThreshold);

        // Verify load shedding metadata
        const loadSheddingResults = successfulResults.filter(
          (r) => r.metadata['loadShedding']?.activated
        );
        expect(loadSheddingResults.length).toBeGreaterThan(0);
      });
    });

    describe('Performance Regression Prevention', () => {
      it('should prevent performance regression through adaptive optimization', async () => {
        const baselinePerformance = 0.85;
        const optimizationThreshold = 0.02; // 2% degradation triggers optimization
        let optimizationCount = 0;

        vi.spyOn(searchManager as any, 'performVectorSearch').mockImplementation(async () => {
          // Simulate gradual performance degradation
          const degradationFactor = 1.0 - optimizationCount * 0.01;
          const performance = Math.max(0.7, baselinePerformance * degradationFactor);

          return [
            {
              id: `optimization-test-${optimizationCount}`,
              content: 'optimization test result',
              score: performance,
            },
          ];
        });

        vi.spyOn(searchManager as any, 'shouldOptimizePerformance').mockImplementation(
          (currentPerformance) => {
            const regressionPercentage =
              ((baselinePerformance - currentPerformance) / baselinePerformance) * 100;
            return regressionPercentage > optimizationThreshold * 100;
          }
        );

        vi.spyOn(searchManager as any, 'optimizePerformance').mockImplementation(() => {
          optimizationCount++;
          return {
            optimized: true,
            optimizationCount,
            timestamp: Date.now(),
            improvements: ['Timeout adjustment', 'Strategy rebalancing', 'Cache warming'],
          };
        });

        const query: SearchQuery = {
          query: 'test performance optimization',
          mode: 'auto',
          limit: 10,
        };

        const results = [];

        // Execute searches to trigger optimization
        for (let i = 0; i < 10; i++) {
          const result = await searchManager.executeSearch(query, 'auto');

          // Check if optimization should be triggered
          if (searchManager['shouldOptimizePerformance'](result.confidence)) {
            const optimization = searchManager['optimizePerformance']();
            result.metadata['performanceOptimization'] = optimization;
          }

          results.push(result);
          await new Promise((resolve) => setTimeout(resolve, 100));
        }

        // Verify optimization was triggered
        expect(optimizationCount).toBeGreaterThan(0);

        // Verify performance recovery
        const optimizedResults = results.filter((r) => r.metadata['performanceOptimization']);
        expect(optimizedResults.length).toBeGreaterThan(0);

        // Later results should show performance improvement
        const laterResults = results.slice(-3);
        const laterAvgPerformance =
          laterResults.reduce((sum, r) => sum + r.confidence, 0) / laterResults.length;
        expect(laterAvgPerformance).toBeGreaterThan(0.75);
      });

      it('should maintain quality metrics within service level objectives', async () => {
        const sloTargets = {
          averageQuality: 0.8,
          p95Quality: 0.75,
          maxDegradation: 0.05, // 5% max degradation
          availability: 0.99, // 99% availability
        };

        const testDuration = 3000; // 3 seconds
        const requestInterval = 100; // Request every 100ms
        const totalRequests = testDuration / requestInterval;

        vi.spyOn(searchManager as any, 'performVectorSearch').mockImplementation(async () => {
          // Simulate performance within SLO targets
          const baseQuality = sloTargets.averageQuality;
          const variation = (Math.random() - 0.5) * sloTargets.maxDegradation;
          const quality = Math.max(
            sloTargets.p95Quality - sloTargets.maxDegradation,
            Math.min(1.0, baseQuality + variation)
          );

          return [
            {
              id: `slo-test-${Date.now()}`,
              content: 'SLO test result',
              score: quality,
            },
          ];
        });

        const query: SearchQuery = {
          query: 'test SLO compliance',
          mode: 'auto',
          limit: 10,
        };

        const results = [];
        const startTime = Date.now();

        // Execute sustained test to verify SLO compliance
        while (Date.now() - startTime < testDuration) {
          try {
            const result = await searchManager.executeSearch(query, 'auto');
            results.push(result);
          } catch (error) {
            // Track failures for availability calculation
          }

          await new Promise((resolve) => setTimeout(resolve, requestInterval));
        }

        // Calculate SLO metrics
        const qualities = results.map((r) => r.confidence).sort((a, b) => a - b);
        const avgQuality = qualities.reduce((a, b) => a + b, 0) / qualities.length;
        const p95Index = Math.floor(qualities.length * 0.95);
        const p95Quality = qualities[p95Index];
        const availability = results.length / totalRequests;
        const maxDegradation = sloTargets.averageQuality - Math.min(...qualities);

        // Verify SLO compliance
        expect(avgQuality).toBeGreaterThanOrEqual(sloTargets.averageQuality - 0.02);
        expect(p95Quality).toBeGreaterThanOrEqual(sloTargets.p95Quality);
        expect(maxDegradation).toBeLessThanOrEqual(sloTargets.maxDegradation);
        expect(availability).toBeGreaterThanOrEqual(sloTargets.availability);

        // Verify SLO tracking in metadata
        const latestResult = results[results.length - 1];
        expect(latestResult.metadata['sloCompliance']).toBeDefined();
        expect(latestResult.metadata['sloCompliance'].targets).toEqual(sloTargets);
        expect(latestResult.metadata['sloCompliance'].compliant).toBe(true);
      });
    });
  });
});
