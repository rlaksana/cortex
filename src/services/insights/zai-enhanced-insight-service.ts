// @ts-nocheck
/**
 * ZAI Enhanced Insight Service
 *
 * Advanced insight generation using ZAI glm-4.6 model with multiple
 * insight strategies, semantic analysis, and intelligent caching.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { randomUUID } from 'crypto';
import { logger } from '@/utils/logger.js';
import { zaiClientService } from '../ai/zai-client.service';
import type { ZAIChatRequest, ZAIChatResponse } from '../../types/zai-interfaces';
import type {
  Insight,
  InsightGenerationRequest,
  InsightGenerationResponse,
  PatternInsight,
  ConnectionInsight,
  RecommendationInsight,
  AnomalyInsight,
  TrendInsight,
  InsightTypeUnion,
} from '../../types/insight-interfaces';
import { InsightCacheService } from './insight-cache.service';
import { PatternRecognitionStrategy } from './insight-strategies/pattern-recognition.strategy';
import { KnowledgeGapStrategy } from './insight-strategies/knowledge-gap.strategy';
import { RelationshipAnalysisStrategy } from './insight-strategies/relationship-analysis.strategy';
import { AnomalyDetectionStrategy } from './insight-strategies/anomaly-detection.strategy';
import { PredictiveInsightStrategy } from './insight-strategies/predictive-insight.strategy';

export interface ZAIEnhancedInsightConfig {
  enabled: boolean;
  strategies: {
    pattern_recognition: boolean;
    knowledge_gap: boolean;
    relationship_analysis: boolean;
    anomaly_detection: boolean;
    predictive_insights: boolean;
  };
  performance: {
    max_processing_time_ms: number;
    batch_size: number;
    parallel_processing: boolean;
    cache_ttl_seconds: number;
  };
  quality: {
    min_confidence_threshold: number;
    max_insights_per_batch: number;
    enable_validation: boolean;
    semantic_similarity_threshold: number;
  };
  zai_model: {
    temperature: number;
    max_tokens: number;
    top_p: number;
    frequency_penalty: number;
    presence_penalty: number;
  };
}

export interface InsightGenerationOptions {
  strategies?: string[];
  confidence_threshold?: number;
  max_insights_per_strategy?: number;
  enable_caching?: boolean;
  background_processing?: boolean;
  include_rationale?: boolean;
}

export interface InsightBatch {
  id: string;
  items: any[];
  options: InsightGenerationOptions;
  created_at: Date;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  insights?: InsightTypeUnion[];
  error?: string;
  processing_time_ms?: number;
}

/**
 * Enhanced insight generation service using ZAI glm-4.6 model
 */
export class ZAIEnhancedInsightService {
  private static instance: ZAIEnhancedInsightService;
  private config: ZAIEnhancedInsightConfig;
  private cacheService: InsightCacheService;
  private strategies: Map<string, any>;
  private processingQueue: Map<string, InsightBatch> = new Map();
  private backgroundProcessingTimer?: NodeJS.Timeout;

  private constructor() {
    this.config = this.loadConfig();
    this.cacheService = new InsightCacheService({
      ttlSeconds: this.config.performance.cache_ttl_seconds,
      maxSize: 1000,
    });
    this.initializeStrategies();
    this.startBackgroundProcessor();
    logger.info('ZAI Enhanced Insight Service initialized');
  }

  /**
   * Get singleton instance
   */
  static getInstance(): ZAIEnhancedInsightService {
    if (!ZAIEnhancedInsightService.instance) {
      ZAIEnhancedInsightService.instance = new ZAIEnhancedInsightService();
    }
    return ZAIEnhancedInsightService.instance;
  }

  /**
   * Generate insights using enhanced ZAI strategies
   */
  async generateInsights(
    request: InsightGenerationRequest,
    options: InsightGenerationOptions = {}
  ): Promise<InsightGenerationResponse> {
    const startTime = Date.now();
    const batchId = randomUUID();

    try {
      logger.info(
        {
          batchId,
          itemCount: request.items.length,
          strategies: options.strategies || this.getEnabledStrategies(),
          enabled: this.config.enabled,
        },
        'Starting ZAI enhanced insight generation'
      );

      if (!this.config.enabled) {
        return this.createDisabledResponse();
      }

      // Merge options with defaults
      const generationOptions = this.mergeOptions(options);

      // Check cache first if enabled
      if (generationOptions.enable_caching) {
        const cachedInsights = await this.getCachedInsights(request, generationOptions);
        if (cachedInsights) {
          logger.debug({ batchId }, 'Returning cached insights');
          return this.createResponse(cachedInsights, startTime, 0, [], true);
        }
      }

      // Process in background if requested
      if (generationOptions.background_processing) {
        return this.queueForBackgroundProcessing(batchId, request, generationOptions);
      }

      // Generate insights synchronously
      const insights = await this.processInsightGeneration(request, generationOptions);

      // Cache results if enabled
      if (generationOptions.enable_caching && insights.length > 0) {
        await this.cacheInsights(request, generationOptions, insights);
      }

      const processingTime = Date.now() - startTime;
      logger.info(
        {
          batchId,
          insightsGenerated: insights.length,
          processingTime,
        },
        'ZAI enhanced insight generation completed'
      );

      return this.createResponse(insights, startTime, 0, []);
    } catch (error) {
      const processingTime = Date.now() - startTime;
      logger.error({ batchId, error }, 'ZAI enhanced insight generation failed');

      return this.createResponse([], startTime, 0, [
        {
          item_id: 'system',
          error_type: 'zai_enhanced_generation_failed',
          message: error instanceof Error ? error.message : 'Unknown error',
        },
      ]);
    }
  }

  /**
   * Process insight generation using enabled strategies
   */
  private async processInsightGeneration(
    request: InsightGenerationRequest,
    options: InsightGenerationOptions
  ): Promise<InsightTypeUnion[]> {
    const allInsights: InsightTypeUnion[] = [];
    const strategies = options.strategies || this.getEnabledStrategies();

    // Process each strategy
    for (const strategyName of strategies) {
      if (!this.isStrategyEnabled(strategyName)) {
        logger.debug({ strategy: strategyName }, 'Strategy disabled, skipping');
        continue;
      }

      try {
        const strategy = this.strategies.get(strategyName);
        if (!strategy) {
          logger.warn({ strategy: strategyName }, 'Strategy not found');
          continue;
        }

        logger.debug({ strategy: strategyName }, 'Executing insight strategy');
        const strategyInsights = await strategy.generateInsights(request, {
          confidence_threshold:
            options.confidence_threshold || this.config.quality.min_confidence_threshold,
          max_insights:
            options.max_insights_per_strategy || this.config.quality.max_insights_per_batch,
          include_rationale: options.include_rationale || false,
          zai_config: this.config.zai_model,
        });

        allInsights.push(...strategyInsights);
        logger.debug(
          { strategy: strategyName, insightCount: strategyInsights.length },
          'Strategy completed'
        );
      } catch (error) {
        logger.error({ strategy: strategyName, error }, 'Strategy execution failed');
        // Continue with other strategies
      }
    }

    // Filter and prioritize insights
    return this.filterAndPrioritizeInsights(allInsights, options);
  }

  /**
   * Initialize insight strategies
   */
  private initializeStrategies(): void {
    this.strategies = new Map([
      ['pattern_recognition', new PatternRecognitionStrategy(zaiClientService)],
      ['knowledge_gap', new KnowledgeGapStrategy(zaiClientService)],
      ['relationship_analysis', new RelationshipAnalysisStrategy(zaiClientService)],
      ['anomaly_detection', new AnomalyDetectionStrategy(zaiClientService)],
      ['predictive_insights', new PredictiveInsightStrategy(zaiClientService)],
    ]);

    logger.info(
      { strategies: Array.from(this.strategies.keys()) },
      'Insight strategies initialized'
    );
  }

  /**
   * Queue batch for background processing
   */
  private async queueForBackgroundProcessing(
    batchId: string,
    request: InsightGenerationRequest,
    options: InsightGenerationOptions
  ): Promise<InsightGenerationResponse> {
    const batch: InsightBatch = {
      id: batchId,
      items: request.items,
      options,
      created_at: new Date(),
      status: 'pending',
    };

    this.processingQueue.set(batchId, batch);
    logger.info({ batchId }, 'Queued for background processing');

    // Return immediate response
    return this.createResponse([], Date.now(), 0, [], false, {
      processing_mode: 'background',
      batch_id: batchId,
      estimated_completion: new Date(Date.now() + 30000).toISOString(),
    });
  }

  /**
   * Start background processor
   */
  private startBackgroundProcessor(): void {
    if (this.backgroundProcessingTimer) {
      clearInterval(this.backgroundProcessingTimer);
    }

    this.backgroundProcessingTimer = setInterval(async () => {
      await this.processBackgroundQueue();
    }, 5000); // Process every 5 seconds

    logger.debug('Background processor started');
  }

  /**
   * Process background queue
   */
  private async processBackgroundQueue(): Promise<void> {
    const pendingBatches = Array.from(this.processingQueue.values()).filter(
      (batch) => batch.status === 'pending'
    );

    if (pendingBatches.length === 0) {
      return;
    }

    logger.debug({ batchCount: pendingBatches.length }, 'Processing background queue');

    for (const batch of pendingBatches.slice(0, this.config.performance.batch_size)) {
      batch.status = 'processing';

      try {
        const request: InsightGenerationRequest = {
          items: batch.items,
          options: {
            enabled: true,
            insight_types: [],
            max_insights_per_item: 10,
            confidence_threshold: 0.7,
            include_metadata: true,
            session_id: batch.id,
          },
          scope: {},
        };

        const startTime = Date.now();
        const insights = await this.processInsightGeneration(request, batch.options);
        const processingTime = Date.now() - startTime;

        batch.status = 'completed';
        batch.insights = insights;
        batch.processing_time_ms = processingTime;

        logger.debug(
          { batchId: batch.id, insightCount: insights.length },
          'Background batch completed'
        );
      } catch (error) {
        batch.status = 'failed';
        batch.error = error instanceof Error ? error.message : 'Unknown error';
        logger.error({ batchId: batch.id, error }, 'Background batch failed');
      }
    }
  }

  /**
   * Get cached insights
   */
  private async getCachedInsights(
    request: InsightGenerationRequest,
    options: InsightGenerationOptions
  ): Promise<InsightTypeUnion[] | null> {
    const cacheKey = this.generateCacheKey(request, options);
    return await this.cacheService.get(cacheKey);
  }

  /**
   * Cache insights
   */
  private async cacheInsights(
    request: InsightGenerationRequest,
    options: InsightGenerationOptions,
    insights: InsightTypeUnion[]
  ): Promise<void> {
    const cacheKey = this.generateCacheKey(request, options);
    await this.cacheService.set(cacheKey, insights);
  }

  /**
   * Generate cache key
   */
  private generateCacheKey(
    request: InsightGenerationRequest,
    options: InsightGenerationOptions
  ): string {
    const keyData = {
      itemIds: request.items.map((item) => item.id).sort(),
      strategies: options.strategies || this.getEnabledStrategies(),
      confidence_threshold: options.confidence_threshold,
      max_insights: options.max_insights_per_strategy,
    };
    return Buffer.from(JSON.stringify(keyData)).toString('base64');
  }

  /**
   * Filter and prioritize insights
   */
  private filterAndPrioritizeInsights(
    insights: InsightTypeUnion[],
    options: InsightGenerationOptions
  ): InsightTypeUnion[] {
    const threshold = options.confidence_threshold || this.config.quality.min_confidence_threshold;

    // Filter by confidence threshold
    let filteredInsights = insights.filter((insight) => insight.confidence >= threshold);

    // Remove duplicates based on semantic similarity
    if (this.config.quality.semantic_similarity_threshold > 0) {
      filteredInsights = this.removeSemanticDuplicates(filteredInsights);
    }

    // Sort by priority and confidence
    filteredInsights.sort((a, b) => {
      if (a.priority !== b.priority) {
        return a.priority - b.priority;
      }
      return b.confidence - a.confidence;
    });

    // Limit results
    const maxInsights =
      options.max_insights_per_strategy || this.config.quality.max_insights_per_batch;
    return filteredInsights.slice(0, maxInsights);
  }

  /**
   * Remove semantic duplicates
   */
  private removeSemanticDuplicates(insights: InsightTypeUnion[]): InsightTypeUnion[] {
    const uniqueInsights: InsightTypeUnion[] = [];
    const seenTitles = new Set<string>();

    for (const insight of insights) {
      const titleKey = insight.title.toLowerCase().replace(/\s+/g, ' ').trim();
      if (!seenTitles.has(titleKey)) {
        seenTitles.add(titleKey);
        uniqueInsights.push(insight);
      }
    }

    return uniqueInsights;
  }

  /**
   * Get enabled strategies
   */
  private getEnabledStrategies(): string[] {
    return Object.entries(this.config.strategies)
      .filter(([_, enabled]) => enabled)
      .map(([name]) => name);
  }

  /**
   * Check if strategy is enabled
   */
  private isStrategyEnabled(strategyName: string): boolean {
    return this.config.strategies[strategyName as keyof typeof this.config.strategies] || false;
  }

  /**
   * Merge options with defaults
   */
  private mergeOptions(options: InsightGenerationOptions): InsightGenerationOptions {
    return {
      strategies: options.strategies || this.getEnabledStrategies(),
      confidence_threshold:
        options.confidence_threshold || this.config.quality.min_confidence_threshold,
      max_insights_per_strategy:
        options.max_insights_per_strategy || this.config.quality.max_insights_per_batch,
      enable_caching: options.enable_caching !== false,
      background_processing: options.background_processing || false,
      include_rationale: options.include_rationale || false,
    };
  }

  /**
   * Create response
   */
  private createResponse(
    insights: InsightTypeUnion[],
    startTime: number,
    cacheHitRate: number,
    errors: any[],
    fromCache: boolean = false,
    additionalMetadata: any = {}
  ): InsightGenerationResponse {
    const processingTime = Date.now() - startTime;

    return {
      insights: insights as Insight[],
      metadata: {
        total_insights: insights.length,
        insights_by_type: this.groupInsightsByType(insights),
        average_confidence: this.calculateAverageConfidence(insights),
        processing_time_ms: processingTime,
        items_processed: insights.length,
        insights_generated: insights.length,
        performance_impact: this.calculatePerformanceImpact(processingTime, insights.length),
        cache_hit_rate: cacheHitRate,
        ...additionalMetadata,
      },
      errors,
      warnings: fromCache ? ['Insights retrieved from cache'] : [],
    };
  }

  /**
   * Create disabled response
   */
  private createDisabledResponse(): InsightGenerationResponse {
    return {
      insights: [],
      metadata: {
        total_insights: 0,
        insights_by_type: {},
        average_confidence: 0,
        processing_time_ms: 0,
        items_processed: 0,
        insights_generated: 0,
        performance_impact: 0,
        cache_hit_rate: 0,
      },
      errors: [],
      warnings: ['ZAI Enhanced Insight Service is disabled'],
    };
  }

  /**
   * Utility methods
   */
  private groupInsightsByType(insights: InsightTypeUnion[]): Record<string, number> {
    const grouped: Record<string, number> = {};
    insights.forEach((insight) => {
      grouped[insight.type] = (grouped[insight.type] || 0) + 1;
    });
    return grouped;
  }

  private calculateAverageConfidence(insights: InsightTypeUnion[]): number {
    if (insights.length === 0) return 0;
    const sum = insights.reduce((acc, insight) => acc + insight.confidence, 0);
    return sum / insights.length;
  }

  private calculatePerformanceImpact(processingTime: number, itemCount: number): number {
    const timePerItem = itemCount > 0 ? processingTime / itemCount : 0;
    return Math.min((timePerItem / 100) * 100, 100);
  }

  private loadConfig(): ZAIEnhancedInsightConfig {
    return {
      enabled: true,
      strategies: {
        pattern_recognition: true,
        knowledge_gap: true,
        relationship_analysis: true,
        anomaly_detection: true,
        predictive_insights: true,
      },
      performance: {
        max_processing_time_ms: 5000,
        batch_size: 10,
        parallel_processing: true,
        cache_ttl_seconds: 3600,
      },
      quality: {
        min_confidence_threshold: 0.7,
        max_insights_per_batch: 50,
        enable_validation: true,
        semantic_similarity_threshold: 0.8,
      },
      zai_model: {
        temperature: 0.3,
        max_tokens: 1000,
        top_p: 0.9,
        frequency_penalty: 0.1,
        presence_penalty: 0.1,
      },
    };
  }

  /**
   * Get processing status for background batches
   */
  async getProcessingStatus(batchId: string): Promise<InsightBatch | null> {
    return this.processingQueue.get(batchId) || null;
  }

  /**
   * Get completed background insights
   */
  async getCompletedInsights(batchId: string): Promise<InsightGenerationResponse | null> {
    const batch = this.processingQueue.get(batchId);
    if (!batch || batch.status !== 'completed' || !batch.insights) {
      return null;
    }

    const response = this.createResponse(
      batch.insights,
      batch.processing_time_ms || 0,
      0,
      [],
      false,
      {
        processing_mode: 'background_completed',
        batch_id: batchId,
        processing_time_ms: batch.processing_time_ms,
      }
    );

    // Clean up completed batch
    this.processingQueue.delete(batchId);

    return response;
  }

  /**
   * Update configuration
   */
  updateConfig(newConfig: Partial<ZAIEnhancedInsightConfig>): void {
    this.config = { ...this.config, ...newConfig };
    logger.info({ config: newConfig }, 'ZAI Enhanced Insight Service configuration updated');
  }

  /**
   * Get current configuration
   */
  getConfig(): ZAIEnhancedInsightConfig {
    return { ...this.config };
  }

  /**
   * Cleanup resources
   */
  destroy(): void {
    if (this.backgroundProcessingTimer) {
      clearInterval(this.backgroundProcessingTimer);
      this.backgroundProcessingTimer = undefined;
    }
    this.processingQueue.clear();
    logger.info('ZAI Enhanced Insight Service destroyed');
  }
}

// Export singleton instance
export const zaiEnhancedInsightService = ZAIEnhancedInsightService.getInstance();
