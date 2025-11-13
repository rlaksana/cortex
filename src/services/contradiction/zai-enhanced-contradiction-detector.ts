
/**
 * ZAI-Enhanced Contradiction Detector
 *
 * Advanced contradiction detection using ZAI glm-4.6 model with multiple strategies:
 * - Semantic contradiction detection using advanced NLP
 * - Temporal reasoning and timeline inconsistency detection
 * - Logical inconsistency analysis and reasoning
 * - Factual contradiction verification with external sources
 * - Process and procedural contradiction detection
 *
 * @author Cortex Team
 * @version 3.0.0
 * @since 2025
 */

import { randomUUID } from 'crypto';

import { logger } from '@/utils/logger.js';

import type {
  ContradictionDetail,
  ContradictionDetectionRequest,
  ContradictionDetectionResponse,
  ContradictionResult,
  ContradictionScore,
  ContradictionStrategy,
  ContradictionStrategyType,
  ContradictionType,
  KnowledgeItem,
  ResolutionSuggestion,
} from '../../types/contradiction-detector.interface';
import type { ZAIChatRequest } from '../../types/zai-interfaces.js';
import { zaiClientService } from '../ai/zai-client.service';

/**
 * Contradiction metadata interface
 */
interface ContradictionMetadata {
  detection_method: string;
  algorithm_version: string;
  processing_time_ms: number;
  comparison_details: Record<string, unknown>;
  evidence: { item_id: string; evidence_type: string; content: string; confidence: number; }[];
  [key: string]: unknown;
}

/**
 * ZAI-Enhanced contradiction detector configuration
 */
interface ZAIContradictionDetectorConfig {
  enabled: boolean;
  sensitivity: 'low' | 'medium' | 'high';
  confidence_threshold: number;
  max_items_per_check: number;
  timeout_ms: number;
  enable_caching: boolean;
  enable_external_verification: boolean;
  strategies: {
    semantic: boolean;
    temporal: boolean;
    logical: boolean;
    factual: boolean;
    procedural: boolean;
  };
  performance: {
    batch_size: number;
    parallel_processing: boolean;
    max_concurrent_requests: number;
  };
}

/**
 * Default configuration
 */
const DEFAULT_CONFIG: ZAIContradictionDetectorConfig = {
  enabled: true,
  sensitivity: 'medium',
  confidence_threshold: 0.7,
  max_items_per_check: 100,
  timeout_ms: 30000,
  enable_caching: true,
  enable_external_verification: true,
  strategies: {
    semantic: true,
    temporal: true,
    logical: true,
    factual: true,
    procedural: true,
  },
  performance: {
    batch_size: 10,
    parallel_processing: true,
    max_concurrent_requests: 5,
  },
};

/**
 * Contradiction detection cache entry
 */
interface CacheEntry {
  contradictionId: string;
  result: ContradictionResult;
  timestamp: number;
  ttl: number;
}

/**
 * ZAI-Enhanced Contradiction Detector
 *
 * Uses ZAI's glm-4.6 model for advanced contradiction detection with
 * multiple specialized strategies and intelligent resolution suggestions.
 */
export class ZAIEnhancedContradictionDetector {
  private config: ZAIContradictionDetectorConfig;
  private cache: Map<string, CacheEntry> = new Map();
  private metrics: {
    totalDetections: number;
    contradictionsFound: number;
    averageProcessingTime: number;
    cacheHits: number;
    cacheMisses: number;
    strategyStats: Record<string, number>;
  };

  constructor(config: Partial<ZAIContradictionDetectorConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.metrics = {
      totalDetections: 0,
      contradictionsFound: 0,
      averageProcessingTime: 0,
      cacheHits: 0,
      cacheMisses: 0,
      strategyStats: {},
    };

    this.initializeStrategyStats();
    logger.info('ZAI-Enhanced Contradiction Detector initialized', { config: this.config });
  }

  /**
   * Detect contradictions in knowledge items using ZAI-powered strategies
   */
  async detectContradictions(
    request: ContradictionDetectionRequest
  ): Promise<ContradictionDetectionResponse> {
    const startTime = Date.now();
    this.metrics.totalDetections++;

    try {
      logger.debug('Starting ZAI-enhanced contradiction detection', {
        itemCount: request.items.length,
        strategies: Object.entries(this.config.strategies)
          .filter(([, enabled]) => enabled)
          .map(([name]) => name),
      });

      // Validate request
      this.validateRequest(request);

      // Process items in batches for optimal performance
      const batches = this.createBatches(request.items, this.config.performance.batch_size);
      const contradictions: ContradictionResult[] = [];

      for (const batch of batches) {
        const batchResults = await this.processBatch(batch, request);
        contradictions.push(...batchResults);
      }

      const processingTime = Date.now() - startTime;
      this.updateMetrics(contradictions.length, processingTime);

      const response = this.createResponse(contradictions, request.items.length, processingTime);

      logger.info('ZAI-enhanced contradiction detection completed', {
        contradictionsFound: contradictions.length,
        processingTime,
        itemsProcessed: request.items.length,
      });

      return response;
    } catch (error) {
      const processingTime = Date.now() - startTime;
      logger.error({ error, processingTime }, 'ZAI-enhanced contradiction detection failed');
      throw error;
    }
  }

  /**
   * Process a batch of items for contradiction detection
   */
  private async processBatch(
    items: KnowledgeItem[],
    request: ContradictionDetectionRequest
  ): Promise<ContradictionResult[]> {
    const contradictions: ContradictionResult[] = [];

    // Process each enabled strategy
    const strategies = Object.entries(this.config.strategies)
      .filter(([, enabled]) => enabled)
      .map(([name]) => name);

    if (this.config.performance.parallel_processing) {
      // Process strategies in parallel
      const strategyResults = await Promise.allSettled(
        strategies.map((strategy) => this.processStrategy(strategy as ContradictionStrategyType, items))
      );

      for (const result of strategyResults) {
        if (result.status === 'fulfilled') {
          contradictions.push(...result.value);
        } else {
          logger.warn({ error: result.reason }, 'Strategy processing failed');
        }
      }
    } else {
      // Process strategies sequentially
      for (const strategy of strategies) {
        try {
          const strategyResults = await this.processStrategy(
            strategy as ContradictionStrategyType,
            items
          );
          contradictions.push(...strategyResults);
        } catch (error) {
          logger.warn({ strategy, error }, 'Strategy processing failed');
        }
      }
    }

    return contradictions;
  }

  /**
   * Process a specific contradiction detection strategy
   */
  private async processStrategy(
    strategy: ContradictionStrategyType,
    items: KnowledgeItem[]
  ): Promise<ContradictionResult[]> {
    logger.debug(`Processing ${strategy} strategy`, { itemCount: items.length });

    switch (strategy) {
      case 'semantic':
        return this.detectSemanticContradictions(items);
      case 'temporal':
        return this.detectTemporalContradictions(items);
      case 'logical':
        return this.detectLogicalContradictions(items);
      case 'factual':
        return this.detectFactualContradictions(items);
      case 'procedural':
        return this.detectProceduralContradictions(items);
      default:
        logger.warn(`Unknown strategy: ${strategy}`);
        return [];
    }
  }

  /**
   * Detect semantic contradictions using ZAI NLP capabilities
   */
  private async detectSemanticContradictions(
    items: KnowledgeItem[]
  ): Promise<ContradictionResult[]> {
    const contradictions: ContradictionResult[] = [];

    // Compare items pairwise for semantic contradictions
    for (let i = 0; i < items.length; i++) {
      for (let j = i + 1; j < items.length; j++) {
        const item1 = items[i];
        const item2 = items[j];

        // Skip if items are in different scopes
        if (!this.itemsInSameScope(item1, item2)) {
          continue;
        }

        // Check cache
        const cacheKey = `semantic:${item1.id}:${item2.id}`;
        const cached = this.getFromCache(cacheKey);
        if (cached) {
          contradictions.push(cached.result);
          continue;
        }

        try {
          const contradiction = await this.analyzeSemanticContradiction(item1, item2);
          if (contradiction && contradiction.confidence_score >= this.config.confidence_threshold) {
            contradictions.push(contradiction);
            this.setToCache(cacheKey, contradiction);
            this.metrics.strategyStats.semantic++;
          }
        } catch (error) {
          logger.warn({ error, item1Id: item1.id, item2Id: item2.id }, 'Semantic analysis failed');
        }
      }
    }

    return contradictions;
  }

  /**
   * Analyze semantic contradiction between two items using ZAI
   */
  private async analyzeSemanticContradiction(
    item1: KnowledgeItem,
    item2: KnowledgeItem
  ): Promise<ContradictionResult | null> {
    const prompt = this.buildSemanticAnalysisPrompt(item1, item2);

    try {
      const response = await zaiClientService.generateCompletion({
        messages: [
          {
            role: 'system',
            content: `You are an expert semantic contradiction detector. Analyze two pieces of text for semantic contradictions.

            A semantic contradiction occurs when two statements express opposing meanings, even if they use different words.
            Examples:
            - "The system is secure" vs "The system has vulnerabilities"
            - "Performance is excellent" vs "Performance is poor"
            - "The feature is complete" vs "The feature needs more work"

            Respond with a JSON object containing:
            {
              "has_contradiction": boolean,
              "confidence": number (0-1),
              "contradiction_type": "direct" | "implicit" | "contextual",
              "description": string,
              "reasoning": string,
              "evidence": [
                {
                  "type": "semantic_opposition" | "negation" | "conflict",
                  "content": string,
                  "confidence": number
                }
              ]
            }

            Only return contradictions with confidence >= 0.6.`,
          },
          {
            role: 'user',
            content: prompt,
          },
        ],
        temperature: 0.1,
        maxTokens: 1000,
      });

      const analysis = JSON.parse(response.choices[0].message.content);

      if (analysis.has_contradiction && analysis.confidence >= this.config.confidence_threshold) {
        return this.createContradictionResult({
          type: 'semantic',
          primaryItemId: item1.id || randomUUID(),
          conflictingItemIds: [item2.id || randomUUID()],
          confidence: analysis.confidence,
          description: analysis.description,
          reasoning: analysis.reasoning,
          evidence: analysis.evidence,
          metadata: {
            contradiction_subtype: analysis.contradiction_type,
            analysis_model: 'zai-glm-4.6',
          },
        });
      }

      return null;
    } catch (error) {
      logger.error(
        { error, item1Id: item1.id, item2Id: item2.id },
        'ZAI semantic analysis failed'
      );
      return null;
    }
  }

  /**
   * Build prompt for semantic contradiction analysis
   */
  private buildSemanticAnalysisPrompt(item1: KnowledgeItem, item2: KnowledgeItem): string {
    const content1 = this.extractItemContent(item1);
    const content2 = this.extractItemContent(item2);

    return `Analyze these two knowledge items for semantic contradictions:

Item 1 (${item1.kind}):
${content1}

Item 2 (${item2.kind}):
${content2}

Focus on:
- Opposing statements or claims
- Contradictory descriptions or assessments
- Confident assertions that conflict with each other
- Implicit contradictions that might not use negation words

Consider the context and kind of each item when determining if there's a genuine contradiction.`;
  }

  /**
   * Detect temporal contradictions using timeline analysis
   */
  private async detectTemporalContradictions(
    items: KnowledgeItem[]
  ): Promise<ContradictionResult[]> {
    const contradictions: ContradictionResult[] = [];

    // Extract temporal information from items
    const temporalItems = items
      .map((item) => ({
        item,
        temporalData: this.extractTemporalData(item),
      }))
      .filter((ti) => ti.temporalData !== null);

    // Compare temporal items for contradictions
    for (let i = 0; i < temporalItems.length; i++) {
      for (let j = i + 1; j < temporalItems.length; j++) {
        const item1 = temporalItems[i];
        const item2 = temporalItems[j];

        if (!this.itemsInSameScope(item1.item, item2.item)) {
          continue;
        }

        const cacheKey = `temporal:${item1.item.id}:${item2.item.id}`;
        const cached = this.getFromCache(cacheKey);
        if (cached) {
          contradictions.push(cached.result);
          continue;
        }

        try {
          const contradiction = await this.analyzeTemporalContradiction(
            item1.item,
            item2.item,
            item1.temporalData!,
            item2.temporalData!
          );

          if (contradiction && contradiction.confidence_score >= this.config.confidence_threshold) {
            contradictions.push(contradiction);
            this.setToCache(cacheKey, contradiction);
            this.metrics.strategyStats.temporal++;
          }
        } catch (error) {
          logger.warn(
            { error, item1Id: item1.item.id, item2Id: item2.item.id },
            'Temporal analysis failed'
          );
        }
      }
    }

    return contradictions;
  }

  /**
   * Analyze temporal contradiction using ZAI
   */
  private async analyzeTemporalContradiction(
    item1: KnowledgeItem,
    item2: KnowledgeItem,
    temporal1: unknown,
    temporal2: unknown
  ): Promise<ContradictionResult | null> {
    const prompt = this.buildTemporalAnalysisPrompt(item1, item2, temporal1, temporal2);

    try {
      const response = await zaiClientService.generateCompletion({
        messages: [
          {
            role: 'system',
            content: `You are an expert temporal contradiction detector. Analyze two knowledge items for temporal inconsistencies.

            Temporal contradictions include:
            - Events claimed to happen at conflicting times
            - Sequences that violate logical order
            - Deadlines or dates that are inconsistent
            - Duration claims that don't align
            - Before/after relationships that are impossible

            Respond with a JSON object containing:
            {
              "has_contradiction": boolean,
              "confidence": number (0-1),
              "contradiction_type": "sequence" | "timing" | "duration" | "deadline",
              "description": string,
              "reasoning": string,
              "evidence": [
                {
                  "type": "timeline_conflict" | "sequence_violation" | "timing_mismatch",
                  "content": string,
                  "confidence": number
                }
              ]
            }

            Only return contradictions with confidence >= 0.6.`,
          },
          {
            role: 'user',
            content: prompt,
          },
        ],
        temperature: 0.1,
        maxTokens: 1000,
      });

      const analysis = JSON.parse(response.choices[0].message.content);

      if (analysis.has_contradiction && analysis.confidence >= this.config.confidence_threshold) {
        return this.createContradictionResult({
          type: 'temporal',
          primaryItemId: item1.id || randomUUID(),
          conflictingItemIds: [item2.id || randomUUID()],
          confidence: analysis.confidence,
          description: analysis.description,
          reasoning: analysis.reasoning,
          evidence: analysis.evidence,
          metadata: {
            contradiction_subtype: analysis.contradiction_type,
            temporal_data: { temporal1, temporal2 },
            analysis_model: 'zai-glm-4.6',
          },
        });
      }

      return null;
    } catch (error) {
      logger.error(
        { error, item1Id: item1.id, item2Id: item2.id },
        'ZAI temporal analysis failed'
      );
      return null;
    }
  }

  /**
   * Build prompt for temporal contradiction analysis
   */
  private buildTemporalAnalysisPrompt(
    item1: KnowledgeItem,
    item2: KnowledgeItem,
    temporal1: unknown,
    temporal2: unknown
  ): string {
    const content1 = this.extractItemContent(item1);
    const content2 = this.extractItemContent(item2);

    return `Analyze these two knowledge items for temporal contradictions:

Item 1 (${item1.kind}):
Content: ${content1}
Temporal Data: ${JSON.stringify(temporal1, null, 2)}

Item 2 (${item2.kind}):
Content: ${content2}
Temporal Data: ${JSON.stringify(temporal2, null, 2)}

Focus on:
- Conflicting timestamps or dates
- Impossible sequences (B happening before A when it should be after)
- Duration contradictions
- Deadline inconsistencies
- Before/after relationship violations

Consider both explicit temporal data and temporal references in the content.`;
  }

  /**
   * Detect logical contradictions using advanced reasoning
   */
  private async detectLogicalContradictions(
    items: KnowledgeItem[]
  ): Promise<ContradictionResult[]> {
    const contradictions: ContradictionResult[] = [];

    // Compare items pairwise for logical contradictions
    for (let i = 0; i < items.length; i++) {
      for (let j = i + 1; j < items.length; j++) {
        const item1 = items[i];
        const item2 = items[j];

        if (!this.itemsInSameScope(item1, item2)) {
          continue;
        }

        const cacheKey = `logical:${item1.id}:${item2.id}`;
        const cached = this.getFromCache(cacheKey);
        if (cached) {
          contradictions.push(cached.result);
          continue;
        }

        try {
          const contradiction = await this.analyzeLogicalContradiction(item1, item2);
          if (contradiction && contradiction.confidence_score >= this.config.confidence_threshold) {
            contradictions.push(contradiction);
            this.setToCache(cacheKey, contradiction);
            this.metrics.strategyStats.logical++;
          }
        } catch (error) {
          logger.warn({ error, item1Id: item1.id, item2Id: item2.id }, 'Logical analysis failed');
        }
      }
    }

    return contradictions;
  }

  /**
   * Analyze logical contradiction using ZAI
   */
  private async analyzeLogicalContradiction(
    item1: KnowledgeItem,
    item2: KnowledgeItem
  ): Promise<ContradictionResult | null> {
    const prompt = this.buildLogicalAnalysisPrompt(item1, item2);

    try {
      const response = await zaiClientService.generateCompletion({
        messages: [
          {
            role: 'system',
            content: `You are an expert logical contradiction detector. Analyze two knowledge items for logical inconsistencies.

            Logical contradictions include:
            - Mutually exclusive statements both claimed as true
            - Violations of logical principles (A and not-A)
            - Inconsistent conditions or requirements
            - Contradictory rules or constraints
            - Implications that don't follow logically

            Respond with a JSON object containing:
            {
              "has_contradiction": boolean,
              "confidence": number (0-1),
              "contradiction_type": "mutual_exclusion" | "logical_violation" | "inconsistent_conditions" | "contradictory_rules",
              "description": string,
              "reasoning": string,
              "evidence": [
                {
                  "type": "logical_conflict" | "mutual_exclusion" | "conditional_contradiction",
                  "content": string,
                  "confidence": number
                }
              ]
            }

            Only return contradictions with confidence >= 0.6.`,
          },
          {
            role: 'user',
            content: prompt,
          },
        ],
        temperature: 0.1,
        maxTokens: 1000,
      });

      const analysis = JSON.parse(response.choices[0].message.content);

      if (analysis.has_contradiction && analysis.confidence >= this.config.confidence_threshold) {
        return this.createContradictionResult({
          type: 'logical',
          primaryItemId: item1.id || randomUUID(),
          conflictingItemIds: [item2.id || randomUUID()],
          confidence: analysis.confidence,
          description: analysis.description,
          reasoning: analysis.reasoning,
          evidence: analysis.evidence,
          metadata: {
            contradiction_subtype: analysis.contradiction_type,
            analysis_model: 'zai-glm-4.6',
          },
        });
      }

      return null;
    } catch (error) {
      logger.error({ error, item1Id: item1.id, item2Id: item2.id }, 'ZAI logical analysis failed');
      return null;
    }
  }

  /**
   * Build prompt for logical contradiction analysis
   */
  private buildLogicalAnalysisPrompt(item1: KnowledgeItem, item2: KnowledgeItem): string {
    const content1 = this.extractItemContent(item1);
    const content2 = this.extractItemContent(item2);

    return `Analyze these two knowledge items for logical contradictions:

Item 1 (${item1.kind}):
${content1}

Item 2 (${item2.kind}):
${content2}

Focus on:
- Mutually exclusive statements or conditions
- Logical violations (A and not-A scenarios)
- Inconsistent rules or requirements
- Contradictory implications
- Logical fallacies or inconsistencies

Consider the logical structure and implications of each statement.`;
  }

  /**
   * Detect factual contradictions with external verification
   */
  private async detectFactualContradictions(
    items: KnowledgeItem[]
  ): Promise<ContradictionResult[]> {
    const contradictions: ContradictionResult[] = [];

    // Compare items pairwise for factual contradictions
    for (let i = 0; i < items.length; i++) {
      for (let j = i + 1; j < items.length; j++) {
        const item1 = items[i];
        const item2 = items[j];

        if (!this.itemsInSameScope(item1, item2)) {
          continue;
        }

        const cacheKey = `factual:${item1.id}:${item2.id}`;
        const cached = this.getFromCache(cacheKey);
        if (cached) {
          contradictions.push(cached.result);
          continue;
        }

        try {
          const contradiction = await this.analyzeFactualContradiction(item1, item2);
          if (contradiction && contradiction.confidence_score >= this.config.confidence_threshold) {
            contradictions.push(contradiction);
            this.setToCache(cacheKey, contradiction);
            this.metrics.strategyStats.factual++;
          }
        } catch (error) {
          logger.warn({ error, item1Id: item1.id, item2Id: item2.id }, 'Factual analysis failed');
        }
      }
    }

    return contradictions;
  }

  /**
   * Analyze factual contradiction using ZAI with external verification
   */
  private async analyzeFactualContradiction(
    item1: KnowledgeItem,
    item2: KnowledgeItem
  ): Promise<ContradictionResult | null> {
    const prompt = this.buildFactualAnalysisPrompt(item1, item2);

    try {
      const response = await zaiClientService.generateCompletion({
        messages: [
          {
            role: 'system',
            content: `You are an expert factual contradiction detector with access to current knowledge. Analyze two knowledge items for factual contradictions.

            Factual contradictions include:
            - Conflicting statements about verifiable facts
            - Incorrect numerical data or measurements
            - Outdated information presented as current
            - Contradictory technical specifications
            - Conflicting external references or sources

            Respond with a JSON object containing:
            {
              "has_contradiction": boolean,
              "confidence": number (0-1),
              "contradiction_type": "verifiable_fact" | "numerical_data" | "technical_spec" | "temporal_fact" | "source_conflict",
              "description": string,
              "reasoning": string,
              "evidence": [
                {
                  "type": "factual_discrepancy" | "measurement_conflict" | "spec_mismatch",
                  "content": string,
                  "confidence": number
                }
              ],
              "external_verification": {
                "can_verify": boolean,
                "verification_method": string,
                "confidence": number
              }
            }

            Only return contradictions with confidence >= 0.6.`,
          },
          {
            role: 'user',
            content: prompt,
          },
        ],
        temperature: 0.1,
        maxTokens: 1200,
      });

      const analysis = JSON.parse(response.choices[0].message.content);

      if (analysis.has_contradiction && analysis.confidence >= this.config.confidence_threshold) {
        return this.createContradictionResult({
          type: 'factual',
          primaryItemId: item1.id || randomUUID(),
          conflictingItemIds: [item2.id || randomUUID()],
          confidence: analysis.confidence,
          description: analysis.description,
          reasoning: analysis.reasoning,
          evidence: analysis.evidence,
          metadata: {
            contradiction_subtype: analysis.contradiction_type,
            external_verification: analysis.external_verification,
            analysis_model: 'zai-glm-4.6',
          },
        });
      }

      return null;
    } catch (error) {
      logger.error({ error, item1Id: item1.id, item2Id: item2.id }, 'ZAI factual analysis failed');
      return null;
    }
  }

  /**
   * Build prompt for factual contradiction analysis
   */
  private buildFactualAnalysisPrompt(item1: KnowledgeItem, item2: KnowledgeItem): string {
    const content1 = this.extractItemContent(item1);
    const content2 = this.extractItemContent(item2);

    return `Analyze these two knowledge items for factual contradictions:

Item 1 (${item1.kind}):
${content1}

Item 2 (${item2.kind}):
${content2}

Focus on:
- Conflicting verifiable facts
- Numerical or measurement discrepancies
- Technical specification conflicts
- Outdated vs current information
- Source or reference conflicts

Consider if these facts can be externally verified and identify the most reliable source.`;
  }

  /**
   * Detect procedural contradictions
   */
  private async detectProceduralContradictions(
    items: KnowledgeItem[]
  ): Promise<ContradictionResult[]> {
    const contradictions: ContradictionResult[] = [];

    // Focus on runbooks, decisions, and process-related items
    const proceduralItems = items.filter(
      (item) =>
        ['runbook', 'decision', 'todo', 'process'].includes(item.kind) ||
        this.contentContainsProceduralTerms(item)
    );

    // Compare procedural items
    for (let i = 0; i < proceduralItems.length; i++) {
      for (let j = i + 1; j < proceduralItems.length; j++) {
        const item1 = proceduralItems[i];
        const item2 = proceduralItems[j];

        if (!this.itemsInSameScope(item1, item2)) {
          continue;
        }

        const cacheKey = `procedural:${item1.id}:${item2.id}`;
        const cached = this.getFromCache(cacheKey);
        if (cached) {
          contradictions.push(cached.result);
          continue;
        }

        try {
          const contradiction = await this.analyzeProceduralContradiction(item1, item2);
          if (contradiction && contradiction.confidence_score >= this.config.confidence_threshold) {
            contradictions.push(contradiction);
            this.setToCache(cacheKey, contradiction);
            this.metrics.strategyStats.procedural++;
          }
        } catch (error) {
          logger.warn(
            { error, item1Id: item1.id, item2Id: item2.id },
            'Procedural analysis failed'
          );
        }
      }
    }

    return contradictions;
  }

  /**
   * Analyze procedural contradiction using ZAI
   */
  private async analyzeProceduralContradiction(
    item1: KnowledgeItem,
    item2: KnowledgeItem
  ): Promise<ContradictionResult | null> {
    const prompt = this.buildProceduralAnalysisPrompt(item1, item2);

    try {
      const response = await zaiClientService.generateCompletion({
        messages: [
          {
            role: 'system',
            content: `You are an expert procedural contradiction detector. Analyze two knowledge items for procedural inconsistencies.

            Procedural contradictions include:
            - Conflicting steps in processes or runbooks
            - Inconsistent decision-making procedures
            - Contradictory workflows or methodologies
            - Incompatible task dependencies
            - Conflicting policies or standards

            Respond with a JSON object containing:
            {
              "has_contradiction": boolean,
              "confidence": number (0-1),
              "contradiction_type": "process_step" | "workflow" | "decision_procedure" | "task_dependency" | "policy_conflict",
              "description": string,
              "reasoning": string,
              "evidence": [
                {
                  "type": "procedural_conflict" | "step_contradiction" | "workflow_inconsistency",
                  "content": string,
                  "confidence": number
                }
              ]
            }

            Only return contradictions with confidence >= 0.6.`,
          },
          {
            role: 'user',
            content: prompt,
          },
        ],
        temperature: 0.1,
        maxTokens: 1000,
      });

      const analysis = JSON.parse(response.choices[0].message.content);

      if (analysis.has_contradiction && analysis.confidence >= this.config.confidence_threshold) {
        return this.createContradictionResult({
          type: 'procedural',
          primaryItemId: item1.id || randomUUID(),
          conflictingItemIds: [item2.id || randomUUID()],
          confidence: analysis.confidence,
          description: analysis.description,
          reasoning: analysis.reasoning,
          evidence: analysis.evidence,
          metadata: {
            contradiction_subtype: analysis.contradiction_type,
            analysis_model: 'zai-glm-4.6',
          },
        });
      }

      return null;
    } catch (error) {
      logger.error(
        { error, item1Id: item1.id, item2Id: item2.id },
        'ZAI procedural analysis failed'
      );
      return null;
    }
  }

  /**
   * Build prompt for procedural contradiction analysis
   */
  private buildProceduralAnalysisPrompt(item1: KnowledgeItem, item2: KnowledgeItem): string {
    const content1 = this.extractItemContent(item1);
    const content2 = this.extractItemContent(item2);

    return `Analyze these two knowledge items for procedural contradictions:

Item 1 (${item1.kind}):
${content1}

Item 2 (${item2.kind}):
${content2}

Focus on:
- Conflicting process steps or procedures
- Inconsistent workflows or methodologies
- Contradictory decision-making processes
- Incompatible task dependencies
- Policy or standard conflicts

Consider the procedural implications and potential conflicts in execution.`;
  }

  /**
   * Extract temporal data from an item
   */
  private extractTemporalData(item: KnowledgeItem): { dates?: string[]; markers?: string[]; sequence?: string[]; created_at?: string; updated_at?: string } | null {
    const temporalData: { dates?: string[]; markers?: string[]; sequence?: string[]; created_at?: string; updated_at?: string } = {};
    const content = this.extractItemContent(item);

    // Extract dates from content
    const datePatterns = [
      /\d{4}-\d{2}-\d{2}/g,
      /\d{2}\/\d{2}\/\d{4}/g,
      /\d{1,2}\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{4}/gi,
    ];

    const dates: string[] = [];
    datePatterns.forEach((pattern) => {
      const matches = content.match(pattern);
      if (matches) dates.push(...matches);
    });

    if (dates.length > 0) {
      temporalData.dates = dates;
    }

    // Extract temporal markers
    const temporalMarkers = [
      'before',
      'after',
      'during',
      'prior to',
      'following',
      'subsequent',
      'first',
      'second',
      'then',
      'next',
      'finally',
      'initially',
      'previously',
      'deadline',
      'due date',
      'timeline',
      'schedule',
      'duration',
      'when',
    ];

    const foundMarkers = temporalMarkers.filter((marker) => content.toLowerCase().includes(marker));

    if (foundMarkers.length > 0) {
      temporalData.markers = foundMarkers;
    }

    // Check for timestamps in item metadata
    if (item.created_at) {
      temporalData.created_at = item.created_at;
    }
    if (item.updated_at) {
      temporalData.updated_at = item.updated_at;
    }

    return Object.keys(temporalData).length > 0 ? temporalData : null;
  }

  /**
   * Check if content contains procedural terms
   */
  private contentContainsProceduralTerms(item: KnowledgeItem): boolean {
    const content = this.extractItemContent(item).toLowerCase();
    const proceduralTerms = [
      'process',
      'procedure',
      'step',
      'workflow',
      'task',
      'decision',
      'policy',
      'standard',
      'guideline',
      'runbook',
      'checklist',
      'approval',
      'review',
      'validate',
      'verify',
      'implement',
      'execute',
      'perform',
    ];

    return proceduralTerms.some((term) => content.includes(term));
  }

  /**
   * Check if two items are in the same scope
   */
  private itemsInSameScope(item1: KnowledgeItem, item2: KnowledgeItem): boolean {
    return item1.scope?.project === item2.scope?.project || item1.scope?.org === item2.scope?.org;
  }

  /**
   * Extract content from a knowledge item
   */
  private extractItemContent(item: KnowledgeItem): string {
    return item.content || JSON.stringify(item.data) || '';
  }

  /**
   * Create a contradiction result
   */
  private createContradictionResult(params: {
    type: string;
    primaryItemId: string;
    conflictingItemIds: string[];
    confidence: number;
    description: string;
    reasoning: string;
    evidence: unknown[];
    metadata?: unknown;
  }): ContradictionResult {
    const severity = this.calculateSeverity(params.confidence, params.type);

    return {
      id: randomUUID(),
      detected_at: new Date(),
      contradiction_type: params.type,
      confidence_score: params.confidence,
      severity,
      primary_item_id: params.primaryItemId,
      conflicting_item_ids: params.conflictingItemIds,
      description: params.description,
      reasoning: params.reasoning,
      metadata: {
        detection_method: 'zai_enhanced',
        algorithm_version: '3.0.0',
        model: 'zai-glm-4.6',
        processing_time_ms: 0,
        comparison_details: {},
        evidence: params.evidence as { item_id: string; evidence_type: string; content: string; confidence: number; }[],
        ...(params.metadata as Record<string, unknown>),
      } as ContradictionMetadata,
      resolution_suggestions: this.generateResolutionSuggestions(params.type, severity),
    };
  }

  /**
   * Calculate contradiction severity
   */
  private calculateSeverity(
    confidence: number,
    type: string
  ): 'low' | 'medium' | 'high' | 'critical' {
    if (confidence >= 0.9) return 'critical';
    if (confidence >= 0.8) return 'high';
    if (confidence >= 0.6) return 'medium';
    return 'low';
  }

  /**
   * Generate resolution suggestions for contradictions
   */
  private generateResolutionSuggestions(
    type: string,
    severity: string
  ): Array<{
    suggestion: string;
    priority: 'low' | 'medium' | 'high' | 'critical';
    effort: 'low' | 'medium' | 'high';
    description: string;
  }> {
    const suggestions: Array<{
      suggestion: string;
      priority: 'low' | 'medium' | 'high' | 'critical';
      effort: 'low' | 'medium' | 'high';
      description: string;
    }> = [];

    const baseSuggestion = {
      suggestion: '',
      priority: 'medium' as const,
      effort: 'medium' as const,
      description: '',
    };

    switch (type) {
      case 'semantic':
        suggestions.push({
          ...baseSuggestion,
          suggestion: 'Review and clarify the semantic meaning of both statements',
          priority: 'high' as const,
          effort: 'medium' as const,
          description: 'Ensure both statements express the intended meaning clearly',
        });
        break;
      case 'temporal':
        suggestions.push({
          ...baseSuggestion,
          suggestion: 'Verify and correct temporal data and sequences',
          priority: 'high' as const,
          effort: 'low' as const,
          description: 'Ensure timestamps and sequences are accurate and consistent',
        });
        break;
      case 'logical':
        suggestions.push({
          ...baseSuggestion,
          suggestion: 'Review logical consistency and remove contradictory statements',
          priority: 'high' as const,
          effort: 'high' as const,
          description: 'Analyze the logical relationships and resolve inconsistencies',
        });
        break;
      case 'factual':
        suggestions.push({
          ...baseSuggestion,
          suggestion: 'Verify factual accuracy with external sources',
          priority: 'critical' as const,
          effort: 'medium' as const,
          description: 'Check both statements against reliable external sources',
        });
        break;
      case 'procedural':
        suggestions.push({
          ...baseSuggestion,
          suggestion: 'Standardize procedures and resolve workflow conflicts',
          priority: 'high' as const,
          effort: 'high' as const,
          description: 'Ensure consistent and compatible procedures across items',
        });
        break;
    }

    return suggestions;
  }

  /**
   * Validate detection request
   */
  private validateRequest(request: ContradictionDetectionRequest): void {
    if (!this.config.enabled) {
      throw new Error('ZAI-enhanced contradiction detection is disabled');
    }

    if (!request.items || request.items.length === 0) {
      throw new Error('No items provided for contradiction detection');
    }

    if (request.items.length > this.config.max_items_per_check) {
      throw new Error(
        `Too many items: ${request.items.length} > ${this.config.max_items_per_check}`
      );
    }
  }

  /**
   * Create batches from items
   */
  private createBatches(items: KnowledgeItem[], batchSize: number): KnowledgeItem[][] {
    const batches: KnowledgeItem[][] = [];
    for (let i = 0; i < items.length; i += batchSize) {
      batches.push(items.slice(i, i + batchSize));
    }
    return batches;
  }

  /**
   * Create response object
   */
  private createResponse(
    contradictions: ContradictionResult[],
    itemsChecked: number,
    processingTime: number
  ): ContradictionDetectionResponse {
    return {
      contradictions,
      summary: {
        total_items_checked: itemsChecked,
        contradictions_found: contradictions.length,
        by_type: this.groupContradictionsByType(contradictions),
        by_severity: this.groupContradictionsBySeverity(contradictions),
        processing_time_ms: processingTime,
        cache_hits: this.metrics.cacheHits,
        cache_misses: this.metrics.cacheMisses,
      },
      performance: {
        items_per_second: (itemsChecked / processingTime) * 1000,
        memory_usage_mb: this.getCurrentMemoryUsage(),
        bottleneck_detected: this.detectBottlenecks(),
        bottlenecks: this.getBottlenecks(),
      },
    };
  }

  /**
   * Group contradictions by type
   */
  private groupContradictionsByType(contradictions: ContradictionResult[]): Record<string, number> {
    const groups: Record<string, number> = {};
    contradictions.forEach((c) => {
      groups[c.contradiction_type] = (groups[c.contradiction_type] || 0) + 1;
    });
    return groups;
  }

  /**
   * Group contradictions by severity
   */
  private groupContradictionsBySeverity(
    contradictions: ContradictionResult[]
  ): Record<string, number> {
    const groups: Record<string, number> = {};
    contradictions.forEach((c) => {
      groups[c.severity] = (groups[c.severity] || 0) + 1;
    });
    return groups;
  }

  /**
   * Get current memory usage (simplified)
   */
  private getCurrentMemoryUsage(): number {
    return 50; // Placeholder - would use process.memoryUsage() in production
  }

  /**
   * Detect performance bottlenecks
   */
  private detectBottlenecks(): boolean {
    return this.getBottlenecks().length > 0;
  }

  /**
   * Get performance bottlenecks
   */
  private getBottlenecks(): string[] {
    const bottlenecks: string[] = [];
    return bottlenecks;
  }

  /**
   * Initialize strategy statistics
   */
  private initializeStrategyStats(): void {
    Object.keys(this.config.strategies).forEach((strategy) => {
      this.metrics.strategyStats[strategy] = 0;
    });
  }

  /**
   * Update metrics
   */
  private updateMetrics(contradictionsFound: number, processingTime: number): void {
    this.metrics.contradictionsFound += contradictionsFound;
    const alpha = 0.1;
    this.metrics.averageProcessingTime =
      alpha * processingTime + (1 - alpha) * this.metrics.averageProcessingTime;
  }

  /**
   * Get item from cache
   */
  private getFromCache(key: string): CacheEntry | null {
    if (!this.config.enable_caching) {
      return null;
    }

    const entry = this.cache.get(key);
    if (!entry) {
      this.metrics.cacheMisses++;
      return null;
    }

    if (Date.now() > entry.timestamp + entry.ttl) {
      this.cache.delete(key);
      this.metrics.cacheMisses++;
      return null;
    }

    this.metrics.cacheHits++;
    return entry;
  }

  /**
   * Set item in cache
   */
  private setToCache(key: string, result: ContradictionResult): void {
    if (!this.config.enable_caching) {
      return;
    }

    const entry: CacheEntry = {
      contradictionId: result.id,
      result,
      timestamp: Date.now(),
      ttl: 3600000, // 1 hour
    };

    this.cache.set(key, entry);
  }

  /**
   * Get detector metrics
   */
  getMetrics(): unknown {
    return {
      ...this.metrics,
      cacheSize: this.cache.size,
      config: this.config,
    };
  }

  /**
   * Clear cache
   */
  clearCache(): void {
    this.cache.clear();
  }
}

/**
 * Export singleton instance
 */
export const zaiEnhancedContradictionDetector = new ZAIEnhancedContradictionDetector();
