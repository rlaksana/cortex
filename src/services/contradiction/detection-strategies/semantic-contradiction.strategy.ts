// @ts-nocheck
/**
 * Semantic Contradiction Detection Strategy
 *
 * Advanced semantic contradiction detection using ZAI glm-4.6 model.
 * Detects contradictions in meaning, intent, and semantic content
 * without relying solely on keyword matching.
 *
 * @author Cortex Team
 * @version 3.0.0
 * @since 2025
 */

import { randomUUID } from 'crypto';
import { logger } from '../../../utils/logger';
import { zaiClientService } from '../../ai/zai-client.service';
import type {
  KnowledgeItem,
  ContradictionResult,
  ContradictionDetail,
} from '../../../types/contradiction-detector.interface';

/**
 * Semantic contradiction types
 */
export type SemanticContradictionType =
  | 'direct_opposition'
  | 'implicit_contradiction'
  | 'contextual_conflict'
  | 'sentiment_contradiction'
  | 'assertion_contradiction'
  | 'negation_contradiction';

/**
 * Semantic analysis result
 */
interface SemanticAnalysisResult {
  has_contradiction: boolean;
  confidence: number;
  contradiction_type: SemanticContradictionType;
  description: string;
  reasoning: string;
  evidence: Array<{
    type: 'semantic_opposition' | 'negation' | 'sentiment_conflict' | 'context_mismatch';
    content: string;
    confidence: number;
    source_item: number;
  }>;
  semantic_similarity?: number;
  sentiment_analysis?: {
    item1: { sentiment: string; confidence: number };
    item2: { sentiment: string; confidence: number };
  };
}

/**
 * Semantic contradiction detection configuration
 */
interface SemanticContradictionConfig {
  confidence_threshold: number;
  max_tokens: number;
  temperature: number;
  enable_sentiment_analysis: boolean;
  enable_similarity_checking: boolean;
  similarity_threshold: number;
}

/**
 * Default configuration
 */
const DEFAULT_CONFIG: SemanticContradictionConfig = {
  confidence_threshold: 0.7,
  max_tokens: 1500,
  temperature: 0.1,
  enable_sentiment_analysis: true,
  enable_similarity_checking: true,
  similarity_threshold: 0.3,
};

/**
 * Semantic Contradiction Detection Strategy
 *
 * Uses ZAI's advanced NLP capabilities to detect semantic contradictions
 * in meaning, sentiment, and context between knowledge items.
 */
export class SemanticContradictionStrategy {
  private config: SemanticContradictionConfig;
  private cache: Map<string, { result: SemanticAnalysisResult; timestamp: number }> = new Map();

  constructor(config: Partial<SemanticContradictionConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    logger.info('Semantic Contradiction Strategy initialized', { config: this.config });
  }

  /**
   * Detect semantic contradictions between two knowledge items
   */
  async detectSemanticContradiction(
    item1: KnowledgeItem,
    item2: KnowledgeItem
  ): Promise<ContradictionResult | null> {
    const cacheKey = `semantic:${item1.id}:${item2.id}`;
    const cached = this.getFromCache(cacheKey);

    if (cached) {
      return this.createResultFromAnalysis(item1, item2, cached.result);
    }

    try {
      const analysis = await this.analyzeSemanticContradiction(item1, item2);

      if (analysis.has_contradiction && analysis.confidence >= this.config.confidence_threshold) {
        this.setToCache(cacheKey, analysis);
        return this.createResultFromAnalysis(item1, item2, analysis);
      }

      return null;
    } catch (error) {
      logger.error(
        { error, item1Id: item1.id, item2Id: item2.id },
        'Semantic contradiction detection failed'
      );
      return null;
    }
  }

  /**
   * Analyze semantic contradiction using ZAI
   */
  private async analyzeSemanticContradiction(
    item1: KnowledgeItem,
    item2: KnowledgeItem
  ): Promise<SemanticAnalysisResult> {
    const prompt = this.buildSemanticAnalysisPrompt(item1, item2);

    try {
      const response = await zaiClientService.generateCompletion({
        messages: [
          {
            role: 'system',
            content: this.getSystemPrompt(),
          },
          {
            role: 'user',
            content: prompt,
          },
        ],
        temperature: this.config.temperature,
        maxTokens: this.config.max_tokens,
      });

      return JSON.parse(response.choices[0].message.content) as SemanticAnalysisResult;
    } catch (error) {
      logger.error(
        { error, item1Id: item1.id, item2Id: item2.id },
        'ZAI semantic analysis failed'
      );
      throw error;
    }
  }

  /**
   * Get system prompt for semantic contradiction detection
   */
  private getSystemPrompt(): string {
    return `You are an expert semantic contradiction detector specializing in identifying contradictions in meaning, intent, and context.

SEMANTIC CONTRADICTION TYPES:
1. "direct_opposition" - Statements directly oppose each other (e.g., "secure" vs "vulnerable")
2. "implicit_contradiction" - Contradictions that aren't explicit but implied by context
3. "contextual_conflict" - Contradictions that emerge from different contexts or framings
4. "sentiment_contradiction" - Contradictory emotional tones or assessments
5. "assertion_contradiction" - Confident assertions that contradict each other
6. "negation_contradiction" - One statement negates or contradicts another

ANALYSIS APPROACH:
1. Extract core meaning and intent from each statement
2. Identify semantic oppositions using contextual understanding
3. Analyze sentiment and emotional tone for contradictions
4. Consider context-specific meanings and terminology
5. Look for implicit contradictions that aren't surface-level
6. Check for assertion confidence vs contradictory content

RESPONSE FORMAT:
{
  "has_contradiction": boolean,
  "confidence": number (0-1),
  "contradiction_type": "direct_opposition" | "implicit_contradiction" | "contextual_conflict" | "sentiment_contradiction" | "assertion_contradiction" | "negation_contradiction",
  "description": string,
  "reasoning": string,
  "evidence": [
    {
      "type": "semantic_opposition" | "negation" | "sentiment_conflict" | "context_mismatch",
      "content": string,
      "confidence": number,
      "source_item": 1 or 2
    }
  ],
  "semantic_similarity": number (0-1),
  "sentiment_analysis": {
    "item1": { "sentiment": string, "confidence": number },
    "item2": { "sentiment": string, "confidence": number }
  }
}

IMPORTANT:
- Only report contradictions with confidence >= 0.6
- Consider technical jargon and domain-specific meanings
- Account for different contexts and framings
- Provide specific evidence for each contradiction
- Explain the reasoning behind the contradiction detection`;
  }

  /**
   * Build analysis prompt for semantic contradiction
   */
  private buildSemanticAnalysisPrompt(item1: KnowledgeItem, item2: KnowledgeItem): string {
    const content1 = this.extractAndCleanContent(item1);
    const content2 = this.extractAndCleanContent(item2);

    return `Analyze these two knowledge items for semantic contradictions:

ITEM 1:
Type: ${item1.kind}
Content: ${content1}

ITEM 2:
Type: ${item2.kind}
Content: ${content2}

ANALYSIS FOCUS:
1. Core meaning and intent contradictions
2. Semantic oppositions beyond keyword matching
3. Contextual conflicts or incompatibilities
4. Sentiment or assessment contradictions
5. Implicit contradictions in meaning
6. Assertion confidence vs contradictory content

CONSIDER:
- Domain-specific terminology and meanings
- Context-dependent interpretations
- Nuanced semantic relationships
- Implied meanings and intentions
- Emotional tones and assessments
- Professional vs general language usage

Provide a detailed semantic analysis focusing on the deeper meaning and intent rather than surface-level keywords.`;
  }

  /**
   * Extract and clean content from item
   */
  private extractAndCleanContent(item: KnowledgeItem): string {
    let content = item.content || '';

    // If no content, extract from data
    if (!content && item.data) {
      content = JSON.stringify(item.data);
    }

    // Clean and normalize content
    content = content.replace(/\s+/g, ' ').trim().substring(0, 2000); // Limit length for analysis

    return content;
  }

  /**
   * Create ContradictionResult from analysis
   */
  private createResultFromAnalysis(
    item1: KnowledgeItem,
    item2: KnowledgeItem,
    analysis: SemanticAnalysisResult
  ): ContradictionResult {
    const severity = this.calculateSeverity(analysis.confidence, analysis.contradiction_type);

    return {
      id: randomUUID(),
      detected_at: new Date(),
      contradiction_type: 'semantic',
      confidence_score: analysis.confidence,
      severity,
      primary_item_id: item1.id || randomUUID(),
      conflicting_item_ids: [item2.id || randomUUID()],
      description: analysis.description,
      reasoning: analysis.reasoning,
      metadata: {
        detection_method: 'zai_semantic_analysis',
        algorithm_version: '3.0.0',
        model: 'zai-glm-4.6',
        processing_time_ms: 0,
        comparison_details: {
          contradiction_subtype: analysis.contradiction_type,
          semantic_similarity: analysis.semantic_similarity,
          sentiment_analysis: analysis.sentiment_analysis,
          item_types: [item1.kind, item2.kind],
        },
        evidence: analysis.evidence.map((ev) => ({
          ...ev,
          evidence_type: ev.type,
          item_id: ev.source_item === 1 ? item1.id : item2.id,
        })),
      },
      resolution_suggestions: this.generateResolutionSuggestions(
        analysis.contradiction_type,
        severity
      ),
    };
  }

  /**
   * Calculate severity based on confidence and contradiction type
   */
  private calculateSeverity(
    confidence: number,
    type: SemanticContradictionType
  ): 'low' | 'medium' | 'high' | 'critical' {
    // Base severity on confidence
    if (confidence >= 0.9) return 'critical';
    if (confidence >= 0.8) return 'high';
    if (confidence >= 0.6) return 'medium';

    // Adjust based on contradiction type
    const criticalTypes = ['direct_opposition', 'assertion_contradiction'];
    const highTypes = ['negation_contradiction', 'sentiment_contradiction'];

    if (criticalTypes.includes(type) && confidence >= 0.7) return 'critical';
    if (highTypes.includes(type) && confidence >= 0.6) return 'high';

    return 'low';
  }

  /**
   * Generate resolution suggestions based on contradiction type
   */
  private generateResolutionSuggestions(
    type: SemanticContradictionType,
    severity: string
  ): Array<{
    suggestion: string;
    priority: 'low' | 'medium' | 'high';
    effort: 'low' | 'medium' | 'high';
    description: string;
  }> {
    const suggestions = [];

    const basePriority =
      severity === 'critical'
        ? ('high' as const)
        : severity === 'high'
          ? ('high' as const)
          : severity === 'medium'
            ? ('medium' as const)
            : ('low' as const);

    switch (type) {
      case 'direct_opposition':
        suggestions.push({
          suggestion: 'Resolve direct semantic opposition by clarifying intended meaning',
          priority: 'high',
          effort: 'medium',
          description: 'Review both statements and ensure they express compatible meanings',
        });
        suggestions.push({
          suggestion: 'Consider if statements refer to different contexts or conditions',
          priority: 'medium',
          effort: 'low',
          description:
            'Add contextual qualifiers if statements are true under different conditions',
        });
        break;

      case 'implicit_contradiction':
        suggestions.push({
          suggestion: 'Clarify implicit meanings and unstated assumptions',
          priority: 'high',
          effort: 'high',
          description: 'Make implicit assumptions explicit and ensure compatibility',
        });
        break;

      case 'contextual_conflict':
        suggestions.push({
          suggestion: 'Harmonize contextual frameworks and perspectives',
          priority: 'medium',
          effort: 'medium',
          description: 'Ensure statements are compatible across different contexts or viewpoints',
        });
        break;

      case 'sentiment_contradiction':
        suggestions.push({
          suggestion: 'Resolve conflicting assessments or emotional tones',
          priority: 'medium',
          effort: 'low',
          description: 'Ensure consistent sentiment and evaluation across related statements',
        });
        break;

      case 'assertion_contradiction':
        suggestions.push({
          suggestion: 'Review and reconcile conflicting assertions',
          priority: 'critical',
          effort: 'high',
          description:
            'Verify which assertion is correct and update or qualify conflicting statements',
        });
        break;

      case 'negation_contradiction':
        suggestions.push({
          suggestion: 'Resolve negation conflicts and contradictory claims',
          priority: 'high',
          effort: 'medium',
          description: 'Clarify which statement should be negated or qualified',
        });
        break;
    }

    return suggestions;
  }

  /**
   * Batch process multiple item pairs
   */
  async batchDetectContradictions(
    itemPairs: Array<{ item1: KnowledgeItem; item2: KnowledgeItem }>
  ): Promise<
    Array<{ item1: KnowledgeItem; item2: KnowledgeItem; contradiction: ContradictionResult | null }>
  > {
    const results = [];

    for (const { item1, item2 } of itemPairs) {
      const contradiction = await this.detectSemanticContradiction(item1, item2);
      results.push({ item1, item2, contradiction });
    }

    return results;
  }

  /**
   * Get strategy statistics
   */
  getStatistics(): {
    cacheSize: number;
    config: SemanticContradictionConfig;
  } {
    return {
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

  /**
   * Get item from cache
   */
  private getFromCache(key: string): { result: SemanticAnalysisResult; timestamp: number } | null {
    const entry = this.cache.get(key);
    if (!entry) return null;

    // Check if cache entry is expired (1 hour)
    if (Date.now() - entry.timestamp > 3600000) {
      this.cache.delete(key);
      return null;
    }

    return entry;
  }

  /**
   * Set item in cache
   */
  private setToCache(key: string, result: SemanticAnalysisResult): void {
    this.cache.set(key, {
      result,
      timestamp: Date.now(),
    });
  }
}

/**
 * Export singleton instance
 */
export const semanticContradictionStrategy = new SemanticContradictionStrategy();

/**
 * Export class for testing
 */
export { SemanticContradictionStrategy };
