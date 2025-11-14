// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck


/**
 * Temporal Contradiction Detection Strategy
 *
 * Advanced temporal contradiction detection using ZAI glm-4.6 model.
 * Detects inconsistencies in timelines, sequences, and temporal relationships
 * between knowledge items.
 *
 * @author Cortex Team
 * @version 3.0.0
 * @since 2025
 */

import { randomUUID } from 'crypto';

import type {
  ContradictionResult,
  KnowledgeItem,
} from '../../../types/contradiction-detector.interface';
import { logger } from '../../../utils/logger.js';
import { zaiClientService } from '../../ai/zai-client.service';

/**
 * Temporal contradiction types
 */
export type TemporalContradictionType =
  | 'sequence_violation'
  | 'timing_conflict'
  | 'duration_contradiction'
  | 'deadline_conflict'
  | 'simultaneity_conflict'
  | 'causality_violation'
  | 'temporal_impossibility';

/**
 * Temporal data extracted from knowledge item
 */
interface TemporalData {
  timestamps: Array<{
    type: 'created_at' | 'updated_at' | 'mentioned' | 'deadline' | 'start_time' | 'end_time';
    value: Date;
    confidence: number;
    source: string;
  }>;
  sequences: Array<{
    type: 'before' | 'after' | 'during' | 'simultaneous';
    reference: string;
    target: string;
    confidence: number;
  }>;
  durations: Array<{
    value: number; // in milliseconds
    unit: 'milliseconds' | 'seconds' | 'minutes' | 'hours' | 'days' | 'weeks' | 'months' | 'years';
    confidence: number;
    source: string;
  }>;
  temporal_markers: Array<{
    marker: string;
    position: number;
    type: 'relative' | 'absolute' | 'duration';
    confidence: number;
  }>;
}

/**
 * Temporal analysis result
 */
interface TemporalAnalysisResult {
  has_contradiction: boolean;
  confidence: number;
  contradiction_type: TemporalContradictionType;
  description: string;
  reasoning: string;
  evidence: Array<{
    type:
      | 'timeline_conflict'
      | 'sequence_violation'
      | 'duration_mismatch'
      | 'deadline_impossibility';
    content: string;
    confidence: number;
    source_item: number;
    temporal_data: unknown;
  }>;
  timeline_analysis: {
    item1_events: Array<{ time: Date; description: string }>;
    item2_events: Array<{ time: Date; description: string }>;
    conflicts: Array<{ conflict: string; severity: number }>;
  };
}

/**
 * Temporal contradiction detection configuration
 */
interface TemporalContradictionConfig {
  confidence_threshold: number;
  max_tokens: number;
  temperature: number;
  enable_sequence_analysis: boolean;
  enable_duration_analysis: boolean;
  enable_deadline_analysis: boolean;
  timeline_fuzziness_ms: number;
}

/**
 * Default configuration
 */
const DEFAULT_CONFIG: TemporalContradictionConfig = {
  confidence_threshold: 0.7,
  max_tokens: 1500,
  temperature: 0.1,
  enable_sequence_analysis: true,
  enable_duration_analysis: true,
  enable_deadline_analysis: true,
  timeline_fuzziness_ms: 60000, // 1 minute
};

/**
 * Temporal Contradiction Detection Strategy
 *
 * Uses ZAI's advanced reasoning capabilities to detect temporal contradictions
 * in timelines, sequences, durations, and deadlines between knowledge items.
 */
export class TemporalContradictionStrategy {
  private config: TemporalContradictionConfig;
  private cache: Map<string, { result: TemporalAnalysisResult; timestamp: number }> = new Map();

  constructor(config: Partial<TemporalContradictionConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    logger.info('Temporal Contradiction Strategy initialized', { config: this.config });
  }

  /**
   * Detect temporal contradictions between two knowledge items
   */
  async detectTemporalContradiction(
    item1: KnowledgeItem,
    item2: KnowledgeItem
  ): Promise<ContradictionResult | null> {
    const cacheKey = `temporal:${item1.id}:${item2.id}`;
    const cached = this.getFromCache(cacheKey);

    if (cached) {
      return this.createResultFromAnalysis(item1, item2, cached.result);
    }

    try {
      // Extract temporal data from both items
      const temporal1 = this.extractTemporalData(item1);
      const temporal2 = this.extractTemporalData(item2);

      // Quick check for obvious contradictions
      const quickContradiction = this.quickTemporalCheck(temporal1, temporal2);
      if (quickContradiction) {
        const result = this.createQuickContradictionResult(item1, item2, quickContradiction);
        this.setToCache(cacheKey, quickContradiction);
        return result;
      }

      // Deep analysis using ZAI
      const analysis = await this.analyzeTemporalContradiction(item1, item2, temporal1, temporal2);

      if (analysis.has_contradiction && analysis.confidence >= this.config.confidence_threshold) {
        this.setToCache(cacheKey, analysis);
        return this.createResultFromAnalysis(item1, item2, analysis);
      }

      return null;
    } catch (error) {
      logger.error(
        { error, item1Id: item1.id, item2Id: item2.id },
        'Temporal contradiction detection failed'
      );
      return null;
    }
  }

  /**
   * Extract temporal data from a knowledge item
   */
  private extractTemporalData(item: KnowledgeItem): TemporalData {
    const content = this.extractContent(item);
    const temporalData: TemporalData = {
      timestamps: [],
      sequences: [],
      durations: [],
      temporal_markers: [],
    };

    // Extract timestamps from content
    temporalData.timestamps.push(...this.extractTimestamps(content));

    // Extract sequence relationships
    temporalData.sequences.push(...this.extractSequences(content));

    // Extract durations
    temporalData.durations.push(...this.extractDurations(content));

    // Extract temporal markers
    temporalData.temporal_markers.push(...this.extractTemporalMarkers(content));

    // Add metadata timestamps
    if (item.created_at) {
      temporalData.timestamps.push({
        type: 'created_at',
        value: new Date(item.created_at),
        confidence: 1.0,
        source: 'metadata',
      });
    }

    if (item.updated_at) {
      temporalData.timestamps.push({
        type: 'updated_at',
        value: new Date(item.updated_at),
        confidence: 1.0,
        source: 'metadata',
      });
    }

    return temporalData;
  }

  /**
   * Extract timestamps from text
   */
  private extractTimestamps(content: string): Array<{
    type: 'mentioned' | 'deadline' | 'start_time' | 'end_time';
    value: Date;
    confidence: number;
    source: string;
  }> {
    const timestamps: Array<{
      type: 'mentioned' | 'deadline' | 'start_time' | 'end_time';
      value: Date;
      confidence: number;
      source: string;
    }> = [];

    // Date patterns
    const patterns = [
      {
        regex: /\d{4}-\d{2}-\d{2}/g,
        type: 'mentioned' as const,
      },
      {
        regex: /\d{2}\/\d{2}\/\d{4}/g,
        type: 'mentioned' as const,
      },
      {
        regex: /\d{1,2}\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{4}/gi,
        type: 'mentioned' as const,
      },
    ];

    patterns.forEach(({ regex, type }) => {
      const matches = content.match(regex);
      if (matches) {
        matches.forEach((match) => {
          const date = new Date(match);
          if (!isNaN(date.getTime())) {
            timestamps.push({
              type,
              value: date,
              confidence: 0.8,
              source: match,
            });
          }
        });
      }
    });

    // Look for deadline indicators
    const deadlineRegex =
      /(deadline|due by|due date|complete by)\s*:?\s*([0-9]{4}-[0-9]{2}-[0-9]{2}|[0-9]{2}\/[0-9]{2}\/[0-9]{4})/gi;
    const deadlineMatches = content.match(deadlineRegex);
    if (deadlineMatches) {
      deadlineMatches.forEach((match) => {
        const dateMatch = match.match(/([0-9]{4}-[0-9]{2}-[0-9]{2}|[0-9]{2}\/[0-9]{2}\/[0-9]{4})/);
        if (dateMatch) {
          const date = new Date(dateMatch[1]);
          if (!isNaN(date.getTime())) {
            timestamps.push({
              type: 'deadline',
              value: date,
              confidence: 0.9,
              source: match,
            });
          }
        }
      });
    }

    return timestamps;
  }

  /**
   * Extract sequence relationships from text
   */
  private extractSequences(content: string): Array<{
    type: 'before' | 'after' | 'during' | 'simultaneous';
    reference: string;
    target: string;
    confidence: number;
  }> {
    const sequences: Array<{
      type: 'before' | 'after' | 'during' | 'simultaneous';
      reference: string;
      target: string;
      confidence: number;
    }> = [];

    // Sequence patterns
    const sequencePatterns = [
      {
        regex: /(\w+(?:\s+\w+)*)\s+(?:before|prior to)\s+(\w+(?:\s+\w+)*)/gi,
        type: 'before' as const,
      },
      {
        regex: /(\w+(?:\s+\w+)*)\s+(?:after|following)\s+(\w+(?:\s+\w+)*)/gi,
        type: 'after' as const,
      },
      {
        regex: /(\w+(?:\s+\w+)*)\s+(?:during|while)\s+(\w+(?:\s+\w+)*)/gi,
        type: 'during' as const,
      },
      {
        regex: /(\w+(?:\s+\w+)*)\s+(?:at the same time as|simultaneous with)\s+(\w+(?:\s+\w+)*)/gi,
        type: 'simultaneous' as const,
      },
    ];

    sequencePatterns.forEach(({ regex, type }) => {
      const matches = content.matchAll(regex);
      for (const match of matches) {
        sequences.push({
          type,
          reference: match[1],
          target: match[2],
          confidence: 0.7,
        });
      }
    });

    return sequences;
  }

  /**
   * Extract durations from text
   */
  private extractDurations(content: string): Array<{
    value: number;
    unit: 'milliseconds' | 'seconds' | 'minutes' | 'hours' | 'days' | 'weeks' | 'months' | 'years';
    confidence: number;
    source: string;
  }> {
    const durations: Array<{
      value: number;
      unit:
        | 'milliseconds'
        | 'seconds'
        | 'minutes'
        | 'hours'
        | 'days'
        | 'weeks'
        | 'months'
        | 'years';
      confidence: number;
      source: string;
    }> = [];

    // Duration patterns
    const durationPatterns = [
      {
        regex: /(\d+)\s+milliseconds?/gi,
        unit: 'milliseconds' as const,
        multiplier: 1,
      },
      {
        regex: /(\d+)\s+seconds?/gi,
        unit: 'seconds' as const,
        multiplier: 1000,
      },
      {
        regex: /(\d+)\s+minutes?/gi,
        unit: 'minutes' as const,
        multiplier: 60000,
      },
      {
        regex: /(\d+)\s+hours?/gi,
        unit: 'hours' as const,
        multiplier: 3600000,
      },
      {
        regex: /(\d+)\s+days?/gi,
        unit: 'days' as const,
        multiplier: 86400000,
      },
      {
        regex: /(\d+)\s+weeks?/gi,
        unit: 'weeks' as const,
        multiplier: 604800000,
      },
      {
        regex: /(\d+)\s+months?/gi,
        unit: 'months' as const,
        multiplier: 2592000000, // ~30 days
      },
      {
        regex: /(\d+)\s+years?/gi,
        unit: 'years' as const,
        multiplier: 31536000000, // ~365 days
      },
    ];

    durationPatterns.forEach(({ regex, unit, multiplier }) => {
      const matches = content.matchAll(regex);
      for (const match of matches) {
        const value = parseInt(match[1]) * multiplier;
        durations.push({
          value,
          unit,
          confidence: 0.8,
          source: match[0],
        });
      }
    });

    return durations;
  }

  /**
   * Extract temporal markers from text
   */
  private extractTemporalMarkers(content: string): Array<{
    marker: string;
    position: number;
    type: 'relative' | 'absolute' | 'duration';
    confidence: number;
  }> {
    const markers: Array<{
      marker: string;
      position: number;
      type: 'relative' | 'absolute' | 'duration';
      confidence: number;
    }> = [];

    const temporalMarkers = [
      'before',
      'after',
      'during',
      'while',
      'since',
      'until',
      'when',
      'first',
      'second',
      'then',
      'next',
      'finally',
      'initially',
      'previously',
      'immediately',
      'concurrently',
      'simultaneously',
      'meanwhile',
      'deadline',
      'due',
      'scheduled',
      'planned',
      'estimated',
      'expected',
    ];

    temporalMarkers.forEach((marker) => {
      const regex = new RegExp(`\\b${marker}\\b`, 'gi');
      let match;
      while ((match = regex.exec(content)) !== null) {
        markers.push({
          marker: match[0],
          position: match.index,
          type: 'relative',
          confidence: 0.6,
        });
      }
    });

    return markers;
  }

  /**
   * Quick check for obvious temporal contradictions
   */
  private quickTemporalCheck(
    temporal1: TemporalData,
    temporal2: TemporalData
  ): TemporalAnalysisResult | null {
    // Check for sequence violations
    for (const seq1 of temporal1.sequences) {
      for (const seq2 of temporal2.sequences) {
        if (this.isSequenceViolation(seq1, seq2)) {
          return {
            has_contradiction: true,
            confidence: 0.9,
            contradiction_type: 'sequence_violation',
            description: `Sequence contradiction detected: ${seq1.reference} ${seq1.type} ${seq1.target} conflicts with ${seq2.reference} ${seq2.type} ${seq2.target}`,
            reasoning: 'The two statements contain contradictory sequence relationships',
            evidence: [
              {
                type: 'sequence_violation',
                content: `Sequence conflict between "${seq1.reference} ${seq1.type} ${seq1.target}" and "${seq2.reference} ${seq2.type} ${seq2.target}"`,
                confidence: 0.9,
                source_item: 1,
                temporal_data: { seq1, seq2 },
              },
            ],
            timeline_analysis: {
              item1_events: [],
              item2_events: [],
              conflicts: [{ conflict: 'sequence_violation', severity: 0.9 }],
            },
          };
        }
      }
    }

    return null;
  }

  /**
   * Check if two sequences violate each other
   */
  private isSequenceViolation(
    seq1: {
      type: 'before' | 'after' | 'during' | 'simultaneous';
      reference: string;
      target: string;
    },
    seq2: {
      type: 'before' | 'after' | 'during' | 'simultaneous';
      reference: string;
      target: string;
    }
  ): boolean {
    // Same items with contradictory sequence relationships
    if (seq1.reference.toLowerCase() === seq2.reference.toLowerCase()) {
      if (
        (seq1.type === 'before' && seq2.type === 'after') ||
        (seq1.type === 'after' && seq2.type === 'before')
      ) {
        return true;
      }
    }

    // Cross-reference contradictions
    if (
      seq1.reference.toLowerCase() === seq2.target.toLowerCase() &&
      seq1.target.toLowerCase() === seq2.reference.toLowerCase()
    ) {
      if (seq1.type === seq2.type) {
        return true; // Both say A before B and B before A
      }
    }

    return false;
  }

  /**
   * Analyze temporal contradiction using ZAI
   */
  private async analyzeTemporalContradiction(
    item1: KnowledgeItem,
    item2: KnowledgeItem,
    temporal1: TemporalData,
    temporal2: TemporalData
  ): Promise<TemporalAnalysisResult> {
    const prompt = this.buildTemporalAnalysisPrompt(item1, item2, temporal1, temporal2);

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

      return JSON.parse(response.choices[0].message.content) as TemporalAnalysisResult;
    } catch (error) {
      logger.error(
        { error, item1Id: item1.id, item2Id: item2.id },
        'ZAI temporal analysis failed'
      );
      throw error;
    }
  }

  /**
   * Get system prompt for temporal contradiction detection
   */
  private getSystemPrompt(): string {
    return `You are an expert temporal contradiction detector specializing in identifying timeline inconsistencies and sequence violations.

TEMPORAL CONTRADICTION TYPES:
1. "sequence_violation" - Events claimed to happen in impossible orders
2. "timing_conflict" - Events claimed at conflicting times
3. "duration_contradiction" - Inconsistent duration claims
4. "deadline_conflict" - Impossible or conflicting deadlines
5. "simultaneity_conflict" - Events claimed simultaneous when they can't be
6. "causality_violation" - Effect claimed before cause
7. "temporal_impossibility" - Logically impossible temporal scenarios

ANALYSIS APPROACH:
1. Extract all temporal information (dates, times, durations, sequences)
2. Build timeline for each item
3. Identify conflicts between timelines
4. Check sequence consistency
5. Verify duration claims
6. Analyze deadline feasibility
7. Check causality relationships

RESPONSE FORMAT:
{
  "has_contradiction": boolean,
  "confidence": number (0-1),
  "contradiction_type": "sequence_violation" | "timing_conflict" | "duration_contradiction" | "deadline_conflict" | "simultaneity_conflict" | "causality_violation" | "temporal_impossibility",
  "description": string,
  "reasoning": string,
  "evidence": [
    {
      "type": "timeline_conflict" | "sequence_violation" | "duration_mismatch" | "deadline_impossibility",
      "content": string,
      "confidence": number,
      "source_item": 1 or 2,
      "temporal_data": object
    }
  ],
  "timeline_analysis": {
    "item1_events": [{"time": "ISO_date", "description": string}],
    "item2_events": [{"time": "ISO_date", "description": string}],
    "conflicts": [{"conflict": string, "severity": number}]
  }
}

IMPORTANT:
- Only report contradictions with confidence >= 0.6
- Consider timezone differences and date formats
- Account for approximate language ("about", "around")
- Identify both explicit and implicit temporal relationships
- Provide specific evidence for each contradiction`;
  }

  /**
   * Build analysis prompt for temporal contradiction
   */
  private buildTemporalAnalysisPrompt(
    item1: KnowledgeItem,
    item2: KnowledgeItem,
    temporal1: TemporalData,
    temporal2: TemporalData
  ): string {
    const content1 = this.extractContent(item1);
    const content2 = this.extractContent(item2);

    return `Analyze these two knowledge items for temporal contradictions:

ITEM 1 (${item1.kind}):
Content: ${content1}
Temporal Data: ${JSON.stringify(temporal1, null, 2)}

ITEM 2 (${item2.kind}):
Content: ${content2}
Temporal Data: ${JSON.stringify(temporal2, null, 2)}

ANALYSIS FOCUS:
1. Timeline conflicts and sequence violations
2. Timing inconsistencies and overlaps
3. Duration contradictions and impossibilities
4. Deadline conflicts and feasibility issues
5. Causality violations (effects before causes)
6. Simultaneity claims that are impossible
7. Temporal logic inconsistencies

CONSIDER:
- Relative vs absolute timing
- Sequence dependencies
- Duration reasonableness
- Deadline feasibility
- Timezone considerations
- Approximate language (about, around, approximately)
- Implicit temporal relationships

Provide detailed temporal analysis focusing on timeline consistency and sequence logic.`;
  }

  /**
   * Extract content from knowledge item
   */
  private extractContent(item: KnowledgeItem): string {
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
    analysis: TemporalAnalysisResult
  ): ContradictionResult {
    const severity = this.calculateSeverity(analysis.confidence, analysis.contradiction_type);

    return {
      id: randomUUID(),
      detected_at: new Date(),
      contradiction_type: 'temporal',
      confidence_score: analysis.confidence,
      severity,
      primary_item_id: item1.id || randomUUID(),
      conflicting_item_ids: [item2.id || randomUUID()],
      description: analysis.description,
      reasoning: analysis.reasoning,
      metadata: {
        detection_method: 'zai_temporal_analysis',
        algorithm_version: '3.0.0',
        processing_time_ms: 0,
        comparison_details: {
          contradiction_subtype: analysis.contradiction_type,
          timeline_analysis: analysis.timeline_analysis,
          item_types: [item1.kind, item2.kind],
        },
        evidence: analysis.evidence.map((ev) => ({
          ...ev,
          evidence_type: ev.type,
          item_id: (ev.source_item === 1 ? item1.id : item2.id) || '',
        })),
      },
      resolution_suggestions: this.generateResolutionSuggestions(
        analysis.contradiction_type,
        severity
      ),
    };
  }

  /**
   * Create quick contradiction result
   */
  private createQuickContradictionResult(
    item1: KnowledgeItem,
    item2: KnowledgeItem,
    analysis: TemporalAnalysisResult
  ): ContradictionResult {
    const severity = 'high';

    return {
      id: randomUUID(),
      detected_at: new Date(),
      contradiction_type: 'temporal',
      confidence_score: analysis.confidence,
      severity,
      primary_item_id: item1.id || randomUUID(),
      conflicting_item_ids: [item2.id || randomUUID()],
      description: analysis.description,
      reasoning: analysis.reasoning,
      metadata: {
        detection_method: 'quick_temporal_check',
        algorithm_version: '3.0.0',
        processing_time_ms: 0,
        comparison_details: {
          contradiction_subtype: analysis.contradiction_type,
          quick_check: true,
          item_types: [item1.kind, item2.kind],
        },
        evidence: analysis.evidence.map((ev) => ({
          ...ev,
          evidence_type: ev.type,
          item_id: (ev.source_item === 1 ? item1.id : item2.id) || '',
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
    type: TemporalContradictionType
  ): 'low' | 'medium' | 'high' | 'critical' {
    // Base severity on confidence
    if (confidence >= 0.9) return 'critical';
    if (confidence >= 0.8) return 'high';
    if (confidence >= 0.6) return 'medium';

    // Adjust based on contradiction type
    const criticalTypes = ['causality_violation', 'temporal_impossibility'];
    const highTypes = ['sequence_violation', 'deadline_conflict'];

    if (criticalTypes.includes(type) && confidence >= 0.7) return 'critical';
    if (highTypes.includes(type) && confidence >= 0.6) return 'high';

    return 'low';
  }

  /**
   * Generate resolution suggestions based on contradiction type
   */
  private generateResolutionSuggestions(
    type: TemporalContradictionType,
    severity: string
  ): Array<{
    suggestion: string;
    priority: 'low' | 'medium' | 'high';
    effort: 'low' | 'medium' | 'high';
    description: string;
  }> {
    const suggestions: Array<{
      suggestion: string;
      priority: 'low' | 'medium' | 'high';
      effort: 'low' | 'medium' | 'high';
      description: string;
    }> = [];

    const basePriority =
      severity === 'critical'
        ? ('high' as const)
        : severity === 'high'
          ? ('high' as const)
          : severity === 'medium'
            ? ('medium' as const)
            : ('low' as const);

    switch (type) {
      case 'sequence_violation':
        suggestions.push({
          suggestion: 'Correct the sequence order to be logically consistent',
          priority: 'high',
          effort: 'medium',
          description: 'Review and fix the temporal sequence to ensure proper ordering',
        });
        break;

      case 'timing_conflict':
        suggestions.push({
          suggestion: 'Resolve timing conflicts and synchronize timestamps',
          priority: 'high',
          effort: 'low',
          description: 'Ensure all timing information is consistent and accurate',
        });
        break;

      case 'duration_contradiction':
        suggestions.push({
          suggestion: 'Verify and correct duration claims',
          priority: 'medium',
          effort: 'medium',
          description: 'Check all duration statements for accuracy and consistency',
        });
        break;

      case 'deadline_conflict':
        suggestions.push({
          suggestion: 'Review and adjust deadlines to be realistic and consistent',
          priority: 'high',
          effort: 'high',
          description: "Ensure deadlines are feasible and don't conflict with other constraints",
        });
        break;

      case 'causality_violation':
        suggestions.push({
          suggestion: 'Fix causality violations (effects before causes)',
          priority: 'high',
          effort: 'high',
          description: 'Ensure causes always precede their effects in the timeline',
        });
        break;

      case 'temporal_impossibility':
        suggestions.push({
          suggestion: 'Resolve logically impossible temporal scenarios',
          priority: 'high',
          effort: 'high',
          description: 'Review and fix temporal relationships that violate logical constraints',
        });
        break;
    }

    return suggestions;
  }

  /**
   * Get strategy statistics
   */
  getStatistics(): {
    cacheSize: number;
    config: TemporalContradictionConfig;
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
  private getFromCache(key: string): { result: TemporalAnalysisResult; timestamp: number } | null {
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
  private setToCache(key: string, result: TemporalAnalysisResult): void {
    this.cache.set(key, {
      result,
      timestamp: Date.now(),
    });
  }
}

/**
 * Export singleton instance
 */
export const temporalContradictionStrategy = new TemporalContradictionStrategy();

