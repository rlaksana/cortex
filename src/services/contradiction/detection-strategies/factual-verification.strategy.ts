/**
 * Factual Verification Contradiction Detection Strategy
 *
 * Advanced factual contradiction detection using ZAI glm-4.6 model
 * with external source verification capabilities. Detects inconsistencies
 * in verifiable facts, data, and claims between knowledge items.
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
 * Factual contradiction types
 */
export type FactualContradictionType =
  | 'verifiable_fact'
  | 'numerical_data'
  | 'technical_spec'
  | 'temporal_fact'
  | 'source_conflict'
  | 'measurement_mismatch'
  | 'statistical_contradiction'
  | 'reference_discrepancy';

/**
 * Fact extraction result
 */
interface FactExtraction {
  facts: Array<{
    type: 'measurement' | 'count' | 'date' | 'specification' | 'statistic' | 'reference' | 'claim';
    content: string;
    value?: unknown;
    unit?: string;
    source?: string;
    confidence: number;
  }>;
  numerical_data: Array<{
    value: number;
    unit: string;
    context: string;
    confidence: number;
  }>;
  dates: Array<{
    date: Date;
    context: string;
    confidence: number;
  }>;
  specifications: Array<{
    parameter: string;
    value: unknown;
    unit?: string;
    context: string;
    confidence: number;
  }>;
  references: Array<{
    type: 'url' | 'document' | 'person' | 'organization' | 'source';
    identifier: string;
    context: string;
    confidence: number;
  }>;
}

/**
 * External verification result
 */
interface ExternalVerification {
  can_verify: boolean;
  verification_method: 'internal_consistency' | 'external_source' | 'calculation' | 'estimation';
  confidence: number;
  sources: Array<{
    type: 'internal' | 'external' | 'calculation';
    identifier: string;
    reliability: number;
  }>;
  result: {
    is_contradiction: boolean;
    evidence: string;
    explanation: string;
  };
}

/**
 * Factual analysis result
 */
interface FactualAnalysisResult {
  has_contradiction: boolean;
  confidence: number;
  contradiction_type: FactualContradictionType;
  description: string;
  reasoning: string;
  evidence: Array<{
    type: 'factual_discrepancy' | 'measurement_conflict' | 'spec_mismatch' | 'reference_conflict';
    content: string;
    confidence: number;
    source_item: number;
    fact_data: unknown;
  }>;
  external_verification: ExternalVerification;
  fact_comparison: {
    item1_facts: FactExtraction;
    item2_facts: FactExtraction;
    conflicts: Array<{
      fact_type: string;
      conflict: string;
      severity: number;
    }>;
  };
}

/**
 * Factual contradiction detection configuration
 */
interface FactualContradictionConfig {
  confidence_threshold: number;
  max_tokens: number;
  temperature: number;
  enable_external_verification: boolean;
  enable_numerical_analysis: boolean;
  enable_date_verification: boolean;
  tolerance_percentage: number;
  date_tolerance_days: number;
}

/**
 * Default configuration
 */
const DEFAULT_CONFIG: FactualContradictionConfig = {
  confidence_threshold: 0.7,
  max_tokens: 1500,
  temperature: 0.1,
  enable_external_verification: true,
  enable_numerical_analysis: true,
  enable_date_verification: true,
  tolerance_percentage: 5, // 5% tolerance for numerical values
  date_tolerance_days: 1,
};

/**
 * Factual Verification Contradiction Detection Strategy
 *
 * Uses ZAI's advanced reasoning capabilities to detect factual contradictions
 * with external source verification and data analysis.
 */
export class FactualVerificationStrategy {
  private config: FactualContradictionConfig;
  private cache: Map<string, { result: FactualAnalysisResult; timestamp: number }> = new Map();

  constructor(config: Partial<FactualContradictionConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    logger.info('Factual Verification Strategy initialized', { config: this.config });
  }

  /**
   * Detect factual contradictions between two knowledge items
   */
  async detectFactualContradiction(
    item1: KnowledgeItem,
    item2: KnowledgeItem
  ): Promise<ContradictionResult | null> {
    const cacheKey = `factual:${item1.id}:${item2.id}`;
    const cached = this.getFromCache(cacheKey);

    if (cached) {
      return this.createResultFromAnalysis(item1, item2, cached.result);
    }

    try {
      // Extract factual data from both items
      const facts1 = this.extractFacts(item1);
      const facts2 = this.extractFacts(item2);

      // Quick check for obvious contradictions
      const quickContradiction = this.quickFactCheck(facts1, facts2);
      if (quickContradiction) {
        const result = this.createQuickContradictionResult(item1, item2, quickContradiction);
        this.setToCache(cacheKey, quickContradiction);
        return result;
      }

      // Deep analysis using ZAI
      const analysis = await this.analyzeFactualContradiction(item1, item2, facts1, facts2);

      if (analysis.has_contradiction && analysis.confidence >= this.config.confidence_threshold) {
        this.setToCache(cacheKey, analysis);
        return this.createResultFromAnalysis(item1, item2, analysis);
      }

      return null;
    } catch (error) {
      logger.error(
        { error, item1Id: item1.id, item2Id: item2.id },
        'Factual contradiction detection failed'
      );
      return null;
    }
  }

  /**
   * Extract facts from a knowledge item
   */
  private extractFacts(item: KnowledgeItem): FactExtraction {
    const content = this.extractContent(item);
    const facts: FactExtraction = {
      facts: [],
      numerical_data: [],
      dates: [],
      specifications: [],
      references: [],
    };

    // Extract numerical data
    facts.numerical_data.push(...this.extractNumericalData(content));

    // Extract dates
    facts.dates.push(...this.extractDates(content));

    // Extract specifications
    facts.specifications.push(...this.extractSpecifications(content));

    // Extract references
    facts.references.push(...this.extractReferences(content));

    // Generate fact statements
    facts.facts.push(...this.generateFactStatements(facts, content));

    return facts;
  }

  /**
   * Extract numerical data from text
   */
  private extractNumericalData(content: string): Array<{
    value: number;
    unit: string;
    context: string;
    confidence: number;
  }> {
    const numericalData: Array<{
      value: number;
      unit: string;
      context: string;
      confidence: number;
    }> = [];

    // Numerical patterns with units
    const numericalPatterns = [
      {
        regex: /(\d+(?:\.\d+)?)\s*(%|percent|percentage)/gi,
        unit: '%',
      },
      {
        regex: /(\d+(?:\.\d+)?)\s*(ms|milliseconds?)/gi,
        unit: 'ms',
      },
      {
        regex: /(\d+(?:\.\d+)?)\s*(seconds?|s)/gi,
        unit: 's',
      },
      {
        regex: /(\d+(?:\.\d+)?)\s*(minutes?|min)/gi,
        unit: 'min',
      },
      {
        regex: /(\d+(?:\.\d+)?)\s*(hours?|hr|h)/gi,
        unit: 'h',
      },
      {
        regex: /(\d+(?:\.\d+)?)\s*(days?|d)/gi,
        unit: 'days',
      },
      {
        regex: /(\d+(?:\.\d+)?)\s*(bytes?|b)/gi,
        unit: 'bytes',
      },
      {
        regex: /(\d+(?:\.\d+)?)\s*(kb|kilobytes?)/gi,
        unit: 'KB',
      },
      {
        regex: /(\d+(?:\.\d+)?)\s*(mb|megabytes?)/gi,
        unit: 'MB',
      },
      {
        regex: /(\d+(?:\.\d+)?)\s*(gb|gigabytes?)/gi,
        unit: 'GB',
      },
    ];

    numericalPatterns.forEach(({ regex, unit }) => {
      const matches = content.matchAll(regex);
      for (const match of matches) {
        const value = parseFloat(match[1]);
        if (!isNaN(value)) {
          // Extract context around the number
          const startIndex = Math.max(0, match.index - 50);
          const endIndex = Math.min(content.length, match.index + match[0].length + 50);
          const context = content.substring(startIndex, endIndex).trim();

          numericalData.push({
            value,
            unit,
            context,
            confidence: 0.8,
          });
        }
      }
    });

    // Pattern for standalone numbers
    const standaloneNumberPattern = /\b(\d+(?:\.\d+)?)\b/g;
    const matches = content.matchAll(standaloneNumberPattern);
    for (const match of matches) {
      const value = parseFloat(match[1]);
      if (!isNaN(value)) {
        const startIndex = Math.max(0, match.index - 30);
        const endIndex = Math.min(content.length, match.index + match[0].length + 30);
        const context = content.substring(startIndex, endIndex).trim();

        numericalData.push({
          value,
          unit: 'count',
          context,
          confidence: 0.6,
        });
      }
    }

    return numericalData;
  }

  /**
   * Extract dates from text
   */
  private extractDates(content: string): Array<{
    date: Date;
    context: string;
    confidence: number;
  }> {
    const dates: Array<{
      date: Date;
      context: string;
      confidence: number;
    }> = [];

    // Date patterns
    const datePatterns = [
      { regex: /\d{4}-\d{2}-\d{2}/g, confidence: 0.9 },
      { regex: /\d{2}\/\d{2}\/\d{4}/g, confidence: 0.9 },
      {
        regex: /\d{1,2}\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{4}/gi,
        confidence: 0.9,
      },
      {
        regex: /(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2},?\s+\d{4}/gi,
        confidence: 0.9,
      },
    ];

    datePatterns.forEach(({ regex, confidence }) => {
      const matches = content.matchAll(regex);
      for (const match of matches) {
        const date = new Date(match[0]);
        if (!isNaN(date.getTime())) {
          const startIndex = Math.max(0, match.index - 30);
          const endIndex = Math.min(content.length, match.index + match[0].length + 30);
          const context = content.substring(startIndex, endIndex).trim();

          dates.push({
            date,
            context,
            confidence,
          });
        }
      }
    });

    return dates;
  }

  /**
   * Extract specifications from text
   */
  private extractSpecifications(content: string): Array<{
    parameter: string;
    value: unknown;
    unit?: string;
    context: string;
    confidence: number;
  }> {
    const specifications: Array<{
      parameter: string;
      value: unknown;
      unit?: string;
      context: string;
      confidence: number;
    }> = [];

    // Specification patterns
    const specPatterns = [
      {
        regex: /(version|ver|v)\s*:?\s*([0-9]+(?:\.[0-9]+)*)/gi,
        parameter: 'version',
      },
      {
        regex: /(port)\s*:?\s*([0-9]+)/gi,
        parameter: 'port',
      },
      {
        regex: /(size|capacity)\s*:?\s*([0-9]+(?:\.[0-9]*)?)\s*(\w+)/gi,
        parameter: 'size',
      },
      {
        regex: /(timeout)\s*:?\s*([0-9]+(?:\.[0-9]*)?)\s*(\w+)/gi,
        parameter: 'timeout',
      },
      {
        regex: /(limit|max|maximum)\s*:?\s*([0-9]+(?:\.[0-9]*)?)\s*(\w*)/gi,
        parameter: 'limit',
      },
    ];

    specPatterns.forEach(({ regex, parameter }) => {
      const matches = content.matchAll(regex);
      for (const match of matches) {
        let value: unknown;
        let unit: string | undefined;

        if (parameter === 'version') {
          value = match[2];
        } else {
          value = parseFloat(match[2]);
          unit = match[3] || undefined;
        }

        const startIndex = Math.max(0, match.index - 30);
        const endIndex = Math.min(content.length, match.index + match[0].length + 30);
        const context = content.substring(startIndex, endIndex).trim();

        specifications.push({
          parameter,
          value,
          unit,
          context,
          confidence: 0.8,
        });
      }
    });

    return specifications;
  }

  /**
   * Extract references from text
   */
  private extractReferences(content: string): Array<{
    type: 'url' | 'document' | 'person' | 'organization' | 'source';
    identifier: string;
    context: string;
    confidence: number;
  }> {
    const references: Array<{
      type: 'url' | 'document' | 'person' | 'organization' | 'source';
      identifier: string;
      context: string;
      confidence: number;
    }> = [];

    // URL patterns
    const urlPattern = /https?:\/\/[^\s]+/gi;
    const urlMatches = content.match(urlPattern);
    if (urlMatches) {
      urlMatches.forEach((url) => {
        references.push({
          type: 'url',
          identifier: url,
          context: url,
          confidence: 0.95,
        });
      });
    }

    // Document patterns
    const docPatterns = [
      /\b([A-Z]+-[0-9]+)\b/g, // Like "RFC-2616"
      /\b(doc|document|file)\s*[:#]?\s*([A-Za-z0-9_\-]+)/gi,
    ];

    docPatterns.forEach((pattern) => {
      const matches = content.matchAll(pattern);
      for (const match of matches) {
        const identifier = match[2] || match[1];
        references.push({
          type: 'document',
          identifier,
          context: match[0],
          confidence: 0.7,
        });
      }
    });

    return references;
  }

  /**
   * Generate fact statements from extracted data
   */
  private generateFactStatements(
    facts: FactExtraction,
    content: string
  ): Array<{
    type: 'measurement' | 'count' | 'date' | 'specification' | 'statistic' | 'reference' | 'claim';
    content: string;
    value?: unknown;
    unit?: string;
    source?: string;
    confidence: number;
  }> {
    const statements: Array<{
      type:
        | 'measurement'
        | 'count'
        | 'date'
        | 'specification'
        | 'statistic'
        | 'reference'
        | 'claim';
      content: string;
      value?: unknown;
      unit?: string;
      source?: string;
      confidence: number;
    }> = [];

    // Generate statements from numerical data
    facts.numerical_data.forEach((data) => {
      statements.push({
        type: 'measurement',
        content: `Value: ${data.value} ${data.unit}`,
        value: data.value,
        unit: data.unit,
        confidence: data.confidence,
      });
    });

    // Generate statements from specifications
    facts.specifications.forEach((spec) => {
      statements.push({
        type: 'specification',
        content: `${spec.parameter}: ${spec.value} ${spec.unit || ''}`,
        value: spec.value,
        unit: spec.unit,
        confidence: spec.confidence,
      });
    });

    return statements;
  }

  /**
   * Quick check for obvious factual contradictions
   */
  private quickFactCheck(
    facts1: FactExtraction,
    facts2: FactExtraction
  ): FactualAnalysisResult | null {
    // Check for exact numerical contradictions
    for (const num1 of facts1.numerical_data) {
      for (const num2 of facts2.numerical_data) {
        if (this.isNumericalContradiction(num1, num2)) {
          return {
            has_contradiction: true,
            confidence: 0.9,
            contradiction_type: 'numerical_data',
            description: `Numerical contradiction: ${num1.value}${num1.unit} vs ${num2.value}${num2.unit}`,
            reasoning: 'Exact numerical values differ for similar measurements',
            evidence: [
              {
                type: 'measurement_conflict',
                content: `Numerical conflict between ${num1.value}${num1.unit} and ${num2.value}${num2.unit}`,
                confidence: 0.9,
                source_item: 1,
                fact_data: { num1, num2 },
              },
            ],
            external_verification: {
              can_verify: true,
              verification_method: 'calculation',
              confidence: 0.9,
              sources: [],
              result: {
                is_contradiction: true,
                evidence: 'Direct numerical comparison',
                explanation: 'Values differ beyond tolerance threshold',
              },
            },
            fact_comparison: {
              item1_facts: facts1,
              item2_facts: facts2,
              conflicts: [
                {
                  fact_type: 'numerical',
                  conflict: `${num1.value}${num1.unit} != ${num2.value}${num2.unit}`,
                  severity: 0.9,
                },
              ],
            },
          };
        }
      }
    }

    // Check for date contradictions
    for (const date1 of facts1.dates) {
      for (const date2 of facts2.dates) {
        if (this.isDateContradiction(date1, date2)) {
          return {
            has_contradiction: true,
            confidence: 0.8,
            contradiction_type: 'temporal_fact',
            description: `Date contradiction: ${date1.date.toISOString()} vs ${date2.date.toISOString()}`,
            reasoning: 'Same event claimed to have occurred on different dates',
            evidence: [
              {
                type: 'factual_discrepancy',
                content: `Date conflict between ${date1.date.toISOString()} and ${date2.date.toISOString()}`,
                confidence: 0.8,
                source_item: 1,
                fact_data: { date1, date2 },
              },
            ],
            external_verification: {
              can_verify: true,
              verification_method: 'internal_consistency',
              confidence: 0.8,
              sources: [],
              result: {
                is_contradiction: true,
                evidence: 'Date comparison',
                explanation: 'Dates differ beyond tolerance threshold',
              },
            },
            fact_comparison: {
              item1_facts: facts1,
              item2_facts: facts2,
              conflicts: [
                {
                  fact_type: 'date',
                  conflict: `${date1.date.toISOString()} != ${date2.date.toISOString()}`,
                  severity: 0.8,
                },
              ],
            },
          };
        }
      }
    }

    return null;
  }

  /**
   * Check if two numerical values contradict
   */
  private isNumericalContradiction(
    num1: { value: number; unit: string; context: string },
    num2: { value: number; unit: string; context: string }
  ): boolean {
    // Same unit and exact values that are different
    if (num1.unit === num2.unit && Math.abs(num1.value - num2.value) > 0) {
      // Check if contexts are similar
      if (this.contextSimilarity(num1.context, num2.context) > 0.7) {
        // Check tolerance
        const tolerance = this.config.tolerance_percentage / 100;
        const diffPercentage = Math.abs(num1.value - num2.value) / Math.max(num1.value, num2.value);
        return diffPercentage > tolerance;
      }
    }

    return false;
  }

  /**
   * Check if two dates contradict
   */
  private isDateContradiction(
    date1: { date: Date; context: string },
    date2: { date: Date; context: string }
  ): boolean {
    const timeDiff = Math.abs(date1.date.getTime() - date2.date.getTime());
    const daysDiff = timeDiff / (1000 * 60 * 60 * 24);

    // If contexts are similar and dates differ more than tolerance
    if (
      this.contextSimilarity(date1.context, date2.context) > 0.7 &&
      daysDiff > this.config.date_tolerance_days
    ) {
      return true;
    }

    return false;
  }

  /**
   * Calculate context similarity (simplified)
   */
  private contextSimilarity(context1: string, context2: string): number {
    const words1 = context1.toLowerCase().split(/\s+/);
    const words2 = context2.toLowerCase().split(/\s+/);

    const commonWords = words1.filter((word) => words2.includes(word));
    const totalWords = new Set([...words1, ...words2]).size;

    return commonWords.length / totalWords;
  }

  /**
   * Analyze factual contradiction using ZAI
   */
  private async analyzeFactualContradiction(
    item1: KnowledgeItem,
    item2: KnowledgeItem,
    facts1: FactExtraction,
    facts2: FactExtraction
  ): Promise<FactualAnalysisResult> {
    const prompt = this.buildFactualAnalysisPrompt(item1, item2, facts1, facts2);

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

      return JSON.parse(response.choices[0].message.content) as FactualAnalysisResult;
    } catch (error) {
      logger.error({ error, item1Id: item1.id, item2Id: item2.id }, 'ZAI factual analysis failed');
      throw error;
    }
  }

  /**
   * Get system prompt for factual contradiction detection
   */
  private getSystemPrompt(): string {
    return `You are an expert factual contradiction detector specializing in identifying inconsistencies in verifiable data and claims.

FACTUAL CONTRADICTION TYPES:
1. "verifiable_fact" - Contradictory claims about objectively verifiable facts
2. "numerical_data" - Conflicting measurements, counts, or calculations
3. "technical_spec" - Inconsistent technical specifications or parameters
4. "temporal_fact" - Conflicting dates or temporal information about facts
5. "source_conflict" - Contradictory references or source attributions
6. "measurement_mismatch" - Different measurements for the same quantity
7. "statistical_contradiction" - Conflicting statistical claims or analyses
8. "reference_discrepancy" - Different references to the same entity

ANALYSIS APPROACH:
1. Extract all factual claims from both statements
2. Identify verifiable data points (numbers, dates, specifications)
3. Compare like-for-like measurements and data
4. Check for internal consistency
5. Evaluate external verifiability
6. Consider measurement tolerances and uncertainties
7. Assess source reliability when available

RESPONSE FORMAT:
{
  "has_contradiction": boolean,
  "confidence": number (0-1),
  "contradiction_type": "verifiable_fact" | "numerical_data" | "technical_spec" | "temporal_fact" | "source_conflict" | "measurement_mismatch" | "statistical_contradiction" | "reference_discrepancy",
  "description": string,
  "reasoning": string,
  "evidence": [
    {
      "type": "factual_discrepancy" | "measurement_conflict" | "spec_mismatch" | "reference_conflict",
      "content": string,
      "confidence": number,
      "source_item": 1 or 2,
      "fact_data": object
    }
  ],
  "external_verification": {
    "can_verify": boolean,
    "verification_method": "internal_consistency" | "external_source" | "calculation" | "estimation",
    "confidence": number,
    "sources": [{"type": "internal" | "external" | "calculation", "identifier": string, "reliability": number}],
    "result": {
      "is_contradiction": boolean,
      "evidence": string,
      "explanation": string
    }
  },
  "fact_comparison": {
    "item1_facts": {...},
    "item2_facts": {...},
    "conflicts": [{"fact_type": string, "conflict": string, "severity": number}]
  }
}

IMPORTANT:
- Only report contradictions with confidence >= 0.6
- Consider measurement tolerances and uncertainties
- Prioritize objectively verifiable facts
- Provide specific evidence for each contradiction
- Assess verifiability and confidence in verification`;
  }

  /**
   * Build analysis prompt for factual contradiction
   */
  private buildFactualAnalysisPrompt(
    item1: KnowledgeItem,
    item2: KnowledgeItem,
    facts1: FactExtraction,
    facts2: FactExtraction
  ): string {
    const content1 = this.extractContent(item1);
    const content2 = this.extractContent(item2);

    return `Analyze these two knowledge items for factual contradictions:

ITEM 1 (${item1.kind}):
Content: ${content1}
Extracted Facts: ${JSON.stringify(facts1, null, 2)}

ITEM 2 (${item2.kind}):
Content: ${content2}
Extracted Facts: ${JSON.stringify(facts2, null, 2)}

ANALYSIS FOCUS:
1. Numerical data contradictions and measurement conflicts
2. Technical specification inconsistencies
3. Date and temporal fact conflicts
4. Reference and source discrepancies
5. Statistical claim contradictions
6. Verifiable fact conflicts
7. Calculation or estimation errors

CONSIDER:
- Measurement tolerances and uncertainties
- Unit conversions and compatibility
- Context-specific meanings
- Source reliability and verification
- Statistical significance and error margins
- Technical specification dependencies
- Reference accuracy and currency

Provide detailed factual analysis focusing on objectively verifiable contradictions and their external verification potential.`;
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
    analysis: FactualAnalysisResult
  ): ContradictionResult {
    const severity = this.calculateSeverity(analysis.confidence, analysis.contradiction_type);

    return {
      id: randomUUID(),
      detected_at: new Date(),
      contradiction_type: 'factual',
      confidence_score: analysis.confidence,
      severity,
      primary_item_id: item1.id || randomUUID(),
      conflicting_item_ids: [item2.id || randomUUID()],
      description: analysis.description,
      reasoning: analysis.reasoning,
      metadata: {
        detection_method: 'zai_factual_verification',
        algorithm_version: '3.0.0',
        processing_time_ms: 0,
        comparison_details: {
          contradiction_subtype: analysis.contradiction_type,
          external_verification: analysis.external_verification,
          fact_comparison: analysis.fact_comparison,
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
    analysis: FactualAnalysisResult
  ): ContradictionResult {
    const severity = 'high';

    return {
      id: randomUUID(),
      detected_at: new Date(),
      contradiction_type: 'factual',
      confidence_score: analysis.confidence,
      severity,
      primary_item_id: item1.id || randomUUID(),
      conflicting_item_ids: [item2.id || randomUUID()],
      description: analysis.description,
      reasoning: analysis.reasoning,
      metadata: {
        detection_method: 'quick_factual_check',
        algorithm_version: '3.0.0',
        processing_time_ms: 0,
        comparison_details: {
          contradiction_subtype: analysis.contradiction_type,
          quick_check: true,
          external_verification: analysis.external_verification,
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
    type: FactualContradictionType
  ): 'low' | 'medium' | 'high' | 'critical' {
    // Base severity on confidence
    if (confidence >= 0.9) return 'critical';
    if (confidence >= 0.8) return 'high';
    if (confidence >= 0.6) return 'medium';

    // Adjust based on contradiction type
    const criticalTypes = ['verifiable_fact', 'statistical_contradiction'];
    const highTypes = ['numerical_data', 'technical_spec', 'measurement_mismatch'];

    if (criticalTypes.includes(type) && confidence >= 0.7) return 'critical';
    if (highTypes.includes(type) && confidence >= 0.6) return 'high';

    return 'low';
  }

  /**
   * Generate resolution suggestions based on contradiction type
   */
  private generateResolutionSuggestions(
    type: FactualContradictionType,
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
      case 'verifiable_fact':
        suggestions.push({
          suggestion: 'Verify factual accuracy with external sources',
          priority: 'high',
          effort: 'medium',
          description: 'Check both claims against reliable external sources to determine accuracy',
        });
        suggestions.push({
          suggestion: 'Update with verified factual information',
          priority: 'high',
          effort: 'low',
          description: 'Replace incorrect factual claims with verified information',
        });
        break;

      case 'numerical_data':
        suggestions.push({
          suggestion: 'Verify numerical measurements and calculations',
          priority: 'high',
          effort: 'medium',
          description: 'Re-measure or recalculate to ensure numerical accuracy',
        });
        suggestions.push({
          suggestion: 'Check unit conversions and measurement consistency',
          priority: 'medium',
          effort: 'low',
          description: 'Ensure all numerical data uses consistent units and conversion methods',
        });
        break;

      case 'technical_spec':
        suggestions.push({
          suggestion: 'Verify technical specifications against documentation',
          priority: 'high',
          effort: 'high',
          description: 'Check technical specifications against official documentation or standards',
        });
        break;

      case 'temporal_fact':
        suggestions.push({
          suggestion: 'Verify dates and temporal information',
          priority: 'medium',
          effort: 'low',
          description: 'Check dates against official records or authoritative sources',
        });
        break;

      case 'source_conflict':
        suggestions.push({
          suggestion: 'Verify source references and credibility',
          priority: 'medium',
          effort: 'medium',
          description: 'Check source accuracy and resolve reference conflicts',
        });
        break;

      case 'measurement_mismatch':
        suggestions.push({
          suggestion: 'Reconcile measurement differences and establish standards',
          priority: 'high',
          effort: 'high',
          description: 'Resolve measurement conflicts and establish consistent measurement methods',
        });
        break;

      case 'statistical_contradiction':
        suggestions.push({
          suggestion: 'Review statistical methodology and calculations',
          priority: 'high',
          effort: 'high',
          description: 'Verify statistical methods, calculations, and data sources',
        });
        break;

      case 'reference_discrepancy':
        suggestions.push({
          suggestion: 'Standardize reference formats and verify accuracy',
          priority: 'medium',
          effort: 'low',
          description: 'Ensure consistent and accurate reference formatting',
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
    config: FactualContradictionConfig;
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
  private getFromCache(key: string): { result: FactualAnalysisResult; timestamp: number } | null {
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
  private setToCache(key: string, result: FactualAnalysisResult): void {
    this.cache.set(key, {
      result,
      timestamp: Date.now(),
    });
  }
}

/**
 * Export singleton instance
 */
export const factualVerificationStrategy = new FactualVerificationStrategy();
