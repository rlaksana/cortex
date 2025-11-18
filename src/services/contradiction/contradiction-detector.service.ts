/**
 * Contradiction Detection Service
 * MVP implementation for detecting potential contradictions in stored knowledge
 */

import {
  DEFAULT_CONTRADICTION_SAFETY_CONFIG,
  DEFAULT_CONTRADICTION_TYPES,
  getContradictionDetectorConfig,
  getSensitivityThresholds,
} from '../../config/contradiction-detector-config.js';
import {
  type ContradictionAnalysis,
  type ContradictionDetectionRequest,
  type ContradictionDetectionResponse,
  type ContradictionDetectorConfig,
  type ContradictionDetectorService,
  type ContradictionEvent,
  type ContradictionFlag,
  type ContradictionPointer,
  type ContradictionResult,
  type ContradictionSafetyConfig,
  type ContradictionType,
} from '../../types/contradiction-detector.interface';
import { type KnowledgeItem } from '../../types/core-interfaces.js';
import { generateId } from '../../utils/id-generator.js';

export class ContradictionDetector implements ContradictionDetectorService {
  private config: ContradictionDetectorConfig;
  private safetyConfig: ContradictionSafetyConfig;
  private contradictionTypes: ContradictionType[];
  private cache: Map<string, unknown> = new Map();
  private metrics: Map<string, number> = new Map();
  private eventQueue: ContradictionEvent[] = [];

  constructor(config?: Partial<ContradictionDetectorConfig>) {
    this.config = { ...getContradictionDetectorConfig(), ...config };
    this.safetyConfig = DEFAULT_CONTRADICTION_SAFETY_CONFIG;
    this.contradictionTypes = DEFAULT_CONTRADICTION_TYPES.filter((type) => type.enabled);
    this.initializeMetrics();
  }

  private initializeMetrics(): void {
    this.metrics.set('contradictions_detected', 0);
    this.metrics.set('false_positives', 0);
    this.metrics.set('processing_time_total_ms', 0);
    this.metrics.set('cache_hits', 0);
    this.metrics.set('cache_misses', 0);
    this.metrics.set('memory_peak_mb', 0);
  }

  async detectContradictions(
    request: ContradictionDetectionRequest
  ): Promise<ContradictionDetectionResponse> {
    const startTime = Date.now();

    if (!this.config.enabled) {
      return this.createEmptyResponse(startTime);
    }

    // Safety checks
    if (request.items.length > this.config.max_items_per_check) {
      throw new Error(
        `Too many items to check: ${request.items.length} > ${this.config.max_items_per_check}`
      );
    }

    const contradictions: ContradictionResult[] = [];
    const checkedItems = request.items.length;
    let cacheHits = 0;
    let cacheMisses = 0;

    // Process items in chunks to manage memory
    const chunkSize = Math.min(50, request.items.length);
    for (let i = 0; i < request.items.length; i += chunkSize) {
      const chunk = request.items.slice(i, i + chunkSize);
      const chunkResults = await this.processChunk(chunk, request);

      contradictions.push(...chunkResults.contradictions);
      cacheHits += chunkResults.cacheHits;
      cacheMisses += chunkResults.cacheMisses;

      // Safety check - memory usage
      if (this.getCurrentMemoryUsage() > this.safetyConfig.memory_limit_mb) {
        console.warn('Memory limit reached, stopping contradiction detection');
        break;
      }
    }

    const processingTime = Date.now() - startTime;
    this.updateMetrics(contradictions, processingTime, cacheHits, cacheMisses);

    return {
      contradictions,
      summary: {
        total_items_checked: checkedItems,
        contradictions_found: contradictions.length,
        by_type: this.groupContradictionsByType(contradictions),
        by_severity: this.groupContradictionsBySeverity(contradictions),
        processing_time_ms: processingTime,
        cache_hits: cacheHits,
        cache_misses: cacheMisses,
      },
      performance: {
        items_per_second: (checkedItems / processingTime) * 1000,
        memory_usage_mb: this.getCurrentMemoryUsage(),
        bottleneck_detected: this.detectBottlenecks(),
        bottlenecks: this.getBottlenecks(),
      },
    };
  }

  private async processChunk(
    items: KnowledgeItem[],
    request: ContradictionDetectionRequest
  ): Promise<{
    contradictions: ContradictionResult[];
    cacheHits: number;
    cacheMisses: number;
  }> {
    const contradictions: ContradictionResult[] = [];
    const cacheHits = 0;
    const cacheMisses = 0;

    // Check each enabled contradiction type
    for (const contradictionType of this.contradictionTypes) {
      if (request.check_types && !request.check_types.includes(contradictionType.id)) {
        continue;
      }

      const typeResults = await this.detectContradictionsByType(items, contradictionType);
      contradictions.push(...typeResults);
    }

    return { contradictions, cacheHits, cacheMisses };
  }

  private async detectContradictionsByType(
    items: KnowledgeItem[],
    type: ContradictionType
  ): Promise<ContradictionResult[]> {
    switch (type.id) {
      case 'factual':
        return this.detectFactualContradictions(items, type);
      case 'temporal':
        return this.detectTemporalContradictions(items, type);
      case 'logical':
        return this.detectLogicalContradictions(items, type);
      case 'attribute':
        return this.detectAttributeContradictions(items, type);
      default:
        return [];
    }
  }

  private async detectFactualContradictions(
    items: KnowledgeItem[],
    _type: ContradictionType
  ): Promise<ContradictionResult[]> {
    const contradictions: ContradictionResult[] = [];
    const sensitivityThresholds = getSensitivityThresholds();
    const factualThreshold = sensitivityThresholds[this.config.sensitivity] || 0.7;

    for (let i = 0; i < items.length; i++) {
      for (let j = i + 1; j < items.length; j++) {
        const item1 = items[i];
        const item2 = items[j];

        // Skip items in different scopes unless explicitly requested
        if (!this.itemsInSameScope(item1, item2)) {
          continue;
        }

        const contradiction = await this.analyzeFactualContradiction(
          item1,
          item2,
          factualThreshold
        );
        if (contradiction) {
          contradictions.push(contradiction);
        }
      }
    }

    return contradictions;
  }

  private async analyzeFactualContradiction(
    item1: KnowledgeItem,
    item2: KnowledgeItem,
    threshold: number
  ): Promise<ContradictionResult | null> {
    const content1 = this.extractContent(item1);
    const content2 = this.extractContent(item2);

    // Check for direct negation
    const hasDirectNegation = this.detectDirectNegation(content1, content2);
    if (hasDirectNegation && hasDirectNegation.confidence >= threshold) {
      return this.createContradictionResult({
        type: 'factual',
        primary_item_id: item1.id || generateId(),
        conflicting_item_ids: [item2.id || generateId()],
        confidence_score: hasDirectNegation.confidence,
        description: hasDirectNegation.description,
        reasoning: hasDirectNegation.reasoning,
        evidence: hasDirectNegation.evidence as {
          item_id: string;
          evidence_type: string;
          content: string;
          confidence: number;
        }[],
      });
    }

    // Check for semantic contradiction
    const semanticContradiction = await this.detectSemanticContradiction(content1, content2);
    if (semanticContradiction && semanticContradiction.confidence >= threshold) {
      return this.createContradictionResult({
        type: 'factual',
        primary_item_id: item1.id || generateId(),
        conflicting_item_ids: [item2.id || generateId()],
        confidence_score: semanticContradiction.confidence,
        description: semanticContradiction.description,
        reasoning: semanticContradiction.reasoning,
        evidence: semanticContradiction.evidence as {
          item_id: string;
          evidence_type: string;
          content: string;
          confidence: number;
        }[],
      });
    }

    return null;
  }

  private detectDirectNegation(
    content1: string,
    content2: string
  ): {
    confidence: number;
    description: string;
    reasoning: string;
    evidence: unknown[];
  } | null {
    const negationMarkers = [
      'not',
      'never',
      'no',
      'false',
      'incorrect',
      'wrong',
      'cannot',
      "can't",
    ];
    const normalized1 = content1.toLowerCase().trim();
    const normalized2 = content2.toLowerCase().trim();

    // Simple direct negation detection
    for (const marker of negationMarkers) {
      if (
        normalized1.includes(marker) &&
        !normalized2.includes(marker) &&
        normalized1.replace(marker, '').trim() === normalized2.trim()
      ) {
        return {
          confidence: 0.9,
          description: `Direct negation detected with marker "${marker}"`,
          reasoning: `One statement contains negation marker "${marker}" while the other asserts the opposite`,
          evidence: [
            { item_id: '', evidence_type: 'negation_marker', content: marker, confidence: 0.9 },
          ],
        };
      }
    }

    return null;
  }

  private async detectSemanticContradiction(
    content1: string,
    content2: string
  ): Promise<{
    confidence: number;
    description: string;
    reasoning: string;
    evidence: unknown[];
  } | null> {
    // Simplified semantic contradiction detection
    // In a real implementation, this would use embedding similarity or NLP models

    const oppositePairs = [
      { words: ['hot', 'cold'], confidence: 0.8 },
      { words: ['true', 'false'], confidence: 0.9 },
      { words: ['enabled', 'disabled'], confidence: 0.8 },
      { words: ['active', 'inactive'], confidence: 0.8 },
    ];

    for (const pair of oppositePairs) {
      if (
        (content1.toLowerCase().includes(pair.words[0]) &&
          content2.toLowerCase().includes(pair.words[1])) ||
        (content1.toLowerCase().includes(pair.words[1]) &&
          content2.toLowerCase().includes(pair.words[0]))
      ) {
        return {
          confidence: pair.confidence,
          description: `Semantic contradiction detected between "${pair.words[0]}" and "${pair.words[1]}"`,
          reasoning: `Statements contain opposing concepts`,
          evidence: [
            {
              item_id: '',
              evidence_type: 'semantic_opposite',
              content: `${pair.words[0]} vs ${pair.words[1]}`,
              confidence: pair.confidence,
            },
          ],
        };
      }
    }

    return null;
  }

  private async detectTemporalContradictions(
    items: KnowledgeItem[],
    type: ContradictionType
  ): Promise<ContradictionResult[]> {
    const contradictions: ContradictionResult[] = [];
    const sensitivityThresholds = getSensitivityThresholds();
    const temporalThreshold = sensitivityThresholds[this.config.sensitivity] || 0.7;

    // Extract temporal information from items
    const temporalItems = items
      .map((item) => ({
        item,
        temporalData: this.extractTemporalData(item),
      }))
      .filter((ti) => ti.temporalData !== null);

    for (let i = 0; i < temporalItems.length; i++) {
      for (let j = i + 1; j < temporalItems.length; j++) {
        const item1 = temporalItems[i];
        const item2 = temporalItems[j];

        if (!this.itemsInSameScope(item1.item, item2.item)) {
          continue;
        }

        const contradiction = await this.analyzeTemporalContradiction(
          item1.item,
          item2.item,
          item1.temporalData!,
          item2.temporalData!,
          temporalThreshold
        );

        if (contradiction) {
          contradictions.push(contradiction);
        }
      }
    }

    return contradictions;
  }

  private extractTemporalData(item: KnowledgeItem): { timestamp: Date; certainty: string } | null {
    // Try to extract temporal data from various fields
    const content = this.extractContent(item);

    // Check for date patterns
    const datePattern = /\d{4}-\d{2}-\d{2}|\d{2}\/\d{2}\/\d{4}/;
    const match = content.match(datePattern);

    if (match) {
      try {
        const date = new Date(match[0]);
        if (!isNaN(date.getTime())) {
          return {
            timestamp: date,
            certainty: 'certain',
          };
        }
      } catch {
        // Invalid date
      }
    }

    // Check created_at and updated_at timestamps
    if (item.created_at) {
      const date = new Date(item.created_at);
      if (!isNaN(date.getTime())) {
        return {
          timestamp: date,
          certainty: 'certain',
        };
      }
    }

    return null;
  }

  private async analyzeTemporalContradiction(
    item1: KnowledgeItem,
    item2: KnowledgeItem,
    temporal1: { timestamp: Date; certainty: string },
    temporal2: { timestamp: Date; certainty: string },
    threshold: number
  ): Promise<ContradictionResult | null> {
    // Simple temporal contradiction detection
    const timeDiff = Math.abs(temporal1.timestamp.getTime() - temporal2.timestamp.getTime());
    const oneMinute = 60 * 1000;

    // If events claim to happen at the same time but are logically sequential
    if (timeDiff < oneMinute && this.hasTemporalSequenceConflict(item1, item2)) {
      return this.createContradictionResult({
        type: 'temporal',
        primary_item_id: item1.id || generateId(),
        conflicting_item_ids: [item2.id || generateId()],
        confidence_score: 0.8,
        description: 'Temporal contradiction: conflicting sequence within same timeframe',
        reasoning: `Events claim to occur within 1 minute but have conflicting sequence requirements`,
        evidence: [
          {
            item_id: item1.id || '',
            evidence_type: 'temporal_data',
            content: temporal1.timestamp.toISOString(),
            confidence: 0.9,
          },
          {
            item_id: item2.id || '',
            evidence_type: 'temporal_data',
            content: temporal2.timestamp.toISOString(),
            confidence: 0.9,
          },
        ],
      });
    }

    return null;
  }

  private hasTemporalSequenceConflict(item1: KnowledgeItem, item2: KnowledgeItem): boolean {
    const content1 = this.extractContent(item1);
    const content2 = this.extractContent(item2);

    const sequenceMarkers = [
      { before: ['before', 'prior to', 'precedes'], after: ['after', 'following', 'succeeds'] },
      { before: ['first', 'initial'], after: ['second', 'subsequent', 'then'] },
    ];

    for (const markerSet of sequenceMarkers) {
      const item1Before = markerSet.before.some((marker) =>
        content1.toLowerCase().includes(marker)
      );
      const item1After = markerSet.after.some((marker) => content1.toLowerCase().includes(marker));
      const item2Before = markerSet.before.some((marker) =>
        content2.toLowerCase().includes(marker)
      );
      const item2After = markerSet.after.some((marker) => content2.toLowerCase().includes(marker));

      if ((item1Before && item2Before) || (item1After && item2After)) {
        return true; // Both claim to be before/after each other
      }
    }

    return false;
  }

  private async detectLogicalContradictions(
    items: KnowledgeItem[],
    type: ContradictionType
  ): Promise<ContradictionResult[]> {
    const contradictions: ContradictionResult[] = [];
    const sensitivityThresholds = getSensitivityThresholds();
    const logicalThreshold = sensitivityThresholds[this.config.sensitivity] || 0.7;

    for (let i = 0; i < items.length; i++) {
      for (let j = i + 1; j < items.length; j++) {
        const item1 = items[i];
        const item2 = items[j];

        if (!this.itemsInSameScope(item1, item2)) {
          continue;
        }

        const contradiction = await this.analyzeLogicalContradiction(
          item1,
          item2,
          logicalThreshold
        );
        if (contradiction) {
          contradictions.push(contradiction);
        }
      }
    }

    return contradictions;
  }

  private async analyzeLogicalContradiction(
    item1: KnowledgeItem,
    item2: KnowledgeItem,
    threshold: number
  ): Promise<ContradictionResult | null> {
    const content1 = this.extractContent(item1);
    const content2 = this.extractContent(item2);

    // Check for mutual exclusion
    const mutualExclusion = this.detectMutualExclusion(content1, content2);
    if (mutualExclusion && mutualExclusion.confidence >= threshold) {
      return this.createContradictionResult({
        type: 'logical',
        primary_item_id: item1.id || generateId(),
        conflicting_item_ids: [item2.id || generateId()],
        confidence_score: mutualExclusion.confidence,
        description: mutualExclusion.description,
        reasoning: mutualExclusion.reasoning,
        evidence: mutualExclusion.evidence as {
          item_id: string;
          evidence_type: string;
          content: string;
          confidence: number;
        }[],
      });
    }

    return null;
  }

  private detectMutualExclusion(
    content1: string,
    content2: string
  ): {
    confidence: number;
    description: string;
    reasoning: string;
    evidence: unknown[];
  } | null {
    const mutualExclusionPatterns = [
      { pattern: /exclusive.*or/i, confidence: 0.9 },
      { pattern: /either.*or.*but.*not.*both/i, confidence: 0.95 },
      { pattern: /mutually.*exclusive/i, confidence: 1.0 },
    ];

    const normalized1 = content1.toLowerCase();
    const normalized2 = content2.toLowerCase();

    for (const patternInfo of mutualExclusionPatterns) {
      if (patternInfo.pattern.test(normalized1) || patternInfo.pattern.test(normalized2)) {
        return {
          confidence: patternInfo.confidence,
          description: 'Mutual exclusion detected between statements',
          reasoning: 'Statements contain mutual exclusion markers but both appear to be true',
          evidence: [
            {
              item_id: '',
              evidence_type: 'mutual_exclusion',
              content: patternInfo.pattern.source,
              confidence: patternInfo.confidence,
            },
          ],
        };
      }
    }

    return null;
  }

  private async detectAttributeContradictions(
    items: KnowledgeItem[],
    type: ContradictionType
  ): Promise<ContradictionResult[]> {
    const contradictions: ContradictionResult[] = [];
    const sensitivityThresholds = getSensitivityThresholds();
    const attributeThreshold = sensitivityThresholds[this.config.sensitivity] || 0.7;

    // Group items by potential attribute conflicts
    for (let i = 0; i < items.length; i++) {
      for (let j = i + 1; j < items.length; j++) {
        const item1 = items[i];
        const item2 = items[j];

        if (!this.itemsInSameScope(item1, item2)) {
          continue;
        }

        const contradiction = await this.analyzeAttributeContradiction(
          item1,
          item2,
          attributeThreshold
        );
        if (contradiction) {
          contradictions.push(contradiction);
        }
      }
    }

    return contradictions;
  }

  private async analyzeAttributeContradiction(
    item1: KnowledgeItem,
    item2: KnowledgeItem,
    threshold: number
  ): Promise<ContradictionResult | null> {
    // Extract potential attributes from data fields
    const attributes1 = this.extractAttributes(item1);
    const attributes2 = this.extractAttributes(item2);

    // Check for conflicting attributes
    for (const [attrName, value1] of Object.entries(attributes1)) {
      if (attributes2[attrName]) {
        const value2 = attributes2[attrName];
        const conflict = this.analyzeAttributeConflict(attrName, value1, value2);

        if (conflict && conflict.confidence >= threshold) {
          return this.createContradictionResult({
            type: 'attribute',
            primary_item_id: item1.id || generateId(),
            conflicting_item_ids: [item2.id || generateId()],
            confidence_score: conflict.confidence,
            description: conflict.description,
            reasoning: conflict.reasoning,
            evidence: conflict.evidence as {
              item_id: string;
              evidence_type: string;
              content: string;
              confidence: number;
            }[],
          });
        }
      }
    }

    return null;
  }

  private extractAttributes(item: KnowledgeItem): Record<string, unknown> {
    const attributes: Record<string, unknown> = {};

    // Extract from data fields
    if (item.data) {
      for (const [key, value] of Object.entries(item.data)) {
        if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
          attributes[key] = value;
        }
      }
    }

    // Extract from content
    const content = this.extractContent(item);
    const attributePattern = /(\w+):\s*([^,;\n]+)/g;
    let match;
    while ((match = attributePattern.exec(content)) !== null) {
      attributes[match[1].trim()] = match[2].trim();
    }

    return attributes;
  }

  private analyzeAttributeConflict(
    attrName: string,
    value1: unknown,
    value2: unknown
  ): {
    confidence: number;
    description: string;
    reasoning: string;
    evidence: unknown[];
  } | null {
    // Type conflict
    if (typeof value1 !== typeof value2) {
      return {
        confidence: 0.9,
        description: `Type conflict for attribute "${attrName}"`,
        reasoning: `Attribute "${attrName}" has different types: ${typeof value1} vs ${typeof value2}`,
        evidence: [
          {
            item_id: '',
            evidence_type: 'type_conflict',
            content: `${attrName}: ${typeof value1} vs ${typeof value2}`,
            confidence: 0.9,
          },
        ],
      };
    }

    // Value conflict for same type
    if (value1 !== value2) {
      let confidence = 0.7;

      // Higher confidence for boolean conflicts
      if (typeof value1 === 'boolean' && typeof value2 === 'boolean') {
        confidence = 0.95;
      }

      // Medium confidence for exact string matches with negation
      if (typeof value1 === 'string' && typeof value2 === 'string') {
        if (this.isOpposite(value1, value2)) {
          confidence = 0.85;
        }
      }

      return {
        confidence,
        description: `Value conflict for attribute "${attrName}"`,
        reasoning: `Attribute "${attrName}" has conflicting values: "${value1}" vs "${value2}"`,
        evidence: [
          {
            item_id: '',
            evidence_type: 'value_conflict',
            content: `${attrName}: "${value1}" vs "${value2}"`,
            confidence,
          },
        ],
      };
    }

    return null;
  }

  private isOpposite(value1: string, value2: string): boolean {
    const opposites = [
      ['true', 'false'],
      ['yes', 'no'],
      ['on', 'off'],
      ['enabled', 'disabled'],
      ['active', 'inactive'],
      ['open', 'closed'],
    ];

    const v1 = value1.toLowerCase().trim();
    const v2 = value2.toLowerCase().trim();

    return opposites.some(
      (pair) => (pair[0] === v1 && pair[1] === v2) || (pair[1] === v1 && pair[0] === v2)
    );
  }

  private createContradictionResult(params: {
    type: string;
    primary_item_id: string;
    conflicting_item_ids: string[];
    confidence_score: number;
    description: string;
    reasoning: string;
    evidence: { item_id: string; evidence_type: string; content: string; confidence: number }[];
  }): ContradictionResult {
    const severity = this.calculateSeverity(params.confidence_score, params.type);

    return {
      id: generateId(),
      detected_at: new Date(),
      contradiction_type: params.type,
      confidence_score: params.confidence_score,
      severity,
      primary_item_id: params.primary_item_id,
      conflicting_item_ids: params.conflicting_item_ids,
      description: params.description,
      reasoning: params.reasoning,
      metadata: {
        detection_method: 'rule_based',
        algorithm_version: '1.0.0',
        processing_time_ms: 0, // Would be calculated in real implementation
        comparison_details: {},
        evidence: params.evidence,
      },
      resolution_suggestions: this.generateResolutionSuggestions(params.type, severity),
    };
  }

  private calculateSeverity(
    confidence: number,
    type: string
  ): 'low' | 'medium' | 'high' | 'critical' {
    if (confidence >= 0.9) return 'critical';
    if (confidence >= 0.75) return 'high';
    if (confidence >= 0.6) return 'medium';
    return 'low';
  }

  private generateResolutionSuggestions(
    type: string,
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

    switch (type) {
      case 'factual':
        suggestions.push({
          suggestion: 'Verify factual accuracy of conflicting statements',
          priority: 'high',
          effort: 'medium',
          description: 'Review both statements and determine which is factually correct',
        });
        suggestions.push({
          suggestion: 'Consider temporal context for statement validity',
          priority: 'medium',
          effort: 'low',
          description: 'Check if statements were true at different times',
        });
        break;

      case 'temporal':
        suggestions.push({
          suggestion: 'Review and correct temporal data',
          priority: 'high',
          effort: 'medium',
          description: 'Ensure timestamps and sequences are accurate',
        });
        break;

      case 'logical':
        suggestions.push({
          suggestion: 'Review logical consistency',
          priority: 'medium',
          effort: 'high',
          description: 'Analyze the logical relationship between statements',
        });
        break;

      case 'attribute':
        suggestions.push({
          suggestion: 'Standardize attribute values',
          priority: 'medium',
          effort: 'low',
          description: 'Ensure consistent attribute values across items',
        });
        break;
    }

    return suggestions;
  }

  private itemsInSameScope(item1: KnowledgeItem, item2: KnowledgeItem): boolean {
    // Check if items are in the same scope (project, branch, org)
    return item1.scope?.project === item2.scope?.project || item1.scope?.org === item2.scope?.org;
  }

  private extractContent(item: KnowledgeItem): string {
    return item.content || JSON.stringify(item.data) || '';
  }

  private groupContradictionsByType(contradictions: ContradictionResult[]): Record<string, number> {
    const groups: Record<string, number> = {};

    contradictions.forEach((c) => {
      groups[c.contradiction_type] = (groups[c.contradiction_type] || 0) + 1;
    });

    return groups;
  }

  private groupContradictionsBySeverity(
    contradictions: ContradictionResult[]
  ): Record<string, number> {
    const groups: Record<string, number> = {};

    contradictions.forEach((c) => {
      groups[c.severity] = (groups[c.severity] || 0) + 1;
    });

    return groups;
  }

  private getCurrentMemoryUsage(): number {
    // Simplified memory usage calculation
    // In real implementation, would use process.memoryUsage()
    return 50; // Placeholder
  }

  private detectBottlenecks(): boolean {
    // Simple bottleneck detection
    return this.getBottlenecks().length > 0;
  }

  private getBottlenecks(): string[] {
    const bottlenecks: string[] = [];

    if (this.getCurrentMemoryUsage() > this.safetyConfig.memory_limit_mb * 0.8) {
      bottlenecks.push('memory_usage');
    }

    const avgProcessingTime =
      (this.metrics.get('processing_time_total_ms') || 0) /
      Math.max(1, this.metrics.get('contradictions_detected') || 1);
    if (avgProcessingTime > 5000) {
      // 5 seconds
      bottlenecks.push('processing_time');
    }

    return bottlenecks;
  }

  private updateMetrics(
    contradictions: ContradictionResult[],
    processingTime: number,
    cacheHits: number,
    cacheMisses: number
  ): void {
    this.metrics.set(
      'contradictions_detected',
      (this.metrics.get('contradictions_detected') || 0) + contradictions.length
    );
    this.metrics.set(
      'processing_time_total_ms',
      (this.metrics.get('processing_time_total_ms') || 0) + processingTime
    );
    this.metrics.set('cache_hits', (this.metrics.get('cache_hits') || 0) + cacheHits);
    this.metrics.set('cache_misses', (this.metrics.get('cache_misses') || 0) + cacheMisses);
  }

  private createEmptyResponse(startTime: number): ContradictionDetectionResponse {
    const processingTime = Date.now() - startTime;

    return {
      contradictions: [],
      summary: {
        total_items_checked: 0,
        contradictions_found: 0,
        by_type: {},
        by_severity: {},
        processing_time_ms: processingTime,
        cache_hits: 0,
        cache_misses: 0,
      },
      performance: {
        items_per_second: 0,
        memory_usage_mb: this.getCurrentMemoryUsage(),
        bottleneck_detected: false,
        bottlenecks: [],
      },
    };
  }

  // Required interface methods (simplified implementations for MVP)

  async flagContradictions(contradictions: ContradictionResult[]): Promise<ContradictionFlag[]> {
    if (!this.config.auto_flag) {
      return [];
    }

    return contradictions.map((contradiction) => ({
      item_id: contradiction.primary_item_id,
      flag_type: 'possible_contradiction',
      contradiction_ids: [contradiction.id],
      flagged_at: new Date(),
      review_status: 'pending',
    }));
  }

  async analyzeItem(item_id: string): Promise<ContradictionAnalysis> {
    // Placeholder implementation
    return {
      item_id,
      contradiction_count: 0,
      contradiction_types: [],
      severity_distribution: {},
      related_items: [],
      trust_score: 1.0,
      last_analysis: new Date(),
      analysis_details: {
        factual_consistency: 1.0,
        temporal_consistency: 1.0,
        logical_consistency: 1.0,
        attribute_consistency: 1.0,
      },
    };
  }

  async getContradictionPointers(item_id: string): Promise<ContradictionPointer[]> {
    // Placeholder implementation
    return [];
  }

  async batchCheck(
    items: KnowledgeItem[],
    options?: { chunk_size?: number; parallel?: boolean }
  ): Promise<ContradictionDetectionResponse> {
    const request: ContradictionDetectionRequest = {
      items,
      force_check: true,
    };

    return this.detectContradictions(request);
  }

  async validateContradiction(contradiction_id: string): Promise<boolean> {
    // Placeholder implementation
    return true;
  }

  async resolveContradiction(contradiction_id: string, resolution: string): Promise<void> {
    // Placeholder implementation
    console.log(`Resolving contradiction ${contradiction_id} with resolution: ${resolution}`);
  }

  getConfiguration(): ContradictionDetectorConfig {
    return { ...this.config };
  }

  async updateConfiguration(config: Partial<ContradictionDetectorConfig>): Promise<void> {
    this.config = { ...this.config, ...config };
  }
}
