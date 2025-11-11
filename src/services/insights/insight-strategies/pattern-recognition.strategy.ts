
/**
 * Pattern Recognition Strategy
 *
 * Advanced pattern recognition using ZAI semantic analysis to identify
 * recurring themes, behavioral patterns, and structural similarities
 * in stored knowledge items.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { randomUUID } from 'crypto';

import type { KnowledgeItem } from '../../../types/core-interfaces.js';
import type {
  InsightGenerationRequest,
  InsightTypeUnion,
  PatternInsight,
} from '../../../types/insight-interfaces.js';
import type { ZAIChatRequest, ZAIChatResponse } from '../../../types/zai-interfaces.js';
import { logger } from '../../../utils/logger.js';
import type { ZAIClientService } from '../../ai/zai-client.service';

export interface PatternRecognitionOptions {
  confidence_threshold: number;
  max_insights: number;
  include_rationale: boolean;
  zai_config: {
    temperature: number;
    max_tokens: number;
    top_p: number;
    frequency_penalty: number;
    presence_penalty: number;
  };
}

export interface PatternAnalysis {
  pattern_type: 'semantic' | 'structural' | 'temporal' | 'behavioral';
  pattern_name: string;
  description: string;
  confidence: number;
  frequency: number;
  items: Array<{
    item_id: string;
    content: string;
    context: string;
    confidence: number;
  }>;
  strength: number;
  metadata: {
    analysis_method: string;
    keywords: string[];
    entities: string[];
    relationships: string[];
  };
}

/**
 * Pattern Recognition Strategy
 */
export class PatternRecognitionStrategy {
  constructor(private zaiClient: ZAIClientService) {}

  /**
   * Generate pattern recognition insights
   */
  async generateInsights(
    request: InsightGenerationRequest,
    options: PatternRecognitionOptions
  ): Promise<PatternInsight[]> {
    const insights: PatternInsight[] = [];

    try {
      logger.debug('Starting pattern recognition analysis');

      // Extract and prepare data for analysis
      const analyzableItems = this.prepareAnalyzableItems(request.items);
      if (analyzableItems.length < 2) {
        logger.debug('Insufficient items for pattern analysis');
        return insights;
      }

      // Perform different types of pattern analysis
      const patternAnalyses = await Promise.all([
        this.analyzeSemanticPatterns(analyzableItems, options),
        this.analyzeStructuralPatterns(analyzableItems, options),
        this.analyzeTemporalPatterns(analyzableItems, options),
        this.analyzeBehavioralPatterns(analyzableItems, options),
      ]);

      // Flatten and filter analyses
      const allAnalyses = patternAnalyses.flat();
      const validAnalyses = allAnalyses.filter(
        (analysis) => analysis.confidence >= options.confidence_threshold
      );

      // Convert analyses to insights
      for (const analysis of validAnalyses.slice(0, options.max_insights)) {
        const insight = this.convertAnalysisToInsight(analysis, request.scope, options);
        insights.push(insight);
      }

      logger.debug(
        {
          totalAnalyses: allAnalyses.length,
          validAnalyses: validAnalyses.length,
          insightsGenerated: insights.length,
        },
        'Pattern recognition analysis completed'
      );

      return insights;
    } catch (error) {
      logger.error({ error }, 'Pattern recognition strategy failed');
      return insights;
    }
  }

  /**
   * Analyze semantic patterns using ZAI
   */
  private async analyzeSemanticPatterns(
    items: KnowledgeItem[],
    options: PatternRecognitionOptions
  ): Promise<PatternAnalysis[]> {
    try {
      const prompt = this.buildSemanticPatternPrompt(items);
      const zaiRequest: ZAIChatRequest = {
        messages: [
          {
            role: 'system',
            content:
              'You are an expert pattern recognition analyst specializing in semantic analysis of knowledge items. Identify recurring themes, concepts, and semantic patterns.',
          },
          {
            role: 'user',
            content: prompt,
          },
        ],
        temperature: options.zai_config.temperature,
        maxTokens: options.zai_config.max_tokens,
        topP: options.zai_config.top_p,
        frequencyPenalty: options.zai_config.frequency_penalty,
        presencePenalty: options.zai_config.presence_penalty,
      };

      const response = await this.zaiClient.generateCompletion(zaiRequest);
      return this.parseSemanticPatternResponse(response, items);
    } catch (error) {
      logger.error({ error }, 'Semantic pattern analysis failed');
      return [];
    }
  }

  /**
   * Analyze structural patterns in knowledge items
   */
  private async analyzeStructuralPatterns(
    items: KnowledgeItem[],
    options: PatternRecognitionOptions
  ): Promise<PatternAnalysis[]> {
    try {
      // Analyze structural patterns: similar data structures, formats, organization
      const structureGroups = this.groupByStructure(items);
      const analyses: PatternAnalysis[] = [];

      for (const [structure, groupItems] of structureGroups.entries()) {
        if (groupItems.length >= 2) {
          const analysis: PatternAnalysis = {
            pattern_type: 'structural',
            pattern_name: `Structural Pattern: ${structure}`,
            description: `Items share similar structural characteristics: ${structure}`,
            confidence: Math.min(groupItems.length / items.length, 1.0),
            frequency: groupItems.length,
            items: groupItems.map((item) => ({
              item_id: item.id || '',
              content: this.extractKeyContent(item),
              context: `Structure: ${structure}`,
              confidence: 0.8,
            })),
            strength: groupItems.length / items.length,
            metadata: {
              analysis_method: 'structural_grouping',
              keywords: [],
              entities: [],
              relationships: [],
            },
          };
          analyses.push(analysis);
        }
      }

      return analyses;
    } catch (error) {
      logger.error({ error }, 'Structural pattern analysis failed');
      return [];
    }
  }

  /**
   * Analyze temporal patterns
   */
  private async analyzeTemporalPatterns(
    items: KnowledgeItem[],
    options: PatternRecognitionOptions
  ): Promise<PatternAnalysis[]> {
    try {
      // Sort items by creation time
      const sortedItems = items
        .filter((item) => item.created_at)
        .sort((a, b) => new Date(a.created_at!).getTime() - new Date(b.created_at!).getTime());

      if (sortedItems.length < 3) {
        return [];
      }

      // Look for time-based patterns
      const timePatterns = this.identifyTimePatterns(sortedItems);
      const analyses: PatternAnalysis[] = [];

      for (const pattern of timePatterns) {
        const analysis: PatternAnalysis = {
          pattern_type: 'temporal',
          pattern_name: `Temporal Pattern: ${pattern.name}`,
          description: pattern.description,
          confidence: pattern.confidence,
          frequency: pattern.items.length,
          items: pattern.items.map((item: KnowledgeItem) => ({
            item_id: item.id || '',
            content: this.extractKeyContent(item),
            context: `Time: ${new Date(item.created_at!).toLocaleString()}`,
            confidence: 0.7,
          })),
          strength: pattern.strength,
          metadata: {
            analysis_method: 'temporal_clustering',
            keywords: ['temporal', 'time', 'pattern'],
            entities: [],
            relationships: [],
          },
        };
        analyses.push(analysis);
      }

      return analyses;
    } catch (error) {
      logger.error({ error }, 'Temporal pattern analysis failed');
      return [];
    }
  }

  /**
   * Analyze behavioral patterns
   */
  private async analyzeBehavioralPatterns(
    items: KnowledgeItem[],
    options: PatternRecognitionOptions
  ): Promise<PatternAnalysis[]> {
    try {
      const prompt = this.buildBehavioralPatternPrompt(items);
      const zaiRequest: ZAIChatRequest = {
        messages: [
          {
            role: 'system',
            content:
              'You are an expert behavioral analyst specializing in identifying patterns of work, decision-making, and problem-solving approaches from knowledge items.',
          },
          {
            role: 'user',
            content: prompt,
          },
        ],
        temperature: options.zai_config.temperature,
        maxTokens: options.zai_config.max_tokens,
        topP: options.zai_config.top_p,
        frequencyPenalty: options.zai_config.frequency_penalty,
        presencePenalty: options.zai_config.presence_penalty,
      };

      const response = await this.zaiClient.generateCompletion(zaiRequest);
      return this.parseBehavioralPatternResponse(response, items);
    } catch (error) {
      logger.error({ error }, 'Behavioral pattern analysis failed');
      return [];
    }
  }

  /**
   * Prepare items for analysis
   */
  private prepareAnalyzableItems(items: KnowledgeItem[]): KnowledgeItem[] {
    return items.filter((item) => {
      const data = item.data as any;
      return (
        item.data &&
        (data.content ||
          data.title ||
          data.description ||
          Object.keys(item.data).length > 0)
      );
    });
  }

  /**
   * Build semantic pattern analysis prompt
   */
  private buildSemanticPatternPrompt(items: KnowledgeItem[]): string {
    const itemSummaries = items
      .map((item, index) => {
        const content = this.extractKeyContent(item);
        return `${index + 1}. Type: ${item.kind}, Content: ${content.substring(0, 200)}...`;
      })
      .join('\n');

    return `
Analyze the following knowledge items and identify semantic patterns:

${itemSummaries}

Focus on:
1. Recurring themes and concepts
2. Semantic similarities between items
3. Topic clusters
4. Domain-specific patterns
5. Cross-cutting concerns

Provide analysis in JSON format:
{
  "patterns": [
    {
      "name": "Pattern Name",
      "description": "Detailed description",
      "confidence": 0.8,
      "keywords": ["keyword1", "keyword2"],
      "entities": ["entity1", "entity2"],
      "item_indices": [1, 2, 3],
      "relationships": ["relationship1", "relationship2"]
    }
  ]
}

Return only the JSON response, no additional text.
`;
  }

  /**
   * Build behavioral pattern analysis prompt
   */
  private buildBehavioralPatternPrompt(items: KnowledgeItem[]): string {
    const itemSummaries = items
      .map((item, index) => {
        return `${index + 1}. Type: ${item.kind}, Content: ${this.extractKeyContent(item)}`;
      })
      .join('\n');

    return `
Analyze the following knowledge items and identify behavioral patterns:

${itemSummaries}

Focus on:
1. Work patterns and workflows
2. Decision-making approaches
3. Problem-solving strategies
4. Collaboration patterns
5. Communication styles
6. Process patterns

Provide analysis in JSON format:
{
  "patterns": [
    {
      "name": "Pattern Name",
      "description": "Detailed description of the behavioral pattern",
      "confidence": 0.8,
      "behavior_type": "workflow|decision|problem_solving|collaboration",
      "item_indices": [1, 2, 3],
      "characteristics": ["characteristic1", "characteristic2"]
    }
  ]
}

Return only the JSON response, no additional text.
`;
  }

  /**
   * Parse semantic pattern response
   */
  private parseSemanticPatternResponse(response: any, items: KnowledgeItem[]): PatternAnalysis[] {
    try {
      const content = response.choices?.[0]?.message?.content;
      if (!content) {
        return [];
      }

      const analysis = JSON.parse(content);
      const patterns = analysis.patterns || [];

      return patterns.map((pattern: any) => ({
        pattern_type: 'semantic' as const,
        pattern_name: pattern.name,
        description: pattern.description,
        confidence: pattern.confidence || 0.5,
        frequency: pattern.item_indices?.length || 0,
        items: (pattern.item_indices || []).map((index: number) => {
          const item = items[index - 1];
          return {
            item_id: item.id,
            content: this.extractKeyContent(item),
            context: 'Semantic pattern match',
            confidence: pattern.confidence || 0.5,
          };
        }),
        strength: (pattern.item_indices?.length || 0) / items.length,
        metadata: {
          analysis_method: 'zai_semantic_analysis',
          keywords: pattern.keywords || [],
          entities: pattern.entities || [],
          relationships: pattern.relationships || [],
        },
      }));
    } catch (error) {
      logger.error({ error }, 'Failed to parse semantic pattern response');
      return [];
    }
  }

  /**
   * Parse behavioral pattern response
   */
  private parseBehavioralPatternResponse(response: any, items: KnowledgeItem[]): PatternAnalysis[] {
    try {
      const content = response.choices?.[0]?.message?.content;
      if (!content) {
        return [];
      }

      const analysis = JSON.parse(content);
      const patterns = analysis.patterns || [];

      return patterns.map((pattern: any) => ({
        pattern_type: 'behavioral' as const,
        pattern_name: pattern.name,
        description: pattern.description,
        confidence: pattern.confidence || 0.5,
        frequency: pattern.item_indices?.length || 0,
        items: (pattern.item_indices || []).map((index: number) => {
          const item = items[index - 1];
          return {
            item_id: item.id,
            content: this.extractKeyContent(item),
            context: `Behavior: ${pattern.behavior_type}`,
            confidence: pattern.confidence || 0.5,
          };
        }),
        strength: (pattern.item_indices?.length || 0) / items.length,
        metadata: {
          analysis_method: 'zai_behavioral_analysis',
          keywords: pattern.characteristics || [],
          entities: [],
          relationships: [],
        },
      }));
    } catch (error) {
      logger.error({ error }, 'Failed to parse behavioral pattern response');
      return [];
    }
  }

  /**
   * Group items by structure
   */
  private groupByStructure(items: KnowledgeItem[]): Map<string, KnowledgeItem[]> {
    const groups = new Map<string, KnowledgeItem[]>();

    for (const item of items) {
      const structure = this.getItemStructure(item);
      if (!groups.has(structure)) {
        groups.set(structure, []);
      }
      groups.get(structure)!.push(item);
    }

    return groups;
  }

  /**
   * Get item structure signature
   */
  private getItemStructure(item: KnowledgeItem): string {
    const data = item.data as any || {};
    const dataKeys = Object.keys(data).sort();
    const hasContent = !!(data.content || data.title || data.description);
    const hasMetadata = !!(data.metadata || data.tags || data.categories);

    return `keys:${dataKeys.length},content:${hasContent},metadata:${hasMetadata}`;
  }

  /**
   * Identify time patterns
   */
  private identifyTimePatterns(sortedItems: KnowledgeItem[]): any[] {
    const patterns = [];

    // Look for clustering of items in time
    const timeClusters = this.findTimeClusters(sortedItems);

    for (const cluster of timeClusters) {
      if (cluster.items.length >= 2) {
        patterns.push({
          name: `Time Cluster: ${cluster.description}`,
          description: `Items clustered around ${cluster.timeRange}`,
          confidence: 0.7,
          strength: cluster.items.length / sortedItems.length,
          items: cluster.items,
        });
      }
    }

    return patterns;
  }

  /**
   * Find time clusters in sorted items
   */
  private findTimeClusters(sortedItems: KnowledgeItem[]): any[] {
    const clusters = [];
    const windowHours = 24; // 24-hour window

    for (let i = 0; i < sortedItems.length; i++) {
      const baseTime = new Date(sortedItems[i].created_at!).getTime();
      const clusterItems = [sortedItems[i]];

      // Find items within the window
      for (let j = i + 1; j < sortedItems.length; j++) {
        const itemTime = new Date(sortedItems[j].created_at!).getTime();
        const hoursDiff = (itemTime - baseTime) / (1000 * 60 * 60);

        if (hoursDiff <= windowHours) {
          clusterItems.push(sortedItems[j]);
        } else {
          break;
        }
      }

      if (clusterItems.length >= 2) {
        const startTime = new Date(baseTime);
        const endTime = new Date(
          new Date(clusterItems[clusterItems.length - 1].created_at!).getTime()
        );

        clusters.push({
          description: `${startTime.toLocaleDateString()} ${startTime.getHours()}:00-${endTime.getHours()}:00`,
          timeRange: `${startTime.toISOString()} - ${endTime.toISOString()}`,
          items: clusterItems,
        });

        // Skip items we've already processed
        i += clusterItems.length - 1;
      }
    }

    return clusters;
  }

  /**
   * Extract key content from item
   */
  private extractKeyContent(item: KnowledgeItem): string {
    const content = [
      item.data?.content,
      item.data?.title,
      item.data?.description,
      item.data?.summary,
    ].filter(Boolean);

    if (content.length === 0) {
      return JSON.stringify(item.data).substring(0, 200);
    }

    return content.join(' ').substring(0, 500);
  }

  /**
   * Convert analysis to insight
   */
  private convertAnalysisToInsight(
    analysis: PatternAnalysis,
    scope: any,
    options: PatternRecognitionOptions
  ): PatternInsight {
    return {
      id: randomUUID(),
      type: 'patterns',
      title: analysis.pattern_name,
      description: analysis.description,
      confidence: analysis.confidence,
      priority: this.calculatePriority(analysis),
      item_ids: analysis.items.map((item) => item.item_id),
      scope: scope,
      metadata: {
        generated_at: new Date().toISOString(),
        generated_by: 'pattern-recognition-strategy',
        processing_time_ms: 1,
        data_sources: ['knowledge_items'],
        tags: analysis.metadata['keywords'],
      },
      actionable: this.isActionable(analysis),
      category: 'pattern',
      pattern_data: {
        pattern_type: analysis.pattern_type,
        frequency: analysis.frequency,
        occurrences: analysis.items.map((item) => ({
          item_id: item.item_id,
          context: item.context,
          confidence: item.confidence,
        })),
        strength: analysis.strength,
      },
    };
  }

  /**
   * Calculate insight priority
   */
  private calculatePriority(analysis: PatternAnalysis): number {
    // Higher priority for stronger, more frequent patterns
    if (analysis.strength > 0.7 && analysis.frequency > 5) return 1; // High priority
    if (analysis.strength > 0.5 && analysis.frequency > 3) return 2; // Medium priority
    return 3; // Low priority
  }

  /**
   * Determine if pattern is actionable
   */
  private isActionable(analysis: PatternAnalysis): boolean {
    // Patterns that suggest areas for improvement or optimization are actionable
    const actionableTypes = ['behavioral', 'structural'];
    return actionableTypes.includes(analysis.pattern_type) && analysis.strength > 0.6;
  }
}
