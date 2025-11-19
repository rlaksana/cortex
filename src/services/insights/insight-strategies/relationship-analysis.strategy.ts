/**
 * Relationship Analysis Strategy
 *
 * Advanced relationship and connection mapping using ZAI semantic analysis
 * to identify hidden connections, dependencies, and relationship patterns
 * between knowledge items.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { randomUUID } from 'crypto';

import type { KnowledgeItem } from '../../../types/core-interfaces.js';
import type {
  ConnectionInsight,
  InsightGenerationRequest,
} from '../../../types/insight-interfaces.js';
import type { ZAIChatRequest } from '../../../types/zai-interfaces.js';
import {
  safeGetArrayProperty,
  safeGetNumberProperty,
  safeGetStringProperty,
} from '../../../utils/type-fixes.js';
import type { ZAIClientService } from '../../ai/zai-client.service';
import { logger } from '../../utils/logger.js';

export interface RelationshipAnalysisOptions {
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

export interface RelationshipAnalysis {
  relationship_type:
    | 'semantic'
    | 'dependency'
    | 'temporal'
    | 'causal'
    | 'hierarchical'
    | 'collaborative';
  relationship_name: string;
  description: string;
  confidence: number;
  strength: number;
  source_items: Array<{
    item_id: string;
    item_type: string;
    role: string;
    confidence: number;
  }>;
  target_items: Array<{
    item_id: string;
    item_type: string;
    role: string;
    confidence: number;
  }>;
  relationship_direction: 'bidirectional' | 'unidirectional';
  relationship_nature: 'strong' | 'moderate' | 'weak';
  metadata: {
    analysis_method: string;
    connection_indicators: string[];
    context_clues: string[];
    verification_status: 'direct' | 'inferred' | 'speculative';
  };
}

/**
 * Relationship Analysis Strategy
 */
export class RelationshipAnalysisStrategy {
  constructor(private zaiClient: ZAIClientService) {}

  /**
   * Generate relationship analysis insights
   */
  async generateInsights(
    request: InsightGenerationRequest,
    options: RelationshipAnalysisOptions
  ): Promise<ConnectionInsight[]> {
    const insights: ConnectionInsight[] = [];

    try {
      logger.debug('Starting relationship analysis');

      // Perform different types of relationship analysis
      const relationshipAnalyses = await Promise.all([
        this.analyzeSemanticRelationships(request.items, options),
        this.analyzeDependencyRelationships(request.items, options),
        this.analyzeTemporalRelationships(request.items, options),
        this.analyzeCausalRelationships(request.items, options),
        this.analyzeHierarchicalRelationships(request.items, options),
        this.analyzeCollaborativeRelationships(request.items, options),
      ]);

      // Flatten and filter analyses
      const allAnalyses = relationshipAnalyses.flat();
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
        'Relationship analysis completed'
      );

      return insights;
    } catch (error) {
      logger.error({ error }, 'Relationship analysis strategy failed');
      return insights;
    }
  }

  /**
   * Analyze semantic relationships using ZAI
   */
  private async analyzeSemanticRelationships(
    items: KnowledgeItem[],
    options: RelationshipAnalysisOptions
  ): Promise<RelationshipAnalysis[]> {
    try {
      const prompt = this.buildSemanticRelationshipPrompt(items);
      const zaiRequest: ZAIChatRequest = {
        messages: [
          {
            role: 'system',
            content:
              'You are an expert semantic relationship analyst. Identify semantic connections, conceptual links, and topic relationships between knowledge items.',
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
      return this.parseRelationshipResponse(response.data!, items, 'semantic');
    } catch (error) {
      logger.error({ error }, 'Semantic relationship analysis failed');
      return [];
    }
  }

  /**
   * Analyze dependency relationships
   */
  private async analyzeDependencyRelationships(
    items: KnowledgeItem[],
    options: RelationshipAnalysisOptions
  ): Promise<RelationshipAnalysis[]> {
    try {
      const prompt = this.buildDependencyRelationshipPrompt(items);
      const zaiRequest: ZAIChatRequest = {
        messages: [
          {
            role: 'system',
            content:
              'You are an expert dependency analyst. Identify dependencies, prerequisites, and sequential relationships between knowledge items.',
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
      return this.parseRelationshipResponse(response.data!, items, 'dependency');
    } catch (error) {
      logger.error({ error }, 'Dependency relationship analysis failed');
      return [];
    }
  }

  /**
   * Analyze temporal relationships
   */
  private async analyzeTemporalRelationships(
    items: KnowledgeItem[],
    options: RelationshipAnalysisOptions
  ): Promise<RelationshipAnalysis[]> {
    try {
      const temporalItems = items.filter((item) => item.created_at);
      if (temporalItems.length < 2) {
        return [];
      }

      const analyses: RelationshipAnalysis[] = [];
      const sortedItems = temporalItems.sort(
        (a, b) => new Date(a.created_at!).getTime() - new Date(b.created_at!).getTime()
      );

      // Look for temporal clusters and sequences
      const temporalClusters = this.findTemporalClusters(sortedItems);
      const temporalSequences = this.findTemporalSequences(sortedItems);

      for (const cluster of temporalClusters) {
        const clusterItems = (cluster as unknown).items || [];
        const clusterDescription = safeGetStringProperty(cluster, 'description');

        if (clusterItems.length >= 2) {
          const analysis: RelationshipAnalysis = {
            relationship_type: 'temporal',
            relationship_name: `Temporal Cluster: ${clusterDescription}`,
            description: `Items created in close temporal proximity suggesting related work or events`,
            confidence: 0.7,
            strength: clusterItems.length / sortedItems.length,
            source_items: clusterItems
              .slice(0, Math.ceil(clusterItems.length / 2))
              .map((item: KnowledgeItem) => ({
                item_id: item.id,
                item_type: item.kind,
                role: 'cluster_member',
                confidence: 0.7,
              })),
            target_items: clusterItems
              .slice(Math.ceil(clusterItems.length / 2))
              .map((item: KnowledgeItem) => ({
                item_id: item.id,
                item_type: item.kind,
                role: 'cluster_member',
                confidence: 0.7,
              })),
            relationship_direction: 'bidirectional',
            relationship_nature: 'moderate',
            metadata: {
              analysis_method: 'temporal_clustering',
              connection_indicators: ['time_proximity'],
              context_clues: ['creation_timestamp'],
              verification_status: 'direct',
            },
          };
          analyses.push(analysis);
        }
      }

      for (const sequence of temporalSequences) {
        const sequenceItems = (sequence as unknown).items || [];
        const sequenceDescription = safeGetStringProperty(sequence, 'description');

        if (sequenceItems.length >= 2) {
          const analysis: RelationshipAnalysis = {
            relationship_type: 'temporal',
            relationship_name: `Temporal Sequence: ${sequenceDescription}`,
            description: `Sequential items suggesting workflow or progression`,
            confidence: 0.6,
            strength: sequenceItems.length / sortedItems.length,
            source_items: sequenceItems.slice(0, -1).map((item: KnowledgeItem) => ({
              item_id: item.id,
              item_type: item.kind,
              role: 'predecessor',
              confidence: 0.6,
            })),
            target_items: sequenceItems.slice(1).map((item: KnowledgeItem) => ({
              item_id: item.id,
              item_type: item.kind,
              role: 'successor',
              confidence: 0.6,
            })),
            relationship_direction: 'unidirectional',
            relationship_nature: 'moderate',
            metadata: {
              analysis_method: 'temporal_sequencing',
              connection_indicators: ['temporal_order'],
              context_clues: ['creation_timestamp', 'sequence'],
              verification_status: 'inferred',
            },
          };
          analyses.push(analysis);
        }
      }

      return analyses;
    } catch (error) {
      logger.error({ error }, 'Temporal relationship analysis failed');
      return [];
    }
  }

  /**
   * Analyze causal relationships
   */
  private async analyzeCausalRelationships(
    items: KnowledgeItem[],
    options: RelationshipAnalysisOptions
  ): Promise<RelationshipAnalysis[]> {
    try {
      const prompt = this.buildCausalRelationshipPrompt(items);
      const zaiRequest: ZAIChatRequest = {
        messages: [
          {
            role: 'system',
            content:
              'You are an expert causal relationship analyst. Identify cause-effect relationships, impact chains, and causal connections between knowledge items.',
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
      return this.parseRelationshipResponse(response.data!, items, 'causal');
    } catch (error) {
      logger.error({ error }, 'Causal relationship analysis failed');
      return [];
    }
  }

  /**
   * Analyze hierarchical relationships
   */
  private async analyzeHierarchicalRelationships(
    items: KnowledgeItem[],
    options: RelationshipAnalysisOptions
  ): Promise<RelationshipAnalysis[]> {
    try {
      const prompt = this.buildHierarchicalRelationshipPrompt(items);
      const zaiRequest: ZAIChatRequest = {
        messages: [
          {
            role: 'system',
            content:
              'You are an expert hierarchical relationship analyst. Identify parent-child relationships, organizational structures, and hierarchical connections between knowledge items.',
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
      return this.parseRelationshipResponse(response.data!, items, 'hierarchical');
    } catch (error) {
      logger.error({ error }, 'Hierarchical relationship analysis failed');
      return [];
    }
  }

  /**
   * Analyze collaborative relationships
   */
  private async analyzeCollaborativeRelationships(
    items: KnowledgeItem[],
    options: RelationshipAnalysisOptions
  ): Promise<RelationshipAnalysis[]> {
    try {
      // Look for collaboration indicators
      const collaborativeGroups = this.findCollaborativeGroups(items);
      const analyses: RelationshipAnalysis[] = [];

      for (const group of collaborativeGroups) {
        const groupItems = (group as unknown).items || [];
        const groupDescription = safeGetStringProperty(group, 'description');
        const groupIndicators = (group as unknown).indicators || [];

        if (groupItems.length >= 2) {
          const analysis: RelationshipAnalysis = {
            relationship_type: 'collaborative',
            relationship_name: `Collaborative Group: ${groupDescription}`,
            description: `Items showing collaborative work or shared effort`,
            confidence: 0.8,
            strength: groupItems.length / items.length,
            source_items: groupItems
              .slice(0, Math.ceil(groupItems.length / 2))
              .map((item: KnowledgeItem) => ({
                item_id: item.id,
                item_type: item.kind,
                role: 'collaborator',
                confidence: 0.8,
              })),
            target_items: groupItems
              .slice(Math.ceil(groupItems.length / 2))
              .map((item: KnowledgeItem) => ({
                item_id: item.id,
                item_type: item.kind,
                role: 'collaborator',
                confidence: 0.8,
              })),
            relationship_direction: 'bidirectional',
            relationship_nature: 'strong',
            metadata: {
              analysis_method: 'collaboration_detection',
              connection_indicators: groupIndicators,
              context_clues: ['shared_scope', 'joint_effort'],
              verification_status: 'direct',
            },
          };
          analyses.push(analysis);
        }
      }

      return analyses;
    } catch (error) {
      logger.error({ error }, 'Collaborative relationship analysis failed');
      return [];
    }
  }

  /**
   * Build semantic relationship prompt
   */
  private buildSemanticRelationshipPrompt(items: KnowledgeItem[]): string {
    const itemSummaries = items
      .map((item, index) => {
        return `${index + 1}. Type: ${item.kind}, Content: ${this.extractKeyContent(item)}`;
      })
      .join('\n');

    return `
Analyze the following knowledge items and identify semantic relationships:

${itemSummaries}

Look for:
1. Topic similarities and thematic connections
2. Conceptual relationships
3. Shared terminology and vocabulary
4. Overlapping subject matter
5. Related concepts or domains
6. Semantic proximity

Provide analysis in JSON format:
{
  "relationships": [
    {
      "name": "Relationship Name",
      "description": "Description of the semantic connection",
      "confidence": 0.8,
      "strength": 0.7,
      "source_indices": [1, 2],
      "target_indices": [3, 4],
      "connection_indicators": ["shared_concept", "similar_terminology"],
      "context_clues": ["topic_overlap", "domain_similarity"],
      "direction": "bidirectional|unidirectional"
    }
  ]
}

Return only the JSON response, no additional text.
`;
  }

  /**
   * Build dependency relationship prompt
   */
  private buildDependencyRelationshipPrompt(items: KnowledgeItem[]): string {
    const itemSummaries = items
      .map((item, index) => {
        return `${index + 1}. Type: ${item.kind}, Content: ${this.extractKeyContent(item)}`;
      })
      .join('\n');

    return `
Analyze the following knowledge items and identify dependency relationships:

${itemSummaries}

Look for:
1. Prerequisite relationships
2. Sequential dependencies
3. Resource dependencies
4. Technical dependencies
5. Process dependencies
6. Blocker or enabler relationships

Provide analysis in JSON format:
{
  "relationships": [
    {
      "name": "Dependency Relationship",
      "description": "Description of the dependency",
      "confidence": 0.8,
      "strength": 0.7,
      "source_indices": [1],  // dependencies
      "target_indices": [2],  // dependents
      "connection_indicators": ["prerequisite", "sequential"],
      "context_clues": ["workflow", "process_flow"],
      "direction": "unidirectional"
    }
  ]
}

Return only the JSON response, no additional text.
`;
  }

  /**
   * Build causal relationship prompt
   */
  private buildCausalRelationshipPrompt(items: KnowledgeItem[]): string {
    const itemSummaries = items
      .map((item, index) => {
        return `${index + 1}. Type: ${item.kind}, Content: ${this.extractKeyContent(item)}`;
      })
      .join('\n');

    return `
Analyze the following knowledge items and identify causal relationships:

${itemSummaries}

Look for:
1. Cause-effect relationships
2. Impact chains
3. Consequences and outcomes
4. Trigger events
5. Resulting changes
6. Causal inference

Provide analysis in JSON format:
{
  "relationships": [
    {
      "name": "Causal Relationship",
      "description": "Description of the causal connection",
      "confidence": 0.8,
      "strength": 0.7,
      "source_indices": [1],  // causes
      "target_indices": [2],  // effects
      "connection_indicators": ["cause", "effect", "impact"],
      "context_clues": ["resulted_in", "led_to", "triggered"],
      "direction": "unidirectional"
    }
  ]
}

Return only the JSON response, no additional text.
`;
  }

  /**
   * Build hierarchical relationship prompt
   */
  private buildHierarchicalRelationshipPrompt(items: KnowledgeItem[]): string {
    const itemSummaries = items
      .map((item, index) => {
        return `${index + 1}. Type: ${item.kind}, Content: ${this.extractKeyContent(item)}`;
      })
      .join('\n');

    return `
Analyze the following knowledge items and identify hierarchical relationships:

${itemSummaries}

Look for:
1. Parent-child relationships
2. Organizational structures
3. Hierarchical classifications
4. Level relationships
5. Sub-component relationships
6. Containment relationships

Provide analysis in JSON format:
{
  "relationships": [
    {
      "name": "Hierarchical Relationship",
      "description": "Description of the hierarchy",
      "confidence": 0.8,
      "strength": 0.7,
      "source_indices": [1],  // parents
      "target_indices": [2],  // children
      "connection_indicators": ["contains", "part_of", "subordinate"],
      "context_clues": ["hierarchy", "structure", "organization"],
      "direction": "unidirectional"
    }
  ]
}

Return only the JSON response, no additional text.
`;
  }

  /**
   * Parse relationship response
   */
  private parseRelationshipResponse(
    response: unknown,
    items: KnowledgeItem[],
    relationshipType: RelationshipAnalysis['relationship_type']
  ): RelationshipAnalysis[] {
    try {
      const content = response.choices?.[0]?.message?.content;
      if (!content) {
        return [];
      }

      const analysis = JSON.parse(content);
      const relationships = analysis.relationships || [];

      return relationships.map((rel: unknown) => {
        const relName = safeGetStringProperty(rel, 'name');
        const relDescription = safeGetStringProperty(rel, 'description');
        const relConfidence = safeGetNumberProperty(rel, 'confidence', 0.5);
        const relStrength = safeGetNumberProperty(rel, 'strength', 0.5);
        const relDirection = safeGetStringProperty(rel, 'direction', 'bidirectional');
        const relConnectionIndicators = safeGetArrayProperty(rel, 'connection_indicators') || [];
        const relContextClues = safeGetArrayProperty(rel, 'context_clues') || [];
        const sourceIndices = (rel as unknown).source_indices || [];
        const targetIndices = (rel as unknown).target_indices || [];

        return {
          relationship_type: relationshipType,
          relationship_name: relName,
          description: relDescription,
          confidence: relConfidence,
          strength: relStrength,
          source_items: sourceIndices.map((index: number) => {
            const item = items[index - 1];
            return {
              item_id: item.id,
              item_type: item.kind,
              role: 'source',
              confidence: relConfidence,
            };
          }),
          target_items: targetIndices.map((index: number) => {
            const item = items[index - 1];
            return {
              item_id: item.id,
              item_type: item.kind,
              role: 'target',
              confidence: relConfidence,
            };
          }),
          relationship_direction: relDirection as 'bidirectional' | 'unidirectional',
          relationship_nature: this.mapStrengthToNature(relStrength),
          metadata: {
            analysis_method: 'zai_relationship_analysis',
            connection_indicators: relConnectionIndicators,
            context_clues: relContextClues,
            verification_status: 'inferred',
          },
        };
      });
    } catch (error) {
      logger.error({ error }, 'Failed to parse relationship response');
      return [];
    }
  }

  /**
   * Find temporal clusters
   */
  private findTemporalClusters(sortedItems: KnowledgeItem[]): unknown[] {
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
        clusters.push({
          description: `${sortedItems[i].created_at} cluster`,
          items: clusterItems,
        });

        // Skip items we've already processed
        i += clusterItems.length - 1;
      }
    }

    return clusters;
  }

  /**
   * Find temporal sequences
   */
  private findTemporalSequences(sortedItems: KnowledgeItem[]): unknown[] {
    const sequences = [];
    let currentSequence = [sortedItems[0]];

    for (let i = 1; i < sortedItems.length; i++) {
      const prevTime = new Date(sortedItems[i - 1].created_at!).getTime();
      const currTime = new Date(sortedItems[i].created_at!).getTime();
      const hoursDiff = (currTime - prevTime) / (1000 * 60 * 60);

      if (hoursDiff <= 48) {
        // Within 48 hours
        currentSequence.push(sortedItems[i]);
      } else {
        if (currentSequence.length >= 2) {
          sequences.push({
            description: `Sequence of ${currentSequence.length} items`,
            items: currentSequence,
          });
        }
        currentSequence = [sortedItems[i]];
      }
    }

    if (currentSequence.length >= 2) {
      sequences.push({
        description: `Sequence of ${currentSequence.length} items`,
        items: currentSequence,
      });
    }

    return sequences;
  }

  /**
   * Find collaborative groups
   */
  private findCollaborativeGroups(items: KnowledgeItem[]): unknown[] {
    const groups = [];
    const scopeGroups = new Map<string, KnowledgeItem[]>();
    const tagGroups = new Map<string, KnowledgeItem[]>();

    // Group by scope
    for (const item of items) {
      if (item.scope && (item.scope.project || item.scope.org)) {
        const scopeKey = `${item.scope.project || ''}-${item.scope.org || ''}`;
        if (!scopeGroups.has(scopeKey)) {
          scopeGroups.set(scopeKey, []);
        }
        scopeGroups.get(scopeKey)!.push(item);
      }
    }

    // Group by common tags
    for (const item of items) {
      const itemTags = (item.data as unknown).tags;
      if (Array.isArray(itemTags)) {
        for (const tag of itemTags) {
          if (!tagGroups.has(tag)) {
            tagGroups.set(tag, []);
          }
          tagGroups.get(tag)!.push(item);
        }
      }
    }

    // Create groups from scope and tag analysis
    for (const [scope, scopeItems] of Array.from(scopeGroups.entries())) {
      if (scopeItems.length >= 2) {
        groups.push({
          description: `Shared scope: ${scope}`,
          items: scopeItems,
          indicators: ['shared_scope', 'collaboration_context'],
        });
      }
    }

    for (const [tag, tagItems] of Array.from(tagGroups.entries())) {
      if (tagItems.length >= 2 && !scopeGroups.has(String(tagItems[0].scope))) {
        groups.push({
          description: `Shared tag: ${tag}`,
          items: tagItems,
          indicators: ['shared_tag', 'common_interest'],
        });
      }
    }

    return groups;
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

    return content.join(' ').substring(0, 300);
  }

  /**
   * Map strength to relationship nature
   */
  private mapStrengthToNature(strength: number): 'strong' | 'moderate' | 'weak' {
    if (strength > 0.7) return 'strong';
    if (strength > 0.4) return 'moderate';
    return 'weak';
  }

  /**
   * Convert analysis to insight
   */
  private convertAnalysisToInsight(
    analysis: RelationshipAnalysis,
    scope: unknown,
    options: RelationshipAnalysisOptions
  ): ConnectionInsight {
    return {
      id: randomUUID(),
      type: 'connections',
      title: analysis.relationship_name,
      description: analysis.description,
      confidence: analysis.confidence,
      priority: this.calculatePriority(analysis),
      item_ids: [
        ...analysis.source_items.map((item) => item.item_id),
        ...analysis.target_items.map((item) => item.item_id),
      ],
      scope: scope,
      metadata: {
        generated_at: new Date().toISOString(),
        generated_by: 'relationship-analysis-strategy',
        processing_time_ms: 1,
        data_sources: ['knowledge_items'],
        tags: [analysis.relationship_type, ...analysis.metadata['connection_indicators']],
      },
      actionable: this.isActionable(analysis),
      category: 'connection',
      connection_data: {
        connection_type: analysis.relationship_type,
        source_items: analysis.source_items.map((item) => item.item_id),
        target_items: analysis.target_items.map((item) => item.item_id),
        relationship_strength: analysis.strength,
        connection_description: analysis.description,
      },
    };
  }

  /**
   * Calculate insight priority
   */
  private calculatePriority(analysis: RelationshipAnalysis): number {
    // Higher priority for strong, confident relationships
    if (analysis.strength > 0.7 && analysis.confidence > 0.8) return 1;
    if (analysis.strength > 0.5 && analysis.confidence > 0.6) return 2;
    return 3;
  }

  /**
   * Determine if relationship is actionable
   */
  private isActionable(analysis: RelationshipAnalysis): boolean {
    // Relationships that suggest optimization or improvement opportunities are actionable
    const actionableTypes = ['dependency', 'causal', 'hierarchical'];
    return actionableTypes.includes(analysis.relationship_type) && analysis.strength > 0.6;
  }
}
