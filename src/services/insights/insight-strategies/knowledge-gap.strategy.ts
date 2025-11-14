/**
 * Knowledge Gap Analysis Strategy
 *
 * Advanced knowledge gap analysis using ZAI to identify missing information,
 * incomplete documentation, and areas requiring additional knowledge capture.
 * Provides intelligent recommendations for knowledge improvement.
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
  RecommendationInsight,
} from '../../../types/insight-interfaces.js';
import type { ZAIChatRequest, ZAIChatResponse } from '../../../types/zai-interfaces.js';
import { logger } from '../../../utils/logger.js';
import type { ZAIClientService } from '../../ai/zai-client.service';

export interface KnowledgeGapOptions {
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

export interface KnowledgeGapAnalysis {
  gap_type:
    | 'missing_documentation'
    | 'incomplete_information'
    | 'outdated_content'
    | 'unanswered_questions'
    | 'process_gaps'
    | 'decision_trail_missing';
  gap_name: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: number;
  affected_items: Array<{
    item_id: string;
    item_type: string;
    gap_context: string;
    confidence: number;
  }>;
  recommendations: Array<{
    action: string;
    priority: 'low' | 'medium' | 'high' | 'critical';
    effort_estimate: 'low' | 'medium' | 'high';
    expected_outcome: string;
  }>;
  metadata: {
    analysis_method: string;
    knowledge_areas: string[];
    stakeholder_impact: string[];
    business_risk: string;
  };
}

/**
 * Knowledge Gap Analysis Strategy
 */
export class KnowledgeGapStrategy {
  constructor(private zaiClient: ZAIClientService) {}

  /**
   * Generate knowledge gap insights
   */
  async generateInsights(
    request: InsightGenerationRequest,
    options: KnowledgeGapOptions
  ): Promise<RecommendationInsight[]> {
    const insights: RecommendationInsight[] = [];

    try {
      logger.debug('Starting knowledge gap analysis');

      // Analyze different types of knowledge gaps
      const gapAnalyses = await Promise.all([
        this.analyzeMissingDocumentation(request.items, options),
        this.analyzeIncompleteInformation(request.items, options),
        this.analyzeOutdatedContent(request.items, options),
        this.analyzeDecisionTrailGaps(request.items, options),
        this.analyzeProcessGaps(request.items, options),
        this.analyzeUnansweredQuestions(request.items, options),
      ]);

      // Flatten and filter analyses
      const allAnalyses = gapAnalyses.flat();
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
        'Knowledge gap analysis completed'
      );

      return insights;
    } catch (error) {
      logger.error({ error }, 'Knowledge gap analysis strategy failed');
      return insights;
    }
  }

  /**
   * Analyze missing documentation gaps
   */
  private async analyzeMissingDocumentation(
    items: KnowledgeItem[],
    options: KnowledgeGapOptions
  ): Promise<KnowledgeGapAnalysis[]> {
    try {
      const prompt = this.buildMissingDocumentationPrompt(items);
      const zaiRequest: ZAIChatRequest = {
        messages: [
          {
            role: 'system',
            content:
              'You are an expert knowledge management analyst specializing in identifying missing documentation and knowledge gaps. Analyze the provided items to identify what documentation is missing or incomplete.',
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
      return this.parseGapResponse(response, items, 'missing_documentation');
    } catch (error) {
      logger.error({ error }, 'Missing documentation analysis failed');
      return [];
    }
  }

  /**
   * Analyze incomplete information gaps
   */
  private async analyzeIncompleteInformation(
    items: KnowledgeItem[],
    options: KnowledgeGapOptions
  ): Promise<KnowledgeGapAnalysis[]> {
    try {
      const incompleteItems = items.filter((item) => this.isIncomplete(item));
      const analyses: KnowledgeGapAnalysis[] = [];

      // Group by type of incompleteness
      const incompletenessTypes = this.groupByIncompletenessType(incompleteItems);

      for (const [type, groupItems] of incompletenessTypes.entries()) {
        if (groupItems.length >= 2) {
          const analysis: KnowledgeGapAnalysis = {
            gap_type: 'incomplete_information',
            gap_name: `Incomplete Information: ${type}`,
            description: `Multiple items lack complete ${type} information, which may impact understanding and decision-making.`,
            severity: this.calculateSeverity(groupItems, items),
            confidence: Math.min(groupItems.length / items.length, 1.0),
            affected_items: groupItems.map((item) => ({
              item_id: item.id || '',
              item_type: item.kind,
              gap_context: `Missing ${type} information`,
              confidence: 0.7,
            })),
            recommendations: [
              {
                action: `Complete ${type} information for all affected items`,
                priority: groupItems.length > 5 ? 'high' : 'medium',
                effort_estimate: 'medium',
                expected_outcome: 'Improved knowledge completeness and usability',
              },
            ],
            metadata: {
              analysis_method: 'structural_analysis',
              knowledge_areas: [type],
              stakeholder_impact: ['knowledge_consumers', 'decision_makers'],
              business_risk: 'misinterpretation',
            },
          };
          analyses.push(analysis);
        }
      }

      return analyses;
    } catch (error) {
      logger.error({ error }, 'Incomplete information analysis failed');
      return [];
    }
  }

  /**
   * Analyze outdated content gaps
   */
  private async analyzeOutdatedContent(
    items: KnowledgeItem[],
    options: KnowledgeGapOptions
  ): Promise<KnowledgeGapAnalysis[]> {
    try {
      const outdatedItems = items.filter((item) => this.mightBeOutdated(item));
      const analyses: KnowledgeGapAnalysis[] = [];

      if (outdatedItems.length >= 2) {
        const analysis: KnowledgeGapAnalysis = {
          gap_type: 'outdated_content',
          gap_name: 'Potentially Outdated Content',
          description:
            'Several items may contain outdated information that requires review and updating.',
          severity: this.calculateSeverity(outdatedItems, items),
          confidence: 0.6,
          affected_items: outdatedItems.map((item) => ({
            item_id: item.id || '',
            item_type: item.kind,
            gap_context: 'Content may be outdated',
            confidence: 0.6,
          })),
          recommendations: [
            {
              action: 'Review and update potentially outdated content',
              priority: 'medium',
              effort_estimate: 'high',
              expected_outcome: 'Current and accurate knowledge base',
            },
            {
              action: 'Implement content review schedule',
              priority: 'low',
              effort_estimate: 'medium',
              expected_outcome: 'Proactive content maintenance',
            },
          ],
          metadata: {
            analysis_method: 'temporal_analysis',
            knowledge_areas: ['content_maintenance'],
            stakeholder_impact: ['all_users'],
            business_risk: 'stale_information',
          },
        };
        analyses.push(analysis);
      }

      return analyses;
    } catch (error) {
      logger.error({ error }, 'Outdated content analysis failed');
      return [];
    }
  }

  /**
   * Analyze decision trail gaps
   */
  private async analyzeDecisionTrailGaps(
    items: KnowledgeItem[],
    options: KnowledgeGapOptions
  ): Promise<KnowledgeGapAnalysis[]> {
    try {
      const prompt = this.buildDecisionTrailPrompt(items);
      const zaiRequest: ZAIChatRequest = {
        messages: [
          {
            role: 'system',
            content:
              'You are an expert decision analysis specialist. Identify gaps in decision documentation, missing rationale, and unclear decision trails.',
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
      return this.parseGapResponse(response, items, 'decision_trail_missing');
    } catch (error) {
      logger.error({ error }, 'Decision trail analysis failed');
      return [];
    }
  }

  /**
   * Analyze process gaps
   */
  private async analyzeProcessGaps(
    items: KnowledgeItem[],
    options: KnowledgeGapOptions
  ): Promise<KnowledgeGapAnalysis[]> {
    try {
      const processItems = items.filter(
        (item) =>
          item.kind === 'runbook' ||
          item.kind === 'todo' ||
          (item.data && (item.data as unknown).tags && (item.data as unknown).tags.includes('process'))
      );

      const prompt = this.buildProcessGapPrompt(processItems);
      const zaiRequest: ZAIChatRequest = {
        messages: [
          {
            role: 'system',
            content:
              'You are an expert process analyst. Identify gaps in process documentation, missing steps, and incomplete workflows.',
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
      return this.parseGapResponse(response, items, 'process_gaps');
    } catch (error) {
      logger.error({ error }, 'Process gap analysis failed');
      return [];
    }
  }

  /**
   * Analyze unanswered questions
   */
  private async analyzeUnansweredQuestions(
    items: KnowledgeItem[],
    options: KnowledgeGapOptions
  ): Promise<KnowledgeGapAnalysis[]> {
    try {
      const questionItems = items.filter(
        (item) =>
          (item.data as unknown)?.content?.includes('?') ||
          (item.data as unknown)?.title?.includes('?') ||
          (item.data && (item.data as unknown).tags && (item.data as unknown).tags.includes('question'))
      );

      const prompt = this.buildUnansweredQuestionsPrompt(questionItems);
      const zaiRequest: ZAIChatRequest = {
        messages: [
          {
            role: 'system',
            content:
              'You are an expert knowledge analyst. Identify unanswered questions, knowledge gaps, and areas requiring additional research or clarification.',
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
      return this.parseGapResponse(response, items, 'unanswered_questions');
    } catch (error) {
      logger.error({ error }, 'Unanswered questions analysis failed');
      return [];
    }
  }

  /**
   * Build missing documentation prompt
   */
  private buildMissingDocumentationPrompt(items: KnowledgeItem[]): string {
    const itemSummaries = items
      .map((item, index) => {
        return `${index + 1}. Type: ${item.kind}, Content: ${JSON.stringify(item.data).substring(0, 200)}...`;
      })
      .join('\n');

    return `
Analyze the following knowledge items and identify missing documentation gaps:

${itemSummaries}

Look for:
1. Undocumented decisions or outcomes
2. Missing rationale or context
3. Unclear processes or procedures
4. Incomplete technical documentation
5. Missing stakeholder information
6. Unclear requirements or specifications

Provide analysis in JSON format:
{
  "gaps": [
    {
      "name": "Gap Name",
      "description": "Detailed description of what's missing",
      "severity": "low|medium|high|critical",
      "confidence": 0.8,
      "knowledge_areas": ["area1", "area2"],
      "item_indices": [1, 2, 3],
      "recommendations": [
        {
          "action": "Specific action to take",
          "priority": "low|medium|high|critical",
          "effort_estimate": "low|medium|high",
          "expected_outcome": "Expected result"
        }
      ]
    }
  ]
}

Return only the JSON response, no additional text.
`;
  }

  /**
   * Build decision trail prompt
   */
  private buildDecisionTrailPrompt(items: KnowledgeItem[]): string {
    const itemSummaries = items
      .map((item, index) => {
        return `${index + 1}. Type: ${item.kind}, Content: ${JSON.stringify(item.data).substring(0, 200)}...`;
      })
      .join('\n');

    return `
Analyze the following knowledge items for decision trail gaps:

${itemSummaries}

Look for:
1. Decisions without clear rationale
2. Missing alternatives considered
3. Unclear decision outcomes
4. Missing stakeholder input
5. Incomplete decision criteria
6. Unclear implementation status

Provide analysis in JSON format:
{
  "gaps": [
    {
      "name": "Decision Trail Gap",
      "description": "What decision information is missing",
      "severity": "low|medium|high|critical",
      "confidence": 0.8,
      "item_indices": [1, 2, 3],
      "recommendations": [
        {
          "action": "Action to improve decision documentation",
          "priority": "low|medium|high|critical",
          "effort_estimate": "low|medium|high",
          "expected_outcome": "Expected improvement"
        }
      ]
    }
  ]
}

Return only the JSON response, no additional text.
`;
  }

  /**
   * Build process gap prompt
   */
  private buildProcessGapPrompt(items: KnowledgeItem[]): string {
    const itemSummaries = items
      .map((item, index) => {
        return `${index + 1}. Type: ${item.kind}, Content: ${JSON.stringify(item.data).substring(0, 200)}...`;
      })
      .join('\n');

    return `
Analyze the following process-related knowledge items for gaps:

${itemSummaries}

Look for:
1. Missing process steps
2. Incomplete workflows
3. Unclear responsibilities
4. Missing handoffs
5. Incomplete quality criteria
6. Missing error handling

Provide analysis in JSON format:
{
  "gaps": [
    {
      "name": "Process Gap",
      "description": "What process information is missing",
      "severity": "low|medium|high|critical",
      "confidence": 0.8,
      "item_indices": [1, 2, 3],
      "recommendations": [
        {
          "action": "Action to complete process documentation",
          "priority": "low|medium|high|critical",
          "effort_estimate": "low|medium|high",
          "expected_outcome": "Expected improvement"
        }
      ]
    }
  ]
}

Return only the JSON response, no additional text.
`;
  }

  /**
   * Build unanswered questions prompt
   */
  private buildUnansweredQuestionsPrompt(items: KnowledgeItem[]): string {
    const itemSummaries = items
      .map((item, index) => {
        return `${index + 1}. Type: ${item.kind}, Content: ${JSON.stringify(item.data).substring(0, 200)}...`;
      })
      .join('\n');

    return `
Analyze the following knowledge items for unanswered questions and knowledge gaps:

${itemSummaries}

Look for:
1. Explicit questions without answers
2. Unclear statements needing clarification
3. Missing information that should be present
4. Areas requiring further research
5. Contradictions or inconsistencies
6. Ambiguous requirements

Provide analysis in JSON format:
{
  "gaps": [
    {
      "name": "Knowledge Gap",
      "description": "What information is missing or unclear",
      "severity": "low|medium|high|critical",
      "confidence": 0.8,
      "item_indices": [1, 2, 3],
      "recommendations": [
        {
          "action": "Action to address the knowledge gap",
          "priority": "low|medium|high|critical",
          "effort_estimate": "low|medium|high",
          "expected_outcome": "Expected improvement"
        }
      ]
    }
  ]
}

Return only the JSON response, no additional text.
`;
  }

  /**
   * Parse gap analysis response
   */
  private parseGapResponse(
    response: unknown,
    items: KnowledgeItem[],
    gapType: KnowledgeGapAnalysis['gap_type']
  ): KnowledgeGapAnalysis[] {
    try {
      const content = response.choices?.[0]?.message?.content;
      if (!content) {
        return [];
      }

      const analysis = JSON.parse(content);
      const gaps = analysis.gaps || [];

      return gaps.map((gap: unknown) => ({
        gap_type: gapType,
        gap_name: gap.name,
        description: gap.description,
        severity: gap.severity || 'medium',
        confidence: gap.confidence || 0.5,
        affected_items: (gap.item_indices || []).map((index: number) => {
          const item = items[index - 1];
          return {
            item_id: item.id || '',
            item_type: item.kind,
            gap_context: gap.name,
            confidence: gap.confidence || 0.5,
          };
        }),
        recommendations: gap.recommendations || [],
        metadata: {
          analysis_method: 'zai_gap_analysis',
          knowledge_areas: gap.knowledge_areas || [],
          stakeholder_impact: [],
          business_risk: 'knowledge_gap',
        },
      }));
    } catch (error) {
      logger.error({ error }, 'Failed to parse gap analysis response');
      return [];
    }
  }

  /**
   * Check if item is incomplete
   */
  private isIncomplete(item: KnowledgeItem): boolean {
    const data = item.data || {};

    // Check for missing common fields
    const hasContent = !!(data.content || data.title || data.description);
    const hasMetadata = !!(data.tags || data.categories || data.metadata);
    const hasDates = !!(data.created_at || data.updated_at);
    const hasContext = !!(data.context || data.background || data.scope);

    // Consider incomplete if missing basic information
    return !hasContent || !hasMetadata;
  }

  /**
   * Group items by incompleteness type
   */
  private groupByIncompletenessType(items: KnowledgeItem[]): Map<string, KnowledgeItem[]> {
    const groups = new Map<string, KnowledgeItem[]>();

    for (const item of items) {
      const data = item.data || {};
      const incompletenessTypes = [];

      if (!data.content && !data.title && !data.description) {
        incompletenessTypes.push('content');
      }
      if (!data.tags && !data.categories) {
        incompletenessTypes.push('categorization');
      }
      if (!data.context && !data.background) {
        incompletenessTypes.push('context');
      }
      if (!data.created_at && !data.updated_at) {
        incompletenessTypes.push('timestamps');
      }

      for (const type of incompletenessTypes) {
        if (!groups.has(type)) {
          groups.set(type, []);
        }
        groups.get(type)!.push(item);
      }
    }

    return groups;
  }

  /**
   * Check if item might be outdated
   */
  private mightBeOutdated(item: KnowledgeItem): boolean {
    if (!item.created_at) {
      return true;
    }

    const createdDate = new Date(item.created_at);
    const now = new Date();
    const daysDiff = (now.getTime() - createdDate.getTime()) / (1000 * 60 * 60 * 24);

    // Consider items older than 90 days as potentially outdated
    return daysDiff > 90;
  }

  /**
   * Calculate severity of gap
   */
  private calculateSeverity(
    affectedItems: KnowledgeItem[],
    totalItems: KnowledgeItem[]
  ): 'low' | 'medium' | 'high' | 'critical' {
    const ratio = affectedItems.length / totalItems.length;

    if (ratio > 0.5) return 'critical';
    if (ratio > 0.3) return 'high';
    if (ratio > 0.1) return 'medium';
    return 'low';
  }

  /**
   * Convert analysis to insight
   */
  private convertAnalysisToInsight(
    analysis: KnowledgeGapAnalysis,
    scope: unknown,
    options: KnowledgeGapOptions
  ): RecommendationInsight {
    // Get the highest priority recommendation
    const primaryRecommendation = analysis.recommendations[0] || {
      action: 'Address the identified knowledge gap',
      priority: 'medium' as const,
      effort_estimate: 'medium' as const,
      expected_outcome: 'Improved knowledge completeness',
    };

    return {
      id: randomUUID(),
      type: 'recommendations',
      title: `Knowledge Gap: ${analysis.gap_name}`,
      description: analysis.description,
      confidence: analysis.confidence,
      priority: this.mapSeverityToPriority(analysis.severity),
      item_ids: analysis.affected_items.map((item) => item.item_id),
      scope: scope,
      metadata: {
        generated_at: new Date().toISOString(),
        generated_by: 'knowledge-gap-strategy',
        processing_time_ms: 1,
        data_sources: ['knowledge_items'],
        tags: ['knowledge_gap', analysis.gap_type, ...analysis.metadata['knowledge_areas']],
      },
      actionable: true,
      category: 'recommendation',
      recommendation_data: {
        action_type: 'address_knowledge_gap',
        priority: primaryRecommendation.priority,
        effort_estimate: primaryRecommendation.effort_estimate,
        impact_assessment: this.mapSeverityToImpact(analysis.severity),
        dependencies: [],
        success_probability: 0.8,
      },
    };
  }

  /**
   * Map severity to priority number
   */
  private mapSeverityToPriority(severity: string): number {
    switch (severity) {
      case 'critical':
        return 1;
      case 'high':
        return 2;
      case 'medium':
        return 3;
      case 'low':
        return 4;
      default:
        return 3;
    }
  }

  /**
   * Map severity to impact assessment
   */
  private mapSeverityToImpact(severity: string): 'low' | 'medium' | 'high' {
    switch (severity) {
      case 'critical':
      case 'high':
        return 'high';
      case 'medium':
        return 'medium';
      case 'low':
        return 'low';
      default:
        return 'medium';
    }
  }
}
