// @ts-nocheck
/**
 * Contradiction Resolution Suggestion Service
 *
 * Advanced intelligent resolution suggestion engine using ZAI glm-4.6 model.
 * Generates context-aware, actionable recommendations for resolving
 * contradictions with impact assessment and implementation guidance.
 *
 * @author Cortex Team
 * @version 3.0.0
 * @since 2025
 */

import { randomUUID } from 'crypto';
import { logger } from '@/utils/logger.js';
import { zaiClientService } from '../ai/zai-client.service';
import type {
  ContradictionResult,
  ContradictionType,
  KnowledgeItem,
} from '../../types/contradiction-detector.interface';

/**
 * Resolution approach types
 */
export type ResolutionApproach =
  | 'merge'
  | 'replace'
  | 'clarify'
  | 'qualify'
  | 'contextualize'
  | 'prioritize'
  | 'defer'
  | 'escalate';

/**
 * Resolution impact assessment
 */
interface ResolutionImpact {
  complexity: 'low' | 'medium' | 'high';
  effort: 'hours' | 'days' | 'weeks';
  risk: 'low' | 'medium' | 'high';
  dependencies: string[];
  side_effects: string[];
  rollback_difficulty: 'easy' | 'moderate' | 'difficult';
}

/**
 * Resolution step details
 */
interface ResolutionStep {
  step_number: number;
  action: string;
  description: string;
  expected_outcome: string;
  estimated_time: string;
  prerequisites: string[];
  verification_criteria: string[];
}

/**
 * Comprehensive resolution suggestion
 */
interface ResolutionSuggestion {
  id: string;
  contradiction_id: string;
  approach: ResolutionApproach;
  title: string;
  description: string;
  reasoning: string;
  priority: 'low' | 'medium' | 'high' | 'critical';
  impact: ResolutionImpact;
  steps: ResolutionStep[];
  alternatives: Array<{
    approach: ResolutionApproach;
    title: string;
    description: string;
    pros: string[];
    cons: string[];
  }>;
  verification: {
    success_criteria: string[];
    testing_approach: string;
    monitoring_requirements: string[];
  };
  prevention: {
    root_cause: string;
    preventive_measures: string[];
    process_improvements: string[];
  };
  metadata: {
    confidence: number;
    model: string;
    generated_at: Date;
    context: string;
  };
}

/**
 * Batch resolution analysis result
 */
interface BatchResolutionAnalysis {
  suggestions: ResolutionSuggestion[];
  summary: {
    total_contradictions: number;
    critical_priority: number;
    high_priority: number;
    medium_priority: number;
    low_priority: number;
    total_effort_hours: number;
    highest_risk_items: string[];
  };
  dependencies: Array<{
    contradiction_id: string;
    depends_on: string[];
    blocks: string[];
  }>;
  implementation_plan: Array<{
    phase: number;
    contradictions: string[];
    estimated_duration: string;
    resources_required: string[];
  }>;
}

/**
 * Resolution suggestion configuration
 */
interface ResolutionSuggestionConfig {
  confidence_threshold: number;
  max_alternatives: number;
  max_tokens: number;
  temperature: number;
  enable_impact_assessment: boolean;
  enable_prevention_suggestions: boolean;
  enable_alternatives: boolean;
  include_verification_steps: boolean;
}

/**
 * Default configuration
 */
const DEFAULT_CONFIG: ResolutionSuggestionConfig = {
  confidence_threshold: 0.7,
  max_alternatives: 3,
  max_tokens: 2000,
  temperature: 0.2,
  enable_impact_assessment: true,
  enable_prevention_suggestions: true,
  enable_alternatives: true,
  include_verification_steps: true,
};

/**
 * Contradiction Resolution Suggestion Service
 *
 * Uses ZAI's advanced reasoning capabilities to generate intelligent,
 * context-aware resolution suggestions for contradictions with impact
 * assessment and implementation guidance.
 */
export class ContradictionResolutionSuggestionService {
  private config: ResolutionSuggestionConfig;
  private cache: Map<string, { suggestion: ResolutionSuggestion; timestamp: number }> = new Map();

  constructor(config: Partial<ResolutionSuggestionConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    logger.info('Contradiction Resolution Suggestion Service initialized', { config: this.config });
  }

  /**
   * Generate resolution suggestion for a single contradiction
   */
  async generateResolutionSuggestion(
    contradiction: ContradictionResult,
    items: KnowledgeItem[]
  ): Promise<ResolutionSuggestion> {
    const cacheKey = `resolution:${contradiction.id}`;
    const cached = this.getFromCache(cacheKey);

    if (cached) {
      return cached.suggestion;
    }

    try {
      // Find the items involved in the contradiction
      const primaryItem = items.find((item) => item.id === contradiction.primary_item_id);
      const conflictingItems = contradiction.conflicting_item_ids
        .map((id) => items.find((item) => item.id === id))
        .filter((item) => item !== undefined) as KnowledgeItem[];

      const suggestion = await this.analyzeAndGenerateSuggestion(
        contradiction,
        primaryItem,
        conflictingItems
      );

      this.setToCache(cacheKey, suggestion);

      logger.debug('Generated resolution suggestion', {
        contradictionId: contradiction.id,
        approach: suggestion.approach,
        priority: suggestion.priority,
      });

      return suggestion;
    } catch (error) {
      logger.error(
        { error, contradictionId: contradiction.id },
        'Failed to generate resolution suggestion'
      );
      throw error;
    }
  }

  /**
   * Generate resolution suggestions for multiple contradictions
   */
  async generateBatchResolutionSuggestions(
    contradictions: ContradictionResult[],
    items: KnowledgeItem[]
  ): Promise<BatchResolutionAnalysis> {
    const suggestions: ResolutionSuggestion[] = [];
    const dependencyMap = new Map<string, { depends_on: string[]; blocks: string[] }>();

    // Generate individual suggestions
    for (const contradiction of contradictions) {
      try {
        const suggestion = await this.generateResolutionSuggestion(contradiction, items);
        suggestions.push(suggestion);
      } catch (error) {
        logger.warn(
          { error, contradictionId: contradiction.id },
          'Failed to generate suggestion for contradiction'
        );
      }
    }

    // Analyze dependencies between contradictions
    for (const suggestion of suggestions) {
      const deps = this.analyzeContradictionDependencies(suggestion, suggestions);
      dependencyMap.set(suggestion.contradiction_id, deps);
    }

    // Create implementation plan
    const implementationPlan = this.createImplementationPlan(suggestions, dependencyMap);

    // Generate summary
    const summary = this.generateBatchSummary(suggestions);

    return {
      suggestions,
      summary,
      dependencies: Array.from(dependencyMap.entries()).map(([id, deps]) => ({
        contradiction_id: id,
        ...deps,
      })),
      implementation_plan: implementationPlan,
    };
  }

  /**
   * Analyze contradiction and generate resolution suggestion using ZAI
   */
  private async analyzeAndGenerateSuggestion(
    contradiction: ContradictionResult,
    primaryItem: KnowledgeItem | undefined,
    conflictingItems: KnowledgeItem[]
  ): Promise<ResolutionSuggestion> {
    const prompt = this.buildResolutionPrompt(contradiction, primaryItem, conflictingItems);

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

      const analysis = JSON.parse(response.choices[0].message.content);

      return this.createResolutionSuggestion(contradiction, analysis);
    } catch (error) {
      logger.error({ error, contradictionId: contradiction.id }, 'ZAI resolution analysis failed');
      throw error;
    }
  }

  /**
   * Get system prompt for resolution suggestion generation
   */
  private getSystemPrompt(): string {
    return `You are an expert contradiction resolution analyst specializing in providing actionable, context-aware solutions for knowledge contradictions.

RESOLUTION APPROACHES:
1. "merge" - Combine contradictory elements into a coherent whole
2. "replace" - Replace incorrect or outdated information
3. "clarify" - Add context and clarification to resolve ambiguity
4. "qualify" - Add conditions or qualifiers to statements
5. "contextualize" - Provide context that explains apparent contradictions
6. "prioritize" - Establish precedence or hierarchy between conflicting items
7. "defer" - Defer resolution pending additional information
8. "escalate" - Escalate to higher authority or expert review

ANALYSIS APPROACH:
1. Understand the nature and severity of the contradiction
2. Consider the context and domain of the knowledge items
3. Assess impact on downstream processes and decisions
4. Evaluate different resolution approaches
5. Recommend the most appropriate solution
6. Provide detailed implementation guidance
7. Include verification and prevention strategies

RESPONSE FORMAT:
{
  "recommended_approach": "merge" | "replace" | "clarify" | "qualify" | "contextualize" | "prioritize" | "defer" | "escalate",
  "title": string,
  "description": string,
  "reasoning": string,
  "priority": "low" | "medium" | "high" | "critical",
  "impact_assessment": {
    "complexity": "low" | "medium" | "high",
    "effort": "hours" | "days" | "weeks",
    "risk": "low" | "medium" | "high",
    "dependencies": string[],
    "side_effects": string[],
    "rollback_difficulty": "easy" | "moderate" | "difficult"
  },
  "implementation_steps": [
    {
      "step_number": number,
      "action": string,
      "description": string,
      "expected_outcome": string,
      "estimated_time": string,
      "prerequisites": string[],
      "verification_criteria": string[]
    }
  ],
  "alternatives": [
    {
      "approach": "merge" | "replace" | "clarify" | "qualify" | "contextualize" | "prioritize" | "defer" | "escalate",
      "title": string,
      "description": string,
      "pros": string[],
      "cons": string[]
    }
  ],
  "verification": {
    "success_criteria": string[],
    "testing_approach": string,
    "monitoring_requirements": string[]
  },
  "prevention": {
    "root_cause": string,
    "preventive_measures": string[],
    "process_improvements": string[]
  }
}

IMPORTANT:
- Provide specific, actionable steps with clear expected outcomes
- Consider practical implementation constraints and risks
- Include verification methods to ensure successful resolution
- Suggest preventive measures to avoid similar contradictions
- Recommend the approach that balances effectiveness with efficiency`;
  }

  /**
   * Build resolution analysis prompt
   */
  private buildResolutionPrompt(
    contradiction: ContradictionResult,
    primaryItem: KnowledgeItem | undefined,
    conflictingItems: KnowledgeItem[]
  ): string {
    const primaryContent = primaryItem ? this.extractContent(primaryItem) : 'Unknown primary item';
    const conflictingContents = conflictingItems
      .map((item) => `Item ${item.id} (${item.kind}): ${this.extractContent(item)}`)
      .join('\n\n');

    return `Analyze this contradiction and provide a comprehensive resolution suggestion:

CONTRADICTION DETAILS:
- ID: ${contradiction.id}
- Type: ${contradiction.contradiction_type}
- Subtype: ${contradiction.metadata?.comparison_details?.contradiction_subtype || 'Unknown'}
- Confidence: ${contradiction.confidence_score}
- Severity: ${contradiction.severity}
- Description: ${contradiction.description}
- Reasoning: ${contradiction.reasoning}

PRIMARY ITEM:
${primaryContent}

CONFLICTING ITEMS:
${conflictingContents}

EVIDENCE:
${JSON.stringify(contradiction.metadata?.evidence || [], null, 2)}

CONTEXT ANALYSIS:
- Item Types: [${contradiction.metadata?.comparison_details?.item_types?.join(', ') || 'Unknown'}]
- Detection Method: ${contradiction.metadata?.detection_method || 'Unknown'}

Please analyze this contradiction and recommend the most appropriate resolution approach with detailed implementation guidance.

Consider:
1. The nature and severity of the contradiction
2. The context and domain of the knowledge items
3. The impact on processes and decisions that depend on this information
4. Implementation complexity and required resources
5. Risk assessment and mitigation strategies
6. Verification methods and success criteria
7. Preventive measures for similar future contradictions`;
  }

  /**
   * Create resolution suggestion from analysis
   */
  private createResolutionSuggestion(
    contradiction: ContradictionResult,
    analysis: any
  ): ResolutionSuggestion {
    return {
      id: randomUUID(),
      contradiction_id: contradiction.id,
      approach: analysis.recommended_approach,
      title: analysis.title,
      description: analysis.description,
      reasoning: analysis.reasoning,
      priority: analysis.priority,
      impact: analysis.impact_assessment,
      steps: analysis.implementation_steps || [],
      alternatives: analysis.alternatives || [],
      verification: analysis.verification,
      prevention: analysis.prevention,
      metadata: {
        confidence: 0.8, // Would be calculated from analysis quality
        model: 'zai-glm-4.6',
        generated_at: new Date(),
        context: `${contradiction.contradiction_type}:${contradiction.severity}`,
      },
    };
  }

  /**
   * Analyze dependencies between contradictions
   */
  private analyzeContradictionDependencies(
    suggestion: ResolutionSuggestion,
    allSuggestions: ResolutionSuggestion[]
  ): { depends_on: string[]; blocks: string[] } {
    const depends_on: string[] = [];
    const blocks: string[] = [];

    // Simple dependency analysis based on content similarity and common elements
    for (const other of allSuggestions) {
      if (other.contradiction_id === suggestion.contradiction_id) continue;

      // Check for dependencies based on content overlap
      if (this.contentOverlap(suggestion, other) > 0.3) {
        depends_on.push(other.contradiction_id);
      }

      // Check for blocking relationships
      if (this.wouldBlockResolution(suggestion, other)) {
        blocks.push(other.contradiction_id);
      }
    }

    return { depends_on, blocks };
  }

  /**
   * Calculate content overlap between suggestions
   */
  private contentOverlap(
    suggestion1: ResolutionSuggestion,
    suggestion2: ResolutionSuggestion
  ): number {
    const text1 = `${suggestion1.title} ${suggestion1.description} ${suggestion1.impact.dependencies.join(' ')}`;
    const text2 = `${suggestion2.title} ${suggestion2.description} ${suggestion2.impact.dependencies.join(' ')}`;

    const words1 = text1.toLowerCase().split(/\s+/);
    const words2 = text2.toLowerCase().split(/\s+/);

    const commonWords = words1.filter((word) => words2.includes(word));
    const totalWords = new Set([...words1, ...words2]).size;

    return commonWords.length / totalWords;
  }

  /**
   * Check if one suggestion would block another
   */
  private wouldBlockResolution(
    suggestion1: ResolutionSuggestion,
    suggestion2: ResolutionSuggestion
  ): boolean {
    // High-priority contradictions might block lower-priority ones
    if (suggestion1.priority === 'critical' && ['medium', 'low'].includes(suggestion2.priority)) {
      return true;
    }

    // Replace approaches might block other modifications
    if (
      suggestion1.approach === 'replace' &&
      suggestion1.impact.dependencies.some((dep) =>
        suggestion2.description.toLowerCase().includes(dep.toLowerCase())
      )
    ) {
      return true;
    }

    return false;
  }

  /**
   * Create implementation plan for batch resolution
   */
  private createImplementationPlan(
    suggestions: ResolutionSuggestion[],
    dependencyMap: Map<string, { depends_on: string[]; blocks: string[] }>
  ): Array<{
    phase: number;
    contradictions: string[];
    estimated_duration: string;
    resources_required: string[];
  }> {
    // Group suggestions by priority and dependencies
    const phases: Array<{
      phase: number;
      contradictions: string[];
      estimated_duration: string;
      resources_required: string[];
    }> = [];

    // Phase 1: Critical priority
    const criticalSuggestions = suggestions.filter((s) => s.priority === 'critical');
    if (criticalSuggestions.length > 0) {
      phases.push({
        phase: 1,
        contradictions: criticalSuggestions.map((s) => s.contradiction_id),
        estimated_duration: this.estimatePhaseDuration(criticalSuggestions),
        resources_required: this.identifyRequiredResources(criticalSuggestions),
      });
    }

    // Phase 2: High priority (without critical dependencies)
    const highSuggestions = suggestions.filter(
      (s) => s.priority === 'high' && !this.dependsOnCritical(s.contradiction_id, dependencyMap)
    );
    if (highSuggestions.length > 0) {
      phases.push({
        phase: phases.length + 1,
        contradictions: highSuggestions.map((s) => s.contradiction_id),
        estimated_duration: this.estimatePhaseDuration(highSuggestions),
        resources_required: this.identifyRequiredResources(highSuggestions),
      });
    }

    // Phase 3: Medium priority
    const mediumSuggestions = suggestions.filter((s) => s.priority === 'medium');
    if (mediumSuggestions.length > 0) {
      phases.push({
        phase: phases.length + 1,
        contradictions: mediumSuggestions.map((s) => s.contradiction_id),
        estimated_duration: this.estimatePhaseDuration(mediumSuggestions),
        resources_required: this.identifyRequiredResources(mediumSuggestions),
      });
    }

    // Phase 4: Low priority
    const lowSuggestions = suggestions.filter((s) => s.priority === 'low');
    if (lowSuggestions.length > 0) {
      phases.push({
        phase: phases.length + 1,
        contradictions: lowSuggestions.map((s) => s.contradiction_id),
        estimated_duration: this.estimatePhaseDuration(lowSuggestions),
        resources_required: this.identifyRequiredResources(lowSuggestions),
      });
    }

    return phases;
  }

  /**
   * Check if contradiction depends on critical ones
   */
  private dependsOnCritical(
    contradictionId: string,
    dependencyMap: Map<string, { depends_on: string[]; blocks: string[] }>
  ): boolean {
    const deps = dependencyMap.get(contradictionId);
    return deps ? deps.depends_on.length > 0 : false;
  }

  /**
   * Estimate duration for a phase
   */
  private estimatePhaseDuration(suggestions: ResolutionSuggestion[]): string {
    const totalHours = suggestions.reduce((total, suggestion) => {
      const effort = suggestion.impact.effort;
      if (effort === 'hours') return total + 4; // Assume 4 hours average
      if (effort === 'days') return total + 24; // Assume 1 day average
      if (effort === 'weeks') return total + 120; // Assume 5 days average
      return total;
    }, 0);

    if (totalHours < 8) return `${totalHours} hours`;
    if (totalHours < 40) return `${Math.ceil(totalHours / 8)} days`;
    return `${Math.ceil(totalHours / 40)} weeks`;
  }

  /**
   * Identify required resources for a phase
   */
  private identifyRequiredResources(suggestions: ResolutionSuggestion[]): string[] {
    const resources = new Set<string>();

    suggestions.forEach((suggestion) => {
      suggestion.impact.dependencies.forEach((dep) => resources.add(dep));
      suggestion.steps.forEach((step) => {
        step.prerequisites.forEach((prereq) => resources.add(prereq));
      });
    });

    return Array.from(resources);
  }

  /**
   * Generate batch summary
   */
  private generateBatchSummary(suggestions: ResolutionSuggestion[]): any {
    const summary = {
      total_contradictions: suggestions.length,
      critical_priority: suggestions.filter((s) => s.priority === 'critical').length,
      high_priority: suggestions.filter((s) => s.priority === 'high').length,
      medium_priority: suggestions.filter((s) => s.priority === 'medium').length,
      low_priority: suggestions.filter((s) => s.priority === 'low').length,
      total_effort_hours: this.calculateTotalEffort(suggestions),
      highest_risk_items: suggestions
        .filter((s) => s.impact.risk === 'high')
        .map((s) => s.contradiction_id),
    };

    return summary;
  }

  /**
   * Calculate total effort in hours
   */
  private calculateTotalEffort(suggestions: ResolutionSuggestion[]): number {
    return suggestions.reduce((total, suggestion) => {
      const effort = suggestion.impact.effort;
      if (effort === 'hours') return total + 4;
      if (effort === 'days') return total + 24;
      if (effort === 'weeks') return total + 120;
      return total;
    }, 0);
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
    content = content.replace(/\s+/g, ' ').trim().substring(0, 1000); // Limit for prompt

    return content;
  }

  /**
   * Get resolution statistics
   */
  getStatistics(): {
    cacheSize: number;
    config: ResolutionSuggestionConfig;
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
  private getFromCache(
    key: string
  ): { suggestion: ResolutionSuggestion; timestamp: number } | null {
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
  private setToCache(key: string, suggestion: ResolutionSuggestion): void {
    this.cache.set(key, {
      suggestion,
      timestamp: Date.now(),
    });
  }
}

/**
 * Export singleton instance
 */
export const contradictionResolutionSuggestionService =
  new ContradictionResolutionSuggestionService();

/**
 * Export class for testing
 */
export { ContradictionResolutionSuggestionService };
