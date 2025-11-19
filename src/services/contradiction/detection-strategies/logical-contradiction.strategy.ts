/**
 * Logical Contradiction Detection Strategy
 *
 * Advanced logical contradiction detection using ZAI glm-4.6 model.
 * Detects inconsistencies in logical reasoning, conditions, rules,
 * and implications between knowledge items.
 *
 * @author Cortex Team
 * @version 3.0.0
 * @since 2025
 */

import { randomUUID } from 'crypto';

import { logger } from '@/utils/logger.js';

import type {
    ContradictionResult,
    KnowledgeItem,
} from '../../../types/contradiction-detector.interface';
import { zaiClientService } from '../../ai/zai-client.service';

/**
 * Logical contradiction types
 */
export type LogicalContradictionType =
  | 'mutual_exclusion'
  | 'logical_violation'
  | 'inconsistent_conditions'
  | 'contradictory_rules'
  | 'implication_failure'
  | 'conditional_contradiction'
  | 'quantifier_conflict';

/**
 * Logical structure extracted from knowledge item
 */
interface LogicalStructure {
  statements: Array<{
    type: 'assertion' | 'condition' | 'implication' | 'negation' | 'universal' | 'existential';
    content: string;
    variables: string[];
    operators: string[];
    confidence: number;
  }>;
  conditions: Array<{
    type: 'if_then' | 'only_if' | 'if_and_only_if' | 'unless' | 'necessary' | 'sufficient';
    antecedent: string;
    consequent: string;
    confidence: number;
  }>;
  quantifiers: Array<{
    type: 'universal' | 'existential' | 'uniqueness';
    scope: string;
    predicate: string;
    confidence: number;
  }>;
  logical_connectives: Array<{
    type: 'and' | 'or' | 'xor' | 'not' | 'implies' | 'equivalent';
    operands: string[];
    confidence: number;
  }>;
}

/**
 * Logical analysis result
 */
interface LogicalAnalysisResult {
  has_contradiction: boolean;
  confidence: number;
  contradiction_type: LogicalContradictionType;
  description: string;
  reasoning: string;
  evidence: Array<{
    type:
      | 'logical_conflict'
      | 'mutual_exclusion'
      | 'conditional_contradiction'
      | 'implication_violation';
    content: string;
    confidence: number;
    source_item: number;
    logical_form: string;
  }>;
  logical_analysis: {
    item1_structure: LogicalStructure;
    item2_structure: LogicalStructure;
    conflicts: Array<{
      conflict_type: string;
      severity: number;
      explanation: string;
    }>;
  };
}

/**
 * Logical contradiction detection configuration
 */
interface LogicalContradictionConfig {
  confidence_threshold: number;
  max_tokens: number;
  temperature: number;
  enable_formal_logic: boolean;
  enable_informal_logic: boolean;
  enable_conditional_analysis: boolean;
  strict_mode: boolean;
}

/**
 * Statement interface for logical analysis
 */
interface LogicalStatement {
  type: 'assertion' | 'condition' | 'implication' | 'negation' | 'universal' | 'existential';
  content: string;
  variables: string[];
  operators: string[];
  confidence: number;
}

/**
 * Condition interface for conditional analysis
 */
interface LogicalCondition {
  type: 'if_then' | 'only_if' | 'if_and_only_if' | 'unless' | 'necessary' | 'sufficient';
  antecedent: string;
  consequent: string;
  confidence: number;
}

/**
 * Default configuration
 */
const DEFAULT_CONFIG: LogicalContradictionConfig = {
  confidence_threshold: 0.7,
  max_tokens: 1500,
  temperature: 0.1,
  enable_formal_logic: true,
  enable_informal_logic: true,
  enable_conditional_analysis: true,
  strict_mode: false,
};

/**
 * Logical Contradiction Detection Strategy
 *
 * Uses ZAI's advanced reasoning capabilities to detect logical contradictions
 * in formal logic, informal reasoning, conditions, and rules between knowledge items.
 */
export class LogicalContradictionStrategy {
  private config: LogicalContradictionConfig;
  private cache: Map<string, { result: LogicalAnalysisResult; timestamp: number }> = new Map();

  constructor(config: Partial<LogicalContradictionConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    logger.info('Logical Contradiction Strategy initialized', { config: this.config });
  }

  /**
   * Detect logical contradictions between two knowledge items
   */
  async detectLogicalContradiction(
    item1: KnowledgeItem,
    item2: KnowledgeItem
  ): Promise<ContradictionResult | null> {
    const cacheKey = `logical:${item1.id}:${item2.id}`;
    const cached = this.getFromCache(cacheKey);

    if (cached) {
      return this.createResultFromAnalysis(item1, item2, cached.result);
    }

    try {
      // Extract logical structures from both items
      const structure1 = this.extractLogicalStructure(item1);
      const structure2 = this.extractLogicalStructure(item2);

      // Quick check for obvious contradictions
      const quickContradiction = this.quickLogicalCheck(structure1, structure2);
      if (quickContradiction) {
        const result = this.createQuickContradictionResult(item1, item2, quickContradiction);
        this.setToCache(cacheKey, quickContradiction);
        return result;
      }

      // Deep analysis using ZAI
      const analysis = await this.analyzeLogicalContradiction(item1, item2, structure1, structure2);

      if (analysis.has_contradiction && analysis.confidence >= this.config.confidence_threshold) {
        this.setToCache(cacheKey, analysis);
        return this.createResultFromAnalysis(item1, item2, analysis);
      }

      return null;
    } catch (error) {
      logger.error(
        { error, item1Id: item1.id, item2Id: item2.id },
        'Logical contradiction detection failed'
      );
      return null;
    }
  }

  /**
   * Extract logical structure from a knowledge item
   */
  private extractLogicalStructure(item: KnowledgeItem): LogicalStructure {
    const content = this.extractContent(item);
    const structure: LogicalStructure = {
      statements: [],
      conditions: [],
      quantifiers: [],
      logical_connectives: [],
    };

    // Extract logical statements
    structure.statements.push(...this.extractStatements(content));

    // Extract conditions
    structure.conditions.push(...this.extractConditions(content));

    // Extract quantifiers
    structure.quantifiers.push(...this.extractQuantifiers(content));

    // Extract logical connectives
    structure.logical_connectives.push(...this.extractLogicalConnectives(content));

    return structure;
  }

  /**
   * Extract logical statements from text
   */
  private extractStatements(content: string): Array<{
    type: 'assertion' | 'condition' | 'implication' | 'negation' | 'universal' | 'existential';
    content: string;
    variables: string[];
    operators: string[];
    confidence: number;
  }> {
    const statements: Array<{
      type: 'assertion' | 'condition' | 'implication' | 'negation' | 'universal' | 'existential';
      content: string;
      variables: string[];
      operators: string[];
      confidence: number;
    }> = [];

    // Negation patterns
    const negationPatterns = [
      {
        regex: /\b(not|never|no|cannot|can't|won't|doesn't|isn't|aren't)\b.+$/gim,
        type: 'negation' as const,
      },
      { regex: /^\s*(it is|it's|this is|that is)\s+(not|never)\s+/gim, type: 'negation' as const },
    ];

    negationPatterns.forEach(({ regex, type }) => {
      const matches = content.match(regex);
      if (matches) {
        matches.forEach((match) => {
          statements.push({
            type,
            content: match.trim(),
            variables: this.extractVariables(match),
            operators: this.extractOperators(match),
            confidence: 0.8,
          });
        });
      }
    });

    // Universal quantification patterns
    const universalPatterns = [
      {
        regex: /\b(all|every|each|any)\s+.+\s+(must|should|shall|will)\s+/gim,
        type: 'universal' as const,
      },
      { regex: /\b(always|necessarily|inevitably)\s+/gim, type: 'universal' as const },
    ];

    universalPatterns.forEach(({ regex, type }) => {
      const matches = content.match(regex);
      if (matches) {
        matches.forEach((match) => {
          statements.push({
            type,
            content: match.trim(),
            variables: this.extractVariables(match),
            operators: this.extractOperators(match),
            confidence: 0.7,
          });
        });
      }
    });

    // Existential patterns
    const existentialPatterns = [
      { regex: /\b(some|exists|there is|there are)\s+/gim, type: 'existential' as const },
      { regex: /\b(at least|sometimes|occasionally)\s+/gim, type: 'existential' as const },
    ];

    existentialPatterns.forEach(({ regex, type }) => {
      const matches = content.match(regex);
      if (matches) {
        matches.forEach((match) => {
          statements.push({
            type,
            content: match.trim(),
            variables: this.extractVariables(match),
            operators: this.extractOperators(match),
            confidence: 0.7,
          });
        });
      }
    });

    // Assertion patterns (positive statements)
    const assertionPatterns = [
      {
        regex: /^[^.!?]*\s+(is|are|will be|shall be|should be)\s+[^.!?]*[.!?]?/gim,
        type: 'assertion' as const,
      },
    ];

    assertionPatterns.forEach(({ regex, type }) => {
      const matches = content.match(regex);
      if (matches) {
        matches.forEach((match) => {
          if (!this.containsNegation(match)) {
            statements.push({
              type,
              content: match.trim(),
              variables: this.extractVariables(match),
              operators: this.extractOperators(match),
              confidence: 0.6,
            });
          }
        });
      }
    });

    return statements;
  }

  /**
   * Extract conditional statements from text
   */
  private extractConditions(content: string): Array<{
    type: 'if_then' | 'only_if' | 'if_and_only_if' | 'unless' | 'necessary' | 'sufficient';
    antecedent: string;
    consequent: string;
    confidence: number;
  }> {
    const conditions: Array<{
      type: 'if_then' | 'only_if' | 'if_and_only_if' | 'unless' | 'necessary' | 'sufficient';
      antecedent: string;
      consequent: string;
      confidence: number;
    }> = [];

    // If-then patterns
    const ifThenPattern = /\bif\s+(.+?),?\s+(then\s+)?(.+?)(?:\.|$)/gim;
    let match;
    while ((match = ifThenPattern.exec(content)) !== null) {
      conditions.push({
        type: 'if_then',
        antecedent: match[1].trim(),
        consequent: match[3].trim(),
        confidence: 0.8,
      });
    }

    // Only if patterns
    const onlyIfPattern = /\b(.+?)\s+only if\s+(.+?)(?:\.|$)/gim;
    while ((match = onlyIfPattern.exec(content)) !== null) {
      conditions.push({
        type: 'only_if',
        antecedent: match[1].trim(),
        consequent: match[2].trim(),
        confidence: 0.8,
      });
    }

    // Unless patterns
    const unlessPattern = /\bunless\s+(.+?),?\s+(.+?)(?:\.|$)/gim;
    while ((match = unlessPattern.exec(content)) !== null) {
      conditions.push({
        type: 'unless',
        antecedent: match[1].trim(),
        consequent: match[2].trim(),
        confidence: 0.7,
      });
    }

    // Necessary condition patterns
    const necessaryPattern = /\b(.+?)\s+(is|are)\s+necessary\s+for\s+(.+?)(?:\.|$)/gim;
    while ((match = necessaryPattern.exec(content)) !== null) {
      conditions.push({
        type: 'necessary',
        antecedent: match[3].trim(),
        consequent: match[1].trim(),
        confidence: 0.7,
      });
    }

    // Sufficient condition patterns
    const sufficientPattern = /\b(.+?)\s+(is|are)\s+sufficient\s+for\s+(.+?)(?:\.|$)/gim;
    while ((match = sufficientPattern.exec(content)) !== null) {
      conditions.push({
        type: 'sufficient',
        antecedent: match[1].trim(),
        consequent: match[3].trim(),
        confidence: 0.7,
      });
    }

    return conditions;
  }

  /**
   * Extract quantifiers from text
   */
  private extractQuantifiers(content: string): Array<{
    type: 'universal' | 'existential' | 'uniqueness';
    scope: string;
    predicate: string;
    confidence: number;
  }> {
    const quantifiers: Array<{
      type: 'universal' | 'existential' | 'uniqueness';
      scope: string;
      predicate: string;
      confidence: number;
    }> = [];

    // Universal quantifiers
    const universalPattern = /\b(all|every|each|any)\s+([^,.!?]+?)\s+(.+)/gim;
    let match;
    while ((match = universalPattern.exec(content)) !== null) {
      quantifiers.push({
        type: 'universal',
        scope: match[2].trim(),
        predicate: match[3].trim(),
        confidence: 0.7,
      });
    }

    // Existential quantifiers
    const existentialPattern = /\b(some|exists|there (?:is|are))\s+([^,.!?]+?)\s+(.+)/gim;
    while ((match = existentialPattern.exec(content)) !== null) {
      quantifiers.push({
        type: 'existential',
        scope: match[2].trim(),
        predicate: match[3].trim(),
        confidence: 0.7,
      });
    }

    // Uniqueness quantifiers
    const uniquenessPattern =
      /\b(only|exactly|just|solely)\s+(one|a single)\s+([^,.!?]+?)(?:\s+(.+))?/gim;
    while ((match = uniquenessPattern.exec(content)) !== null) {
      quantifiers.push({
        type: 'uniqueness',
        scope: match[3].trim(),
        predicate: (match[4] || '').trim() || 'exists',
        confidence: 0.8,
      });
    }

    return quantifiers;
  }

  /**
   * Extract logical connectives from text
   */
  private extractLogicalConnectives(content: string): Array<{
    type: 'and' | 'or' | 'xor' | 'not' | 'implies' | 'equivalent';
    operands: string[];
    confidence: number;
  }> {
    const connectives: Array<{
      type: 'and' | 'or' | 'xor' | 'not' | 'implies' | 'equivalent';
      operands: string[];
      confidence: number;
    }> = [];

    // AND connectives
    const andPattern = /\b([^,.!?]+?)\s+and\s+([^,.!?]+?)(?:\s+and\s+([^,.!?]+?))?(?:[.!?]|$)/gim;
    let match;
    while ((match = andPattern.exec(content)) !== null) {
      const operands = [match[1].trim(), match[2].trim()];
      if (match[3]) operands.push(match[3].trim());
      connectives.push({
        type: 'and',
        operands,
        confidence: 0.6,
      });
    }

    // OR connectives
    const orPattern = /\b([^,.!?]+?)\s+or\s+([^,.!?]+?)(?:\s+or\s+([^,.!?]+?))?(?:[.!?]|$)/gim;
    while ((match = orPattern.exec(content)) !== null) {
      const operands = [match[1].trim(), match[2].trim()];
      if (match[3]) operands.push(match[3].trim());
      connectives.push({
        type: 'or',
        operands,
        confidence: 0.6,
      });
    }

    // BUT as exclusive OR (context-dependent)
    const butPattern = /\b([^,.!?]+?)\s+but\s+([^,.!?]+?)(?:[.!?]|$)/gim;
    while ((match = butPattern.exec(content)) !== null) {
      connectives.push({
        type: 'xor',
        operands: [match[1].trim(), match[2].trim()],
        confidence: 0.5,
      });
    }

    return connectives;
  }

  /**
   * Extract variables from text (simplified)
   */
  private extractVariables(text: string): string[] {
    // Extract noun phrases and potential variables
    const variablePatterns = [
      /\b([A-Z][a-z]+(?:\s+[a-z]+)*?)\b/g, // Proper nouns
      /\b(the|a|an)\s+([a-z]+)/gi, // Nouns with articles
      /\b(each|every|all|some|any)\s+([a-z]+)/gi, // Quantified nouns
    ];

    const variables: string[] = [];
    variablePatterns.forEach((pattern) => {
      const matches = text.match(pattern);
      if (matches) {
        matches.forEach((match) => {
          const cleanVar = match.replace(/^(the|a|an|each|every|all|some|any)\s+/i, '').trim();
          if (cleanVar.length > 0 && !variables.includes(cleanVar)) {
            variables.push(cleanVar);
          }
        });
      }
    });

    return variables;
  }

  /**
   * Extract logical operators from text
   */
  private extractOperators(text: string): string[] {
    const operators: string[] = [];
    const operatorWords = [
      'is',
      'are',
      'was',
      'were',
      'will be',
      'shall be',
      'must',
      'should',
      'can',
      'could',
      'may',
      'might',
      'and',
      'or',
      'not',
      'if',
      'then',
      'only if',
      'unless',
      'implies',
      'therefore',
      'because',
      'since',
      'thus',
      'hence',
    ];

    operatorWords.forEach((op) => {
      if (text.toLowerCase().includes(op)) {
        operators.push(op);
      }
    });

    return [...new Set(operators)]; // Remove duplicates
  }

  /**
   * Check if text contains negation
   */
  private containsNegation(text: string): boolean {
    const negationWords = [
      'not',
      'never',
      'no',
      'cannot',
      "can't",
      "won't",
      "doesn't",
      "isn't",
      "aren't",
    ];
    return negationWords.some((word) => text.toLowerCase().includes(word));
  }

  /**
   * Quick check for obvious logical contradictions
   */
  private quickLogicalCheck(
    structure1: LogicalStructure,
    structure2: LogicalStructure
  ): LogicalAnalysisResult | null {
    // Check for direct negation conflicts
    for (const stmt1 of structure1.statements) {
      for (const stmt2 of structure2.statements) {
        if (this.isDirectNegation(stmt1, stmt2)) {
          return {
            has_contradiction: true,
            confidence: 0.9,
            contradiction_type: 'logical_violation',
            description: `Direct logical contradiction: "${stmt1.content}" contradicts "${stmt2.content}"`,
            reasoning: 'One statement directly negates the other',
            evidence: [
              {
                type: 'logical_conflict',
                content: `Negation conflict between "${stmt1.content}" and "${stmt2.content}"`,
                confidence: 0.9,
                source_item: 1,
                logical_form: `¬(${stmt2.content}) ∧ ${stmt1.content}`,
              },
            ],
            logical_analysis: {
              item1_structure: structure1,
              item2_structure: structure2,
              conflicts: [
                {
                  conflict_type: 'direct_negation',
                  severity: 0.9,
                  explanation: 'Statements directly contradict each other',
                },
              ],
            },
          };
        }
      }
    }

    // Check for conditional contradictions
    for (const cond1 of structure1.conditions) {
      for (const cond2 of structure2.conditions) {
        if (this.isConditionalContradiction(cond1, cond2)) {
          return {
            has_contradiction: true,
            confidence: 0.8,
            contradiction_type: 'conditional_contradiction',
            description: `Conditional contradiction between "${cond1.antecedent} → ${cond1.consequent}" and "${cond2.antecedent} → ${cond2.consequent}"`,
            reasoning: 'Conditional statements have conflicting implications',
            evidence: [
              {
                type: 'conditional_contradiction',
                content: `Conditional conflict between ${cond1.type} and ${cond2.type}`,
                confidence: 0.8,
                source_item: 1,
                logical_form: `(${cond1.antecedent} → ${cond1.consequent}) ∧ (${cond2.antecedent} → ${cond2.consequent})`,
              },
            ],
            logical_analysis: {
              item1_structure: structure1,
              item2_structure: structure2,
              conflicts: [
                {
                  conflict_type: 'conditional_conflict',
                  severity: 0.8,
                  explanation: 'Conditional statements conflict',
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
   * Check if two statements are direct negations
   */
  private isDirectNegation(stmt1: LogicalStatement, stmt2: LogicalStatement): boolean {
    // Simple heuristic: if one is negation and they refer to similar content
    if (stmt1.type === 'negation' && stmt2.type === 'assertion') {
      return this.contentSimilarity(stmt1.content, stmt2.content) > 0.7;
    }
    if (stmt2.type === 'negation' && stmt1.type === 'assertion') {
      return this.contentSimilarity(stmt1.content, stmt2.content) > 0.7;
    }
    return false;
  }

  /**
   * Check if two conditions contradict each other
   */
  private isConditionalContradiction(cond1: LogicalCondition, cond2: LogicalCondition): boolean {
    // Same antecedent with different consequents
    if (
      cond1.antecedent.toLowerCase() === cond2.antecedent.toLowerCase() &&
      cond1.consequent.toLowerCase() !== cond2.consequent.toLowerCase()
    ) {
      return true;
    }

    // Contradictory conditions
    if (
      cond1.antecedent.toLowerCase() === cond2.consequent.toLowerCase() &&
      cond1.consequent.toLowerCase() === cond2.antecedent.toLowerCase()
    ) {
      return true;
    }

    return false;
  }

  /**
   * Calculate content similarity (simplified)
   */
  private contentSimilarity(content1: string, content2: string): number {
    const words1 = content1.toLowerCase().split(/\s+/);
    const words2 = content2.toLowerCase().split(/\s+/);

    const commonWords = words1.filter((word) => words2.includes(word));
    const totalWords = new Set([...words1, ...words2]).size;

    return commonWords.length / totalWords;
  }

  /**
   * Analyze logical contradiction using ZAI
   */
  private async analyzeLogicalContradiction(
    item1: KnowledgeItem,
    item2: KnowledgeItem,
    structure1: LogicalStructure,
    structure2: LogicalStructure
  ): Promise<LogicalAnalysisResult> {
    const prompt = this.buildLogicalAnalysisPrompt(item1, item2, structure1, structure2);

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

      if (!response.success || !response.data) {
        throw new Error('Failed to generate completion');
      }

      return JSON.parse(response.data.choices[0].message.content) as LogicalAnalysisResult;
    } catch (error) {
      logger.error({ error, item1Id: item1.id, item2Id: item2.id }, 'ZAI logical analysis failed');
      throw error;
    }
  }

  /**
   * Get system prompt for logical contradiction detection
   */
  private getSystemPrompt(): string {
    return `You are an expert logical contradiction detector specializing in identifying inconsistencies in formal and informal reasoning.

LOGICAL CONTRADICTION TYPES:
1. "mutual_exclusion" - Two statements cannot both be true (A and ¬A)
2. "logical_violation" - Violation of fundamental logical principles
3. "inconsistent_conditions" - Contradictory conditional requirements
4. "contradictory_rules" - Rules that cannot both be followed
5. "implication_failure" - If-then statements with invalid implications
6. "conditional_contradiction" - Contradictions in conditional logic
7. "quantifier_conflict" - Conflicts between universal and existential claims

ANALYSIS APPROACH:
1. Extract logical structure from each statement
2. Identify formal logical forms (propositional, predicate logic)
3. Check for basic contradictions (A ∧ ¬A)
4. Analyze conditional relationships
5. Verify logical consistency of rules
6. Check quantifier compatibility
7. Identify implicit contradictions

RESPONSE FORMAT:
{
  "has_contradiction": boolean,
  "confidence": number (0-1),
  "contradiction_type": "mutual_exclusion" | "logical_violation" | "inconsistent_conditions" | "contradictory_rules" | "implication_failure" | "conditional_contradiction" | "quantifier_conflict",
  "description": string,
  "reasoning": string,
  "evidence": [
    {
      "type": "logical_conflict" | "mutual_exclusion" | "conditional_contradiction" | "implication_violation",
      "content": string,
      "confidence": number,
      "source_item": 1 or 2,
      "logical_form": string
    }
  ],
  "logical_analysis": {
    "item1_structure": {...},
    "item2_structure": {...},
    "conflicts": [{"conflict_type": string, "severity": number, "explanation": string}]
  }
}

IMPORTANT:
- Only report contradictions with confidence >= 0.6
- Consider both formal logic and informal reasoning
- Account for context-dependent interpretations
- Provide specific logical forms for contradictions
- Explain the reasoning behind each contradiction detection`;
  }

  /**
   * Build analysis prompt for logical contradiction
   */
  private buildLogicalAnalysisPrompt(
    item1: KnowledgeItem,
    item2: KnowledgeItem,
    structure1: LogicalStructure,
    structure2: LogicalStructure
  ): string {
    const content1 = this.extractContent(item1);
    const content2 = this.extractContent(item2);

    return `Analyze these two knowledge items for logical contradictions:

ITEM 1 (${item1.kind}):
Content: ${content1}
Logical Structure: ${JSON.stringify(structure1, null, 2)}

ITEM 2 (${item2.kind}):
Content: ${content2}
Logical Structure: ${JSON.stringify(structure2, null, 2)}

ANALYSIS FOCUS:
1. Formal logical contradictions (A ∧ ¬A, ∀x P(x) vs ∃x ¬P(x))
2. Inconsistent conditional statements and rules
3. Contradictory implications and consequences
4. Mutual exclusivity claims
5. Quantifier conflicts (universal vs existential)
6. Logical structure inconsistencies
7. Implicit contradictions in reasoning

CONSIDER:
- Both formal and informal logic
- Context-dependent interpretations
- Implicit assumptions and premises
- Logical connectives and their meanings
- Conditional relationships
- Quantifier scope and relationships
- Practical vs theoretical contradictions

Provide detailed logical analysis focusing on formal reasoning and implicit contradictions.`;
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
    analysis: LogicalAnalysisResult
  ): ContradictionResult {
    const severity = this.calculateSeverity(analysis.confidence, analysis.contradiction_type);

    return {
      id: randomUUID(),
      detected_at: new Date(),
      contradiction_type: 'logical',
      confidence_score: analysis.confidence,
      severity,
      primary_item_id: item1.id || randomUUID(),
      conflicting_item_ids: [item2.id || randomUUID()],
      description: analysis.description,
      reasoning: analysis.reasoning,
      metadata: {
        detection_method: 'zai_logical_analysis',
        algorithm_version: '3.0.0',
        processing_time_ms: 0,
        comparison_details: {
          contradiction_subtype: analysis.contradiction_type,
          logical_analysis: analysis.logical_analysis,
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
    analysis: LogicalAnalysisResult
  ): ContradictionResult {
    const severity = 'high';

    return {
      id: randomUUID(),
      detected_at: new Date(),
      contradiction_type: 'logical',
      confidence_score: analysis.confidence,
      severity,
      primary_item_id: item1.id || randomUUID(),
      conflicting_item_ids: [item2.id || randomUUID()],
      description: analysis.description,
      reasoning: analysis.reasoning,
      metadata: {
        detection_method: 'quick_logical_check',
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
    type: LogicalContradictionType
  ): 'low' | 'medium' | 'high' | 'critical' {
    // Base severity on confidence
    if (confidence >= 0.9) return 'critical';
    if (confidence >= 0.8) return 'high';
    if (confidence >= 0.6) return 'medium';

    // Adjust based on contradiction type
    const criticalTypes = ['mutual_exclusion', 'logical_violation'];
    const highTypes = ['contradictory_rules', 'implication_failure'];

    if (criticalTypes.includes(type) && confidence >= 0.7) return 'critical';
    if (highTypes.includes(type) && confidence >= 0.6) return 'high';

    return 'low';
  }

  /**
   * Generate resolution suggestions based on contradiction type
   */
  private generateResolutionSuggestions(
    type: LogicalContradictionType,
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
      case 'mutual_exclusion':
        suggestions.push({
          suggestion: 'Resolve mutual exclusivity by clarifying which statement is correct',
          priority: 'high',
          effort: 'medium',
          description: 'Review both statements and determine which should be true or false',
        });
        suggestions.push({
          suggestion: 'Add context qualifiers to resolve the mutual exclusion',
          priority: 'medium',
          effort: 'low',
          description: 'Specify conditions under which each statement applies',
        });
        break;

      case 'logical_violation':
        suggestions.push({
          suggestion: 'Correct the logical violation to restore logical consistency',
          priority: 'high',
          effort: 'high',
          description: 'Review and fix the logical structure that violates fundamental principles',
        });
        break;

      case 'inconsistent_conditions':
        suggestions.push({
          suggestion: 'Harmonize conditional statements to be consistent',
          priority: 'high',
          effort: 'medium',
          description: 'Ensure all conditional requirements are compatible',
        });
        break;

      case 'contradictory_rules':
        suggestions.push({
          suggestion: 'Reconcile contradictory rules or establish precedence',
          priority: 'high',
          effort: 'high',
          description: 'Resolve rule conflicts or establish clear hierarchy and exceptions',
        });
        break;

      case 'implication_failure':
        suggestions.push({
          suggestion: 'Fix invalid implications in conditional statements',
          priority: 'high',
          effort: 'medium',
          description: 'Review and correct the logical relationships in if-then statements',
        });
        break;

      case 'quantifier_conflict':
        suggestions.push({
          suggestion: 'Resolve conflicts between universal and existential claims',
          priority: 'medium',
          effort: 'medium',
          description: 'Clarify scope and applicability of quantified statements',
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
    config: LogicalContradictionConfig;
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
  private getFromCache(key: string): { result: LogicalAnalysisResult; timestamp: number } | null {
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
  private setToCache(key: string, result: LogicalAnalysisResult): void {
    this.cache.set(key, {
      result,
      timestamp: Date.now(),
    });
  }
}

/**
 * Export singleton instance
 */
export const logicalContradictionStrategy = new LogicalContradictionStrategy();
