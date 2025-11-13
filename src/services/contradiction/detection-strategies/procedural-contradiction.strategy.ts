
/**
 * Procedural Contradiction Detection Strategy
 *
 * Advanced procedural contradiction detection using ZAI glm-4.6 model.
 * Detects inconsistencies in processes, workflows, procedures, and
 * operational steps between knowledge items.
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
 * Procedural contradiction types
 */
export type ProceduralContradictionType =
  | 'process_step'
  | 'workflow'
  | 'decision_procedure'
  | 'task_dependency'
  | 'policy_conflict'
  | 'authorization_conflict'
  | 'resource_conflict'
  | 'sequence_contradiction';

/**
 * Procedural element extracted from knowledge item
 */
interface ProceduralElement {
  type:
    | 'step'
    | 'decision'
    | 'condition'
    | 'action'
    | 'approval'
    | 'requirement'
    | 'constraint'
    | 'resource';
  content: string;
  sequence?: number;
  dependencies: string[];
  conditions: string[];
  actors: string[];
  artifacts: string[];
  confidence: number;
}

/**
 * Process structure extracted from knowledge item
 */
interface ProcessStructure {
  elements: ProceduralElement[];
  steps: Array<{
    step_number: number;
    description: string;
    prerequisites: string[];
    outputs: string[];
    actor?: string;
    approval_required?: boolean;
  }>;
  decisions: Array<{
    condition: string;
    branches: Array<{ condition: string; outcome: string }>;
    actor?: string;
  }>;
  workflows: Array<{
    name: string;
    steps: string[];
    dependencies: Array<{ from: string; to: string; type: string }>;
  }>;
  policies: Array<{
    name: string;
    rule: string;
    scope: string;
    exceptions: string[];
  }>;
  resources: Array<{
    type: string;
    name: string;
    requirements: string[];
    constraints: string[];
  }>;
}

/**
 * Procedural analysis result
 */
interface ProceduralAnalysisResult {
  has_contradiction: boolean;
  confidence: number;
  contradiction_type: ProceduralContradictionType;
  description: string;
  reasoning: string;
  evidence: Array<{
    type:
      | 'procedural_conflict'
      | 'step_contradiction'
      | 'workflow_inconsistency'
      | 'policy_conflict';
    content: string;
    confidence: number;
    source_item: number;
    procedural_element: unknown;
  }>;
  procedural_analysis: {
    item1_structure: ProcessStructure;
    item2_structure: ProcessStructure;
    conflicts: Array<{
      conflict_type: string;
      severity: number;
      explanation: string;
      affected_elements: string[];
    }>;
  };
}

/**
 * Procedural contradiction detection configuration
 */
interface ProceduralContradictionConfig {
  confidence_threshold: number;
  max_tokens: number;
  temperature: number;
  enable_workflow_analysis: boolean;
  enable_policy_analysis: boolean;
  enable_dependency_analysis: boolean;
  strict_mode: boolean;
}

/**
 * Default configuration
 */
const DEFAULT_CONFIG: ProceduralContradictionConfig = {
  confidence_threshold: 0.7,
  max_tokens: 1500,
  temperature: 0.1,
  enable_workflow_analysis: true,
  enable_policy_analysis: true,
  enable_dependency_analysis: true,
  strict_mode: false,
};

/**
 * Procedural Contradiction Detection Strategy
 *
 * Uses ZAI's advanced reasoning capabilities to detect procedural contradictions
 * in workflows, processes, decision procedures, and operational policies.
 */
export class ProceduralContradictionStrategy {
  private config: ProceduralContradictionConfig;
  private cache: Map<string, { result: ProceduralAnalysisResult; timestamp: number }> = new Map();

  constructor(config: Partial<ProceduralContradictionConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    logger.info('Procedural Contradiction Strategy initialized', { config: this.config });
  }

  /**
   * Detect procedural contradictions between two knowledge items
   */
  async detectProceduralContradiction(
    item1: KnowledgeItem,
    item2: KnowledgeItem
  ): Promise<ContradictionResult | null> {
    const cacheKey = `procedural:${item1.id}:${item2.id}`;
    const cached = this.getFromCache(cacheKey);

    if (cached) {
      return this.createResultFromAnalysis(item1, item2, cached.result);
    }

    try {
      // Check if items contain procedural content
      if (!this.isProceduralContent(item1) || !this.isProceduralContent(item2)) {
        return null;
      }

      // Extract procedural structure from both items
      const structure1 = this.extractProcessStructure(item1);
      const structure2 = this.extractProcessStructure(item2);

      // Quick check for obvious contradictions
      const quickContradiction = this.quickProceduralCheck(structure1, structure2);
      if (quickContradiction) {
        const result = this.createQuickContradictionResult(item1, item2, quickContradiction);
        this.setToCache(cacheKey, quickContradiction);
        return result;
      }

      // Deep analysis using ZAI
      const analysis = await this.analyzeProceduralContradiction(
        item1,
        item2,
        structure1,
        structure2
      );

      if (analysis.has_contradiction && analysis.confidence >= this.config.confidence_threshold) {
        this.setToCache(cacheKey, analysis);
        return this.createResultFromAnalysis(item1, item2, analysis);
      }

      return null;
    } catch (error) {
      logger.error(
        { error, item1Id: item1.id, item2Id: item2.id },
        'Procedural contradiction detection failed'
      );
      return null;
    }
  }

  /**
   * Check if item contains procedural content
   */
  private isProceduralContent(item: KnowledgeItem): boolean {
    const proceduralKinds = [
      'runbook',
      'decision',
      'todo',
      'process',
      'workflow',
      'procedure',
      'policy',
    ];
    const content = this.extractContent(item).toLowerCase();

    // Check kind
    if (proceduralKinds.includes(item.kind)) {
      return true;
    }

    // Check content for procedural indicators
    const proceduralIndicators = [
      'step',
      'process',
      'procedure',
      'workflow',
      'approval',
      'review',
      'implement',
      'execute',
      'perform',
      'complete',
      'validate',
      'verify',
      'policy',
      'guideline',
      'standard',
      'requirement',
      'specification',
      'first',
      'second',
      'then',
      'next',
      'finally',
      'before',
      'after',
      'if',
      'when',
      'unless',
      'condition',
      'requirement',
      'constraint',
    ];

    return proceduralIndicators.some((indicator) => content.includes(indicator));
  }

  /**
   * Extract process structure from a knowledge item
   */
  private extractProcessStructure(item: KnowledgeItem): ProcessStructure {
    const content = this.extractContent(item);
    const structure: ProcessStructure = {
      elements: [],
      steps: [],
      decisions: [],
      workflows: [],
      policies: [],
      resources: [],
    };

    // Extract steps
    structure.steps.push(...this.extractSteps(content));

    // Extract decisions
    structure.decisions.push(...this.extractDecisions(content));

    // Extract workflows
    structure.workflows.push(...this.extractWorkflows(content));

    // Extract policies
    structure.policies.push(...this.extractPolicies(content));

    // Extract resources
    structure.resources.push(...this.extractResources(content));

    // Generate elements
    structure.elements.push(...this.generateProceduralElements(structure, content));

    return structure;
  }

  /**
   * Extract steps from text
   */
  private extractSteps(content: string): Array<{
    step_number: number;
    description: string;
    prerequisites: string[];
    outputs: string[];
    actor?: string;
    approval_required?: boolean;
  }> {
    const steps: Array<{
      step_number: number;
      description: string;
      prerequisites: string[];
      outputs: string[];
      actor?: string;
      approval_required?: boolean;
    }> = [];

    // Step patterns
    const stepPatterns = [
      { regex: /(\d+)[\.\)]\s*(.+?)(?=\n\d+[\.\)]|\n\n|$)/gs, type: 'numbered' },
      { regex: /[-•*]\s*(.+?)(?=\n[-•*]|\n\n|$)/gs, type: 'bullet' },
      {
        regex:
          /(step\s+\d+|first|second|then|next|finally)\s*:?\s*(.+?)(?=\n(step\s+\d+|first|second|then|next|finally)|\n\n|$)/gs,
        type: 'sequential',
      },
    ];

    stepPatterns.forEach(({ regex, type }) => {
      const matches = content.matchAll(regex);
      for (const match of matches) {
        const description = match[2]?.trim() || match[1]?.trim();
        if (description && description.length > 5) {
          const stepNumber = type === 'numbered' ? parseInt(match[1]) : steps.length + 1;

          steps.push({
            step_number: stepNumber,
            description,
            prerequisites: this.extractPrerequisites(description),
            outputs: this.extractOutputs(description),
            actor: this.extractActor(description),
            approval_required: this.requiresApproval(description),
          });
        }
      }
    });

    return steps;
  }

  /**
   * Extract decisions from text
   */
  private extractDecisions(content: string): Array<{
    condition: string;
    branches: Array<{ condition: string; outcome: string }>;
    actor?: string;
  }> {
    const decisions: Array<{
      condition: string;
      branches: Array<{ condition: string; outcome: string }>;
      actor?: string;
    }> = [];

    // Decision patterns
    const decisionPatterns = [
      {
        regex: /if\s+(.+?),?\s*then\s+(.+?)(?:\s*else\s+(.+?))?(?:\n|$)/gi,
        type: 'if_then_else',
      },
      {
        regex: /when\s+(.+?),?\s*(.+?)(?:\s*otherwise\s+(.+?))?(?:\n|$)/gi,
        type: 'when_then',
      },
      {
        regex: /case\s+(.+?):\s*(.+?)(?:\s*default:?\s*(.+?))?(?:\n|$)/gi,
        type: 'case_switch',
      },
    ];

    decisionPatterns.forEach(({ regex, type }) => {
      const matches = content.matchAll(regex);
      for (const match of matches) {
        const branches = [];

        if (type === 'if_then_else') {
          branches.push({ condition: 'true', outcome: match[2].trim() });
          if (match[3]) {
            branches.push({ condition: 'false', outcome: match[3].trim() });
          }
          decisions.push({
            condition: match[1].trim(),
            branches,
            actor: this.extractActor(match[0]),
          });
        }
      }
    });

    return decisions;
  }

  /**
   * Extract workflows from text
   */
  private extractWorkflows(content: string): Array<{
    name: string;
    steps: string[];
    dependencies: Array<{ from: string; to: string; type: string }>;
  }> {
    const workflows: Array<{
      name: string;
      steps: string[];
      dependencies: Array<{ from: string; to: string; type: string }>;
    }> = [];

    // Workflow patterns
    const workflowPatterns = [
      {
        regex: /workflow\s*[:#]?\s*([^\n]+)\s*\n((?:\s*[-•*]\s*.+(?:\n|$))+)/gi,
        type: 'explicit_workflow',
      },
      {
        regex: /process\s*[:#]?\s*([^\n]+)\s*\n((?:\s*\d+[.\)]\s*.+(?:\n|$))+)/gi,
        type: 'process_workflow',
      },
    ];

    workflowPatterns.forEach(({ regex, type }) => {
      const matches = content.matchAll(regex);
      for (const match of matches) {
        const name = match[1].trim();
        const stepsText = match[2];

        const steps = [];
        const stepMatches = stepsText.matchAll(/[-•*\d+[.\)]\s*(.+)/g);
        for (const stepMatch of stepMatches) {
          steps.push(stepMatch[1].trim());
        }

        workflows.push({
          name,
          steps,
          dependencies: this.extractDependencies(stepsText),
        });
      }
    });

    return workflows;
  }

  /**
   * Extract policies from text
   */
  private extractPolicies(content: string): Array<{
    name: string;
    rule: string;
    scope: string;
    exceptions: string[];
  }> {
    const policies: Array<{
      name: string;
      rule: string;
      scope: string;
      exceptions: string[];
    }> = [];

    // Policy patterns
    const policyPatterns = [
      {
        regex: /policy\s*[:#]?\s*([^\n]+)\s*[:\-]?\s*(.+?)(?:\nexception[s]?:?\s*(.+?))?(?:\n|$)/gi,
        type: 'explicit_policy',
      },
      {
        regex: /(must|shall|should|required)\s+(.+?)(?:\nunless\s+(.+?))?(?:\n|$)/gi,
        type: 'requirement_policy',
      },
    ];

    policyPatterns.forEach(({ regex, type }) => {
      const matches = content.matchAll(regex);
      for (const match of matches) {
        if (type === 'explicit_policy') {
          policies.push({
            name: match[1].trim(),
            rule: match[2].trim(),
            scope: 'general',
            exceptions: match[3] ? match[3].split(',').map((e) => e.trim()) : [],
          });
        }
      }
    });

    return policies;
  }

  /**
   * Extract resources from text
   */
  private extractResources(content: string): Array<{
    type: string;
    name: string;
    requirements: string[];
    constraints: string[];
  }> {
    const resources: Array<{
      type: string;
      name: string;
      requirements: string[];
      constraints: string[];
    }> = [];

    // Resource patterns
    const resourcePatterns = [
      {
        regex:
          /(system|service|tool|resource)\s*:?\s*([^\n]+)\s*(?:\nrequires?:?\s*(.+?))?(?:\nconstraints?:?\s*(.+?))?(?:\n|$)/gi,
        type: 'resource_spec',
      },
    ];

    resourcePatterns.forEach(({ regex, type }) => {
      const matches = content.matchAll(regex);
      for (const match of matches) {
        resources.push({
          type: match[1].trim(),
          name: match[2].trim(),
          requirements: match[3] ? match[3].split(',').map((r) => r.trim()) : [],
          constraints: match[4] ? match[4].split(',').map((c) => c.trim()) : [],
        });
      }
    });

    return resources;
  }

  /**
   * Generate procedural elements from structure
   */
  private generateProceduralElements(
    structure: ProcessStructure,
    content: string
  ): ProceduralElement[] {
    const elements: ProceduralElement[] = [];

    // Generate elements from steps
    structure.steps.forEach((step, index) => {
      elements.push({
        type: 'step',
        content: step.description,
        sequence: step.step_number,
        dependencies: step.prerequisites,
        conditions: [],
        actors: step.actor ? [step.actor] : [],
        artifacts: step.outputs,
        confidence: 0.8,
      });
    });

    // Generate elements from decisions
    structure.decisions.forEach((decision) => {
      elements.push({
        type: 'decision',
        content: decision.condition,
        dependencies: [],
        conditions: [decision.condition],
        actors: decision.actor ? [decision.actor] : [],
        artifacts: decision.branches.map((b) => b.outcome),
        confidence: 0.7,
      });
    });

    return elements;
  }

  /**
   * Extract prerequisites from step description
   */
  private extractPrerequisites(description: string): string[] {
    const prerequisites: string[] = [];

    const prerequisitePatterns = [
      /after\s+(.+?)(?:\s|$)/gi,
      /once\s+(.+?)(?:\s|$)/gi,
      /following\s+(.+?)(?:\s|$)/gi,
      /requires?\s+(.+?)(?:\s|$)/gi,
    ];

    prerequisitePatterns.forEach((pattern) => {
      const matches = description.matchAll(pattern);
      for (const match of matches) {
        prerequisites.push(match[1].trim());
      }
    });

    return prerequisites;
  }

  /**
   * Extract outputs from step description
   */
  private extractOutputs(description: string): string[] {
    const outputs: string[] = [];

    const outputPatterns = [
      /produce[s]?\s+(.+?)(?:\s|$)/gi,
      /create[s]?\s+(.+?)(?:\s|$)/gi,
      /generate[s]?\s+(.+?)(?:\s|$)/gi,
      /output[s]?\s+(.+?)(?:\s|$)/gi,
    ];

    outputPatterns.forEach((pattern) => {
      const matches = description.matchAll(pattern);
      for (const match of matches) {
        outputs.push(match[1].trim());
      }
    });

    return outputs;
  }

  /**
   * Extract actor from description
   */
  private extractActor(description: string): string | undefined {
    const actorPatterns = [
      /\b(developer|admin|user|manager|team|system|service)\b/gi,
      /by\s+(\w+(?:\s+\w+)*?)(?:\s|$)/gi,
    ];

    for (const pattern of actorPatterns) {
      const match = description.match(pattern);
      if (match) {
        return match[1] || match[0];
      }
    }

    return undefined;
  }

  /**
   * Check if step requires approval
   */
  private requiresApproval(description: string): boolean {
    const approvalIndicators = [
      'approval',
      'review',
      'sign-off',
      'authorize',
      'validate',
      'verify',
      'check',
      'confirm',
      'accept',
      'approve',
    ];

    return approvalIndicators.some((indicator) => description.toLowerCase().includes(indicator));
  }

  /**
   * Extract dependencies from workflow text
   */
  private extractDependencies(
    workflowText: string
  ): Array<{ from: string; to: string; type: string }> {
    const dependencies: Array<{ from: string; to: string; type: string }> = [];

    const dependencyPatterns = [
      { regex: /(.+?)\s*->\s*(.+)/g, type: 'sequence' },
      { regex: /(.+?)\s+before\s+(.+)/g, type: 'prerequisite' },
      { regex: /(.+?)\s+after\s+(.+)/g, type: 'dependent' },
    ];

    dependencyPatterns.forEach(({ regex, type }) => {
      const matches = workflowText.matchAll(regex);
      for (const match of matches) {
        dependencies.push({
          from: match[1].trim(),
          to: match[2].trim(),
          type,
        });
      }
    });

    return dependencies;
  }

  /**
   * Quick check for obvious procedural contradictions
   */
  private quickProceduralCheck(
    structure1: ProcessStructure,
    structure2: ProcessStructure
  ): ProceduralAnalysisResult | null {
    // Check for step order contradictions
    for (const step1 of structure1.steps) {
      for (const step2 of structure2.steps) {
        if (this.isStepOrderContradiction(step1, step2)) {
          return {
            has_contradiction: true,
            confidence: 0.8,
            contradiction_type: 'sequence_contradiction',
            description: `Step order contradiction: "${step1.description}" conflicts with "${step2.description}"`,
            reasoning: 'Steps have conflicting order or sequence requirements',
            evidence: [
              {
                type: 'step_contradiction',
                content: `Step conflict between step ${step1.step_number} and step ${step2.step_number}`,
                confidence: 0.8,
                source_item: 1,
                procedural_element: { step1, step2 },
              },
            ],
            procedural_analysis: {
              item1_structure: structure1,
              item2_structure: structure2,
              conflicts: [
                {
                  conflict_type: 'step_order',
                  severity: 0.8,
                  explanation: 'Steps have conflicting sequence requirements',
                  affected_elements: [step1.description, step2.description],
                },
              ],
            },
          };
        }
      }
    }

    // Check for policy conflicts
    for (const policy1 of structure1.policies) {
      for (const policy2 of structure2.policies) {
        if (this.isPolicyConflict(policy1, policy2)) {
          return {
            has_contradiction: true,
            confidence: 0.9,
            contradiction_type: 'policy_conflict',
            description: `Policy contradiction between "${policy1.name}" and "${policy2.name}"`,
            reasoning: 'Policies have conflicting rules or requirements',
            evidence: [
              {
                type: 'policy_conflict',
                content: `Policy conflict between ${policy1.name} and ${policy2.name}`,
                confidence: 0.9,
                source_item: 1,
                procedural_element: { policy1, policy2 },
              },
            ],
            procedural_analysis: {
              item1_structure: structure1,
              item2_structure: structure2,
              conflicts: [
                {
                  conflict_type: 'policy_conflict',
                  severity: 0.9,
                  explanation: 'Policies have conflicting requirements',
                  affected_elements: [policy1.name, policy2.name],
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
   * Check if two steps have order contradictions
   */
  private isStepOrderContradiction(
    step1: { step_number: number; description: string; prerequisites: string[] },
    step2: { step_number: number; description: string; prerequisites: string[] }
  ): boolean {
    // If steps have same number but different descriptions
    if (step1.step_number === step2.step_number && step1.description !== step2.description) {
      // Check if descriptions are similar
      return this.contentSimilarity(step1.description, step2.description) < 0.7;
    }

    // Check for contradictory prerequisites
    for (const prereq1 of step1.prerequisites) {
      for (const prereq2 of step2.prerequisites) {
        if (this.arePrerequisitesConflicting(prereq1, prereq2)) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Check if two policies conflict
   */
  private isPolicyConflict(
    policy1: { name: string; rule: string; scope: string },
    policy2: { name: string; rule: string; scope: string }
  ): boolean {
    // Same scope and conflicting rules
    if (policy1.scope === policy2.scope) {
      // Check for mutual exclusion
      const rule1Lower = policy1.rule.toLowerCase();
      const rule2Lower = policy2.rule.toLowerCase();

      // Look for contradictory requirements
      const contradictions = [
        ['must', 'must not'],
        ['required', 'prohibited'],
        ['always', 'never'],
        ['enabled', 'disabled'],
        ['allow', 'deny'],
      ];

      for (const [word1, word2] of contradictions) {
        if (rule1Lower.includes(word1) && rule2Lower.includes(word2)) {
          return true;
        }
        if (rule1Lower.includes(word2) && rule2Lower.includes(word1)) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Check if prerequisites are conflicting
   */
  private arePrerequisitesConflicting(prereq1: string, prereq2: string): boolean {
    // Simple heuristic for conflicting prerequisites
    const conflicts = [
      ['before', 'after'],
      ['complete', 'start'],
      ['success', 'failure'],
      ['approved', 'rejected'],
    ];

    const prereq1Lower = prereq1.toLowerCase();
    const prereq2Lower = prereq2.toLowerCase();

    for (const [word1, word2] of conflicts) {
      if (
        (prereq1Lower.includes(word1) && prereq2Lower.includes(word2)) ||
        (prereq1Lower.includes(word2) && prereq2Lower.includes(word1))
      ) {
        return true;
      }
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
   * Analyze procedural contradiction using ZAI
   */
  private async analyzeProceduralContradiction(
    item1: KnowledgeItem,
    item2: KnowledgeItem,
    structure1: ProcessStructure,
    structure2: ProcessStructure
  ): Promise<ProceduralAnalysisResult> {
    const prompt = this.buildProceduralAnalysisPrompt(item1, item2, structure1, structure2);

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

      return JSON.parse(response.choices[0].message.content) as ProceduralAnalysisResult;
    } catch (error) {
      logger.error(
        { error, item1Id: item1.id, item2Id: item2.id },
        'ZAI procedural analysis failed'
      );
      throw error;
    }
  }

  /**
   * Get system prompt for procedural contradiction detection
   */
  private getSystemPrompt(): string {
    return `You are an expert procedural contradiction detector specializing in identifying inconsistencies in processes, workflows, and procedures.

PROCEDURAL CONTRADICTION TYPES:
1. "process_step" - Contradictory steps or actions in a process
2. "workflow" - Inconsistent workflows or process flows
3. "decision_procedure" - Conflicting decision-making procedures
4. "task_dependency" - Incompatible task dependencies or prerequisites
5. "policy_conflict" - Contradictory policies or rules
6. "authorization_conflict" - Conflicting approval or authorization requirements
7. "resource_conflict" - Incompatible resource requirements or constraints
8. "sequence_contradiction" - Impossible or conflicting step sequences

ANALYSIS APPROACH:
1. Extract all procedural elements (steps, decisions, workflows)
2. Analyze step sequences and dependencies
3. Check for policy and rule conflicts
4. Verify workflow consistency
5. Identify authorization conflicts
6. Check resource requirement compatibility
7. Analyze decision procedure contradictions

RESPONSE FORMAT:
{
  "has_contradiction": boolean,
  "confidence": number (0-1),
  "contradiction_type": "process_step" | "workflow" | "decision_procedure" | "task_dependency" | "policy_conflict" | "authorization_conflict" | "resource_conflict" | "sequence_contradiction",
  "description": string,
  "reasoning": string,
  "evidence": [
    {
      "type": "procedural_conflict" | "step_contradiction" | "workflow_inconsistency" | "policy_conflict",
      "content": string,
      "confidence": number,
      "source_item": 1 or 2,
      "procedural_element": object
    }
  ],
  "procedural_analysis": {
    "item1_structure": {...},
    "item2_structure": {...},
    "conflicts": [{"conflict_type": string, "severity": number, "explanation": string, "affected_elements": string[]}]
  }
}

IMPORTANT:
- Only report contradictions with confidence >= 0.6
- Focus on procedural logic and workflow consistency
- Consider both formal procedures and informal processes
- Identify specific procedural elements that conflict
- Provide clear evidence for each contradiction`;
  }

  /**
   * Build analysis prompt for procedural contradiction
   */
  private buildProceduralAnalysisPrompt(
    item1: KnowledgeItem,
    item2: KnowledgeItem,
    structure1: ProcessStructure,
    structure2: ProcessStructure
  ): string {
    const content1 = this.extractContent(item1);
    const content2 = this.extractContent(item2);

    return `Analyze these two knowledge items for procedural contradictions:

ITEM 1 (${item1.kind}):
Content: ${content1}
Procedural Structure: ${JSON.stringify(structure1, null, 2)}

ITEM 2 (${item2.kind}):
Content: ${content2}
Procedural Structure: ${JSON.stringify(structure2, null, 2)}

ANALYSIS FOCUS:
1. Step sequence contradictions and workflow conflicts
2. Decision procedure inconsistencies
3. Task dependency conflicts
4. Policy and rule contradictions
5. Authorization and approval conflicts
6. Resource requirement incompatibilities
7. Procedural logic violations

CONSIDER:
- Step order and sequence requirements
- Dependencies between tasks and processes
- Decision logic and branching conditions
- Policy scope and applicability
- Authorization and approval chains
- Resource allocation and constraints
- Workflow start and end conditions
- Exception handling and error procedures

Provide detailed procedural analysis focusing on workflow consistency and procedural logic contradictions.`;
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
    analysis: ProceduralAnalysisResult
  ): ContradictionResult {
    const severity = this.calculateSeverity(analysis.confidence, analysis.contradiction_type);

    return {
      id: randomUUID(),
      detected_at: new Date(),
      contradiction_type: 'procedural',
      confidence_score: analysis.confidence,
      severity,
      primary_item_id: item1.id || randomUUID(),
      conflicting_item_ids: [item2.id || randomUUID()],
      description: analysis.description,
      reasoning: analysis.reasoning,
      metadata: {
        detection_method: 'zai_procedural_analysis',
        algorithm_version: '3.0.0',
        processing_time_ms: 0,
        comparison_details: {
          contradiction_subtype: analysis.contradiction_type,
          procedural_analysis: analysis.procedural_analysis,
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
    analysis: ProceduralAnalysisResult
  ): ContradictionResult {
    const severity = 'high';

    return {
      id: randomUUID(),
      detected_at: new Date(),
      contradiction_type: 'procedural',
      confidence_score: analysis.confidence,
      severity,
      primary_item_id: item1.id || randomUUID(),
      conflicting_item_ids: [item2.id || randomUUID()],
      description: analysis.description,
      reasoning: analysis.reasoning,
      metadata: {
        detection_method: 'quick_procedural_check',
        algorithm_version: '3.0.0',
        processing_time_ms: 0,
        comparison_details: {
          contradiction_subtype: analysis.contradiction_type,
          quick_check: true,
          procedural_analysis: analysis.procedural_analysis,
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
    type: ProceduralContradictionType
  ): 'low' | 'medium' | 'high' | 'critical' {
    // Base severity on confidence
    if (confidence >= 0.9) return 'critical';
    if (confidence >= 0.8) return 'high';
    if (confidence >= 0.6) return 'medium';

    // Adjust based on contradiction type
    const criticalTypes = ['policy_conflict', 'authorization_conflict'];
    const highTypes = ['process_step', 'workflow', 'sequence_contradiction'];

    if (criticalTypes.includes(type) && confidence >= 0.7) return 'critical';
    if (highTypes.includes(type) && confidence >= 0.6) return 'high';

    return 'low';
  }

  /**
   * Generate resolution suggestions based on contradiction type
   */
  private generateResolutionSuggestions(
    type: ProceduralContradictionType,
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
      case 'process_step':
        suggestions.push({
          suggestion: 'Reconcile conflicting process steps and establish clear sequence',
          priority: 'high',
          effort: 'medium',
          description: 'Review and standardize process steps to eliminate conflicts',
        });
        break;

      case 'workflow':
        suggestions.push({
          suggestion: 'Harmonize workflows and ensure process compatibility',
          priority: 'high',
          effort: 'high',
          description: 'Align workflow steps and dependencies across conflicting processes',
        });
        break;

      case 'decision_procedure':
        suggestions.push({
          suggestion: 'Standardize decision procedures and criteria',
          priority: 'medium',
          effort: 'medium',
          description: 'Ensure consistent decision-making logic and procedures',
        });
        break;

      case 'task_dependency':
        suggestions.push({
          suggestion: 'Resolve task dependency conflicts and establish clear prerequisites',
          priority: 'high',
          effort: 'medium',
          description:
            'Clarify task relationships and eliminate circular or conflicting dependencies',
        });
        break;

      case 'policy_conflict':
        suggestions.push({
          suggestion: 'Reconcile policy conflicts and establish clear precedence',
          priority: 'high',
          effort: 'high',
          description:
            'Resolve contradictory policies and establish clear hierarchy or scope separation',
        });
        break;

      case 'authorization_conflict':
        suggestions.push({
          suggestion: 'Standardize authorization and approval procedures',
          priority: 'high',
          effort: 'high',
          description: 'Ensure consistent authorization requirements and approval chains',
        });
        break;

      case 'resource_conflict':
        suggestions.push({
          suggestion: 'Resolve resource conflicts and establish allocation priorities',
          priority: 'medium',
          effort: 'medium',
          description: 'Harmonize resource requirements and establish clear allocation rules',
        });
        break;

      case 'sequence_contradiction':
        suggestions.push({
          suggestion: 'Fix step sequence contradictions and establish logical order',
          priority: 'high',
          effort: 'low',
          description: 'Correct step ordering and ensure logical process flow',
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
    config: ProceduralContradictionConfig;
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
  ): { result: ProceduralAnalysisResult; timestamp: number } | null {
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
  private setToCache(key: string, result: ProceduralAnalysisResult): void {
    this.cache.set(key, {
      result,
      timestamp: Date.now(),
    });
  }
}

/**
 * Export singleton instance
 */
export const proceduralContradictionStrategy = new ProceduralContradictionStrategy();

