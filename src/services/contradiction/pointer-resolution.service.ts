/**
 * Pointer and Resolution Service
 * Manages contradiction pointers and provides resolution workflows
 */

import {
  ContradictionPointer,
  ContradictionResult,
  ContradictionFlag,
  KnowledgeItem,
} from '../../types/contradiction-detector.interface';
import { generateId } from '../../utils/id-generator';

export interface ResolutionAction {
  id: string;
  type: 'merge' | 'delete' | 'update' | 'ignore' | 'flag_as_resolved';
  description: string;
  item_ids: string[];
  parameters?: Record<string, any>;
  confidence: number;
  effort: 'low' | 'medium' | 'high';
  risk_level: 'low' | 'medium' | 'high';
}

export interface ResolutionWorkflow {
  id: string;
  contradiction_id: string;
  primary_item_id: string;
  conflicting_item_ids: string[];
  created_at: Date;
  status: 'pending' | 'in_progress' | 'completed' | 'cancelled';
  assigned_to?: string;
  actions: ResolutionAction[];
  current_step: number;
  total_steps: number;
  notes: string[];
  deadline?: Date;
  metadata: Record<string, any>;
}

export interface ContradictionCluster {
  id: string;
  center_item_id: string;
  member_item_ids: string[];
  contradiction_count: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  cluster_type: 'star' | 'chain' | 'cycle' | 'complex';
  confidence_score: number;
  suggested_resolution: string;
  created_at: Date;
}

export class PointerResolutionService {
  private workflows: Map<string, ResolutionWorkflow> = new Map();
  private clusters: Map<string, ContradictionCluster> = new Map();
  private resolutionHistory: Array<{
    contradiction_id: string;
    action: string;
    item_id: string;
    timestamp: Date;
    user_id?: string;
    result: 'success' | 'failed' | 'partial';
  }> = [];

  /**
   * Creates a resolution workflow for a contradiction
   */
  async createResolutionWorkflow(
    contradiction: ContradictionResult,
    items: KnowledgeItem[],
    userId?: string
  ): Promise<ResolutionWorkflow> {
    const workflowId = generateId();

    const suggestedActions = this.generateResolutionActions(contradiction, items);
    const workflow: ResolutionWorkflow = {
      id: workflowId,
      contradiction_id: contradiction.id,
      primary_item_id: contradiction.primary_item_id,
      conflicting_item_ids: contradiction.conflicting_item_ids,
      created_at: new Date(),
      status: 'pending',
      assigned_to: userId,
      actions: suggestedActions,
      current_step: 0,
      total_steps: suggestedActions.length,
      notes: [],
      deadline: this.calculateDeadline(contradiction.severity),
      metadata: {
        contradiction_type: contradiction.contradiction_type,
        severity: contradiction.severity,
        confidence_score: contradiction.confidence_score,
        created_by: 'automatic',
      },
    };

    this.workflows.set(workflowId, workflow);
    return workflow;
  }

  /**
   * Generates suggested resolution actions for a contradiction
   */
  private generateResolutionActions(
    contradiction: ContradictionResult,
    items: KnowledgeItem[]
  ): ResolutionAction[] {
    const actions: ResolutionAction[] = [];

    // Primary item (highest confidence or most recent)
    const primaryItem = items.find((item) => item.id === contradiction.primary_item_id);
    const conflictingItems = items.filter((item) =>
      contradiction.conflicting_item_ids.includes(item.id || '')
    );

    switch (contradiction.contradiction_type) {
      case 'factual':
        actions.push(
          ...this.generateFactualResolutionActions(contradiction, primaryItem, conflictingItems)
        );
        break;

      case 'temporal':
        actions.push(
          ...this.generateTemporalResolutionActions(contradiction, primaryItem, conflictingItems)
        );
        break;

      case 'logical':
        actions.push(
          ...this.generateLogicalResolutionActions(contradiction, primaryItem, conflictingItems)
        );
        break;

      case 'attribute':
        actions.push(
          ...this.generateAttributeResolutionActions(contradiction, primaryItem, conflictingItems)
        );
        break;
    }

    // Always add review and ignore options
    actions.push({
      id: generateId(),
      type: 'ignore',
      description: 'Mark contradiction as false positive',
      item_ids: [contradiction.primary_item_id, ...contradiction.conflicting_item_ids],
      confidence: 0.3,
      effort: 'low',
      risk_level: 'medium',
    });

    actions.push({
      id: generateId(),
      type: 'flag_as_resolved',
      description: 'Manually mark as resolved without changes',
      item_ids: [contradiction.primary_item_id],
      confidence: 0.8,
      effort: 'low',
      risk_level: 'low',
    });

    return actions.sort(
      (a, b) =>
        b.confidence * (1 - this.getEffortWeight(a.effort)) -
        a.confidence * (1 - this.getEffortWeight(b.effort))
    );
  }

  private getEffortWeight(effort: 'low' | 'medium' | 'high'): number {
    switch (effort) {
      case 'low':
        return 0.1;
      case 'medium':
        return 0.3;
      case 'high':
        return 0.5;
      default:
        return 0.3;
    }
  }

  private generateFactualResolutionActions(
    contradiction: ContradictionResult,
    primaryItem: KnowledgeItem | undefined,
    conflictingItems: KnowledgeItem[]
  ): ResolutionAction[] {
    const actions: ResolutionAction[] = [];

    if (contradiction.confidence_score > 0.8) {
      actions.push({
        id: generateId(),
        type: 'delete',
        description: 'Remove contradictory items (high confidence contradiction)',
        item_ids: contradiction.conflicting_item_ids,
        confidence: contradiction.confidence_score,
        effort: 'low',
        risk_level: 'medium',
      });
    }

    actions.push({
      id: generateId(),
      type: 'update',
      description: 'Add temporal context or qualifiers to resolve factual contradiction',
      item_ids: [contradiction.primary_item_id, ...contradiction.conflicting_item_ids],
      parameters: {
        add_temporal_context: true,
        add_certainty_qualifiers: true,
        preserve_both_with_context: true,
      },
      confidence: 0.7,
      effort: 'medium',
      risk_level: 'low',
    });

    if (primaryItem && conflictingItems.length > 0) {
      actions.push({
        id: generateId(),
        type: 'merge',
        description: 'Merge factual statements with conflict resolution',
        item_ids: [contradiction.primary_item_id, ...contradiction.conflicting_item_ids],
        parameters: {
          merge_strategy: 'conflict_resolution',
          preserve_primary_confidence: true,
          add_resolution_note: true,
        },
        confidence: 0.6,
        effort: 'high',
        risk_level: 'medium',
      });
    }

    return actions;
  }

  private generateTemporalResolutionActions(
    contradiction: ContradictionResult,
    primaryItem: KnowledgeItem | undefined,
    conflictingItems: KnowledgeItem[]
  ): ResolutionAction[] {
    const actions: ResolutionAction[] = [];

    actions.push({
      id: generateId(),
      type: 'update',
      description: 'Correct temporal data to resolve timeline conflicts',
      item_ids: [contradiction.primary_item_id, ...contradiction.conflicting_item_ids],
      parameters: {
        temporal_correction: true,
        sequence_validation: true,
        timezone_normalization: true,
      },
      confidence: 0.8,
      effort: 'medium',
      risk_level: 'low',
    });

    actions.push({
      id: generateId(),
      type: 'merge',
      description: 'Create sequential timeline from conflicting temporal statements',
      item_ids: [contradiction.primary_item_id, ...contradiction.conflicting_item_ids],
      parameters: {
        timeline_reconstruction: true,
        preserve_temporal_relationships: true,
        add_timeline_metadata: true,
      },
      confidence: 0.7,
      effort: 'high',
      risk_level: 'medium',
    });

    return actions;
  }

  private generateLogicalResolutionActions(
    contradiction: ContradictionResult,
    primaryItem: KnowledgeItem | undefined,
    conflictingItems: KnowledgeItem[]
  ): ResolutionAction[] {
    const actions: ResolutionAction[] = [];

    actions.push({
      id: generateId(),
      type: 'update',
      description: 'Add logical qualifiers to resolve mutual exclusions',
      item_ids: [contradiction.primary_item_id, ...contradiction.conflicting_item_ids],
      parameters: {
        logical_qualifiers: true,
        condition_clarification: true,
        context_addition: true,
      },
      confidence: 0.7,
      effort: 'medium',
      risk_level: 'low',
    });

    if (contradiction.confidence_score > 0.9) {
      actions.push({
        id: generateId(),
        type: 'delete',
        description: 'Remove logically impossible statements',
        item_ids: contradiction.conflicting_item_ids,
        confidence: contradiction.confidence_score,
        effort: 'low',
        risk_level: 'high',
      });
    }

    return actions;
  }

  private generateAttributeResolutionActions(
    contradiction: ContradictionResult,
    primaryItem: KnowledgeItem | undefined,
    conflictingItems: KnowledgeItem[]
  ): ResolutionAction[] {
    const actions: ResolutionAction[] = [];

    actions.push({
      id: generateId(),
      type: 'update',
      description: 'Standardize conflicting attribute values',
      item_ids: [contradiction.primary_item_id, ...contradiction.conflicting_item_ids],
      parameters: {
        attribute_standardization: true,
        type_conversion: true,
        value_normalization: true,
      },
      confidence: 0.8,
      effort: 'medium',
      risk_level: 'low',
    });

    actions.push({
      id: generateId(),
      type: 'merge',
      description: 'Create unified attribute definition with versioning',
      item_ids: [contradiction.primary_item_id, ...contradiction.conflicting_item_ids],
      parameters: {
        versioned_attributes: true,
        change_tracking: true,
        attribute_history: true,
      },
      confidence: 0.6,
      effort: 'high',
      risk_level: 'medium',
    });

    return actions;
  }

  /**
   * Executes a resolution action
   */
  async executeResolutionAction(
    workflowId: string,
    actionId: string,
    userId?: string,
    customParameters?: Record<string, any>
  ): Promise<{
    success: boolean;
    message: string;
    affected_items: string[];
    next_action?: ResolutionAction;
  }> {
    const workflow = this.workflows.get(workflowId);
    if (!workflow) {
      return {
        success: false,
        message: 'Workflow not found',
        affected_items: [],
      };
    }

    const action = workflow.actions.find((a) => a.id === actionId);
    if (!action) {
      return {
        success: false,
        message: 'Action not found',
        affected_items: [],
      };
    }

    try {
      const parameters = { ...action.parameters, ...customParameters };
      const result = await this.performAction(action, parameters);

      // Record in resolution history
      this.resolutionHistory.push({
        contradiction_id: workflow.contradiction_id,
        action: action.type,
        item_id: action.item_ids[0], // Primary item
        timestamp: new Date(),
        user_id: userId,
        result: result.success ? 'success' : 'failed',
      });

      // Update workflow status
      workflow.current_step++;
      if (workflow.current_step >= workflow.total_steps) {
        workflow.status = 'completed';
      } else {
        workflow.status = 'in_progress';
      }

      const nextAction =
        workflow.current_step < workflow.total_steps
          ? workflow.actions[workflow.current_step]
          : undefined;

      return {
        success: result.success,
        message: result.message,
        affected_items: action.item_ids,
        next_action: nextAction,
      };
    } catch (error) {
      return {
        success: false,
        message: `Error executing action: ${error}`,
        affected_items: [],
      };
    }
  }

  private async performAction(
    action: ResolutionAction,
    parameters: Record<string, any>
  ): Promise<{ success: boolean; message: string }> {
    switch (action.type) {
      case 'delete':
        return this.performDeleteAction(action, parameters);
      case 'update':
        return this.performUpdateAction(action, parameters);
      case 'merge':
        return this.performMergeAction(action, parameters);
      case 'ignore':
        return this.performIgnoreAction(action, parameters);
      case 'flag_as_resolved':
        return this.performFlagResolvedAction(action, parameters);
      default:
        return {
          success: false,
          message: `Unknown action type: ${action.type}`,
        };
    }
  }

  private async performDeleteAction(
    action: ResolutionAction,
    parameters: Record<string, any>
  ): Promise<{ success: boolean; message: string }> {
    // In a real implementation, this would call the storage service
    return {
      success: true,
      message: `Deleted ${action.item_ids.length} items as part of contradiction resolution`,
    };
  }

  private async performUpdateAction(
    action: ResolutionAction,
    parameters: Record<string, any>
  ): Promise<{ success: boolean; message: string }> {
    // In a real implementation, this would call the storage service
    const updateTypes = [];
    if (parameters.temporal_correction) updateTypes.push('temporal');
    if (parameters.attribute_standardization) updateTypes.push('attribute');
    if (parameters.logical_qualifiers) updateTypes.push('logical');

    return {
      success: true,
      message: `Updated ${action.item_ids.length} items with ${updateTypes.join(', ')} corrections`,
    };
  }

  private async performMergeAction(
    action: ResolutionAction,
    parameters: Record<string, any>
  ): Promise<{ success: boolean; message: string }> {
    // In a real implementation, this would call the storage service
    return {
      success: true,
      message: `Merged ${action.item_ids.length} items into unified representation`,
    };
  }

  private async performIgnoreAction(
    action: ResolutionAction,
    parameters: Record<string, any>
  ): Promise<{ success: boolean; message: string }> {
    return {
      success: true,
      message: `Marked contradiction as false positive for ${action.item_ids.length} items`,
    };
  }

  private async performFlagResolvedAction(
    action: ResolutionAction,
    parameters: Record<string, any>
  ): Promise<{ success: boolean; message: string }> {
    return {
      success: true,
      message: `Manually marked contradiction as resolved for ${action.item_ids.length} items`,
    };
  }

  /**
   * Identifies and creates contradiction clusters
   */
  async identifyContradictionClusters(
    contradictions: ContradictionResult[],
    pointers: ContradictionPointer[]
  ): Promise<ContradictionCluster[]> {
    const clusters: ContradictionCluster[] = [];
    const visited = new Set<string>();

    for (const contradiction of contradictions) {
      const allItemIds = [contradiction.primary_item_id, ...contradiction.conflicting_item_ids];

      if (allItemIds.some((id) => visited.has(id))) {
        continue; // Already part of a cluster
      }

      const cluster = this.createContradictionCluster(contradiction, pointers);
      if (cluster.member_item_ids.length > 1) {
        clusters.push(cluster);
        cluster.member_item_ids.forEach((id) => visited.add(id));
        this.clusters.set(cluster.id, cluster);
      }
    }

    return clusters;
  }

  private createContradictionCluster(
    contradiction: ContradictionResult,
    pointers: ContradictionPointer[]
  ): ContradictionCluster {
    const allItemIds = new Set([
      contradiction.primary_item_id,
      ...contradiction.conflicting_item_ids,
    ]);
    const relatedPointers = pointers.filter(
      (p) => allItemIds.has(p.source_id) && allItemIds.has(p.target_id)
    );

    // Determine cluster type
    let clusterType: 'star' | 'chain' | 'cycle' | 'complex' = 'star';
    if (relatedPointers.length === 2) {
      clusterType = 'chain';
    } else if (this.detectCycle(relatedPointers)) {
      clusterType = 'cycle';
    } else if (relatedPointers.length > 3) {
      clusterType = 'complex';
    }

    const severity = this.calculateClusterSeverity(contradiction, relatedPointers);
    const avgConfidence =
      relatedPointers.reduce((sum, p) => sum + p.strength, 0) / Math.max(1, relatedPointers.length);

    return {
      id: generateId(),
      center_item_id: contradiction.primary_item_id,
      member_item_ids: Array.from(allItemIds),
      contradiction_count: 1, // Simplified for MVP
      severity,
      cluster_type: clusterType,
      confidence_score: avgConfidence,
      suggested_resolution: this.generateClusterSuggestion(clusterType, severity),
      created_at: new Date(),
    };
  }

  private detectCycle(pointers: ContradictionPointer[]): boolean {
    // Simple cycle detection - in a real implementation would be more sophisticated
    return (
      pointers.length >= 3 &&
      pointers.every((p) => pointers.some((other) => other.source_id === p.target_id))
    );
  }

  private calculateClusterSeverity(
    contradiction: ContradictionResult,
    pointers: ContradictionPointer[]
  ): 'low' | 'medium' | 'high' | 'critical' {
    const maxPointerStrength = Math.max(
      ...pointers.map((p) => p.strength),
      contradiction.confidence_score
    );

    if (maxPointerStrength >= 0.9) return 'critical';
    if (maxPointerStrength >= 0.75) return 'high';
    if (maxPointerStrength >= 0.6) return 'medium';
    return 'low';
  }

  private generateClusterSuggestion(clusterType: string, severity: string): string {
    if (severity === 'critical' || severity === 'high') {
      return 'Immediate manual review and resolution required';
    } else if (clusterType === 'cycle') {
      return 'Review circular dependencies and establish hierarchy';
    } else if (clusterType === 'complex') {
      return 'Break down into smaller contradictions for systematic resolution';
    } else {
      return 'Standard contradiction resolution workflow applies';
    }
  }

  private calculateDeadline(severity: string): Date {
    const now = new Date();
    switch (severity) {
      case 'critical':
        return new Date(now.getTime() + 24 * 60 * 60 * 1000); // 1 day
      case 'high':
        return new Date(now.getTime() + 3 * 24 * 60 * 60 * 1000); // 3 days
      case 'medium':
        return new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000); // 1 week
      case 'low':
        return new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000); // 1 month
      default:
        return new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
    }
  }

  /**
   * Gets resolution workflow by ID
   */
  getWorkflow(workflowId: string): ResolutionWorkflow | undefined {
    return this.workflows.get(workflowId);
  }

  /**
   * Gets all active workflows
   */
  getActiveWorkflows(): ResolutionWorkflow[] {
    return Array.from(this.workflows.values()).filter(
      (w) => w.status === 'pending' || w.status === 'in_progress'
    );
  }

  /**
   * Gets contradiction cluster by ID
   */
  getCluster(clusterId: string): ContradictionCluster | undefined {
    return this.clusters.get(clusterId);
  }

  /**
   * Gets all contradiction clusters
   */
  getAllClusters(): ContradictionCluster[] {
    return Array.from(this.clusters.values());
  }

  /**
   * Gets resolution statistics
   */
  getResolutionStatistics(): {
    total_workflows: number;
    completed_workflows: number;
    pending_workflows: number;
    average_resolution_time_hours: number;
    success_rate: number;
    most_common_action: string;
    clusters_by_severity: Record<string, number>;
  } {
    const workflows = Array.from(this.workflows.values());
    const completedWorkflows = workflows.filter((w) => w.status === 'completed');
    const pendingWorkflows = workflows.filter((w) => w.status === 'pending');

    const averageResolutionTime =
      completedWorkflows.length > 0
        ? completedWorkflows.reduce((sum, w) => {
            const duration = w.created_at.getTime() - new Date().getTime();
            return sum + Math.abs(duration / (1000 * 60 * 60)); // Convert to hours
          }, 0) / completedWorkflows.length
        : 0;

    const actionCounts = this.resolutionHistory.reduce(
      (counts, record) => {
        counts[record.action] = (counts[record.action] || 0) + 1;
        return counts;
      },
      {} as Record<string, number>
    );

    const mostCommonAction =
      Object.entries(actionCounts).sort(([, a], [, b]) => b - a)[0]?.[0] || 'none';

    const clustersBySeverity = Array.from(this.clusters.values()).reduce(
      (counts, cluster) => {
        counts[cluster.severity] = (counts[cluster.severity] || 0) + 1;
        return counts;
      },
      {} as Record<string, number>
    );

    const successfulResolutions = this.resolutionHistory.filter(
      (r) => r.result === 'success'
    ).length;
    const successRate =
      this.resolutionHistory.length > 0 ? successfulResolutions / this.resolutionHistory.length : 0;

    return {
      total_workflows: workflows.length,
      completed_workflows: completedWorkflows.length,
      pending_workflows: pendingWorkflows.length,
      average_resolution_time_hours: averageResolutionTime,
      success_rate: successRate,
      most_common_action: mostCommonAction,
      clusters_by_severity: clustersBySeverity,
    };
  }
}
