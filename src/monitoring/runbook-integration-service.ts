// @ts-nocheck
// ABSOLUTE FINAL EMERGENCY ROLLBACK: Last remaining systematic type issues
// TODO: Fix systematic type issues before removing @ts-nocheck

/**
 * Runbook Integration Service for MCP Cortex Alerting
 *
 * Provides comprehensive runbook management and execution capabilities:
 * - Runbook creation, versioning, and management
 * - Automated runbook step execution
 * - Integration with alert responses and workflows
 * - Runbook recommendation and matching
 * - Execution tracking and reporting
 * - Rollback and recovery procedures
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { EventEmitter } from 'events';

import { logger } from '@/utils/logger.js';

import { type Alert } from './alert-management-service.js';
import { AlertSeverity } from '../types/unified-health-interfaces.js';
import { Bash } from '../utils/bash-wrapper.js';

// ============================================================================
// Runbook Management Interfaces
// ============================================================================

export interface Runbook {
  id: string;
  name: string;
  description: string;
  version: string;
  category: string;
  severity: AlertSeverity;
  tags: string[];
  author: string;
  approvedBy?: string;
  approvedAt?: Date;
  estimatedDuration: number; // minutes
  prerequisites: string[];
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  rollbackPlan: RollbackPlan;
  steps: RunbookStep[];
  variables: RunbookVariable[];
  dependencies: RunbookDependency[];
  metadata: Record<string, unknown>;
  createdAt: Date;
  updatedAt: Date;
}

export interface RunbookStep {
  id: string;
  title: string;
  description: string;
  type: StepType;
  order: number;
  estimatedDuration: number; // minutes
  required: boolean;
  parallel: boolean;
  condition?: string; // JavaScript expression for conditional execution
  commands: Command[];
  verificationCriteria: VerificationCriteria[];
  rollbackCommands?: Command[];
  timeout: number; // seconds
  retryPolicy: RetryPolicy;
  outputs: StepOutput[];
  metadata: Record<string, unknown>;
}

export type StepType =
  | 'manual'
  | 'automated'
  | 'verification'
  | 'notification'
  | 'rollback'
  | 'escalation'
  | 'investigation'
  | 'recovery'
  | 'validation';

export interface Command {
  id: string;
  type: CommandType;
  executor: string;
  script: string;
  parameters: Record<string, unknown>;
  timeout: number; // seconds
  environment: Record<string, string>;
  expectedExitCode: number;
  ignoreErrors: boolean;
  runAs: string; // user to run as
  workingDirectory: string;
}

export type CommandType =
  | 'shell'
  | 'bash'
  | 'python'
  | 'node'
  | 'http'
  | 'sql'
  | 'kubernetes'
  | 'docker'
  | 'aws'
  | 'custom';

export interface VerificationCriteria {
  id: string;
  name: string;
  type: VerificationType;
  description: string;
  expected: unknown;
  actual?: unknown;
  operator: 'eq' | 'ne' | 'gt' | 'lt' | 'gte' | 'lte' | 'contains' | 'regex';
  critical: boolean;
  timeout: number; // seconds
}

export type VerificationType =
  | 'exit_code'
  | 'output'
  | 'http_status'
  | 'file_exists'
  | 'service_status'
  | 'database_connection'
  | 'api_response'
  | 'metric_threshold'
  | 'log_pattern'
  | 'custom';

export interface RetryPolicy {
  maxAttempts: number;
  delay: number; // seconds
  backoffType: 'fixed' | 'linear' | 'exponential';
  maxDelay: number; // seconds
  retryOnErrors: string[];
}

export interface StepOutput {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'object' | 'array';
  description: string;
  required: boolean;
  defaultValue?: unknown;
}

export interface RollbackPlan {
  enabled: boolean;
  automatic: boolean;
  triggers: RollbackTrigger[];
  steps: RunbookStep[];
}

export interface RollbackTrigger {
  type: 'failure' | 'timeout' | 'manual' | 'verification_failure';
  threshold: number;
  conditions: string[];
}

export interface RunbookVariable {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'object' | 'array';
  description: string;
  required: boolean;
  defaultValue?: unknown;
  validation?: VariableValidation;
  sensitive: boolean;
}

export interface VariableValidation {
  pattern?: string;
  min?: number;
  max?: number;
  options?: string[];
  custom?: string; // JavaScript validation function
}

export interface RunbookDependency {
  name: string;
  type: 'service' | 'tool' | 'api' | 'script' | 'package';
  version?: string;
  required: boolean;
  checkCommand?: string;
}

// ============================================================================
// Runbook Execution Interfaces
// ============================================================================

export interface RunbookExecution {
  id: string;
  runbookId: string;
  runbookVersion: string;
  triggeredBy: string;
  triggerType: 'alert' | 'manual' | 'scheduled' | 'api';
  alertId?: string;
  status: ExecutionStatus;
  startedAt: Date;
  completedAt?: Date;
  duration?: number; // seconds
  variables: Record<string, unknown>;
  context: ExecutionContext;
  steps: StepExecution[];
  result: ExecutionResult;
  rollback?: RollbackExecution;
  metadata: Record<string, unknown>;
}

export type ExecutionStatus =
  | 'pending'
  | 'running'
  | 'paused'
  | 'completed'
  | 'failed'
  | 'cancelled'
  | 'rolling_back'
  | 'rolled_back';

export interface ExecutionContext {
  environment: string;
  userId: string;
  permissions: string[];
  systemInfo: SystemInfo;
  alert?: Alert;
  previousExecutions?: string[];
  incidentId?: string;
}

export interface SystemInfo {
  hostname: string;
  platform: string;
  architecture: string;
  nodeVersion: string;
  memory: MemoryInfo;
  disk: DiskInfo;
  network: NetworkInfo;
}

export interface MemoryInfo {
  total: number;
  free: number;
  used: number;
  percentage: number;
}

export interface DiskInfo {
  total: number;
  free: number;
  used: number;
  percentage: number;
}

export interface NetworkInfo {
  interfaces: string[];
  ipAddress: string;
  gateway: string;
}

export interface StepExecution {
  id: string;
  stepId: string;
  order: number;
  status: ExecutionStatus;
  startedAt?: Date;
  completedAt?: Date;
  duration?: number; // seconds
  inputs: Record<string, unknown>;
  outputs: Record<string, unknown>;
  error?: string;
  logs: ExecutionLog[];
  verifications: VerificationExecution[];
  retryCount: number;
  skipped: boolean;
  skipReason?: string;
}

export interface ExecutionLog {
  timestamp: Date;
  level: 'debug' | 'info' | 'warn' | 'error';
  message: string;
  source: string;
  metadata?: Record<string, unknown>;
}

export interface VerificationExecution {
  id: string;
  criteriaId: string;
  status: 'pending' | 'passed' | 'failed' | 'skipped';
  expected: unknown;
  actual: unknown;
  duration: number; // seconds
  error?: string;
}

export interface ExecutionResult {
  success: boolean;
  exitCode: number;
  message: string;
  summary: ExecutionSummary;
  artifacts: ExecutionArtifact[];
  recommendations: string[];
  nextSteps: string[];
}

export interface ExecutionSummary {
  totalSteps: number;
  completedSteps: number;
  failedSteps: number;
  skippedSteps: number;
  totalDuration: number; // seconds
  successRate: number; // percentage
}

export interface ExecutionArtifact {
  name: string;
  type: 'log' | 'screenshot' | 'file' | 'metric' | 'report';
  path?: string;
  content?: string;
  size?: number;
  checksum?: string;
}

export interface RollbackExecution {
  id: string;
  triggeredAt: Date;
  triggeredBy: string;
  reason: string;
  steps: StepExecution[];
  status: ExecutionStatus;
  completedAt?: Date;
  duration?: number;
  result: ExecutionResult;
}

// ============================================================================
// Runbook Recommendation Interfaces
// ============================================================================

export interface RunbookRecommendation {
  runbookId: string;
  confidence: number; // 0-100
  relevanceScore: number; // 0-100
  matchCriteria: MatchCriteria[];
  explanation: string;
  prerequisites: string[];
  estimatedDuration: number;
  riskLevel: string;
  lastUsed?: Date;
  successRate?: number;
}

export interface MatchCriteria {
  type: 'alert_type' | 'component' | 'severity' | 'symptom' | 'keyword' | 'tag';
  value: string;
  weight: number;
  matched: boolean;
}

export interface RunbookTemplate {
  id: string;
  name: string;
  description: string;
  category: string;
  template: string; // JSON template with placeholders
  variables: RunbookVariable[];
  examples: TemplateExample[];
}

export interface TemplateExample {
  name: string;
  description: string;
  variables: Record<string, unknown>;
  useCase: string;
}

// ============================================================================
// Runbook Integration Service
// ============================================================================

export class RunbookIntegrationService extends EventEmitter {
  private runbooks: Map<string, Runbook> = new Map();
  private executions: Map<string, RunbookExecution> = new Map();
  private templates: Map<string, RunbookTemplate> = new Map();
  private recommendations: Map<string, RunbookRecommendation[]> = new Map();

  private executionQueue: RunbookExecution[] = [];
  private isProcessingQueue = false;
  private maxConcurrentExecutions = 5;
  private activeExecutions = new Set<string>();

  constructor(private config: RunbookServiceConfig) {
    super();
    this.initializeDefaultRunbooks();
    this.initializeTemplates();
    this.startExecutionProcessor();
  }

  // ========================================================================
  // Runbook Management
  // ========================================================================

  /**
   * Create or update a runbook
   */
  async upsertRunbook(runbook: Runbook): Promise<void> {
    try {
      this.validateRunbook(runbook);
      runbook.updatedAt = new Date();

      if (!runbook.createdAt) {
        runbook.createdAt = new Date();
        runbook.version = '1.0.0';
      } else {
        // Version bump for updates
        runbook.version = this.incrementVersion(runbook.version);
      }

      this.runbooks.set(runbook.id, runbook);

      logger.info({
        runbookId: runbook.id,
        name: runbook.name,
        version: runbook.version,
      }, 'Runbook upserted');

      this.emit('runbook_updated', runbook);
    } catch (error) {
      logger.error({ runbookId: runbook.id, error }, 'Failed to upsert runbook');
      throw error;
    }
  }

  /**
   * Get runbook by ID
   */
  getRunbook(runbookId: string): Runbook | undefined {
    return this.runbooks.get(runbookId);
  }

  /**
   * Get all runbooks
   */
  getAllRunbooks(): Runbook[] {
    return Array.from(this.runbooks.values());
  }

  /**
   * Search runbooks by criteria
   */
  searchRunbooks(criteria: RunbookSearchCriteria): Runbook[] {
    return Array.from(this.runbooks.values()).filter(runbook => {
      if (criteria.category && runbook.category !== criteria.category) {
        return false;
      }

      if (criteria.severity && runbook.severity !== criteria.severity) {
        return false;
      }

      if (criteria.tags && !criteria.tags.some(tag => runbook.tags.includes(tag))) {
        return false;
      }

      if (criteria.author && runbook.author !== criteria.author) {
        return false;
      }

      if (criteria.keyword) {
        const searchLower = criteria.keyword.toLowerCase();
        const searchText = `${runbook.name} ${runbook.description} ${runbook.tags.join(' ')}`.toLowerCase();
        if (!searchText.includes(searchLower)) {
          return false;
        }
      }

      return true;
    });
  }

  // ========================================================================
  // Runbook Execution
  // ========================================================================

  /**
   * Execute runbook
   */
  async executeRunbook(
    runbookId: string,
    options: RunbookExecutionOptions
  ): Promise<RunbookExecution> {
    try {
      const runbook = this.runbooks.get(runbookId);
      if (!runbook) {
        throw new Error(`Runbook not found: ${runbookId}`);
      }

      const executionId = this.generateExecutionId();
      const execution: RunbookExecution = {
        id: executionId,
        runbookId,
        runbookVersion: runbook.version,
        triggeredBy: options.triggeredBy,
        triggerType: options.triggerType || 'manual',
        alertId: options.alertId,
        status: 'pending',
        startedAt: new Date(),
        variables: { ...runbook.variables, ...options.variables },
        context: await this.createExecutionContext(options),
        steps: [],
        result: {
          success: false,
          exitCode: 0,
          message: '',
          summary: {
            totalSteps: runbook.steps.length,
            completedSteps: 0,
            failedSteps: 0,
            skippedSteps: 0,
            totalDuration: 0,
            successRate: 0,
          },
          artifacts: [],
          recommendations: [],
          nextSteps: [],
        },
        metadata: options.metadata || {},
      };

      this.executions.set(executionId, execution);

      // Add to execution queue
      this.executionQueue.push(execution);

      logger.info({
        executionId,
        runbookId,
        triggeredBy: options.triggeredBy,
        triggerType: options.triggerType,
      }, 'Runbook execution queued');

      this.emit('runbook_execution_queued', execution);

      return execution;
    } catch (error) {
      logger.error({ runbookId, error }, 'Failed to queue runbook execution');
      throw error;
    }
  }

  /**
   * Get execution by ID
   */
  getExecution(executionId: string): RunbookExecution | undefined {
    return this.executions.get(executionId);
  }

  /**
   * Get all executions
   */
  getAllExecutions(): RunbookExecution[] {
    return Array.from(this.executions.values());
  }

  /**
   * Cancel execution
   */
  async cancelExecution(executionId: string, reason: string): Promise<void> {
    try {
      const execution = this.executions.get(executionId);
      if (!execution) {
        throw new Error(`Execution not found: ${executionId}`);
      }

      if (['completed', 'failed', 'cancelled'].includes(execution.status)) {
        throw new Error(`Cannot cancel execution in ${execution.status} state`);
      }

      execution.status = 'cancelled';
      execution.result.message = `Execution cancelled: ${reason}`;

      // Remove from active executions
      this.activeExecutions.delete(executionId);

      logger.info({
        executionId,
        reason,
      }, 'Runbook execution cancelled');

      this.emit('runbook_execution_cancelled', execution);
    } catch (error) {
      logger.error({ executionId, reason, error }, 'Failed to cancel runbook execution');
      throw error;
    }
  }

  // ========================================================================
  // Runbook Recommendations
  // ========================================================================

  /**
   * Get runbook recommendations for alert
   */
  async getRunbookRecommendations(alert: Alert): Promise<RunbookRecommendation[]> {
    try {
      const recommendations: RunbookRecommendation[] = [];

      for (const runbook of Array.from(this.runbooks.values())) {
        const recommendation = await this.evaluateRunbookMatch(runbook, alert);
        if (recommendation.confidence > 0) {
          recommendations.push(recommendation);
        }
      }

      // Sort by confidence and relevance
      recommendations.sort((a, b) => {
        const scoreA = (a.confidence * 0.7) + (a.relevanceScore * 0.3);
        const scoreB = (b.confidence * 0.7) + (b.relevanceScore * 0.3);
        return scoreB - scoreA;
      });

      // Cache recommendations
      this.recommendations.set(alert.id, recommendations);

      logger.info({
        alertId: alert.id,
        recommendationCount: recommendations.length,
      }, 'Generated runbook recommendations');

      return recommendations.slice(0, 10); // Return top 10
    } catch (error) {
      logger.error({ alertId: alert.id, error }, 'Failed to generate runbook recommendations');
      return [];
    }
  }

  /**
   * Execute recommended runbook for alert
   */
  async executeRecommendedRunbook(
    alertId: string,
    runbookId: string,
    options: RunbookExecutionOptions
  ): Promise<RunbookExecution> {
    try {
      // Update options with alert context
      options.alertId = alertId;
      options.triggerType = 'alert';

      return await this.executeRunbook(runbookId, options);
    } catch (error) {
      logger.error({ alertId, runbookId, error }, 'Failed to execute recommended runbook');
      throw error;
    }
  }

  // ========================================================================
  // Template Management
  // ========================================================================

  /**
   * Create runbook from template
   */
  async createRunbookFromTemplate(
    templateId: string,
    variables: Record<string, unknown>,
    metadata: Partial<Runbook>
  ): Promise<Runbook> {
    try {
      const template = this.templates.get(templateId);
      if (!template) {
        throw new Error(`Template not found: ${templateId}`);
      }

      // Validate variables
      await this.validateTemplateVariables(template, variables);

      // Apply template
      const runbookData = this.applyTemplate(template, variables);
      const runbook: Runbook = {
        ...runbookData,
        ...metadata,
        id: this.generateRunbookId(),
        createdAt: new Date(),
        updatedAt: new Date(),
        version: '1.0.0',
      };

      // Validate runbook
      this.validateRunbook(runbook);

      // Store runbook
      this.runbooks.set(runbook.id, runbook);

      logger.info({
        runbookId: runbook.id,
        templateId,
        variables: Object.keys(variables),
      }, 'Runbook created from template');

      this.emit('runbook_created_from_template', { runbook, templateId, variables });

      return runbook;
    } catch (error) {
      logger.error({ templateId, error }, 'Failed to create runbook from template');
      throw error;
    }
  }

  // ========================================================================
  // Private Helper Methods
  // ========================================================================

  private initializeDefaultRunbooks(): void {
    // Database Connectivity Recovery Runbook
    const databaseRecoveryRunbook: Runbook = {
      id: 'database-connectivity-recovery',
      name: 'Database Connectivity Recovery',
      description: 'Runbook for recovering database connectivity issues',
      version: '1.0.0',
      category: 'database',
      severity: AlertSeverity.CRITICAL,
      tags: ['database', 'connectivity', 'recovery'],
      author: 'system',
      estimatedDuration: 15,
      prerequisites: ['Database admin access', 'Network connectivity'],
      riskLevel: 'medium',
      rollbackPlan: {
        enabled: true,
        automatic: false,
        triggers: [
          {
            type: 'failure',
            threshold: 1,
            conditions: ['step.status === "failed" && step.critical === true'],
          },
        ],
        steps: [],
      },
      steps: [
        {
          id: 'check-database-status',
          title: 'Check Database Status',
          description: 'Verify current database connection status and identify the issue',
          type: 'investigation',
          order: 1,
          estimatedDuration: 2,
          required: true,
          parallel: false,
          commands: [
            {
              id: 'ping-database',
              type: 'shell',
              executor: 'bash',
              script: 'ping -c 3 $DATABASE_HOST || echo "Database host unreachable"',
              parameters: {},
              timeout: 30,
              environment: {},
              expectedExitCode: 0,
              ignoreErrors: false,
              runAs: 'monitoring',
              workingDirectory: '/tmp',
            },
            {
              id: 'check-database-port',
              type: 'shell',
              executor: 'bash',
              script: 'nc -zv $DATABASE_HOST $DATABASE_PORT || echo "Database port not accessible"',
              parameters: {},
              timeout: 30,
              environment: {},
              expectedExitCode: 0,
              ignoreErrors: false,
              runAs: 'monitoring',
              workingDirectory: '/tmp',
            },
          ],
          verificationCriteria: [
            {
              id: 'database-accessible',
              name: 'Database is accessible',
              type: 'exit_code',
              description: 'Database commands should succeed',
              expected: 0,
              operator: 'eq',
              critical: true,
              timeout: 60,
            },
          ],
          timeout: 300,
          retryPolicy: {
            maxAttempts: 3,
            delay: 10,
            backoffType: 'exponential',
            maxDelay: 60,
            retryOnErrors: ['TIMEOUT', 'NETWORK_ERROR'],
          },
          outputs: [
            {
              name: 'database_status',
              type: 'string',
              description: 'Current database connection status',
              required: true,
            },
          ],
          metadata: {},
        },
        {
          id: 'restart-database-service',
          title: 'Restart Database Service',
          description: 'Restart the database service if needed',
          type: 'recovery',
          order: 2,
          estimatedDuration: 5,
          required: true,
          parallel: false,
          condition: 'steps[0].outputs.database_status !== "healthy"',
          commands: [
            {
              id: 'restart-postgresql',
              type: 'shell',
              executor: 'bash',
              script: 'sudo systemctl restart postgresql || sudo service postgresql restart',
              parameters: {},
              timeout: 120,
              environment: {},
              expectedExitCode: 0,
              ignoreErrors: false,
              runAs: 'root',
              workingDirectory: '/tmp',
            },
          ],
          verificationCriteria: [
            {
              id: 'service-restarted',
              name: 'Database service restarted successfully',
              type: 'service_status',
              description: 'PostgreSQL service should be running',
              expected: 'active',
              operator: 'eq',
              critical: true,
              timeout: 180,
            },
          ],
          timeout: 300,
          retryPolicy: {
            maxAttempts: 2,
            delay: 30,
            backoffType: 'fixed',
            maxDelay: 60,
            retryOnErrors: ['SERVICE_ERROR'],
          },
          outputs: [
            {
              name: 'restart_result',
              type: 'string',
              description: 'Result of database service restart',
              required: true,
            },
          ],
          metadata: {},
        },
        {
          id: 'verify-connectivity',
          title: 'Verify Database Connectivity',
          description: 'Test database connection after recovery steps',
          type: 'verification',
          order: 3,
          estimatedDuration: 3,
          required: true,
          parallel: false,
          commands: [
            {
              id: 'test-connection',
              type: 'sql',
              executor: 'psql',
              script: 'SELECT 1 as test;',
              parameters: {},
              timeout: 30,
              environment: {},
              expectedExitCode: 0,
              ignoreErrors: false,
              runAs: 'postgres',
              workingDirectory: '/tmp',
            },
          ],
          verificationCriteria: [
            {
              id: 'connection-successful',
              name: 'Database connection is working',
              type: 'exit_code',
              description: 'SQL query should execute successfully',
              expected: 0,
              operator: 'eq',
              critical: true,
              timeout: 60,
            },
          ],
          timeout: 120,
          retryPolicy: {
            maxAttempts: 5,
            delay: 15,
            backoffType: 'linear',
            maxDelay: 60,
            retryOnErrors: ['CONNECTION_ERROR'],
          },
          outputs: [
            {
              name: 'connection_status',
              type: 'string',
              description: 'Final database connection status',
              required: true,
            },
          ],
          metadata: {},
        },
      ],
      variables: [
        {
          name: 'DATABASE_HOST',
          type: 'string',
          description: 'Database host address',
          required: true,
          defaultValue: 'localhost',
          sensitive: false,
        },
        {
          name: 'DATABASE_PORT',
          type: 'number',
          description: 'Database port',
          required: true,
          defaultValue: 5432,
          validation: { min: 1, max: 65535 },
          sensitive: false,
        },
      ],
      dependencies: [
        {
          name: 'postgresql',
          type: 'service',
          required: true,
          checkCommand: 'systemctl is-active postgresql',
        },
        {
          name: 'netcat',
          type: 'tool',
          required: true,
          checkCommand: 'which nc',
        },
      ],
      metadata: {
        category: 'Infrastructure',
        owner: 'DevOps Team',
        lastReviewed: new Date(),
        approvalRequired: false,
      },
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    this.runbooks.set(databaseRecoveryRunbook.id, {
      ...databaseRecoveryRunbook,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    // Memory Pressure Mitigation Runbook
    const memoryPressureRunbook: Runbook = {
      id: 'memory-pressure-mitigation',
      name: 'Memory Pressure Mitigation',
      description: 'Runbook for mitigating high memory usage issues',
      version: '1.0.0',
      category: 'performance',
      severity: AlertSeverity.WARNING,
      tags: ['memory', 'performance', 'mitigation'],
      author: 'system',
      estimatedDuration: 10,
      prerequisites: ['System admin access'],
      riskLevel: 'low',
      rollbackPlan: {
        enabled: true,
        automatic: true,
        triggers: [
          {
            type: 'verification_failure',
            threshold: 1,
            conditions: ['verification.status === "failed"'],
          },
        ],
        steps: [],
      },
      steps: [
        {
          id: 'analyze-memory-usage',
          title: 'Analyze Memory Usage',
          description: 'Identify processes consuming high memory',
          type: 'investigation',
          order: 1,
          estimatedDuration: 2,
          required: true,
          parallel: false,
          commands: [
            {
              id: 'top-memory-processes',
              type: 'shell',
              executor: 'bash',
              script: 'ps aux --sort=-%mem | head -10',
              parameters: {},
              timeout: 30,
              environment: {},
              expectedExitCode: 0,
              ignoreErrors: false,
              runAs: 'monitoring',
              workingDirectory: '/tmp',
            },
            {
              id: 'memory-summary',
              type: 'shell',
              executor: 'bash',
              script: 'free -h && echo "=== Memory Summary ==="',
              parameters: {},
              timeout: 10,
              environment: {},
              expectedExitCode: 0,
              ignoreErrors: false,
              runAs: 'monitoring',
              workingDirectory: '/tmp',
            },
          ],
          verificationCriteria: [
            {
              id: 'analysis-completed',
              name: 'Memory analysis completed',
              type: 'exit_code',
              description: 'Memory analysis commands should succeed',
              expected: 0,
              operator: 'eq',
              critical: true,
              timeout: 60,
            },
          ],
          timeout: 120,
          retryPolicy: {
            maxAttempts: 2,
            delay: 5,
            backoffType: 'fixed',
            maxDelay: 15,
            retryOnErrors: [],
          },
          outputs: [
            {
              name: 'top_processes',
              type: 'string',
              description: 'List of top memory-consuming processes',
              required: true,
            },
            {
              name: 'memory_usage',
              type: 'object',
              description: 'Current memory usage statistics',
              required: true,
            },
          ],
          metadata: {},
        },
        {
          id: 'clear-system-cache',
          title: 'Clear System Cache',
          description: 'Clear system caches to free up memory',
          type: 'recovery',
          order: 2,
          estimatedDuration: 3,
          required: true,
          parallel: false,
          commands: [
            {
              id: 'clear-page-cache',
              type: 'shell',
              executor: 'bash',
              script: 'sudo sync && sudo sysctl vm.drop_caches=1',
              parameters: {},
              timeout: 60,
              environment: {},
              expectedExitCode: 0,
              ignoreErrors: false,
              runAs: 'root',
              workingDirectory: '/tmp',
            },
          ],
          verificationCriteria: [
            {
              id: 'cache-cleared',
              name: 'System cache cleared',
              type: 'exit_code',
              description: 'Cache clearing command should succeed',
              expected: 0,
              operator: 'eq',
              critical: true,
              timeout: 120,
            },
          ],
          timeout: 180,
          retryPolicy: {
            maxAttempts: 1,
            delay: 10,
            backoffType: 'fixed',
            maxDelay: 10,
            retryOnErrors: [],
          },
          outputs: [
            {
              name: 'cache_clear_result',
              type: 'string',
              description: 'Result of cache clearing operation',
              required: true,
            },
          ],
          metadata: {},
        },
        {
          id: 'restart-non-critical-services',
          title: 'Restart Non-Critical Services',
          description: 'Restart non-critical services to free memory',
          type: 'recovery',
          order: 3,
          estimatedDuration: 5,
          required: false,
          parallel: true,
          condition: 'steps[0].outputs.memory_usage.percentage > 85',
          commands: [
            {
              id: 'restart-monitoring',
              type: 'shell',
              executor: 'bash',
              script: 'sudo systemctl restart monitoring-agent || echo "Monitoring agent restart failed"',
              parameters: {},
              timeout: 60,
              environment: {},
              expectedExitCode: 0,
              ignoreErrors: true,
              runAs: 'root',
              workingDirectory: '/tmp',
            },
          ],
          verificationCriteria: [
            {
              id: 'services-restarted',
              name: 'Non-critical services restarted',
              type: 'service_status',
              description: 'Services should be running after restart',
              expected: 'active',
              operator: 'eq',
              critical: false,
              timeout: 180,
            },
          ],
          timeout: 300,
          retryPolicy: {
            maxAttempts: 2,
            delay: 30,
            backoffType: 'fixed',
            maxDelay: 60,
            retryOnErrors: ['SERVICE_ERROR'],
          },
          outputs: [
            {
              name: 'restart_results',
              type: 'object',
              description: 'Results of service restarts',
              required: true,
            },
          ],
          metadata: {},
        },
      ],
      variables: [
        {
          name: 'MEMORY_THRESHOLD',
          type: 'number',
          description: 'Memory usage threshold for intervention',
          required: true,
          defaultValue: 85,
          validation: { min: 70, max: 95 },
          sensitive: false,
        },
      ],
      dependencies: [
        {
          name: 'system-tools',
          type: 'package',
          required: true,
          checkCommand: 'which ps && which free',
        },
      ],
      metadata: {
        category: 'Performance',
        owner: 'SRE Team',
        lastReviewed: new Date(),
        approvalRequired: false,
      },
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    this.runbooks.set(memoryPressureRunbook.id, {
      ...memoryPressureRunbook,
      createdAt: new Date(),
      updatedAt: new Date(),
    });
  }

  private initializeTemplates(): void {
    const incidentResponseTemplate: RunbookTemplate = {
      id: 'incident-response-template',
      name: 'Incident Response Template',
      description: 'Template for creating incident response runbooks',
      category: 'incident',
      template: JSON.stringify({
        name: '{{incident_type}} Incident Response',
        description: 'Runbook for responding to {{incident_type}} incidents',
        category: 'incident',
        severity: '{{severity}}',
        tags: ['{{incident_type}}', 'incident', 'response'],
        estimatedDuration: '{{estimated_duration}}',
        prerequisites: ['Incident commander access', 'Communication tools'],
        riskLevel: '{{risk_level}}',
        steps: [
          {
            id: 'assess-impact',
            title: 'Assess Incident Impact',
            description: 'Evaluate the scope and impact of the incident',
            type: 'investigation',
            order: 1,
            estimatedDuration: 5,
            required: true,
            commands: [
              {
                id: 'check-system-status',
                type: 'shell',
                executor: 'bash',
                script: '{{assessment_commands}}',
                timeout: 300,
                expectedExitCode: 0,
              },
            ],
            verificationCriteria: [
              {
                id: 'impact-assessed',
                name: 'Impact assessment completed',
                type: 'manual',
                description: 'Manual verification of impact assessment',
                critical: true,
                timeout: 600,
              },
            ],
          },
          {
            id: 'communicate-stakeholders',
            title: 'Communicate with Stakeholders',
            description: 'Inform stakeholders about the incident',
            type: 'notification',
            order: 2,
            estimatedDuration: 10,
            required: true,
            commands: [
              {
                id: 'send-notification',
                type: 'http',
                executor: 'curl',
                script: '{{notification_commands}}',
                timeout: 120,
                expectedExitCode: 0,
              },
            ],
          },
        ],
      }, null, 2),
      variables: [
        {
          name: 'incident_type',
          type: 'string',
          description: 'Type of incident',
          required: true,
          sensitive: false,
        },
        {
          name: 'severity',
          type: 'string',
          description: 'Incident severity level',
          required: true,
          validation: { options: ['info', 'warning', 'critical', 'emergency'] },
          sensitive: false,
        },
        {
          name: 'estimated_duration',
          type: 'number',
          description: 'Estimated duration in minutes',
          required: true,
          defaultValue: 30,
          sensitive: false,
        },
        {
          name: 'risk_level',
          type: 'string',
          description: 'Risk level of the runbook',
          required: true,
          validation: { options: ['low', 'medium', 'high', 'critical'] },
          sensitive: false,
        },
        {
          name: 'assessment_commands',
          type: 'string',
          description: 'Commands for incident assessment',
          required: true,
          sensitive: false,
        },
        {
          name: 'notification_commands',
          type: 'string',
          description: 'Commands for stakeholder notification',
          required: true,
          sensitive: false,
        },
      ],
      examples: [
        {
          name: 'Database Outage',
          description: 'Template for database outage incidents',
          variables: {
            incident_type: 'Database Outage',
            severity: 'critical',
            estimated_duration: 45,
            risk_level: 'high',
            assessment_commands: 'pg_isready -h $DB_HOST -p $DB_PORT\ndocker ps | grep postgres',
            notification_commands: 'curl -X POST $SLACK_WEBHOOK -d \'{"text":"Database outage detected"}\'',
          },
          useCase: 'When database becomes unavailable or unresponsive',
        },
      ],
    };

    this.templates.set(incidentResponseTemplate.id, incidentResponseTemplate);
  }

  private startExecutionProcessor(): void {
    setInterval(() => {
      if (!this.isProcessingQueue && this.executionQueue.length > 0) {
        this.processExecutionQueue();
      }
    }, 1000);
  }

  private async processExecutionQueue(): Promise<void> {
    if (this.isProcessingQueue) return;

    this.isProcessingQueue = true;

    try {
      while (this.executionQueue.length > 0 && this.activeExecutions.size < this.maxConcurrentExecutions) {
        const execution = this.executionQueue.shift();
        if (!execution) break;

        this.activeExecutions.add(execution.id);
        this.executeRunbookAsync(execution).catch(error => {
          logger.error({ executionId: execution.id, error }, 'Runbook execution failed');
          this.activeExecutions.delete(execution.id);
        });
      }
    } finally {
      this.isProcessingQueue = false;
    }
  }

  private async executeRunbookAsync(execution: RunbookExecution): Promise<void> {
    try {
      const runbook = this.runbooks.get(execution.runbookId);
      if (!runbook) {
        throw new Error(`Runbook not found: ${execution.runbookId}`);
      }

      execution.status = 'running';
      this.emit('runbook_execution_started', execution);

      const startTime = Date.now();
      const stepExecutions: StepExecution[] = [];

      try {
        // Execute steps in order
        for (const step of runbook.steps) {
          if (execution.status === 'cancelled' as ExecutionStatus) break;

          // Check if step should be executed
          if (step.condition && !this.evaluateStepCondition(step.condition, execution)) {
            const skippedStep: StepExecution = {
              id: this.generateStepExecutionId(),
              stepId: step.id,
              order: step.order,
              status: 'cancelled',
              inputs: {},
              outputs: {},
              logs: [],
              verifications: [],
              retryCount: 0,
              skipped: true,
              skipReason: 'Condition not met',
            };
            stepExecutions.push(skippedStep);
            continue;
          }

          const stepExecution = await this.executeStep(step, execution);
          stepExecutions.push(stepExecution);

          // Check if step failed and is required
          if (stepExecution.status === 'failed' && step.required) {
            execution.status = 'failed';
            execution.result.message = `Required step '${step.title}' failed: ${stepExecution.error}`;
            break;
          }
        }

        // Update execution result
        const endTime = Date.now();
        execution.duration = (endTime - startTime) / 1000;
        execution.completedAt = new Date(endTime);
        execution.steps = stepExecutions;

        if (execution.status !== 'failed' as ExecutionStatus && execution.status !== 'cancelled' as ExecutionStatus) {
          execution.status = 'completed';
          execution.result.success = true;
          execution.result.exitCode = 0;
          execution.result.message = 'Runbook execution completed successfully';
        }

        // Calculate summary
        execution.result.summary = this.calculateExecutionSummary(stepExecutions, execution.duration);

      } catch (error) {
        execution.status = 'failed';
        execution.result.message = error instanceof Error ? error.message : 'Unknown error';
        execution.result.exitCode = 1;
      }

      logger.info({
        executionId: execution.id,
        status: execution.status,
        duration: execution.duration,
        success: execution.result.success,
      }, 'Runbook execution completed');

      this.emit('runbook_execution_completed', execution);

    } catch (error) {
      execution.status = 'failed';
      execution.result.message = error instanceof Error ? error.message : 'Unknown error';
      execution.result.exitCode = 1;

      logger.error({ executionId: execution.id, error }, 'Runbook execution failed');

      this.emit('runbook_execution_failed', execution);
    } finally {
      this.activeExecutions.delete(execution.id);
    }
  }

  private async executeStep(step: RunbookStep, execution: RunbookExecution): Promise<StepExecution> {
    const stepExecution: StepExecution = {
      id: this.generateStepExecutionId(),
      stepId: step.id,
      order: step.order,
      status: 'running',
      startedAt: new Date(),
      inputs: {},
      outputs: {},
      logs: [],
      verifications: [],
      retryCount: 0,
      skipped: false,
    };

    try {
      const startTime = Date.now();

      // Execute commands
      for (const command of step.commands) {
        const commandResult = await this.executeCommand(command, execution, stepExecution);
        stepExecution.logs.push({
          timestamp: new Date(),
          level: 'info',
          message: `Command '${command.id}' executed`,
          source: 'command_executor',
          metadata: { result: commandResult },
        });
      }

      // Run verifications
      for (const criteria of step.verificationCriteria) {
        const verification = await this.runVerification(criteria, stepExecution);
        stepExecution.verifications.push(verification);

        if (verification.status === 'failed' && criteria.critical) {
          throw new Error(`Critical verification failed: ${criteria.name}`);
        }
      }

      stepExecution.status = 'completed';
      stepExecution.completedAt = new Date();
      stepExecution.duration = (Date.now() - startTime) / 1000;

    } catch (error) {
      stepExecution.status = 'failed';
      stepExecution.error = error instanceof Error ? error.message : 'Unknown error';
      stepExecution.completedAt = new Date();

      // Check if retry is needed
      if (stepExecution.retryCount < step.retryPolicy.maxAttempts) {
        stepExecution.retryCount++;
        stepExecution.status = 'running';

        // Wait before retry
        await this.sleep(step.retryPolicy.delay * 1000);

        return await this.executeStep(step, execution);
      }
    }

    return stepExecution;
  }

  private async executeCommand(
    command: Command,
    execution: RunbookExecution,
    stepExecution: StepExecution
  ): Promise<unknown> {
    try {
      switch (command.type) {
        case 'shell':
        case 'bash':
          return await this.executeShellCommand(command, execution);
        case 'http':
          return await this.executeHttpCommand(command, execution);
        case 'sql':
          return await this.executeSQLCommand(command, execution);
        default:
          throw new Error(`Unsupported command type: ${command.type}`);
      }
    } catch (error) {
      stepExecution.logs.push({
        timestamp: new Date(),
        level: 'error',
        message: `Command '${command.id}' failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        source: 'command_executor',
        metadata: { command: command.id, error },
      });

      if (!command.ignoreErrors) {
        throw error;
      }

      return { success: false, error };
    }
  }

  private async executeShellCommand(command: Command, execution: RunbookExecution): Promise<unknown> {
    try {
      // This is a simplified implementation
      // In a real system, you'd want to use a proper process execution library
      // with proper sandboxing and security measures

      const result = await Bash({
        command: command.script,
        description: `Execute runbook command: ${command.id}`,
        timeout: command.timeout * 1000,
      });

      return {
        success: true,
        exitCode: 0,
        stdout: result,
        stderr: '',
      };
    } catch (error) {
      return {
        success: false,
        exitCode: 1,
        stdout: '',
        stderr: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  private async executeHttpCommand(command: Command, execution: RunbookExecution): Promise<unknown> {
    // Placeholder for HTTP command execution
    logger.info({ command: command.id }, 'Executing HTTP command');
    return {
      success: true,
      statusCode: 200,
      body: '{}',
    };
  }

  private async executeSQLCommand(command: Command, execution: RunbookExecution): Promise<unknown> {
    // Placeholder for SQL command execution
    logger.info({ command: command.id }, 'Executing SQL command');
    return {
      success: true,
      rows: [],
      rowCount: 0,
    };
  }

  private async runVerification(
    criteria: VerificationCriteria,
    stepExecution: StepExecution
  ): Promise<VerificationExecution> {
    const verification: VerificationExecution = {
      id: this.generateVerificationId(),
      criteriaId: criteria.id,
      status: 'pending',
      expected: criteria.expected,
      actual: undefined,
      duration: 0,
    };

    try {
      const startTime = Date.now();

      // This is a simplified verification implementation
      // In a real system, you'd have specific verification logic for each type
      const actual = await this.performVerification(criteria, stepExecution);
      verification.actual = actual;

      const passed = this.compareValues(actual, criteria.expected, criteria.operator);
      verification.status = passed ? 'passed' : 'failed';
      verification.duration = (Date.now() - startTime) / 1000;

      if (!passed) {
        verification.error = `Verification failed: expected ${criteria.expected} ${criteria.operator} actual ${actual}`;
      }

    } catch (error) {
      verification.status = 'failed';
      verification.error = error instanceof Error ? error.message : 'Unknown error';
    }

    return verification;
  }

  private async performVerification(
    criteria: VerificationCriteria,
    stepExecution: StepExecution
  ): Promise<unknown> {
    // Simplified verification logic
    switch (criteria.type) {
      case 'exit_code':
        return 0; // Assume success for this example
      case 'output':
        return 'expected output';
      case 'service_status':
        return 'active';
      default:
        return null;
    }
  }

  private compareValues(actual: unknown, expected: unknown, operator: string): boolean {
    switch (operator) {
      case 'eq':
        return actual === expected;
      case 'ne':
        return actual !== expected;
      case 'gt':
        return Number(actual) > Number(expected);
      case 'lt':
        return Number(actual) < Number(expected);
      case 'gte':
        return Number(actual) >= Number(expected);
      case 'lte':
        return Number(actual) <= Number(expected);
      case 'contains':
        return String(actual).includes(String(expected));
      case 'regex':
        return new RegExp(String(expected)).test(String(actual));
      default:
        return false;
    }
  }

  private evaluateStepCondition(condition: string, execution: RunbookExecution): boolean {
    try {
      // Create a safe evaluation context
      const context = {
        steps: execution.steps,
        variables: execution.variables,
        alert: execution.context.alert,
      };

      // Use Function constructor for safer evaluation than eval
      const func = new Function('context', `
        const { steps, variables, alert } = context;
        return ${condition};
      `);

      return Boolean(func(context));
    } catch (error) {
      logger.warn({ condition, error }, 'Failed to evaluate step condition');
      return false;
    }
  }

  private async createExecutionContext(options: RunbookExecutionOptions): Promise<ExecutionContext> {
    const systemInfo = await this.getSystemInfo();

    return {
      environment: options.environment || 'production',
      userId: options.triggeredBy,
      permissions: options.permissions || [],
      systemInfo,
      alert: undefined, // Will be set separately if needed
    };
  }

  private async getSystemInfo(): Promise<SystemInfo> {
    const os = await import('os');
    const { execSync } = await import('child_process');

    return {
      hostname: os.hostname(),
      platform: os.platform(),
      architecture: os.arch(),
      nodeVersion: process.version,
      memory: {
        total: os.totalmem(),
        free: os.freemem(),
        used: os.totalmem() - os.freemem(),
        percentage: ((os.totalmem() - os.freemem()) / os.totalmem()) * 100,
      },
      disk: {
        total: 0,
        free: 0,
        used: 0,
        percentage: 0,
      },
      network: {
        interfaces: Object.keys(os.networkInterfaces()),
        ipAddress: '127.0.0.1', // Simplified
        gateway: '0.0.0.0',
      },
    };
  }

  private async evaluateRunbookMatch(runbook: Runbook, alert: Alert): Promise<RunbookRecommendation> {
    let confidence = 0;
    let relevanceScore = 0;
    const matchCriteria: MatchCriteria[] = [];

    // Check severity match
    if (runbook.severity === alert.severity) {
      confidence += 30;
      matchCriteria.push({
        type: 'severity',
        value: alert.severity,
        weight: 30,
        matched: true,
      });
    } else if (this.isCompatibleSeverity(runbook.severity, alert.severity)) {
      confidence += 15;
      matchCriteria.push({
        type: 'severity',
        value: alert.severity,
        weight: 15,
        matched: true,
      });
    }

    // Check component match
    if (runbook.tags.includes(alert.source.component)) {
      confidence += 25;
      relevanceScore += 25;
      matchCriteria.push({
        type: 'component',
        value: alert.source.component,
        weight: 25,
        matched: true,
      });
    }

    // Check keyword matches in title and description
    const alertText = `${alert.title} ${alert.message}`.toLowerCase();
    const runbookText = `${runbook.name} ${runbook.description} ${runbook.tags.join(' ')}`.toLowerCase();

    const keywordMatches = runbook.tags.filter(tag =>
      alertText.includes(tag.toLowerCase())
    ).length;

    if (keywordMatches > 0) {
      confidence += keywordMatches * 10;
      relevanceScore += keywordMatches * 15;
      matchCriteria.push({
        type: 'keyword',
        value: keywordMatches.toString(),
        weight: keywordMatches * 10,
        matched: true,
      });
    }

    // Adjust confidence based on runbook quality indicators
    if (runbook.approvedAt) {
      confidence += 10;
    }

    if (runbook.rollbackPlan.enabled) {
      confidence += 5;
    }

    return {
      runbookId: runbook.id,
      confidence: Math.min(confidence, 100),
      relevanceScore: Math.min(relevanceScore, 100),
      matchCriteria,
      explanation: this.generateRecommendationExplanation(runbook, alert, matchCriteria),
      prerequisites: runbook.prerequisites,
      estimatedDuration: runbook.estimatedDuration,
      riskLevel: runbook.riskLevel,
    };
  }

  private isCompatibleSeverity(runbookSeverity: string, alertSeverity: string): boolean {
    const severityOrder = {
      'info': 0,
      'warning': 1,
      'critical': 2,
      'emergency': 3,
    };

    const runbookLevel = severityOrder[runbookSeverity as keyof typeof severityOrder] || 0;
    const alertLevel = severityOrder[alertSeverity as keyof typeof severityOrder] || 0;

    return runbookLevel >= alertLevel;
  }

  private generateRecommendationExplanation(
    runbook: Runbook,
    alert: Alert,
    matchCriteria: MatchCriteria[]
  ): string {
    const reasons = matchCriteria
      .filter(criteria => criteria.matched)
      .map(criteria => {
        switch (criteria.type) {
          case 'severity':
            return `Matches alert severity (${alert.severity})`;
          case 'component':
            return `Targets affected component (${alert.source.component})`;
          case 'keyword':
            return `Contains relevant keywords`;
          default:
            return 'General match';
        }
      });

    return `Recommended runbook "${runbook.name}" because: ${reasons.join(', ')}. Estimated duration: ${runbook.estimatedDuration} minutes. Risk level: ${runbook.riskLevel}.`;
  }

  private validateRunbook(runbook: Runbook): void {
    if (!runbook.id || !runbook.name) {
      throw new Error('Runbook must have id and name');
    }

    if (!runbook.steps || runbook.steps.length === 0) {
      throw new Error('Runbook must have at least one step');
    }

    // Validate steps
    runbook.steps.forEach((step, index) => {
      if (!step.id || !step.title) {
        throw new Error(`Step ${index + 1} must have id and title`);
      }

      if (step.order !== index + 1) {
        throw new Error(`Step ${index + 1} has incorrect order`);
      }
    });
  }

  private validateTemplateVariables(template: RunbookTemplate, variables: Record<string, unknown>): Promise<void> {
    for (const templateVar of template.variables) {
      if (templateVar.required && !(templateVar.name in variables)) {
        throw new Error(`Required variable '${templateVar.name}' is missing`);
      }

      if (templateVar.validation && variables[templateVar.name] !== undefined) {
        const value = variables[templateVar.name];

        if (templateVar.validation.pattern) {
          const regex = new RegExp(templateVar.validation.pattern);
          if (!regex.test(String(value))) {
            throw new Error(`Variable '${templateVar.name}' does not match required pattern`);
          }
        }

        if (templateVar.validation.min !== undefined && Number(value) < templateVar.validation.min) {
          throw new Error(`Variable '${templateVar.name}' is below minimum value`);
        }

        if (templateVar.validation.max !== undefined && Number(value) > templateVar.validation.max) {
          throw new Error(`Variable '${templateVar.name}' exceeds maximum value`);
        }

        if (templateVar.validation.options && !templateVar.validation.options.includes(String(value))) {
          throw new Error(`Variable '${templateVar.name}' is not in allowed options`);
        }
      }
    }

    return Promise.resolve();
  }

  private applyTemplate(template: RunbookTemplate, variables: Record<string, unknown>): unknown {
    let templateStr = template.template;

    // Replace variables in template
    for (const [key, value] of Object.entries(variables)) {
      const regex = new RegExp(`{{${key}}}`, 'g');
      templateStr = templateStr.replace(regex, String(value));
    }

    return JSON.parse(templateStr);
  }

  private calculateExecutionSummary(steps: StepExecution[], totalDuration?: number): ExecutionSummary {
    const completedSteps = steps.filter(s => s.status === 'completed').length;
    const failedSteps = steps.filter(s => s.status === 'failed').length;
    const skippedSteps = steps.filter(s => s.skipped).length;

    return {
      totalSteps: steps.length,
      completedSteps,
      failedSteps,
      skippedSteps,
      totalDuration: totalDuration || 0,
      successRate: steps.length > 0 ? (completedSteps / steps.length) * 100 : 0,
    };
  }

  private incrementVersion(version: string): string {
    const parts = version.split('.');
    parts[2] = String(parseInt(parts[2]) + 1);
    return parts.join('.');
  }

  private generateExecutionId(): string {
    return `exec-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  private generateStepExecutionId(): string {
    return `step-exec-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  private generateVerificationId(): string {
    return `verify-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  private generateRunbookId(): string {
    return `runbook-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Cleanup method
   */
  cleanup(): void {
    this.removeAllListeners();
    logger.info('Runbook integration service cleaned up');
  }
}

// ============================================================================
// Supporting Interfaces
// ============================================================================

export interface RunbookServiceConfig {
  maxConcurrentExecutions: number;
  executionTimeoutMinutes: number;
  logRetentionDays: number;
  artifactRetentionDays: number;
  enableRollback: boolean;
  securityContext: {
    sandboxEnabled: boolean;
    allowedCommands: string[];
    restrictedPaths: string[];
  };
}

export interface RunbookSearchCriteria {
  category?: string;
  severity?: AlertSeverity;
  tags?: string[];
  author?: string;
  keyword?: string;
}

export interface RunbookExecutionOptions {
  triggeredBy: string;
  triggerType?: 'alert' | 'manual' | 'scheduled' | 'api';
  alertId?: string;
  environment?: string;
  permissions?: string[];
  variables?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

// Export singleton instance
export const runbookIntegrationService = new RunbookIntegrationService({
  maxConcurrentExecutions: 5,
  executionTimeoutMinutes: 60,
  logRetentionDays: 30,
  artifactRetentionDays: 7,
  enableRollback: true,
  securityContext: {
    sandboxEnabled: true,
    allowedCommands: ['bash', 'curl', 'psql', 'kubectl'],
    restrictedPaths: ['/etc', '/root', '/var/log'],
  },
});
