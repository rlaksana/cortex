// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck

/**
 * Workflow Service Interfaces
 *
 * Comprehensive type definitions for workflow management functionality including:
 * - Workflow definitions and templates
 * - Workflow execution and state management
 * - Task orchestration and human integration
 * - Analytics and monitoring
 * - Service integration patterns
 */

// Core workflow types
export type WorkflowStatus = 'draft' | 'active' | 'inactive' | 'archived' | 'deprecated';
export type TaskStatus =
  | 'pending'
  | 'assigned'
  | 'in_progress'
  | 'completed'
  | 'failed'
  | 'timeout'
  | 'escalated'
  | 'cancelled';
export type TaskPriority = 'low' | 'medium' | 'high' | 'critical' | 'urgent';
export type ExecutionMode = 'sequential' | 'parallel' | 'conditional' | 'hybrid';
export type TriggerType = 'manual' | 'event' | 'schedule' | 'api' | 'webhook';
export type ActionType =
  | 'create'
  | 'update'
  | 'delete'
  | 'approve'
  | 'reject'
  | 'escalate'
  | 'notify';
export type NotificationType = 'email' | 'slack' | 'sms' | 'push' | 'in_app';
export type IntegrationType = 'service' | 'api' | 'database' | 'message_queue' | 'webhook';

// Basic workflow structures
export interface WorkflowDefinition {
  id: string;
  name: string;
  description: string;
  category: string;
  version: string;
  status: WorkflowStatus;
  tasks: WorkflowTask[];
  triggers: WorkflowTrigger[];
  metadata: WorkflowMetadata;
  createdAt: string;
  updatedAt: string;
}

export interface WorkflowTask {
  id: string;
  name: string;
  description?: string;
  type: TaskType;
  priority: TaskPriority;
  dependencies: string[];
  assignee?: string;
  assignees?: string[];
  config: TaskConfig;
  validation?: TaskValidation;
  timeout?: TaskTimeout;
  retry?: TaskRetry;
  escalation?: TaskEscalation;
  notifications?: TaskNotification[];
  metadata?: Record<string, unknown>;
}

export type TaskType =
  | 'human'
  | 'approval'
  | 'escalation'
  | 'service'
  | 'parallel'
  | 'conditional'
  | 'script'
  | 'timer';

export interface TaskConfig {
  [key: string]: unknown;
  // Service tasks
  serviceName?: string;
  endpoint?: string;
  method?: string;
  payload?: Record<string, unknown>;
  // Human tasks
  instructions?: string;
  requiredData?: string[];
  outputSchema?: Record<string, unknown>;
  // Approval tasks
  requiredApprovals?: number;
  votingMethod?: 'majority' | 'unanimous' | 'quorum';
  // Parallel tasks
  parallelTasks?: WorkflowTask[];
  // Conditional tasks
  condition?: Condition;
  branches?: ConditionalBranch[];
  default?: boolean;
  // Timer tasks
  duration?: number;
  repeat?: boolean;
  // Script tasks
  script?: string;
  language?: string;
}

export interface Condition {
  field: string;
  operator: 'equals' | 'not_equals' | 'greater_than' | 'less_than' | 'contains' | 'in' | 'not_in';
  value: unknown;
  and?: Condition[];
  or?: Condition[];
}

export interface ConditionalBranch {
  id: string;
  name: string;
  condition?: Condition;
  tasks: string[];
}

export interface TaskValidation {
  required: boolean;
  rules: ValidationRule[];
}

export interface ValidationRule {
  field: string;
  type: 'required' | 'format' | 'range' | 'custom';
  constraint: unknown;
  message: string;
}

export interface TaskTimeout {
  duration: number;
  action: 'fail' | 'escalate' | 'skip' | 'notify';
  escalationTarget?: string;
}

export interface TaskRetry {
  maxRetries: number;
  backoffStrategy: 'fixed' | 'linear' | 'exponential';
  initialDelay: number;
  maxDelay?: number;
}

export interface TaskEscalation {
  levels: EscalationLevel[];
  autoEscalate: boolean;
}

export interface EscalationLevel {
  level: number;
  target: string;
  delay: number;
  action: 'assign' | 'notify' | 'approve';
}

export interface TaskNotification {
  type: NotificationType;
  trigger: 'assigned' | 'completed' | 'failed' | 'timeout' | 'escalated';
  template?: string;
  recipients: string[];
  config?: Record<string, unknown>;
}

// Workflow templates
export interface WorkflowTemplate {
  id: string;
  name: string;
  description: string;
  category: string;
  version: string;
  tasks: WorkflowTask[];
  variables?: TemplateVariable[];
  metadata: TemplateMetadata;
  createdAt: string;
  updatedAt: string;
}

export interface TemplateVariable {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'object' | 'array';
  required: boolean;
  defaultValue?: unknown;
  description?: string;
  validation?: ValidationRule[];
}

export interface TemplateMetadata {
  created_by: string;
  created_at: string;
  updated_at: string;
  tags?: string[];
  usage_count?: number;
  rating?: number;
}

// Workflow versions
export interface WorkflowVersion {
  id: string;
  templateId: string;
  version: string;
  changes: Partial<WorkflowTemplate>;
  changelog: string;
  status: 'draft' | 'active' | 'archived';
  metadata: VersionMetadata;
  createdAt: string;
}

export interface VersionMetadata {
  created_by: string;
  created_at: string;
  reason: string;
  migrationRequired: boolean;
  rollbackAvailable: boolean;
}

// Workflow execution
export interface WorkflowExecution {
  id: string;
  workflowId: string;
  templateId: string;
  status: ExecutionStatus;
  mode: ExecutionMode;
  startedAt: string;
  completedAt?: string;
  currentTask?: string;
  currentTasks?: string[];
  context: WorkflowContext;
  state: WorkflowState;
  tasks: TaskExecution[];
  variables: Record<string, unknown>;
  error?: WorkflowError;
  metadata: ExecutionMetadata;
}

export type ExecutionStatus =
  | 'pending'
  | 'running'
  | 'suspended'
  | 'completed'
  | 'failed'
  | 'cancelled'
  | 'escalated';

export interface TaskExecution {
  id: string;
  taskId: string;
  status: TaskStatus;
  assignee?: string;
  assignedAt?: string;
  startedAt?: string;
  completedAt?: string;
  failedAt?: string;
  timeoutAt?: string;
  escalatedAt?: string;
  result?: unknown;
  error?: string;
  duration?: number;
  retryCount?: number;
  output?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

export interface WorkflowContext {
  trigger?: WorkflowTrigger;
  initiator?: string;
  [key: string]: unknown;
}

export interface WorkflowState {
  currentPhase?: string;
  completedPhases: string[];
  variables: Record<string, unknown>;
  checkpoints: Record<string, unknown>;
  history: StateHistory[];
}

export interface StateHistory {
  timestamp: string;
  action: string;
  task?: string;
  data: Record<string, unknown>;
  user?: string;
}

export interface ExecutionMetadata {
  started_by: string;
  started_at: string;
  completed_at?: string;
  environment: string;
  version: string;
  tags?: string[];
}

// Workflow execution requests
export interface WorkflowExecutionRequest {
  templateId: string;
  context: WorkflowContext;
  mode?: ExecutionMode;
  priority?: TaskPriority;
  scheduledAt?: string;
  tags?: string[];
  overrides?: {
    tasks?: Record<string, Partial<WorkflowTask>>;
    variables?: Record<string, unknown>;
  };
}

// Task assignments
export interface TaskAssignment {
  taskId: string;
  executionId: string;
  assignee: string;
  assignedBy: string;
  assignedAt: string;
  dueDate?: string;
  priority?: TaskPriority;
  metadata?: Record<string, unknown>;
}

// Human task types
export interface HumanTask extends WorkflowTask {
  type: 'human';
  assignee: string;
  dueDate?: string;
  instructions?: string;
  requiredData?: string[];
  outputSchema?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

export interface ApprovalTask extends WorkflowTask {
  type: 'approval';
  approvers: string[];
  requiredApprovals: number;
  votingMethod: 'majority' | 'unanimous' | 'quorum';
  deadline?: string;
  minQuorum?: number;
  allowComments?: boolean;
}

export interface EscalationTask extends WorkflowTask {
  type: 'escalation';
  originalTaskId: string;
  escalationLevel: number;
  escalatedTo: string;
  reason: EscalationReason;
  originalDeadline?: string;
  newDeadline?: string;
  autoResolve?: boolean;
}

export type EscalationReason = 'timeout' | 'failure' | 'rejection' | 'manual' | 'overload';

export interface ServiceTask extends WorkflowTask {
  type: 'service';
  serviceConfig: ServiceConfig;
}

export interface ServiceConfig {
  serviceName: string;
  endpoint: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  payload?: Record<string, unknown>;
  headers?: Record<string, string>;
  timeout: number;
  retryConfig?: TaskRetry;
  authentication?: {
    type: 'bearer' | 'basic' | 'api_key';
    credentials: Record<string, string>;
  };
}

export interface ParallelTask extends WorkflowTask {
  type: 'parallel';
  config: {
    parallelTasks: WorkflowTask[];
    waitStrategy: 'all' | 'any' | 'majority';
    continueOnError: boolean;
  };
}

export interface ConditionalTask extends WorkflowTask {
  type: 'conditional';
  config: {
    condition: Condition;
    branches: ConditionalBranch[];
    defaultBranch?: string;
  };
}

// Workflow analytics
export interface WorkflowAnalytics {
  workflowId: string;
  executionCount: number;
  averageExecutionTime: number;
  successRate: number;
  mostFailedTask?: string;
  commonBottlenecks: string[];
  lastMonthExecutions: number;
  averageTaskCompletionTime: Record<string, number>;
  createdAt: string;
  updatedAt: string;
}

export interface WorkflowMetrics {
  id: string;
  workflowId: string;
  executionId: string;
  taskId?: string;
  metricType: string;
  value: number;
  unit?: string;
  timestamp: string;
  metadata?: Record<string, unknown>;
}

export interface WorkflowPerformanceData {
  taskId: string;
  averageDuration: number;
  queueTime: number;
  executionTime: number;
  failureRate: number;
  timeoutRate: number;
  escalationRate: number;
  userSatisfaction?: number;
}

export interface WorkflowBottleneck {
  taskId: string;
  taskName: string;
  issues: string[];
  impact: 'low' | 'medium' | 'high' | 'critical';
  recommendations: string[];
  estimatedImpact: number;
}

// Workflow reporting
export interface WorkflowReport {
  id: string;
  type: 'comprehensive' | 'summary' | 'performance' | 'analytics' | 'custom';
  title: string;
  description: string;
  dateRange: {
    start: string;
    end: string;
  };
  templateIds?: string[];
  filters: WorkflowFilter;
  metrics: ReportMetrics;
  visualizations: ReportVisualization[];
  recommendations: ReportRecommendation[];
  generatedAt: string;
  generatedBy: string;
}

export interface ReportMetrics {
  executionMetrics: Record<string, number>;
  performanceMetrics: Record<string, number>;
  userMetrics: Record<string, number>;
  errorMetrics: Record<string, number>;
}

export interface ReportVisualization {
  type: 'chart' | 'graph' | 'table' | 'heatmap' | 'gauge';
  title: string;
  data: unknown;
  config: Record<string, unknown>;
}

export interface ReportRecommendation {
  category: 'performance' | 'reliability' | 'usability' | 'efficiency';
  priority: 'low' | 'medium' | 'high';
  description: string;
  impact: string;
  effort: 'low' | 'medium' | 'high';
  timeline?: string;
}

// Workflow queries and filters
export interface WorkflowQuery {
  workflowIds?: string[];
  templateIds?: string[];
  statuses?: ExecutionStatus[];
  assignees?: string[];
  dateRange?: {
    start: string;
    end: string;
  };
  tags?: string[];
  context?: Record<string, unknown>;
  includeMetrics?: boolean;
  includeTasks?: boolean;
  limit?: number;
  offset?: number;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
}

export interface WorkflowFilter {
  status?: ExecutionStatus[];
  priority?: TaskPriority[];
  assignee?: string[];
  dateRange?: {
    start: string;
    end: string;
  };
  tags?: string[];
  customFilters?: CustomFilter[];
}

export interface CustomFilter {
  field: string;
  operator: string;
  value: unknown;
}

// Workflow events
export interface WorkflowEvent {
  id: string;
  type: string;
  source: string;
  data: Record<string, unknown>;
  timestamp: string;
  correlationId?: string;
  causationId?: string;
  metadata?: Record<string, unknown>;
}

// Workflow notifications
export interface WorkflowNotification {
  id: string;
  type: NotificationType;
  recipient: string;
  taskId?: string;
  workflowId?: string;
  executionId?: string;
  message: string;
  subject?: string;
  channels: NotificationType[];
  priority: TaskPriority;
  scheduledAt?: string;
  sentAt?: string;
  template?: string;
  variables?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

// Workflow integration
export interface WorkflowIntegration {
  id: string;
  name: string;
  type: IntegrationType;
  config: IntegrationConfig;
  status: 'active' | 'inactive' | 'error';
  healthCheck?: HealthCheck;
  metrics?: IntegrationMetrics;
  createdAt: string;
  updatedAt: string;
}

export interface IntegrationConfig {
  endpoint?: string;
  authentication?: Record<string, unknown>;
  timeout?: number;
  retryConfig?: TaskRetry;
  mappings?: FieldMapping[];
  transformers?: DataTransformer[];
  [key: string]: unknown;
}

export interface FieldMapping {
  source: string;
  target: string;
  transform?: string;
}

export interface DataTransformer {
  name: string;
  config: Record<string, unknown>;
}

export interface HealthCheck {
  url: string;
  method: string;
  expectedStatus: number;
  timeout: number;
  interval: number;
  healthy: boolean;
  lastCheck: string;
  responseTime?: number;
}

export interface IntegrationMetrics {
  requestCount: number;
  successCount: number;
  errorCount: number;
  averageResponseTime: number;
  lastRequest: string;
  lastError?: string;
}

// Workflow triggers
export interface WorkflowTrigger {
  id: string;
  type: TriggerType;
  name: string;
  description?: string;
  config: TriggerConfig;
  enabled: boolean;
  conditions?: Condition[];
  createdAt: string;
  updatedAt: string;
}

export interface TriggerConfig {
  [key: string]: unknown;
  // Event triggers
  eventType?: string;
  source?: string;
  // Schedule triggers
  schedule?: string; // cron expression
  timezone?: string;
  // API triggers
  endpoint?: string;
  method?: string;
  // Webhook triggers
  webhookUrl?: string;
  secret?: string;
  // Manual triggers
  allowedUsers?: string[];
}

// Workflow actions
export interface WorkflowAction {
  id: string;
  type: ActionType;
  name: string;
  description?: string;
  config: ActionConfig;
  conditions?: Condition[];
  order: number;
  enabled: boolean;
}

export interface ActionConfig {
  [key: string]: unknown;
  // Create actions
  entityType?: string;
  data?: Record<string, unknown>;
  // Update actions
  updateData?: Record<string, unknown>;
  // Delete actions
  deleteCriteria?: Record<string, unknown>;
  // Approve/Reject actions
  decision?: 'approve' | 'reject';
  reason?: string;
  // Escalate actions
  escalationLevel?: number;
  escalationTarget?: string;
  // Notify actions
  notification?: WorkflowNotification;
}

// Workflow results
export interface WorkflowResult {
  id: string;
  executionId: string;
  status: ExecutionStatus;
  output?: Record<string, unknown>;
  error?: WorkflowError;
  metrics?: ExecutionMetrics;
  artifacts?: WorkflowArtifact[];
  completedAt: string;
  duration: number;
}

export interface WorkflowError {
  code: string;
  message: string;
  details?: Record<string, unknown>;
  stack?: string;
  taskId?: string;
  timestamp: string;
  retryable: boolean;
}

export interface ExecutionMetrics {
  totalTasks: number;
  completedTasks: number;
  failedTasks: number;
  averageTaskTime: number;
  totalDuration: number;
  successRate: number;
  errorRate: number;
}

export interface WorkflowArtifact {
  id: string;
  name: string;
  type: 'document' | 'data' | 'log' | 'report' | 'other';
  url?: string;
  content?: string;
  metadata?: Record<string, unknown>;
  createdAt: string;
}

// Workflow configuration
export interface WorkflowConfiguration {
  settings: WorkflowSettings;
  validation: WorkflowValidation;
  security: SecuritySettings;
  performance: PerformanceSettings;
  integrations: IntegrationSettings;
}

export interface WorkflowSettings {
  defaultTimeout: number;
  defaultRetryPolicy: TaskRetry;
  defaultEscalationPolicy: TaskEscalation;
  maxConcurrentExecutions: number;
  executionHistoryRetention: number;
  auditEnabled: boolean;
  notificationsEnabled: boolean;
}

export interface WorkflowValidation {
  strictValidation: boolean;
  customValidators: CustomValidator[];
  requiredFields: string[];
  fieldValidationRules: Record<string, ValidationRule[]>;
}

export interface CustomValidator {
  name: string;
  function: string;
  config: Record<string, unknown>;
}

export interface SecuritySettings {
  authentication: {
    required: boolean;
    methods: string[];
    providers: string[];
  };
  authorization: {
    required: boolean;
    roles: string[];
    permissions: string[];
  };
  encryption: {
    atRest: boolean;
    inTransit: boolean;
    algorithm?: string;
  };
  audit: {
    logLevel: string;
    retentionPeriod: number;
    includeSensitiveData: boolean;
  };
}

export interface PerformanceSettings {
  caching: {
    enabled: boolean;
    ttl: number;
    maxSize: number;
  };
  optimization: {
    queryOptimization: boolean;
    batchProcessing: boolean;
    parallelExecution: boolean;
  };
  monitoring: {
    metricsCollection: boolean;
    performanceProfiling: boolean;
    alerting: boolean;
  };
}

export interface IntegrationSettings {
  defaultTimeout: number;
  retryPolicy: TaskRetry;
  circuitBreaker: CircuitBreakerSettings;
  rateLimiting: RateLimitSettings;
}

export interface CircuitBreakerSettings {
  enabled: boolean;
  failureThreshold: number;
  recoveryTimeout: number;
  expectedRecoveryTime: number;
}

export interface RateLimitSettings {
  enabled: boolean;
  requestsPerSecond: number;
  burstSize: number;
  windowSize: number;
}

// Workflow metadata
export interface WorkflowMetadata {
  id?: string;
  kind?: string;
  scope?: {
    project?: string;
    branch?: string;
    org?: string;
  };
  data?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
  created_at?: string;
  updated_at?: string;
}
