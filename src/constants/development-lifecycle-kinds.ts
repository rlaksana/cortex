// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck

/**
 * Development Lifecycle Knowledge Types
 *
 * Knowledge types that support the software development lifecycle:
 * - runbook: Operational procedures with step-by-step instructions
 * - change: Change tracking for all modifications
 * - issue: Issue tracking with external system integration
 * - decision: Architecture Decision Records (ADR) with immutability constraints
 * - todo: Task and todo management with status tracking
 * - release_note: Release documentation with version tracking
 * - ddl: Database schema migration tracking
 * - pr_context: Pull request context with metadata
 *
 * @version 1.0.0
 */


import {
  ChangeSchema,
  DDLSchema,
  DecisionSchema,
  IssueSchema,
  PRContextSchema,
  ReleaseNoteSchema,
  RunbookSchema,
  TodoSchema,
} from '../schemas/knowledge-types.js';
/**
 * Knowledge type categories for logical grouping
 */
export type KnowledgeCategory =
  | 'core-graph-extension'
  | 'core-document-types'
  | 'development-lifecycle'
  | 'eight-log-system';

/**
 * Validation features supported by each knowledge type
 */
export interface ValidationFeatures {
  hasSchemaValidation: boolean;
  supportsDeduplication: boolean;
  hasImmutabilityConstraints: boolean;
  supportsScopeIsolation: boolean;
  hasTTLPolicies: boolean;
}

/**
 * Business rules and constraints for knowledge types
 */
export interface BusinessRules {
  rules: string[];
  constraints: string[];
  requiredFields: string[];
  optionalFields: string[];
}

/**
 * Comprehensive metadata for knowledge types
 */
export interface KnowledgeTypeMetadata {
  kind: string;
  displayName: string;
  category: KnowledgeCategory;
  description: string;
  useCases: string[];
  validationFeatures: ValidationFeatures;
  businessRules: BusinessRules;
  schemaType: unknown;
  typescriptType: string;
  tableName: string;
  isImplemented: boolean;
  introducedIn: string;
  relatedTypes: string[];
  tags: string[];
}

/**
 * Development Lifecycle knowledge type metadata
 */
export const DEVELOPMENT_LIFECYCLE_METADATA: Record<string, KnowledgeTypeMetadata> = {
  runbook: {
    kind: 'runbook',
    displayName: 'Runbook',
    category: 'development-lifecycle' as KnowledgeCategory,
    description:
      'Operational procedures with step-by-step instructions, triggers, and verification timestamps for reliability',
    useCases: [
      'Incident response procedures',
      'Deployment runbooks',
      'System maintenance tasks',
      'Troubleshooting guides',
      'Operational checklists',
    ],
    validationFeatures: {
      hasSchemaValidation: true,
      supportsDeduplication: true,
      hasImmutabilityConstraints: false,
      supportsScopeIsolation: true,
      hasTTLPolicies: true,
    },
    businessRules: {
      rules: [
        'At least one step is required',
        'Each step must have a step_number and description',
        'Verification tracking with last_verified_at timestamp',
        'Service association for operational context',
      ],
      constraints: [
        'service must be 1-200 characters',
        'title must be 1-500 characters',
        'steps must be ordered and sequential',
      ],
      requiredFields: ['service', 'steps', 'title'],
      optionalFields: ['description', 'triggers', 'last_verified_at'],
    },
    schemaType: RunbookSchema,
    typescriptType: 'RunbookItem',
    tableName: 'runbook',
    isImplemented: true,
    introducedIn: '1.0.0',
    relatedTypes: ['incident', 'change'],
    tags: ['operations', 'procedures', 'reliability', 'troubleshooting'],
  },

  change: {
    kind: 'change',
    displayName: 'Change',
    category: 'development-lifecycle' as KnowledgeCategory,
    description:
      'Change tracking for all modifications including features, bugfixes, refactoring, and configuration updates',
    useCases: [
      'Feature development tracking',
      'Bug fix documentation',
      'Refactoring records',
      'Configuration change management',
      'Dependency update tracking',
    ],
    validationFeatures: {
      hasSchemaValidation: true,
      supportsDeduplication: true,
      hasImmutabilityConstraints: false,
      supportsScopeIsolation: true,
      hasTTLPolicies: true,
    },
    businessRules: {
      rules: [
        'Subject reference required (commit SHA, PR number, etc.)',
        'Categorized change types for better organization',
        'Affected files tracking for impact analysis',
        'Author attribution for accountability',
      ],
      constraints: [
        'subject_ref must be 1-200 characters',
        'summary is required',
        'change_type must be predefined enum value',
      ],
      requiredFields: ['change_type', 'subject_ref', 'summary'],
      optionalFields: ['details', 'affected_files', 'author', 'commit_sha'],
    },
    schemaType: ChangeSchema,
    typescriptType: 'ChangeItem',
    tableName: 'changeLog',
    isImplemented: true,
    introducedIn: '1.0.0',
    relatedTypes: ['release', 'issue', 'decision'],
    tags: ['development', 'tracking', 'version-control', 'audit'],
  },

  issue: {
    kind: 'issue',
    displayName: 'Issue',
    category: 'development-lifecycle' as KnowledgeCategory,
    description:
      'Issue tracking with external system integration, supporting GitHub, Jira, Linear and other issue trackers',
    useCases: [
      'Bug tracking and resolution',
      'Feature request management',
      'Task and epic tracking',
      'External system synchronization',
      'Issue lifecycle management',
    ],
    validationFeatures: {
      hasSchemaValidation: true,
      supportsDeduplication: true,
      hasImmutabilityConstraints: false,
      supportsScopeIsolation: true,
      hasTTLPolicies: true,
    },
    businessRules: {
      rules: [
        'External system integration (tracker, external_id)',
        'Label and metadata handling for categorization',
        'URL tracking for external references',
        'Status and severity tracking',
      ],
      constraints: [
        'tracker must be 1-100 characters',
        'external_id must be 1-100 characters',
        'title must be 1-500 characters',
        'description must be 5000 characters or less',
      ],
      requiredFields: ['tracker', 'external_id', 'title'],
      optionalFields: [
        'status',
        'description',
        'severity',
        'issue_type',
        'assignee',
        'reporter',
        'labels',
        'url',
        'affected_components',
      ],
    },
    schemaType: IssueSchema,
    typescriptType: 'IssueItem',
    tableName: 'issueLog',
    isImplemented: true,
    introducedIn: '1.0.0',
    relatedTypes: ['decision', 'change', 'release'],
    tags: ['tracking', 'external-systems', 'lifecycle', 'collaboration'],
  },

  decision: {
    kind: 'decision',
    displayName: 'Decision (ADR)',
    category: 'development-lifecycle' as KnowledgeCategory,
    description:
      'Architecture Decision Records (ADR) with immutability constraints for maintaining architectural history',
    useCases: [
      'Architecture decision documentation',
      'Technical choices and rationale',
      'Alternative analysis tracking',
      'Decision history and evolution',
      'Stakeholder communication',
    ],
    validationFeatures: {
      hasSchemaValidation: true,
      supportsDeduplication: true,
      hasImmutabilityConstraints: true, // ADR immutability when accepted
      supportsScopeIsolation: true,
      hasTTLPolicies: true,
    },
    businessRules: {
      rules: [
        'ADR immutability when status is accepted',
        'Scope-based organization',
        'Alternatives considered tracking',
        'Supersedes relationship for decision evolution',
      ],
      constraints: [
        'component must be 1-200 characters',
        'title must be 1-500 characters',
        'rationale is required and immutable when accepted',
      ],
      requiredFields: ['component', 'status', 'title', 'rationale'],
      optionalFields: ['alternatives_considered', 'consequences', 'supersedes'],
    },
    schemaType: DecisionSchema,
    typescriptType: 'DecisionItem',
    tableName: 'adrDecision',
    isImplemented: true,
    introducedIn: '1.0.0',
    relatedTypes: ['issue', 'section', 'change'],
    tags: ['adr', 'architecture', 'immutability', 'decision-making'],
  },

  todo: {
    kind: 'todo',
    displayName: 'Todo',
    category: 'development-lifecycle' as KnowledgeCategory,
    description:
      'Task and todo management with status tracking, priorities, due dates, and assignee management',
    useCases: [
      'Task management and tracking',
      'Sprint planning and execution',
      'Bug tracking and resolution',
      'Feature development tasks',
      'Personal and team productivity',
    ],
    validationFeatures: {
      hasSchemaValidation: true,
      supportsDeduplication: true,
      hasImmutabilityConstraints: false,
      supportsScopeIsolation: true,
      hasTTLPolicies: true,
    },
    businessRules: {
      rules: [
        'Status-based workflow management',
        'Priority handling and ordering',
        'Assignee tracking and responsibility',
        'Due date management with notifications',
      ],
      constraints: [
        'scope must be 1-200 characters',
        'text is required',
        'status must be predefined enum value',
      ],
      requiredFields: ['scope', 'todo_type', 'text', 'status'],
      optionalFields: ['priority', 'assignee', 'due_date', 'closed_at'],
    },
    schemaType: TodoSchema,
    typescriptType: 'TodoItem',
    tableName: 'todoLog',
    isImplemented: true,
    introducedIn: '1.0.0',
    relatedTypes: ['issue', 'change', 'release'],
    tags: ['tasks', 'workflow', 'planning', 'productivity'],
  },

  release_note: {
    kind: 'release_note',
    displayName: 'Release Note',
    category: 'development-lifecycle' as KnowledgeCategory,
    description:
      'Release documentation with version tracking, feature lists, bug fixes, and breaking changes',
    useCases: [
      'Release communication',
      'Change documentation',
      'Release notes generation',
      'Stakeholder updates',
      'Release tracking and history',
    ],
    validationFeatures: {
      hasSchemaValidation: true,
      supportsDeduplication: true,
      hasImmutabilityConstraints: false,
      supportsScopeIsolation: true,
      hasTTLPolicies: true,
    },
    businessRules: {
      rules: [
        'Version tracking with semantic versioning',
        'Release date tracking for chronological ordering',
        'Categorized changes (features, bug fixes, deprecations)',
        'Breaking changes highlighting',
      ],
      constraints: [
        'version must be 1-100 characters',
        'release_date is required datetime',
        'summary is required',
      ],
      requiredFields: ['version', 'release_date', 'summary'],
      optionalFields: ['breaking_changes', 'new_features', 'bug_fixes', 'deprecations'],
    },
    schemaType: ReleaseNoteSchema,
    typescriptType: 'ReleaseNoteItem',
    tableName: 'releaseNote',
    isImplemented: true,
    introducedIn: '1.0.0',
    relatedTypes: ['release', 'change'],
    tags: ['releases', 'communication', 'documentation', 'versioning'],
  },

  ddl: {
    kind: 'ddl',
    displayName: 'DDL',
    category: 'development-lifecycle' as KnowledgeCategory,
    description:
      'Database schema migration tracking with DDL text, checksums, and application timestamps',
    useCases: [
      'Database migration tracking',
      'Schema evolution documentation',
      'Rollback planning',
      'Change audit trails',
      'Development coordination',
    ],
    validationFeatures: {
      hasSchemaValidation: true,
      supportsDeduplication: true,
      hasImmutabilityConstraints: false,
      supportsScopeIsolation: true,
      hasTTLPolicies: true,
    },
    businessRules: {
      rules: [
        'SHA-256 checksum verification for integrity',
        'Migration ID tracking for ordering',
        'Application timestamp for deployment tracking',
        'DDL text storage for rollback capability',
      ],
      constraints: [
        'migration_id must be 1-200 characters',
        'ddl_text is required',
        'checksum must be exactly 64 characters (SHA-256)',
      ],
      requiredFields: ['migration_id', 'ddl_text', 'checksum'],
      optionalFields: ['applied_at', 'description'],
    },
    schemaType: DDLSchema,
    typescriptType: 'DDLItem',
    tableName: 'ddlHistory',
    isImplemented: true,
    introducedIn: '1.0.0',
    relatedTypes: ['release', 'change'],
    tags: ['database', 'migrations', 'schema', 'infrastructure'],
  },

  pr_context: {
    kind: 'pr_context',
    displayName: 'PR Context',
    category: 'development-lifecycle' as KnowledgeCategory,
    description:
      'Pull request context with metadata, expires 30 days post-merge for temporary storage',
    useCases: [
      'Pull request metadata tracking',
      'Code review context preservation',
      'Merge request documentation',
      'Collaboration history',
      'Temporary context storage',
    ],
    validationFeatures: {
      hasSchemaValidation: true,
      supportsDeduplication: true,
      hasImmutabilityConstraints: false,
      supportsScopeIsolation: true,
      hasTTLPolicies: true,
    },
    businessRules: {
      rules: [
        '30-day TTL post-merge for cleanup',
        'Branch tracking for merge context',
        'Status tracking for PR lifecycle',
        'Expiration management for storage optimization',
      ],
      constraints: [
        'pr_number must be positive integer',
        'title must be 1-500 characters',
        'author must be 1-200 characters',
        'base_branch and head_branch required',
      ],
      requiredFields: ['pr_number', 'title', 'author', 'status', 'base_branch', 'head_branch'],
      optionalFields: ['description', 'merged_at', 'expires_at'],
    },
    schemaType: PRContextSchema,
    typescriptType: 'PRContextItem',
    tableName: 'prContext',
    isImplemented: true,
    introducedIn: '1.0.0',
    relatedTypes: ['change', 'release'],
    tags: ['git', 'collaboration', 'temporary', 'code-review'],
  },
};

/**
 * Development Lifecycle knowledge types array
 */
export const DEVELOPMENT_LIFECYCLE_TYPES = [
  'runbook',
  'change',
  'issue',
  'decision',
  'todo',
  'release_note',
  'ddl',
  'pr_context',
] as const;
