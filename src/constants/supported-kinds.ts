/**
 * Cortex Memory MCP - Supported Knowledge Types
 *
 * Single source of truth for all 16 knowledge types supported by the Cortex Memory system.
 * Provides comprehensive metadata, categorization, and validation features for each type.
 *
 * Categories:
 * - Core Graph Extension: entity, relation, observation
 * - Core Document Types: section
 * - Development Lifecycle: runbook, change, issue, decision, todo, release_note, ddl, pr_context
 * - 8-LOG SYSTEM: incident, release, risk, assumption
 *
 * @version 1.0.0 - Authoritative knowledge type registry
 */

import { z } from 'zod';
import {
  SectionSchema,
  RunbookSchema,
  ChangeSchema,
  IssueSchema,
  DecisionSchema,
  TodoSchema,
  ReleaseNoteSchema,
  DDLSchema,
  PRContextSchema,
  EntitySchema,
  RelationSchema,
  ObservationSchema,
  IncidentSchema,
  ReleaseSchema,
  RiskSchema,
  AssumptionSchema,
} from '../schemas/knowledge-types.js';

// ============================================================================
// Type Definitions
// ============================================================================

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
  /** Has comprehensive Zod schema validation */
  hasSchemaValidation: boolean;
  /** Supports content-hash based deduplication */
  supportsDeduplication: boolean;
  /** Has immutability constraints */
  hasImmutabilityConstraints: boolean;
  /** Supports scope-based isolation */
  supportsScopeIsolation: boolean;
  /** Has TTL (time-to-live) policies */
  hasTTLPolicies: boolean;
}

/**
 * Business rules and constraints for knowledge types
 */
export interface BusinessRules {
  /** Key business rules that must be enforced */
  rules: string[];
  /** Critical constraints that cannot be violated */
  constraints: string[];
  /** Valid state transitions if applicable */
  validTransitions?: string[];
  /** Required fields for creation */
  requiredFields: string[];
  /** Optional fields that can be added later */
  optionalFields: string[];
}

/**
 * Metadata for a single knowledge type
 */
export interface KnowledgeTypeMetadata {
  /** Unique identifier for the knowledge type */
  kind: string;
  /** Human-readable display name */
  displayName: string;
  /** Category this type belongs to */
  category: KnowledgeCategory;
  /** Comprehensive description of purpose and use cases */
  description: string;
  /** Example usage scenarios */
  useCases: string[];
  /** Validation capabilities and features */
  validationFeatures: ValidationFeatures;
  /** Business rules and constraints */
  businessRules: BusinessRules;
  /** Corresponding Zod schema reference */
  schemaType: z.ZodType;
  /** Corresponding TypeScript type */
  typescriptType: string;
  /** Database table/collection name */
  tableName: string;
  /** Whether this type is actively implemented */
  isImplemented: boolean;
  /** Version when this type was introduced */
  introducedIn: string;
  /** Related knowledge types */
  relatedTypes: string[];
  /** Tags for filtering and organization */
  tags: string[];
}

// ============================================================================
// Supported Knowledge Types Array
// ============================================================================

/**
 * Simple array of all supported knowledge types
 * Use this for basic validation and enumeration
 */
export const SUPPORTED_KINDS = [
  'entity',
  'relation',
  'observation',
  'section',
  'runbook',
  'change',
  'issue',
  'decision',
  'todo',
  'release_note',
  'ddl',
  'pr_context',
  'incident',
  'release',
  'risk',
  'assumption',
] as const;

/**
 * Type guard to check if a string is a supported knowledge kind
 */
export function isSupportedKind(kind: string): kind is (typeof SUPPORTED_KINDS)[number] {
  return SUPPORTED_KINDS.includes(kind as any);
}

// ============================================================================
// Comprehensive Knowledge Type Metadata
// ============================================================================

/**
 * Detailed metadata for all supported knowledge types
 * This serves as the authoritative source for knowledge type capabilities
 */
export const KNOWLEDGE_TYPE_METADATA: Record<
  (typeof SUPPORTED_KINDS)[number],
  KnowledgeTypeMetadata
> = {
  // Core Graph Extension Types
  entity: {
    kind: 'entity',
    displayName: 'Entity',
    category: 'core-graph-extension',
    description:
      'Flexible entity storage with dynamic schemas for representing core concepts like users, organizations, goals, and preferences',
    useCases: [
      'User profile management',
      'Organization structure tracking',
      'Goal and preference storage',
      'Component and service definitions',
      'Stakeholder management',
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
        'Content-hash based deduplication prevents duplicates',
        'Soft delete pattern for data retention',
        'Scope-based isolation for multi-tenancy',
        'Flexible JSONB schema with no validation constraints',
      ],
      constraints: [
        'entity_type must be 1-100 characters',
        'name must be unique within entity_type',
        'name must be 1-500 characters',
      ],
      requiredFields: ['entity_type', 'name'],
      optionalFields: ['data'],
    },
    schemaType: EntitySchema,
    typescriptType: 'EntityItem',
    tableName: 'knowledgeEntity',
    isImplemented: true,
    introducedIn: '1.0.0',
    relatedTypes: ['relation', 'observation'],
    tags: ['graph', 'flexible', 'core-extension', 'storage'],
  },

  relation: {
    kind: 'relation',
    displayName: 'Relation',
    category: 'core-graph-extension',
    description:
      'Entity relationships that define connections between knowledge items with metadata for weight, confidence, and temporal aspects',
    useCases: [
      'Connecting decisions to issues they resolve',
      'Linking components to their specifications',
      'Building dependency graphs',
      'Tracking stakeholder relationships',
      'Modeling system architectures',
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
        'Both from_entity_id and to_entity_id must be valid UUIDs',
        'Relations can have optional metadata for weighting and confidence',
        'Supports various relation types like resolves, supersedes, references',
      ],
      constraints: [
        'from_entity_type and to_entity_type must be 1-100 characters',
        'relation_type must be 1-100 characters',
        'entity IDs must be valid UUIDs',
      ],
      requiredFields: [
        'from_entity_type',
        'from_entity_id',
        'to_entity_type',
        'to_entity_id',
        'relation_type',
      ],
      optionalFields: ['metadata'],
    },
    schemaType: RelationSchema,
    typescriptType: 'RelationItem',
    tableName: 'knowledgeRelation',
    isImplemented: true,
    introducedIn: '1.0.0',
    relatedTypes: ['entity', 'observation'],
    tags: ['graph', 'relationships', 'core-extension', 'connections'],
  },

  observation: {
    kind: 'observation',
    displayName: 'Observation',
    category: 'core-graph-extension',
    description:
      'Fine-grained fact storage with append-only pattern for tracking detailed information about entities',
    useCases: [
      'Status updates and progress tracking',
      'Metric and measurement logging',
      'Audit trail and activity feeds',
      'Fine-grained fact tracking',
      'Historical record keeping',
    ],
    validationFeatures: {
      hasSchemaValidation: true,
      supportsDeduplication: true,
      hasImmutabilityConstraints: true, // Append-only
      supportsScopeIsolation: true,
      hasTTLPolicies: true,
    },
    businessRules: {
      rules: [
        'Append-only storage pattern for historical integrity',
        'Soft delete lifecycle management',
        'Full-text search with tsquery capabilities',
        'Entity relationship tracking',
      ],
      constraints: [
        'entity_type must be 1-100 characters',
        'entity_id must be valid UUID',
        'observation must be 1+ characters',
      ],
      requiredFields: ['entity_type', 'entity_id', 'observation'],
      optionalFields: ['observation_type', 'metadata'],
    },
    schemaType: ObservationSchema,
    typescriptType: 'ObservationItem',
    tableName: 'knowledgeObservation',
    isImplemented: true,
    introducedIn: '1.0.0',
    relatedTypes: ['entity', 'relation'],
    tags: ['graph', 'append-only', 'facts', 'audit-trail'],
  },

  // Core Document Types
  section: {
    kind: 'section',
    displayName: 'Section',
    category: 'core-document-types',
    description:
      'Document sections with markdown or text content, supporting hierarchical document structures and citation tracking',
    useCases: [
      'Technical documentation',
      'Architecture specifications',
      'Policy documents',
      'Knowledge base articles',
      'Meeting minutes and notes',
    ],
    validationFeatures: {
      hasSchemaValidation: true,
      supportsDeduplication: true,
      hasImmutabilityConstraints: true, // Write-lock when approved
      supportsScopeIsolation: true,
      hasTTLPolicies: true,
    },
    businessRules: {
      rules: [
        'Either body_md or body_text must be provided',
        'Write-lock enforced when tagged as approved',
        'Citation count tracking for references',
        'Hierarchical document structure support',
      ],
      constraints: [
        'title must be 1-500 characters',
        'heading must be 1-300 characters',
        'description must be 5000 characters or less',
      ],
      requiredFields: ['title', 'heading'],
      optionalFields: ['body_md', 'body_text', 'document_id', 'citation_count'],
    },
    schemaType: SectionSchema,
    typescriptType: 'SectionItem',
    tableName: 'section',
    isImplemented: true,
    introducedIn: '1.0.0',
    relatedTypes: ['decision', 'entity'],
    tags: ['documents', 'markdown', 'content', 'specifications'],
  },

  // Development Lifecycle Types
  runbook: {
    kind: 'runbook',
    displayName: 'Runbook',
    category: 'development-lifecycle',
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
    category: 'development-lifecycle',
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
    category: 'development-lifecycle',
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
    category: 'development-lifecycle',
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
    category: 'development-lifecycle',
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
    category: 'development-lifecycle',
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
    category: 'development-lifecycle',
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
    category: 'development-lifecycle',
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

  // 8-LOG SYSTEM Types
  incident: {
    kind: 'incident',
    displayName: 'Incident',
    category: 'eight-log-system',
    description:
      'Comprehensive incident management with severity tracking, timeline documentation, and recovery procedures',
    useCases: [
      'Production incident tracking',
      'Emergency response coordination',
      'Root cause analysis documentation',
      'Post-incident review processes',
      'Service reliability management',
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
        'Severity classification for prioritization',
        'Timeline tracking for incident progression',
        'Impact assessment for business context',
        'Recovery action documentation',
      ],
      constraints: [
        'title must be 1-500 characters',
        'severity is required enum value',
        'impact description is required',
      ],
      requiredFields: ['title', 'severity', 'impact', 'resolution_status'],
      optionalFields: [
        'timeline',
        'root_cause_analysis',
        'affected_services',
        'business_impact',
        'recovery_actions',
      ],
    },
    schemaType: IncidentSchema,
    typescriptType: 'IncidentItem',
    tableName: 'incidentLog',
    isImplemented: true,
    introducedIn: '2.1.0',
    relatedTypes: ['runbook', 'risk', 'decision'],
    tags: ['incident-management', 'reliability', 'emergency', '8-log-system'],
  },

  release: {
    kind: 'release',
    displayName: 'Release',
    category: 'eight-log-system',
    description:
      'Release management with deployment strategies, approval tracking, and rollback planning',
    useCases: [
      'Release planning and coordination',
      'Deployment strategy documentation',
      'Approval workflow tracking',
      'Rollback planning and execution',
      'Release performance monitoring',
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
        'Release type classification (major, minor, patch, hotfix)',
        'Status tracking through release lifecycle',
        'Approval workflow management',
        'Rollback plan requirements',
      ],
      constraints: [
        'version must be 1-100 characters',
        'release_type is required enum',
        'scope description is required',
      ],
      requiredFields: ['version', 'release_type', 'scope', 'status'],
      optionalFields: [
        'release_date',
        'ticket_references',
        'included_changes',
        'deployment_strategy',
        'rollback_plan',
      ],
    },
    schemaType: ReleaseSchema,
    typescriptType: 'ReleaseItem',
    tableName: 'releaseLog',
    isImplemented: true,
    introducedIn: '2.1.0',
    relatedTypes: ['release_note', 'change', 'ddl'],
    tags: ['release-management', 'deployment', 'coordination', '8-log-system'],
  },

  risk: {
    kind: 'risk',
    displayName: 'Risk',
    category: 'eight-log-system',
    description:
      'Risk management with probability assessment, impact analysis, and mitigation strategy tracking',
    useCases: [
      'Risk identification and assessment',
      'Mitigation strategy planning',
      'Risk monitoring and review',
      'Compliance and audit requirements',
      'Proactive risk management',
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
        'Risk categorization (technical, business, operational, security, compliance)',
        'Probability and impact assessment',
        'Mitigation strategy tracking',
        'Owner assignment and review scheduling',
      ],
      constraints: [
        'title must be 1-500 characters',
        'category and risk_level are required enums',
        'impact description is required',
      ],
      requiredFields: [
        'title',
        'category',
        'risk_level',
        'probability',
        'impact_description',
        'status',
      ],
      optionalFields: [
        'trigger_events',
        'mitigation_strategies',
        'owner',
        'review_date',
        'related_decisions',
      ],
    },
    schemaType: RiskSchema,
    typescriptType: 'RiskItem',
    tableName: 'riskLog',
    isImplemented: true,
    introducedIn: '2.1.0',
    relatedTypes: ['decision', 'assumption', 'incident'],
    tags: ['risk-management', 'assessment', 'mitigation', '8-log-system'],
  },

  assumption: {
    kind: 'assumption',
    displayName: 'Assumption',
    category: 'eight-log-system',
    description:
      'Assumption management with validation tracking, impact analysis, and dependency documentation',
    useCases: [
      'Assumption identification and documentation',
      'Validation criteria definition',
      'Impact assessment for invalid assumptions',
      'Dependency tracking and management',
      'Assumption review processes',
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
        'Assumption categorization (technical, business, user, market, resource)',
        'Validation status tracking',
        'Impact assessment for invalid scenarios',
        'Review frequency management',
      ],
      constraints: [
        'title must be 1-500 characters',
        'description and impact_if_invalid are required',
        'category and validation_status are required enums',
      ],
      requiredFields: [
        'title',
        'description',
        'category',
        'validation_status',
        'impact_if_invalid',
      ],
      optionalFields: [
        'validation_criteria',
        'validation_date',
        'owner',
        'related_assumptions',
        'dependencies',
      ],
    },
    schemaType: AssumptionSchema,
    typescriptType: 'AssumptionItem',
    tableName: 'assumptionLog',
    isImplemented: true,
    introducedIn: '2.1.0',
    relatedTypes: ['risk', 'decision', 'observation'],
    tags: ['assumption-management', 'validation', 'planning', '8-log-system'],
  },
};

// ============================================================================
// Helper Functions and Utilities
// ============================================================================

/**
 * Get metadata for a specific knowledge type
 */
export function getKnowledgeTypeMetadata(
  kind: (typeof SUPPORTED_KINDS)[number]
): KnowledgeTypeMetadata {
  const metadata = KNOWLEDGE_TYPE_METADATA[kind];
  if (!metadata) {
    throw new Error(`Unknown knowledge type: ${kind}`);
  }
  return metadata;
}

/**
 * Get all knowledge types in a specific category
 */
export function getKnowledgeTypesByCategory(category: KnowledgeCategory): string[] {
  return Object.values(KNOWLEDGE_TYPE_METADATA)
    .filter((metadata) => metadata.category === category)
    .map((metadata) => metadata.kind);
}

/**
 * Get knowledge types with specific validation features
 */
export function getKnowledgeTypesByValidationFeature(feature: keyof ValidationFeatures): string[] {
  return Object.entries(KNOWLEDGE_TYPE_METADATA)
    .filter(([, metadata]) => metadata.validationFeatures[feature])
    .map(([kind]) => kind);
}

/**
 * Get knowledge types with specific tags
 */
export function getKnowledgeTypesByTag(tag: string): string[] {
  return Object.entries(KNOWLEDGE_TYPE_METADATA)
    .filter(([, metadata]) => metadata.tags.includes(tag))
    .map(([kind]) => kind);
}

/**
 * Get related knowledge types for a given type
 */
export function getRelatedKnowledgeTypes(kind: (typeof SUPPORTED_KINDS)[number]): string[] {
  const metadata = getKnowledgeTypeMetadata(kind);
  return metadata.relatedTypes;
}

/**
 * Check if a knowledge type supports specific validation features
 */
export function supportsValidationFeature(
  kind: (typeof SUPPORTED_KINDS)[number],
  feature: keyof ValidationFeatures
): boolean {
  const metadata = getKnowledgeTypeMetadata(kind);
  return metadata.validationFeatures[feature];
}

/**
 * Validate if a knowledge type is in the expected category
 */
export function validateKnowledgeTypeCategory(
  kind: (typeof SUPPORTED_KINDS)[number],
  expectedCategory: KnowledgeCategory
): boolean {
  const metadata = getKnowledgeTypeMetadata(kind);
  return metadata.category === expectedCategory;
}

// ============================================================================
// Type Guards and Validation
// ============================================================================

/**
 * Type guard for KnowledgeCategory
 */
export function isKnowledgeCategory(value: string): value is KnowledgeCategory {
  return [
    'core-graph-extension',
    'core-document-types',
    'development-lifecycle',
    'eight-log-system',
  ].includes(value);
}

/**
 * Validate knowledge type metadata integrity
 */
export function validateKnowledgeTypeMetadata(): {
  isValid: boolean;
  issues: string[];
} {
  const issues: string[] = [];

  // Check all supported kinds have metadata
  for (const kind of SUPPORTED_KINDS) {
    if (!KNOWLEDGE_TYPE_METADATA[kind]) {
      issues.push(`Missing metadata for knowledge type: ${kind}`);
    }
  }

  // Check metadata consistency
  Object.entries(KNOWLEDGE_TYPE_METADATA).forEach(([kind, metadata]) => {
    if (!SUPPORTED_KINDS.includes(kind as any)) {
      issues.push(`Metadata for unknown knowledge type: ${kind}`);
    }

    if (metadata.kind !== kind) {
      issues.push(`Kind mismatch in metadata for ${kind}: expected ${kind}, got ${metadata.kind}`);
    }

    if (!metadata.tableName) {
      issues.push(`Missing table name for knowledge type: ${kind}`);
    }
  });

  return {
    isValid: issues.length === 0,
    issues,
  };
}

// ============================================================================
// Exports
// ============================================================================
// Types are exported inline above to avoid conflicts

// Re-export for convenience - commonly used combinations
export const CORE_GRAPH_EXTENSION_TYPES = getKnowledgeTypesByCategory('core-graph-extension');
export const CORE_DOCUMENT_TYPES = getKnowledgeTypesByCategory('core-document-types');
export const DEVELOPMENT_LIFECYCLE_TYPES = getKnowledgeTypesByCategory('development-lifecycle');
export const EIGHT_LOG_SYSTEM_TYPES = getKnowledgeTypesByCategory('eight-log-system');

// Validation feature groups
export const IMMUTABLE_TYPES = getKnowledgeTypesByValidationFeature('hasImmutabilityConstraints');
export const DEDUPLICATED_TYPES = getKnowledgeTypesByValidationFeature('supportsDeduplication');
export const SCOPE_ISOLATED_TYPES = getKnowledgeTypesByValidationFeature('supportsScopeIsolation');
export const TTL_SUPPORTED_TYPES = getKnowledgeTypesByValidationFeature('hasTTLPolicies');
