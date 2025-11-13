/**
 * 8-LOG SYSTEM Knowledge Types
 *
 * Knowledge types for comprehensive organizational logging and management:
 * - incident: Incident management with severity tracking and recovery procedures
 * - release: Release management with deployment strategies and approval tracking
 * - risk: Risk management with probability assessment and mitigation strategies
 * - assumption: Assumption management with validation tracking and impact analysis
 *
 * @version 2.1.0
 */

import { z } from 'zod';

import {
  AssumptionSchema,
  IncidentSchema,
  ReleaseSchema,
  RiskSchema,
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
 * 8-LOG SYSTEM knowledge type metadata
 */
export const EIGHT_LOG_SYSTEM_METADATA: Record<string, KnowledgeTypeMetadata> = {
  incident: {
    kind: 'incident',
    displayName: 'Incident',
    category: 'eight-log-system' as KnowledgeCategory,
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
    category: 'eight-log-system' as KnowledgeCategory,
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
    category: 'eight-log-system' as KnowledgeCategory,
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
    category: 'eight-log-system' as KnowledgeCategory,
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

/**
 * 8-LOG SYSTEM knowledge types array
 */
export const EIGHT_LOG_SYSTEM_TYPES = ['incident', 'release', 'risk', 'assumption'] as const;
