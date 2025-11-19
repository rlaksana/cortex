/**
 * Entity Type Guards for Database Results
 *
 * Provides comprehensive type guards for database entities that come back
 * as `unknown` from database operations, enabling type-safe property access.
 *
 * This file implements the research-backed strategy for systematic property
 * access resolution using runtime type validation.
 */

import type { JSONValue } from './index.js';
import { hasBooleanProperty, hasObjectProperty, hasProperty,hasStringProperty } from '../utils/type-fixes.js';

// ============================================================================
// User Entity Type Guards
// ============================================================================

export interface UserEntity {
  id: string;
  username: string;
  email: string;
  password_hash: string;
  role: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
  last_login?: string;
  [key: string]: unknown; // Allow additional properties
}

export function isUserEntity(obj: unknown): obj is UserEntity {
  return (
    typeof obj === 'object' &&
    obj !== null &&
    hasStringProperty(obj, 'id') &&
    hasStringProperty(obj, 'username') &&
    hasStringProperty(obj, 'email') &&
    hasStringProperty(obj, 'password_hash') &&
    hasStringProperty(obj, 'role') &&
    hasBooleanProperty(obj, 'is_active') &&
    hasStringProperty(obj, 'created_at') &&
    hasStringProperty(obj, 'updated_at')
  );
}

export function isPartialUserEntity(obj: unknown): obj is Partial<UserEntity> {
  return typeof obj === 'object' && obj !== null;
}

// ============================================================================
// API Key Entity Type Guards
// ============================================================================

export interface APIKeyEntity {
  id: string;
  key_id: string;
  key_hash: string;
  user_id: string;
  name: string;
  description?: string;
  scopes: string[];
  is_active: boolean;
  expires_at?: string;
  created_at: string;
  updated_at: string;
  last_used_at?: string;
  [key: string]: unknown;
}

export function isAPIKeyEntity(obj: unknown): obj is APIKeyEntity {
  return (
    typeof obj === 'object' &&
    obj !== null &&
    hasStringProperty(obj, 'id') &&
    hasStringProperty(obj, 'key_id') &&
    hasStringProperty(obj, 'key_hash') &&
    hasStringProperty(obj, 'user_id') &&
    hasStringProperty(obj, 'name') &&
    hasProperty(obj, 'scopes') && Array.isArray((obj as unknown).scopes) &&
    hasBooleanProperty(obj, 'is_active') &&
    hasStringProperty(obj, 'created_at') &&
    hasStringProperty(obj, 'updated_at')
  );
}

// ============================================================================
// Token Revocation Entity Type Guards
// ============================================================================

export interface TokenRevocationEntity {
  id: string;
  token_id: string;
  user_id: string;
  revoked_at: string;
  reason?: string;
  revoked_by?: string;
  expires_at?: string;
  [key: string]: unknown;
}

export function isTokenRevocationEntity(obj: unknown): obj is TokenRevocationEntity {
  return (
    typeof obj === 'object' &&
    obj !== null &&
    hasStringProperty(obj, 'id') &&
    hasStringProperty(obj, 'token_id') &&
    hasStringProperty(obj, 'user_id') &&
    hasStringProperty(obj, 'revoked_at')
  );
}

// ============================================================================
// Audit Event Entity Type Guards
// ============================================================================

export interface AuditEventEntity {
  id: string;
  table_name: string;
  operation: string;
  user_id?: string;
  old_data?: JSONValue;
  new_data?: JSONValue;
  changed_by?: string;
  record_id?: string;
  event_type?: string;
  changed_at?: string;
  created_at: string;
  [key: string]: unknown;
}

export function isAuditEventEntity(obj: unknown): obj is AuditEventEntity {
  return (
    typeof obj === 'object' &&
    obj !== null &&
    hasStringProperty(obj, 'id') &&
    hasStringProperty(obj, 'table_name') &&
    hasStringProperty(obj, 'operation') &&
    hasStringProperty(obj, 'created_at')
  );
}

// ============================================================================
// Security Event Entity Type Guards
// ============================================================================

export interface SecurityEventEntity {
  id: string;
  event_type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  user_id?: string;
  ip_address?: string;
  user_agent?: string;
  details?: JSONValue;
  resolved: boolean;
  resolved_at?: string;
  resolved_by?: string;
  created_at: string;
  updated_at: string;
  [key: string]: unknown;
}

export function isSecurityEventEntity(obj: unknown): obj is SecurityEventEntity {
  return (
    typeof obj === 'object' &&
    obj !== null &&
    hasStringProperty(obj, 'id') &&
    hasStringProperty(obj, 'event_type') &&
    hasStringProperty(obj, 'severity') &&
    hasStringProperty(obj, 'description') &&
    hasBooleanProperty(obj, 'resolved') &&
    hasStringProperty(obj, 'created_at') &&
    hasStringProperty(obj, 'updated_at')
  );
}

// ============================================================================
// Auth Instance Entity Type Guards
// ============================================================================

export interface AuthInstanceEntity {
  id: string;
  instance_id: string;
  user_id: string;
  session_token: string;
  refresh_token?: string;
  ip_address?: string;
  user_agent?: string;
  is_active: boolean;
  expires_at?: string;
  created_at: string;
  updated_at: string;
  last_accessed_at?: string;
  [key: string]: unknown;
}

export function isAuthInstanceEntity(obj: unknown): obj is AuthInstanceEntity {
  return (
    typeof obj === 'object' &&
    obj !== null &&
    hasStringProperty(obj, 'id') &&
    hasStringProperty(obj, 'instance_id') &&
    hasStringProperty(obj, 'user_id') &&
    hasStringProperty(obj, 'session_token') &&
    hasBooleanProperty(obj, 'is_active') &&
    hasStringProperty(obj, 'created_at') &&
    hasStringProperty(obj, 'updated_at')
  );
}

// ============================================================================
// Knowledge Entity Type Guards
// ============================================================================

export interface KnowledgeEntity {
  id: string;
  kind: string;
  content: string;
  scope: Record<string, unknown>;
  data: JSONValue;
  metadata?: JSONValue;
  created_at: string;
  updated_at: string;
  expiry_at?: string;
  [key: string]: unknown;
}

export function isKnowledgeEntity(obj: unknown): obj is KnowledgeEntity {
  return (
    typeof obj === 'object' &&
    obj !== null &&
    hasStringProperty(obj, 'id') &&
    hasStringProperty(obj, 'kind') &&
    hasStringProperty(obj, 'content') &&
    hasObjectProperty(obj, 'scope') &&
    hasObjectProperty(obj, 'data') &&
    hasStringProperty(obj, 'created_at') &&
    hasStringProperty(obj, 'updated_at')
  );
}

// ============================================================================
// Section Entity Type Guards
// ============================================================================

export interface SectionEntity extends KnowledgeEntity {
  kind: 'section';
  data: {
    title?: string;
    heading?: string;
    body_md?: string;
    body_text?: string;
    body_jsonb?: JSONValue;
    citation_count?: number;
    [key: string]: unknown;
  };
}

export function isSectionEntity(obj: unknown): obj is SectionEntity {
  return (
    isKnowledgeEntity(obj) &&
    obj.kind === 'section' &&
    typeof obj.data === 'object' &&
    obj.data !== null
  );
}

// ============================================================================
// Runbook Entity Type Guards
// ============================================================================

export interface RunbookEntity extends KnowledgeEntity {
  kind: 'runbook';
  data: {
    service: string;
    steps: JSONValue;
    title?: string;
    description?: string;
    triggers?: JSONValue;
    owner?: string;
    last_verified_at?: string;
    [key: string]: unknown;
  };
}

export function isRunbookEntity(obj: unknown): obj is RunbookEntity {
  return (
    isKnowledgeEntity(obj) &&
    obj.kind === 'runbook' &&
    typeof obj.data === 'object' &&
    obj.data !== null &&
    hasStringProperty(obj.data, 'service')
  );
}

// ============================================================================
// Issue Entity Type Guards
// ============================================================================

export interface IssueEntity extends KnowledgeEntity {
  kind: 'issue';
  data: {
    tracker?: string;
    external_id?: string;
    title: string;
    status: string;
    description?: string;
    assignee?: string;
    labels?: JSONValue;
    priority?: string;
    [key: string]: unknown;
  };
}

export function isIssueEntity(obj: unknown): obj is IssueEntity {
  return (
    isKnowledgeEntity(obj) &&
    obj.kind === 'issue' &&
    typeof obj.data === 'object' &&
    obj.data !== null &&
    hasStringProperty(obj.data, 'title') &&
    hasStringProperty(obj.data, 'status')
  );
}

// ============================================================================
// Decision Entity Type Guards
// ============================================================================

export interface DecisionEntity extends KnowledgeEntity {
  kind: 'decision';
  data: {
    title: string;
    decision: string;
    rationale?: string;
    alternatives?: JSONValue;
    impact?: string;
    stakeholders?: JSONValue;
    [key: string]: unknown;
  };
}

export function isDecisionEntity(obj: unknown): obj is DecisionEntity {
  return (
    isKnowledgeEntity(obj) &&
    obj.kind === 'decision' &&
    typeof obj.data === 'object' &&
    obj.data !== null &&
    hasStringProperty(obj.data, 'title') &&
    hasStringProperty(obj.data, 'decision')
  );
}

// ============================================================================
// Todo Entity Type Guards
// ============================================================================

export interface TodoEntity extends KnowledgeEntity {
  kind: 'todo';
  data: {
    title: string;
    description?: string;
    status: 'pending' | 'in_progress' | 'completed' | 'cancelled';
    assignee?: string;
    priority?: 'low' | 'medium' | 'high';
    due_date?: string;
    tags?: JSONValue;
    [key: string]: unknown;
  };
}

export function isTodoEntity(obj: unknown): obj is TodoEntity {
  return (
    isKnowledgeEntity(obj) &&
    obj.kind === 'todo' &&
    typeof obj.data === 'object' &&
    obj.data !== null &&
    hasStringProperty(obj.data, 'title') &&
    hasStringProperty(obj.data, 'status')
  );
}

// ============================================================================
// Entity Factory Functions
// ============================================================================

/**
 * Create a typed user entity from unknown database result
 */
export function createUserEntity(obj: unknown): UserEntity | null {
  if (!isUserEntity(obj)) return null;
  return obj;
}

/**
 * Create a typed API key entity from unknown database result
 */
export function createAPIKeyEntity(obj: unknown): APIKeyEntity | null {
  if (!isAPIKeyEntity(obj)) return null;
  return obj;
}

/**
 * Create a typed token revocation entity from unknown database result
 */
export function createTokenRevocationEntity(obj: unknown): TokenRevocationEntity | null {
  if (!isTokenRevocationEntity(obj)) return null;
  return obj;
}

/**
 * Create a typed audit event entity from unknown database result
 */
export function createAuditEventEntity(obj: unknown): AuditEventEntity | null {
  if (!isAuditEventEntity(obj)) return null;
  return obj;
}

/**
 * Create a typed security event entity from unknown database result
 */
export function createSecurityEventEntity(obj: unknown): SecurityEventEntity | null {
  if (!isSecurityEventEntity(obj)) return null;
  return obj;
}

/**
 * Create a typed auth instance entity from unknown database result
 */
export function createAuthInstanceEntity(obj: unknown): AuthInstanceEntity | null {
  if (!isAuthInstanceEntity(obj)) return null;
  return obj;
}

// ============================================================================
// Entity Collection Type Guards
// ============================================================================

/**
 * Type guard for arrays of user entities
 */
export function isUserEntityArray(arr: unknown): arr is UserEntity[] {
  return Array.isArray(arr) && arr.every(isUserEntity);
}

/**
 * Type guard for arrays of API key entities
 */
export function isAPIKeyEntityArray(arr: unknown): arr is APIKeyEntity[] {
  return Array.isArray(arr) && arr.every(isAPIKeyEntity);
}

/**
 * Type guard for arrays of token revocation entities
 */
export function isTokenRevocationEntityArray(arr: unknown): arr is TokenRevocationEntity[] {
  return Array.isArray(arr) && arr.every(isTokenRevocationEntity);
}

/**
 * Type guard for arrays of audit event entities
 */
export function isAuditEventEntityArray(arr: unknown): arr is AuditEventEntity[] {
  return Array.isArray(arr) && arr.every(isAuditEventEntity);
}

/**
 * Type guard for arrays of knowledge entities
 */
export function isKnowledgeEntityArray(arr: unknown): arr is KnowledgeEntity[] {
  return Array.isArray(arr) && arr.every(isKnowledgeEntity);
}

// ============================================================================
// Entity Utility Functions
// ============================================================================

/**
 * Safely extract user entities from unknown database results
 */
export function extractUserEntities(results: unknown[]): UserEntity[] {
  return results.filter(isUserEntity);
}

/**
 * Safely extract API key entities from unknown database results
 */
export function extractAPIKeyEntities(results: unknown[]): APIKeyEntity[] {
  return results.filter(isAPIKeyEntity);
}

/**
 * Safely extract token revocation entities from unknown database results
 */
export function extractTokenRevocationEntities(results: unknown[]): TokenRevocationEntity[] {
  return results.filter(isTokenRevocationEntity);
}

/**
 * Safely extract audit event entities from unknown database results
 */
export function extractAuditEventEntities(results: unknown[]): AuditEventEntity[] {
  return results.filter(isAuditEventEntity);
}

/**
 * Safely extract knowledge entities from unknown database results
 */
export function extractKnowledgeEntities(results: unknown[]): KnowledgeEntity[] {
  return results.filter(isKnowledgeEntity);
}

/**
 * Get the first entity of a specific type from unknown results
 */
export function getFirstEntity<T>(
  results: unknown[],
  typeGuard: (obj: unknown) => obj is T
): T | null {
  const entity = results.find(typeGuard);
  return entity || null;
}