/**
 * Authentication and authorization type definitions for Cortex MCP
 * Implements JWT-based authentication with RBAC and scope-based authorization
 */

export interface User {
  id: string;
  username: string;
  email: string;
  password_hash: string;
  role: UserRole;
  is_active: boolean;
  created_at: string;
  updated_at: string;
  last_login?: string;
}

export interface ApiKey {
  id: string;
  key_id: string;
  key_hash: string;
  user_id: string;
  name: string;
  scopes: AuthScope[];
  is_active: boolean;
  expires_at?: string;
  created_at: string;
  last_used?: string;
  updated_at?: string;
  description?: string;
}

export interface AuthToken {
  access_token: string;
  refresh_token?: string;
  token_type: 'Bearer';
  expires_in: number;
  scope: string[];
}

export interface TokenPayload {
  sub: string; // user_id
  username: string;
  role: UserRole;
  scopes: string[];
  iat: number; // issued at
  exp: number; // expiration
  jti: string; // JWT ID for token revocation
  session_id?: string;
}

export interface AuthSession {
  id: string;
  user_id: string;
  session_token: string;
  refresh_token?: string;
  ip_address: string;
  user_agent: string;
  created_at: string;
  expires_at: string;
  is_active: boolean;
}

export enum UserRole {
  ADMIN = 'admin',
  USER = 'user',
  READ_ONLY = 'read_only',
  SERVICE = 'service'
}

export enum AuthScope {
  // Memory operations
  MEMORY_READ = 'memory:read',
  MEMORY_WRITE = 'memory:write',
  MEMORY_DELETE = 'memory:delete',

  // Knowledge operations
  KNOWLEDGE_READ = 'knowledge:read',
  KNOWLEDGE_WRITE = 'knowledge:write',
  KNOWLEDGE_DELETE = 'knowledge:delete',

  // Admin operations
  USER_MANAGE = 'user:manage',
  API_KEY_MANAGE = 'api_key:manage',
  SYSTEM_READ = 'system:read',
  SYSTEM_MANAGE = 'system:manage',

  // Audit operations
  AUDIT_READ = 'audit:read',
  AUDIT_WRITE = 'audit:write',

  // Search operations
  SEARCH_BASIC = 'search:basic',
  SEARCH_ADVANCED = 'search:advanced',
  SEARCH_DEEP = 'search:deep',

  // Scope operations
  SCOPE_MANAGE = 'scope:manage',
  SCOPE_ISOLATE = 'scope:isolate'
}

export interface Permission {
  id: string;
  name: string;
  description: string;
  required_scopes: AuthScope[];
  resource_pattern: string;
  action: 'read' | 'write' | 'delete' | 'manage';
}

export interface RolePermissions {
  role: UserRole;
  default_scopes: AuthScope[];
  max_scopes: AuthScope[];
  description: string;
}

export interface AuthContext {
  user: {
    id: string;
    username: string;
    role: UserRole;
  };
  session: {
    id: string;
    ip_address: string;
    user_agent: string;
  };
  scopes: AuthScope[];
  token_jti: string;
}

export interface AuthenticatedRequest {
  auth: AuthContext;
  timestamp: number;
  idempotency_key?: string;
}

export interface SecurityAuditLog {
  id: string;
  event_type: 'auth_success' | 'auth_failure' | 'token_revoked' | 'api_key_created' | 'api_key_updated' | 'api_key_revoked' | 'permission_denied' | 'suspicious_activity';
  user_id?: string;
  session_id?: string;
  api_key_id?: string;
  ip_address: string;
  user_agent: string;
  resource?: string;
  action?: string;
  details: Record<string, any>;
  severity: 'low' | 'medium' | 'high' | 'critical';
  created_at: string;
}

export interface AuthError {
  code: 'INVALID_TOKEN' | 'EXPIRED_TOKEN' | 'INSUFFICIENT_SCOPES' | 'INVALID_API_KEY' | 'USER_INACTIVE' | 'SESSION_EXPIRED' | 'RATE_LIMITED';
  message: string;
  details?: Record<string, any>;
}

export interface AuthMiddlewareConfig {
  required_scopes?: AuthScope[];
  optional_scopes?: AuthScope[];
  allow_api_keys?: boolean;
  require_user_session?: boolean;
  rate_limit?: {
    requests: number;
    window_ms: number;
  };
}

export interface TokenRevocationList {
  jti: string;
  user_id: string;
  revoked_at: string;
  reason: string;
  expires_at: string;
}

// Default role permissions configuration
export const DEFAULT_ROLE_PERMISSIONS: Record<UserRole, RolePermissions> = {
  [UserRole.ADMIN]: {
    role: UserRole.ADMIN,
    default_scopes: [
      AuthScope.MEMORY_READ,
      AuthScope.MEMORY_WRITE,
      AuthScope.MEMORY_DELETE,
      AuthScope.KNOWLEDGE_READ,
      AuthScope.KNOWLEDGE_WRITE,
      AuthScope.KNOWLEDGE_DELETE,
      AuthScope.USER_MANAGE,
      AuthScope.API_KEY_MANAGE,
      AuthScope.SYSTEM_READ,
      AuthScope.SYSTEM_MANAGE,
      AuthScope.AUDIT_READ,
      AuthScope.AUDIT_WRITE,
      AuthScope.SEARCH_BASIC,
      AuthScope.SEARCH_ADVANCED,
      AuthScope.SEARCH_DEEP,
      AuthScope.SCOPE_MANAGE,
      AuthScope.SCOPE_ISOLATE
    ],
    max_scopes: Object.values(AuthScope),
    description: 'Full system access with all permissions'
  },
  [UserRole.USER]: {
    role: UserRole.USER,
    default_scopes: [
      AuthScope.MEMORY_READ,
      AuthScope.MEMORY_WRITE,
      AuthScope.MEMORY_DELETE,
      AuthScope.KNOWLEDGE_READ,
      AuthScope.KNOWLEDGE_WRITE,
      AuthScope.KNOWLEDGE_DELETE,
      AuthScope.SEARCH_BASIC,
      AuthScope.SEARCH_ADVANCED
    ],
    max_scopes: [
      AuthScope.MEMORY_READ,
      AuthScope.MEMORY_WRITE,
      AuthScope.MEMORY_DELETE,
      AuthScope.KNOWLEDGE_READ,
      AuthScope.KNOWLEDGE_WRITE,
      AuthScope.KNOWLEDGE_DELETE,
      AuthScope.SEARCH_BASIC,
      AuthScope.SEARCH_ADVANCED,
      AuthScope.AUDIT_READ
    ],
    description: 'Standard user access for memory and knowledge operations'
  },
  [UserRole.READ_ONLY]: {
    role: UserRole.READ_ONLY,
    default_scopes: [
      AuthScope.MEMORY_READ,
      AuthScope.KNOWLEDGE_READ,
      AuthScope.SEARCH_BASIC
    ],
    max_scopes: [
      AuthScope.MEMORY_READ,
      AuthScope.KNOWLEDGE_READ,
      AuthScope.SEARCH_BASIC,
      AuthScope.AUDIT_READ
    ],
    description: 'Read-only access to memory and knowledge'
  },
  [UserRole.SERVICE]: {
    role: UserRole.SERVICE,
    default_scopes: [
      AuthScope.MEMORY_READ,
      AuthScope.MEMORY_WRITE,
      AuthScope.KNOWLEDGE_READ,
      AuthScope.KNOWLEDGE_WRITE,
      AuthScope.SEARCH_BASIC,
      AuthScope.SEARCH_ADVANCED
    ],
    max_scopes: [
      AuthScope.MEMORY_READ,
      AuthScope.MEMORY_WRITE,
      AuthScope.KNOWLEDGE_READ,
      AuthScope.KNOWLEDGE_WRITE,
      AuthScope.SEARCH_BASIC,
      AuthScope.SEARCH_ADVANCED,
      AuthScope.SCOPE_ISOLATE
    ],
    description: 'Service account access for automated operations'
  }
};

// Resource-to-scope mapping
export const RESOURCE_SCOPE_MAPPING: Record<string, Record<string, AuthScope[]>> = {
  'memory_store': {
    'read': [AuthScope.MEMORY_READ],
    'write': [AuthScope.MEMORY_WRITE],
    'delete': [AuthScope.MEMORY_DELETE]
  },
  'memory_find': {
    'read': [AuthScope.MEMORY_READ, AuthScope.SEARCH_BASIC],
    'deep': [AuthScope.SEARCH_DEEP],
    'advanced': [AuthScope.SEARCH_ADVANCED]
  },
  'knowledge': {
    'read': [AuthScope.KNOWLEDGE_READ],
    'write': [AuthScope.KNOWLEDGE_WRITE],
    'delete': [AuthScope.KNOWLEDGE_DELETE]
  },
  'audit': {
    'read': [AuthScope.AUDIT_READ],
    'write': [AuthScope.AUDIT_WRITE]
  },
  'system': {
    'read': [AuthScope.SYSTEM_READ],
    'manage': [AuthScope.SYSTEM_MANAGE]
  },
  'user': {
    'manage': [AuthScope.USER_MANAGE]
  },
  'api_key': {
    'manage': [AuthScope.API_KEY_MANAGE]
  }
};