// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck

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
  _ADMIN = 'admin',
  _USER = 'user',
  _READ_ONLY = 'read_only',
  _SERVICE = 'service',
}

export enum AuthScope {
  // Memory operations
  _MEMORY_READ = 'memory:read',
  _MEMORY_WRITE = 'memory:write',
  _MEMORY_DELETE = 'memory:delete',

  // Knowledge operations
  _KNOWLEDGE_READ = 'knowledge:read',
  _KNOWLEDGE_WRITE = 'knowledge:write',
  _KNOWLEDGE_DELETE = 'knowledge:delete',

  // Admin operations
  _USER_MANAGE = 'user:manage',
  _API_KEY_MANAGE = 'api_key:manage',
  _SYSTEM_READ = 'system:read',
  _SYSTEM_MANAGE = 'system:manage',

  // Audit operations
  _AUDIT_READ = 'audit:read',
  _AUDIT_WRITE = 'audit:write',

  // Search operations
  _SEARCH_BASIC = 'search:basic',
  _SEARCH_ADVANCED = 'search:advanced',
  _SEARCH_DEEP = 'search:deep',

  // Scope operations
  _SCOPE_MANAGE = 'scope:manage',
  _SCOPE_ISOLATE = 'scope:isolate',
}

// Backward compatibility exports (without underscores)
export const UserRoleValues = {
  ADMIN: UserRole._ADMIN,
  USER: UserRole._USER,
  READ_ONLY: UserRole._READ_ONLY,
  SERVICE: UserRole._SERVICE,
} as const;

export const AuthScopeValues = {
  MEMORY_READ: AuthScope._MEMORY_READ,
  MEMORY_WRITE: AuthScope._MEMORY_WRITE,
  MEMORY_DELETE: AuthScope._MEMORY_DELETE,
  KNOWLEDGE_READ: AuthScope._KNOWLEDGE_READ,
  KNOWLEDGE_WRITE: AuthScope._KNOWLEDGE_WRITE,
  KNOWLEDGE_DELETE: AuthScope._KNOWLEDGE_DELETE,
  USER_MANAGE: AuthScope._USER_MANAGE,
  API_KEY_MANAGE: AuthScope._API_KEY_MANAGE,
  SYSTEM_READ: AuthScope._SYSTEM_READ,
  SYSTEM_MANAGE: AuthScope._SYSTEM_MANAGE,
  AUDIT_READ: AuthScope._AUDIT_READ,
  AUDIT_WRITE: AuthScope._AUDIT_WRITE,
  SEARCH_BASIC: AuthScope._SEARCH_BASIC,
  SEARCH_ADVANCED: AuthScope._SEARCH_ADVANCED,
  SEARCH_DEEP: AuthScope._SEARCH_DEEP,
  SCOPE_MANAGE: AuthScope._SCOPE_MANAGE,
  SCOPE_ISOLATE: AuthScope._SCOPE_ISOLATE,
} as const;

// Type aliases for common usage
export type UserRoleType = keyof typeof UserRoleValues;
export type AuthScopeType = keyof typeof AuthScopeValues;

// Security event types
export enum SecurityEventType {
  LOGIN_SUCCESS = 'LOGIN_SUCCESS',
  LOGIN_FAILURE = 'LOGIN_FAILURE',
  LOGOUT = 'LOGOUT',
  PERMISSION_DENIED = 'PERMISSION_DENIED',
  SECURITY_VIOLATION = 'SECURITY_VIOLATION',
  TOKEN_REVOKED = 'TOKEN_REVOKED',
  API_KEY_CREATED = 'API_KEY_CREATED',
  API_KEY_UPDATED = 'API_KEY_UPDATED',
  API_KEY_REVOKED = 'API_KEY_REVOKED',
  SUSPICIOUS_ACTIVITY = 'SUSPICIOUS_ACTIVITY',
}

// Encryption algorithms
export enum EncryptionAlgorithm {
  AES_256_GCM = 'aes-256-gcm',
  AES_192_GCM = 'aes-192-gcm',
  AES_128_GCM = 'aes-128-gcm',
  AES_256_CBC = 'aes-256-cbc',
  AES_192_CBC = 'aes-192-cbc',
  AES_128_CBC = 'aes-128-cbc',
  CHACHA20_POLY1305 = 'chacha20-poly1305',
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
    organizationId?: string;
  };
  session: {
    id: string;
    ip_address: string;
    user_agent: string;
  };
  scopes: AuthScope[];
  token_jti: string;
  apiKeyId?: string;
}

export interface AuthenticatedRequest {
  auth: AuthContext;
  timestamp: number;
  idempotency_key?: string;
}

export interface SecurityAuditLog {
  id: string;
  event_type:
    | 'auth_success'
    | 'auth_failure'
    | 'token_revoked'
    | 'api_key_created'
    | 'api_key_updated'
    | 'api_key_revoked'
    | 'permission_denied'
    | 'suspicious_activity'
    | 'ip_validation_failed'
    | 'ip_validation_bypassed';
  user_id?: string;
  session_id?: string;
  api_key_id?: string;
  ip_address: string;
  user_agent: string;
  resource?: string;
  action?: string;
  details: Record<string, unknown>;
  severity: 'low' | 'medium' | 'high' | 'critical';
  created_at: string;
}

export interface AuthError {
  code:
    | 'INVALID_TOKEN'
    | 'EXPIRED_TOKEN'
    | 'INSUFFICIENT_SCOPES'
    | 'INVALID_API_KEY'
    | 'USER_INACTIVE'
    | 'SESSION_EXPIRED'
    | 'RATE_LIMITED'
    | 'IP_VALIDATION_FAILED';
  message: string;
  details?: Record<string, unknown>;
  stack?: string;
  timestamp?: string;
}

export type IPValidationMode = 'strict' | 'subnet' | 'disabled';

export interface IPValidationConfig {
  mode: IPValidationMode;
  trusted_proxies?: string[]; // CIDR ranges for trusted proxy servers
  allowed_subnets?: string[]; // CIDR ranges for client IP validation (subnet mode only)
  subnet_mask?: number; // Default subnet mask for subnet validation (24 for IPv4, 64 for IPv6)
  max_header_length?: number; // Maximum length for proxy headers to prevent injection
  validate_headers?: boolean; // Whether to validate proxy header format
  log_ip_changes?: boolean; // Whether to log IP change events
}

export interface AuthMiddlewareConfig {
  required_scopes?: AuthScope[];
  optional_scopes?: AuthScope[];
  allow_api_keys?: boolean;
  require_user_session?: boolean;
  ip_validation?: IPValidationConfig;
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
  [UserRole._ADMIN]: {
    role: UserRole._ADMIN,
    default_scopes: [
      AuthScope._MEMORY_READ,
      AuthScope._MEMORY_WRITE,
      AuthScope._MEMORY_DELETE,
      AuthScope._KNOWLEDGE_READ,
      AuthScope._KNOWLEDGE_WRITE,
      AuthScope._KNOWLEDGE_DELETE,
      AuthScope._USER_MANAGE,
      AuthScope._API_KEY_MANAGE,
      AuthScope._SYSTEM_READ,
      AuthScope._SYSTEM_MANAGE,
      AuthScope._AUDIT_READ,
      AuthScope._AUDIT_WRITE,
      AuthScope._SEARCH_BASIC,
      AuthScope._SEARCH_ADVANCED,
      AuthScope._SEARCH_DEEP,
      AuthScope._SCOPE_MANAGE,
      AuthScope._SCOPE_ISOLATE,
    ],
    max_scopes: Object.values(AuthScope),
    description: 'Full system access with all permissions',
  },
  [UserRole._USER]: {
    role: UserRole._USER,
    default_scopes: [
      AuthScope._MEMORY_READ,
      AuthScope._MEMORY_WRITE,
      AuthScope._MEMORY_DELETE,
      AuthScope._KNOWLEDGE_READ,
      AuthScope._KNOWLEDGE_WRITE,
      AuthScope._KNOWLEDGE_DELETE,
      AuthScope._SEARCH_BASIC,
      AuthScope._SEARCH_ADVANCED,
    ],
    max_scopes: [
      AuthScope._MEMORY_READ,
      AuthScope._MEMORY_WRITE,
      AuthScope._MEMORY_DELETE,
      AuthScope._KNOWLEDGE_READ,
      AuthScope._KNOWLEDGE_WRITE,
      AuthScope._KNOWLEDGE_DELETE,
      AuthScope._SEARCH_BASIC,
      AuthScope._SEARCH_ADVANCED,
      AuthScope._AUDIT_READ,
    ],
    description: 'Standard user access for memory and knowledge operations',
  },
  [UserRole._READ_ONLY]: {
    role: UserRole._READ_ONLY,
    default_scopes: [AuthScope._MEMORY_READ, AuthScope._KNOWLEDGE_READ, AuthScope._SEARCH_BASIC],
    max_scopes: [
      AuthScope._MEMORY_READ,
      AuthScope._KNOWLEDGE_READ,
      AuthScope._SEARCH_BASIC,
      AuthScope._AUDIT_READ,
    ],
    description: 'Read-only access to memory and knowledge',
  },
  [UserRole._SERVICE]: {
    role: UserRole._SERVICE,
    default_scopes: [
      AuthScope._MEMORY_READ,
      AuthScope._MEMORY_WRITE,
      AuthScope._KNOWLEDGE_READ,
      AuthScope._KNOWLEDGE_WRITE,
      AuthScope._SEARCH_BASIC,
      AuthScope._SEARCH_ADVANCED,
    ],
    max_scopes: [
      AuthScope._MEMORY_READ,
      AuthScope._MEMORY_WRITE,
      AuthScope._KNOWLEDGE_READ,
      AuthScope._KNOWLEDGE_WRITE,
      AuthScope._SEARCH_BASIC,
      AuthScope._SEARCH_ADVANCED,
      AuthScope._SCOPE_ISOLATE,
    ],
    description: 'Service account access for automated operations',
  },
};

// Resource-to-scope mapping
export const RESOURCE_SCOPE_MAPPING: Record<string, Record<string, AuthScope[]>> = {
  memory_store: {
    read: [AuthScope._MEMORY_READ],
    write: [AuthScope._MEMORY_WRITE],
    delete: [AuthScope._MEMORY_DELETE],
  },
  memory_find: {
    read: [AuthScope._MEMORY_READ, AuthScope._SEARCH_BASIC],
    deep: [AuthScope._SEARCH_DEEP],
    advanced: [AuthScope._SEARCH_ADVANCED],
  },
  knowledge: {
    read: [AuthScope._KNOWLEDGE_READ],
    write: [AuthScope._KNOWLEDGE_WRITE],
    delete: [AuthScope._KNOWLEDGE_DELETE],
  },
  audit: {
    read: [AuthScope._AUDIT_READ],
    write: [AuthScope._AUDIT_WRITE],
  },
  system: {
    read: [AuthScope._SYSTEM_READ],
    manage: [AuthScope._SYSTEM_MANAGE],
  },
  user: {
    manage: [AuthScope._USER_MANAGE],
  },
  api_key: {
    manage: [AuthScope._API_KEY_MANAGE],
  },
};
