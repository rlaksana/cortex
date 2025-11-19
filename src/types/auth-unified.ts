/**
 * Unified Authentication Type Definitions
 *
 * Resolves conflicts between different AuthContext definitions
 * and provides compatibility adapters for smooth migration.
 */

// ============================================================================
// AUTHENTICATED USER TYPES
// ============================================================================

/**
 * Standardized User interface that works across all contexts
 */
export interface User {
  id: string;
  username: string;
  email: string;
  password_hash?: string; // Optional for service interfaces
  role: UserRole;
  is_active: boolean;
  created_at: string;
  updated_at: string;
  last_login?: string;
  organizationId?: string; // Optional field for compatibility
}

/**
 * User role enumeration
 */
export type UserRole = 'admin' | 'user' | 'readonly' | 'moderator';

// ============================================================================
// UNIFIED AUTH CONTEXT
// ============================================================================

/**
 * Unified AuthContext that combines the simplicity of service-interfaces
 * with the richness of auth-types
 */
export interface AuthContext {
  // Simple fields from service-interfaces
  userId?: string;
  orgId?: string;
  projectId?: string;
  permissions?: string[];

  // Rich user structure from auth-types (optional for backward compatibility)
  user?: {
    id: string;
    username: string;
    role: UserRole;
    organizationId?: string;
  };

  // Session information (optional)
  session?: {
    id: string;
    ip_address: string;
    user_agent: string;
    created_at: string;
    expires_at?: string;
  };

  // Token information (optional)
  token?: {
    jti: string;
    scopes: string[];
    iat: number;
    exp: number;
  };
}

// ============================================================================
// AUTHENTICATION TOKEN TYPES
// ============================================================================

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

// ============================================================================
// API KEY TYPES
// ============================================================================

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

export type AuthScope = string;

// ============================================================================
// TYPE CONVERSION UTILITIES
// ============================================================================

/**
 * Convert simple AuthContext (service-interfaces) to unified AuthContext
 */
export function toUnifiedAuthContext(simple: {
  userId?: string;
  orgId?: string;
  projectId?: string;
  permissions?: string[];
}): AuthContext {
  return {
    userId: simple.userId,
    orgId: simple.orgId,
    projectId: simple.projectId,
    permissions: simple.permissions,
  };
}

/**
 * Convert rich AuthContext (auth-types) to unified AuthContext
 */
export function fromRichAuthContext(rich: {
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
    created_at: string;
    expires_at?: string;
  };
}): AuthContext {
  return {
    userId: rich.user.id,
    orgId: rich.user.organizationId,
    user: rich.user,
    session: rich.session,
    permissions: [], // Default to empty, can be populated from roles
  };
}

/**
 * Convert unified AuthContext to simple format (service-interfaces)
 */
export function toSimpleAuthContext(unified: AuthContext): {
  userId?: string;
  orgId?: string;
  projectId?: string;
  permissions?: string[];
} {
  return {
    userId: unified.userId ?? unified.user?.id,
    orgId: unified.orgId ?? unified.user?.organizationId,
    projectId: unified.projectId,
    permissions: unified.permissions,
  };
}

/**
 * Convert unified AuthContext to User type
 */
export function toUser(unified: AuthContext): User | null {
  const userId = unified.userId ?? unified.user?.id;
  if (!userId) {
    return null;
  }

  return {
    id: userId,
    username: unified.user?.username ?? '',
    email: '', // Not available in simple context
    role: unified.user?.role ?? 'user',
    is_active: true,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    organizationId: unified.orgId ?? unified.user?.organizationId,
  };
}

/**
 * Type guard to check if value is a valid AuthContext
 */
export function isAuthContext(value: unknown): value is AuthContext {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }

  const ctx = value as Record<string, unknown>;

  // At least one identifier should be present
  const hasUserId = typeof ctx.userId === 'string';
  const hasUser = ctx.user && typeof ctx.user === 'object' && typeof (ctx.user as any).id === 'string';

  return hasUserId || hasUser;
}

/**
 * Safe conversion from unknown to AuthContext
 */
export function asAuthContext(value: unknown): AuthContext | null {
  if (isAuthContext(value)) {
    return value;
  }

  // Try to convert from simple format
  if (
    value &&
    typeof value === 'object' &&
    !Array.isArray(value)
  ) {
    const simple = value as Record<string, unknown>;

    if (
      (typeof simple.userId === 'string' || typeof simple.orgId === 'string') &&
      (typeof simple.permissions === 'undefined' || Array.isArray(simple.permissions))
    ) {
      return toUnifiedAuthContext({
        userId: simple.userId as string | undefined,
        orgId: simple.orgId as string | undefined,
        projectId: simple.projectId as string | undefined,
        permissions: simple.permissions as string[] | undefined,
      });
    }
  }

  return null;
}