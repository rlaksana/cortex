/**
 * Authorization Service for Cortex MCP
 * Implements scope-based access control with fine-grained permissions
 */

import { logger } from '../../utils/logger.js';
import {
  AuthScope,
  UserRole,
  User,
  ApiKey,
  AuthContext,
  Permission,
  DEFAULT_ROLE_PERMISSIONS,
} from '../../types/auth-types.js';

export interface ResourceAccessRule {
  resource: string;
  action: string;
  required_scopes: AuthScope[];
  conditions?: {
    user_roles?: UserRole[];
    scope_isolation?: boolean;
    owner_only?: boolean;
    project_access?: boolean;
  };
}

export interface AccessDecision {
  allowed: boolean;
  reason: string;
  required_scopes: AuthScope[];
  missing_scopes: AuthScope[];
  conditions_met: boolean;
  details?: Record<string, any>;
}

export class AuthorizationService {
  private resourceRules: Map<string, ResourceAccessRule[]> = new Map();
  private customPermissions: Map<string, Permission[]> = new Map();

  constructor() {
    this.initializeDefaultResourceRules();
  }

  /**
   * Check if a user has permission to access a resource with a specific action
   */
  async checkAccess(
    authContext: AuthContext,
    resource: string,
    action: string,
    context?: Record<string, any>
  ): Promise<AccessDecision> {
    const userScopes = authContext.scopes;

    // Get applicable rules for this resource and action
    const rules = this.getResourceRules(resource, action);

    if (rules.length === 0) {
      return {
        allowed: false,
        reason: `No access rules defined for resource '${resource}' with action '${action}'`,
        required_scopes: [],
        missing_scopes: [],
        conditions_met: false,
      };
    }

    // Evaluate each rule until we find one that allows access
    for (const rule of rules) {
      const decision = await this.evaluateRule(rule, authContext, context);

      if (decision.allowed) {
        logger.debug(
          {
            user: authContext.user.id,
            resource,
            action,
            rule: rule.required_scopes.join(', '),
          },
          'Access granted'
        );
        return decision;
      }
    }

    // No rules allowed access
    const allRequiredScopes = rules.flatMap((rule) => rule.required_scopes);
    const missingScopes = allRequiredScopes.filter((scope) => !userScopes.includes(scope));

    return {
      allowed: false,
      reason: `Insufficient permissions for ${action} on ${resource}`,
      required_scopes: allRequiredScopes,
      missing_scopes: missingScopes,
      conditions_met: false,
    };
  }

  /**
   * Batch check multiple permissions
   */
  async checkMultipleAccess(
    authContext: AuthContext,
    requests: Array<{ resource: string; action: string; context?: Record<string, any> }>
  ): Promise<Map<string, AccessDecision>> {
    const results = new Map<string, AccessDecision>();

    for (const request of requests) {
      const key = `${request.resource}:${request.action}`;
      const decision = await this.checkAccess(
        authContext,
        request.resource,
        request.action,
        request.context
      );
      results.set(key, decision);
    }

    return results;
  }

  /**
   * Get all scopes a user is allowed to have based on their role
   */
  getAllowedScopes(user: User): AuthScope[] {
    const roleConfig = DEFAULT_ROLE_PERMISSIONS[user.role];
    return roleConfig ? roleConfig.max_scopes : [];
  }

  /**
   * Get default scopes for a user role
   */
  getDefaultScopes(user: User): AuthScope[] {
    const roleConfig = DEFAULT_ROLE_PERMISSIONS[user.role];
    return roleConfig ? roleConfig.default_scopes : [];
  }

  /**
   * Validate that a set of scopes is allowed for a user
   */
  validateUserScopes(
    user: User,
    scopes: AuthScope[]
  ): { valid: boolean; invalidScopes: AuthScope[] } {
    const allowedScopes = this.getAllowedScopes(user);
    const invalidScopes = scopes.filter((scope) => !allowedScopes.includes(scope));

    return {
      valid: invalidScopes.length === 0,
      invalidScopes,
    };
  }

  /**
   * Add a custom resource access rule
   */
  addResourceRule(rule: ResourceAccessRule): void {
    const key = `${rule.resource}:${rule.action}`;
    const existingRules = this.resourceRules.get(key) || [];
    existingRules.push(rule);
    this.resourceRules.set(key, existingRules);

    logger.info(
      {
        resource: rule.resource,
        action: rule.action,
        required_scopes: rule.required_scopes,
        conditions: rule.conditions,
      },
      'Added resource access rule'
    );
  }

  /**
   * Remove a resource access rule
   */
  removeResourceRule(resource: string, action: string, index?: number): void {
    const key = `${resource}:${action}`;
    const rules = this.resourceRules.get(key);

    if (rules) {
      if (index !== undefined) {
        rules.splice(index, 1);
      } else {
        this.resourceRules.delete(key);
      }

      if (rules.length === 0) {
        this.resourceRules.delete(key);
      }

      logger.info(
        {
          resource,
          action,
          index,
        },
        'Removed resource access rule'
      );
    }
  }

  /**
   * Add custom permission for a user or API key
   */
  addCustomPermissions(identifier: string, permissions: Permission[]): void {
    this.customPermissions.set(identifier, permissions);
    logger.info({ identifier, count: permissions.length }, 'Added custom permissions');
  }

  /**
   * Remove custom permissions
   */
  removeCustomPermissions(identifier: string): void {
    this.customPermissions.delete(identifier);
    logger.info({ identifier }, 'Removed custom permissions');
  }

  /**
   * Get effective scopes for a user including custom permissions
   */
  getEffectiveScopes(user: User, apiKey?: ApiKey): AuthScope[] {
    const baseScopes = this.getDefaultScopes(user);
    const customPermissions = this.customPermissions.get(user.id) || [];
    const apiKeyPermissions = apiKey ? this.customPermissions.get(apiKey.id) || [] : [];

    // Extract scopes from custom permissions
    const customScopes = [
      ...customPermissions.flatMap((p) => p.required_scopes),
      ...apiKeyPermissions.flatMap((p) => p.required_scopes),
    ];

    // Combine and deduplicate scopes
    const allScopes = [...baseScopes, ...customScopes];
    return [...new Set(allScopes)];
  }

  /**
   * Check if user can access a specific scope
   */
  canAccessScope(authContext: AuthContext, scope: AuthScope): boolean {
    return authContext.scopes.includes(scope);
  }

  /**
   * Check if user can access any of the provided scopes
   */
  canAccessAnyScope(authContext: AuthContext, scopes: AuthScope[]): boolean {
    return scopes.some((scope) => authContext.scopes.includes(scope));
  }

  /**
   * Check if user can access all of the provided scopes
   */
  canAccessAllScopes(authContext: AuthContext, scopes: AuthScope[]): boolean {
    return scopes.every((scope) => authContext.scopes.includes(scope));
  }

  /**
   * Get resource rules for a specific resource and action
   */
  private getResourceRules(resource: string, action: string): ResourceAccessRule[] {
    const key = `${resource}:${action}`;
    return this.resourceRules.get(key) || [];
  }

  /**
   * Evaluate a single resource access rule
   */
  private async evaluateRule(
    rule: ResourceAccessRule,
    authContext: AuthContext,
    context?: Record<string, any>
  ): Promise<AccessDecision> {
    const userScopes = authContext.scopes;

    // Check if user has required scopes
    const hasRequiredScopes = rule.required_scopes.every((scope) => userScopes.includes(scope));
    const missingScopes = rule.required_scopes.filter((scope) => !userScopes.includes(scope));

    if (!hasRequiredScopes) {
      return {
        allowed: false,
        reason: `Missing required scopes: ${missingScopes.join(', ')}`,
        required_scopes: rule.required_scopes,
        missing_scopes: missingScopes,
        conditions_met: false,
      };
    }

    // Check additional conditions
    if (rule.conditions) {
      const conditionsMet = await this.evaluateConditions(rule.conditions, authContext, context);

      if (!conditionsMet) {
        return {
          allowed: false,
          reason: 'Additional access conditions not met',
          required_scopes: rule.required_scopes,
          missing_scopes: [],
          conditions_met: false,
          details: { conditions: rule.conditions },
        };
      }
    }

    return {
      allowed: true,
      reason: 'Access granted',
      required_scopes: rule.required_scopes,
      missing_scopes: [],
      conditions_met: true,
    };
  }

  /**
   * Evaluate additional access conditions
   */
  private async evaluateConditions(
    conditions: ResourceAccessRule['conditions'],
    authContext: AuthContext,
    context?: Record<string, any>
  ): Promise<boolean> {
    if (!conditions) {
      return true;
    }

    // Check user role conditions
    if (conditions.user_roles && !conditions.user_roles.includes(authContext.user.role)) {
      return false;
    }

    // Check scope isolation (user can only access their own data)
    if (conditions.scope_isolation && context) {
      const resourceOwnerId = context.owner_id;
      if (resourceOwnerId && resourceOwnerId !== authContext.user.id) {
        return false;
      }
    }

    // Check owner-only access
    if (conditions.owner_only && context) {
      const resourceOwnerId = context.owner_id;
      if (!resourceOwnerId || resourceOwnerId !== authContext.user.id) {
        return false;
      }
    }

    // Check project access
    if (conditions.project_access && context) {
      const resourceProject = context.project;
      const userProjects = authContext.scopes
        .filter((scope) => scope.startsWith('project:'))
        .map((scope) => scope.replace('project:', ''));

      if (resourceProject && !userProjects.includes(resourceProject)) {
        return false;
      }
    }

    return true;
  }

  /**
   * Initialize default resource access rules
   */
  private initializeDefaultResourceRules(): void {
    // Memory Store rules
    this.addResourceRule({
      resource: 'memory_store',
      action: 'write',
      required_scopes: [AuthScope._MEMORY_WRITE],
    });

    this.addResourceRule({
      resource: 'memory_store',
      action: 'read',
      required_scopes: [AuthScope._MEMORY_READ],
    });

    this.addResourceRule({
      resource: 'memory_store',
      action: 'delete',
      required_scopes: [AuthScope._MEMORY_DELETE],
      conditions: {
        scope_isolation: true, // Users can only delete their own memories
      },
    });

    // Memory Find rules
    this.addResourceRule({
      resource: 'memory_find',
      action: 'read',
      required_scopes: [AuthScope._MEMORY_READ, AuthScope._SEARCH_BASIC],
    });

    this.addResourceRule({
      resource: 'memory_find',
      action: 'deep',
      required_scopes: [AuthScope._SEARCH_DEEP],
    });

    this.addResourceRule({
      resource: 'memory_find',
      action: 'advanced',
      required_scopes: [AuthScope._SEARCH_ADVANCED],
    });

    // Knowledge operations
    this.addResourceRule({
      resource: 'knowledge',
      action: 'read',
      required_scopes: [AuthScope._KNOWLEDGE_READ],
    });

    this.addResourceRule({
      resource: 'knowledge',
      action: 'write',
      required_scopes: [AuthScope._KNOWLEDGE_WRITE],
    });

    this.addResourceRule({
      resource: 'knowledge',
      action: 'delete',
      required_scopes: [AuthScope._KNOWLEDGE_DELETE],
      conditions: {
        user_roles: [UserRole._ADMIN, UserRole._USER], // Only admins and users can delete knowledge
      },
    });

    // System operations
    this.addResourceRule({
      resource: 'system',
      action: 'read',
      required_scopes: [AuthScope._SYSTEM_READ],
      conditions: {
        user_roles: [UserRole._ADMIN],
      },
    });

    this.addResourceRule({
      resource: 'system',
      action: 'manage',
      required_scopes: [AuthScope._SYSTEM_MANAGE],
      conditions: {
        user_roles: [UserRole._ADMIN],
      },
    });

    // User management
    this.addResourceRule({
      resource: 'user',
      action: 'manage',
      required_scopes: [AuthScope._USER_MANAGE],
      conditions: {
        user_roles: [UserRole._ADMIN],
      },
    });

    // API Key management
    this.addResourceRule({
      resource: 'api_key',
      action: 'manage',
      required_scopes: [AuthScope._API_KEY_MANAGE],
      conditions: {
        user_roles: [UserRole._ADMIN, UserRole._USER],
      },
    });

    // Audit operations
    this.addResourceRule({
      resource: 'audit',
      action: 'read',
      required_scopes: [AuthScope._AUDIT_READ],
      conditions: {
        user_roles: [UserRole._ADMIN, UserRole._USER],
      },
    });

    this.addResourceRule({
      resource: 'audit',
      action: 'write',
      required_scopes: [AuthScope._AUDIT_WRITE],
      conditions: {
        user_roles: [UserRole._ADMIN],
      },
    });

    // Scope management
    this.addResourceRule({
      resource: 'scope',
      action: 'manage',
      required_scopes: [AuthScope._SCOPE_MANAGE],
      conditions: {
        user_roles: [UserRole._ADMIN],
      },
    });

    this.addResourceRule({
      resource: 'scope',
      action: 'isolate',
      required_scopes: [AuthScope._SCOPE_ISOLATE],
      conditions: {
        user_roles: [UserRole._ADMIN, UserRole._SERVICE],
      },
    });

    // Disable logging during MCP initialization to prevent stdout contamination
    if (process.env.NODE_ENV !== 'production') {
      // logger.info('Initialized default resource access rules');
    }
  }

  /**
   * Get all resource rules for debugging/auditing
   */
  getAllResourceRules(): Map<string, ResourceAccessRule[]> {
    return new Map(this.resourceRules);
  }

  /**
   * Get all custom permissions for debugging/auditing
   */
  getAllCustomPermissions(): Map<string, Permission[]> {
    return new Map(this.customPermissions);
  }

  /**
   * Validate authorization configuration
   */
  validateConfiguration(): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    // Check if all required scopes are defined in AuthScope enum
    const definedScopes = Object.values(AuthScope);

    for (const [key, rules] of this.resourceRules) {
      for (const rule of rules) {
        for (const scope of rule.required_scopes) {
          if (!definedScopes.includes(scope)) {
            errors.push(`Undefined scope '${scope}' in rule '${key}'`);
          }
        }
      }
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }
}
