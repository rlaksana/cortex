/**
 * Unit tests for AuthorizationService
 * Tests scope-based access control, resource permissions, and role-based authorization
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { AuthorizationService } from '../../../src/services/auth/authorization-service.js';
import { AuthContext, AuthScope, UserRole } from '../../../src/types/auth-types.js';

describe('AuthorizationService', () => {
  let authorizationService: AuthorizationService;
  let testAuthContext: AuthContext;

  beforeEach(() => {
    authorizationService = new AuthorizationService();

    testAuthContext = {
      user: {
        id: 'test-user-id',
        username: 'testuser',
        role: UserRole.USER
      },
      session: {
        id: 'test-session-id',
        ip_address: '127.0.0.1',
        user_agent: 'test-agent'
      },
      scopes: [AuthScope.MEMORY_READ, AuthScope.MEMORY_WRITE, AuthScope.SEARCH_BASIC],
      token_jti: 'test-token-id'
    };
  });

  describe('Access Control', () => {
    it('should allow access with correct scopes', async () => {
      const decision = await authorizationService.checkAccess(
        testAuthContext,
        'memory_store',
        'write'
      );

      expect(decision.allowed).toBe(true);
      expect(decision.reason).toBe('Access granted');
      expect(decision.required_scopes).toContain(AuthScope.MEMORY_WRITE);
      expect(decision.missing_scopes).toEqual([]);
      expect(decision.conditions_met).toBe(true);
    });

    it('should deny access with insufficient scopes', async () => {
      const decision = await authorizationService.checkAccess(
        testAuthContext,
        'system',
        'manage'
      );

      expect(decision.allowed).toBe(false);
      expect(decision.reason).toContain('Insufficient permissions');
      expect(decision.required_scopes.length).toBeGreaterThan(0);
      expect(decision.missing_scopes.length).toBeGreaterThan(0);
      expect(decision.conditions_met).toBe(false);
    });

    it('should allow admin access to system resources', async () => {
      const adminContext: AuthContext = {
        user: {
          id: 'admin-user-id',
          username: 'admin',
          role: UserRole.ADMIN
        },
        session: {
          id: 'admin-session-id',
          ip_address: '127.0.0.1',
          user_agent: 'admin-agent'
        },
        scopes: [AuthScope.SYSTEM_MANAGE, AuthScope.USER_MANAGE],
        token_jti: 'admin-token-id'
      };

      const decision = await authorizationService.checkAccess(
        adminContext,
        'system',
        'manage'
      );

      expect(decision.allowed).toBe(true);
      expect(decision.reason).toBe('Access granted');
    });

    it('should deny access to undefined resources', async () => {
      const decision = await authorizationService.checkAccess(
        testAuthContext,
        'undefined_resource',
        'unknown_action'
      );

      expect(decision.allowed).toBe(false);
      expect(decision.reason).toContain('No access rules defined');
    });
  });

  describe('Memory Store Operations', () => {
    it('should allow memory read with correct scopes', async () => {
      const decision = await authorizationService.checkAccess(
        testAuthContext,
        'memory_store',
        'read'
      );

      expect(decision.allowed).toBe(true);
      expect(decision.required_scopes).toContain(AuthScope.MEMORY_READ);
    });

    it('should allow memory write with correct scopes', async () => {
      const decision = await authorizationService.checkAccess(
        testAuthContext,
        'memory_store',
        'write'
      );

      expect(decision.allowed).toBe(true);
      expect(decision.required_scopes).toContain(AuthScope.MEMORY_WRITE);
    });

    it('should deny memory delete without delete scope', async () => {
      const decision = await authorizationService.checkAccess(
        testAuthContext,
        'memory_store',
        'delete'
      );

      expect(decision.allowed).toBe(false);
      expect(decision.required_scopes).toContain(AuthScope.MEMORY_DELETE);
      expect(decision.missing_scopes).toContain(AuthScope.MEMORY_DELETE);
    });

    it('should enforce scope isolation for delete operations', async () => {
      const deleteContext: AuthContext = {
        ...testAuthContext,
        scopes: [...testAuthContext.scopes, AuthScope.MEMORY_DELETE]
      };

      const decision = await authorizationService.checkAccess(
        deleteContext,
        'memory_store',
        'delete',
        { owner_id: 'different-user-id' } // Resource owned by different user
      );

      expect(decision.allowed).toBe(false);
      expect(decision.reason).toContain('Additional access conditions not met');
    });

    it('should allow delete for resource owner', async () => {
      const deleteContext: AuthContext = {
        ...testAuthContext,
        scopes: [...testAuthContext.scopes, AuthScope.MEMORY_DELETE]
      };

      const decision = await authorizationService.checkAccess(
        deleteContext,
        'memory_store',
        'delete',
        { owner_id: 'test-user-id' } // Resource owned by same user
      );

      expect(decision.allowed).toBe(true);
    });
  });

  describe('Memory Find Operations', () => {
    it('should allow basic search with correct scopes', async () => {
      const decision = await authorizationService.checkAccess(
        testAuthContext,
        'memory_find',
        'read'
      );

      expect(decision.allowed).toBe(true);
      expect(decision.required_scopes).toEqual([AuthScope.MEMORY_READ, AuthScope.SEARCH_BASIC]);
    });

    it('should deny deep search without deep scope', async () => {
      const decision = await authorizationService.checkAccess(
        testAuthContext,
        'memory_find',
        'deep'
      );

      expect(decision.allowed).toBe(false);
      expect(decision.required_scopes).toContain(AuthScope.SEARCH_DEEP);
      expect(decision.missing_scopes).toContain(AuthScope.SEARCH_DEEP);
    });

    it('should allow deep search with correct scopes', async () => {
      const deepSearchContext: AuthContext = {
        ...testAuthContext,
        scopes: [...testAuthContext.scopes, AuthScope.SEARCH_DEEP]
      };

      const decision = await authorizationService.checkAccess(
        deepSearchContext,
        'memory_find',
        'deep'
      );

      expect(decision.allowed).toBe(true);
      expect(decision.required_scopes).toContain(AuthScope.SEARCH_DEEP);
    });

    it('should deny advanced search without advanced scope', async () => {
      const decision = await authorizationService.checkAccess(
        testAuthContext,
        'memory_find',
        'advanced'
      );

      expect(decision.allowed).toBe(false);
      expect(decision.required_scopes).toContain(AuthScope.SEARCH_ADVANCED);
      expect(decision.missing_scopes).toContain(AuthScope.SEARCH_ADVANCED);
    });
  });

  describe('Knowledge Operations', () => {
    it('should allow knowledge read with correct scopes', async () => {
      const knowledgeContext: AuthContext = {
        ...testAuthContext,
        scopes: [...testAuthContext.scopes, AuthScope.KNOWLEDGE_READ]
      };

      const decision = await authorizationService.checkAccess(
        knowledgeContext,
        'knowledge',
        'read'
      );

      expect(decision.allowed).toBe(true);
      expect(decision.required_scopes).toContain(AuthScope.KNOWLEDGE_READ);
    });

    it('should allow knowledge write with correct scopes', async () => {
      const knowledgeContext: AuthContext = {
        ...testAuthContext,
        scopes: [...testAuthContext.scopes, AuthScope.KNOWLEDGE_WRITE]
      };

      const decision = await authorizationService.checkAccess(
        knowledgeContext,
        'knowledge',
        'write'
      );

      expect(decision.allowed).toBe(true);
      expect(decision.required_scopes).toContain(AuthScope.KNOWLEDGE_WRITE);
    });

    it('should deny knowledge delete to regular users', async () => {
      const knowledgeContext: AuthContext = {
        ...testAuthContext,
        scopes: [...testAuthContext.scopes, AuthScope.KNOWLEDGE_DELETE]
      };

      const decision = await authorizationService.checkAccess(
        knowledgeContext,
        'knowledge',
        'delete'
      );

      expect(decision.allowed).toBe(false);
      expect(decision.reason).toContain('Additional access conditions not met');
    });

    it('should allow knowledge delete to admin users', async () => {
      const adminContext: AuthContext = {
        user: {
          id: 'admin-user-id',
          username: 'admin',
          role: UserRole.ADMIN
        },
        session: {
          id: 'admin-session-id',
          ip_address: '127.0.0.1',
          user_agent: 'admin-agent'
        },
        scopes: [AuthScope.KNOWLEDGE_DELETE],
        token_jti: 'admin-token-id'
      };

      const decision = await authorizationService.checkAccess(
        adminContext,
        'knowledge',
        'delete'
      );

      expect(decision.allowed).toBe(true);
    });
  });

  describe('System Operations', () => {
    it('should deny system operations to regular users', async () => {
      const readDecision = await authorizationService.checkAccess(
        testAuthContext,
        'system',
        'read'
      );

      const manageDecision = await authorizationService.checkAccess(
        testAuthContext,
        'system',
        'manage'
      );

      expect(readDecision.allowed).toBe(false);
      expect(manageDecision.allowed).toBe(false);
    });

    it('should allow system operations to admin users', async () => {
      const adminContext: AuthContext = {
        user: {
          id: 'admin-user-id',
          username: 'admin',
          role: UserRole.ADMIN
        },
        session: {
          id: 'admin-session-id',
          ip_address: '127.0.0.1',
          user_agent: 'admin-agent'
        },
        scopes: [AuthScope.SYSTEM_READ, AuthScope.SYSTEM_MANAGE],
        token_jti: 'admin-token-id'
      };

      const readDecision = await authorizationService.checkAccess(
        adminContext,
        'system',
        'read'
      );

      const manageDecision = await authorizationService.checkAccess(
        adminContext,
        'system',
        'manage'
      );

      expect(readDecision.allowed).toBe(true);
      expect(manageDecision.allowed).toBe(true);
    });
  });

  describe('User Management Operations', () => {
    it('should deny user management to regular users', async () => {
      const decision = await authorizationService.checkAccess(
        testAuthContext,
        'user',
        'manage'
      );

      expect(decision.allowed).toBe(false);
      expect(decision.required_scopes).toContain(AuthScope.USER_MANAGE);
    });

    it('should allow user management to admin users', async () => {
      const adminContext: AuthContext = {
        user: {
          id: 'admin-user-id',
          username: 'admin',
          role: UserRole.ADMIN
        },
        session: {
          id: 'admin-session-id',
          ip_address: '127.0.0.1',
          user_agent: 'admin-agent'
        },
        scopes: [AuthScope.USER_MANAGE],
        token_jti: 'admin-token-id'
      };

      const decision = await authorizationService.checkAccess(
        adminContext,
        'user',
        'manage'
      );

      expect(decision.allowed).toBe(true);
    });
  });

  describe('Batch Access Checking', () => {
    it('should check multiple access requests efficiently', async () => {
      const requests = [
        { resource: 'memory_store', action: 'read' },
        { resource: 'memory_store', action: 'write' },
        { resource: 'memory_find', action: 'read' },
        { resource: 'system', action: 'manage' } // This should be denied
      ];

      const results = await authorizationService.checkMultipleAccess(testAuthContext, requests);

      expect(results.size).toBe(4);
      expect(results.get('memory_store:read')?.allowed).toBe(true);
      expect(results.get('memory_store:write')?.allowed).toBe(true);
      expect(results.get('memory_find:read')?.allowed).toBe(true);
      expect(results.get('system:manage')?.allowed).toBe(false);
    });
  });

  describe('Scope Validation', () => {
    let mockUser: any;

    beforeEach(() => {
      mockUser = {
        id: 'test-user-id',
        username: 'testuser',
        email: 'test@example.com',
        password_hash: 'hashedpassword',
        role: UserRole.USER,
        is_active: true,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      };
    });

    it('should return correct allowed scopes for user roles', () => {
      const allowedScopes = authorizationService.getAllowedScopes(mockUser);

      expect(allowedScopes).toContain(AuthScope.MEMORY_READ);
      expect(allowedScopes).toContain(AuthScope.MEMORY_WRITE);
      expect(allowedScopes).toContain(AuthScope.KNOWLEDGE_READ);
      expect(allowedScopes).toContain(AuthScope.KNOWLEDGE_WRITE);
      expect(allowedScopes).toContain(AuthScope.SEARCH_BASIC);
      expect(allowedScopes).toContain(AuthScope.SEARCH_ADVANCED);
      expect(allowedScopes).toContain(AuthScope.AUDIT_READ);
    });

    it('should return correct default scopes for user roles', () => {
      const defaultScopes = authorizationService.getDefaultScopes(mockUser);

      expect(defaultScopes).toContain(AuthScope.MEMORY_READ);
      expect(defaultScopes).toContain(AuthScope.MEMORY_WRITE);
      expect(defaultScopes).toContain(AuthScope.KNOWLEDGE_READ);
      expect(defaultScopes).toContain(AuthScope.KNOWLEDGE_WRITE);
      expect(defaultScopes).toContain(AuthScope.SEARCH_BASIC);
      expect(defaultScopes).toContain(AuthScope.SEARCH_ADVANCED);
    });

    it('should validate user scopes correctly', () => {
      const validScopes = [AuthScope.MEMORY_READ, AuthScope.MEMORY_WRITE];
      const invalidScopes = [AuthScope.SYSTEM_MANAGE, AuthScope.USER_MANAGE];

      const validResult = authorizationService.validateUserScopes(mockUser, validScopes);
      expect(validResult.valid).toBe(true);
      expect(validResult.invalidScopes).toEqual([]);

      const invalidResult = authorizationService.validateUserScopes(mockUser, invalidScopes);
      expect(invalidResult.valid).toBe(false);
      expect(invalidResult.invalidScopes.length).toBeGreaterThan(0);
    });
  });

  describe('Custom Resource Rules', () => {
    it('should allow adding custom resource rules', () => {
      const customRule = {
        resource: 'custom_resource',
        action: 'custom_action',
        required_scopes: [AuthScope.MEMORY_READ],
        conditions: {
          user_roles: [UserRole.ADMIN]
        }
      };

      authorizationService.addResourceRule(customRule);

      const adminContext: AuthContext = {
        user: {
          id: 'admin-user-id',
          username: 'admin',
          role: UserRole.ADMIN
        },
        session: {
          id: 'admin-session-id',
          ip_address: '127.0.0.1',
          user_agent: 'admin-agent'
        },
        scopes: [AuthScope.MEMORY_READ],
        token_jti: 'admin-token-id'
      };

      const userContext: AuthContext = {
        user: {
          id: 'user-id',
          username: 'user',
          role: UserRole.USER
        },
        session: {
          id: 'user-session-id',
          ip_address: '127.0.0.1',
          user_agent: 'user-agent'
        },
        scopes: [AuthScope.MEMORY_READ],
        token_jti: 'user-token-id'
      };

      // Test that custom rule works
      const adminDecision = authorizationService.checkAccess(
        adminContext,
        'custom_resource',
        'custom_action'
      );

      const userDecision = authorizationService.checkAccess(
        userContext,
        'custom_resource',
        'custom_action'
      );

      expect(adminDecision).resolves.toMatchObject({ allowed: true });
      expect(userDecision).resolves.toMatchObject({ allowed: false });
    });

    it('should allow removing resource rules', () => {
      const customRule = {
        resource: 'temporary_resource',
        action: 'temporary_action',
        required_scopes: [AuthScope.MEMORY_READ]
      };

      authorizationService.addResourceRule(customRule);

      // Rule should work initially
      const initialDecision = authorizationService.checkAccess(
        testAuthContext,
        'temporary_resource',
        'temporary_action'
      );

      expect(initialDecision).resolves.toMatchObject({ allowed: true });

      // Remove the rule
      authorizationService.removeResourceRule('temporary_resource', 'temporary_action');

      // Rule should no longer work
      const finalDecision = authorizationService.checkAccess(
        testAuthContext,
        'temporary_resource',
        'temporary_action'
      );

      expect(finalDecision).resolves.toMatchObject({ allowed: false });
    });
  });

  describe('Custom Permissions', () => {
    it('should allow adding custom permissions for users', () => {
      const customPermissions = [
        {
          id: 'custom-permission-1',
          name: 'Custom Access',
          description: 'Custom permission for testing',
          required_scopes: [AuthScope.SYSTEM_READ],
          resource_pattern: 'custom/*',
          action: 'read' as const
        }
      ];

      authorizationService.addCustomPermissions('test-user-id', customPermissions);

      const effectiveScopes = authorizationService.getEffectiveScopes(testAuthContext.user);
      expect(effectiveScopes).toContain(AuthScope.SYSTEM_READ);
    });

    it('should remove custom permissions', () => {
      const customPermissions = [
        {
          id: 'custom-permission-1',
          name: 'Custom Access',
          description: 'Custom permission for testing',
          required_scopes: [AuthScope.SYSTEM_READ],
          resource_pattern: 'custom/*',
          action: 'read' as const
        }
      ];

      authorizationService.addCustomPermissions('test-user-id', customPermissions);

      let effectiveScopes = authorizationService.getEffectiveScopes(testAuthContext.user);
      expect(effectiveScopes).toContain(AuthScope.SYSTEM_READ);

      authorizationService.removeCustomPermissions('test-user-id');

      effectiveScopes = authorizationService.getEffectiveScopes(testAuthContext.user);
      expect(effectiveScopes).not.toContain(AuthScope.SYSTEM_READ);
    });
  });

  describe('Scope Access Checks', () => {
    it('should check individual scope access', () => {
      expect(authorizationService.canAccessScope(testAuthContext, AuthScope.MEMORY_READ)).toBe(true);
      expect(authorizationService.canAccessScope(testAuthContext, AuthScope.SYSTEM_MANAGE)).toBe(false);
    });

    it('should check any scope access', () => {
      const scopesToCheck = [AuthScope.MEMORY_READ, AuthScope.SYSTEM_MANAGE];
      expect(authorizationService.canAccessAnyScope(testAuthContext, scopesToCheck)).toBe(true);

      const restrictedScopes = [AuthScope.SYSTEM_MANAGE, AuthScope.USER_MANAGE];
      expect(authorizationService.canAccessAnyScope(testAuthContext, restrictedScopes)).toBe(false);
    });

    it('should check all scope access', () => {
      const availableScopes = [AuthScope.MEMORY_READ, AuthScope.MEMORY_WRITE];
      expect(authorizationService.canAccessAllScopes(testAuthContext, availableScopes)).toBe(true);

      const mixedScopes = [AuthScope.MEMORY_READ, AuthScope.SYSTEM_MANAGE];
      expect(authorizationService.canAccessAllScopes(testAuthContext, mixedScopes)).toBe(false);
    });
  });

  describe('Configuration Validation', () => {
    it('should validate authorization configuration', () => {
      const validation = authorizationService.validateConfiguration();

      expect(validation.valid).toBe(true);
      expect(validation.errors).toEqual([]);
    });

    it('should detect invalid scopes in resource rules', () => {
      // Add a rule with an invalid scope
      const invalidRule = {
        resource: 'test_resource',
        action: 'test_action',
        required_scopes: ['invalid_scope' as AuthScope]
      };

      authorizationService.addResourceRule(invalidRule);

      const validation = authorizationService.validateConfiguration();

      expect(validation.valid).toBe(false);
      expect(validation.errors.length).toBeGreaterThan(0);
      expect(validation.errors[0]).toContain('invalid_scope');
    });
  });

  describe('Debug and Audit Functions', () => {
    it('should return all resource rules for debugging', () => {
      const allRules = authorizationService.getAllResourceRules();

      expect(allRules).toBeDefined();
      expect(allRules.size).toBeGreaterThan(0);

      // Check that default rules exist
      expect(allRules.has('memory_store:write')).toBe(true);
      expect(allRules.has('memory_find:read')).toBe(true);
      expect(allRules.has('system:manage')).toBe(true);
    });

    it('should return all custom permissions for debugging', () => {
      const customPermissions = [
        {
          id: 'debug-permission',
          name: 'Debug Permission',
          description: 'For debugging purposes',
          required_scopes: [AuthScope.SYSTEM_READ],
          resource_pattern: 'debug/*',
          action: 'read' as const
        }
      ];

      authorizationService.addCustomPermissions('debug-user', customPermissions);

      const allPermissions = authorizationService.getAllCustomPermissions();

      expect(allPermissions).toBeDefined();
      expect(allPermissions.has('debug-user')).toBe(true);
      expect(allPermissions.get('debug-user')).toEqual(customPermissions);
    });
  });
});