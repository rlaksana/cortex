/**
 * Tenant Isolation Tests for Cortex MCP Tools
 *
 * Tests ensure that tenant boundaries are properly enforced and that
 * cross-tenant access controls work correctly across all scenarios.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { Request, Response } from 'express';
import {
  EnhancedSecurityMiddleware,
  TenantIsolation,
  DEFAULT_SECURITY_CONFIG,
  TOOL_SECURITY_CONFIGS,
} from '../../src/middleware/enhanced-security-middleware.js';
import type { AuthContext } from '../../src/types/auth-types.js';

describe('Tenant Isolation', () => {
  let tenantIsolation: TenantIsolation;
  let securityMiddleware: EnhancedSecurityMiddleware;

  beforeEach(() => {
    tenantIsolation = new TenantIsolation(DEFAULT_SECURITY_CONFIG.tenant_isolation);
    securityMiddleware = new EnhancedSecurityMiddleware(DEFAULT_SECURITY_CONFIG);
  });

  describe('Tenant ID Extraction', () => {
    it('should extract tenant ID from auth context', () => {
      const authContext: AuthContext = {
        user: {
          id: 'user-123',
          username: 'testuser',
          role: 'user' as any,
        },
        session: {
          id: 'session-123',
          ip_address: '127.0.0.1',
          user_agent: 'test-agent',
        },
        scopes: [],
        token_jti: 'token-123',
      };

      // Mock organizationId in user
      (authContext.user as any).organizationId = 'tenant-123';

      const req = { headers: {}, query: {} } as Request;
      const tenantId = tenantIsolation.extractTenantId(req, authContext);

      expect(tenantId).toBe('tenant-123');
    });

    it('should extract tenant ID from headers', () => {
      const authContext: AuthContext = {
        user: {
          id: 'user-123',
          username: 'testuser',
          role: 'user' as any,
        },
        session: {
          id: 'session-123',
          ip_address: '127.0.0.1',
          user_agent: 'test-agent',
        },
        scopes: [],
        token_jti: 'token-123',
      };

      const req = {
        headers: { 'x-tenant-id': 'tenant-456' },
        query: {},
      } as Request;

      const tenantId = tenantIsolation.extractTenantId(req, authContext);
      expect(tenantId).toBe('tenant-456');
    });

    it('should extract tenant ID from query parameters', () => {
      const req = {
        headers: {},
        query: { tenant_id: 'tenant-789' },
      } as Request;

      const tenantId = tenantIsolation.extractTenantId(req);
      expect(tenantId).toBe('tenant-789');
    });

    it('should use default tenant when configured', () => {
      const config = {
        ...DEFAULT_SECURITY_CONFIG.tenant_isolation,
        default_tenant: 'default-tenant',
      };
      const tenantIsolationWithDefault = new TenantIsolation(config);

      const req = { headers: {}, query: {} } as Request;
      const tenantId = tenantIsolationWithDefault.extractTenantId(req);

      expect(tenantId).toBe('default-tenant');
    });

    it('should respect tenant ID source priority', () => {
      const authContext: AuthContext = {
        user: {
          id: 'user-123',
          username: 'testuser',
          role: 'user' as any,
        },
        session: {
          id: 'session-123',
          ip_address: '127.0.0.1',
          user_agent: 'test-agent',
        },
        scopes: [],
        token_jti: 'token-123',
      };

      (authContext.user as any).organizationId = 'tenant-auth';

      const req = {
        headers: { 'x-tenant-id': 'tenant-header' },
        query: { tenant_id: 'tenant-query' },
      } as Request;

      const tenantId = tenantIsolation.extractTenantId(req, authContext);
      expect(tenantId).toBe('tenant-auth'); // Auth takes priority
    });
  });

  describe('Tenant Validation', () => {
    it('should allow matching tenant IDs', () => {
      const validation = tenantIsolation.validateTenantIsolation(
        'memory_store',
        'tenant-123',
        'tenant-123',
        { project: 'test-project' }
      );

      expect(validation.isValid).toBe(true);
      expect(validation.errors).toHaveLength(0);
    });

    it('should reject mismatched tenant IDs in strict mode', () => {
      const config = {
        ...DEFAULT_SECURITY_CONFIG.tenant_isolation,
        strict_mode: true,
      };
      const strictTenantIsolation = new TenantIsolation(config);

      const validation = strictTenantIsolation.validateTenantIsolation(
        'memory_store',
        'tenant-123',
        'tenant-456',
        { project: 'test-project' }
      );

      expect(validation.isValid).toBe(false);
      expect(validation.errors).toContain('Tenant mismatch: request=tenant-123, auth=tenant-456');
    });

    it('should allow cross-tenant access for authorized tools', () => {
      const validation = tenantIsolation.validateTenantIsolation(
        'system_status', // This tool is in cross_tenant_access
        'tenant-123',
        'tenant-456',
        { project: 'test-project' }
      );

      expect(validation.isValid).toBe(true);
      expect(validation.warnings).toContain(
        'Cross-tenant access for tool system_status: tenant-123 -> tenant-456'
      );
    });

    it('should validate scope tenant consistency', () => {
      const validation = tenantIsolation.validateTenantIsolation(
        'memory_store',
        'tenant-123',
        'tenant-123',
        { project: 'test-project', tenant: 'tenant-456' } // Mismatched tenant in scope
      );

      expect(validation.isValid).toBe(false);
      expect(validation.errors).toContain(
        'Scope tenant mismatch: scope=tenant-456, request=tenant-123'
      );
    });

    it('should handle missing tenant IDs in non-strict mode', () => {
      const validation = tenantIsolation.validateTenantIsolation(
        'memory_store',
        null,
        null,
        { project: 'test-project' }
      );

      expect(validation.isValid).toBe(true); // Non-strict mode allows missing tenants
    });

    it('should require tenant ID in strict mode', () => {
      const config = {
        ...DEFAULT_SECURITY_CONFIG.tenant_isolation,
        strict_mode: true,
      };
      const strictTenantIsolation = new TenantIsolation(config);

      const validation = strictTenantIsolation.validateTenantIsolation(
        'memory_store',
        null,
        null,
        { project: 'test-project' }
      );

      expect(validation.isValid).toBe(false);
      expect(validation.errors).toContain('Tenant ID required in strict mode');
    });
  });

  describe('Scope Application', () => {
    it('should apply tenant to empty scope', () => {
      const result = tenantIsolation.applyTenantToScope({}, 'tenant-123');
      expect(result).toEqual({ tenant: 'tenant-123' });
    });

    it('should apply tenant to existing scope', () => {
      const scope = { project: 'test-project', branch: 'main' };
      const result = tenantIsolation.applyTenantToScope(scope, 'tenant-123');

      expect(result).toEqual({
        project: 'test-project',
        branch: 'main',
        tenant: 'tenant-123',
        organization_id: 'tenant-123',
        org: 'tenant-123',
      });
    });

    it('should override inconsistent tenant fields', () => {
      const scope = {
        project: 'test-project',
        tenant: 'old-tenant',
        organization_id: 'old-org',
        org: 'old-org',
      };
      const result = tenantIsolation.applyTenantToScope(scope, 'new-tenant');

      expect(result).toEqual({
        project: 'test-project',
        tenant: 'new-tenant',
        organization_id: 'new-tenant',
        org: 'new-tenant',
      });
    });

    it('should preserve existing consistent tenant fields', () => {
      const scope = {
        project: 'test-project',
        tenant: 'tenant-123',
        organization_id: 'tenant-123',
      };
      const result = tenantIsolation.applyTenantToScope(scope, 'tenant-123');

      expect(result).toEqual({
        project: 'test-project',
        tenant: 'tenant-123',
        organization_id: 'tenant-123',
        org: 'tenant-123',
      });
    });
  });

  describe('Security Middleware Integration', () => {
    it('should apply tenant isolation in middleware', async () => {
      const toolName = 'memory_store';
      const middleware = securityMiddleware.createMiddleware(toolName);

      const req = {
        auth: {
          user: {
            id: 'user-123',
            username: 'testuser',
            role: 'user' as any,
            organizationId: 'tenant-123',
          },
        } as AuthContext,
        body: {
          items: [{ kind: 'entity', content: 'test' }],
          scope: { project: 'test-project' },
        },
        headers: {},
        method: 'POST',
        url: '/test',
        ip: '127.0.0.1',
      } as any;

      const res = {
        status: vi.fn().mockReturnThis(),
        json: vi.fn(),
        setHeader: vi.fn(),
      } as any;

      const next = vi.fn();

      await middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(req.body.scope.tenant).toBe('tenant-123');
      expect((req as any).tenantId).toBe('tenant-123');
      expect((req as any).securityContext).toBeDefined();
    });

    it('should reject cross-tenant requests', async () => {
      const toolName = 'memory_store';
      const config = {
        ...DEFAULT_SECURITY_CONFIG,
        tenant_isolation: {
          ...DEFAULT_SECURITY_CONFIG.tenant_isolation,
          strict_mode: true,
        },
      };
      const strictMiddleware = new EnhancedSecurityMiddleware(config);
      const middleware = strictMiddleware.createMiddleware(toolName);

      const req = {
        auth: {
          user: {
            id: 'user-123',
            username: 'testuser',
            role: 'user' as any,
            organizationId: 'tenant-123',
          },
        } as AuthContext,
        body: {
          items: [{ kind: 'entity', content: 'test' }],
          scope: { project: 'test-project', tenant: 'tenant-456' },
        },
        headers: { 'x-tenant-id': 'tenant-456' },
        method: 'POST',
        url: '/test',
        ip: '127.0.0.1',
      } as any;

      const res = {
        status: vi.fn().mockReturnThis(),
        json: vi.fn(),
        setHeader: vi.fn(),
      } as any;

      const next = vi.fn();

      await middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith({
        error: 'Tenant validation failed',
        details: expect.arrayContaining([
          expect.stringContaining('Tenant mismatch'),
        ]),
      });
      expect(next).not.toHaveBeenCalled();
    });

    it('should allow cross-tenant access for system tools', async () => {
      const toolName = 'system_status';
      const middleware = securityMiddleware.createMiddleware(toolName);

      const req = {
        auth: {
          user: {
            id: 'user-123',
            username: 'testuser',
            role: 'user' as any,
            organizationId: 'tenant-123',
          },
        } as AuthContext,
        body: {
          operation: 'health',
          scope: { project: 'test-project' },
        },
        headers: { 'x-tenant-id': 'tenant-456' },
        method: 'POST',
        url: '/test',
        ip: '127.0.0.1',
      } as any;

      const res = {
        status: vi.fn().mockReturnThis(),
        json: vi.fn(),
        setHeader: vi.fn(),
      } as any;

      const next = vi.fn();

      await middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect((req as any).securityContext.warnings).toContain(
        expect.stringContaining('Cross-tenant access for tool system_status')
      );
    });
  });

  describe('Tool-Specific Configurations', () => {
    it('should use tool-specific security configs', () => {
      const memoryStoreConfig = TOOL_SECURITY_CONFIGS.memory_store;
      expect(memoryStoreConfig.quotas?.max_content_length).toBe(5000000);
      expect(memoryStoreConfig.input_validation?.sanitize_html).toBe(true);

      const systemStatusConfig = TOOL_SECURITY_CONFIGS.system_status;
      expect(systemStatusConfig.tenant_isolation?.enabled).toBe(false);
    });

    it('should apply tool-specific quota limits', async () => {
      const memoryStoreConfig = {
        ...DEFAULT_SECURITY_CONFIG,
        ...TOOL_SECURITY_CONFIGS.memory_store,
      };
      const memoryStoreMiddleware = new EnhancedSecurityMiddleware(memoryStoreConfig);
      const middleware = memoryStoreMiddleware.createMiddleware('memory_store');

      const req = {
        auth: {
          user: {
            id: 'user-123',
            username: 'testuser',
            role: 'user' as any,
            organizationId: 'tenant-123',
          },
        } as AuthContext,
        body: {
          items: [{ kind: 'entity', content: 'test' }],
          scope: { project: 'test-project' },
        },
        headers: {},
        method: 'POST',
        url: '/test',
        ip: '127.0.0.1',
      } as any;

      const res = {
        status: vi.fn().mockReturnThis(),
        json: vi.fn(),
        setHeader: vi.fn(),
      } as any;

      const next = vi.fn();

      await middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      // The middleware should use the tool-specific quota limits
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle malformed tenant IDs gracefully', () => {
      const req = {
        headers: { 'x-tenant-id': '' }, // Empty tenant ID
        query: {},
      } as Request;

      const tenantId = tenantIsolation.extractTenantId(req);
      expect(tenantId).toBeNull();
    });

    it('should handle disabled tenant isolation', () => {
      const config = {
        ...DEFAULT_SECURITY_CONFIG.tenant_isolation,
        enabled: false,
      };
      const disabledTenantIsolation = new TenantIsolation(config);

      const validation = disabledTenantIsolation.validateTenantIsolation(
        'memory_store',
        'tenant-123',
        'tenant-456',
        { project: 'test-project' }
      );

      expect(validation.isValid).toBe(true);
      expect(validation.warnings).toContain('Tenant isolation disabled');
    });

    it('should handle large numbers of tenant fields in scope', () => {
      const scope = {
        project: 'test-project',
        tenant: 'tenant-123',
        organization_id: 'tenant-123',
        org: 'tenant-123',
        // Additional tenant-related fields
        custom_tenant: 'tenant-123',
        tenant_data: { id: 'tenant-123' },
      };

      const result = tenantIsolation.applyTenantToScope(scope, 'tenant-456');
      expect(result.tenant).toBe('tenant-456');
      expect(result.organization_id).toBe('tenant-456');
      expect(result.org).toBe('tenant-456');
      // Custom fields should remain unchanged
      expect(result.custom_tenant).toBe('tenant-123');
    });
  });

  describe('Performance Tests', () => {
    it('should handle tenant validation efficiently', () => {
      const start = Date.now();

      for (let i = 0; i < 1000; i++) {
        tenantIsolation.validateTenantIsolation(
          'memory_store',
          `tenant-${i}`,
          `tenant-${i}`,
          { project: 'test-project' }
        );
      }

      const duration = Date.now() - start;
      expect(duration).toBeLessThan(100); // Should complete in < 100ms
    });

    it('should handle scope application efficiently', () => {
      const scope = { project: 'test-project', branch: 'main' };
      const start = Date.now();

      for (let i = 0; i < 1000; i++) {
        tenantIsolation.applyTenantToScope(scope, `tenant-${i}`);
      }

      const duration = Date.now() - start;
      expect(duration).toBeLessThan(50); // Should complete in < 50ms
    });
  });
});