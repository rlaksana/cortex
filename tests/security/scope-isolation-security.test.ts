/**
 * Scope Isolation Security Tests
 *
 * Comprehensive testing for scope-based access control including:
 * - Project-based data isolation
 * - Branch-level access control
 * - Organization-level permissions
 * - Cross-scope data leakage prevention
 * - Scope boundary enforcement
 * - Escalation attempts prevention
 * - Privilege boundary testing
 * - Multi-tenant security
 * - Data segregation validation
 * - Scope inheritance security
 * - Cross-project access restrictions
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { memoryStore } from '../services/memory-store.ts';
import { smartMemoryFind } from '../services/smart-find.ts';
import { inferScope, type Scope } from '../utils/scope.ts';
// Prisma client removed - system now uses Qdrant + PostgreSQL architecture

describe('Scope Isolation Security Tests', () => {
  // Test scopes for isolation
  const testScopes = {
    org1Project1Branch1: { org: 'org1', project: 'project1', branch: 'branch1' },
    org1Project1Branch2: { org: 'org1', project: 'project1', branch: 'branch2' },
    org1Project2Branch1: { org: 'org1', project: 'project2', branch: 'branch1' },
    org2Project1Branch1: { org: 'org2', project: 'project1', branch: 'branch1' },
    noOrgProject1: { project: 'project1', branch: 'main' },
    org1NoProject: { org: 'org1' },
    projectOnly: { project: 'isolated-project' },
    orgOnly: { org: 'isolated-org' },
    empty: {},
  };

  // Malicious scope manipulation attempts
  const maliciousScopes = [
    { org: '../../../etc', project: 'passwd' },
    { org: '..\\..\\windows', project: 'system32' },
    { org: 'org1/**', project: 'admin' },
    { org: 'org1', project: '*/admin' },
    { org: 'org1', project: 'project1/../admin' },
    { org: 'org1\x00', project: 'project1' },
    { org: 'org1', project: 'project1\x00admin' },
    { org: 'org1', project: 'project1' },
    { org: 'org1', project: 'project1', branch: 'main\x00admin' },
    { org: 'org1', project: '', branch: 'main' },
    { org: '', project: 'project1', branch: 'main' },
    { org: 'org1', project: 'project1', branch: '' },
  ];

  beforeEach(async () => {
    // Clean up test data before each test using UnifiedDatabaseLayer
    try {
      const { UnifiedDatabaseLayer } = await import('../../src/db/unified-database-layer.ts');
      const db = new UnifiedDatabaseLayer();
      await db.initialize();

      // Clean up test entities with test-scope- in their tags
      await db.delete('knowledgeEntity', {
        tags: {
          path: ['project'],
          string_contains: 'test-scope-'
        }
      });
    } catch (error) {
      // Ignore cleanup errors in test environment
    }
  });

  describe('Basic Scope Isolation', () => {
    it('should enforce project-level data isolation', async () => {
      const scope1 = { org: 'test-org', project: 'project-a', branch: 'main' };
      const scope2 = { org: 'test-org', project: 'project-b', branch: 'main' };

      // Store data in project A
      const entityA = {
        items: [{
          kind: 'entity' as const,
          scope: scope1,
          data: {
            name: 'project-a-entity',
            entity_type: 'test',
            sensitive_data: 'project-a-secret'
          }
        }]
      };

      const resultA = await memoryStore(entityA.items);
      expect(resultA.stored).toHaveLength(1);

      // Store data in project B
      const entityB = {
        items: [{
          kind: 'entity' as const,
          scope: scope2,
          data: {
            name: 'project-b-entity',
            entity_type: 'test',
            sensitive_data: 'project-b-secret'
          }
        }]
      };

      const resultB = await memoryStore(entityB.items);
      expect(resultB.stored).toHaveLength(1);

      // Search from project A should not return project B data
      const searchFromA = await smartMemoryFind({
        query: 'entity',
        scope: scope1,
        mode: 'auto'
      });

      const foundNames = searchFromA.hits.map(hit => hit.title);
      expect(foundNames).toContain('project-a-entity');
      expect(foundNames).not.toContain('project-b-entity');

      // Search from project B should not return project A data
      const searchFromB = await smartMemoryFind({
        query: 'entity',
        scope: scope2,
        mode: 'auto'
      });

      const foundNamesB = searchFromB.hits.map(hit => hit.title);
      expect(foundNamesB).toContain('project-b-entity');
      expect(foundNamesB).not.toContain('project-a-entity');
    });

    it('should enforce branch-level data isolation within same project', async () => {
      const scope1 = { org: 'test-org', project: 'project-branch', branch: 'develop' };
      const scope2 = { org: 'test-org', project: 'project-branch', branch: 'feature/new-feature' };

      // Store data in develop branch
      const developEntity = {
        items: [{
          kind: 'entity' as const,
          scope: scope1,
          data: {
            name: 'develop-branch-entity',
            entity_type: 'test',
            data: 'develop-only-data'
          }
        }]
      };

      const resultDevelop = await memoryStore(developEntity.items);
      expect(resultDevelop.stored).toHaveLength(1);

      // Store data in feature branch
      const featureEntity = {
        items: [{
          kind: 'entity' as const,
          scope: scope2,
          data: {
            name: 'feature-branch-entity',
            entity_type: 'test',
            data: 'feature-only-data'
          }
        }]
      };

      const resultFeature = await memoryStore(featureEntity.items);
      expect(resultFeature.stored).toHaveLength(1);

      // Search from develop branch should not see feature branch data
      const searchDevelop = await smartMemoryFind({
        query: 'entity',
        scope: scope1,
        mode: 'auto'
      });

      const developHits = searchDevelop.hits.map(hit => hit.title);
      expect(developHits).toContain('develop-branch-entity');
      expect(developHits).not.toContain('feature-branch-entity');

      // Search from feature branch should not see develop branch data
      const searchFeature = await smartMemoryFind({
        query: 'entity',
        scope: scope2,
        mode: 'auto'
      });

      const featureHits = searchFeature.hits.map(hit => hit.title);
      expect(featureHits).toContain('feature-branch-entity');
      expect(featureHits).not.toContain('develop-branch-entity');
    });

    it('should enforce organization-level data isolation', async () => {
      const org1Scope = { org: 'organization-1', project: 'shared-project', branch: 'main' };
      const org2Scope = { org: 'organization-2', project: 'shared-project', branch: 'main' };

      // Store data in org1
      const org1Entity = {
        items: [{
          kind: 'entity' as const,
          scope: org1Scope,
          data: {
            name: 'org1-entity',
            entity_type: 'test',
            confidential: 'org1-confidential-data'
          }
        }]
      };

      const resultOrg1 = await memoryStore(org1Entity.items);
      expect(resultOrg1.stored).toHaveLength(1);

      // Store data in org2
      const org2Entity = {
        items: [{
          kind: 'entity' as const,
          scope: org2Scope,
          data: {
            name: 'org2-entity',
            entity_type: 'test',
            confidential: 'org2-confidential-data'
          }
        }]
      };

      const resultOrg2 = await memoryStore(org2Entity.items);
      expect(resultOrg2.stored).toHaveLength(1);

      // Search from org1 should not see org2 data
      const searchOrg1 = await smartMemoryFind({
        query: 'entity',
        scope: org1Scope,
        mode: 'auto'
      });

      const org1Hits = searchOrg1.hits.map(hit => hit.title);
      expect(org1Hits).toContain('org1-entity');
      expect(org1Hits).not.toContain('org2-entity');

      // Search from org2 should not see org1 data
      const searchOrg2 = await smartMemoryFind({
        query: 'entity',
        scope: org2Scope,
        mode: 'auto'
      });

      const org2Hits = searchOrg2.hits.map(hit => hit.title);
      expect(org2Hits).toContain('org2-entity');
      expect(org2Hits).not.toContain('org1-entity');
    });
  });

  describe('Scope Boundary Enforcement', () => {
    it('should prevent cross-scope data access', async () => {
      const adminScope = { org: 'admin-org', project: 'admin-project', branch: 'main' };
      const userScope = { org: 'user-org', project: 'user-project', branch: 'main' };

      // Store sensitive admin data
      const adminData = {
        items: [{
          kind: 'entity' as const,
          scope: adminScope,
          data: {
            name: 'admin-config',
            entity_type: 'configuration',
            secrets: 'admin-secrets',
            credentials: 'admin-credentials'
          }
        }]
      };

      await memoryStore(adminData.items);

      // Attempt to access admin data from user scope should fail
      const unauthorizedAccess = await smartMemoryFind({
        query: 'admin',
        scope: userScope,
        mode: 'auto'
      });

      // Should not find admin data
      const adminHits = unauthorizedAccess.hits.filter(hit =>
        hit.title.includes('admin') || hit.snippet.includes('secrets')
      );
      expect(adminHits).toHaveLength(0);

      // Even with direct queries, should not access
      const directAccess = await smartMemoryFind({
        query: 'admin-config OR secrets OR credentials',
        scope: userScope,
        mode: 'deep'
      });

      const directHits = directAccess.hits.filter(hit =>
        hit.snippet.includes('secrets') || hit.snippet.includes('credentials')
      );
      expect(directHits).toHaveLength(0);
    });

    it('should prevent scope escalation attempts', async () => {
      const userScope = { org: 'user-org', project: 'user-project', branch: 'feature-branch' };

      // Store user data
      const userData = {
        items: [{
          kind: 'entity' as const,
          scope: userScope,
          data: {
            name: 'user-entity',
            entity_type: 'user-data',
            content: 'user-content'
          }
        }]
      };

      await memoryStore(userData.items);

      // Attempt escalation via manipulated scope parameters
      const escalationAttempts = [
        { org: 'admin-org', project: 'user-project', branch: 'main' }, // Change org
        { org: 'user-org', project: 'admin-project', branch: 'main' }, // Change project
        { org: 'user-org', project: 'user-project', branch: 'main' }, // Change branch
        { org: '', project: '', branch: '' }, // Empty scope (wildcard attempt)
        {}, // No scope (global access attempt)
      ];

      for (const escalationScope of escalationAttempts) {
        const escalationSearch = await smartMemoryFind({
          query: 'user-entity',
          scope: escalationScope,
          mode: 'deep'
        });

        // Should not find user data from different scopes
        const foundUser = escalationSearch.hits.find(hit => hit.title === 'user-entity');
        if (JSON.stringify(escalationScope) !== JSON.stringify(userScope)) {
          expect(foundUser).toBeUndefined();
        }
      }
    });

    it('should handle partial scope specifications correctly', async () => {
      // Test data with various scope combinations
      const testEntities = [
        { scope: { org: 'test-org', project: 'project-a', branch: 'main' }, name: 'full-scope' },
        { scope: { org: 'test-org', project: 'project-b' }, name: 'no-branch' },
        { scope: { org: 'test-org' }, name: 'org-only' },
        { scope: { project: 'project-c', branch: 'main' }, name: 'no-org' },
        { scope: {}, name: 'no-scope' },
      ];

      // Store all test entities
      for (const entity of testEntities) {
        const item = {
          items: [{
            kind: 'entity' as const,
            scope: entity.scope,
            data: {
              name: entity.name,
              entity_type: 'test'
            }
          }]
        };
        await memoryStore(item.items);
      }

      // Test partial scope searches
      const orgOnlySearch = await smartMemoryFind({
        query: 'entity',
        scope: { org: 'test-org' },
        mode: 'auto'
      });

      // Should only return entities from test-org
      const orgOnlyResults = orgOnlySearch.hits.map(hit => hit.title);
      expect(orgOnlyResults).toContain('full-scope');
      expect(orgOnlyResults).toContain('no-branch');
      expect(orgOnlyResults).toContain('org-only');
      expect(orgOnlyResults).not.toContain('no-org');
      expect(orgOnlyResults).not.toContain('no-scope');

      const projectOnlySearch = await smartMemoryFind({
        query: 'entity',
        scope: { project: 'project-a' },
        mode: 'auto'
      });

      // Should only return entities from project-a
      const projectOnlyResults = projectOnlySearch.hits.map(hit => hit.title);
      expect(projectOnlyResults).toContain('full-scope');
      expect(projectOnlyResults).not.toContain('no-branch');
      expect(projectOnlyResults).not.toContain('org-only');
    });
  });

  describe('Malicious Scope Manipulation', () => {
    it('should reject malicious scope patterns', async () => {
      for (const maliciousScope of maliciousScopes) {
        const maliciousEntity = {
          items: [{
            kind: 'entity' as const,
            scope: maliciousScope,
            data: {
              name: 'malicious-entity',
              entity_type: 'test'
            }
          }]
        };

        try {
          const result = await memoryStore(maliciousEntity.items);

          // If storage succeeds, scope should be normalized
          if (result.stored.length > 0) {
            // Verify malicious patterns are neutralized
            const storedData = JSON.stringify(result.stored);
            expect(storedData).not.toContain('../');
            expect(storedData).not.toContain('..\\');
            expect(storedData).not.toContain('\x00');
            expect(storedData).not.toContain('**');
            expect(storedData).not.toContain('*/');
          }
        } catch (error) {
          // Rejection is expected for malicious scopes
          expect(error).toBeInstanceOf(Error);
        }
      }
    });

    it('should prevent scope-based directory traversal', async () => {
      const traversalScopes = [
        { org: '../../../etc', project: 'passwd', branch: 'main' },
        { org: 'org1', project: '../admin', branch: 'main' },
        { org: 'org1', project: 'project1', branch: '../../secrets' },
        { org: '..\\..\\windows', project: 'system32', branch: 'config' },
        { org: 'org1', project: 'project1\\..\\admin', branch: 'main' },
      ];

      for (const traversalScope of traversalScopes) {
        const traversalEntity = {
          items: [{
            kind: 'entity' as const,
            scope: traversalScope,
            data: {
              name: 'traversal-attempt',
              entity_type: 'attack'
            }
          }]
        };

        try {
          const result = await memoryStore(traversalEntity.items);

          if (result.stored.length > 0) {
            // Should normalize traversal paths
            const storedData = JSON.stringify(result.stored);
            expect(storedData).not.toContain('../');
            expect(storedData).not.toContain('..\\');
            expect(storedData).not.toContain('..');
          }
        } catch (error) {
          // Rejection is preferred
          expect(error).toBeInstanceOf(Error);
        }
      }
    });

    it('should handle Unicode-based scope attacks', async () => {
      const unicodeScopes = [
        { org: 'ｏｒｇ１', project: 'project1', branch: 'main' }, // Full-width
        { org: 'оrg1', project: 'project1', branch: 'main' }, // Cyrillic o
        { org: 'org1\u200b', project: 'project1', branch: 'main' }, // Zero-width space
        { org: 'org1', project: 'project1\u200c', branch: 'main' }, // Zero-width non-joiner
        { org: 'org1', project: 'project1', branch: 'main\u200d' }, // Zero-width joiner
      ];

      for (const unicodeScope of unicodeScopes) {
        const unicodeEntity = {
          items: [{
            kind: 'entity' as const,
            scope: unicodeScope,
            data: {
              name: 'unicode-entity',
              entity_type: 'test'
            }
          }]
        };

        try {
          const result = await memoryStore(unicodeEntity.items);

          if (result.stored.length > 0) {
            // Should normalize Unicode characters
            const storedData = JSON.stringify(result.stored);
            expect(storedData).not.toContain('\u200b');
            expect(storedData).not.toContain('\u200c');
            expect(storedData).not.toContain('\u200d');
          }
        } catch (error) {
          // Rejection is acceptable for suspicious Unicode
          expect(error).toBeInstanceOf(Error);
        }
      }
    });
  });

  describe('Multi-Tenant Security', () => {
    it('should enforce strict tenant isolation', async () => {
      const tenants = [
        { id: 'tenant1', org: 'tenant1-org', project: 'app' },
        { id: 'tenant2', org: 'tenant2-org', project: 'app' },
        { id: 'tenant3', org: 'tenant3-org', project: 'app' },
      ];

      // Store sensitive data for each tenant
      for (const tenant of tenants) {
        const tenantData = {
          items: [{
            kind: 'entity' as const,
            scope: { org: tenant.org, project: tenant.project, branch: 'main' },
            data: {
              name: `${tenant.id}-secrets`,
              entity_type: 'tenant-data',
              api_keys: `${tenant.id}-api-key-12345`,
              database_url: `${tenant.id}-db.example.com`,
              secrets: `${tenant.id}-super-secret-data`
            }
          }]
        };

        await memoryStore(tenantData.items);
      }

      // Verify tenants cannot access each other's data
      for (const tenant of tenants) {
        const tenantSearch = await smartMemoryFind({
          query: 'secrets OR api_keys OR database_url',
          scope: { org: tenant.org, project: tenant.project, branch: 'main' },
          mode: 'deep'
        });

        // Should only find tenant's own data
        const hits = tenantSearch.hits;
        expect(hits.length).toBeGreaterThanOrEqual(1);

        // Verify no cross-tenant data leakage
        for (const hit of hits) {
          expect(hit.snippet).toContain(tenant.id);
          expect(hit.snippet).not.toContain('api-key-12345'); // Should be sanitized
          expect(hit.snippet).not.toContain('super-secret'); // Should be sanitized
        }

        // Try searching for other tenants' data
        for (const otherTenant of tenants) {
          if (otherTenant.id !== tenant.id) {
            const otherSearch = await smartMemoryFind({
              query: otherTenant.id,
              scope: { org: tenant.org, project: tenant.project, branch: 'main' },
              mode: 'deep'
            });

            // Should not find other tenant's data
            const otherHits = otherSearch.hits.filter(hit =>
              hit.snippet.includes(otherTenant.id)
            );
            expect(otherHits).toHaveLength(0);
          }
        }
      }
    });

    it('should prevent tenant enumeration attacks', async () => {
      // Create some tenants with data
      const tenants = ['customer-a', 'customer-b', 'internal-team'];

      for (const tenant of tenants) {
        const tenantData = {
          items: [{
            kind: 'entity' as const,
            scope: { org: tenant, project: 'app', branch: 'main' },
            data: {
              name: `${tenant}-config`,
              entity_type: 'config'
            }
          }]
        };
        await memoryStore(tenantData.items);
      }

      // Attempt tenant enumeration
      const enumerationPayloads = [
        '*', // Wildcard
        '%', // SQL wildcard
        '_', // Single character wildcard
        '.*', // Regex wildcard
        'customer%', // Partial match
        'customer-*', // Pattern match
        'cust*', // Partial enumeration
      ];

      for (const payload of enumerationPayloads) {
        const enumSearch = await smartMemoryFind({
          query: payload,
          scope: { org: 'attacker-org', project: 'app', branch: 'main' },
          mode: 'auto'
        });

        // Should not enumerate other tenants
        const hits = enumSearch.hits.filter(hit =>
          tenants.some(tenant => hit.snippet.includes(tenant))
        );
        expect(hits).toHaveLength(0);
      }
    });
  });

  describe('Data Segregation Validation', () => {
    it('should maintain data segregation across all operations', async () => {
      const scopes = [
        { org: 'finance', project: 'accounting', branch: 'main' },
        { org: 'hr', project: 'employee-data', branch: 'main' },
        { org: 'engineering', project: 'source-code', branch: 'develop' },
      ];

      const sensitiveData = [
        { scope: scopes[0], data: 'financial-records', type: 'financial' },
        { scope: scopes[1], data: 'employee-ssn', type: 'personal' },
        { scope: scopes[2], data: 'api-keys', type: 'technical' },
      ];

      // Store sensitive data in each department
      for (let i = 0; i < scopes.length; i++) {
        const entity = {
          items: [{
            kind: 'entity' as const,
            scope: scopes[i],
            data: {
              name: sensitiveData[i].data,
              entity_type: sensitiveData[i].type,
              confidential: `confidential-${sensitiveData[i].type}-data`
            }
          }]
        };
        await memoryStore(entity.items);
      }

      // Verify complete segregation
      for (let i = 0; i < scopes.length; i++) {
        const currentScope = scopes[i];

        // Search from current scope
        const search = await smartMemoryFind({
          query: 'confidential',
          scope: currentScope,
          mode: 'deep'
        });

        // Should only find current scope's data
        expect(search.hits).toHaveLength(1);
        expect(search.hits[0].title).toBe(sensitiveData[i].data);

        // Should not find other departments' data
        for (let j = 0; j < scopes.length; j++) {
          if (i !== j) {
            expect(search.hits[0].title).not.toBe(sensitiveData[j].data);
          }
        }
      }
    });

    it('should handle cross-scope reference security', async () => {
      const projectScope = { org: 'company', project: 'project-x', branch: 'main' };
      const adminScope = { org: 'company', project: 'admin', branch: 'main' };

      // Store project data
      const projectEntity = {
        items: [{
          kind: 'entity' as const,
          scope: projectScope,
          data: {
            name: 'project-data',
            entity_type: 'project',
            references_admin: 'admin-config-123' // Reference to admin data
          }
        }]
      };

      await memoryStore(projectEntity.items);

      // Store admin data
      const adminEntity = {
        items: [{
          kind: 'entity' as const,
          scope: adminScope,
          data: {
            name: 'admin-config-123',
            entity_type: 'admin',
            secrets: 'admin-secrets'
          }
        }]
      };

      await memoryStore(adminEntity.items);

      // Try to access admin data via project scope
      const projectSearch = await smartMemoryFind({
        query: 'admin-config-123 OR admin-secrets',
        scope: projectScope,
        mode: 'deep'
      });

      // Should not find admin data even if referenced
      const adminHits = projectSearch.hits.filter(hit =>
        hit.title.includes('admin') || hit.snippet.includes('secrets')
      );
      expect(adminHits).toHaveLength(0);
    });
  });

  describe('Scope Inheritance Security', () => {
    it('should handle scope inheritance securely', async () => {
      // Create hierarchical scopes
      const orgScope = { org: 'mega-corp' };
      const projectScope = { org: 'mega-corp', project: 'product-a' };
      const branchScope = { org: 'mega-corp', project: 'product-a', branch: 'main' };

      // Store data at different scope levels
      const orgData = {
        items: [{
          kind: 'entity' as const,
          scope: orgScope,
          data: {
            name: 'org-policy',
            entity_type: 'policy',
            content: 'organization-wide-policy'
          }
        }]
      };

      const projectData = {
        items: [{
          kind: 'entity' as const,
          scope: projectScope,
          data: {
            name: 'project-config',
            entity_type: 'config',
            content: 'project-specific-config'
          }
        }]
      };

      const branchData = {
        items: [{
          kind: 'entity' as const,
          scope: branchScope,
          data: {
            name: 'branch-feature',
            entity_type: 'feature',
            content: 'branch-specific-feature'
          }
        }]
      };

      await memoryStore(orgData.items);
      await memoryStore(projectData.items);
      await memoryStore(branchData.items);

      // Test scope inheritance behavior
      const branchSearch = await smartMemoryFind({
        query: 'policy OR config OR feature',
        scope: branchScope,
        mode: 'auto'
      });

      // Should only return data from same or broader scopes if allowed
      const foundTitles = branchSearch.hits.map(hit => hit.title);

      // This depends on the inheritance policy - test current behavior
      expect(branchSearch.hits.length).toBeGreaterThanOrEqual(1);

      // Verify no unauthorized access to different org/project data
      expect(foundTitles.every(title =>
        ['org-policy', 'project-config', 'branch-feature'].includes(title)
      )).toBe(true);
    });
  });

  describe('Scope Injection Prevention', () => {
    it('should prevent scope parameter injection', async () => {
      const injectionScopes = [
        { org: 'test-org', project: 'project-1', branch: 'main\' OR 1=1 --' },
        { org: 'test-org', project: 'project-1\', \'main\' -- ', branch: 'injected' },
        { org: 'test-org', project: 'project-1; DROP TABLE knowledge_entity; --', branch: 'main' },
        { org: 'test-org', project: 'project-1\' UNION SELECT name FROM knowledge_entity --', branch: 'main' },
      ];

      for (const injectionScope of injectionScopes) {
        const injectionEntity = {
          items: [{
            kind: 'entity' as const,
            scope: injectionScope,
            data: {
              name: 'injection-test',
              entity_type: 'test'
            }
          }]
        };

        try {
          const result = await memoryStore(injectionEntity.items);

          if (result.stored.length > 0) {
            // Should sanitize scope parameters
            const storedData = JSON.stringify(result.stored);
            expect(storedData).not.toContain('OR 1=1');
            expect(storedData).not.toContain('DROP TABLE');
            expect(storedData).not.toContain('UNION SELECT');
            expect(storedData).not.toContain('--');
          }
        } catch (error) {
          // Rejection is expected for injection attempts
          expect(error).toBeInstanceOf(Error);
        }
      }
    });
  });

  describe('Performance and Scalability', () => {
    it('should maintain isolation under high load', async () => {
      const scopes = Array.from({ length: 100 }, (_, i) => ({
        org: `org-${i % 10}`,
        project: `project-${i % 20}`,
        branch: `branch-${i % 5}`
      }));

      // Store大量数据 across different scopes
      const storePromises = scopes.map(async (scope, index) => {
        const entity = {
          items: [{
            kind: 'entity' as const,
            scope,
            data: {
              name: `entity-${index}`,
              entity_type: 'test',
              data: `test-data-${index}`
            }
          }]
        };
        return memoryStore(entity.items);
      });

      const results = await Promise.all(storePromises);
      expect(results.every(r => r.stored.length > 0 || r.errors.length > 0)).toBe(true);

      // Test isolation holds under load
      const testScopes = scopes.slice(0, 10);
      const searchPromises = testScopes.map(async scope => {
        const search = await smartMemoryFind({
          query: 'entity',
          scope,
          mode: 'auto'
        });
        return { scope, hits: search.hits };
      });

      const searchResults = await Promise.all(searchPromises);

      // Verify isolation is maintained
      for (const { scope, hits } of searchResults) {
        // Each scope should only see its own data
        const expectedEntityName = `entity-${scopes.findIndex(s =>
          JSON.stringify(s) === JSON.stringify(scope)
        )}`;

        if (hits.length > 0) {
          expect(hits.every(hit => hit.title.includes(expectedEntityName))).toBe(true);
        }
      }
    });
  });
});