/**
 * Comprehensive Unit Tests for Release Knowledge Type
 *
 * Tests release knowledge type functionality including:
 * - Release validation with all required fields
 * - Version format validation (semantic versioning)
 * - Release type validation (major, minor, patch, hotfix)
 * - Release date format validation
 * - Status transitions and lifecycle
 * - Deployment strategy and rollback plan validation
 * - Ticket references and included changes
 * - Error handling and edge cases
 * - Integration with knowledge system
 * - TTL policy and metadata support
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  ReleaseSchema,
  validateKnowledgeItem,
  safeValidateKnowledgeItem,
  KnowledgeItem,
  ReleaseItem,
} from '../../../src/schemas/knowledge-types';

describe('Release Knowledge Type - Comprehensive Testing', () => {
  describe('Release Schema Validation', () => {
    it('should validate complete release with all fields', () => {
      const release = {
        kind: 'release' as const,
        scope: {
          project: 'my-awesome-project',
          branch: 'main',
        },
        data: {
          version: '2.1.0',
          release_type: 'major' as const,
          scope: 'Complete authentication system overhaul with OAuth 2.0 support',
          release_date: '2025-01-15T10:00:00Z',
          status: 'completed' as const,
          ticket_references: ['TICKET-123', 'TICKET-124', 'TICKET-125'],
          included_changes: [
            'OAuth 2.0 provider integration',
            'User session management improvements',
            'Security audit and vulnerability fixes',
          ],
          deployment_strategy: 'Blue-green deployment with zero downtime',
          rollback_plan:
            'Previous version available in backup storage with instant rollback capability',
          testing_status: 'All tests passed - 100% coverage including integration tests',
          approvers: ['tech-lead', 'product-manager', 'devops-lead'],
          release_notes:
            'Major release introducing OAuth 2.0 authentication, improved security, and enhanced user experience.',
          post_release_actions: [
            'Monitor authentication success rates',
            'Update API documentation',
            'Notify stakeholders of completion',
          ],
        },
        tags: { security: true, 'oauth-2.0': true, 'major-release': true },
        source: {
          actor: 'release-manager',
          tool: 'release-automation-system',
          timestamp: '2025-01-15T10:00:00Z',
        },
      };

      const result = ReleaseSchema.safeParse(release);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result['data.kind']).toBe('release');
        expect(result['data.data'].version).toBe('2.1.0');
        expect(result['data.data'].release_type).toBe('major');
        expect(result['data.data'].status).toBe('completed');
        expect(result['data.data'].ticket_references).toHaveLength(3);
        expect(result['data.data'].included_changes).toHaveLength(3);
        expect(result['data.data'].approvers).toHaveLength(3);
      }
    });

    it('should validate minimal release with only required fields', () => {
      const release = {
        kind: 'release' as const,
        scope: {
          project: 'my-awesome-project',
          branch: 'main',
        },
        data: {
          version: '1.0.1',
          release_type: 'patch' as const,
          scope: 'Critical security fix for authentication bypass vulnerability',
          status: 'completed' as const,
        },
      };

      const result = ReleaseSchema.safeParse(release);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result['data.data'].version).toBe('1.0.1');
        expect(result['data.data'].release_type).toBe('patch');
        expect(result['data.data'].scope).toContain('security fix');
        expect(result['data.data'].status).toBe('completed');
        expect(result['data.data'].release_date).toBeUndefined();
      }
    });

    it('should reject release with invalid version format', () => {
      const release = {
        kind: 'release' as const,
        scope: {
          project: 'my-awesome-project',
          branch: 'main',
        },
        data: {
          version: '', // Empty version
          release_type: 'minor' as const,
          scope: 'Feature release',
          status: 'completed' as const,
        },
      };

      const result = ReleaseSchema.safeParse(release);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('release version is required');
      }
    });

    it('should reject release with invalid release_type', () => {
      const release = {
        kind: 'release' as const,
        scope: {
          project: 'my-awesome-project',
          branch: 'main',
        },
        data: {
          version: '1.1.0',
          release_type: 'invalid' as any, // Invalid release type
          scope: 'Feature release',
          status: 'completed' as const,
        },
      };

      const result = ReleaseSchema.safeParse(release);
      expect(result.success).toBe(false);
    });

    it('should reject release with invalid status', () => {
      const release = {
        kind: 'release' as const,
        scope: {
          project: 'my-awesome-project',
          branch: 'main',
        },
        data: {
          version: '1.1.0',
          release_type: 'minor' as const,
          scope: 'Feature release',
          status: 'invalid' as any, // Invalid status
        },
      };

      const result = ReleaseSchema.safeParse(release);
      expect(result.success).toBe(false);
    });

    it('should reject release with invalid release_date format', () => {
      const release = {
        kind: 'release' as const,
        scope: {
          project: 'my-awesome-project',
          branch: 'main',
        },
        data: {
          version: '1.1.0',
          release_type: 'minor' as const,
          scope: 'Feature release',
          release_date: '2025-01-15', // Invalid datetime format
          status: 'completed' as const,
        },
      };

      const result = ReleaseSchema.safeParse(release);
      expect(result.success).toBe(false);
    });

    it('should reject release with empty scope description', () => {
      const release = {
        kind: 'release' as const,
        scope: {
          project: 'my-awesome-project',
          branch: 'main',
        },
        data: {
          version: '1.1.0',
          release_type: 'minor' as const,
          scope: '', // Empty scope description
          status: 'completed' as const,
        },
      };

      const result = ReleaseSchema.safeParse(release);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('release scope description is required');
      }
    });

    it('should validate release with very long version', () => {
      const release = {
        kind: 'release' as const,
        scope: {
          project: 'my-awesome-project',
          branch: 'main',
        },
        data: {
          version: '1.0.0'.repeat(20), // 80 characters
          release_type: 'patch' as const,
          scope: 'Patch release',
          status: 'completed' as const,
        },
      };

      const result = ReleaseSchema.safeParse(release);
      expect(result.success).toBe(true);
    });

    it('should reject release with overly long version', () => {
      const release = {
        kind: 'release' as const,
        scope: {
          project: 'my-awesome-project',
          branch: 'main',
        },
        data: {
          version: '1.0.0'.repeat(26), // 102 characters - exceeds limit
          release_type: 'patch' as const,
          scope: 'Patch release',
          status: 'completed' as const,
        },
      };

      const result = ReleaseSchema.safeParse(release);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('version must be 100 characters or less');
      }
    });

    it('should validate release with semantic versioning patterns', () => {
      const validVersions = [
        '1.0.0',
        '2.1.3',
        '10.15.20',
        '1.0.0-alpha',
        '1.0.0-beta.1',
        '1.0.0-rc.1',
        '2.0.0+build.1',
        '1.1.0-alpha.1+build.2',
      ];

      validVersions.forEach((version) => {
        const release = {
          kind: 'release' as const,
          scope: {
            project: 'my-awesome-project',
            branch: 'main',
          },
          data: {
            version,
            release_type: 'minor' as const,
            scope: `Version ${version} release`,
            status: 'completed' as const,
          },
        };

        const result = ReleaseSchema.safeParse(release);
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result['data.data'].version).toBe(version);
        }
      });
    });

    it('should validate all release types', () => {
      const releaseTypes = ['major', 'minor', 'patch', 'hotfix'] as const;

      releaseTypes.forEach((type) => {
        const release = {
          kind: 'release' as const,
          scope: {
            project: 'my-awesome-project',
            branch: 'main',
          },
          data: {
            version: '1.0.0',
            release_type: type,
            scope: `${type} release`,
            status: 'completed' as const,
          },
        };

        const result = ReleaseSchema.safeParse(release);
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result['data.data'].release_type).toBe(type);
        }
      });
    });

    it('should validate all release statuses', () => {
      const statuses = ['planned', 'in_progress', 'completed', 'rolled_back'] as const;

      statuses.forEach((statusValue) => {
        const release = {
          kind: 'release' as const,
          scope: {
            project: 'my-awesome-project',
            branch: 'main',
          },
          data: {
            version: '1.0.0',
            release_type: 'minor' as const,
            scope: 'Feature release',
            status: statusValue,
          },
        };

        const result = ReleaseSchema.safeParse(release);
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result['data.data'].status).toBe(statusValue);
        }
      });
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle complex release with many features and fixes', () => {
      const complexRelease = {
        kind: 'release' as const,
        scope: {
          project: 'enterprise-platform',
          branch: 'main',
        },
        data: {
          version: '3.5.0',
          release_type: 'minor' as const,
          scope: 'Major feature update with comprehensive improvements across all modules',
          release_date: '2025-02-01T09:00:00Z',
          status: 'completed' as const,
          ticket_references: [
            'FEAT-1001',
            'FEAT-1002',
            'FEAT-1003',
            'FEAT-1004',
            'FEAT-1005',
            'BUG-2001',
            'BUG-2002',
            'BUG-2003',
            'BUG-2004',
            'BUG-2005',
            'SEC-3001',
            'SEC-3002',
            'PERF-4001',
            'PERF-4002',
          ],
          included_changes: [
            'Advanced analytics dashboard with real-time data visualization',
            'Multi-tenant architecture improvements',
            'Enhanced security audit logging',
            'Performance optimizations reducing query time by 40%',
            'Mobile responsive design improvements',
            'API rate limiting and throttling',
            'Database connection pooling optimization',
            'Background job processing improvements',
            'User interface accessibility enhancements',
            'Third-party integration updates',
          ],
          deployment_strategy:
            'Gradual rollout with feature flags, monitoring, and automated rollback triggers',
          rollback_plan:
            'Instant rollback available with database migration reversal and service restart',
          testing_status:
            'Comprehensive testing completed: unit (95%), integration (90%), E2E (85%), performance (passed), security (passed)',
          approvers: [
            'cto',
            'head-of-engineering',
            'product-manager',
            'qa-lead',
            'security-officer',
            'devops-lead',
            'customer-success-lead',
          ],
          release_notes: `Version 3.5.0 represents a significant milestone in our platform evolution.

Key Features:
- Real-time analytics with customizable dashboards
- Enhanced multi-tenant security and isolation
- Performance improvements across all core modules
- Mobile-first responsive design

Bug Fixes:
- Resolved memory leaks in long-running processes
- Fixed authentication token refresh issues
- Corrected data export formatting problems
- Addressed concurrent user session conflicts
- Fixed API pagination edge cases

Security Improvements:
- Enhanced audit logging for compliance
- Improved input validation and sanitization
- Updated third-party dependencies for security patches`,
          post_release_actions: [
            'Monitor system performance metrics for 24 hours',
            'Conduct post-release security audit',
            'Update customer documentation and help center',
            'Send release notification to all stakeholders',
            'Schedule follow-up performance review meeting',
            'Update internal training materials',
            'Monitor customer support tickets for issues',
          ],
        },
        tags: {
          'enterprise-grade': true,
          'multi-tenant': true,
          analytics: true,
          security: true,
          performance: true,
          'mobile-responsive': true,
          'feature-flags': true,
          'comprehensive-testing': true,
        },
        source: {
          actor: 'release-automation-system',
          tool: 'enterprise-release-pipeline',
          timestamp: '2025-02-01T09:00:00Z',
        },
      };

      const result = ReleaseSchema.safeParse(complexRelease);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result['data.data'].ticket_references).toHaveLength(14);
        expect(result['data.data'].included_changes).toHaveLength(10);
        expect(result['data.data'].approvers).toHaveLength(7);
        expect(result['data.data'].post_release_actions).toHaveLength(7);
        expect(Object.keys(result['data.tags']!)).toHaveLength(8);
      }
    });

    it('should handle release with breaking changes and detailed impact', () => {
      const breakingRelease = {
        kind: 'release' as const,
        scope: {
          project: 'api-platform',
          branch: 'main',
        },
        data: {
          version: '2.0.0',
          release_type: 'major' as const,
          scope: 'Breaking API changes for improved security and performance',
          release_date: '2025-01-15T10:00:00Z',
          status: 'completed' as const,
          ticket_references: ['BREAK-001', 'BREAK-002', 'SEC-001'],
          included_changes: [
            'Authentication endpoint changed from /api/v1/auth to /api/v2/auth',
            'Request format now requires JSON content-type header',
            'Response format standardized with consistent error handling',
            'Deprecated legacy XML support - removed',
            'Rate limiting now enforced per API key rather than per IP',
          ],
          deployment_strategy:
            'Extended maintenance window with backward compatibility layer for 30 days',
          rollback_plan:
            'Restore v1.9.x branch and revert database schema changes, maintain v1 compatibility layer during transition',
          testing_status:
            'Extensive regression testing completed, migration scripts validated, performance benchmarks show 60% improvement',
          approvers: ['cto', 'api-lead', 'security-architect', 'customer-advocate'],
          release_notes: `IMPORTANT BREAKING CHANGES IN VERSION 2.0.0

This release contains breaking changes that require action from all API consumers.

Breaking Changes:
1. Authentication endpoint moved to /api/v2/auth
2. All requests must include Content-Type: application/json header
3. XML support has been completely removed
4. Rate limiting scope changed from IP-based to API key-based
5. Error response format standardized

Migration Required:
- Update authentication endpoint URLs
- Add proper content-type headers to all requests
- Convert any remaining XML integrations to JSON
- Update rate limiting strategy and monitoring
- Update error handling logic for new response format

Support:
- v1.9.x compatibility layer available until 2025-02-15
- Migration guide available at /docs/migration/v2
- Dedicated support channel: migration-support@api-platform.com`,
          post_release_actions: [
            'Monitor API error rates and response times',
            'Track v1.9.x compatibility layer usage',
            'Provide proactive support to high-volume customers',
            'Update API documentation and code examples',
            'Conduct post-release customer feedback survey',
            'Monitor security metrics and authentication success rates',
          ],
        },
        tags: {
          'breaking-changes': true,
          'api-v2': true,
          'migration-required': true,
          'security-improvements': true,
          'backward-compatibility': true,
          'customer-communication': true,
        },
        source: {
          actor: 'api-team-lead',
          tool: 'api-release-manager',
          timestamp: '2025-01-15T10:00:00Z',
        },
      };

      const result = ReleaseSchema.safeParse(breakingRelease);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result['data.data'].release_type).toBe('major');
        expect(result['data.data'].version).toBe('2.0.0');
        expect(result['data.data'].scope).toContain('Breaking API changes');
        expect(result['data.data'].release_notes).toContain('IMPORTANT BREAKING CHANGES');
      }
    });

    it('should handle hotfix release with urgent security patches', () => {
      const hotfixRelease = {
        kind: 'release' as const,
        scope: {
          project: 'payment-system',
          branch: 'hotfix/security-patch-2025-01',
        },
        data: {
          version: '1.2.1',
          release_type: 'hotfix' as const,
          scope: 'Critical security vulnerability fix in payment processing',
          release_date: '2025-01-10T22:30:00Z',
          status: 'completed' as const,
          ticket_references: ['SEC-CRITICAL-001', 'PAYMENT-BUG-001'],
          included_changes: [
            'Fixed SQL injection vulnerability in payment validation',
            'Enhanced input sanitization for payment forms',
            'Updated encryption key rotation mechanism',
            'Added comprehensive audit logging for payment attempts',
          ],
          deployment_strategy: 'Emergency hotfix deployment with immediate rollout to all regions',
          rollback_plan:
            'Previous version (1.2.0) available in backup with instant rollback capability',
          testing_status:
            'Security testing completed, vulnerability scans passed, payment processing verified in staging',
          approvers: ['cto', 'security-officer', 'head-of-engineering'],
          release_notes: `CRITICAL SECURITY HOTFIX - VERSION 1.2.1

IMMEDIATE ACTION REQUIRED

This hotfix addresses a critical security vulnerability discovered in payment processing.

Security Issue:
- SQL injection vulnerability in payment validation endpoint
- Potential for unauthorized payment data access
- Affects all payment processing operations

Fix Applied:
- Comprehensive input validation and sanitization
- Parameterized query implementation
- Enhanced security monitoring and alerting
- Audit logging for all payment operations

Actions Taken:
- Emergency patch deployed to all production environments
- Security audit completed for all payment-related code
- Enhanced monitoring implemented for detection of similar issues
- Incident response team activated and monitoring for unusual activity

Customer Impact:
- No customer data was compromised
- Payment processing continued without interruption
- Enhanced security measures now in place
- Ongoing monitoring and surveillance active

Support:
- 24/7 security team monitoring active
- Customer support teams briefed on the issue
- Technical documentation updated with security best practices`,
          post_release_actions: [
            'Continue 24/7 security monitoring for 7 days',
            'Conduct comprehensive security audit of entire codebase',
            'Review and update security development practices',
            'Provide security briefing to all engineering teams',
            'Update security training materials',
            'Implement additional automated security testing',
            'Schedule follow-up security review in 30 days',
          ],
        },
        tags: {
          'critical-security': true,
          hotfix: true,
          emergency: true,
          'payment-security': true,
          'sql-injection': true,
          'vulnerability-patch': true,
          'customer-safety': true,
        },
        source: {
          actor: 'incident-response-team',
          tool: 'emergency-release-system',
          timestamp: '2025-01-10T22:30:00Z',
        },
      };

      const result = ReleaseSchema.safeParse(hotfixRelease);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result['data.data'].release_type).toBe('hotfix');
        expect(result['data.data'].version).toBe('1.2.1');
        expect(result['data.data'].scope).toContain('Critical security vulnerability');
        expect(result['data.data'].release_notes).toContain('CRITICAL SECURITY HOTFIX');
      }
    });

    it('should handle version format edge cases', () => {
      const edgeCaseVersions = [
        '0.0.1', // Initial development version
        '10.20.30', // Large version numbers
        '1.0.0-alpha', // Pre-release version
        '1.0.0-beta.1', // Beta with build number
        '1.0.0-rc.2', // Release candidate
        '1.0.0+build.1', // Build metadata
        '1.0.0-alpha.1+build.2', // Full semantic versioning
        'v1.2.3', // Version with v prefix (still valid string)
        'release-1.0.0', // Version with release prefix (still valid string)
      ];

      edgeCaseVersions.forEach((version) => {
        const release = {
          kind: 'release' as const,
          scope: {
            project: 'version-testing',
            branch: 'main',
          },
          data: {
            version,
            release_type: 'patch' as const,
            scope: `Testing version format: ${version}`,
            status: 'completed' as const,
          },
        };

        const result = ReleaseSchema.safeParse(release);
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result['data.data'].version).toBe(version);
        }
      });
    });

    it('should handle release with minimal metadata but comprehensive deployment plan', () => {
      const minimalRelease = {
        kind: 'release' as const,
        scope: {
          project: 'minimal-service',
          branch: 'main',
        },
        data: {
          version: '1.0.0',
          release_type: 'major' as const,
          scope: 'Initial service deployment',
          release_date: '2025-01-01T00:00:00Z',
          status: 'completed' as const,
          deployment_strategy: `Multi-stage deployment pipeline:
1. Canary deployment to 5% of traffic
2. Monitor key metrics for 15 minutes
3. Gradual increase to 25% traffic
4. Full rollout to 100% traffic
5. Post-deployment monitoring for 1 hour

Key Monitoring Metrics:
- Response time < 100ms (p95)
- Error rate < 0.1%
- CPU utilization < 70%
- Memory usage < 80%
- Database connection pool < 80%`,
          rollback_plan: `Automated rollback procedure:
1. Detect failure condition
2. Immediately halt new deployments
3. Route traffic back to previous version
4. Verify system health
5. Notify stakeholders

Manual rollback triggers:
- Error rate > 1% for 5 minutes
- Response time > 500ms for 10 minutes
- Critical service failures
- Customer-reported issues`,
          testing_status: `Comprehensive testing completed:
✅ Unit tests: 245/245 passing
✅ Integration tests: 89/89 passing
✅ Load testing: 10x production load
✅ Security scanning: 0 vulnerabilities
✅ Performance testing: All benchmarks met`,
          approvers: ['devops-lead', 'tech-lead'],
        },
      };

      const result = ReleaseSchema.safeParse(minimalRelease);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result['data.data'].deployment_strategy).toContain('Canary deployment');
        expect(result['data.data'].rollback_plan).toContain('Automated rollback procedure');
        expect(result['data.data'].testing_status).toContain('245/245 passing');
        expect(result['data.data'].approvers).toHaveLength(2);
      }
    });
  });

  describe('Integration with Knowledge System', () => {
    it('should validate release using validateKnowledgeItem function', () => {
      const release = {
        kind: 'release' as const,
        scope: {
          project: 'integration-test',
          branch: 'main',
        },
        data: {
          version: '1.5.0',
          release_type: 'minor' as const,
          scope: 'Integration testing release',
          release_date: '2025-01-25T12:00:00Z',
          status: 'completed' as const,
        },
      };

      // validateKnowledgeItem directly returns the parsed data or throws
      const result = validateKnowledgeItem(release);
      expect(result).toBeDefined();
      expect(result.kind).toBe('release');
      expect(result['data.version']).toBe('1.5.0');
    });

    it('should handle invalid release using validateKnowledgeItem function', () => {
      const invalidRelease = {
        kind: 'release' as const,
        scope: {
          project: 'integration-test',
          branch: 'main',
        },
        data: {
          version: '', // Invalid empty version
          release_type: 'invalid' as any, // Invalid release type
          scope: 'Invalid release test',
          status: 'completed' as const,
        },
      };

      // validateKnowledgeItem throws on validation error
      expect(() => validateKnowledgeItem(invalidRelease)).toThrow();
    });

    it('should handle release validation using safeValidateKnowledgeItem function', () => {
      const release = {
        kind: 'release' as const,
        scope: {
          project: 'safe-validation-test',
          branch: 'main',
        },
        data: {
          version: '1.0.0',
          release_type: 'major' as const,
          scope: 'Safe validation test release',
          status: 'completed' as const,
        },
      };

      const result = safeValidateKnowledgeItem(release, 'release');
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result['data.kind']).toBe('release');
        expect(result['data.data'].version).toBe('1.0.0');
      }
    });

    it('should handle type mismatch in safeValidateKnowledgeItem', () => {
      const nonRelease = {
        kind: 'entity' as const, // Wrong kind
        scope: {
          project: 'type-mismatch-test',
          branch: 'main',
        },
        data: {
          version: '1.0.0',
          release_type: 'major' as const,
          scope: 'This should fail',
          status: 'completed' as const,
        },
      };

      const result = safeValidateKnowledgeItem(nonRelease, 'release');
      expect(result.success).toBe(false);
    });

    it('should support TTL policy for releases', () => {
      const releaseWithTTL = {
        kind: 'release' as const,
        scope: {
          project: 'ttl-test',
          branch: 'main',
        },
        data: {
          version: '1.0.0',
          release_type: 'major' as const,
          scope: 'TTL policy test release',
          status: 'completed' as const,
        },
        ttl_policy: 'default' as const,
      };

      const result = ReleaseSchema.safeParse(releaseWithTTL);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result['data.ttl_policy']).toBeDefined();
        expect(result['data.ttl_policy']).toBe('default');
      }
    });

    it('should support comprehensive metadata and tags', () => {
      const releaseWithMetadata = {
        kind: 'release' as const,
        scope: {
          project: 'metadata-test',
          branch: 'main',
        },
        data: {
          version: '2.1.0',
          release_type: 'minor' as const,
          scope: 'Metadata and tags test release',
          release_date: '2025-01-30T15:45:00Z',
          status: 'completed' as const,
        },
        tags: {
          'feature-flags': true,
          'beta-testing': true,
          'customer-feedback': true,
          'performance-improvements': true,
          'security-enhancements': true,
          'ui-updates': true,
          'api-changes': true,
          'bug-fixes': true,
          'documentation-updated': true,
          'testing-completed': true,
          'team-alpha': 'backend',
          'team-beta': 'frontend',
          'team-gamma': 'qa',
          priority: 'high',
          'customer-impact': 'medium',
          'rollback-tested': true,
          'monitoring-enabled': true,
          'incident-response-ready': true,
        },
        source: {
          actor: 'release-coordinator',
          tool: 'enterprise-release-platform',
          timestamp: '2025-01-30T15:45:00Z',
        },
        idempotency_key: 'release-2.1.0-2025-01-30-unique-key',
      };

      const result = ReleaseSchema.safeParse(releaseWithMetadata);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(Object.keys(result['data.tags']!)).toHaveLength(18);
        expect(result['data.tags']!['feature-flags']).toBe(true);
        expect(result['data.tags']!['team-alpha']).toBe('backend');
        expect(result['data.source']!.actor).toBe('release-coordinator');
        expect(result['data.source']!.tool).toBe('enterprise-release-platform');
        expect(result['data.idempotency_key']).toBeDefined();
      }
    });
  });

  describe('Advanced Release Scenarios', () => {
    it('should handle feature release with gradual rollout strategy', () => {
      const featureRelease = {
        kind: 'release' as const,
        scope: {
          project: 'saas-platform',
          branch: 'main',
        },
        data: {
          version: '3.2.0',
          release_type: 'minor' as const,
          scope: 'Advanced analytics and reporting features with gradual rollout',
          release_date: '2025-01-22T09:00:00Z',
          status: 'in_progress' as const,
          ticket_references: ['FEAT-3001', 'FEAT-3002', 'FEAT-3003', 'INFRA-1001'],
          included_changes: [
            'Real-time analytics dashboard with custom widgets',
            'Advanced reporting engine with scheduled reports',
            'Data export improvements (CSV, Excel, PDF)',
            'Enhanced data visualization capabilities',
            'Performance optimizations for large datasets',
          ],
          deployment_strategy: `Gradual Feature Rollout Strategy:

Phase 1 (Day 1-2): Internal Testing (5% users)
- Engineering and QA teams
- Feature flag: analytics_v3_enabled = false
- Monitoring: Error rates, performance metrics

Phase 2 (Day 3-5): Beta Customers (20% users)
- Selected beta customers with opt-in
- Feature flag: analytics_v3_enabled = true (beta group)
- Monitoring: User engagement, feature adoption

Phase 3 (Day 6-10): Early Adopters (50% users)
- Customers with high usage patterns
- Feature flag: analytics_v3_enabled = true (early adopters)
- Monitoring: System performance, user feedback

Phase 4 (Day 11+): Full Rollout (100% users)
- All customers
- Feature flag: analytics_v3_enabled = true (all users)
- Monitoring: Complete system metrics

Rollback Triggers:
- Error rate > 0.5% for 10 minutes
- Response time > 2 seconds for 5 minutes
- Customer complaints > 5 per hour
- System resource utilization > 90%`,
          rollback_plan: `Feature Flag Rollback:
1. Disable analytics_v3_enabled feature flag
2. Route all users back to analytics v2
3. Verify system stability
4. Monitor user experience
5. Investigate root cause

Database Rollback:
1. Stop new analytics data processing
2. Revert database schema changes
3. Restore data migration backups
4. Validate data integrity
5. Resume normal operations`,
          testing_status: `Comprehensive Testing Results:
✅ Unit Tests: 1,234/1,234 passing (100%)
✅ Integration Tests: 456/456 passing (100%)
✅ E2E Tests: 78/80 passing (97.5%)
✅ Performance Tests: All benchmarks met
✅ Load Tests: 10x production load successful
✅ Security Tests: No critical vulnerabilities
✅ Feature Flag Testing: All scenarios validated
✅ Rollback Testing: Verified and documented`,
          approvers: [
            'vp-engineering',
            'product-manager',
            'head-of-qa',
            'devops-lead',
            'customer-success-director',
          ],
          release_notes: `Version 3.2.0: Advanced Analytics & Reporting Features

🚀 New Features:
• Real-time analytics dashboard with customizable widgets
• Advanced reporting engine with automated scheduling
• Enhanced data export capabilities
• Interactive data visualization tools
• Performance optimizations for large datasets

📊 Analytics Improvements:
- Real-time data processing with sub-second updates
- Custom dashboard creation and sharing
- Advanced filtering and segmentation options
- Historical data comparison and trend analysis
- Mobile-responsive analytics interface

📈 Reporting Enhancements:
- Scheduled report generation and delivery
- Custom report templates and branding
- Multi-format export (CSV, Excel, PDF)
- Automated data refresh and caching
- Report sharing and collaboration features

⚡ Performance Improvements:
- 50% faster dashboard loading times
- Optimized query performance for large datasets
- Reduced memory usage by 30%
- Improved data processing throughput
- Enhanced caching mechanisms

🔧 Technical Details:
- New analytics processing engine
- Improved data pipeline architecture
- Enhanced error handling and recovery
- Better resource utilization and scaling
- Comprehensive monitoring and alerting

📋 Migration Notes:
- Existing reports will continue to work
- New features available via feature flags
- Gradual rollout over 10 days
- Comprehensive documentation available
- Training sessions scheduled for next week`,
          post_release_actions: [
            'Monitor feature flag performance and usage metrics',
            'Collect user feedback and analytics data',
            'Conduct daily stability reviews during rollout',
            'Update documentation and training materials',
            'Schedule customer webinars for new features',
            'Monitor system performance and capacity',
            'Track feature adoption and engagement rates',
            'Address customer issues and support tickets',
            'Prepare follow-up improvements based on feedback',
          ],
        },
        tags: {
          analytics: true,
          reporting: true,
          'gradual-rollout': true,
          'feature-flags': true,
          performance: true,
          'user-feedback': true,
          'beta-testing': true,
          'customer-communication': true,
        },
      };

      const result = ReleaseSchema.safeParse(featureRelease);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result['data.data'].version).toBe('3.2.0');
        expect(result['data.data'].release_type).toBe('minor');
        expect(result['data.data'].status).toBe('in_progress');
        expect(result['data.data'].deployment_strategy).toContain('Gradual Feature Rollout Strategy');
        expect(result['data.data'].testing_status).toContain('1,234/1,234 passing');
      }
    });

    it('should handle database migration release with detailed rollback procedures', () => {
      const dbMigrationRelease = {
        kind: 'release' as const,
        scope: {
          project: 'data-platform',
          branch: 'main',
        },
        data: {
          version: '2.0.0',
          release_type: 'major' as const,
          scope: 'Database schema migration and data model overhaul',
          release_date: '2025-01-18T02:00:00Z',
          status: 'completed' as const,
          ticket_references: ['DB-MIGRATION-001', 'SCHEMA-CHANGE-001', 'DATA-MODEL-001'],
          included_changes: [
            'User table schema overhaul with new relationship structure',
            'Migration from legacy authentication to new auth system',
            'Data model normalization and optimization',
            'Index improvements for query performance',
            'Data consistency validation and cleanup',
          ],
          deployment_strategy: `Database Migration Strategy:

Pre-Migration (2 hours before):
1. Create full database backups
2. Verify backup integrity
3. Prepare migration scripts
4. Set application to read-only mode
5. Drain active connections

Migration Execution (1 hour window):
1. Execute schema migration scripts
2. Run data transformation and migration
3. Validate data integrity and consistency
4. Update application configuration
5. Perform smoke tests

Post-Migration (2 hours monitoring):
1. Monitor application performance
2. Validate all critical functions
3. Check data consistency
4. Monitor error rates
5. Prepare rollback if needed

Maintenance Window:
- Scheduled: 2025-01-18 02:00-05:00 UTC
- Duration: 3 hours maximum
- Customer notification: 24 hours in advance
- Support team: On standby during migration`,
          rollback_plan: `Comprehensive Rollback Procedure:

Immediate Rollback Triggers:
- Data corruption detected
- Application errors > 1% for 5 minutes
- Migration script failures
- Performance degradation > 50%

Rollback Steps:
1. Stop all application services
2. Restore database from pre-migration backup
3. Revert application configuration
4. Validate restored data integrity
5. Restart application services
6. Perform smoke tests
7. Monitor system stability

Data Recovery Options:
- Point-in-time recovery to 01:55 UTC
- Full backup restoration (4-6 hours)
- Partial rollback for specific tables
- Manual data reconciliation

Communication Plan:
- Immediate incident response team notification
- Customer communication within 30 minutes
- Status updates every 15 minutes
- Post-incident report within 24 hours`,
          testing_status: `Database Migration Testing:
✅ Migration scripts validated in staging (5 runs)
✅ Data integrity checks passed (10M+ records)
✅ Performance benchmarks met (queries < 100ms)
✅ Rollback procedures tested and verified
✅ Backup/restore procedures validated
✅ Application compatibility tested
✅ Load testing with new schema (5x traffic)
✅ Security testing with new data model`,
          approvers: [
            'database-architect',
            'vp-engineering',
            'head-of-operations',
            'compliance-officer',
            'data-privacy-officer',
          ],
          release_notes: `Version 2.0.0: Database Migration & Data Model Overhaul

🗄️ Database Changes:
• Complete user table schema restructure
• New authentication system integration
• Optimized data relationships and indexing
• Enhanced data consistency and validation
• Improved query performance and scalability

📊 Migration Details:
- 10M+ user records migrated
- Zero data loss during migration
- 99.9% data integrity maintained
- Migration completed in 45 minutes
- Rollback capability preserved

⚡ Performance Improvements:
- Query performance improved by 60%
- Database size optimized by 25%
- Index optimization for common queries
- Connection pooling improvements
- Caching layer enhancements

🔒 Security & Compliance:
- Enhanced data encryption at rest
- Improved access control and auditing
- GDPR compliance improvements
- Data retention policy updates
- Security audit completion

⚠️ Important Notes:
- Migration completed successfully
- All systems operational
- Performance improvements active
- Monitoring increased for 72 hours
- Support team on high alert

📞 Support Information:
- 24/7 monitoring active
- Enhanced alerting configured
- Support team trained on new schema
- Documentation updated and available`,
          post_release_actions: [
            'Continue enhanced monitoring for 72 hours',
            'Validate all automated processes with new schema',
            'Update all data documentation and schemas',
            'Conduct performance review meeting',
            'Update development and staging environments',
            'Review and optimize slow queries',
            'Train support team on new data model',
            'Monitor backup and recovery procedures',
            'Schedule follow-up database health check',
          ],
        },
        tags: {
          'database-migration': true,
          'schema-change': true,
          'major-release': true,
          'data-integrity': true,
          performance: true,
          security: true,
          compliance: true,
          'rollback-tested': true,
        },
      };

      const result = ReleaseSchema.safeParse(dbMigrationRelease);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result['data.data'].version).toBe('2.0.0');
        expect(result['data.data'].release_type).toBe('major');
        expect(result['data.data'].status).toBe('completed');
        expect(result['data.data'].scope).toContain('Database schema migration');
        expect(result['data.data'].deployment_strategy).toContain('Pre-Migration');
        expect(result['data.data'].rollback_plan).toContain('Immediate Rollback Triggers');
      }
    });
  });
});
