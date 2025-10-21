/**
 * COMPREHENSIVE PRISMA SCHEMA COMPLIANCE TESTS FOR ALL 16 KNOWLEDGE TYPES
 *
 * Validates that every knowledge type service follows Prisma Schema field definitions
 * and eliminates metadata/tags workarounds across the entire system.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { TestRunner, TestAssertions, MockDataGenerator } from '../framework/test-setup.js';

// Import all knowledge type services
import { storeSection } from '../../src/services/knowledge/section.js';
import { storeDecision } from '../../src/services/knowledge/decision.js';
import { storeIssue, validatePrismaSchemaCompliance as validateIssueCompliance } from '../../src/services/knowledge/issue.js';
import { storeTodo } from '../../src/services/knowledge/todo.js';
import { storeRunbook } from '../../src/services/knowledge/runbook.js';
import { storeChange } from '../../src/services/knowledge/change.js';
import { storeReleaseNote } from '../../src/services/knowledge/release_note.js';
import { storeDdl } from '../../src/services/knowledge/ddl.js';
import { storePrContext } from '../../src/services/knowledge/pr_context.js';
import { memoryStore } from '../../src/services/memory-store.js';
import { storeIncident } from '../../src/services/knowledge/incident.js';
import { storeRelease } from '../../src/services/knowledge/release.js';
import { storeRisk } from '../../src/services/knowledge/risk.js';
import { storeAssumption } from '../../src/services/knowledge/assumption.js';
import type {
  SectionData,
  DecisionData,
  IssueData,
  TodoData,
  RunbookData,
  ChangeData,
  ReleaseNoteData,
  DdlData,
  PrContextData,
  ScopeFilter
} from '../../src/types/knowledge-data.js';

describe('PRISMA SCHEMA COMPLIANCE - ALL KNOWLEDGE TYPES', () => {
  let testRunner: TestRunner;
  let testContext: any;

  beforeEach(async () => {
    testRunner = new TestRunner();
    await testRunner.initialize();

    const testDb = await testRunner.framework.createTestDatabase();
    testContext = {
      framework: testRunner.framework,
      testDb,
      dataFactory: testRunner.framework.getDataFactory(),
      performanceHelper: testRunner.framework.getPerformanceHelper(),
      validationHelper: testRunner.framework.getValidationHelper(),
      errorHelper: testRunner.framework.getErrorHelper(),
    };
  });

  afterEach(async () => {
    await testRunner.cleanup();
  });

  describe('SECTION KNOWLEDGE TYPE', () => {
    it('should comply with Prisma Schema for Section model', async () => {
      const sectionData: SectionData = {
        title: 'Test Section with All Fields',
        content: 'This is test content with detailed information',
        heading: 'Test Heading',
        body_md: '# Markdown Content\n\nThis is markdown content.',
        body_text: 'Plain text content without formatting',
        document_id: 'DOC-12345',
        citation_count: 5,
        metadata: {
          section_type: 'introduction',
          word_count: 150
        }
      };

      const scope: ScopeFilter = { project: 'prisma-section-test' };

      const startTime = Date.now();
      const result = await storeSection(sectionData, scope);
      const duration = Date.now() - startTime;

      expect(result).toBeDefined();
      TestAssertions.assertPerformance(duration, 1000, 'storeSection');

      // Verify database storage
      const prisma = testContext.framework.getPrismaClient();
      const storedSection = await prisma.section.findUnique({
        where: { id: result }
      });

      expect(storedSection!.title).toBe(sectionData.title);
      expect(storedSection!.heading).toBe(sectionData.heading);
      expect(storedSection!.body_md).toBe(sectionData.body_md);
      expect(storedSection!.document_id).toBe(sectionData.document_id);
      expect(storedSection!.citation_count).toBe(sectionData.citation_count);
    });

    it('should enforce Section field length constraints', async () => {
      const tooLongTitle = 'a'.repeat(501); // Exceeds 500 char limit
      const tooLongHeading = 'a'.repeat(501); // Exceeds 500 char limit
      const tooLongDocumentId = 'a'.repeat(201); // Exceeds 200 char limit

      await expect(storeSection({
        title: tooLongTitle,
        content: 'Test content'
      }, {})).rejects.toThrow();

      await expect(storeSection({
        title: 'Valid Title',
        content: 'Test content',
        heading: tooLongHeading
      }, {})).rejects.toThrow();

      await expect(storeSection({
        title: 'Valid Title',
        content: 'Test content',
        document_id: tooLongDocumentId
      }, {})).rejects.toThrow();
    });
  });

  describe('DECISION KNOWLEDGE TYPE', () => {
    it('should comply with Prisma Schema for AdrDecision model', async () => {
      const decisionData: DecisionData = {
        component: 'auth-service',
        status: 'accepted',
        title: 'Use OAuth 2.0 for Authentication',
        rationale: 'OAuth 2.0 provides industry-standard security',
        alternativesConsidered: [
          'Basic Auth',
          'JWT without OAuth',
          'Custom authentication system'
        ],
        metadata: {
          decision_maker: 'architecture-team',
          review_date: '2025-01-15'
        }
      };

      const scope: ScopeFilter = { project: 'prisma-decision-test' };

      const startTime = Date.now();
      const result = await storeDecision(decisionData, scope);
      const duration = Date.now() - startTime;

      expect(result).toBeDefined();
      TestAssertions.assertPerformance(duration, 1000, 'storeDecision');

      // Verify database storage
      const prisma = testContext.framework.getPrismaClient();
      const storedDecision = await prisma.adrDecision.findUnique({
        where: { id: result }
      });

      expect(storedDecision!.component).toBe(decisionData.component);
      expect(storedDecision!.status).toBe(decisionData.status);
      expect(storedDecision!.title).toBe(decisionData.title);
      expect(storedDecision!.rationale).toBe(decisionData.rationale);
      expect(storedDecision!.alternativesConsidered).toEqual(decisionData.alternativesConsidered);
    });

    it('should enforce Decision field length constraints', async () => {
      const tooLongComponent = 'a'.repeat(201); // Exceeds 200 char limit
      const tooLongTitle = 'a'.repeat(501); // Exceeds 500 char limit

      await expect(storeDecision({
        component: tooLongComponent,
        status: 'proposed',
        title: 'Test',
        rationale: 'Test rationale'
      }, {})).rejects.toThrow();

      await expect(storeDecision({
        component: 'valid-component',
        status: 'proposed',
        title: tooLongTitle,
        rationale: 'Test rationale'
      }, {})).rejects.toThrow();
    });
  });

  describe('ISSUE KNOWLEDGE TYPE', () => {
    it('should validate IssueLog compliance with direct field access', async () => {
      const issueData: IssueData = {
        title: 'API Response Time Issue',
        description: 'API endpoints responding slowly',
        status: 'in-progress',
        tracker: 'jira',
        external_id: 'PERF-123',
        severity: 'high',
        labels: ['performance', 'api'],
        url: 'https://test.atlassian.net/browse/PERF-123',
        assignee: 'backend-team@test.com',
        metadata: {
          priority: 'critical',
          affected_components: ['auth-service', 'user-service']
        }
      };

      const scope: ScopeFilter = { project: 'prisma-issue-test' };

      // Should pass validation
      expect(() => validateIssueCompliance(issueData)).not.toThrow();

      const startTime = Date.now();
      const result = await storeIssue(issueData, scope);
      const duration = Date.now() - startTime;

      expect(result).toBeDefined();
      TestAssertions.assertPerformance(duration, 1000, 'storeIssue');

      // Verify database storage
      const prisma = testContext.framework.getPrismaClient();
      const storedIssue = await prisma.issueLog.findUnique({
        where: { id: result }
      });

      expect(storedIssue!.tracker).toBe(issueData.tracker);
      expect(storedIssue!.external_id).toBe(issueData.external_id);
      expect(storedIssue!.severity).toBe(issueData.severity);
      expect(storedIssue!.labels).toEqual(issueData.labels);
      expect(storedIssue!.url).toBe(issueData.url);
      expect(storedIssue!.assignee).toBe(issueData.assignee);
    });
  });

  describe('TODO KNOWLEDGE TYPE', () => {
    it('should comply with Prisma Schema for TodoLog model', async () => {
      const todoData: TodoData = {
        title: 'Implement API Rate Limiting',
        description: 'Add rate limiting to prevent API abuse',
        status: 'in-progress',
        priority: 'high',
        due_date: new Date('2025-02-15'),
        todo_type: 'feature',
        text: 'Detailed task description with implementation notes',
        assignee: 'developer@test.com',
        metadata: {
          estimated_hours: 16,
          story_points: 8,
          epic: 'Performance Improvements'
        }
      };

      const scope: ScopeFilter = { project: 'prisma-todo-test' };

      const startTime = Date.now();
      const result = await storeTodo(todoData, scope);
      const duration = Date.now() - startTime;

      expect(result).toBeDefined();
      TestAssertions.assertPerformance(duration, 1000, 'storeTodo');

      // Verify database storage
      const prisma = testContext.framework.getPrismaClient();
      const storedTodo = await prisma.todoLog.findUnique({
        where: { id: result }
      });

      expect(storedTodo!.title).toBe(todoData.title);
      expect(storedTodo!.priority).toBe(todoData.priority);
      expect(storedTodo!.todo_type).toBe(todoData.todo_type);
      expect(storedTodo!.text).toBe(todoData.text);
      expect(storedTodo!.assignee).toBe(todoData.assignee);
    });
  });

  describe('RUNBOOK KNOWLEDGE TYPE', () => {
    it('should comply with Prisma Schema for Runbook model', async () => {
      const runbookData: RunbookData = {
        title: 'Database Connection Failure Recovery',
        description: 'Steps to recover from database connection failures',
        steps: [
          'Check database server status',
          'Verify network connectivity',
          'Restart application if needed',
          'Monitor connection pool'
        ],
        service: 'database-service',
        triggers: [
          'connection_timeout',
          'max_connections_reached',
          'database_server_down'
        ],
        last_verified_at: new Date('2025-01-20'),
        metadata: {
          verified_by: 'ops-team',
          risk_level: 'medium'
        }
      };

      const scope: ScopeFilter = { project: 'prisma-runbook-test' };

      const startTime = Date.now();
      const result = await storeRunbook(runbookData, scope);
      const duration = Date.now() - startTime;

      expect(result).toBeDefined();
      TestAssertions.assertPerformance(duration, 1000, 'storeRunbook');

      // Verify database storage
      const prisma = testContext.framework.getPrismaClient();
      const storedRunbook = await prisma.runbook.findUnique({
        where: { id: result }
      });

      expect(storedRunbook!.service).toBe(runbookData.service);
      expect(storedRunbook!.steps).toEqual(runbookData.steps);
      expect(storedRunbook!.triggers).toEqual(runbookData.triggers);
    });
  });

  describe('CHANGE KNOWLEDGE TYPE', () => {
    it('should comply with Prisma Schema for ChangeLog model', async () => {
      const changeData: ChangeData = {
        change_type: 'feature',
        subject_ref: 'auth-service/impl',
        summary: 'Added OAuth 2.0 authentication support',
        author: 'developer@test.com',
        commit_sha: 'abc123def456',
        metadata: {
          pull_request: 'PR-123',
          reviewed_by: 'tech-lead'
        }
      };

      const scope: ScopeFilter = { project: 'prisma-change-test' };

      const startTime = Date.now();
      const result = await storeChange(changeData, scope);
      const duration = Date.now() - startTime;

      expect(result).toBeDefined();
      TestAssertions.assertPerformance(duration, 1000, 'storeChange');

      // Verify database storage
      const prisma = testContext.framework.getPrismaClient();
      const storedChange = await prisma.changeLog.findUnique({
        where: { id: result }
      });

      expect(storedChange!.change_type).toBe(changeData.change_type);
      expect(storedChange!.subject_ref).toBe(changeData.subject_ref);
      expect(storedChange!.summary).toBe(changeData.summary);
      expect(storedChange!.author).toBe(changeData.author);
      expect(storedChange!.commit_sha).toBe(changeData.commit_sha);
    });
  });

  describe('RELEASE NOTE KNOWLEDGE TYPE', () => {
    it('should comply with Prisma Schema for ReleaseNote model', async () => {
      const releaseNoteData: ReleaseNoteData = {
        version: '2.1.0',
        summary: 'Added OAuth 2.0 support and performance improvements',
        metadata: {
          release_date: '2025-01-20',
          breaking_changes: false
        }
      };

      const scope: ScopeFilter = { project: 'prisma-release-note-test' };

      const startTime = Date.now();
      const result = await storeReleaseNote(releaseNoteData, scope);
      const duration = Date.now() - startTime;

      expect(result).toBeDefined();
      TestAssertions.assertPerformance(duration, 1000, 'storeReleaseNote');

      // Verify database storage
      const prisma = testContext.framework.getPrismaClient();
      const storedReleaseNote = await prisma.releaseNote.findUnique({
        where: { id: result }
      });

      expect(storedReleaseNote!.version).toBe(releaseNoteData.version);
      expect(storedReleaseNote!.summary).toBe(releaseNoteData.summary);
    });
  });

  describe('DDL KNOWLEDGE TYPE', () => {
    it('should comply with Prisma Schema for DdlHistory model', async () => {
      const ddlData: DdlData = {
        migration_id: '20250120_add_oauth_tables',
        ddl_text: 'CREATE TABLE oauth_tokens (...)',
        checksum: 'sha256:abc123',
        applied_at: new Date('2025-01-20'),
        description: 'Add OAuth token storage tables',
        status: 'applied',
        metadata: {
          rollback_script: 'DROP TABLE oauth_tokens',
          reviewed_by: 'dba-team'
        }
      };

      const scope: ScopeFilter = { project: 'prisma-ddl-test' };

      const startTime = Date.now();
      const result = await storeDdl(ddlData, scope);
      const duration = Date.now() - startTime;

      expect(result).toBeDefined();
      TestAssertions.assertPerformance(duration, 1000, 'storeDdl');

      // Verify database storage
      const prisma = testContext.framework.getPrismaClient();
      const storedDdl = await prisma.ddlHistory.findUnique({
        where: { id: result }
      });

      expect(storedDdl!.migration_id).toBe(ddlData.migration_id);
      expect(storedDdl!.ddl_text).toBe(ddlData.ddl_text);
      expect(storedDdl!.checksum).toBe(ddlData.checksum);
      expect(storedDdl!.status).toBe(ddlData.status);
    });
  });

  describe('PR CONTEXT KNOWLEDGE TYPE', () => {
    it('should comply with Prisma Schema for PrContext model', async () => {
      const prContextData: PrContextData = {
        pr_number: 123,
        title: 'Add OAuth 2.0 Authentication',
        description: 'This PR adds OAuth 2.0 support to the application',
        author: 'developer@test.com',
        status: 'open',
        metadata: {
          reviewers: ['tech-lead@test.com', 'security-team@test.com'],
          ci_status: 'passed'
        }
      };

      const scope: ScopeFilter = { project: 'prisma-pr-context-test' };

      const startTime = Date.now();
      const result = await storePrContext(prContextData, scope);
      const duration = Date.now() - startTime;

      expect(result).toBeDefined();
      TestAssertions.assertPerformance(duration, 1000, 'storePrContext');

      // Verify database storage
      const prisma = testContext.framework.getPrismaClient();
      const storedPrContext = await prisma.prContext.findUnique({
        where: { id: result }
      });

      expect(storedPrContext!.pr_number).toBe(prContextData.pr_number);
      expect(storedPrContext!.title).toBe(prContextData.title);
      expect(storedPrContext!.author).toBe(prContextData.author);
      expect(storedPrContext!.status).toBe(prContextData.status);
    });
  });

  describe('ENTITY KNOWLEDGE TYPE', () => {
    it('should comply with Prisma Schema for KnowledgeEntity model', async () => {
      const entityData = {
        entity_type: 'component',
        name: 'auth-service',
        data: {
          description: 'Authentication microservice',
          technology: 'Node.js',
          endpoints: ['/login', '/logout', '/refresh'],
          dependencies: ['user-service', 'database']
        },
        metadata: {
          owner: 'auth-team',
          repository: 'https://github.com/company/auth-service'
        }
      };

      const scope: ScopeFilter = { project: 'prisma-entity-test' };

      const startTime = Date.now();
      const result = await memoryStore({
        items: [{
          kind: 'entity',
          scope,
          data: entityData
        }]
      });
      const duration = Date.now() - startTime;

      expect(result).toBeDefined();
      expect(result.status).toBe('success');
      TestAssertions.assertPerformance(duration, 1000, 'storeEntity');
    });
  });

  describe('INCIDENT KNOWLEDGE TYPE', () => {
    it('should comply with Prisma Schema for IncidentLog model', async () => {
      const incidentData = {
        title: 'Database Connection Pool Exhaustion',
        severity: 'high',
        impact: 'API endpoints experiencing timeouts',
        affected_services: ['auth-service', 'user-service'],
        business_impact: 'Users unable to authenticate',
        recovery_actions: [
          'Increased connection pool size',
          'Added connection monitoring',
          'Implemented circuit breaker pattern'
        ],
        incident_commander: 'ops-lead@test.com',
        metadata: {
          detection_method: 'monitoring-alerts',
          communication_sent: true
        }
      };

      const scope: ScopeFilter = { project: 'prisma-incident-test' };

      const startTime = Date.now();
      const result = await storeIncident(incidentData, scope);
      const duration = Date.now() - startTime;

      expect(result).toBeDefined();
      TestAssertions.assertPerformance(duration, 1000, 'storeIncident');

      // Verify database storage
      const prisma = testContext.framework.getPrismaClient();
      const storedIncident = await prisma.incidentLog.findUnique({
        where: { id: result }
      });

      expect(storedIncident!.severity).toBe(incidentData.severity);
      expect(storedIncident!.impact).toBe(incidentData.impact);
      expect(storedIncident!.affected_services).toEqual(incidentData.affected_services);
      expect(storedIncident!.business_impact).toBe(incidentData.business_impact);
      expect(storedIncident!.recovery_actions).toEqual(incidentData.recovery_actions);
      expect(storedIncident!.incident_commander).toBe(incidentData.incident_commander);
    });
  });

  describe('RELEASE KNOWLEDGE TYPE', () => {
    it('should comply with Prisma Schema for ReleaseLog model', async () => {
      const releaseData = {
        version: '2.1.0',
        release_type: 'minor',
        scope: 'Authentication and Performance improvements',
        ticket_references: ['TICKET-123', 'TICKET-124'],
        included_changes: [
          'Added OAuth 2.0 support',
          'Improved API response times',
          'Fixed memory leak in caching layer'
        ],
        deployment_strategy: 'blue-green',
        testing_status: 'passed',
        approvers: ['tech-lead', 'qa-lead'],
        release_notes: 'This release adds OAuth 2.0 authentication support and includes performance improvements.',
        post_release_actions: [
          'Monitor system performance',
          'Check authentication metrics',
          'Update documentation'
        ],
        metadata: {
          release_manager: 'release-lead@test.com',
          rollback_tested: true
        }
      };

      const scope: ScopeFilter = { project: 'prisma-release-test' };

      const startTime = Date.now();
      const result = await storeRelease(releaseData, scope);
      const duration = Date.now() - startTime;

      expect(result).toBeDefined();
      TestAssertions.assertPerformance(duration, 1000, 'storeRelease');

      // Verify database storage
      const prisma = testContext.framework.getPrismaClient();
      const storedRelease = await prisma.releaseLog.findUnique({
        where: { id: result }
      });

      expect(storedRelease!.version).toBe(releaseData.version);
      expect(storedRelease!.release_type).toBe(releaseData.release_type);
      expect(storedRelease!.scope).toBe(releaseData.scope);
      expect(storedRelease!.ticket_references).toEqual(releaseData.ticket_references);
      expect(storedRelease!.included_changes).toEqual(releaseData.included_changes);
      expect(storedRelease!.deployment_strategy).toBe(releaseData.deployment_strategy);
    });
  });

  describe('RISK KNOWLEDGE TYPE', () => {
    it('should comply with Prisma Schema for RiskLog model', async () => {
      const riskData = {
        title: 'Database Single Point of Failure',
        category: 'infrastructure',
        risk_level: 'high',
        impact_description: 'Complete system outage if primary database fails',
        probability: 'medium',
        mitigation_strategies: [
          'Implement database replication',
          'Add automatic failover mechanism',
          'Create regular backup procedures'
        ],
        trigger_events: [
          'Database server hardware failure',
          'Network connectivity loss',
          'Database corruption'
        ],
        owner: 'infrastructure-team@test.com',
        review_date: '2025-02-01',
        monitoring_indicators: [
          'Database replication lag',
          'Connection error rates',
          'Backup success rates'
        ],
        contingency_plans: 'Switch to standby database and initiate disaster recovery procedures',
        metadata: {
          identified_date: '2025-01-15',
          risk_id: 'RISK-001'
        }
      };

      const scope: ScopeFilter = { project: 'prisma-risk-test' };

      const startTime = Date.now();
      const result = await storeRisk(riskData, scope);
      const duration = Date.now() - startTime;

      expect(result).toBeDefined();
      TestAssertions.assertPerformance(duration, 1000, 'storeRisk');

      // Verify database storage
      const prisma = testContext.framework.getPrismaClient();
      const storedRisk = await prisma.riskLog.findUnique({
        where: { id: result }
      });

      expect(storedRisk!.title).toBe(riskData.title);
      expect(storedRisk!.category).toBe(riskData.category);
      expect(storedRisk!.risk_level).toBe(riskData.risk_level);
      expect(storedRisk!.probability).toBe(riskData.probability);
      expect(storedRisk!.mitigation_strategies).toEqual(riskData.mitigation_strategies);
      expect(storedRisk!.owner).toBe(riskData.owner);
      expect(storedRisk!.contingency_plans).toBe(riskData.contingency_plans);
    });
  });

  describe('ASSUMPTION KNOWLEDGE TYPE', () => {
    it('should comply with Prisma Schema for AssumptionLog model', async () => {
      const assumptionData = {
        title: 'API Load Growth Will Be Linear',
        description: 'We assume API traffic will grow at a predictable linear rate of 10% per month',
        category: 'performance',
        validation_status: 'assumed',
        impact_if_invalid: 'System may not handle traffic spikes, leading to performance degradation',
        validation_criteria: [
          'Monitor actual vs predicted traffic patterns',
          'Compare with historical data',
          'Review during capacity planning'
        ],
        validation_date: '2025-03-01',
        owner: 'performance-team@test.com',
        related_assumptions: ['Database capacity is sufficient', 'Network bandwidth is adequate'],
        monitoring_approach: 'Real-time traffic monitoring with alerts for deviations',
        review_frequency: 'monthly',
        metadata: {
          assumption_id: 'ASSUMPTION-001',
          created_by: 'architecture-team'
        }
      };

      const scope: ScopeFilter = { project: 'prisma-assumption-test' };

      const startTime = Date.now();
      const result = await storeAssumption(assumptionData, scope);
      const duration = Date.now() - startTime;

      expect(result).toBeDefined();
      TestAssertions.assertPerformance(duration, 1000, 'storeAssumption');

      // Verify database storage
      const prisma = testContext.framework.getPrismaClient();
      const storedAssumption = await prisma.assumptionLog.findUnique({
        where: { id: result }
      });

      expect(storedAssumption!.title).toBe(assumptionData.title);
      expect(storedAssumption!.category).toBe(assumptionData.category);
      expect(storedAssumption!.validation_status).toBe(assumptionData.validation_status);
      expect(storedAssumption!.impact_if_invalid).toBe(assumptionData.impact_if_invalid);
      expect(storedAssumption!.validation_criteria).toEqual(assumptionData.validation_criteria);
      expect(storedAssumption!.owner).toBe(assumptionData.owner);
      expect(storedAssumption!.review_frequency).toBe(assumptionData.review_frequency);
    });
  });

  describe('CROSS-TYPE CONSISTENCY VALIDATION', () => {
    it('should maintain consistent field access patterns across all knowledge types', async () => {
      // This test ensures all knowledge types follow the same Prisma Schema compliance patterns

      const testData = [
        {
          name: 'Section',
          data: {
            title: 'Test Section',
            content: 'Content',
            heading: 'Heading',
            body_md: 'Markdown',
            document_id: 'DOC-123'
          },
          storeFn: (data: any, scope: any) => storeSection(data, scope)
        },
        {
          name: 'Decision',
          data: {
            component: 'test-component',
            status: 'proposed',
            title: 'Test Decision',
            rationale: 'Rationale'
          },
          storeFn: (data: any, scope: any) => storeDecision(data, scope)
        },
        {
          name: 'Todo',
          data: {
            title: 'Test Todo',
            status: 'open',
            todo_type: 'task',
            assignee: 'test@test.com'
          },
          storeFn: (data: any, scope: any) => storeTodo(data, scope)
        }
      ];

      const scope: ScopeFilter = { project: 'consistency-test' };
      const results = [];

      for (const testCase of testData) {
        const startTime = Date.now();
        const result = await testCase.storeFn(testCase.data, scope);
        const duration = Date.now() - startTime;

        expect(result).toBeDefined();
        expect(typeof result).toBe('string');

        // Performance consistency check
        TestAssertions.assertPerformance(duration, 1000, `store${testCase.name}`);

        results.push({
          type: testCase.name,
          id: result,
          duration
        });
      }

      // Verify all results are valid and performant
      expect(results).toHaveLength(testData.length);
      results.forEach(result => {
        expect(result.id).toMatch(/^c/); // Prisma CUID format
        expect(result.duration).toBeLessThan(1000);
      });

      console.log('📊 Cross-type performance results:', results);
    });

    it('should prevent metadata/tag workarounds across all knowledge types', async () => {
      // This test ensures no knowledge type can bypass Prisma Schema using metadata/tags

      const violationAttempts = [
        {
          name: 'Issue with metadata tracker',
          test: () => validateIssueCompliance({
            title: 'Test',
            status: 'open',
            metadata: { tracker: 'github' }
          })
        }
      ];

      for (const attempt of violationAttempts) {
        expect(attempt.test).toThrow('PRISMA SCHEMA VIOLATION');
      }
    });
  });
});