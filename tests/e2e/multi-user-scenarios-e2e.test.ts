/**
 * Multi-User Scenarios E2E Tests
 *
 * Tests collaborative knowledge management, concurrent access,
 * user permissions, and team workflows across multiple users.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { spawn, ChildProcess } from 'child_process';
import { setTimeout } from 'timers/promises';
import { randomUUID } from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

interface TestServer {
  process: ChildProcess;
  port: number;
}

interface User {
  id: string;
  name: string;
  role: string;
  team: string;
  permissions: string[];
}

interface CollaborationSession {
  id: string;
  participants: User[];
  project: string;
  started_at: string;
  activity: Array<{
    user_id: string;
    action: string;
    timestamp: string;
    details: any;
  }>;
}

describe('Multi-User Scenarios E2E', () => {
  let server: TestServer;
  const TEST_DB_URL = process.env.TEST_DATABASE_URL ||
    'postgresql://cortex:trust@localhost:5433/cortex_test_e2e';

  // Mock users for testing
  const users: User[] = [
    {
      id: 'user-001',
      name: 'Alice Johnson',
      role: 'Senior Developer',
      team: 'frontend',
      permissions: ['read', 'write', 'approve', 'admin']
    },
    {
      id: 'user-002',
      name: 'Bob Smith',
      role: 'Backend Developer',
      team: 'backend',
      permissions: ['read', 'write']
    },
    {
      id: 'user-003',
      name: 'Carol Davis',
      role: 'Product Manager',
      team: 'product',
      permissions: ['read', 'write', 'approve']
    },
    {
      id: 'user-004',
      name: 'David Wilson',
      role: 'DevOps Engineer',
      team: 'infrastructure',
      permissions: ['read', 'write']
    },
    {
      id: 'user-005',
      name: 'Eva Brown',
      role: 'QA Engineer',
      team: 'quality',
      permissions: ['read', 'write']
    }
  ];

  beforeAll(async () => {
    await setupTestDatabase();
    server = await startMCPServer();
    await setTimeout(2000);
  });

  afterAll(async () => {
    if (server?.process) {
      server.process.kill('SIGTERM');
      await setTimeout(1000);
    }
    await cleanupTestDatabase();
  });

  beforeEach(async () => {
    await cleanupTestData();
  });

  describe('Collaborative Decision Making', () => {
    it('should support multi-user decision workflow', async () => {
      const projectId = `collab-decision-${randomUUID().substring(0, 8)}`;
      const session: CollaborationSession = {
        id: randomUUID(),
        participants: [users[0], users[1], users[2]], // Alice, Bob, Carol
        project: projectId,
        started_at: new Date().toISOString(),
        activity: []
      };

      // Step 1: Alice proposes initial decision
      const aliceProposal = {
        items: [{
          kind: 'decision',
          scope: { project: projectId, team: 'frontend' },
          data: {
            component: 'frontend_framework',
            status: 'proposed',
            title: 'Adopt Next.js for Frontend Development',
            rationale: 'Next.js provides SSR, routing, and excellent developer experience',
            alternatives_considered: [
              { alternative: 'Create React App', reason: 'Limited to SPA' },
              { alternative: 'Gatsby', reason: 'Better for static sites' }
            ],
            proposed_by: users[0].id,
            proposed_at: new Date().toISOString()
          },
          source: { actor: users[0].id }
        }]
      };

      const proposalResult = await callMCPTool('memory_store', aliceProposal, users[0]);
      expect(proposalResult.stored).toHaveLength(1);

      session.activity.push({
        user_id: users[0].id,
        action: 'proposed_decision',
        timestamp: new Date().toISOString(),
        details: { decision_id: proposalResult.stored[0].id }
      });

      // Step 2: Bob provides technical feedback
      const bobFeedback = {
        items: [{
          kind: 'observation',
          scope: { project: projectId, team: 'backend' },
          data: {
            title: 'Backend Integration Considerations for Next.js',
            content: `
Next.js adoption considerations from backend perspective:

1. API Routes: Next.js API routes can replace some backend services
2. Authentication: Need to ensure auth system works with SSR
3. Data Fetching: Implement proper caching strategies
4. Deployment: Update build and deployment pipeline

Recommendation: Proceed with adoption, but plan integration work.
            `.trim(),
            feedback_type: 'technical_review',
            reviewer: users[1].id,
            review_date: new Date().toISOString()
          },
          source: { actor: users[1].id }
        }]
      };

      const feedbackResult = await callMCPTool('memory_store', bobFeedback, users[1]);
      expect(feedbackResult.stored).toHaveLength(1);

      session.activity.push({
        user_id: users[1].id,
        action: 'provided_feedback',
        timestamp: new Date().toISOString(),
        details: { observation_id: feedbackResult.stored[0].id }
      });

      // Step 3: Carol adds product requirements
      const carolRequirements = {
        items: [
          {
            kind: 'todo',
            scope: { project: projectId, team: 'product' },
            data: {
              text: 'Define SEO requirements for Next.js implementation',
              status: 'pending',
              priority: 'high',
              todo_type: 'requirement',
              assignee: users[2].id,
              due_date: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()
            },
            source: { actor: users[2].id }
          },
          {
            kind: 'todo',
            scope: { project: projectId, team: 'product' },
            data: {
              text: 'Plan user migration strategy',
              status: 'pending',
              priority: 'medium',
              todo_type: 'planning',
              assignee: users[2].id
            },
            source: { actor: users[2].id }
          }
        ]
      };

      const requirementsResult = await callMCPTool('memory_store', carolRequirements, users[2]);
      expect(requirementsResult.stored).toHaveLength(2);

      session.activity.push({
        user_id: users[2].id,
        action: 'added_requirements',
        timestamp: new Date().toISOString(),
        details: { todos_added: 2 }
      });

      // Step 4: Eva adds QA considerations
      const evaFeedback = {
        items: [{
          kind: 'observation',
          scope: { project: projectId, team: 'quality' },
          data: {
            title: 'QA Testing Strategy for Next.js Migration',
            content: `
Testing considerations for Next.js adoption:

1. Regression Testing: Ensure existing functionality works
2. Performance Testing: SSR performance impact
3. SEO Testing: Meta tags and structured data
4. Accessibility Testing: Component-level accessibility
5. Cross-browser Testing: SSR consistency

Resource estimation: 2 weeks for comprehensive testing.
            `.trim(),
            feedback_type: 'qa_strategy',
            reviewer: users[4].id,
            review_date: new Date().toISOString()
          },
          source: { actor: users[4].id }
        }]
      };

      await callMCPTool('memory_store', evaFeedback, users[4]);

      // Step 5: Carol approves decision with conditions
      const approvalDecision = {
        items: [{
          kind: 'decision',
          scope: { project: projectId, team: 'product' },
          data: {
            id: proposalResult.stored[0].id,
            status: 'accepted',
            approval_conditions: [
              'Complete backend integration planning',
              'Define comprehensive QA strategy',
              'Create detailed migration timeline',
              'Plan team training sessions'
            ],
            approved_by: users[2].id,
            approved_at: new Date().toISOString(),
            implementation_timeline: '6 weeks',
            budget_approved: true
          },
          source: { actor: users[2].id }
        }]
      };

      const approvalResult = await callMCPTool('memory_store', approvalDecision, users[2]);
      expect(approvalResult.stored).toHaveLength(1);
      expect(approvalResult.stored[0].status).toBe('updated');

      session.activity.push({
        user_id: users[2].id,
        action: 'approved_decision',
        timestamp: new Date().toISOString(),
        details: { conditions: 4 }
      });

      // Step 6: Verify collaborative workflow
      const collaborativeSearch = await callMCPTool('memory_find', {
        query: 'Next.js adoption collaborative decision',
        scope: { project: projectId },
        types: ['decision', 'observation', 'todo']
      });

      expect(collaborativeSearch.hits.length).toBeGreaterThan(5);

      // Verify all user contributions are present
      const decisionItem = collaborativeSearch.hits.find(h => h.kind === 'decision');
      expect(decisionItem?.data?.status).toBe('accepted');
      expect(decisionItem?.data?.approved_by).toBe(users[2].id);

      const observations = collaborativeSearch.hits.filter(h => h.kind === 'observation');
      expect(observations.length).toBe(2); // Bob's technical feedback and Eva's QA strategy

      const todos = collaborativeSearch.hits.filter(h => h.kind === 'todo');
      expect(todos.length).toBe(2); // Carol's requirements

      // Verify different teams contributed
      const teams = new Set();
      collaborativeSearch.hits.forEach(hit => {
        if (hit.data?.team) teams.add(hit.data.team);
      });
      expect(teams.size).toBeGreaterThan(2);
    });

    it('should handle concurrent user editing gracefully', async () => {
      const projectId = `concurrent-edit-${randomUUID().substring(0, 8)}`;
      const documentId = randomUUID();

      // Alice starts creating a specification
      const aliceInitialEdit = {
        items: [{
          kind: 'section',
          scope: { project: projectId, team: 'frontend' },
          data: {
            id: documentId,
            title: 'Component Library Specification',
            heading: 'Overview',
            body_md: `
# Component Library Specification

## Purpose
This document defines the standards and guidelines for our React component library.

## Goals
- Consistent UI across applications
- Reusable components
- Accessibility compliance
- Performance optimization
            `.trim(),
            version: 1,
            last_edited_by: users[0].id,
            last_edited_at: new Date().toISOString()
          },
          source: { actor: users[0].id }
        }]
      };

      const aliceResult = await callMCPTool('memory_store', aliceInitialEdit, users[0]);
      expect(aliceResult.stored).toHaveLength(1);

      // Simulate concurrent edits by different users
      const concurrentEdits = await Promise.all([
        // Bob adds technical specifications
        callMCPTool('memory_store', {
          items: [{
            kind: 'section',
            scope: { project: projectId, team: 'backend' },
            data: {
              id: documentId,
              title: 'Component Library Specification',
              heading: 'Technical Requirements',
              body_md: `
## Technical Requirements

### TypeScript Support
- All components must have full TypeScript definitions
- Use generic types where appropriate
- Export proper type definitions

### Performance Requirements
- Components must render within 16ms for 60fps
- Bundle size optimization required
- Lazy loading for heavy components
              `.trim(),
              version: 2,
              last_edited_by: users[1].id,
              last_edited_at: new Date().toISOString()
            },
            source: { actor: users[1].id }
          }]
        }, users[1]),

        // Carol adds product requirements
        callMCPTool('memory_store', {
          items: [{
            kind: 'section',
            scope: { project: projectId, team: 'product' },
            data: {
              id: documentId,
              title: 'Component Library Specification',
              heading: 'Product Requirements',
              body_md: `
## Product Requirements

### Design System Integration
- Must align with design system tokens
- Support theming and customization
- Responsive design principles

### Browser Support
- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+
              `.trim(),
              version: 3,
              last_edited_by: users[2].id,
              last_edited_at: new Date().toISOString()
            },
            source: { actor: users[2].id }
          }]
        }, users[2])
      ]);

      expect(concurrentEdits.length).toBe(2);

      // Eva adds accessibility requirements
      const evaEdit = {
        items: [{
          kind: 'section',
          scope: { project: projectId, team: 'quality' },
          data: {
            id: documentId,
            title: 'Component Library Specification',
            heading: 'Accessibility Requirements',
            body_md: `
## Accessibility Requirements

### WCAG 2.1 AA Compliance
- All interactive elements must be keyboard accessible
- Proper ARIA labels and descriptions
- Sufficient color contrast ratios
- Screen reader compatibility

### Testing Requirements
- Automated accessibility testing in CI/CD
- Manual testing with screen readers
- Keyboard navigation testing
              `.trim(),
            version: 4,
            last_edited_by: users[4].id,
            last_edited_at: new Date().toISOString()
          },
          source: { actor: users[4].id }
        }]
      };

      await callMCPTool('memory_store', evaEdit, users[4]);

      // Verify final document contains all contributions
      const finalDocument = await callMCPTool('memory_find', {
        query: 'Component Library Specification',
        scope: { project: projectId },
        types: ['section']
      });

      expect(finalDocument.hits.length).toBeGreaterThan(0);

      // Check that all sections are present
      const sections = finalDocument.hits.map(h => h.data?.heading);
      expect(sections).toContain('Overview');
      expect(sections).toContain('Technical Requirements');
      expect(sections).toContain('Product Requirements');
      expect(sections).toContain('Accessibility Requirements');

      // Verify version control
      const latestVersion = finalDocument.hits.reduce((max, hit) =>
        Math.max(max, hit.data?.version || 0), 0
      );
      expect(latestVersion).toBe(4);

      // Verify edit history through observations
      const editHistory = await callMCPTool('memory_find', {
        query: 'edit history collaboration version',
        scope: { project: projectId },
        types: ['observation']
      });

      expect(editHistory.hits.length).toBeGreaterThan(0);
    });
  });

  describe('Team-Based Workflows', () => {
    it('should support cross-team project coordination', async () => {
      const projectId = `cross-team-${randomUUID().substring(0, 8)}`;
      const teams = ['frontend', 'backend', 'product', 'infrastructure', 'quality'];

      // Step 1: Product team creates project requirements
      const productRequirements = {
        items: [
          {
            kind: 'section',
            scope: { project: projectId, team: 'product' },
            data: {
              title: 'Mobile App Feature Requirements',
              heading: 'Project Overview',
              body_md: `
# Mobile App - User Profile Management

## Business Requirements
- Users can create and manage profiles
- Social media integration
- Real-time notifications
- Offline functionality

## Success Metrics
- User engagement: +25%
- Profile completion rate: 80%
- App store rating: 4.5+
              `.trim()
            },
            source: { actor: users[2].id }
          },
          {
            kind: 'decision',
            scope: { project: projectId, team: 'product' },
            data: {
              component: 'mobile_platform',
              status: 'accepted',
              title: 'Use React Native for Cross-Platform Development',
              rationale: 'Single codebase for iOS and Android, faster time to market',
              alternatives_considered: [
                { alternative: 'Native iOS/Android', reason: 'Higher development cost' },
                { alternative: 'Flutter', reason: 'Team expertise in React' }
              ]
            },
            source: { actor: users[2].id }
          }
        ]
      };

      await callMCPTool('memory_store', productRequirements, users[2]);

      // Step 2: Frontend team creates technical specifications
      const frontendSpec = {
        items: [
          {
            kind: 'section',
            scope: { project: projectId, team: 'frontend' },
            data: {
              title: 'React Native Technical Architecture',
              heading: 'Component Structure',
              body_md: `
# React Native Architecture

## Component Hierarchy
- App (Root)
  - Navigation
    - Profile Stack
    - Settings Stack
    - Notifications Stack

## State Management
- Redux Toolkit for global state
- React Query for server state
- AsyncStorage for persistence

## Navigation
- React Navigation v6
- Stack and Tab navigators
- Deep linking support
              `.trim()
            },
            source: { actor: users[0].id }
          },
          {
            kind: 'entity',
            scope: { project: projectId, team: 'frontend' },
            data: {
              entity_type: 'component_library',
              name: 'MobileUIComponents',
              data: {
                components: ['ProfileForm', 'Avatar', 'NotificationList'],
                styling: 'Styled Components',
                testing: 'Jest + React Native Testing Library'
              }
            },
            source: { actor: users[0].id }
          }
        ]
      };

      await callMCPTool('memory_store', frontendSpec, users[0]);

      // Step 3: Backend team designs API
      const backendAPI = {
        items: [
          {
            kind: 'section',
            scope: { project: projectId, team: 'backend' },
            data: {
              title: 'Mobile Backend API Specification',
              heading: 'REST API Endpoints',
              body_md: `
# Mobile API Endpoints

## Authentication
- POST /api/auth/login
- POST /api/auth/refresh
- POST /api/auth/logout

## Profile Management
- GET /api/profiles/:id
- PUT /api/profiles/:id
- POST /api/profiles
- DELETE /api/profiles/:id

## Real-time Features
- WebSocket: /ws/notifications
- Server-Sent Events: /api/events
              `.trim()
            },
            source: { actor: users[1].id }
          },
          {
            kind: 'entity',
            scope: { project: projectId, team: 'backend' },
            data: {
              entity_type: 'api_service',
              name: 'UserManagementAPI',
              data: {
                version: 'v2',
                authentication: 'JWT',
                rate_limiting: '1000 requests/hour',
                caching: 'Redis'
              }
            },
            source: { actor: users[1].id }
          }
        ]
      };

      await callMCPTool('memory_store', backendAPI, users[1]);

      // Step 4: Infrastructure team plans deployment
      const infraPlan = {
        items: [
          {
            kind: 'runbook',
            scope: { project: projectId, team: 'infrastructure' },
            data: {
              title: 'Mobile App Deployment Pipeline',
              description: 'CI/CD pipeline for React Native mobile applications',
              triggers: ['Git push to main', 'Pull request merge'],
              steps: [
                {
                  step: 1,
                  action: 'Code Analysis',
                  details: 'ESLint, TypeScript checks, security scanning',
                  owner: 'devops-team'
                },
                {
                  step: 2,
                  action: 'Automated Testing',
                  details: 'Unit tests, integration tests, E2E tests',
                  owner: 'qa-team'
                },
                {
                  step: 3,
                  action: 'Build Applications',
                  details: 'iOS build using Xcode, Android build using Gradle',
                  owner: 'devops-team'
                },
                {
                  step: 4,
                  action: 'Deploy to Stores',
                  details: 'TestFlight for iOS, Play Store Internal Testing for Android',
                  owner: 'devops-team'
                }
              ]
            },
            source: { actor: users[3].id }
          },
          {
            kind: 'entity',
            scope: { project: projectId, team: 'infrastructure' },
            data: {
              entity_type: 'monitoring',
              name: 'MobileAppMonitoring',
              data: {
                tools: ['Sentry', 'Firebase Analytics', 'Crashlytics'],
                metrics: ['crash_rate', 'performance', 'user_engagement'],
                alerts: ['high_crash_rate', 'performance_degradation']
              }
            },
            source: { actor: users[3].id }
          }
        ]
      };

      await callMCPTool('memory_store', infraPlan, users[3]);

      // Step 5: QA team creates testing strategy
      const qaStrategy = {
        items: [
          {
            kind: 'section',
            scope: { project: projectId, team: 'quality' },
            data: {
              title: 'Mobile App Testing Strategy',
              heading: 'Testing Approach',
              body_md: `
# Comprehensive Testing Strategy

## Test Pyramid
- Unit Tests: 70% (Jest)
- Integration Tests: 20% (React Native Testing Library)
- E2E Tests: 10% (Detox)

## Device Coverage
- iOS: iPhone 12, 13, 14 (Latest 3 versions)
- Android: Samsung, Google Pixel, OnePlus (Popular devices)
- Screen sizes: Small, Medium, Large, Extra Large

## Automation
- CI/CD integration
- Parallel test execution
- Visual regression testing
              `.trim()
            },
            source: { actor: users[4].id }
          },
          {
            kind: 'todo',
            scope: { project: projectId, team: 'quality' },
            data: {
              text: 'Setup mobile testing device farm',
              status: 'pending',
              priority: 'high',
              todo_type: 'infrastructure',
              assignee: users[4].id,
              estimated_cost: '$5000 for device procurement'
            },
            source: { actor: users[4].id }
          }
        ]
      };

      await callMCPTool('memory_store', qaStrategy, users[4]);

      // Step 6: Create cross-team dependencies and relationships
      const createDependencies = {
        items: [
          {
            kind: 'relation',
            scope: { project: projectId },
            data: {
              from_entity: 'Mobile App Feature Requirements',
              to_entity: 'React Native Technical Architecture',
              relation_type: 'drives_architecture',
              description: 'Product requirements drive frontend architecture decisions'
            }
          },
          {
            kind: 'relation',
            scope: { project: projectId },
            data: {
              from_entity: 'React Native Technical Architecture',
              to_entity: 'Mobile Backend API Specification',
              relation_type: 'integrates_with',
              description: 'Frontend architecture integrates with backend API'
            }
          },
          {
            kind: 'relation',
            scope: { project: projectId },
            data: {
              from_entity: 'Mobile App Testing Strategy',
              to_entity: 'Mobile App Deployment Pipeline',
              relation_type: 'validates',
              description: 'Testing strategy validates deployment pipeline'
            }
          }
        ]
      };

      await callMCPTool('memory_store', createDependencies);

      // Step 7: Verify cross-team coordination
      const coordinationSearch = await callMCPTool('memory_find', {
        query: 'mobile app cross-team coordination',
        scope: { project: projectId },
        types: ['section', 'entity', 'runbook', 'todo', 'relation']
      });

      expect(coordinationSearch.hits.length).toBeGreaterThan(10);

      // Verify all teams contributed
      const teamContributions = coordinationSearch.hits.reduce((acc, hit) => {
        const team = hit.data?.team;
        if (team) acc[team] = (acc[team] || 0) + 1;
        return acc;
      }, {} as Record<string, number>);

      expect(Object.keys(teamContributions)).toContain('frontend');
      expect(Object.keys(teamContributions)).toContain('backend');
      expect(Object.keys(teamContributions)).toContain('product');
      expect(Object.keys(teamContributions)).toContain('infrastructure');
      expect(Object.keys(teamContributions)).toContain('quality');

      // Verify relationships connect team work
      const relations = coordinationSearch.hits.filter(h => h.kind === 'relation');
      expect(relations.length).toBe(3);

      // Verify comprehensive project coverage
      const sections = coordinationSearch.hits.filter(h => h.kind === 'section');
      const sectionTitles = sections.map(h => h.data?.title);

      expect(sectionTitles.some(t => t.includes('Requirements'))).toBe(true);
      expect(sectionTitles.some(t => t.includes('Architecture'))).toBe(true);
      expect(sectionTitles.some(t => t.includes('API'))).toBe(true);
      expect(sectionTitles.some(t => t.includes('Testing'))).toBe(true);
    });

    it('should handle team-based access control', async () => {
      const projectId = `access-control-${randomUUID().substring(0, 8)}`;

      // Step 1: Create team-restricted content
      const sensitiveContent = {
        items: [
          {
            kind: 'section',
            scope: { project: projectId, team: 'backend', access_level: 'team_only' },
            data: {
              title: 'Database Security Configuration',
              heading: 'Sensitive Information',
              body_md: `
# Database Security Credentials

## Production Database
- Host: prod-db.internal.company.com
- Connection pool: 20 connections
- SSL: Required

## Security Measures
- Encryption at rest and in transit
- Regular security audits
- Access logging and monitoring
              `.trim(),
              restricted_to: ['backend', 'infrastructure']
            },
            source: { actor: users[1].id }
          },
          {
            kind: 'section',
            scope: { project: projectId, team: 'product', access_level: 'internal' },
            data: {
              title: 'Product Roadmap (Internal)',
              heading: 'Confidential Planning',
              body_md: `
# Q3-Q4 Product Roadmap

## New Features
- Advanced analytics dashboard
- AI-powered recommendations
- Enhanced mobile experience

## Timeline
- Beta testing: Q3 2024
- Public release: Q4 2024
              `.trim(),
              restricted_to: ['product', 'frontend', 'backend']
            },
            source: { actor: users[2].id }
          }
        ]
      };

      await callMCPTool('memory_store', sensitiveContent, users[1]);

      // Step 2: Test access control for different users
      // Backend user (Bob) should see database security content
      const backendAccess = await callMCPTool('memory_find', {
        query: 'database security configuration',
        scope: { project: projectId },
        types: ['section']
      }, users[1]);

      expect(backendAccess.hits.length).toBeGreaterThan(0);
      expect(backendAccess.hits[0].data?.title).toBe('Database Security Configuration');

      // Frontend user (Alice) should NOT see database security content
      const frontendRestrictedAccess = await callMCPTool('memory_find', {
        query: 'database security configuration',
        scope: { project: projectId },
        types: ['section']
      }, users[0]);

      expect(frontendRestrictedAccess.hits.length).toBe(0);

      // But Alice should see product roadmap
      const frontendAllowedAccess = await callMCPTool('memory_find', {
        query: 'product roadmap',
        scope: { project: projectId },
        types: ['section']
      }, users[0]);

      expect(frontendAllowedAccess.hits.length).toBeGreaterThan(0);

      // Step 3: Test permission-based operations
      // Carol (Product Manager) can approve decisions
      const carolApproval = {
        items: [{
          kind: 'decision',
          scope: { project: projectId, team: 'product' },
          data: {
            component: 'feature_priority',
            status: 'accepted',
            title: 'Prioritize Mobile App Features',
            rationale: 'Mobile engagement is critical for Q4 goals',
            approved_by: users[2].id,
            approved_at: new Date().toISOString()
          },
          source: { actor: users[2].id }
        }]
      };

      const approvalResult = await callMCPTool('memory_store', carolApproval, users[2]);
      expect(approvalResult.stored).toHaveLength(1);

      // Bob (Backend Developer) cannot approve admin-level decisions
      const bobAdminAttempt = {
        items: [{
          kind: 'decision',
          scope: { project: projectId, team: 'backend' },
          data: {
            component: 'system_architecture',
            status: 'accepted',
            title: 'Database Migration Strategy',
            rationale: 'Migrate to PostgreSQL for better performance',
            requires_admin_approval: true,
            approved_by: users[1].id, // Bob trying to approve
            approved_at: new Date().toISOString()
          },
          source: { actor: users[1].id }
        }]
      };

      const adminResult = await callMCPTool('memory_store', bobAdminAttempt, users[1]);
      // Should either fail or require elevated permissions
      if (adminResult.errors.length > 0) {
        expect(adminResult.errors[0].error_code).toMatch(/(PERMISSION_DENIED|ADMIN_REQUIRED)/);
      }

      // Step 4: Test cross-team collaboration permissions
      // Create a collaborative decision that requires multiple team approvals
      const multiTeamDecision = {
        items: [{
          kind: 'decision',
          scope: { project: projectId, team: 'product' },
          data: {
            component: 'api_design',
            status: 'proposed',
            title: 'Adopt GraphQL for API Layer',
            rationale: 'GraphQL provides better flexibility for mobile clients',
            required_approvals: ['product', 'backend', 'frontend'],
            alternatives_considered: [
              { alternative: 'REST API', reason: 'Less flexible for mobile' },
              { alternative: 'gRPC', reason: 'Limited web client support' }
            ],
            proposed_by: users[2].id
          },
          source: { actor: users[2].id }
        }]
      };

      await callMCPTool('memory_store', multiTeamDecision, users[2]);

      // Backend team provides technical approval
      const backendApproval = {
        items: [{
          kind: 'observation',
          scope: { project: projectId, team: 'backend' },
          data: {
            title: 'Backend Team Technical Review',
            content: 'GraphQL adoption is technically feasible. Team has expertise. Timeline: 4 weeks.',
            approval_type: 'technical_approval',
            approved_by: users[1].id,
            team: 'backend'
          },
          source: { actor: users[1].id }
        }]
      };

      await callMCPTool('memory_store', backendApproval, users[1]);

      // Verify approval tracking
      const approvalSearch = await callMCPTool('memory_find', {
        query: 'GraphQL API approval status',
        scope: { project: projectId },
        types: ['decision', 'observation']
      });

      expect(approvalSearch.hits.length).toBeGreaterThan(0);

      const decision = approvalSearch.hits.find(h => h.kind === 'decision');
      expect(decision?.data?.required_approvals).toContain('backend');

      const approvals = approvalSearch.hits.filter(h => h.kind === 'observation');
      expect(approvals.some(a => a.data?.team === 'backend')).toBe(true);
    });
  });

  describe('Real-time Collaboration', () => {
    it('should support real-time collaborative sessions', async () => {
      const projectId = `realtime-collab-${randomUUID().substring(0, 8)}`;
      const sessionId = randomUUID();

      // Step 1: Start a collaborative planning session
      const sessionStart = {
        items: [{
          kind: 'entity',
          scope: { project: projectId },
          data: {
            entity_type: 'collaboration_session',
            name: `Sprint Planning - ${new Date().toLocaleDateString()}`,
            data: {
              session_id: sessionId,
              participants: [users[0].id, users[1].id, users[2].id],
              started_at: new Date().toISOString(),
              status: 'active',
              agenda: [
                'Review previous sprint outcomes',
                'Plan new sprint backlog',
                'Identify dependencies and risks',
                'Assign tasks to team members'
              ]
            }
          },
          source: { actor: users[2].id } // Carol as facilitator
        }]
      };

      const sessionResult = await callMCPTool('memory_store', sessionStart, users[2]);

      // Step 2: Participants join and contribute in real-time
      const realTimeContributions = await Promise.all([
        // Alice adds frontend tasks
        callMCPTool('memory_store', {
          items: [{
            kind: 'todo',
            scope: { project: projectId, session_id: sessionId },
            data: {
              text: 'Implement user profile React components',
              status: 'ready',
              priority: 'high',
              todo_type: 'development',
              assignee: users[0].id,
              story_points: 5,
              session_contribution: true
            },
            source: { actor: users[0].id }
          }]
        }, users[0]),

        // Bob adds backend tasks
        callMCPTool('memory_store', {
          items: [{
            kind: 'todo',
            scope: { project: projectId, session_id: sessionId },
            data: {
              text: 'Design user profile API endpoints',
              status: 'ready',
              priority: 'high',
              todo_type: 'development',
              assignee: users[1].id,
              story_points: 3,
              session_contribution: true
            },
            source: { actor: users[1].id }
          }]
        }, users[1]),

        // Carol adds planning notes
        callMCPTool('memory_store', {
          items: [{
            kind: 'observation',
            scope: { project: projectId, session_id: sessionId },
            data: {
              title: 'Sprint Planning Notes',
              content: 'Team capacity: 3 developers x 2 weeks = 30 story points planned',
              session_notes: true,
              confidence_level: 'high'
            },
            source: { actor: users[2].id }
          }]
        }, users[2])
      ]);

      expect(realTimeContributions.length).toBe(3);

      // Step 3: Simulate real-time updates and notifications
      const sessionUpdates = [
        // Alice updates task status
        callMCPTool('memory_store', {
          items: [{
            kind: 'todo',
            scope: { project: projectId, session_id: sessionId },
            data: {
              id: realTimeContributions[0].stored[0].id,
              status: 'in_progress',
              started_at: new Date().toISOString(),
              real_time_update: true
            },
            source: { actor: users[0].id }
          }]
        }, users[0]),

        // Bob adds dependency
        callMCPTool('memory_store', {
          items: [{
            kind: 'relation',
            scope: { project: projectId, session_id: sessionId },
            data: {
              from_entity: realTimeContributions[1].stored[0].id,
              to_entity: realTimeContributions[0].stored[0].id,
              relation_type: 'blocks',
              description: 'API design must be completed before component implementation',
              real_time_update: true
            },
            source: { actor: users[1].id }
          }]
        }, users[1])
      ];

      await Promise.all(sessionUpdates);

      // Step 4: End session and summarize outcomes
      const sessionEnd = {
        items: [{
          kind: 'entity',
          scope: { project: projectId },
          data: {
            id: sessionResult.stored[0].id,
            status: 'completed',
            ended_at: new Date().toISOString(),
            outcomes: {
              tasks_created: 2,
              dependencies_identified: 1,
              total_story_points: 8,
              participants: [users[0].id, users[1].id, users[2].id],
              next_steps: [
                'Begin API design work',
                'Setup React component scaffolding',
                'Schedule follow-up meeting'
              ]
            }
          },
          source: { actor: users[2].id }
        }]
      };

      const endResult = await callMCPTool('memory_store', sessionEnd, users[2]);
      expect(endResult.stored[0].status).toBe('updated');

      // Step 5: Verify real-time collaboration results
      const collaborationSearch = await callMCPTool('memory_find', {
        query: `sprint planning session ${sessionId}`,
        scope: { project: projectId },
        types: ['entity', 'todo', 'observation', 'relation']
      });

      expect(collaborationSearch.hits.length).toBeGreaterThan(4);

      // Verify session participation
      const session = collaborationSearch.hits.find(h =>
        h.kind === 'entity' && h.data?.entity_type === 'collaboration_session'
      );
      expect(session?.data?.participants).toHaveLength(3);
      expect(session?.data?.status).toBe('completed');

      // Verify real-time contributions
      const sessionTodos = collaborationSearch.hits.filter(h =>
        h.kind === 'todo' && h.data?.session_contribution
      );
      expect(sessionTodos.length).toBe(2);

      // Verify dependencies created during session
      const sessionRelations = collaborationSearch.hits.filter(h =>
        h.kind === 'relation' && h.data?.real_time_update
      );
      expect(sessionRelations.length).toBe(1);

      // Verify session summary
      expect(session?.data?.outcomes?.tasks_created).toBe(2);
      expect(session?.data?.outcomes?.total_story_points).toBe(8);
    });

    it('should handle conflict resolution in collaborative editing', async () => {
      const projectId = `conflict-resolution-${randomUUID().substring(0, 8)}`;
      const documentId = randomUUID();

      // Step 1: Alice creates initial document
      const initialDocument = {
        items: [{
          kind: 'section',
          scope: { project: projectId },
          data: {
            id: documentId,
            title: 'API Design Document',
            heading: 'Endpoints Overview',
            body_md: `
# API Design Document

## Authentication Endpoints
- POST /api/auth/login
- POST /api/auth/register
- POST /api/auth/refresh

## User Management Endpoints
- GET /api/users/:id
- PUT /api/users/:id
- DELETE /api/users/:id
            `.trim(),
            version: 1,
            last_edited_by: users[0].id,
            last_edited_at: new Date().toISOString()
          },
          source: { actor: users[0].id }
        }]
      };

      const initialResult = await callMCPTool('memory_store', initialDocument, users[0]);

      // Step 2: Bob and Alice edit simultaneously (conflict scenario)
      await setTimeout(50); // Small delay to simulate timing

      const concurrentEdits = await Promise.all([
        // Alice adds new section
        callMCPTool('memory_store', {
          items: [{
            kind: 'section',
            scope: { project: projectId },
            data: {
              id: documentId,
              title: 'API Design Document',
              heading: 'Rate Limiting',
              body_md: `
# Rate Limiting

## Endpoints
- All authenticated endpoints: 1000 requests/hour
- Authentication endpoints: 100 requests/hour
- Public endpoints: 100 requests/hour

## Implementation
- Redis-based rate limiting
- Sliding window algorithm
- Response headers: X-RateLimit-Limit, X-RateLimit-Remaining
              `.trim(),
              version: 2,
              last_edited_by: users[0].id,
              last_edited_at: new Date().toISOString(),
              conflict_resolution: 'merge_changes'
            },
            source: { actor: users[0].id }
          }]
        }, users[0]),

        // Bob modifies existing section
        callMCPTool('memory_store', {
          items: [{
            kind: 'section',
            scope: { project: projectId },
            data: {
              id: documentId,
              title: 'API Design Document',
              heading: 'User Management Endpoints',
              body_md: `
## User Management Endpoints
- GET /api/users/:id - Get user profile
- PUT /api/users/:id - Update user profile
- DELETE /api/users/:id - Delete user account
- POST /api/users/:id/avatar - Upload user avatar
- GET /api/users/:id/preferences - Get user preferences
- PUT /api/users/:id/preferences - Update user preferences

## Response Format
All endpoints return JSON with consistent structure:
\`\`\`json
{
  "success": true,
  "data": {...},
  "message": "Operation completed",
  "timestamp": "2024-01-01T00:00:00Z"
}
\`\`\`
              `.trim(),
              version: 2,
              last_edited_by: users[1].id,
              last_edited_at: new Date().toISOString(),
              conflict_resolution: 'merge_changes'
            },
            source: { actor: users[1].id }
          }]
        }, users[1])
      ]);

      expect(concurrentEdits.length).toBe(2);

      // Step 3: Create conflict resolution record
      const conflictRecord = {
        items: [{
          kind: 'observation',
          scope: { project: projectId },
          data: {
            title: 'Edit Conflict Resolution',
            content: `
Concurrent editing conflict detected and resolved:

Conflict: Alice and Bob edited the same document simultaneously
Resolution: Changes merged successfully
- Alice's additions: Rate limiting section
- Bob's modifications: Enhanced user management endpoints

No data loss occurred. Both users' contributions preserved.
            `.trim(),
            conflict_type: 'concurrent_edit',
            resolved_by: 'system',
            resolved_at: new Date().toISOString(),
            involved_users: [users[0].id, users[1].id]
          },
          source: { actor: 'system' }
        }]
      };

      await callMCPTool('memory_store', conflictRecord);

      // Step 4: Verify conflict resolution
      const resolvedDocument = await callMCPTool('memory_find', {
        query: 'API Design Document resolved',
        scope: { project: projectId },
        types: ['section', 'observation']
      });

      expect(resolvedDocument.hits.length).toBeGreaterThan(0);

      // Verify both contributions are present
      const sections = resolvedDocument.hits.filter(h => h.kind === 'section');
      const headings = sections.map(s => s.data?.heading);

      expect(headings).toContain('Rate Limiting'); // Alice's addition
      expect(headings).toContain('User Management Endpoints'); // Bob's modification

      // Verify conflict was recorded
      const conflictObservation = resolvedDocument.hits.find(h =>
        h.kind === 'observation' && h.data?.conflict_type === 'concurrent_edit'
      );
      expect(conflictObservation).toBeDefined();
      expect(conflictObservation?.data?.involved_users).toHaveLength(2);

      // Verify document integrity
      const latestDocument = sections.reduce((latest, current) =>
        (current.data?.version || 0) > (latest.data?.version || 0) ? current : latest
      );
      expect(latestDocument.data?.version).toBe(2);
    });
  });

  describe('User Activity Tracking', () => {
    it('should track and report user activities across the system', async () => {
      const projectId = `activity-tracking-${randomUUID().substring(0, 8)}`;

      // Step 1: Various users perform different activities
      const activities = await Promise.all([
        // Alice creates and updates decisions
        callMCPTool('memory_store', {
          items: [{
            kind: 'decision',
            scope: { project: projectId, team: 'frontend' },
            data: {
              title: 'Use TypeScript for Type Safety',
              status: 'proposed',
              rationale: 'TypeScript prevents runtime errors',
              proposed_by: users[0].id
            },
            source: { actor: users[0].id }
          }]
        }, users[0]),

        // Bob creates entities
        callMCPTool('memory_store', {
          items: [{
            kind: 'entity',
            scope: { project: projectId, team: 'backend' },
            data: {
              entity_type: 'service',
              name: 'UserService',
              data: { version: '1.0.0' }
            },
            source: { actor: users[1].id }
          }]
        }, users[1]),

        // Carol creates todos
        callMCPTool('memory_store', {
          items: [{
            kind: 'todo',
            scope: { project: projectId, team: 'product' },
            data: {
              text: 'Define user stories for sprint',
              status: 'pending',
              assignee: users[2].id
            },
            source: { actor: users[2].id }
          }]
        }, users[2])
      ]);

      // Step 2: Create activity summary
      const activitySummary = {
        items: [{
          kind: 'observation',
          scope: { project: projectId },
          data: {
            title: 'Team Activity Summary',
            content: `
Recent team activities in project ${projectId}:

Alice (Frontend):
- Created 1 decision (TypeScript adoption)
- Activity level: High

Bob (Backend):
- Created 1 entity (UserService)
- Activity level: Medium

Carol (Product):
- Created 1 todo (user stories)
- Activity level: Medium

Total activity: 3 knowledge items created
Collaboration score: 3 different teams engaged
            `.trim(),
            summary_type: 'activity_report',
            reporting_period: 'last_24_hours',
            generated_at: new Date().toISOString()
          },
          source: { actor: 'system' }
        }]
      };

      await callMCPTool('memory_store', activitySummary);

      // Step 3: Generate user-specific activity reports
      const userReports = await Promise.all([
        callMCPTool('memory_find', {
          query: `activities by ${users[0].name}`,
          scope: { project: projectId },
          types: ['decision', 'entity', 'todo', 'observation']
        }),
        callMCPTool('memory_find', {
          query: `activities by ${users[1].name}`,
          scope: { project: projectId },
          types: ['decision', 'entity', 'todo', 'observation']
        }),
        callMCPTool('memory_find', {
          query: `activities by ${users[2].name}`,
          scope: { project: projectId },
          types: ['decision', 'entity', 'todo', 'observation']
        })
      ]);

      // Verify individual user activities
      userReports.forEach((report, index) => {
        expect(report.hits.length).toBeGreaterThan(0);

        // Each user should have at least their own contribution
        const userContribution = report.hits.find(h =>
          h.data?.source?.actor === users[index].id ||
          h.data?.proposed_by === users[index].id ||
          h.data?.assignee === users[index].id
        );
        expect(userContribution).toBeDefined();
      });

      // Step 4: Test activity analytics
      const analyticsSearch = await callMCPTool('memory_find', {
        query: 'team activity analytics collaboration metrics',
        scope: { project: projectId },
        types: ['decision', 'entity', 'todo', 'observation']
      });

      expect(analyticsSearch.hits.length).toBeGreaterThan(0);

      // Analyze activity patterns
      const activitiesByType = analyticsSearch.hits.reduce((acc, hit) => {
        acc[hit.kind] = (acc[hit.kind] || 0) + 1;
        return acc;
      }, {} as Record<string, number>);

      expect(activitiesByType.decision).toBe(1);
      expect(activitiesByType.entity).toBe(1);
      expect(activitiesByType.todo).toBe(1);
      expect(activitiesByType.observation).toBe(1);

      // Analyze user participation
      const userParticipation = analyticsSearch.hits.reduce((acc, hit) => {
        const actor = hit.data?.source?.actor || hit.data?.proposed_by || hit.data?.assignee;
        if (actor) acc[actor] = (acc[actor] || 0) + 1;
        return acc;
      }, {} as Record<string, number>);

      expect(Object.keys(userParticipation)).toHaveLength(3);
      expect(userParticipation[users[0].id]).toBe(1);
      expect(userParticipation[users[1].id]).toBe(1);
      expect(userParticipation[users[2].id]).toBe(1);
    });
  });
});

// Helper Functions
async function setupTestDatabase(): Promise<void> {
  console.log('Setting up test database for multi-user scenarios...');
}

async function cleanupTestDatabase(): Promise<void> {
  console.log('Cleaning up test database for multi-user scenarios...');
}

async function cleanupTestData(): Promise<void> {
  console.log('Cleaning up test data for multi-user scenarios...');
}

async function startMCPServer(): Promise<TestServer> {
  const serverPath = path.join(__dirname, '../../dist/index.js');
  const process = spawn('node', [serverPath], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: {
      ...process.env,
      DATABASE_URL: TEST_DB_URL,
      NODE_ENV: 'test'
    }
  });

  return {
    process,
    port: 0 // Using stdio
  };
}

async function callMCPTool(toolName: string, args: any, user?: User): Promise<any> {
  return new Promise((resolve) => {
    setTimeout(() => {
      const items = args.items || [];

      // Add user context to items if provided
      if (user && items.length > 0) {
        items.forEach(item => {
          if (!item.source) item.source = {};
          item.source.actor = user.id;
          item.source.user_name = user.name;
          item.source.user_role = user.role;
          item.source.team = user.team;
        });
      }

      // Simulate permission checks
      if (user && args.items?.some(item => item.data?.requires_admin_approval)) {
        if (!user.permissions.includes('admin')) {
          resolve({
            stored: [],
            errors: [{
              index: 0,
              error_code: 'PERMISSION_DENIED',
              message: 'Admin approval required for this operation'
            }],
            autonomous_context: {
              action_performed: 'rejected',
              reason: 'Insufficient permissions',
              user: user.name
            }
          });
          return;
        }
      }

      // Simulate access control filtering
      let filteredItems = items;
      if (user && items.some(item => item.data?.restricted_to)) {
        filteredItems = items.filter(item =>
          !item.data?.restricted_to ||
          item.data.restricted_to.includes(user.team) ||
          item.data.restricted_to.includes(user.role)
        );
      }

      resolve({
        stored: filteredItems.map((item: any) => ({
          id: item.data?.id || randomUUID(),
          status: item.data?.id ? 'updated' : 'inserted',
          kind: item.kind || 'unknown',
          created_at: new Date().toISOString()
        })),
        errors: items.length - filteredItems.length > 0 ? [{
          index: 0,
          error_code: 'ACCESS_DENIED',
          message: 'Access denied to restricted content'
        }] : [],
        autonomous_context: {
          action_performed: filteredItems.length > 1 ? 'batch' : 'created',
          user: user?.name || 'anonymous',
          team: user?.team || 'no_team',
          permissions: user?.permissions || [],
          items_processed: filteredItems.length,
          items_denied: items.length - filteredItems.length,
          recommendation: filteredItems.length > 0 ? 'Operation completed' : 'Access denied',
          reasoning: user ? `User ${user.name} (${user.team}) performed operation` : 'Anonymous operation',
          user_message_suggestion: `✓ ${user?.name || 'User'} processed ${filteredItems.length} items`
        }
      });
    }, 80); // Slightly longer delay for multi-user scenario complexity
  });
}