/**
 * End-to-End MCP Tools Enhanced Testing
 *
 * Comprehensive end-to-end testing for MCP tools with ZAI integration,
 * including complete workflows, system health monitoring, and real-world scenarios.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { describe, test, expect, beforeAll, afterAll, beforeEach, afterEach } from '@jest/globals';
import {
  MockZAIServicesManager,
  createTestInsightRequest,
  createTestContradictionRequest,
  measurePerformance,
  mockZAIResponses,
  mockErrorScenarios,
} from '../mocks/zai-service.mock.js';
import type {
  InsightGenerationRequest,
  ContradictionDetectionRequest,
  ZAIJobType,
} from '../../src/types/zai-interfaces.js';

// Mock MCP server for testing
class MockMCPServer {
  private zaiServices: MockZAIServicesManager;
  private requestCount: number = 0;
  private errorCount: number = 0;

  constructor(zaiServices: MockZAIServicesManager) {
    this.zaiServices = zaiServices;
  }

  async initialize() {
    await this.zaiServices.initialize();
  }

  async shutdown() {
    await this.zaiServices.shutdown();
  }

  async handleRequest(request: any) {
    this.requestCount++;

    try {
      const { method, params } = request;

      switch (method) {
        case 'memory/store':
          return await this.handleMemoryStore(params);
        case 'memory/find':
          return await this.handleMemoryFind(params);
        case 'memory/insights/generate':
          return await this.handleInsightGeneration(params);
        case 'memory/contradictions/detect':
          return await this.handleContradictionDetection(params);
        case 'system/status':
          return await this.handleSystemStatus();
        case 'system/health':
          return await this.handleSystemHealth();
        case 'tools/list':
          return await this.handleToolsList();
        default:
          throw new Error(`Unknown method: ${method}`);
      }
    } catch (error) {
      this.errorCount++;
      throw error;
    }
  }

  private async handleMemoryStore(params: any) {
    const { items } = params;
    // Mock memory store implementation
    return {
      stored: items.length,
      ids: items.map((item: any) => item.id || `generated-${Date.now()}`),
    };
  }

  private async handleMemoryFind(params: any) {
    const { query, scope, types } = params;
    // Mock memory find implementation
    return {
      items: [
        {
          id: 'found-1',
          kind: 'decision',
          content: 'Found decision related to query',
          data: { title: 'Mock Decision' },
          score: 0.9,
        },
      ],
      total: 1,
      query,
    };
  }

  private async handleInsightGeneration(params: any) {
    const { items, options, scope } = params;
    const zaiClient = this.zaiServices.getZAIClient();

    const request: InsightGenerationRequest = {
      items,
      options,
      scope,
    };

    return await zaiClient.generateInsights(request);
  }

  private async handleContradictionDetection(params: any) {
    const { items, options, scope } = params;
    const zaiClient = this.zaiServices.getZAIClient();

    const request: ContradictionDetectionRequest = {
      items,
      options,
      scope,
    };

    return await zaiClient.detectContradictions(request);
  }

  private async handleSystemStatus() {
    return {
      status: 'healthy',
      uptime: 3600,
      version: '2.0.1',
      services: {
        zai: await this.zaiServices.getZAIClient().getServiceStatus(),
        orchestrator: await this.zaiServices.getOrchestrator().getStatus(),
        backgroundProcessor: this.zaiServices.getBackgroundProcessor().getStatus(),
      },
    };
  }

  private async handleSystemHealth() {
    return await this.zaiServices.healthCheck();
  }

  private async handleToolsList() {
    return {
      tools: [
        {
          name: 'memory_store',
          description: 'Store items in memory',
          inputSchema: { type: 'object' },
        },
        {
          name: 'memory_find',
          description: 'Find items in memory',
          inputSchema: { type: 'object' },
        },
        {
          name: 'insight_generation',
          description: 'Generate insights from items',
          inputSchema: { type: 'object' },
        },
        {
          name: 'contradiction_detection',
          description: 'Detect contradictions in items',
          inputSchema: { type: 'object' },
        },
      ],
    };
  }

  getMetrics() {
    return {
      requestCount: this.requestCount,
      errorCount: this.errorCount,
      errorRate: this.requestCount > 0 ? this.errorCount / this.requestCount : 0,
    };
  }
}

describe('End-to-End MCP Tools Enhanced Testing', () => {
  let mockServices: MockZAIServicesManager;
  let mockServer: MockMCPServer;

  beforeAll(async () => {
    mockServices = new MockZAIServicesManager();
    await mockServices.initialize();
    mockServer = new MockMCPServer(mockServices);
    await mockServer.initialize();
  });

  afterAll(async () => {
    await mockServer.shutdown();
    await mockServices.shutdown();
  });

  beforeEach(() => {
    mockServices.getZAIClient().reset();
    mockServices.getZAIClient().clearErrors();
  });

  afterEach(() => {
    mockServices.getZAIClient().clearErrors();
  });

  describe('Complete MCP Workflow Testing', () => {
    test('should handle complete insight generation workflow', async () => {
      // 1. Store items in memory
      const itemsToStore = [
        {
          id: 'workflow-1',
          kind: 'decision',
          content: 'Decision to adopt microservices architecture',
          data: {
            title: 'Microservices Decision',
            rationale: 'Improved scalability',
            impact: 'high',
          },
        },
        {
          id: 'workflow-2',
          kind: 'todo',
          content: 'Implement user authentication service',
          data: {
            title: 'Auth Service Task',
            priority: 'high',
            assignee: 'backend-team',
          },
        },
        {
          id: 'workflow-3',
          kind: 'issue',
          content: 'Performance degradation in current monolith',
          data: {
            title: 'Performance Issue',
            severity: 'medium',
            affected_components: ['api', 'database'],
          },
        },
      ];

      const storeResponse = await mockServer.handleRequest({
        method: 'memory/store',
        params: { items: itemsToStore },
      });

      expect(storeResponse.stored).toBe(3);
      expect(storeResponse.ids).toHaveLength(3);

      // 2. Generate insights for stored items
      const insightResponse = await mockServer.handleRequest({
        method: 'memory/insights/generate',
        params: {
          items: itemsToStore,
          options: {
            enabled: true,
            insight_types: ['patterns', 'connections', 'recommendations'],
            max_insights_per_item: 2,
            confidence_threshold: 0.6,
          },
          scope: { project: 'architecture-modernization' },
        },
      });

      expect(insightResponse.insights).toBeDefined();
      expect(insightResponse.metadata['items_processed']).toBe(3);

      // 3. Find related items based on insights
      const findResponse = await mockServer.handleRequest({
        method: 'memory/find',
        params: {
          query: 'microservices architecture decisions',
          scope: { project: 'architecture-modernization' },
          types: ['decision'],
        },
      });

      expect(findResponse.items).toBeDefined();
      expect(findResponse.items.length).toBeGreaterThanOrEqual(1);

      // 4. Check system health after workflow
      const healthResponse = await mockServer.handleRequest({
        method: 'system/health',
        params: {},
      });

      expect(healthResponse.status).toBe('healthy');
    });

    test('should handle contradiction detection workflow', async () => {
      // 1. Store potentially contradictory items
      const contradictoryItems = [
        {
          id: 'contradiction-1',
          kind: 'decision',
          content: 'Proceed with major system rewrite next quarter',
          data: {
            title: 'System Rewrite Decision',
            rationale: 'Technical debt cleanup',
            timeline: 'Q2 2025',
            impact: 'critical',
          },
        },
        {
          id: 'contradiction-2',
          kind: 'issue',
          content: 'Critical production stability issues requiring immediate attention',
          data: {
            title: 'Production Stability Crisis',
            severity: 'critical',
            timeline: 'Immediate',
            affected_components: ['core-system', 'database'],
          },
        },
      ];

      await mockServer.handleRequest({
        method: 'memory/store',
        params: { items: contradictoryItems },
      });

      // 2. Detect contradictions
      const contradictionResponse = await mockServer.handleRequest({
        method: 'memory/contradictions/detect',
        params: {
          items: contradictoryItems,
          options: {
            enabled: true,
            detection_types: ['semantic', 'temporal', 'logical'],
            confidence_threshold: 0.7,
          },
          scope: { project: 'system-stability' },
        },
      });

      expect(contradictionResponse.contradictions).toBeDefined();
      expect(contradictionResponse.metadata['items_processed']).toBe(2);

      // 3. Generate insights based on contradictions
      const insightResponse = await mockServer.handleRequest({
        method: 'memory/insights/generate',
        params: {
          items: contradictoryItems,
          options: {
            enabled: true,
            insight_types: ['recommendations', 'anomalies'],
            max_insights_per_item: 2,
            confidence_threshold: 0.6,
          },
          scope: { project: 'system-stability' },
        },
      });

      expect(insightResponse.insights).toBeDefined();

      // 4. System should remain healthy
      const statusResponse = await mockServer.handleRequest({
        method: 'system/status',
        params: {},
      });

      expect(statusResponse.status).toBe('healthy');
    });

    test('should handle combined insight and contradiction workflow', async () => {
      // Create complex scenario with multiple item types
      const complexItems = [
        {
          id: 'complex-1',
          kind: 'decision',
          content: 'Migrate to cloud-native architecture',
          data: {
            title: 'Cloud Migration Strategy',
            rationale: 'Better scalability and cost efficiency',
            timeline: '6 months',
            budget: '$500K',
          },
        },
        {
          id: 'complex-2',
          kind: 'todo',
          content: 'Set up Kubernetes infrastructure',
          data: {
            title: 'K8s Setup Task',
            priority: 'high',
            dependencies: ['cloud-provider-selection'],
            estimated_days: 30,
          },
        },
        {
          id: 'complex-3',
          kind: 'issue',
          content: 'Team lacks cloud expertise',
          data: {
            title: 'Skills Gap Issue',
            severity: 'high',
            affected_teams: ['development', 'operations'],
            resolution_needed: 'training or hiring',
          },
        },
        {
          id: 'complex-4',
          kind: 'entity',
          content: 'Cloud Migration Project Team',
          data: {
            title: 'Migration Team',
            members: ['team-lead', 'dev-1', 'dev-2', 'ops-1'],
            expertise_level: 'intermediate',
          },
        },
      ];

      // Store all items
      await mockServer.handleRequest({
        method: 'memory/store',
        params: { items: complexItems },
      });

      // Parallel processing of insights and contradictions
      const [insights, contradictions] = await Promise.all([
        mockServer.handleRequest({
          method: 'memory/insights/generate',
          params: {
            items: complexItems,
            options: {
              enabled: true,
              insight_types: ['patterns', 'connections', 'recommendations', 'trends'],
              max_insights_per_item: 2,
              confidence_threshold: 0.6,
            },
            scope: { project: 'cloud-migration' },
          },
        }),
        mockServer.handleRequest({
          method: 'memory/contradictions/detect',
          params: {
            items: complexItems,
            options: {
              enabled: true,
              detection_types: ['semantic', 'logical'],
              confidence_threshold: 0.6,
            },
            scope: { project: 'cloud-migration' },
          },
        }),
      ]);

      expect(insights.insights).toBeDefined();
      expect(insights.metadata['items_processed']).toBe(4);
      expect(contradictions.contradictions).toBeDefined();
      expect(contradictions.metadata['items_processed']).toBe(4);

      // System should handle parallel processing efficiently
      const metrics = mockServer.getMetrics();
      expect(metrics.requestCount).toBeGreaterThanOrEqual(3); // store + insights + contradictions
      expect(metrics.errorRate).toBe(0);
    });
  });

  describe('MCP Tool Integration Testing', () => {
    test('should list and validate all available tools', async () => {
      const toolsResponse = await mockServer.handleRequest({
        method: 'tools/list',
        params: {},
      });

      expect(toolsResponse.tools).toBeDefined();
      expect(Array.isArray(toolsResponse.tools)).toBe(true);

      const expectedTools = [
        'memory_store',
        'memory_find',
        'insight_generation',
        'contradiction_detection',
      ];

      const toolNames = toolsResponse.tools.map((tool: any) => tool.name);
      expectedTools.forEach((toolName) => {
        expect(toolNames).toContain(toolName);
      });

      // Each tool should have required properties
      toolsResponse.tools.forEach((tool: any) => {
        expect(tool.name).toBeDefined();
        expect(tool.description).toBeDefined();
        expect(tool.inputSchema).toBeDefined();
      });
    });

    test('should handle tool schema validation', async () => {
      // Test valid memory store request
      const validStoreRequest = {
        method: 'memory/store',
        params: {
          items: [
            {
              kind: 'decision',
              content: 'Test decision',
              data: { title: 'Test' },
            },
          ],
        },
      };

      await expect(mockServer.handleRequest(validStoreRequest)).resolves.toBeDefined();

      // Test invalid insight generation request (missing required fields)
      const invalidInsightRequest = {
        method: 'memory/insights/generate',
        params: {
          // Missing items array
          options: {
            enabled: true,
            insight_types: ['patterns'],
          },
        },
      };

      // Should handle gracefully without crashing
      await expect(mockServer.handleRequest(invalidInsightRequest)).resolves.toBeDefined();
    });

    test('should handle concurrent tool usage', async () => {
      const concurrentRequests = 10;

      const requests = Array.from({ length: concurrentRequests }, (_, i) => ({
        method:
          i % 3 === 0 ? 'memory/store' : i % 3 === 1 ? 'memory/insights/generate' : 'memory/find',
        params: {
          ...(i % 3 === 0 && {
            items: [
              {
                id: `concurrent-${i}`,
                kind: 'todo',
                content: `Concurrent task ${i}`,
                data: { title: `Task ${i}` },
              },
            ],
          }),
          ...(i % 3 === 1 && {
            items: [
              {
                id: `insight-${i}`,
                kind: 'decision',
                content: `Decision for insight ${i}`,
                data: { title: `Decision ${i}` },
              },
            ],
            options: {
              enabled: true,
              insight_types: ['patterns'],
              max_insights_per_item: 1,
            },
          }),
          ...(i % 3 === 2 && {
            query: `search query ${i}`,
            scope: { project: 'test' },
          }),
        },
      }));

      const startTime = Date.now();
      const responses = await Promise.allSettled(
        requests.map((request) => mockServer.handleRequest(request))
      );
      const totalTime = Date.now() - startTime;

      const successful = responses.filter((r) => r.status === 'fulfilled').length;
      const failed = responses.filter((r) => r.status === 'rejected').length;

      expect(successful + failed).toBe(concurrentRequests);
      expect(successful).toBeGreaterThan(concurrentRequests * 0.8); // At least 80% success

      // Should handle concurrent requests efficiently
      expect(totalTime).toBeLessThan(5000); // Less than 5 seconds for 10 concurrent requests

      const metrics = mockServer.getMetrics();
      expect(metrics.errorRate).toBeLessThan(0.2); // Less than 20% error rate
    });
  });

  describe('Real-world Scenario Testing', () => {
    test('should handle project management workflow', async () => {
      // Simulate a real project management scenario
      const projectItems = [
        // Project decisions
        {
          id: 'proj-decision-1',
          kind: 'decision',
          content: 'Adopt Agile methodology for new product development',
          data: {
            title: 'Agile Adoption Decision',
            rationale: 'Faster delivery and better customer feedback',
            impact: 'high',
            stakeholders: ['product', 'engineering', 'management'],
            timeline: 'Starting next sprint',
          },
        },
        {
          id: 'proj-decision-2',
          kind: 'decision',
          content: 'Invest in automated testing infrastructure',
          data: {
            title: 'Testing Infrastructure Investment',
            rationale: 'Improve code quality and reduce bugs',
            budget: '$100K',
            expected_roi: 'Reduced QA costs by 40%',
          },
        },

        // Project tasks
        {
          id: 'proj-todo-1',
          kind: 'todo',
          content: 'Set up CI/CD pipeline',
          data: {
            title: 'CI/CD Pipeline Setup',
            priority: 'high',
            assignee: 'devops-team',
            dependencies: ['git-repo-setup'],
            estimated_days: 10,
          },
        },
        {
          id: 'proj-todo-2',
          kind: 'todo',
          content: 'Conduct Agile training sessions',
          data: {
            title: 'Agile Training',
            priority: 'medium',
            assignee: 'scrum-master',
            attendees: 'all-development-team',
            duration: '2 days',
          },
        },

        // Project issues
        {
          id: 'proj-issue-1',
          kind: 'issue',
          content: 'Team resistance to Agile methodology change',
          data: {
            title: 'Change Management Issue',
            severity: 'medium',
            affected_teams: ['development', 'qa'],
            symptoms: ['Missed stand-ups', 'Sprint planning delays'],
          },
        },
        {
          id: 'proj-issue-2',
          kind: 'issue',
          content: 'Limited testing environment capacity',
          data: {
            title: 'Testing Infrastructure Limitation',
            severity: 'high',
            impact: ['Deployment delays', 'Quality issues'],
            bottleneck: 'insufficient test servers',
          },
        },
      ];

      // 1. Store all project items
      await mockServer.handleRequest({
        method: 'memory/store',
        params: { items: projectItems },
      });

      // 2. Generate comprehensive insights
      const insights = await mockServer.handleRequest({
        method: 'memory/insights/generate',
        params: {
          items: projectItems,
          options: {
            enabled: true,
            insight_types: ['patterns', 'connections', 'recommendations', 'anomalies', 'trends'],
            max_insights_per_item: 3,
            confidence_threshold: 0.6,
          },
          scope: { project: 'product-development-2025' },
        },
      });

      expect(insights.insights.length).toBeGreaterThan(0);
      expect(insights.metadata['items_processed']).toBe(6);

      // 3. Detect potential contradictions or issues
      const contradictions = await mockServer.handleRequest({
        method: 'memory/contradictions/detect',
        params: {
          items: projectItems,
          options: {
            enabled: true,
            detection_types: ['semantic', 'logical'],
            confidence_threshold: 0.6,
          },
          scope: { project: 'product-development-2025' },
        },
      });

      expect(contradictions.contradictions).toBeDefined();

      // 4. Find related items for specific queries
      const agileRelated = await mockServer.handleRequest({
        method: 'memory/find',
        params: {
          query: 'Agile methodology implementation challenges',
          scope: { project: 'product-development-2025' },
          types: ['decision', 'issue'],
        },
      });

      expect(agileRelated.items.length).toBeGreaterThan(0);

      // 5. Check system health after complex workflow
      const health = await mockServer.handleRequest({
        method: 'system/health',
        params: {},
      });

      expect(health.status).toBe('healthy');
    });

    test('should handle incident response workflow', async () => {
      // Simulate incident response scenario
      const incidentItems = [
        {
          id: 'incident-1',
          kind: 'incident',
          content: 'Production database outage affecting user authentication',
          data: {
            title: 'Database Outage Incident',
            severity: 'critical',
            impact: ['User login failures', 'Data access issues'],
            timeline: 'Started 30 minutes ago',
            affected_users: 'All active users',
            incident_commander: 'ops-lead',
          },
        },
        {
          id: 'incident-2',
          kind: 'decision',
          content: 'Execute emergency failover to backup database',
          data: {
            title: 'Emergency Failover Decision',
            rationale: 'Restore service availability quickly',
            decision_maker: 'incident-commander',
            approval: 'emergency-protocol',
            risks: ['Potential data sync issues'],
          },
        },
        {
          id: 'incident-3',
          kind: 'todo',
          content: 'Notify all stakeholders about service disruption',
          data: {
            title: 'Stakeholder Communication',
            priority: 'critical',
            channels: ['email', 'status-page', 'slack'],
            message: 'Service temporarily unavailable due to database issues',
            next_update: 'in 15 minutes',
          },
        },
      ];

      // Process incident items rapidly
      const startTime = Date.now();

      await mockServer.handleRequest({
        method: 'memory/store',
        params: { items: incidentItems },
      });

      const insights = await mockServer.handleRequest({
        method: 'memory/insights/generate',
        params: {
          items: incidentItems,
          options: {
            enabled: true,
            insight_types: ['recommendations', 'anomalies'],
            max_insights_per_item: 2,
            confidence_threshold: 0.5, // Lower threshold for emergency situations
          },
          scope: { project: 'incident-response' },
        },
      });

      const contradictions = await mockServer.handleRequest({
        method: 'memory/contradictions/detect',
        params: {
          items: incidentItems,
          options: {
            enabled: true,
            detection_types: ['semantic'],
            confidence_threshold: 0.5,
          },
          scope: { project: 'incident-response' },
        },
      });

      const processingTime = Date.now() - startTime;

      // Incident response should be fast
      expect(processingTime).toBeLessThan(2000); // Less than 2 seconds

      // Should provide actionable insights
      expect(insights.insights.length).toBeGreaterThan(0);

      // System should remain stable during incident processing
      const status = await mockServer.handleRequest({
        method: 'system/status',
        params: {},
      });

      expect(status.status).toBe('healthy');
    });
  });

  describe('Performance and Scalability Testing', () => {
    test('should handle high-volume operations efficiently', async () => {
      const volume = 50;
      const itemsPerBatch = 10;

      // Create high-volume scenario
      const highVolumeItems = Array.from({ length: volume }, (_, i) => ({
        id: `volume-${i}`,
        kind: ['decision', 'todo', 'issue', 'entity'][i % 4] as any,
        content: `High volume test item ${i}`,
        data: {
          title: `Volume Test Item ${i}`,
          content: `Extended content for volume testing item ${i} to simulate real-world data complexity and processing requirements.`,
          metadata: {
            batch: Math.floor(i / itemsPerBatch),
            priority: i % 3 === 0 ? 'high' : 'normal',
            complexity: 'medium',
          },
        },
      }));

      // Measure performance of high-volume operations
      const { durationMs } = await measurePerformance(async () => {
        // Store all items
        await mockServer.handleRequest({
          method: 'memory/store',
          params: { items: highVolumeItems },
        });

        // Process in batches
        const batches = [];
        for (let i = 0; i < highVolumeItems.length; i += itemsPerBatch) {
          const batch = highVolumeItems.slice(i, i + itemsPerBatch);
          batches.push(batch);
        }

        // Process insights for each batch
        const insightPromises = batches.map((batch) =>
          mockServer.handleRequest({
            method: 'memory/insights/generate',
            params: {
              items: batch,
              options: {
                enabled: true,
                insight_types: ['patterns', 'connections'],
                max_insights_per_item: 1,
                confidence_threshold: 0.6,
              },
              scope: { project: 'volume-test' },
            },
          })
        );

        await Promise.all(insightPromises);
      });

      // High-volume operations should complete within reasonable time
      expect(durationMs).toBeLessThan(15000); // Less than 15 seconds for 50 items

      // System should handle load without degradation
      const health = await mockServer.handleRequest({
        method: 'system/health',
        params: {},
      });

      expect(health.status).toBe('healthy');
    });

    test('should maintain performance under sustained load', async () => {
      const loadTestDuration = 3000; // 3 seconds
      const requestInterval = 50; // Request every 50ms
      const startTime = Date.now();
      const requestTimes: number[] = [];

      while (Date.now() - startTime < loadTestDuration) {
        const requestStartTime = Date.now();

        await mockServer.handleRequest({
          method: 'memory/find',
          params: {
            query: `Sustained load test query ${Date.now()}`,
            scope: { project: 'load-test' },
            types: ['decision', 'todo'],
          },
        });

        const requestDuration = Date.now() - requestStartTime;
        requestTimes.push(requestDuration);

        await new Promise((resolve) => setTimeout(resolve, requestInterval));
      }

      // Analyze performance consistency
      const averageTime = requestTimes.reduce((sum, time) => sum + time, 0) / requestTimes.length;
      const maxTime = Math.max(...requestTimes);
      const minTime = Math.min(...requestTimes);

      // Performance should be consistent under load
      expect(maxTime).toBeLessThan(averageTime * 2); // Max not more than 2x average
      expect(minTime).toBeGreaterThan(averageTime * 0.5); // Min not less than 0.5x average
      expect(averageTime).toBeLessThan(200); // Average under 200ms per request
    });
  });

  describe('Error Handling and Recovery Testing', () => {
    test('should handle service failures gracefully', async () => {
      // Simulate ZAI service failure
      mockServices.getZAIClient().setErrorScenario('api_error');

      // Operations should fail gracefully
      await expect(
        mockServer.handleRequest({
          method: 'memory/insights/generate',
          params: {
            items: [createTestInsightRequest().items[0]],
            options: { enabled: true, insight_types: ['patterns'] },
          },
        })
      ).rejects.toThrow();

      // Clear error and test recovery
      mockServices.getZAIClient().clearErrors();

      // Should recover and work normally
      await expect(
        mockServer.handleRequest({
          method: 'memory/insights/generate',
          params: {
            items: [createTestInsightRequest().items[0]],
            options: { enabled: true, insight_types: ['patterns'] },
          },
        })
      ).resolves.toBeDefined();

      // System should report health status
      const health = await mockServer.handleRequest({
        method: 'system/health',
        params: {},
      });

      expect(health.status).toBe('healthy');
    });

    test('should handle partial failures in complex workflows', async () => {
      const items = [
        { id: 'partial-1', kind: 'decision', content: 'Item 1' },
        { id: 'partial-2', kind: 'todo', content: 'Item 2' },
        { id: 'partial-3', kind: 'issue', content: 'Item 3' },
      ];

      // Store items successfully
      await mockServer.handleRequest({
        method: 'memory/store',
        params: { items },
      });

      // Simulate intermittent failure during insight generation
      let requestCount = 0;
      const originalHandleRequest = mockServer.handleRequest.bind(mockServer);
      mockServer.handleRequest = async function (request: any) {
        requestCount++;
        if (request.method === 'memory/insights/generate' && requestCount === 2) {
          throw new Error('Simulated intermittent failure');
        }
        return originalHandleRequest(request);
      };

      // First insight generation should work
      const result1 = await mockServer.handleRequest({
        method: 'memory/insights/generate',
        params: {
          items,
          options: { enabled: true, insight_types: ['patterns'] },
        },
      });
      expect(result1).toBeDefined();

      // Second should fail
      await expect(
        mockServer.handleRequest({
          method: 'memory/insights/generate',
          params: {
            items,
            options: { enabled: true, insight_types: ['patterns'] },
          },
        })
      ).rejects.toThrow();

      // Third should work again
      const result3 = await mockServer.handleRequest({
        method: 'memory/insights/generate',
        params: {
          items,
          options: { enabled: true, insight_types: ['patterns'] },
        },
      });
      expect(result3).toBeDefined();

      // Restore original handler
      mockServer.handleRequest = originalHandleRequest;
    });
  });

  describe('System Integration and Health Monitoring', () => {
    test('should provide comprehensive system status', async () => {
      const status = await mockServer.handleRequest({
        method: 'system/status',
        params: {},
      });

      expect(status.status).toBe('healthy');
      expect(status.uptime).toBeGreaterThan(0);
      expect(status.version).toBeDefined();
      expect(status.services).toBeDefined();

      // Check individual service statuses
      expect(status.services.zai).toBeDefined();
      expect(status.services.orchestrator).toBeDefined();
      expect(status.services.backgroundProcessor).toBeDefined();
    });

    test('should perform comprehensive health checks', async () => {
      const health = await mockServer.handleRequest({
        method: 'system/health',
        params: {},
      });

      expect(health.status).toBeDefined();
      expect(health.provider).toBeDefined();
      expect(health.orchestrator).toBeDefined();
      expect(health.backgroundProcessor).toBeDefined();
      expect(health.metrics).toBeDefined();

      // Health metrics should be within reasonable ranges
      expect(health.metrics.errorRate).toBeLessThanOrEqual(1.0);
      expect(health.metrics.averageLatency).toBeGreaterThan(0);
    });

    test('should track metrics over time', async () => {
      const initialMetrics = mockServer.getMetrics();

      // Perform various operations
      await mockServer.handleRequest({ method: 'tools/list', params: {} });
      await mockServer.handleRequest({
        method: 'memory/store',
        params: { items: [{ id: 'metrics-1', kind: 'todo', content: 'Test' }] },
      });
      await mockServer.handleRequest({
        method: 'memory/find',
        params: { query: 'test', scope: {} },
      });

      const finalMetrics = mockServer.getMetrics();

      expect(finalMetrics.requestCount).toBeGreaterThan(initialMetrics.requestCount);
      expect(finalMetrics.errorRate).toBeLessThanOrEqual(0.5); // Error rate should be low
    });
  });
});
