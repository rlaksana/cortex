/**
 * ZAI Service Mock Framework
 *
 * Comprehensive mocking framework for ZAI services including
 * insight generation, contradiction detection, and AI operations
 * for isolated unit testing.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { vi, beforeEach, afterEach, describe, it, expect } from 'vitest';
import type {
  ZAIChatRequest,
  ZAIChatResponse,
  ZAIJobType,
  InsightGenerationRequest,
  InsightGenerationResponse,
  ContradictionDetectionRequest,
  ContradictionDetectionResponse,
} from '../../src/types/zai-interfaces.js';

// Mock response templates
export const mockZAIResponses = {
  insight_generation: {
    pattern_recognition: {
      type: 'patterns',
      confidence: 0.92,
      description: 'Repeated architecture decisions indicate microservices migration pattern',
      items: ['test-item-1', 'test-item-3'],
      metadata: {
        pattern_type: 'temporal',
        frequency: 3,
        time_span: '2_weeks',
      },
    },
    knowledge_gaps: {
      type: 'recommendations',
      confidence: 0.87,
      description: 'Missing performance testing strategy for microservices migration',
      recommendation: 'Create comprehensive performance testing plan before migration',
      priority: 'high',
      items: ['test-item-1', 'test-item-2'],
    },
    relationship_analysis: {
      type: 'connections',
      confidence: 0.95,
      description: 'Strong dependency between authentication service and user service',
      relationship_type: 'dependency',
      source: 'test-item-2',
      target: 'user-service',
      strength: 0.9,
    },
    anomaly_detection: {
      type: 'anomalies',
      confidence: 0.78,
      description: 'Unusual spike in database connection issues during migration',
      anomaly_type: 'performance_regression',
      severity: 'medium',
      affected_items: ['test-item-3'],
    },
    predictive_insights: {
      type: 'trends',
      confidence: 0.83,
      description: 'Likely increase in cross-service communication overhead',
      trend_direction: 'increasing',
      confidence_interval: [0.75, 0.91],
      timeframe: 'next_3_months',
    },
  },
  contradiction_detection: {
    semantic: {
      type: 'contradiction',
      confidence: 0.91,
      description: 'Architecture decision conflicts with performance issue symptoms',
      items: ['test-item-1', 'test-item-3'],
      contradiction_type: 'semantic',
      severity: 'high',
      resolution_suggestion: 'Re-evaluate microservices migration timeline',
    },
    temporal: {
      type: 'timeline_conflict',
      confidence: 0.85,
      description: 'Implementation overlaps with performance degradation period',
      items: ['test-item-2', 'test-item-3'],
      conflict_type: 'temporal',
      severity: 'medium',
      timeline_details: {
        implementation_start: '2025-01-16T14:30:00Z',
        degradation_start: '2025-01-17T09:15:00Z',
        overlap_hours: 18.75,
      },
    },
    logical: {
      type: 'logical_inconsistency',
      confidence: 0.88,
      description: 'Decision to migrate conflicts with current system instability',
      items: ['test-item-1', 'test-item-3'],
      inconsistency_type: 'strategic',
      severity: 'high',
      logical_implications: [
        'Increased risk during migration',
        'Potential for extended downtime',
        'Resource contention issues',
      ],
    },
  },
};

// Performance benchmark data
export const mockPerformanceData = {
  insight_generation: {
    batch_50_items: {
      target_time_ms: 5000,
      acceptable_variance_ms: 1000,
      memory_usage_mb: 128,
      cpu_usage_percent: 45,
    },
    batch_100_items: {
      target_time_ms: 8000,
      acceptable_variance_ms: 1500,
      memory_usage_mb: 256,
      cpu_usage_percent: 65,
    },
    single_item: {
      target_time_ms: 200,
      acceptable_variance_ms: 100,
      memory_usage_mb: 32,
      cpu_usage_percent: 15,
    },
  },
  contradiction_detection: {
    batch_100_items: {
      target_time_ms: 3000,
      acceptable_variance_ms: 500,
      memory_usage_mb: 96,
      cpu_usage_percent: 35,
    },
    batch_200_items: {
      target_time_ms: 5000,
      acceptable_variance_ms: 800,
      memory_usage_mb: 192,
      cpu_usage_percent: 55,
    },
    single_item: {
      target_time_ms: 150,
      acceptable_variance_ms: 75,
      memory_usage_mb: 24,
      cpu_usage_percent: 12,
    },
  },
};

// Error scenarios for testing
export const mockErrorScenarios = {
  network_timeout: {
    name: 'NetworkTimeoutError',
    message: 'ZAI API request timed out after 30 seconds',
    code: 'NETWORK_TIMEOUT',
    retry_after: 5000,
  },
  rate_limit: {
    name: 'RateLimitError',
    message: 'ZAI API rate limit exceeded',
    code: 'RATE_LIMIT_EXCEEDED',
    retry_after: 60000,
    limit: 100,
    remaining: 0,
  },
  api_error: {
    name: 'ZAI_APIError',
    message: 'ZAI API returned an error',
    code: 'API_ERROR',
    status: 500,
    details: 'Internal server error',
  },
  invalid_response: {
    name: 'InvalidResponseError',
    message: 'Invalid response format from ZAI API',
    code: 'INVALID_RESPONSE',
    received: 'Malformed JSON',
  },
  authentication: {
    name: 'AuthenticationError',
    message: 'Invalid ZAI API credentials',
    code: 'AUTHENTICATION_ERROR',
    status: 401,
  },
  model_unavailable: {
    name: 'ModelUnavailableError',
    message: 'Requested ZAI model is currently unavailable',
    code: 'MODEL_UNAVAILABLE',
    model: 'glm-4.6',
    available_models: ['glm-4.5', 'glm-4.0'],
  },
};

// Mock ZAI Client Service
export class MockZAIClientService {
  private responses: any = {};
  private errors: any[] = [];
  private responseDelay: number = 100;

  constructor(config?: any) {
    this.setupDefaultResponses();
  }

  private setupDefaultResponses() {
    this.responses = {
      'chat/completions': this.mockChatCompletion,
      'insights/generate': this.mockInsightGeneration,
      'contradictions/detect': this.mockContradictionDetection,
    };
  }

  setResponseDelay(delay: number) {
    this.responseDelay = delay;
  }

  setMockResponse(endpoint: string, response: any) {
    this.responses[endpoint] = response;
  }

  setErrorScenario(scenario: keyof typeof mockErrorScenarios) {
    this.errors.push(mockErrorScenarios[scenario]);
  }

  clearErrors() {
    this.errors = [];
  }

  private async mockChatCompletion(request: ZAIChatRequest): Promise<ZAIChatResponse> {
    await this.simulateDelay();
    this.checkForErrors();

    return {
      id: `chat_${Date.now()}`,
      object: 'chat.completion',
      created: Math.floor(Date.now() / 1000),
      model: request.model || 'glm-4.6',
      choices: [
        {
          index: 0,
          message: {
            role: 'assistant',
            content: this.generateMockResponse(request.messages),
          },
          finish_reason: 'stop',
        },
      ],
      usage: {
        prompt_tokens: this.estimateTokens(request.messages),
        completion_tokens: 150,
        total_tokens: this.estimateTokens(request.messages) + 150,
      },
    };
  }

  private async mockInsightGeneration(
    request: InsightGenerationRequest
  ): Promise<InsightGenerationResponse> {
    await this.simulateDelay();
    this.checkForErrors();

    const insights = [];
    const strategies = request.options?.insight_types || [
      'patterns',
      'connections',
      'recommendations',
    ];

    for (const strategy of strategies) {
      const mockInsight =
        mockZAIResponses.insight_generation[
          strategy as keyof typeof mockZAIResponses.insight_generation
        ];
      if (mockInsight) {
        insights.push({
          id: `insight_${Date.now()}_${strategy}`,
          item_id: request.items[0]?.id || 'unknown',
          type: mockInsight.type,
          confidence: mockInsight.confidence,
          description: mockInsight.description,
          metadata: mockInsight,
          created_at: new Date().toISOString(),
        });
      }
    }

    return {
      insights,
      errors: [],
      warnings: [],
      metadata: {
        total_insights: insights.length,
        items_processed: request.items.length,
        processing_time_ms: this.responseDelay,
        average_confidence:
          insights.length > 0
            ? insights.reduce((sum, i) => sum + i.confidence, 0) / insights.length
            : 0,
        insights_by_type: insights.reduce(
          (acc, i) => {
            acc[i.type] = (acc[i.type] || 0) + 1;
            return acc;
          },
          {} as Record<string, number>
        ),
        performance_impact: 0.1,
        cache_hit_rate: 0.0,
      },
    };
  }

  private async mockContradictionDetection(
    request: ContradictionDetectionRequest
  ): Promise<ContradictionDetectionResponse> {
    await this.simulateDelay();
    this.checkForErrors();

    const contradictions = [];
    const detectionTypes = ['semantic', 'temporal', 'logical'];

    for (const type of detectionTypes) {
      const mockContradiction =
        mockZAIResponses.contradiction_detection[
          type as keyof typeof mockZAIResponses.contradiction_detection
        ];
      if (mockContradiction && Math.random() > 0.5) {
        contradictions.push({
          id: `contradiction_${Date.now()}_${type}`,
          type: mockContradiction.type,
          confidence: mockContradiction.confidence,
          description: mockContradiction.description,
          items: mockContradiction.items,
          metadata: mockContradiction,
          created_at: new Date().toISOString(),
        });
      }
    }

    return {
      contradictions,
      metadata: {
        total_contradictions: contradictions.length,
        items_processed: request.items.length,
        processing_time_ms: this.responseDelay,
        average_confidence:
          contradictions.length > 0
            ? contradictions.reduce((sum, c) => sum + c.confidence, 0) / contradictions.length
            : 0,
        contradictions_by_type: contradictions.reduce(
          (acc, c) => {
            acc[c.type] = (acc[c.type] || 0) + 1;
            return acc;
          },
          {} as Record<string, number>
        ),
      },
    };
  }

  private async simulateDelay() {
    return new Promise((resolve) => setTimeout(resolve, this.responseDelay));
  }

  private checkForErrors() {
    if (this.errors.length > 0) {
      const error = this.errors.shift();
      throw new Error(error.message);
    }
  }

  private generateMockResponse(messages: any[]): string {
    const lastMessage = messages[messages.length - 1];
    if (lastMessage?.role === 'user') {
      const content = lastMessage.content.toLowerCase();

      if (content.includes('insight')) {
        return 'Based on the analysis, I can see patterns in your decision-making process that suggest a systematic approach to architecture migration.';
      } else if (content.includes('contradiction')) {
        return 'I detect a potential contradiction between your migration decision and the current system instability.';
      } else if (content.includes('pattern')) {
        return 'There is a clear pattern of architectural decisions favoring microservices over monolithic approaches.';
      }
    }

    return 'I understand your request. Based on the context provided, here is my analysis.';
  }

  private estimateTokens(messages: any[]): number {
    return messages.reduce((total, msg) => {
      return total + Math.ceil((msg.content || '').length / 4);
    }, 0);
  }

  // Public API methods
  async chat(request: ZAIChatRequest): Promise<ZAIChatResponse> {
    return this.mockChatCompletion(request);
  }

  async generateInsights(request: InsightGenerationRequest): Promise<InsightGenerationResponse> {
    return this.mockInsightGeneration(request);
  }

  async detectContradictions(
    request: ContradictionDetectionRequest
  ): Promise<ContradictionDetectionResponse> {
    return this.mockContradictionDetection(request);
  }

  getMetrics() {
    return {
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      averageResponseTime: this.responseDelay,
      errorRate: 0,
      uptime: 100,
    };
  }

  async getServiceStatus() {
    return {
      status: 'healthy',
      responseTime: this.responseDelay,
      errorRate: 0,
      circuitBreakerState: 'closed',
      uptime: 100,
    };
  }

  reset() {
    this.clearErrors();
    this.setupDefaultResponses();
  }
}

// Mock AI Orchestrator Service
export class MockAIOrchestratorService {
  private activeProvider: 'zai' | 'openai' = 'zai';
  private failoverCount: number = 0;
  private zaiClient: MockZAIClientService;

  constructor(zaiClient: MockZAIClientService) {
    this.zaiClient = zaiClient;
  }

  async getStatus() {
    return {
      status: 'healthy',
      activeProvider: this.activeProvider,
      primaryProvider: 'zai',
      fallbackProvider: 'openai',
      failoverCount: this.failoverCount,
      autoFailoverEnabled: true,
      uptime: 100,
    };
  }

  getMetrics() {
    return {
      orchestrator: {
        uptime: 100,
        totalRequests: 0,
        successfulRequests: 0,
        failedRequests: 0,
      },
      providers: {
        zai: {
          status: 'healthy',
          responseTime: 100,
          errorRate: 0,
        },
        openai: {
          status: 'healthy',
          responseTime: 120,
          errorRate: 0,
        },
      },
    };
  }

  async switchProvider(provider: 'zai' | 'openai') {
    if (provider !== this.activeProvider) {
      this.activeProvider = provider;
      this.failoverCount++;
    }
  }

  getClient() {
    return this.zaiClient;
  }
}

// Mock Background Processor Service
export class MockBackgroundProcessorService {
  private jobs: Map<string, any> = new Map();
  private jobIdCounter: number = 1;

  async submitJob(type: ZAIJobType, data: any, options?: any): Promise<string> {
    const jobId = `job_${this.jobIdCounter++}`;
    const job = {
      id: jobId,
      type,
      data,
      options: { priority: 'normal', ...options },
      status: 'pending',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    this.jobs.set(jobId, job);

    // Simulate async processing
    setTimeout(() => {
      job.status = 'processing';
      job.updated_at = new Date().toISOString();

      setTimeout(() => {
        job.status = 'completed';
        job.updated_at = new Date().toISOString();
        job.result = this.generateMockJobResult(type, data);
      }, 200);
    }, 100);

    return jobId;
  }

  getJobStatus(jobId: string) {
    return this.jobs.get(jobId) || null;
  }

  getStatus() {
    const jobs = Array.from(this.jobs.values());
    return {
      status: 'healthy',
      activeJobs: jobs.filter((j) => j.status === 'processing').length,
      queuedJobs: jobs.filter((j) => j.status === 'pending').length,
      completedJobs: jobs.filter((j) => j.status === 'completed').length,
      failedJobs: jobs.filter((j) => j.status === 'failed').length,
      uptime: 100,
      memoryUsage: {
        used: 64,
        total: 512,
        percentage: 12.5,
      },
    };
  }

  getMetrics() {
    return {
      processor: {
        uptime: 100,
        totalJobsProcessed: this.jobs.size,
        successRate: 0.95,
      },
      queue: {
        size: this.jobs.size,
        processingTime: 250,
      },
      workers: {
        active: 2,
        idle: 3,
        total: 5,
      },
      performance: {
        successRate: 0.95,
        averageProcessingTime: 250,
        throughput: 4,
      },
    };
  }

  private generateMockJobResult(type: ZAIJobType, data: any) {
    switch (type) {
      case 'text_transformation':
        return { transformed_text: data.text?.toUpperCase() || '' };
      case 'summarization':
        return { summary: `Summary of: ${data.text?.substring(0, 50)}...` };
      case 'classification':
        return { category: data.categories?.[0] || 'general', confidence: 0.85 };
      case 'insight_generation':
        return { insights: ['mock insight 1', 'mock insight 2'] };
      case 'contradiction_detection':
        return { contradictions: ['mock contradiction 1'] };
      default:
        return { result: 'mock job result' };
    }
  }
}

// Mock Services Manager
export class MockZAIServicesManager {
  private zaiClient: MockZAIClientService;
  private orchestrator: MockAIOrchestratorService;
  private backgroundProcessor: MockBackgroundProcessorService;
  private initialized: boolean = false;

  constructor() {
    this.zaiClient = new MockZAIClientService();
    this.orchestrator = new MockAIOrchestratorService(this.zaiClient);
    this.backgroundProcessor = new MockBackgroundProcessorService();
  }

  async initialize() {
    this.initialized = true;
  }

  async shutdown() {
    this.initialized = false;
  }

  isReady() {
    return this.initialized;
  }

  async healthCheck() {
    return {
      status: 'healthy',
      provider: await this.zaiClient.getServiceStatus(),
      orchestrator: await this.orchestrator.getStatus(),
      backgroundProcessor: this.backgroundProcessor.getStatus(),
      metrics: {
        errorRate: 0,
        averageLatency: 150,
      },
    };
  }

  getMetrics() {
    return {
      config: {
        zai: { model: 'glm-4.6', enabled: true },
        orchestrator: { primaryProvider: 'zai', autoFailover: true },
        backgroundProcessor: { maxConcurrency: 5, queueSize: 100 },
      },
      zai: this.zaiClient.getMetrics(),
      orchestrator: this.orchestrator.getMetrics(),
      backgroundProcessor: this.backgroundProcessor.getMetrics(),
      system: {
        ready: this.initialized,
        memoryUsage: {
          used: 256,
          total: 2048,
          percentage: 12.5,
        },
      },
    };
  }

  async submitJob(type: ZAIJobType, data: any, options?: any) {
    return this.backgroundProcessor.submitJob(type, data, options);
  }

  // Access to individual services for testing
  getZAIClient() {
    return this.zaiClient;
  }
  getOrchestrator() {
    return this.orchestrator;
  }
  getBackgroundProcessor() {
    return this.backgroundProcessor;
  }
}

// Test utilities
export const createTestInsightRequest = (): InsightGenerationRequest => ({
  items: [
    {
      id: 'test-item-1',
      kind: 'decision',
      content: 'Decision to migrate to microservices architecture',
      data: {
        title: 'Microservices Migration Decision',
        content:
          'After careful consideration, we decided to migrate our monolithic application to microservices.',
        rationale: 'Improved scalability, team autonomy, and technology flexibility',
        impact: 'High',
        tags: ['architecture', 'migration', 'microservices'],
        created_at: '2025-01-15T10:00:00Z',
      },
      scope: { project: 'platform-migration' },
      created_at: '2025-01-15T10:00:00Z',
    },
  ],
  options: {
    enabled: true,
    insight_types: ['patterns', 'connections', 'recommendations'],
    max_insights_per_item: 3,
    confidence_threshold: 0.6,
    include_metadata: true,
  },
  scope: { project: 'platform-migration' },
});

export const createTestContradictionRequest = (): ContradictionDetectionRequest => ({
  items: [
    {
      id: 'test-item-1',
      kind: 'decision',
      content: 'Decision to migrate to microservices architecture',
      data: {
        title: 'Microservices Migration Decision',
        content:
          'After careful consideration, we decided to migrate our monolithic application to microservices.',
        rationale: 'Improved scalability, team autonomy, and technology flexibility',
        impact: 'High',
        tags: ['architecture', 'migration', 'microservices'],
        created_at: '2025-01-15T10:00:00Z',
      },
      scope: { project: 'platform-migration' },
      created_at: '2025-01-15T10:00:00Z',
    },
    {
      id: 'test-item-2',
      kind: 'issue',
      content: 'System experiencing performance degradation',
      data: {
        title: 'Performance Issues',
        content: 'System is experiencing significant performance degradation and instability.',
        severity: 'high',
        symptoms: ['Slow response times', 'Memory leaks', 'Connection timeouts'],
        tags: ['performance', 'stability', 'production'],
        created_at: '2025-01-16T14:30:00Z',
      },
      scope: { project: 'platform-migration' },
      created_at: '2025-01-16T14:30:00Z',
    },
  ],
  options: {
    enabled: true,
    detection_types: ['semantic', 'temporal', 'logical'],
    confidence_threshold: 0.7,
    include_metadata: true,
  },
  scope: { project: 'platform-migration' },
});

// Performance testing utilities
export const measurePerformance = async (fn: () => Promise<any>) => {
  const start = performance.now();
  const result = await fn();
  const end = performance.now();

  return {
    result,
    durationMs: end - start,
    performance: {
      throughput: 1000 / (end - start),
      latency: end - start,
    },
  };
};

export const createPerformanceBenchmark = (target: any) => {
  return {
    target,
    validate: (actual: number) => ({
      passed: actual <= target.target_time_ms,
      variance: Math.abs(actual - target.target_time_ms),
      withinVariance: Math.abs(actual - target.target_time_ms) <= target.acceptable_variance_ms,
      percentageOfTarget: (actual / target.target_time_ms) * 100,
    }),
  };
};

export { MockZAIClientService as default };
