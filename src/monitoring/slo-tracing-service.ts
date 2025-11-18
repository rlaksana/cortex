/**
 * SLO Tracing Service
 *
 * Provides distributed tracing for SLO compliance monitoring.
 * Ensures tracing spans exist for MCP entry points, core services, and Qdrant.
 *
 * @version 1.0.0
 * @since 2025-11-14
 */

import { randomUUID } from 'crypto';

import { EventEmitter } from 'events';

// ============================================================================
// Tracing Interfaces
// ============================================================================

export interface TraceSpan {
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  operationName: string;
  startTime: number;
  endTime?: number;
  duration?: number;
  status: SpanStatus;
  tags: Record<string, string | number | boolean>;
  logs: TraceLog[];
  service: string;
  component: string;
  resource?: string;
}

export interface TraceLog {
  timestamp: number;
  level: 'debug' | 'info' | 'warn' | 'error';
  message: string;
  fields?: Record<string, unknown>;
}

export type SpanStatus = 'ok' | 'error' | 'timeout' | 'cancelled' | 'unknown';

export interface TraceContext {
  traceId: string;
  spanId: string;
  baggage?: Record<string, string>;
  sampled?: boolean;
}

export interface TracingConfig {
  serviceName: string;
  samplingRate: number;
  maxSpansPerTrace: number;
  enablePropagation: boolean;
  propagationHeaders: string[];
  spanRetentionHours: number;
}

// ============================================================================
// Operation Categories for SLO Tracing
// ============================================================================

export const TRACING_OPERATIONS = {
  // MCP Entry Points
  MCP_TOOL_EXECUTION: 'mcp.tool.execution',
  MCP_TOOL_VALIDATION: 'mcp.tool.validation',
  MCP_TOOL_RESPONSE: 'mcp.tool.response',

  // Core Services
  MEMORY_STORE: 'memory.store',
  MEMORY_FIND: 'memory.find',
  MEMORY_DELETE: 'memory.delete',
  DEDUPLICATION_CHECK: 'deduplication.check',
  DEDUPLICATION_MERGE: 'deduplication.merge',

  // Qdrant Operations
  QDRANT_SEARCH: 'qdrant.search',
  QDRANT_INSERT: 'qdrant.insert',
  QDRANT_UPDATE: 'qdrant.update',
  QDRANT_DELETE: 'qdrant.delete',
  QDRANT_HEALTH_CHECK: 'qdrant.health_check',

  // AI Services
  EMBEDDING_GENERATION: 'ai.embedding.generation',
  AI_ORCHESTRATION: 'ai.orchestration',
  AI_INFERENCE: 'ai.inference',

  // System Operations
  HTTP_REQUEST: 'http.request',
  DATABASE_CONNECTION: 'db.connection',
  CACHE_ACCESS: 'cache.access',
} as const;

export const COMPONENTS = {
  MCP_SERVER: 'mcp-server',
  MEMORY_STORE: 'memory-store',
  QDRANT_ADAPTER: 'qdrant-adapter',
  AI_ORCHESTRATOR: 'ai-orchestrator',
  DEDUPLICATION_SERVICE: 'deduplication-service',
  HTTP_CLIENT: 'http-client',
} as const;

export const STANDARD_TAGS = {
  SERVICE_NAME: 'service.name',
  COMPONENT: 'component',
  OPERATION_NAME: 'operation.name',
  SPAN_KIND: 'span.kind',
  STATUS_CODE: 'status.code',
  ERROR: 'error',
  HTTP_METHOD: 'http.method',
  HTTP_STATUS_CODE: 'http.status_code',
  HTTP_URL: 'http.url',
  DB_SYSTEM: 'db.system',
  DB_STATEMENT: 'db.statement',
  PEER_SERVICE: 'peer.service',
  PEER_ADDRESS: 'peer.address',
} as const;

// ============================================================================
// SLO Tracing Service
// ============================================================================

export class SLOTracingService extends EventEmitter {
  private config: TracingConfig;
  private activeSpans: Map<string, TraceSpan> = new Map();
  private completedSpans: TraceSpan[] = [];
  private traceContexts: Map<string, TraceContext> = new Map();
  private retentionTimer?: NodeJS.Timeout;

  constructor(config?: Partial<TracingConfig>) {
    super();

    this.config = {
      serviceName: 'cortex-mcp',
      samplingRate: 1.0, // Sample all traces for SLO monitoring
      maxSpansPerTrace: 1000,
      enablePropagation: true,
      propagationHeaders: ['x-trace-id', 'x-span-id', 'x-parent-span-id', 'x-trace-flags'],
      spanRetentionHours: 24,
      ...config,
    };

    this.startRetentionCleanup();
  }

  /**
   * Start a new trace span
   */
  startSpan(
    operationName: string,
    parentContext?: TraceContext,
    tags?: Record<string, string | number | boolean>
  ): TraceSpan {
    const traceId = parentContext?.traceId || this.generateTraceId();
    const spanId = this.generateSpanId();
    const parentSpanId = parentContext?.spanId;

    const span: TraceSpan = {
      traceId,
      spanId,
      parentSpanId,
      operationName,
      startTime: Date.now(),
      status: 'unknown',
      tags: {
        [STANDARD_TAGS.SERVICE_NAME]: this.config.serviceName,
        [STANDARD_TAGS.OPERATION_NAME]: operationName,
        ...tags,
      },
      logs: [],
      service: this.config.serviceName,
      component: this.extractComponentFromOperation(operationName),
    };

    this.activeSpans.set(spanId, span);

    // Store trace context for propagation
    this.traceContexts.set(spanId, {
      traceId,
      spanId,
      sampled: true,
    });

    this.emit('span_started', span);

    return span;
  }

  /**
   * Finish a trace span
   */
  finishSpan(
    spanId: string,
    status: SpanStatus = 'ok',
    finalTags?: Record<string, string | number | boolean>
  ): TraceSpan | null {
    const span = this.activeSpans.get(spanId);
    if (!span) {
      this.emit('span_finish_error', { spanId, error: 'Span not found' });
      return null;
    }

    const endTime = Date.now();
    const duration = endTime - span.startTime;

    // Update span
    span.endTime = endTime;
    span.duration = duration;
    span.status = status;

    if (finalTags) {
      span.tags = { ...span.tags, ...finalTags };
    }

    // Add duration tag
    span.tags['duration.ms'] = duration;
    span.tags[STANDARD_TAGS.STATUS_CODE] = status;

    // Move to completed spans
    this.activeSpans.delete(spanId);
    this.completedSpans.push(span);

    // Clean up trace context
    this.traceContexts.delete(spanId);

    this.emit('span_finished', span);

    return span;
  }

  /**
   * Add a log entry to a span
   */
  logSpanEvent(
    spanId: string,
    level: 'debug' | 'info' | 'warn' | 'error',
    message: string,
    fields?: Record<string, unknown>
  ): void {
    const span = this.activeSpans.get(spanId);
    if (!span) {
      return;
    }

    const log: TraceLog = {
      timestamp: Date.now(),
      level,
      message,
      fields,
    };

    span.logs.push(log);

    this.emit('span_log_added', { spanId, log });
  }

  /**
   * Get current trace context for propagation
   */
  getTraceContext(spanId: string): TraceContext | null {
    return this.traceContexts.get(spanId) || null;
  }

  /**
   * Extract trace context from headers
   */
  extractContextFromHeaders(headers: Record<string, string>): TraceContext | null {
    const traceId = headers['x-trace-id'] || headers['traceparent']?.split('-')[1];
    const spanId = headers['x-span-id'] || headers['traceparent']?.split('-')[2];

    if (!traceId || !spanId) {
      return null;
    }

    return {
      traceId,
      spanId,
      sampled: true,
    };
  }

  /**
   * Inject trace context into headers
   */
  injectContextIntoHeaders(context: TraceContext, headers: Record<string, string>): void {
    headers['x-trace-id'] = context.traceId;
    headers['x-span-id'] = context.spanId;
    headers['x-trace-flags'] = context.sampled ? '1' : '0';
  }

  /**
   * Create a span for MCP tool execution
   */
  startMCPToolSpan(toolName: string, inputSize?: number, parentContext?: TraceContext): TraceSpan {
    return this.startSpan(TRACING_OPERATIONS.MCP_TOOL_EXECUTION, parentContext, {
      [STANDARD_TAGS.COMPONENT]: COMPONENTS.MCP_SERVER,
      'tool.name': toolName,
      'tool.input_size': inputSize || 0,
      'span.kind': 'server',
    });
  }

  /**
   * Create a span for memory store operations
   */
  startMemoryStoreSpan(
    operation: 'store' | 'find' | 'delete',
    memoryId?: string,
    parentContext?: TraceContext
  ): TraceSpan {
    const operationName =
      operation === 'store'
        ? TRACING_OPERATIONS.MEMORY_STORE
        : operation === 'find'
          ? TRACING_OPERATIONS.MEMORY_FIND
          : TRACING_OPERATIONS.MEMORY_DELETE;

    return this.startSpan(operationName, parentContext, {
      [STANDARD_TAGS.COMPONENT]: COMPONENTS.MEMORY_STORE,
      'memory.operation': operation,
      'memory.id': memoryId || 'unknown',
      'span.kind': 'server',
    });
  }

  /**
   * Create a span for Qdrant operations
   */
  startQdrantSpan(
    operation: 'search' | 'insert' | 'update' | 'delete',
    collectionName?: string,
    parentContext?: TraceContext
  ): TraceSpan {
    const operationName =
      operation === 'search'
        ? TRACING_OPERATIONS.QDRANT_SEARCH
        : operation === 'insert'
          ? TRACING_OPERATIONS.QDRANT_INSERT
          : operation === 'update'
            ? TRACING_OPERATIONS.QDRANT_UPDATE
            : TRACING_OPERATIONS.QDRANT_DELETE;

    return this.startSpan(operationName, parentContext, {
      [STANDARD_TAGS.COMPONENT]: COMPONENTS.QDRANT_ADAPTER,
      [STANDARD_TAGS.DB_SYSTEM]: 'qdrant',
      'db.operation': operation,
      'db.collection': collectionName || 'unknown',
      [STANDARD_TAGS.PEER_SERVICE]: 'qdrant',
      'span.kind': 'client',
    });
  }

  /**
   * Create a span for AI operations
   */
  startAIOperationSpan(
    operation: 'embedding' | 'orchestration' | 'inference',
    model?: string,
    parentContext?: TraceContext
  ): TraceSpan {
    const operationName =
      operation === 'embedding'
        ? TRACING_OPERATIONS.EMBEDDING_GENERATION
        : operation === 'orchestration'
          ? TRACING_OPERATIONS.AI_ORCHESTRATION
          : TRACING_OPERATIONS.AI_INFERENCE;

    return this.startSpan(operationName, parentContext, {
      [STANDARD_TAGS.COMPONENT]: COMPONENTS.AI_ORCHESTRATOR,
      'ai.operation': operation,
      'ai.model': model || 'unknown',
      'span.kind': 'client',
    });
  }

  /**
   * Get spans for a specific trace
   */
  getTraceSpans(traceId: string): TraceSpan[] {
    return [
      ...Array.from(this.activeSpans.values()).filter((span) => span.traceId === traceId),
      ...this.completedSpans.filter((span) => span.traceId === traceId),
    ];
  }

  /**
   * Get spans filtered by criteria
   */
  getSpans(filter: {
    service?: string;
    component?: string;
    operationName?: string;
    status?: SpanStatus;
    minDuration?: number;
    maxDuration?: number;
    startTime?: number;
    endTime?: number;
  }): TraceSpan[] {
    const allSpans = [...this.activeSpans.values(), ...this.completedSpans];

    return allSpans.filter((span) => {
      if (filter.service && span.service !== filter.service) return false;
      if (filter.component && span.component !== filter.component) return false;
      if (filter.operationName && span.operationName !== filter.operationName) return false;
      if (filter.status && span.status !== filter.status) return false;
      if (filter.minDuration && (!span.duration || span.duration < filter.minDuration))
        return false;
      if (filter.maxDuration && (!span.duration || span.duration > filter.maxDuration))
        return false;
      if (filter.startTime && span.startTime < filter.startTime) return false;
      if (filter.endTime && span.startTime > filter.endTime) return false;

      return true;
    });
  }

  /**
   * Get SLO metrics from tracing data
   */
  getSLOMetrics(timeWindowMinutes: number = 60): {
    totalRequests: number;
    errorRate: number;
    p95Latency: number;
    p99Latency: number;
    operationBreakdown: Record<
      string,
      {
        count: number;
        errorRate: number;
        avgLatency: number;
      }
    >;
  } {
    const cutoff = Date.now() - timeWindowMinutes * 60 * 1000;
    const relevantSpans = this.completedSpans.filter(
      (span) => span.endTime && span.endTime >= cutoff && span.duration
    );

    if (relevantSpans.length === 0) {
      return {
        totalRequests: 0,
        errorRate: 0,
        p95Latency: 0,
        p99Latency: 0,
        operationBreakdown: {},
      };
    }

    const durations = relevantSpans.map((span) => span.duration!).sort((a, b) => a - b);
    const errorCount = relevantSpans.filter((span) => span.status === 'error').length;

    const p95Index = Math.floor(durations.length * 0.95);
    const p99Index = Math.floor(durations.length * 0.99);

    // Calculate operation breakdown
    const operationBreakdown: Record<
      string,
      {
        count: number;
        errorRate: number;
        avgLatency: number;
      }
    > = {};

    for (const span of relevantSpans) {
      const op = span.operationName;
      if (!operationBreakdown[op]) {
        operationBreakdown[op] = {
          count: 0,
          errorRate: 0,
          avgLatency: 0,
        };
      }

      operationBreakdown[op].count++;
      if (span.status === 'error') {
        operationBreakdown[op].errorRate++;
      }
      if (span.duration) {
        operationBreakdown[op].avgLatency += span.duration;
      }
    }

    // Finalize operation breakdown
    for (const op of Object.keys(operationBreakdown)) {
      const breakdown = operationBreakdown[op];
      breakdown.errorRate = (breakdown.errorRate / breakdown.count) * 100;
      breakdown.avgLatency = breakdown.avgLatency / breakdown.count;
    }

    return {
      totalRequests: relevantSpans.length,
      errorRate: (errorCount / relevantSpans.length) * 100,
      p95Latency: durations[p95Index] || 0,
      p99Latency: durations[p99Index] || 0,
      operationBreakdown,
    };
  }

  /**
   * Export spans in standard format
   */
  exportSpans(format: 'json' | 'jaeger' | 'zipkin' = 'json'): string {
    const allSpans = [...this.activeSpans.values(), ...this.completedSpans];

    switch (format) {
      case 'json':
        return JSON.stringify(
          {
            spans: allSpans,
            timestamp: Date.now(),
            totalCount: allSpans.length,
          },
          null,
          2
        );

      case 'jaeger':
        return this.exportJaegerFormat(allSpans);

      case 'zipkin':
        return this.exportZipkinFormat(allSpans);

      default:
        throw new Error(`Unsupported export format: ${format}`);
    }
  }

  /**
   * Cleanup old spans
   */
  cleanup(): void {
    const cutoff = Date.now() - this.config.spanRetentionHours * 60 * 60 * 1000;

    this.completedSpans = this.completedSpans.filter(
      (span) => (span.endTime || span.startTime) >= cutoff
    );

    this.emit('cleanup_completed', {
      spansRemoved: this.completedSpans.length,
      cutoff,
    });
  }

  /**
   * Get tracing statistics
   */
  getStatistics(): {
    activeSpans: number;
    completedSpans: number;
    totalSpans: number;
    averageSpanDuration: number;
    spanByComponent: Record<string, number>;
    spanByStatus: Record<string, number>;
  } {
    const completedWithDuration = this.completedSpans.filter((span) => span.duration);
    const totalDuration = completedWithDuration.reduce((sum, span) => sum + span.duration!, 0);
    const avgDuration =
      completedWithDuration.length > 0 ? totalDuration / completedWithDuration.length : 0;

    const spanByComponent: Record<string, number> = {};
    const spanByStatus: Record<string, number> = {};

    for (const span of [...this.activeSpans.values(), ...this.completedSpans]) {
      spanByComponent[span.component] = (spanByComponent[span.component] || 0) + 1;
      spanByStatus[span.status] = (spanByStatus[span.status] || 0) + 1;
    }

    return {
      activeSpans: this.activeSpans.size,
      completedSpans: this.completedSpans.length,
      totalSpans: this.activeSpans.size + this.completedSpans.length,
      averageSpanDuration: avgDuration,
      spanByComponent,
      spanByStatus,
    };
  }

  // ============================================================================
  // Private Methods
  // ============================================================================

  private extractComponentFromOperation(operationName: string): string {
    if (operationName.startsWith('mcp.')) return COMPONENTS.MCP_SERVER;
    if (operationName.startsWith('memory.')) return COMPONENTS.MEMORY_STORE;
    if (operationName.startsWith('qdrant.')) return COMPONENTS.QDRANT_ADAPTER;
    if (operationName.startsWith('ai.')) return COMPONENTS.AI_ORCHESTRATOR;
    if (operationName.startsWith('deduplication.')) return COMPONENTS.DEDUPLICATION_SERVICE;
    if (operationName.startsWith('http.')) return COMPONENTS.HTTP_CLIENT;
    return 'unknown';
  }

  private generateTraceId(): string {
    return randomUUID().replace(/-/g, '');
  }

  private generateSpanId(): string {
    return randomUUID().replace(/-/g, '').substring(0, 16);
  }

  private exportJaegerFormat(spans: TraceSpan[]): string {
    // Simplified Jaeger format export
    const jaegerSpans = spans.map((span) => ({
      traceID: span.traceId,
      spanID: span.spanId,
      parentSpanID: span.parentSpanId,
      operationName: span.operationName,
      startTime: span.startTime * 1000, // Microseconds
      duration: (span.duration || 0) * 1000, // Microseconds
      tags: Object.entries(span.tags).map(([key, value]) => ({
        key,
        value: String(value),
        type: typeof value === 'boolean' ? 'bool' : 'string',
      })),
      logs: span.logs.map((log) => ({
        timestamp: log.timestamp * 1000,
        fields: [
          { key: 'level', value: log.level },
          { key: 'message', value: log.message },
          ...(log.fields
            ? Object.entries(log.fields).map(([k, v]) => ({ key: k, value: String(v) }))
            : []),
        ],
      })),
      status: { code: span.status === 'ok' ? 0 : 1 },
    }));

    return JSON.stringify(
      {
        data: [
          {
            traceID: spans[0]?.traceId || '',
            spans: jaegerSpans,
            processID: 'p1',
            processes: {
              p1: {
                serviceName: this.config.serviceName,
                tags: [{ key: 'hostname', value: 'cortex-mcp' }],
              },
            },
          },
        ],
      },
      null,
      2
    );
  }

  private exportZipkinFormat(spans: TraceSpan[]): string {
    // Simplified Zipkin format export
    const zipkinSpans = spans.map((span) => ({
      traceId: span.traceId,
      id: span.spanId,
      parentId: span.parentSpanId,
      name: span.operationName,
      timestamp: span.startTime * 1000, // Microseconds
      duration: span.duration || 0,
      localEndpoint: {
        serviceName: this.config.serviceName,
        ipv4: '127.0.0.1',
      },
      tags: span.tags,
      annotations: span.logs.map((log) => ({
        timestamp: log.timestamp * 1000,
        value: `${log.level}: ${log.message}`,
      })),
    }));

    return JSON.stringify(zipkinSpans, null, 2);
  }

  private startRetentionCleanup(): void {
    // Run cleanup every hour
    this.retentionTimer = setInterval(
      () => {
        this.cleanup();
      },
      60 * 60 * 1000
    );
  }

  /**
   * Graceful shutdown
   */
  async shutdown(): Promise<void> {
    if (this.retentionTimer) {
      clearInterval(this.retentionTimer);
      this.retentionTimer = undefined;
    }

    // Finish all active spans with cancelled status
    for (const [spanId, span] of this.activeSpans.entries()) {
      this.finishSpan(spanId, 'cancelled', { 'shutdown.reason': 'service_shutdown' });
    }

    this.removeAllListeners();
    this.emit('shutdown_complete');
  }
}

// Export singleton instance
export const sloTracingService = new SLOTracingService();
