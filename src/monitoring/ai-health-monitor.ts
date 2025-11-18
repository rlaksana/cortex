// EMERGENCY ROLLBACK: Monitoring system type compatibility issues

/* @file: src/monitoring/ai-health-monitor.ts
 * Clean scaffold after accidental regex corruption.
 * Keep minimal, deterministic shapes; no widening.
 */

// Helpers
export const num = (v: unknown, d = 0): number => Number((v as number | undefined) ?? d);
export const str = (v: unknown, d = ''): string => ((v as string | undefined) ?? d).trim();
export const obj = <T extends object>(v: unknown, d: T): T =>
  v && typeof v === 'object' ? (v as T) : d;

// Status mapping
export type ExternalStatus = 'healthy' | 'degraded' | 'unhealthy' | 'unknown' | string;
export type InternalMapped = 'pass' | 'warn' | 'fail' | 'unknown';
export const toHealthStatus = (s: ExternalStatus): InternalMapped => {
  const k = String(s || 'unknown').toLowerCase();
  if (k === 'healthy') return 'pass';
  if (k === 'degraded') return 'warn';
  if (k === 'unhealthy') return 'fail';
  return 'unknown';
};

// Minimal shapes
export type CircuitBreakerState = 'open' | 'closed' | 'half-open';
export interface PerformanceSnapshot {
  latency: number;
  throughput: number;
  resources: { memory: number };
}
export interface DependencySnapshot {
  status: string;
  details?: Record<string, unknown>;
  lastCheck: Date;
}
export interface OverallHealth {
  status: 'healthy' | 'degraded' | 'unhealthy' | 'unknown';
  timestamp: Date;
  performance: PerformanceSnapshot;
  dependencies: DependencySnapshot;
  circuitBreaker: { status: CircuitBreakerState };
}

// Core API
export function calculateOverallHealth(results: unknown): OverallHealth {
  const resultsObj = obj(results, {} as Record<string, unknown>);
  const performance = obj(resultsObj.performance, {} as Record<string, unknown>);
  const resources = obj(performance.resources, {} as Record<string, unknown>);
  const dependencies = obj(resultsObj.dependencies, {} as Record<string, unknown>);

  return {
    status: str(resultsObj.status, 'unknown') as OverallHealth['status'],
    timestamp: new Date(Date.now()),
    performance: {
      latency: num(performance.latency, 0),
      throughput: num(performance.throughput, 0),
      resources: { memory: num(resources.memory, 0) },
    },
    dependencies: {
      status: str(dependencies.status, 'unknown'),
      details: obj(dependencies.details, {} as Record<string, unknown>),
      lastCheck: new Date(Date.now()),
    },
    circuitBreaker: { status: 'open' },
  };
}

export async function getOverallHealth(source?: unknown): Promise<OverallHealth> {
  const results = source ?? {};
  return calculateOverallHealth(results);
}

// Example sink used elsewhere
export function buildDashboardHealth(results: unknown) {
  const resultsObj = obj(results, {} as Record<string, unknown>);
  return {
    status: toHealthStatus(str(resultsObj.status, 'unknown') as ExternalStatus),
    timestamp: new Date(Date.now()),
  };
}
