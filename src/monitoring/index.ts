/**
 * Monitoring Module Index for Cortex MCP
 * Exports all monitoring components and sets up default configuration
 */

export { PerformanceCollector, performanceCollector } from './performance-collector.js';
export { PerformanceMiddleware, performanceMiddleware } from './performance-middleware.js';
export { PerformanceDashboard, performanceDashboard } from './performance-dashboard.js';

export type {
  PerformanceMetric,
  PerformanceSummary,
  PerformanceAlert
} from './performance-collector.js';

export type {
  PerformanceMiddlewareOptions
} from './performance-middleware.js';

export type {
  DashboardConfig
} from './performance-dashboard.js';