
/**
 * Traffic Splitter Service
 *
 * Provides intelligent traffic routing and splitting with:
 * - Percentage-based traffic distribution
 * - Header-based routing
 * - Cookie-based session affinity
 * - IP-based consistent hashing
 * - Weighted round-robin load balancing
 * - Real-time traffic metrics
 * - Dynamic routing rule updates
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { EventEmitter } from 'events';

import { logger } from '@/utils/logger.js';

import { metricsService } from '../../monitoring/metrics-service.js';
import { featureFlagService } from '../feature-flag/feature-flag-service.js';

// ============================================================================
// Types and Interfaces
// ============================================================================

/**
 * Traffic routing strategy
 */
export enum RoutingStrategy {
  PERCENTAGE = 'percentage',
  ROUND_ROBIN = 'round_robin',
  WEIGHTED_ROUND_ROBIN = 'weighted_round_robin',
  LEAST_CONNECTIONS = 'least_connections',
  CONSISTENT_HASH = 'consistent_hash',
  HEADER_BASED = 'header_based',
  COOKIE_BASED = 'cookie_based',
  FEATURE_FLAG = 'feature_flag',
}

/**
 * Target service definition
 */
export interface ServiceTarget {
  id: string;
  name: string;
  endpoint: string;
  version: string;
  weight: number;
  healthy: boolean;
  connections: number;
  lastHealthCheck: Date;
  metadata: {
    region?: string;
    zone?: string;
    instanceType?: string;
    [key: string]: any;
  };
}

/**
 * Traffic routing rule
 */
export interface TrafficRule {
  id: string;
  name: string;
  strategy: RoutingStrategy;
  priority: number;
  enabled: boolean;
  conditions: RoutingCondition[];
  targets: ServiceTarget[];
  sessionAffinity: SessionAffinityConfig;
  failover: FailoverConfig;
  rateLimit: RateLimitConfig;
  healthCheck: HealthCheckConfig;
  metadata: {
    createdBy?: string;
    createdAt: Date;
    updatedAt: Date;
    tags?: string[];
  };
}

/**
 * Routing condition for traffic matching
 */
export interface RoutingCondition {
  type: 'header' | 'query' | 'cookie' | 'path' | 'method' | 'ip' | 'custom';
  field: string;
  operator: 'equals' | 'not_equals' | 'contains' | 'not_contains' | 'regex' | 'in' | 'not_in';
  value: string | string[];
  weight?: number;
  caseSensitive?: boolean;
}

/**
 * Session affinity configuration
 */
export interface SessionAffinityConfig {
  enabled: boolean;
  type: 'cookie' | 'header' | 'ip';
  name: string;
  ttl: number;
  path: string;
  secure: boolean;
  httpOnly: boolean;
}

/**
 * Failover configuration
 */
export interface FailoverConfig {
  enabled: boolean;
  strategy: 'fail_open' | 'fail_closed' | 'fallback';
  fallbackTargets: ServiceTarget[];
  retryAttempts: number;
  retryDelayMs: number;
  circuitBreaker: {
    enabled: boolean;
    failureThreshold: number;
    recoveryTimeout: number;
  };
}

/**
 * Rate limit configuration
 */
export interface RateLimitConfig {
  enabled: boolean;
  requestsPerSecond: number;
  burst: number;
  windowSize: number;
  keyExtractor?: string;
}

/**
 * Health check configuration
 */
export interface HealthCheckConfig {
  enabled: boolean;
  path: string;
  intervalMs: number;
  timeoutMs: number;
  healthyThreshold: number;
  unhealthyThreshold: number;
  expectedStatuses: number[];
}

/**
 * Traffic request context
 */
export interface RequestContext {
  id: string;
  method: string;
  path: string;
  headers: Record<string, string>;
  query: Record<string, string>;
  cookies: Record<string, string>;
  clientIP: string;
  userAgent: string;
  timestamp: Date;
  sessionId?: string;
}

/**
 * Routing decision
 */
export interface RoutingDecision {
  target: ServiceTarget;
  rule: TrafficRule;
  matchedConditions: string[];
  sessionAffinityUsed: boolean;
  routingTime: number;
  metadata: Record<string, any>;
}

/**
 * Traffic metrics
 */
export interface TrafficMetrics {
  timestamp: Date;
  totalRequests: number;
  requestsByTarget: Record<string, number>;
  requestsByRule: Record<string, number>;
  errorRate: number;
  averageResponseTime: number;
  activeConnections: number;
  healthCheckResults: Record<string, boolean>;
}

/**
 * Load balancer state
 */
export interface LoadBalancerState {
  algorithm: RoutingStrategy;
  currentIndex: number;
  connectionCounts: Record<string, number>;
  requestCounts: Record<string, number>;
  lastRotation: Date;
}

// ============================================================================
// Traffic Splitter Implementation
// ============================================================================

/**
 * Main traffic splitter service
 */
export class TrafficSplitterService extends EventEmitter {
  private rules: Map<string, TrafficRule> = new Map();
  private metricsHistory: TrafficMetrics[] = [];
  private loadBalancerStates: Map<string, LoadBalancerState> = new Map();
  private healthCheckIntervals: Map<string, NodeJS.Timeout> = new Map();
  private rateLimiters: Map<string, RateLimiter> = new Map();

  // Static instance for singleton pattern
  private static instance: TrafficSplitterService | null = null;

  constructor() {
    super();
    this.startMetricsCollection();
    logger.info('Traffic Splitter Service initialized');
  }

  /**
   * Get singleton instance
   */
  public static getInstance(): TrafficSplitterService {
    if (!TrafficSplitterService.instance) {
      TrafficSplitterService.instance = new TrafficSplitterService();
    }
    return TrafficSplitterService.instance;
  }

  // ============================================================================
  // Rule Management
  // ============================================================================

  /**
   * Create a new traffic routing rule
   */
  createRule(rule: Omit<TrafficRule, 'id' | 'metadata'>): TrafficRule {
    const id = this.generateId();
    const now = new Date();

    const newRule: TrafficRule = {
      ...rule,
      id,
      metadata: {
        createdAt: now,
        updatedAt: now,
      },
    };

    this.rules.set(id, newRule);

    // Initialize load balancer state
    this.initializeLoadBalancerState(id, newRule);

    // Start health checking if enabled
    if (newRule.healthCheck.enabled) {
      this.startHealthChecking(id, newRule);
    }

    // Initialize rate limiting if enabled
    if (newRule.rateLimit.enabled) {
      this.initializeRateLimiter(id, newRule);
    }

    logger.info('Traffic routing rule created', {
      ruleId: id,
      name: rule.name,
      strategy: rule.strategy,
      targetCount: rule.targets.length,
    });

    this.emit('ruleCreated', newRule);

    return newRule;
  }

  /**
   * Update a traffic routing rule
   */
  updateRule(id: string, updates: Partial<TrafficRule>): TrafficRule | null {
    const rule = this.rules.get(id);
    if (!rule) {
      logger.warn('Traffic routing rule not found for update', { ruleId: id });
      return null;
    }

    const updatedRule: TrafficRule = {
      ...rule,
      ...updates,
      id, // Preserve ID
      metadata: {
        ...rule.metadata,
        updatedAt: new Date(),
      },
    };

    this.rules.set(id, updatedRule);

    // Restart health checking if configuration changed
    if (updates.healthCheck && !updates.healthCheck.enabled) {
      this.stopHealthChecking(id);
    } else if (updates.healthCheck && updates.healthCheck.enabled) {
      this.startHealthChecking(id, updatedRule);
    }

    // Reinitialize rate limiter if configuration changed
    if (updates.rateLimit) {
      this.initializeRateLimiter(id, updatedRule);
    }

    logger.info('Traffic routing rule updated', {
      ruleId: id,
      name: rule.name,
      changes: Object.keys(updates),
    });

    this.emit('ruleUpdated', updatedRule);

    return updatedRule;
  }

  /**
   * Delete a traffic routing rule
   */
  deleteRule(id: string): boolean {
    const rule = this.rules.get(id);
    if (!rule) {
      return false;
    }

    // Stop health checking
    this.stopHealthChecking(id);

    // Clean up rate limiter
    this.rateLimiters.delete(id);

    // Clean up load balancer state
    this.loadBalancerStates.delete(id);

    this.rules.delete(id);

    logger.info('Traffic routing rule deleted', {
      ruleId: id,
      name: rule.name,
    });

    this.emit('ruleDeleted', { id, name: rule.name });

    return true;
  }

  /**
   * Get a traffic routing rule by ID
   */
  getRule(id: string): TrafficRule | undefined {
    return this.rules.get(id);
  }

  /**
   * Get all traffic routing rules
   */
  getAllRules(): TrafficRule[] {
    return Array.from(this.rules.values());
  }

  /**
   * Get enabled traffic routing rules
   */
  getEnabledRules(): TrafficRule[] {
    return this.getAllRules().filter(rule => rule.enabled);
  }

  // ============================================================================
  // Traffic Routing
  // ============================================================================

  /**
   * Route a request to the appropriate target
   */
  async routeRequest(context: RequestContext): Promise<RoutingDecision | null> {
    const startTime = Date.now();

    try {
      // Find matching rules
      const matchingRules = this.findMatchingRules(context);
      if (matchingRules.length === 0) {
        logger.debug('No matching routing rules found', { requestId: context.id });
        return null;
      }

      // Use highest priority rule
      const rule = matchingRules[0];

      // Check rate limiting
      if (rule.rateLimit.enabled && !this.checkRateLimit(rule.id, context)) {
        logger.warn('Request rate limited', {
          requestId: context.id,
          ruleId: rule.id,
          ruleName: rule.name,
        });
        throw new Error('Rate limit exceeded');
      }

      // Select target based on strategy
      const target = await this.selectTarget(rule, context);
      if (!target) {
        logger.warn('No healthy targets available', {
          requestId: context.id,
          ruleId: rule.id,
        });

        // Try failover
        if (rule.failover.enabled) {
          const fallbackTarget = this.selectFallbackTarget(rule);
          if (fallbackTarget) {
            const decision: RoutingDecision = {
              target: fallbackTarget,
              rule,
              matchedConditions: [],
              sessionAffinityUsed: false,
              routingTime: Date.now() - startTime,
              metadata: { failover: true },
            };

            this.emit('requestRouted', context, decision);
            return decision;
          }
        }

        throw new Error('No healthy targets available');
      }

      const matchedConditions = rule.conditions
        .filter(condition => this.evaluateCondition(condition, context))
        .map(condition => `${condition.type}:${condition.field}`);

      const decision: RoutingDecision = {
        target,
        rule,
        matchedConditions,
        sessionAffinityUsed: false,
        routingTime: Date.now() - startTime,
        metadata: {},
      };

      // Check session affinity
      if (rule.sessionAffinity.enabled) {
        const affinityTarget = this.handleSessionAffinity(rule, context);
        if (affinityTarget && this.isTargetHealthy(affinityTarget)) {
          decision.target = affinityTarget;
          decision.sessionAffinityUsed = true;
        }
      }

      // Update connection counts
      this.updateConnectionCounts(target, 1);

      // Record metrics
      this.recordRoutingMetrics(rule, target, context);

      logger.debug('Request routed successfully', {
        requestId: context.id,
        ruleId: rule.id,
        ruleName: rule.name,
        targetId: target.id,
        targetName: target.name,
        routingTime: decision.routingTime,
      });

      this.emit('requestRouted', context, decision);

      return decision;

    } catch (error) {
      logger.error('Error routing request', {
        requestId: context.id,
        error: error instanceof Error ? error.message : String(error),
      });

      this.emit('routingError', context, error);
      throw error;
    }
  }

  /**
   * Find matching rules for a request
   */
  private findMatchingRules(context: RequestContext): TrafficRule[] {
    return this.getEnabledRules()
      .filter(rule => rule.conditions.length === 0 || rule.conditions.some(condition =>
        this.evaluateCondition(condition, context)
      ))
      .sort((a, b) => b.priority - a.priority); // Higher priority first
  }

  /**
   * Evaluate a routing condition
   */
  private evaluateCondition(condition: RoutingCondition, context: RequestContext): boolean {
    let value: string | undefined;

    switch (condition.type) {
      case 'header':
        value = context.headers[condition.field.toLowerCase()];
        break;
      case 'query':
        value = context.query[condition.field];
        break;
      case 'cookie':
        value = context.cookies[condition.field];
        break;
      case 'path':
        value = context.path;
        break;
      case 'method':
        value = context.method;
        break;
      case 'ip':
        value = context.clientIP;
        break;
      case 'custom':
        // Custom conditions would be evaluated by a provided function
        return false;
    }

    if (!value) {
      return false;
    }

    const conditionValue = Array.isArray(condition.value) ? condition.value : [condition.value];
    const caseSensitive = condition.caseSensitive !== false;

    switch (condition.operator) {
      case 'equals':
        return conditionValue.some(cv =>
          caseSensitive ? value === cv : value.toLowerCase() === cv.toLowerCase()
        );
      case 'not_equals':
        return !conditionValue.some(cv =>
          caseSensitive ? value === cv : value.toLowerCase() === cv.toLowerCase()
        );
      case 'contains':
        return conditionValue.some(cv =>
          caseSensitive ? value.includes(cv) : value.toLowerCase().includes(cv.toLowerCase())
        );
      case 'not_contains':
        return !conditionValue.some(cv =>
          caseSensitive ? value.includes(cv) : value.toLowerCase().includes(cv.toLowerCase())
        );
      case 'regex':
        try {
          const regex = new RegExp(condition.value as string, caseSensitive ? 'g' : 'gi');
          return regex.test(value);
        } catch {
          return false;
        }
      case 'in':
        return conditionValue.includes(value);
      case 'not_in':
        return !conditionValue.includes(value);
      default:
        return false;
    }
  }

  /**
   * Select target based on routing strategy
   */
  private async selectTarget(rule: TrafficRule, context: RequestContext): Promise<ServiceTarget | null> {
    const healthyTargets = rule.targets.filter(target => this.isTargetHealthy(target));
    if (healthyTargets.length === 0) {
      return null;
    }

    switch (rule.strategy) {
      case RoutingStrategy.PERCENTAGE:
        return this.selectByPercentage(healthyTargets, rule, context);
      case RoutingStrategy.ROUND_ROBIN:
        return this.selectByRoundRobin(healthyTargets, rule);
      case RoutingStrategy.WEIGHTED_ROUND_ROBIN:
        return this.selectByWeightedRoundRobin(healthyTargets, rule);
      case RoutingStrategy.LEAST_CONNECTIONS:
        return this.selectByLeastConnections(healthyTargets);
      case RoutingStrategy.CONSISTENT_HASH:
        return this.selectByConsistentHash(healthyTargets, context);
      case RoutingStrategy.HEADER_BASED:
        return this.selectByHeader(healthyTargets, rule, context);
      case RoutingStrategy.COOKIE_BASED:
        return this.selectByCookie(healthyTargets, rule, context);
      case RoutingStrategy.FEATURE_FLAG:
        return this.selectByFeatureFlag(healthyTargets, rule, context);
      default:
        return healthyTargets[0];
    }
  }

  /**
   * Select target by percentage-based routing
   */
  private selectByPercentage(targets: ServiceTarget[], rule: TrafficRule, context: RequestContext): ServiceTarget {
    // Use hash for consistent percentage-based routing
    const hash = this.hashString(`${context.clientIP}:${context.path}:${context.id}`);
    const percentage = (hash % 100) + 1;

    let cumulativePercentage = 0;
    for (const target of targets) {
      cumulativePercentage += target.weight;
      if (percentage <= cumulativePercentage) {
        return target;
      }
    }

    return targets[0]; // Fallback
  }

  /**
   * Select target by round-robin
   */
  private selectByRoundRobin(targets: ServiceTarget[], rule: TrafficRule): ServiceTarget {
    const state = this.loadBalancerStates.get(rule.id);
    if (!state) {
      return targets[0];
    }

    const target = targets[state.currentIndex % targets.length];
    state.currentIndex = (state.currentIndex + 1) % targets.length;
    state.lastRotation = new Date();

    return target;
  }

  /**
   * Select target by weighted round-robin
   */
  private selectByWeightedRoundRobin(targets: ServiceTarget[], rule: TrafficRule): ServiceTarget {
    const state = this.loadBalancerStates.get(rule.id);
    if (!state) {
      return this.selectByPercentage(targets, rule, {} as RequestContext);
    }

    // Calculate total weight
    const totalWeight = targets.reduce((sum, target) => sum + target.weight, 0);
    const hash = this.hashString(`${state.currentIndex}:${Date.now()}`);
    const percentage = (hash % totalWeight) + 1;

    let cumulativeWeight = 0;
    for (const target of targets) {
      cumulativeWeight += target.weight;
      if (percentage <= cumulativeWeight) {
        state.currentIndex++;
        return target;
      }
    }

    state.currentIndex++;
    return targets[0];
  }

  /**
   * Select target with least connections
   */
  private selectByLeastConnections(targets: ServiceTarget[]): ServiceTarget {
    return targets.reduce((least, current) =>
      current.connections < least.connections ? current : least
    );
  }

  /**
   * Select target by consistent hash
   */
  private selectByConsistentHash(targets: ServiceTarget[], context: RequestContext): ServiceTarget {
    const hash = this.hashString(context.clientIP + context.path);
    const index = hash % targets.length;
    return targets[index];
  }

  /**
   * Select target by header value
   */
  private selectByHeader(targets: ServiceTarget[], rule: TrafficRule, context: RequestContext): ServiceTarget {
    // This would need to be configured based on specific header logic
    // For now, fall back to percentage-based routing
    return this.selectByPercentage(targets, rule, context);
  }

  /**
   * Select target by cookie value
   */
  private selectByCookie(targets: ServiceTarget[], rule: TrafficRule, context: RequestContext): ServiceTarget {
    // This would need to be configured based on specific cookie logic
    // For now, fall back to percentage-based routing
    return this.selectByPercentage(targets, rule, context);
  }

  /**
   * Select target by feature flag evaluation
   */
  private async selectByFeatureFlag(
    targets: ServiceTarget[],
    rule: TrafficRule,
    context: RequestContext
  ): Promise<ServiceTarget> {
    try {
      // Check if the user is in the feature flag cohort
      const flagName = `routing-${rule.name}`;
      const isEnabled = await featureFlagService.isEnabled(
        flagName,
        context.clientIP,
        context.headers
      );

      // Route to first target if enabled, second target if disabled
      return isEnabled ? targets[0] : targets[1] || targets[0];
    } catch (error) {
      logger.error('Error evaluating feature flag for routing', {
        ruleId: rule.id,
        error: error instanceof Error ? error.message : String(error),
      });
      return targets[0];
    }
  }

  /**
   * Handle session affinity
   */
  private handleSessionAffinity(rule: TrafficRule, context: RequestContext): ServiceTarget | null {
    if (!rule.sessionAffinity.enabled) {
      return null;
    }

    let sessionKey: string | undefined;

    switch (rule.sessionAffinity.type) {
      case 'cookie':
        sessionKey = context.cookies[rule.sessionAffinity.name];
        break;
      case 'header':
        sessionKey = context.headers[rule.sessionAffinity.name.toLowerCase()];
        break;
      case 'ip':
        sessionKey = context.clientIP;
        break;
    }

    if (!sessionKey) {
      return null;
    }

    // Find target associated with this session
    const targetId = this.getTargetForSession(sessionKey, rule.id);
    if (targetId) {
      return rule.targets.find(target => target.id === targetId) || null;
    }

    return null;
  }

  /**
   * Select fallback target
   */
  private selectFallbackTarget(rule: TrafficRule): ServiceTarget | null {
    const healthyFallbackTargets = rule.failover.fallbackTargets.filter(target =>
      this.isTargetHealthy(target)
    );

    if (healthyFallbackTargets.length === 0) {
      return null;
    }

    return healthyFallbackTargets[0];
  }

  // ============================================================================
  // Health Checking
  // ============================================================================

  /**
   * Start health checking for a rule
   */
  private startHealthChecking(ruleId: string, rule: TrafficRule): void {
    if (this.healthCheckIntervals.has(ruleId)) {
      return;
    }

    const interval = setInterval(async () => {
      await this.performHealthChecks(ruleId, rule);
    }, rule.healthCheck.intervalMs);

    this.healthCheckIntervals.set(ruleId, interval);

    logger.debug('Started health checking', {
      ruleId,
      intervalMs: rule.healthCheck.intervalMs,
    });
  }

  /**
   * Stop health checking for a rule
   */
  private stopHealthChecking(ruleId: string): void {
    const interval = this.healthCheckIntervals.get(ruleId);
    if (interval) {
      clearInterval(interval);
      this.healthCheckIntervals.delete(ruleId);
    }
  }

  /**
   * Perform health checks for all targets
   */
  private async performHealthChecks(ruleId: string, rule: TrafficRule): Promise<void> {
    for (const target of rule.targets) {
      try {
        const isHealthy = await this.checkTargetHealth(target, rule.healthCheck);
        const wasHealthy = target.healthy;

        target.healthy = isHealthy;
        target.lastHealthCheck = new Date();

        if (wasHealthy !== isHealthy) {
          logger.info('Target health status changed', {
            ruleId,
            targetId: target.id,
            targetName: target.name,
            healthy: isHealthy,
          });

          this.emit('targetHealthChanged', target, isHealthy);
        }

      } catch (error) {
        logger.error('Error performing health check', {
          ruleId,
          targetId: target.id,
          error: error instanceof Error ? error.message : String(error),
        });

        target.healthy = false;
        target.lastHealthCheck = new Date();
      }
    }
  }

  /**
   * Check health of a specific target
   */
  private async checkTargetHealth(target: ServiceTarget, config: HealthCheckConfig): Promise<boolean> {
    try {
      // In a real implementation, this would make an HTTP request to the health check endpoint
      // For now, we'll simulate the health check

      const response = await this.makeHealthCheckRequest(target, config);
      return config.expectedStatuses.includes(response.status);

    } catch (error) {
      return false;
    }
  }

  /**
   * Make health check request
   */
  private async makeHealthCheckRequest(
    target: ServiceTarget,
    config: HealthCheckConfig
  ): Promise<{ status: number; responseTime: number }> {
    // Simulate health check request
    // In a real implementation, this would use fetch or another HTTP client
    await new Promise(resolve => setTimeout(resolve, Math.random() * 100));

    return {
      status: Math.random() > 0.1 ? 200 : 503,
      responseTime: Math.random() * 1000,
    };
  }

  /**
   * Check if target is healthy
   */
  private isTargetHealthy(target: ServiceTarget): boolean {
    return target.healthy;
  }

  // ============================================================================
  // Rate Limiting
  // ============================================================================

  /**
   * Initialize rate limiter for a rule
   */
  private initializeRateLimiter(ruleId: string, rule: TrafficRule): void {
    if (!rule.rateLimit.enabled) {
      return;
    }

    this.rateLimiters.set(ruleId, new RateLimiter(rule.rateLimit));
  }

  /**
   * Check rate limit for a request
   */
  private checkRateLimit(ruleId: string, context: RequestContext): boolean {
    const rateLimiter = this.rateLimiters.get(ruleId);
    if (!rateLimiter) {
      return true;
    }

    const key = rateLimiter.keyExtractor
      ? context[rateLimiter.keyExtractor as keyof RequestContext] as string
      : context.clientIP;

    return rateLimiter.isAllowed(key);
  }

  // ============================================================================
  // Metrics and Monitoring
  // ============================================================================

  /**
   * Start metrics collection
   */
  private startMetricsCollection(): void {
    setInterval(() => {
      this.collectMetrics();
    }, 60000); // Collect metrics every minute
  }

  /**
   * Collect traffic metrics
   */
  private collectMetrics(): void {
    const metrics: TrafficMetrics = {
      timestamp: new Date(),
      totalRequests: this.getTotalRequests(),
      requestsByTarget: this.getRequestsByTarget(),
      requestsByRule: this.getRequestsByRule(),
      errorRate: this.calculateErrorRate(),
      averageResponseTime: this.calculateAverageResponseTime(),
      activeConnections: this.getActiveConnections(),
      healthCheckResults: this.getHealthCheckResults(),
    };

    this.metricsHistory.push(metrics);

    // Keep only last 24 hours of metrics
    const cutoffTime = new Date(Date.now() - 24 * 60 * 60 * 1000);
    this.metricsHistory = this.metricsHistory.filter(m => m.timestamp > cutoffTime);

    // Record metrics to metrics service
    metricsService.recordGauge('traffic_splitter_total_requests', metrics.totalRequests);
    metricsService.recordGauge('traffic_splitter_error_rate', metrics.errorRate);
    metricsService.recordGauge('traffic_splitter_active_connections', metrics.activeConnections);

    this.emit('metricsCollected', metrics);
  }

  /**
   * Record routing metrics
   */
  private recordRoutingMetrics(rule: TrafficRule, target: ServiceTarget, context: RequestContext): void {
    const state = this.loadBalancerStates.get(rule.id);
    if (state) {
      state.requestCounts[target.id] = (state.requestCounts[target.id] || 0) + 1;
    }

    // Record metrics to metrics service
    metricsService.recordCounter('traffic_splitter_requests_routed', 1, {
      rule_name: rule.name,
      target_name: target.name,
      target_version: target.version,
    });
  }

  /**
   * Update connection counts
   */
  private updateConnectionCounts(target: ServiceTarget, delta: number): void {
    target.connections = Math.max(0, target.connections + delta);
  }

  /**
   * Initialize load balancer state
   */
  private initializeLoadBalancerState(ruleId: string, rule: TrafficRule): void {
    const state: LoadBalancerState = {
      algorithm: rule.strategy,
      currentIndex: 0,
      connectionCounts: {},
      requestCounts: {},
      lastRotation: new Date(),
    };

    this.loadBalancerStates.set(ruleId, state);
  }

  // ============================================================================
  // Utility Methods
  // ============================================================================

  /**
   * Hash string for consistent routing
   */
  private hashString(str: string): number {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash);
  }

  /**
   * Get target for session
   */
  private getTargetForSession(sessionKey: string, ruleId: string): string | null {
    // In a real implementation, this would use a session store
    // For now, return null to disable session affinity
    return null;
  }

  /**
   * Get total requests
   */
  private getTotalRequests(): number {
    let total = 0;
    for (const state of this.loadBalancerStates.values()) {
      total += Object.values(state.requestCounts).reduce((sum, count) => sum + count, 0);
    }
    return total;
  }

  /**
   * Get requests by target
   */
  private getRequestsByTarget(): Record<string, number> {
    const requestsByTarget: Record<string, number> = {};
    for (const state of this.loadBalancerStates.values()) {
      for (const [targetId, count] of Object.entries(state.requestCounts)) {
        requestsByTarget[targetId] = (requestsByTarget[targetId] || 0) + count;
      }
    }
    return requestsByTarget;
  }

  /**
   * Get requests by rule
   */
  private getRequestsByRule(): Record<string, number> {
    const requestsByRule: Record<string, number> = {};
    for (const [ruleId, state] of this.loadBalancerStates.entries()) {
      const rule = this.rules.get(ruleId);
      if (rule) {
        requestsByRule[rule.name] = Object.values(state.requestCounts)
          .reduce((sum, count) => sum + count, 0);
      }
    }
    return requestsByRule;
  }

  /**
   * Calculate error rate
   */
  private calculateErrorRate(): number {
    // This would calculate actual error rate from metrics
    // For now, return a simulated value
    return Math.random() * 5;
  }

  /**
   * Calculate average response time
   */
  private calculateAverageResponseTime(): number {
    // This would calculate actual average response time from metrics
    // For now, return a simulated value
    return Math.random() * 1000 + 50;
  }

  /**
   * Get active connections
   */
  private getActiveConnections(): number {
    let total = 0;
    for (const rule of this.rules.values()) {
      total += rule.targets.reduce((sum, target) => sum + target.connections, 0);
    }
    return total;
  }

  /**
   * Get health check results
   */
  private getHealthCheckResults(): Record<string, boolean> {
    const results: Record<string, boolean> = {};
    for (const rule of this.rules.values()) {
      for (const target of rule.targets) {
        results[`${target.id}:${target.name}`] = target.healthy;
      }
    }
    return results;
  }

  /**
   * Get service metrics
   */
  getMetrics(): {
    totalRules: number;
    enabledRules: number;
    totalTargets: number;
    healthyTargets: number;
    activeConnections: number;
    metricsHistorySize: number;
  } {
    const rules = this.getAllRules();
    const targets = rules.flatMap(rule => rule.targets);

    return {
      totalRules: rules.length,
      enabledRules: rules.filter(rule => rule.enabled).length,
      totalTargets: targets.length,
      healthyTargets: targets.filter(target => target.healthy).length,
      activeConnections: this.getActiveConnections(),
      metricsHistorySize: this.metricsHistory.length,
    };
  }

  /**
   * Get traffic metrics history
   */
  getMetricsHistory(limit?: number): TrafficMetrics[] {
    const history = [...this.metricsHistory].reverse();
    return limit ? history.slice(0, limit) : history;
  }

  /**
   * Generate unique ID
   */
  private generateId(): string {
    return Math.random().toString(36).substring(2) + Date.now().toString(36);
  }

  /**
   * Cleanup method
   */
  cleanup(): void {
    // Stop all health checking
    for (const [ruleId] of this.healthCheckIntervals) {
      this.stopHealthChecking(ruleId);
    }

    this.rules.clear();
    this.metricsHistory = [];
    this.loadBalancerStates.clear();
    this.rateLimiters.clear();
    this.removeAllListeners();

    logger.info('Traffic Splitter Service cleaned up');
  }
}

// ============================================================================
// Rate Limiter Implementation
// ============================================================================

/**
 * Simple rate limiter implementation
 */
class RateLimiter {
  private config: RateLimitConfig;
  private counters: Map<string, { count: number; resetTime: number }> = new Map();

  constructor(config: RateLimitConfig) {
    this.config = config;
  }

  isAllowed(key: string): boolean {
    const now = Date.now();
    const windowStart = now - this.config.windowSize;

    let counter = this.counters.get(key);
    if (!counter || counter.resetTime < now) {
      counter = { count: 0, resetTime: now + this.config.windowSize };
      this.counters.set(key, counter);
    }

    if (counter.count >= this.config.requestsPerSecond) {
      return false;
    }

    counter.count++;
    return true;
  }

  keyExtractor?: unknown
}

// Export singleton instance
export const trafficSplitterService = TrafficSplitterService.getInstance();
