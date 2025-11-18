// EMERGENCY ROLLBACK: Monitoring system type compatibility issues

/**
 * Alert Rules Engine for MCP Cortex
 *
 * Supports:
 * - evaluation of one or multiple rules against system health
 * - threshold checks with hysteresis
 * - noisy signal filtering and debouncing
 */

export interface HysteresisConfig {
  threshold: number;
  delayMs?: number;
  rising?: boolean;
}

export interface RuleEvaluationOptions {
  allowPartialEval?: boolean;
  bypassCooldown?: boolean;
  hysteresis?: HysteresisConfig;
}

/**
 * Evaluates a rule condition against a metric.
 *
 * Supports 'gt' | 'lt' | 'eq' | 'ne' | 'gte' | 'lte' | 'in' | 'not_in' operators.
 * Performs numeric or string coercion for equality comparisons.
 */
export function evaluateCondition(value: number, operator: string, threshold: number): boolean;
export function evaluateCondition(
  value: unknown,
  operator: 'gt' | 'lt' | 'eq' | 'ne' | 'gte' | 'lte' | 'in' | 'not_in',
  threshold: unknown
): boolean;
export function evaluateCondition(value: unknown, operator: string, threshold: unknown): boolean {
  try {
    if (operator === 'gt') return Number(value) > Number(threshold);
    if (operator === 'lt') return Number(value) < Number(threshold);
    if (operator === 'gte') return Number(value) >= Number(threshold);
    if (operator === 'lte') return Number(value) <= Number(threshold);
    if (operator === 'eq') {
      // numeric eq
      const nv = Number(value);
      const nt = Number(threshold);
      if (!Number.isNaN(nv) && !Number.isNaN(nt)) return nv === nt;
      return String(value) === String(threshold);
    }
    if (operator === 'ne') {
      const nv = Number(value);
      const nt = Number(threshold);
      if (!Number.isNaN(nv) && !Number.isNaN(nt)) return nv !== nt;
      return String(value) !== String(threshold);
    }
    if (operator === 'in') {
      const list = Array.isArray(threshold) ? threshold : [threshold];
      return list.some((v) => evaluateCondition(value, 'eq', v));
    }
    if (operator === 'not_in') {
      const list = Array.isArray(threshold) ? threshold : [threshold];
      return list.every((v) => !evaluateCondition(value, 'eq', v));
    }
    return false;
  } catch {
    return false;
  }
}

/**
 * Applies hysteresis to a rule evaluation to reduce flickering alerts.
 * Returns true only if the metric remains beyond the threshold for the configured delay.
 */
export async function withHysteresis(
  metricFetcher: () => Promise<number>,
  config: HysteresisConfig
): Promise<boolean> {
  const start = Date.now();
  // Simple implementation: wait until threshold is crossed for delayMs

  while (Date.now() - start < (config.delayMs ?? 0)) {
    try {
      const v = await metricFetcher();
      const test = config.rising ? v > config.threshold : v < config.threshold;
      if (!test) return false;
      await new Promise((r) => setTimeout(r, 100));
    } catch {
      return false;
    }
  }
  return true;
}

/**
 * Filters noisy signals by debouncing triggers over a sliding window.
 */
export async function debounceSignal<T>(
  signal: () => Promise<T>,
  windowMs: number,
  predicate: (v: T) => boolean
): Promise<boolean> {
  const start = Date.now();
  let ok = true;

  while (Date.now() - start < windowMs) {
    try {
      const v = await signal();
      if (!predicate(v)) {
        ok = false;
        break;
      }
      await new Promise((r) => setTimeout(r, 100));
    } catch {
      ok = false;
      break;
    }
  }
  return ok;
}
