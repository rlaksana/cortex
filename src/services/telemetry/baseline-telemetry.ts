/**
 * Minimal baseline telemetry for 1-day observation
 * Tracks only the essential pain points before fixes
 */

export interface BaselineStoreLog {
  timestamp: string;
  truncated: boolean;
  original_length: number;
  final_length: number;
  kind: string;
  scope: string;
}

export interface BaselineFindLog {
  timestamp: string;
  query_text: string;
  scope: string;
  returned_count: number;
  top_score: number;
  strategy: string;
}

export class BaselineTelemetry {
  private storeLogs: BaselineStoreLog[] = [];
  private findLogs: BaselineFindLog[] = [];

  logStoreAttempt(
    truncated: boolean,
    originalLength: number,
    finalLength: number,
    kind: string,
    scope: string
  ): void {
    this.storeLogs.push({
      timestamp: new Date().toISOString(),
      truncated,
      original_length: originalLength,
      final_length: finalLength,
      kind,
      scope
    });
  }

  logFindAttempt(
    queryText: string,
    scope: string,
    returnedCount: number,
    topScore: number,
    strategy: string
  ): void {
    this.findLogs.push({
      timestamp: new Date().toISOString(),
      query_text: queryText,
      scope,
      returned_count: returnedCount,
      top_score: topScore,
      strategy
    });
  }

  getStoreMetrics(): {
    total_stores: number;
    truncated_stores: number;
    truncation_ratio: number;
    avg_truncated_loss: number;
  } {
    const total = this.storeLogs.length;
    const truncated = this.storeLogs.filter(log => log.truncated).length;
    const truncation_ratio = total > 0 ? truncated / total : 0;

    const truncatedLogs = this.storeLogs.filter(log => log.truncated);
    const avg_truncated_loss = truncatedLogs.length > 0
      ? truncatedLogs.reduce((sum, log) => sum + (log.original_length - log.final_length), 0) / truncatedLogs.length
      : 0;

    return {
      total_stores: total,
      truncated_stores: truncated,
      truncation_ratio,
      avg_truncated_loss
    };
  }

  getFindMetrics(): {
    total_queries: number;
    zero_result_queries: number;
    zero_result_ratio: number;
    avg_returned_count: number;
    avg_top_score: number;
  } {
    const total = this.findLogs.length;
    const zeroResults = this.findLogs.filter(log => log.returned_count === 0).length;
    const zero_result_ratio = total > 0 ? zeroResults / total : 0;

    const avg_returned_count = total > 0
      ? this.findLogs.reduce((sum, log) => sum + log.returned_count, 0) / total
      : 0;

    const avg_top_score = total > 0
      ? this.findLogs.reduce((sum, log) => sum + log.top_score, 0) / total
      : 0;

    return {
      total_queries: total,
      zero_result_queries: zeroResults,
      zero_result_ratio,
      avg_returned_count,
      avg_top_score
    };
  }

  getScopeAnalysis(): {
    [scope: string]: {
      stores: number;
      queries: number;
      zero_results: number;
      avg_score: number;
    };
  } {
    const scopeStats: Record<string, {
      stores: number;
      queries: number;
      zero_results: number;
      total_score: number;
    }> = {};

    // Store stats by scope
    for (const log of this.storeLogs) {
      if (!scopeStats[log.scope]) {
        scopeStats[log.scope] = { stores: 0, queries: 0, zero_results: 0, total_score: 0 };
      }
      scopeStats[log.scope].stores++;
    }

    // Query stats by scope
    for (const log of this.findLogs) {
      if (!scopeStats[log.scope]) {
        scopeStats[log.scope] = { stores: 0, queries: 0, zero_results: 0, total_score: 0 };
      }
      scopeStats[log.scope].queries++;
      if (log.returned_count === 0) {
        scopeStats[log.scope].zero_results++;
      }
      scopeStats[log.scope].total_score += log.top_score;
    }

    // Calculate averages
    const result: { [scope: string]: any } = {};
    for (const [scope, stats] of Object.entries(scopeStats)) {
      result[scope] = {
        stores: stats.stores,
        queries: stats.queries,
        zero_results: stats.zero_results,
        avg_score: stats.queries > 0 ? stats.total_score / stats.queries : 0
      };
    }

    return result;
  }

  // Export logs for analysis
  exportLogs(): {
    store_logs: BaselineStoreLog[];
    find_logs: BaselineFindLog[];
    summary: {
      store: ReturnType<BaselineTelemetry['getStoreMetrics']>;
      find: ReturnType<BaselineTelemetry['getFindMetrics']>;
      scope_analysis: ReturnType<BaselineTelemetry['getScopeAnalysis']>;
    };
  } {
    return {
      store_logs: [...this.storeLogs],
      find_logs: [...this.findLogs],
      summary: {
        store: this.getStoreMetrics(),
        find: this.getFindMetrics(),
        scope_analysis: this.getScopeAnalysis()
      }
    };
  }

  reset(): void {
    this.storeLogs = [];
    this.findLogs = [];
  }
}