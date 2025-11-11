/**
 * Benchmark Framework Types
 *
 * Type definitions for the Cortex Memory MCP benchmark framework
 */

export interface BenchmarkConfig {
  /** Benchmark suite name */
  name: string;
  /** Version identifier */
  version: string;
  /** Output directory for reports */
  outputDir: string;
  /** Number of warmup iterations */
  warmupIterations: number;
  /** Number of benchmark iterations */
  benchmarkIterations: number;
  /** Delay between scenarios (ms) */
  scenarioDelay?: number;
  /** Enable memory profiling */
  enableMemoryProfiling?: boolean;
  /** Enable CPU profiling */
  enableCPUProfiling?: boolean;
  /** Maximum test duration (ms) */
  maxDuration?: number;
}

export interface BenchmarkScenario {
  /** Scenario name */
  name: string;
  /** Scenario description */
  description: string;
  /** Execution function */
  execute: (config: LoadTestConfig) => Promise<any>;
  /** Load test configuration */
  config: LoadTestConfig;
  /** Tags for categorization */
  tags?: string[];
}

export interface LoadTestConfig {
  /** Number of concurrent operations */
  concurrency: number;
  /** Number of operations to execute */
  operations: number;
  /** Delay between operations (ms) */
  operationDelay?: number;
  /** Ramp-up time (ms) */
  rampUpTime?: number;
  /** Test data configuration */
  dataConfig?: TestDataConfig;
  /** Custom parameters */
  parameters?: Record<string, any>;
}

export interface TestDataConfig {
  /** Number of test items to generate */
  itemCount: number;
  /** Average item size (bytes) */
  averageItemSize: number;
  /** Item size variance (percentage) */
  sizeVariance?: number;
  /** Data type distribution */
  typeDistribution?: Record<string, number>;
  /** Use existing dataset */
  useExisting?: boolean;
  /** Dataset file path */
  datasetPath?: string;
}

export interface BenchmarkResult {
  /** Scenario name */
  scenario: string;
  /** Scenario description */
  description: string;
  /** Individual iteration results */
  iterations: IterationResult[];
  /** Summary statistics */
  summary: SummaryStats;
  /** Performance metrics */
  metrics: PerformanceMetrics;
  /** Configuration used */
  config: LoadTestConfig;
  /** Result timestamp */
  timestamp: string;
}

export interface IterationResult {
  /** Iteration number */
  iteration: number;
  /** Duration in milliseconds */
  duration: number;
  /** Success status */
  success: boolean;
  /** Error message (if failed) */
  error: string | null;
  /** Memory usage information */
  memoryUsage: MemoryUsageInfo;
  /** Custom result data */
  result: any;
}

export interface MemoryUsageInfo {
  /** Memory at start */
  start: NodeJS.MemoryUsage;
  /** Memory at end */
  end: NodeJS.MemoryUsage;
  /** Memory delta */
  delta: {
    rss: number;
    heapUsed: number;
    heapTotal: number;
    external: number;
  };
}

export interface SummaryStats {
  /** Total operations executed */
  totalOperations: number;
  /** Total duration (ms) */
  totalDuration: number;
  /** Number of errors */
  errors: number;
  /** Average duration (ms) */
  averageDuration: number;
  /** Success rate percentage */
  successRate: number;
  /** Throughput (operations per second) */
  throughput: number;
}

export interface PerformanceMetrics {
  /** Latency percentiles */
  latencies: LatencyMetrics;
  /** Throughput metrics */
  throughput: number;
  /** Error rate percentage */
  errorRate: number;
  /** Memory usage metrics */
  memoryUsage: MemoryMetrics;
}

export interface LatencyMetrics {
  /** 50th percentile */
  p50: number;
  /** 95th percentile */
  p95: number;
  /** 99th percentile */
  p99: number;
  /** Minimum latency */
  min: number;
  /** Maximum latency */
  max: number;
}

export interface MemoryMetrics {
  /** Peak memory usage (bytes) */
  peak: number;
  /** Average memory usage (bytes) */
  average: number;
}

export interface BenchmarkReport {
  /** Report metadata */
  metadata: ReportMetadata;
  /** Benchmark results */
  results: BenchmarkResult[];
  /** Summary analysis */
  analysis: ReportAnalysis;
}

export interface ReportMetadata {
  /** Report name */
  name: string;
  /** Version */
  version: string;
  /** Generation timestamp */
  timestamp: string;
  /** Total duration (seconds) */
  totalDuration: number;
  /** Environment information */
  environment: EnvironmentInfo;
}

export interface EnvironmentInfo {
  /** Node.js version */
  nodeVersion: string;
  /** Operating system platform */
  platform: string;
  /** System architecture */
  arch: string;
  /** Memory information */
  memory: NodeJS.MemoryUsage;
  /** CPU information */
  cpu?: {
    model: string;
    speed: number;
    cores: number;
  };
}

export interface ReportAnalysis {
  /** Performance summary */
  performanceSummary: PerformanceSummary;
  /** SLA compliance */
  slaCompliance: SLACompliance;
  /** Recommendations */
  recommendations: string[];
  /** Trend analysis */
  trends?: TrendAnalysis;
}

export interface PerformanceSummary {
  /** Best performing scenario */
  bestScenario: {
    name: string;
    metric: string;
    value: number;
  };
  /** Worst performing scenario */
  worstScenario: {
    name: string;
    metric: string;
    value: number;
  };
  /** Overall averages */
  averages: {
    p50: number;
    p95: number;
    p99: number;
    throughput: number;
    errorRate: number;
  };
}

export interface SLACompliance {
  /** Overall compliance percentage */
  overallCompliance: number;
  /** Individual SLA results */
  slaResults: SLAResult[];
}

export interface SLAResult {
  /** SLA name */
  name: string;
  /** Target value */
  target: number;
  /** Actual value */
  actual: number;
  /** Compliance status */
  compliant: boolean;
  /** Deviation percentage */
  deviation: number;
}

export interface TrendAnalysis {
  /** Performance trends over time */
  performanceTrends: {
    scenario: string;
    metric: string;
    trend: 'improving' | 'degrading' | 'stable';
    changePercentage: number;
  }[];
  /** Capacity projections */
  capacityProjections: {
    metric: string;
    projectedGrowth: number;
    timeToLimit: string;
  }[];
}

export interface DataGeneratorConfig {
  /** Number of items to generate */
  itemCount: number;
  /** Types of items to generate */
  itemTypes: string[];
  /** Size distribution */
  sizeDistribution: {
    min: number;
    max: number;
    average: number;
  };
  /** Content patterns */
  contentPatterns?: string[];
  /** Relationship density */
  relationshipDensity?: number;
  /** Embedding dimensions */
  embeddingDimensions?: number;
}

export interface TestDataset {
  /** Dataset metadata */
  metadata: {
    name: string;
    version: string;
    created: string;
    itemCount: number;
    totalSize: number;
  };
  /** Test items */
  items: TestItem[];
  /** Relationships between items */
  relationships: TestRelationship[];
}

export interface TestItem {
  /** Item ID */
  id: string;
  /** Item type */
  type: string;
  /** Item content */
  content: string;
  /** Item size (bytes) */
  size: number;
  /** Creation timestamp */
  created: string;
  /** Tags */
  tags?: string[];
  /** Custom metadata */
  metadata?: Record<string, any>;
}

export interface TestRelationship {
  /** Source item ID */
  source: string;
  /** Target item ID */
  target: string;
  /** Relationship type */
  type: string;
  /** Relationship weight */
  weight?: number;
  /** Creation timestamp */
  created: string;
}

export interface BenchmarkComparison {
  /** Comparison metadata */
  metadata: {
    baseline: string;
    comparison: string;
    timestamp: string;
  };
  /** Performance changes */
  changes: PerformanceChange[];
  /** Summary */
  summary: {
    overallChange: 'improved' | 'degraded' | 'unchanged';
    significantChanges: number;
    recommendations: string[];
  };
}

export interface PerformanceChange {
  /** Scenario name */
  scenario: string;
  /** Metric name */
  metric: string;
  /** Baseline value */
  baseline: number;
  /** Comparison value */
  comparison: number;
  /** Percentage change */
  changePercentage: number;
  /** Significance level */
  significance: 'significant' | 'minor' | 'negligible';
  /** Trend direction */
  trend: 'improvement' | 'degradation' | 'unchanged';
}
