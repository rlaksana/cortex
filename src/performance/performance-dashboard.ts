// ULTIMATE FINAL EMERGENCY ROLLBACK: Remaining systematic type issues

/**
 * Performance Dashboard
 *
 * Web-based performance dashboard for visualizing performance metrics,
 * trends, and regression analysis with interactive charts and reports
 */

import { mkdirSync, writeFileSync } from 'fs';
import { join } from 'path';

import type { PerformanceRegression, PerformanceTestResult } from './performance-harness.js';

export interface DataPoint {
  value: number;
  timestamp?: number;
  label?: string;
}

export interface DashboardConfig {
  /** Dashboard title */
  title: string;
  /** Base directory for dashboard files */
  outputDir: string;
  /** Dashboard URL path */
  basePath: string;
  /** Refresh interval (seconds) */
  refreshInterval: number;
  /** Maximum number of results to display */
  maxResults: number;
  /** Enable real-time updates */
  enableRealTime: boolean;
  /** Theme configuration */
  theme: 'light' | 'dark' | 'auto';
  /** Chart configuration */
  charts: {
    defaultType: 'line' | 'bar';
    colors: string[];
    animationDuration: number;
  };
}

export interface DashboardData {
  /** Metadata */
  metadata: {
    generated: string;
    version: string;
    totalTests: number;
    totalResults: number;
  };
  /** Test results */
  results: PerformanceTestResult[];
  /** Performance regressions */
  regressions: PerformanceRegression[];
  /** Performance trends */
  trends: PerformanceTrend[];
  /** System metrics */
  systemMetrics: SystemMetricData[];
}

export interface PerformanceTrend {
  /** Test name */
  testName: string;
  /** Metric name */
  metric: string;
  /** Trend data points */
  dataPoints: Array<{
    timestamp: string;
    value: number;
    testId: string;
  }>;
  /** Trend direction */
  direction: 'improving' | 'degrading' | 'stable';
  /** Trend strength */
  strength: number;
}

export interface SystemMetricData {
  /** Timestamp */
  timestamp: string;
  /** CPU usage */
  cpu: number;
  /** Memory usage */
  memory: {
    used: number;
    total: number;
    percentage: number;
  };
  /** Disk usage */
  disk: {
    used: number;
    total: number;
    percentage: number;
  };
}

export class PerformanceDashboard {
  private config: DashboardConfig;

  constructor(config?: Partial<DashboardConfig>) {
    this.config = {
      title: 'Cortex Memory MCP Performance Dashboard',
      outputDir: './artifacts/performance/dashboard',
      basePath: '/performance-dashboard',
      refreshInterval: 60,
      maxResults: 100,
      enableRealTime: false,
      theme: 'light',
      charts: {
        defaultType: 'line',
        colors: ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#06b6d4'],
        animationDuration: 750,
      },
      ...config,
    };

    this.ensureDirectories();
  }

  /**
   * Generate complete dashboard
   */
  async generateDashboard(results: PerformanceTestResult[]): Promise<void> {
    console.log('🎨 Generating Performance Dashboard...');

    // Prepare dashboard data
    const dashboardData = this.prepareDashboardData(results);

    // Generate HTML dashboard
    await this.generateHTMLDashboard(dashboardData);

    // Generate API endpoints for data
    await this.generateDataAPI(dashboardData);

    // Generate assets
    await this.generateAssets();

    console.log('✅ Dashboard generated successfully');
    console.log(`📁 Dashboard location: ${this.config.outputDir}/index.html`);
  }

  /**
   * Prepare dashboard data
   */
  private prepareDashboardData(results: PerformanceTestResult[]): DashboardData {
    const recentResults = results.slice(-this.config.maxResults);
    const trends = this.calculateTrends(recentResults);
    const systemMetrics = this.extractSystemMetrics(recentResults);

    return {
      metadata: {
        generated: new Date().toISOString(),
        version: '2.0.1',
        totalTests: new Set(results.map((r) => r.config.name)).size,
        totalResults: results.length,
      },
      results: recentResults,
      regressions: [], // Would be calculated from regression analysis
      trends,
      systemMetrics,
    };
  }

  /**
   * Calculate performance trends
   */
  private calculateTrends(results: PerformanceTestResult[]): PerformanceTrend[] {
    const trends: PerformanceTrend[] = [];
    const testGroups = new Map<string, PerformanceTestResult[]>();

    // Group results by test name
    for (const result of results) {
      if (!testGroups.has(result.config.name)) {
        testGroups.set(result.config.name, []);
      }
      testGroups.get(result.config.name)!.push(result);
    }

    // Calculate trends for each test and metric
    const metrics = ['p50_latency', 'p95_latency', 'p99_latency', 'throughput', 'error_rate'];

    for (const [testName, testResults] of Array.from(testGroups.entries())) {
      for (const metric of metrics) {
        const trend = this.calculateMetricTrend(testName, metric, testResults);
        if (trend) {
          trends.push(trend);
        }
      }
    }

    return trends;
  }

  /**
   * Calculate trend for specific metric
   */
  private calculateMetricTrend(
    testName: string,
    metric: string,
    results: PerformanceTestResult[]
  ): PerformanceTrend | null {
    if (results.length < 3) return null; // Need at least 3 data points for trend

    const metricDataPoints = results
      .map((result) => {
        let value: number;

        switch (metric) {
          case 'p50_latency':
            value = result.results.metrics.latencies.p50;
            break;
          case 'p95_latency':
            value = result.results.metrics.latencies.p95;
            break;
          case 'p99_latency':
            value = result.results.metrics.latencies.p99;
            break;
          case 'throughput':
            value = result.results.metrics.throughput;
            break;
          case 'error_rate':
            value = result.results.metrics.errorRate;
            break;
          default:
            return null;
        }

        return {
          timestamp: result.metadata.timestamp,
          value,
          testId: result.metadata.testId,
        };
      })
      .filter((point) => point !== null);

    if (metricDataPoints.length < 3) return null;

    // Convert to DataPoint format for trend calculation
    const dataPoints: DataPoint[] = metricDataPoints.map(point => ({
      value: point.value,
      timestamp: Date.parse(point.timestamp),
      label: point.testId
    }));

    // Calculate trend direction using linear regression
    const direction = this.calculateTrendDirection(dataPoints);
    const strength = this.calculateTrendStrength(dataPoints);

    return {
      testName,
      metric,
      dataPoints: metricDataPoints,
      direction,
      strength,
    };
  }

  /**
   * Calculate trend direction
   */
  private calculateTrendDirection(dataPoints: DataPoint[]): 'improving' | 'degrading' | 'stable' {
    const n = dataPoints.length;
    if (n < 2) return 'stable';

    const sumX = dataPoints.reduce((sum, _, i) => sum + i, 0);
    const sumY = dataPoints.reduce((sum, point) => sum + point.value, 0);
    const sumXY = dataPoints.reduce((sum, point, i) => sum + i * point.value, 0);
    const sumXX = dataPoints.reduce((sum, _, i) => sum + i * i, 0);

    const slope = (n * sumXY - sumX * sumY) / (n * sumXX - sumX * sumX);

    if (Math.abs(slope) < 0.01) return 'stable';
    return slope > 0 ? 'degrading' : 'improving'; // Note: lower values are better for latency
  }

  /**
   * Calculate trend strength
   */
  private calculateTrendStrength(dataPoints: DataPoint[]): number {
    const values = dataPoints.map((p) => p.value);
    const mean = values.reduce((sum, v) => sum + v, 0) / values.length;
    const variance = values.reduce((sum, v) => sum + Math.pow(v - mean, 2), 0) / values.length;
    const stdDev = Math.sqrt(variance);

    // Calculate coefficient of variation
    const cv = stdDev / mean;

    // Convert to strength (0-1, where 1 is strong trend)
    return Math.min(1, cv / 0.5);
  }

  /**
   * Extract system metrics from results
   */
  private extractSystemMetrics(results: PerformanceTestResult[]): SystemMetricData[] {
    return results.map((result) => ({
      timestamp: result.metadata.timestamp,
      cpu: 0, // Would be extracted from system monitoring
      memory: {
        used: result.metadata.systemMetrics.peakMemoryUsage,
        total: 2 * 1024 * 1024 * 1024, // 2GB assumed total
        percentage:
          (result.metadata.systemMetrics.peakMemoryUsage / (2 * 1024 * 1024 * 1024)) * 100,
      },
      disk: {
        used: 0, // Would be extracted from system monitoring
        total: 0,
        percentage: 0,
      },
    }));
  }

  /**
   * Generate HTML dashboard
   */
  private async generateHTMLDashboard(data: DashboardData): Promise<void> {
    const htmlContent = this.generateDashboardHTML(data);
    const indexPath = join(this.config.outputDir, 'index.html');
    writeFileSync(indexPath, htmlContent);
  }

  /**
   * Generate dashboard HTML
   */
  private generateDashboardHTML(data: DashboardData): string {
    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${this.config.title}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        .chart-container {
            position: relative;
            height: 300px;
            width: 100%;
        }
        .metric-card {
            transition: all 0.3s ease;
        }
        .metric-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1);
        }
        .status-passed { color: #10b981; }
        .status-failed { color: #ef4444; }
        .status-warning { color: #f59e0b; }
        .trend-improving { color: #10b981; }
        .trend-degrading { color: #ef4444; }
        .trend-stable { color: #6b7280; }
        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid #f3f3f3;
            border-top: 3px solid #3b82f6;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    </style>
</head>
<body class="bg-gray-50 min-h-screen">
    <!-- Header -->
    <header class="bg-white shadow-sm border-b">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex justify-between items-center py-4">
                <div class="flex items-center">
                    <i class="fas fa-tachometer-alt text-blue-600 text-2xl mr-3"></i>
                    <h1 class="text-2xl font-bold text-gray-900">${this.config.title}</h1>
                </div>
                <div class="flex items-center space-x-4">
                    <span class="text-sm text-gray-500">Last updated: <span id="last-updated">${new Date(data.metadata.generated).toLocaleString()}</span></span>
                    <button onclick="refreshData()" class="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 transition">
                        <i class="fas fa-sync-alt mr-2"></i>Refresh
                    </button>
                </div>
            </div>
        </div>
    </header>

    <!-- Main Content -->
    <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <!-- Summary Cards -->
        <section class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            <div class="metric-card bg-white rounded-lg shadow p-6">
                <div class="flex items-center">
                    <div class="flex-shrink-0">
                        <i class="fas fa-flask text-blue-600 text-2xl"></i>
                    </div>
                    <div class="ml-4">
                        <p class="text-sm font-medium text-gray-600">Total Tests</p>
                        <p class="text-2xl font-semibold text-gray-900">${data.metadata.totalTests}</p>
                    </div>
                </div>
            </div>

            <div class="metric-card bg-white rounded-lg shadow p-6">
                <div class="flex items-center">
                    <div class="flex-shrink-0">
                        <i class="fas fa-chart-line text-green-600 text-2xl"></i>
                    </div>
                    <div class="ml-4">
                        <p class="text-sm font-medium text-gray-600">Total Results</p>
                        <p class="text-2xl font-semibold text-gray-900">${data.metadata.totalResults}</p>
                    </div>
                </div>
            </div>

            <div class="metric-card bg-white rounded-lg shadow p-6">
                <div class="flex items-center">
                    <div class="flex-shrink-0">
                        <i class="fas fa-check-circle text-green-600 text-2xl"></i>
                    </div>
                    <div class="ml-4">
                        <p class="text-sm font-medium text-gray-600">Pass Rate</p>
                        <p class="text-2xl font-semibold text-gray-900">${this.calculatePassRate(data.results)}%</p>
                    </div>
                </div>
            </div>

            <div class="metric-card bg-white rounded-lg shadow p-6">
                <div class="flex items-center">
                    <div class="flex-shrink-0">
                        <i class="fas fa-clock text-yellow-600 text-2xl"></i>
                    </div>
                    <div class="ml-4">
                        <p class="text-sm font-medium text-gray-600">Avg Duration</p>
                        <p class="text-2xl font-semibold text-gray-900">${this.calculateAverageDuration(data.results)}s</p>
                    </div>
                </div>
            </div>
        </section>

        <!-- Charts Section -->
        <section class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
            <!-- Latency Trends Chart -->
            <div class="bg-white rounded-lg shadow p-6">
                <h2 class="text-lg font-semibold text-gray-900 mb-4">Latency Trends</h2>
                <div class="chart-container">
                    <canvas id="latency-trends-chart"></canvas>
                </div>
            </div>

            <!-- Throughput Trends Chart -->
            <div class="bg-white rounded-lg shadow p-6">
                <h2 class="text-lg font-semibold text-gray-900 mb-4">Throughput Trends</h2>
                <div class="chart-container">
                    <canvas id="throughput-trends-chart"></canvas>
                </div>
            </div>
        </section>

        <!-- Recent Results Table -->
        <section class="bg-white rounded-lg shadow">
            <div class="px-6 py-4 border-b border-gray-200">
                <h2 class="text-lg font-semibold text-gray-900">Recent Test Results</h2>
            </div>
            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Test Name</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">p95 (ms)</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">p99 (ms)</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Throughput (ops/s)</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Error Rate (%)</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Timestamp</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
                        ${data.results.map((result) => this.generateResultRow(result)).join('')}
                    </tbody>
                </table>
            </div>
        </section>
    </main>

    <!-- Footer -->
    <footer class="bg-white border-t mt-12">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
            <div class="flex justify-between items-center">
                <p class="text-sm text-gray-500">Cortex Memory MCP Performance Dashboard v${data.metadata.version}</p>
                <p class="text-sm text-gray-500">Generated: ${new Date(data.metadata.generated).toLocaleString()}</p>
            </div>
        </div>
    </footer>

    <script>
        // Dashboard data
        const dashboardData = ${JSON.stringify(data, null, 2)};

        // Initialize charts
        let latencyChart, throughputChart;

        document.addEventListener('DOMContentLoaded', function() {
            initializeCharts();
            setupAutoRefresh();
        });

        function initializeCharts() {
            // Latency Trends Chart
            const latencyCtx = document.getElementById('latency-trends-chart').getContext('2d');
            latencyChart = new Chart(latencyCtx, {
                type: 'line',
                data: getLatencyChartData(),
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'top',
                        },
                        title: {
                            display: false
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            title: {
                                display: true,
                                text: 'Latency (ms)'
                            }
                        }
                    }
                }
            });

            // Throughput Trends Chart
            const throughputCtx = document.getElementById('throughput-trends-chart').getContext('2d');
            throughputChart = new Chart(throughputCtx, {
                type: 'line',
                data: getThroughputChartData(),
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'top',
                        },
                        title: {
                            display: false
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            title: {
                                display: true,
                                text: 'Throughput (ops/s)'
                            }
                        }
                    }
                }
            });
        }

        function getLatencyChartData() {
            const latencyTrends = dashboardData.trends.filter(t => t.metric.includes('latency'));
            const datasets = [];
            const colors = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6'];

            latencyTrends.forEach((trend, index) => {
                datasets.push({
                    label: \`\${trend.testName} - \${trend.metric}\`,
                    data: trend.dataPoints.map(point => ({
                        x: new Date(point.timestamp).getTime(),
                        y: point.value
                    })),
                    borderColor: colors[index % colors.length],
                    backgroundColor: colors[index % colors.length] + '20',
                    tension: 0.1
                });
            });

            return { datasets };
        }

        function getThroughputChartData() {
            const throughputTrends = dashboardData.trends.filter(t => t.metric === 'throughput');
            const datasets = [];
            const colors = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6'];

            throughputTrends.forEach((trend, index) => {
                datasets.push({
                    label: trend.testName,
                    data: trend.dataPoints.map(point => ({
                        x: new Date(point.timestamp).getTime(),
                        y: point.value
                    })),
                    borderColor: colors[index % colors.length],
                    backgroundColor: colors[index % colors.length] + '20',
                    tension: 0.1
                });
            });

            return { datasets };
        }

        function refreshData() {
            const refreshButton = document.querySelector('button[onclick="refreshData()"]');
            const originalContent = refreshButton.innerHTML;
            refreshButton.innerHTML = '<div class="loading"></div> Refreshing...';
            refreshButton.disabled = true;

            // Simulate data refresh (in real implementation, this would fetch new data)
            setTimeout(() => {
                refreshButton.innerHTML = originalContent;
                refreshButton.disabled = false;
                document.getElementById('last-updated').textContent = new Date().toLocaleString();
            }, 2000);
        }

        function setupAutoRefresh() {
            ${
              this.config.enableRealTime
                ? `
            setInterval(() => {
                refreshData();
            }, ${this.config.refreshInterval * 1000});
            `
                : ''
            }
        }
    </script>
</body>
</html>`;
  }

  /**
   * Generate result row for table
   */
  private generateResultRow(result: PerformanceTestResult): string {
    const statusClass = result.validation.passed ? 'status-passed' : 'status-failed';
    const statusIcon = result.validation.passed ? '✅' : '❌';
    const statusText = result.validation.passed ? 'Passed' : 'Failed';

    return `
        <tr>
            <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                ${result.config.name}
            </td>
            <td class="px-6 py-4 whitespace-nowrap text-sm">
                <span class="${statusClass} font-medium">
                    ${statusIcon} ${statusText}
                </span>
            </td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                ${result.results.metrics.latencies.p95.toFixed(1)}
            </td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                ${result.results.metrics.latencies.p99.toFixed(1)}
            </td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                ${result.results.metrics.throughput.toFixed(1)}
            </td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                ${result.results.metrics.errorRate.toFixed(1)}
            </td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                ${new Date(result.metadata.timestamp).toLocaleString()}
            </td>
        </tr>
    `;
  }

  /**
   * Calculate pass rate
   */
  private calculatePassRate(results: PerformanceTestResult[]): number {
    if (results.length === 0) return 0;
    const passed = results.filter((r) => r.validation.passed).length;
    return Math.round((passed / results.length) * 100);
  }

  /**
   * Calculate average duration
   */
  private calculateAverageDuration(results: PerformanceTestResult[]): number {
    if (results.length === 0) return 0;
    const totalDuration = results.reduce((sum, r) => sum + r.metadata.duration, 0);
    return Math.round((totalDuration / results.length / 1000) * 100) / 100; // Convert to seconds and round to 2 decimal places
  }

  /**
   * Generate data API endpoints
   */
  private async generateDataAPI(data: DashboardData): Promise<void> {
    const apiDir = join(this.config.outputDir, 'api');
    mkdirSync(apiDir, { recursive: true });

    // Generate results API
    const resultsAPI = {
      results: data.results,
      metadata: data.metadata,
    };
    writeFileSync(join(apiDir, 'results.json'), JSON.stringify(resultsAPI, null, 2));

    // Generate trends API
    const trendsAPI = {
      trends: data.trends,
      metadata: data.metadata,
    };
    writeFileSync(join(apiDir, 'trends.json'), JSON.stringify(trendsAPI, null, 2));

    // Generate system metrics API
    const systemMetricsAPI = {
      metrics: data.systemMetrics,
      metadata: data.metadata,
    };
    writeFileSync(join(apiDir, 'system-metrics.json'), JSON.stringify(systemMetricsAPI, null, 2));
  }

  /**
   * Generate dashboard assets
   */
  private async generateAssets(): Promise<void> {
    const assetsDir = join(this.config.outputDir, 'assets');
    mkdirSync(assetsDir, { recursive: true });

    // Generate CSS file
    const cssContent = this.generateDashboardCSS();
    writeFileSync(join(assetsDir, 'dashboard.css'), cssContent);

    // Generate JavaScript file
    const jsContent = this.generateDashboardJS();
    writeFileSync(join(assetsDir, 'dashboard.js'), jsContent);
  }

  /**
   * Generate dashboard CSS
   */
  private generateDashboardCSS(): string {
    return `
/* Performance Dashboard Custom Styles */
.performance-dashboard {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
}

.metric-trend {
    display: inline-flex;
    align-items: center;
    font-size: 0.875rem;
    margin-left: 0.5rem;
}

.trend-up {
    color: #ef4444;
}

.trend-down {
    color: #10b981;
}

.trend-stable {
    color: #6b7280;
}

.chart-legend {
    display: flex;
    flex-wrap: wrap;
    gap: 1rem;
    margin-top: 1rem;
}

.legend-item {
    display: flex;
    align-items: center;
    font-size: 0.875rem;
}

.legend-color {
    width: 12px;
    height: 12px;
    border-radius: 2px;
    margin-right: 0.5rem;
}

.status-badge {
    display: inline-flex;
    align-items: center;
    padding: 0.25rem 0.75rem;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 500;
}

.status-badge.passed {
    background-color: #d1fae5;
    color: #065f46;
}

.status-badge.failed {
    background-color: #fee2e2;
    color: #991b1b;
}

.status-badge.warning {
    background-color: #fed7aa;
    color: #92400e;
}

.loading-overlay {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background-color: rgba(255, 255, 255, 0.8);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 9999;
}

@media (max-width: 768px) {
    .metric-card {
        margin-bottom: 1rem;
    }

    .chart-container {
        height: 250px;
    }
}
`;
  }

  /**
   * Generate dashboard JavaScript
   */
  private generateDashboardJS(): string {
    return `
// Performance Dashboard JavaScript
class PerformanceDashboard {
    constructor() {
        this.refreshInterval = ${this.config.refreshInterval * 1000};
        this.charts = new Map();
        this.isRefreshing = false;
    }

    async init() {
        await this.loadData();
        this.initializeCharts();
        this.setupEventListeners();
        this.startAutoRefresh();
    }

    async loadData() {
        try {
            const response = await fetch('./api/results.json');
            this.data = await response.json();
        } catch (error) {
            console.error('Failed to load dashboard data:', error);
        }
    }

    initializeCharts() {
        // Initialize all charts with data
        this.updateChart('latency-trends', this.getLatencyData());
        this.updateChart('throughput-trends', this.getThroughputData());
    }

    updateChart(chartId, data) {
        const ctx = document.getElementById(chartId);
        if (!ctx) return;

        if (this.charts.has(chartId)) {
            this.charts.get(chartId).destroy();
        }

        const chart = new Chart(ctx, {
            type: 'line',
            data: data,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'top',
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });

        this.charts.set(chartId, chart);
    }

    getLatencyData() {
        // Process latency data from this.data
        return {
            labels: [],
            datasets: []
        };
    }

    getThroughputData() {
        // Process throughput data from this.data
        return {
            labels: [],
            datasets: []
        };
    }

    setupEventListeners() {
        document.getElementById('refresh-btn')?.addEventListener('click', () => {
            this.refreshData();
        });
    }

    async refreshData() {
        if (this.isRefreshing) return;

        this.isRefreshing = true;
        this.showLoading(true);

        try {
            await this.loadData();
            this.updateCharts();
            this.updateMetrics();
        } catch (error) {
            console.error('Failed to refresh data:', error);
        } finally {
            this.isRefreshing = false;
            this.showLoading(false);
        }
    }

    updateCharts() {
        this.updateChart('latency-trends', this.getLatencyData());
        this.updateChart('throughput-trends', this.getThroughputData());
    }

    updateMetrics() {
        // Update metric cards with new data
        const metrics = this.calculateMetrics();

        document.getElementById('total-tests').textContent = metrics.totalTests;
        document.getElementById('total-results').textContent = metrics.totalResults;
        document.getElementById('pass-rate').textContent = metrics.passRate + '%';
        document.getElementById('avg-duration').textContent = metrics.avgDuration + 's';
    }

    calculateMetrics() {
        if (!this.data?.results) return { totalTests: 0, totalResults: 0, passRate: 0, avgDuration: 0 };

        const results = this.data.results;
        const passed = results.filter(r => r.validation.passed).length;
        const avgDuration = results.reduce((sum, r) => sum + r.metadata.duration, 0) / results.length;

        return {
            totalTests: new Set(results.map(r => r.config.name)).size,
            totalResults: results.length,
            passRate: Math.round((passed / results.length) * 100),
            avgDuration: Math.round(avgDuration / 1000 * 100) / 100
        };
    }

    showLoading(show) {
        const overlay = document.getElementById('loading-overlay');
        if (overlay) {
            overlay.style.display = show ? 'flex' : 'none';
        }
    }

    startAutoRefresh() {
        if (${this.config.enableRealTime}) {
            setInterval(() => {
                this.refreshData();
            }, this.refreshInterval);
        }
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    const dashboard = new PerformanceDashboard();
    dashboard.init();
});
`;
  }

  /**
   * Ensure directories exist
   */
  private ensureDirectories(): void {
    const dirs = [
      this.config.outputDir,
      join(this.config.outputDir, 'api'),
      join(this.config.outputDir, 'assets'),
    ];

    for (const dir of dirs) {
      mkdirSync(dir, { recursive: true });
    }
  }

  /**
   * Start dashboard server (optional)
   */
  async startServer(port: number = 3001): Promise<void> {
    // This would start a simple Express server to serve the dashboard
    console.log(`🚀 Dashboard server would start on port ${port}`);
    console.log(`📊 Dashboard available at: http://localhost:${port}`);
  }
}
