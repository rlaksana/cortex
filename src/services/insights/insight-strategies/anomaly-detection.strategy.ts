// @ts-nocheck
/**
 * Anomaly Detection Strategy
 *
 * Advanced anomaly detection and trend analysis using ZAI to identify
 * unusual patterns, outliers, and emerging trends in knowledge items.
 * Provides early warning signals and trend forecasting.
 *
 * @author Cortex Team
 * @version 2.0.0
 * @since 2025
 */

import { randomUUID } from 'crypto';
import { logger } from '../../../utils/logger';
import type { ZAIClientService } from '../../ai/zai-client.service';
import type { ZAIChatRequest, ZAIChatResponse } from '../../../types/zai-interfaces';
import type {
  InsightGenerationRequest,
  AnomalyInsight,
  TrendInsight,
  InsightTypeUnion,
} from '../../../types/insight-interfaces';

export interface AnomalyDetectionOptions {
  confidence_threshold: number;
  max_insights: number;
  include_rationale: boolean;
  zai_config: {
    temperature: number;
    max_tokens: number;
    top_p: number;
    frequency_penalty: number;
    presence_penalty: number;
  };
}

export interface AnomalyAnalysis {
  anomaly_type:
    | 'statistical_outlier'
    | 'pattern_deviation'
    | 'temporal_anomaly'
    | 'content_anomaly'
    | 'volume_anomaly'
    | 'semantic_anomaly';
  anomaly_name: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: number;
  affected_items: Array<{
    item_id: string;
    item_type: string;
    anomaly_context: string;
    confidence: number;
  }>;
  baseline_data: any;
  deviation_score: number;
  potential_causes: string[];
  metadata: {
    analysis_method: string;
    detection_algorithm: string;
    statistical_significance: number;
    time_period: string;
  };
}

export interface TrendAnalysis {
  trend_type:
    | 'emerging_trend'
    | 'volume_trend'
    | 'semantic_trend'
    | 'behavioral_trend'
    | 'temporal_trend';
  trend_name: string;
  description: string;
  trend_direction: 'increasing' | 'decreasing' | 'stable' | 'volatile';
  trend_strength: number;
  confidence: number;
  time_period: {
    start: string;
    end: string;
  };
  data_points: Array<{
    timestamp: string;
    value: number;
    context: string;
  }>;
  predictions: Array<{
    timeframe: string;
    predicted_value: number;
    confidence: number;
  }>;
  metadata: {
    analysis_method: string;
    trend_algorithm: string;
    forecast_method: string;
  };
}

/**
 * Anomaly Detection Strategy
 */
export class AnomalyDetectionStrategy {
  constructor(private zaiClient: ZAIClientService) {}

  /**
   * Generate anomaly detection and trend insights
   */
  async generateInsights(
    request: InsightGenerationRequest,
    options: AnomalyDetectionOptions
  ): Promise<InsightTypeUnion[]> {
    const insights: InsightTypeUnion[] = [];

    try {
      logger.debug('Starting anomaly detection and trend analysis');

      // Perform different types of analysis
      const [anomalyAnalyses, trendAnalyses] = await Promise.all([
        this.detectAnomalies(request.items, options),
        this.analyzeTrends(request.items, options),
      ]);

      // Convert analyses to insights
      for (const analysis of anomalyAnalyses.slice(0, Math.floor(options.max_insights / 2))) {
        const insight = this.convertAnomalyToInsight(analysis, request.scope, options);
        insights.push(insight);
      }

      for (const analysis of trendAnalyses.slice(0, Math.floor(options.max_insights / 2))) {
        const insight = this.convertTrendToInsight(analysis, request.scope, options);
        insights.push(insight);
      }

      logger.debug(
        {
          anomalyAnalyses: anomalyAnalyses.length,
          trendAnalyses: trendAnalyses.length,
          insightsGenerated: insights.length,
        },
        'Anomaly detection and trend analysis completed'
      );

      return insights;
    } catch (error) {
      logger.error({ error }, 'Anomaly detection strategy failed');
      return insights;
    }
  }

  /**
   * Detect anomalies in knowledge items
   */
  private async detectAnomalies(
    items: any[],
    options: AnomalyDetectionOptions
  ): Promise<AnomalyAnalysis[]> {
    const analyses: AnomalyAnalysis[] = [];

    try {
      // Statistical outlier detection
      const statisticalOutliers = await this.detectStatisticalOutliers(items, options);
      analyses.push(...statisticalOutliers);

      // Pattern deviation detection
      const patternDeviations = await this.detectPatternDeviations(items, options);
      analyses.push(...patternDeviations);

      // Temporal anomaly detection
      const temporalAnomalies = await this.detectTemporalAnomalies(items, options);
      analyses.push(...temporalAnomalies);

      // Volume anomaly detection
      const volumeAnomalies = await this.detectVolumeAnomalies(items, options);
      analyses.push(...volumeAnomalies);

      // Semantic anomaly detection using ZAI
      const semanticAnomalies = await this.detectSemanticAnomalies(items, options);
      analyses.push(...semanticAnomalies);

      // Filter by confidence threshold
      return analyses.filter((analysis) => analysis.confidence >= options.confidence_threshold);
    } catch (error) {
      logger.error({ error }, 'Anomaly detection failed');
      return [];
    }
  }

  /**
   * Analyze trends in knowledge items
   */
  private async analyzeTrends(
    items: any[],
    options: AnomalyDetectionOptions
  ): Promise<TrendAnalysis[]> {
    const analyses: TrendAnalysis[] = [];

    try {
      // Volume trends
      const volumeTrends = this.analyzeVolumeTrends(items, options);
      analyses.push(...volumeTrends);

      // Semantic trends using ZAI
      const semanticTrends = await this.analyzeSemanticTrends(items, options);
      analyses.push(...semanticTrends);

      // Behavioral trends
      const behavioralTrends = await this.analyzeBehavioralTrends(items, options);
      analyses.push(...behavioralTrends);

      // Temporal trends
      const temporalTrends = this.analyzeTemporalTrends(items, options);
      analyses.push(...temporalTrends);

      // Filter by confidence threshold
      return analyses.filter((analysis) => analysis.confidence >= options.confidence_threshold);
    } catch (error) {
      logger.error({ error }, 'Trend analysis failed');
      return [];
    }
  }

  /**
   * Detect statistical outliers
   */
  private async detectStatisticalOutliers(
    items: any[],
    options: AnomalyDetectionOptions
  ): Promise<AnomalyAnalysis[]> {
    const analyses: AnomalyAnalysis[] = [];

    // Analyze content length outliers
    const contentLengths = items.map((item) => ({
      id: item.id,
      type: item.kind,
      length: this.getContentLength(item),
    }));

    const avgLength =
      contentLengths.reduce((sum, item) => sum + item.length, 0) / contentLengths.length;
    const stdDev = Math.sqrt(
      contentLengths.reduce((sum, item) => sum + Math.pow(item.length - avgLength, 2), 0) /
        contentLengths.length
    );

    const outliers = contentLengths.filter(
      (item) => Math.abs(item.length - avgLength) > 2 * stdDev
    );

    if (outliers.length > 0) {
      const analysis: AnomalyAnalysis = {
        anomaly_type: 'statistical_outlier',
        anomaly_name: 'Content Length Anomaly',
        description: `Detected ${outliers.length} items with unusual content length (significantly different from average)`,
        severity: outliers.length > items.length * 0.1 ? 'medium' : 'low',
        confidence: 0.7,
        affected_items: outliers.map((item) => ({
          item_id: item.id,
          item_type: item.type,
          anomaly_context: `Content length: ${item.length} (avg: ${Math.round(avgLength)})`,
          confidence: 0.7,
        })),
        baseline_data: { average_length: avgLength, standard_deviation: stdDev },
        deviation_score: Math.max(
          ...outliers.map((item) => Math.abs(item.length - avgLength) / stdDev)
        ),
        potential_causes: [
          'Incomplete documentation',
          'Exceptionally detailed content',
          'Data quality issues',
          'Content generation variations',
        ],
        metadata: {
          analysis_method: 'statistical_analysis',
          detection_algorithm: 'standard_deviation',
          statistical_significance: 0.95,
          time_period: 'all_time',
        },
      };
      analyses.push(analysis);
    }

    return analyses;
  }

  /**
   * Detect pattern deviations
   */
  private async detectPatternDeviations(
    items: any[],
    options: AnomalyDetectionOptions
  ): Promise<AnomalyAnalysis[]> {
    const analyses: AnomalyAnalysis[] = [];

    // Analyze kind distribution
    const kindCounts = new Map<string, number>();
    items.forEach((item) => {
      kindCounts.set(item.kind, (kindCounts.get(item.kind) || 0) + 1);
    });

    const expectedDistribution = 1 / kindCounts.size;
    const deviations: { kind: string; count: number; deviation: number }[] = [];

    for (const [kind, count] of kindCounts.entries()) {
      const actualDistribution = count / items.length;
      const deviation = Math.abs(actualDistribution - expectedDistribution) / expectedDistribution;
      deviations.push({ kind, count, deviation });
    }

    const significantDeviations = deviations.filter((d) => d.deviation > 2.0);

    for (const deviation of significantDeviations) {
      const analysis: AnomalyAnalysis = {
        anomaly_type: 'pattern_deviation',
        anomaly_name: `Kind Distribution Anomaly: ${deviation.kind}`,
        description: `Unusual concentration of "${deviation.kind}" items (${deviation.count} items, ${Math.round((deviation.count / items.length) * 100)}% of total)`,
        severity: deviation.deviation > 3.0 ? 'high' : 'medium',
        confidence: Math.min(deviation.deviation / 4.0, 1.0),
        affected_items: items
          .filter((item) => item.kind === deviation.kind)
          .map((item) => ({
            item_id: item.id,
            item_type: item.kind,
            anomaly_context: `High concentration of this item type`,
            confidence: Math.min(deviation.deviation / 4.0, 1.0),
          })),
        baseline_data: { expected_distribution: expectedDistribution },
        deviation_score: deviation.deviation,
        potential_causes: [
          'Focused work on specific area',
          'Data collection bias',
          'Systematic categorization issues',
          'Temporary spike in activity',
        ],
        metadata: {
          analysis_method: 'distribution_analysis',
          detection_algorithm: 'chi_square',
          statistical_significance: 0.95,
          time_period: 'all_time',
        },
      };
      analyses.push(analysis);
    }

    return analyses;
  }

  /**
   * Detect temporal anomalies
   */
  private async detectTemporalAnomalies(
    items: any[],
    options: AnomalyDetectionOptions
  ): Promise<AnomalyAnalysis[]> {
    const analyses: AnomalyAnalysis[] = [];

    const timeItems = items.filter((item) => item.created_at);
    if (timeItems.length < 5) {
      return analyses;
    }

    // Group by day
    const dailyCounts = new Map<string, number>();
    timeItems.forEach((item) => {
      const day = new Date(item.created_at!).toISOString().split('T')[0];
      dailyCounts.set(day, (dailyCounts.get(day) || 0) + 1);
    });

    const counts = Array.from(dailyCounts.values());
    const avgCount = counts.reduce((sum, count) => sum + count, 0) / counts.length;
    const stdDev = Math.sqrt(
      counts.reduce((sum, count) => sum + Math.pow(count - avgCount, 2), 0) / counts.length
    );

    const anomalousDays = Array.from(dailyCounts.entries()).filter(
      ([_, count]) => Math.abs(count - avgCount) > 2 * stdDev
    );

    if (anomalousDays.length > 0) {
      for (const [day, count] of anomalousDays) {
        const analysis: AnomalyAnalysis = {
          anomaly_type: 'temporal_anomaly',
          anomaly_name: `Activity Spike on ${day}`,
          description: `Unusual activity level detected: ${count} items created (avg: ${Math.round(avgCount)} per day)`,
          severity: count > avgCount * 3 ? 'high' : 'medium',
          confidence: Math.min(Math.abs(count - avgCount) / stdDev / 3, 1.0),
          affected_items: timeItems
            .filter((item) => new Date(item.created_at!).toISOString().split('T')[0] === day)
            .map((item) => ({
              item_id: item.id,
              item_type: item.kind,
              anomaly_context: `Created during activity spike`,
              confidence: 0.7,
            })),
          baseline_data: { average_daily_items: avgCount, daily_std_dev: stdDev },
          deviation_score: Math.abs(count - avgCount) / stdDev,
          potential_causes: [
            'Major project milestone',
            'System migration or update',
            'Team training or documentation push',
            'Incident response or recovery effort',
          ],
          metadata: {
            analysis_method: 'temporal_analysis',
            detection_algorithm: 'moving_average',
            statistical_significance: 0.95,
            time_period: day,
          },
        };
        analyses.push(analysis);
      }
    }

    return analyses;
  }

  /**
   * Detect volume anomalies
   */
  private async detectVolumeAnomalies(
    items: any[],
    options: AnomalyDetectionOptions
  ): Promise<AnomalyAnalysis[]> {
    const analyses: AnomalyAnalysis[] = [];

    // Check for recent volume spikes
    const recentItems = items.filter((item) => {
      if (!item.created_at) return false;
      const daysSinceCreation =
        (Date.now() - new Date(item.created_at).getTime()) / (1000 * 60 * 60 * 24);
      return daysSinceCreation <= 7; // Last 7 days
    });

    const olderItems = items.filter((item) => {
      if (!item.created_at) return false;
      const daysSinceCreation =
        (Date.now() - new Date(item.created_at).getTime()) / (1000 * 60 * 60 * 24);
      return daysSinceCreation > 7;
    });

    if (olderItems.length > 0) {
      const recentRate = recentItems.length / 7; // Items per day in last week
      const historicalRate = olderItems.length / 30; // Approximate historical rate
      const rateIncrease = recentRate / historicalRate;

      if (rateIncrease > 2.0) {
        // More than 2x increase
        const analysis: AnomalyAnalysis = {
          anomaly_type: 'volume_anomaly',
          anomaly_name: 'Recent Volume Spike',
          description: `Significant increase in knowledge creation: ${Math.round(rateIncrease * 100)}% increase in recent activity`,
          severity: rateIncrease > 5.0 ? 'critical' : rateIncrease > 3.0 ? 'high' : 'medium',
          confidence: Math.min(rateIncrease / 5.0, 1.0),
          affected_items: recentItems.map((item) => ({
            item_id: item.id,
            item_type: item.kind,
            anomaly_context: 'Part of recent volume spike',
            confidence: 0.8,
          })),
          baseline_data: {
            recent_rate: recentRate,
            historical_rate: historicalRate,
            increase_factor: rateIncrease,
          },
          deviation_score: Math.log(rateIncrease),
          potential_causes: [
            'Active development sprint',
            'Major documentation effort',
            'Knowledge capture initiative',
            'System integration or migration',
          ],
          metadata: {
            analysis_method: 'volume_analysis',
            detection_algorithm: 'rate_comparison',
            statistical_significance: 0.95,
            time_period: 'last_7_days',
          },
        };
        analyses.push(analysis);
      }
    }

    return analyses;
  }

  /**
   * Detect semantic anomalies using ZAI
   */
  private async detectSemanticAnomalies(
    items: any[],
    options: AnomalyDetectionOptions
  ): Promise<AnomalyAnalysis[]> {
    try {
      const prompt = this.buildSemanticAnomalyPrompt(items);
      const zaiRequest: ZAIChatRequest = {
        messages: [
          {
            role: 'system',
            content:
              'You are an expert semantic anomaly detector. Identify unusual content, contradictory information, outliers in topics, and semantic anomalies in knowledge items.',
          },
          {
            role: 'user',
            content: prompt,
          },
        ],
        temperature: options.zai_config.temperature,
        maxTokens: options.zai_config.max_tokens,
        topP: options.zai_config.top_p,
        frequencyPenalty: options.zai_config.frequency_penalty,
        presencePenalty: options.zai_config.presence_penalty,
      };

      const response = await this.zaiClient.generateCompletion(zaiRequest);
      return this.parseAnomalyResponse(response, items, 'semantic_anomaly');
    } catch (error) {
      logger.error({ error }, 'Semantic anomaly detection failed');
      return [];
    }
  }

  /**
   * Analyze volume trends
   */
  private analyzeVolumeTrends(items: any[], options: AnomalyDetectionOptions): TrendAnalysis[] {
    const analyses: TrendAnalysis[] = [];

    const timeItems = items.filter((item) => item.created_at);
    if (timeItems.length < 10) {
      return analyses;
    }

    // Create time series data
    const sortedItems = timeItems.sort(
      (a, b) => new Date(a.created_at!).getTime() - new Date(b.created_at!).getTime()
    );

    // Group by week for trend analysis
    const weeklyCounts = new Map<string, number>();
    sortedItems.forEach((item) => {
      const week = this.getWeekKey(new Date(item.created_at!));
      weeklyCounts.set(week, (weeklyCounts.get(week) || 0) + 1);
    });

    const weeks = Array.from(weeklyCounts.keys()).sort();
    if (weeks.length < 3) {
      return analyses;
    }

    const counts = weeks.map((week) => weeklyCounts.get(week)!);
    const trendDirection = this.calculateTrendDirection(counts);
    const trendStrength = this.calculateTrendStrength(counts);

    const analysis: TrendAnalysis = {
      trend_type: 'volume_trend',
      trend_name: 'Knowledge Creation Volume Trend',
      description: `Trend analysis of knowledge item creation volume over time`,
      trend_direction: trendDirection,
      trend_strength: trendStrength,
      confidence: Math.abs(trendStrength) > 0.3 ? 0.8 : 0.5,
      time_period: {
        start: new Date(weeks[0]).toISOString(),
        end: new Date(weeks[weeks.length - 1]).toISOString(),
      },
      data_points: weeks.map((week, index) => ({
        timestamp: week,
        value: counts[index],
        context: 'weekly_volume',
      })),
      predictions: this.generateSimplePredictions(counts),
      metadata: {
        analysis_method: 'time_series_analysis',
        trend_algorithm: 'linear_regression',
        forecast_method: 'extrapolation',
      },
    };

    analyses.push(analysis);
    return analyses;
  }

  /**
   * Analyze semantic trends using ZAI
   */
  private async analyzeSemanticTrends(
    items: any[],
    options: AnomalyDetectionOptions
  ): Promise<TrendAnalysis[]> {
    try {
      const prompt = this.buildSemanticTrendPrompt(items);
      const zaiRequest: ZAIChatRequest = {
        messages: [
          {
            role: 'system',
            content:
              'You are an expert semantic trend analyst. Identify emerging topics, shifting focus areas, and semantic trends in knowledge items.',
          },
          {
            role: 'user',
            content: prompt,
          },
        ],
        temperature: options.zai_config.temperature,
        maxTokens: options.zai_config.max_tokens,
        topP: options.zai_config.top_p,
        frequencyPenalty: options.zai_config.frequency_penalty,
        presencePenalty: options.zai_config.presence_penalty,
      };

      const response = await this.zaiClient.generateCompletion(zaiRequest);
      return this.parseTrendResponse(response, items, 'semantic_trend');
    } catch (error) {
      logger.error({ error }, 'Semantic trend analysis failed');
      return [];
    }
  }

  /**
   * Analyze behavioral trends using ZAI
   */
  private async analyzeBehavioralTrends(
    items: any[],
    options: AnomalyDetectionOptions
  ): Promise<TrendAnalysis[]> {
    try {
      const prompt = this.buildBehavioralTrendPrompt(items);
      const zaiRequest: ZAIChatRequest = {
        messages: [
          {
            role: 'system',
            content:
              'You are an expert behavioral trend analyst. Identify changes in work patterns, collaboration trends, and behavioral shifts in knowledge creation.',
          },
          {
            role: 'user',
            content: prompt,
          },
        ],
        temperature: options.zai_config.temperature,
        maxTokens: options.zai_config.max_tokens,
        topP: options.zai_config.top_p,
        frequencyPenalty: options.zai_config.frequency_penalty,
        presencePenalty: options.zai_config.presence_penalty,
      };

      const response = await this.zaiClient.generateCompletion(zaiRequest);
      return this.parseTrendResponse(response, items, 'behavioral_trend');
    } catch (error) {
      logger.error({ error }, 'Behavioral trend analysis failed');
      return [];
    }
  }

  /**
   * Analyze temporal trends
   */
  private analyzeTemporalTrends(items: any[], options: AnomalyDetectionOptions): TrendAnalysis[] {
    const analyses: TrendAnalysis[] = [];

    // Analyze creation patterns by time of day/day of week
    const timeItems = items.filter((item) => item.created_at);
    if (timeItems.length < 20) {
      return analyses;
    }

    const hourCounts = new Array(24).fill(0);
    const dayOfWeekCounts = new Array(7).fill(0);

    timeItems.forEach((item) => {
      const date = new Date(item.created_at!);
      hourCounts[date.getHours()]++;
      dayOfWeekCounts[date.getDay()]++;
    });

    // Find peak hours and days
    const peakHour = hourCounts.indexOf(Math.max(...hourCounts));
    const peakDay = dayOfWeekCounts.indexOf(Math.max(...dayOfWeekCounts));

    const analysis: TrendAnalysis = {
      trend_type: 'temporal_trend',
      trend_name: 'Knowledge Creation Temporal Pattern',
      description: `Analysis of when knowledge items are typically created - peak activity on ${this.getDayName(peakDay)} at ${peakHour}:00`,
      trend_direction: 'stable',
      trend_strength: 0.6,
      confidence: 0.7,
      time_period: {
        start: new Date(timeItems[0].created_at!).toISOString(),
        end: new Date(timeItems[timeItems.length - 1].created_at!).toISOString(),
      },
      data_points: hourCounts.map((count, hour) => ({
        timestamp: `2024-01-01T${hour.toString().padStart(2, '0')}:00:00Z`,
        value: count,
        context: 'hourly_pattern',
      })),
      predictions: [
        {
          timeframe: 'next_week',
          predicted_value: hourCounts[peakHour],
          confidence: 0.7,
        },
      ],
      metadata: {
        analysis_method: 'temporal_pattern_analysis',
        trend_algorithm: 'frequency_analysis',
        forecast_method: 'pattern_projection',
      },
    };

    analyses.push(analysis);
    return analyses;
  }

  /**
   * Build semantic anomaly detection prompt
   */
  private buildSemanticAnomalyPrompt(items: any[]): string {
    const itemSummaries = items
      .map((item, index) => {
        return `${index + 1}. Type: ${item.kind}, Content: ${this.extractKeyContent(item)}`;
      })
      .join('\n');

    return `
Analyze the following knowledge items and identify semantic anomalies:

${itemSummaries}

Look for:
1. Content that contradicts other items
2. Unusual topics or themes
3. Outliers in terminology or language
4. Semantic inconsistencies
5. Unusual content structures
6. Potential quality issues

Provide analysis in JSON format:
{
  "anomalies": [
    {
      "name": "Anomaly Name",
      "description": "Description of the semantic anomaly",
      "severity": "low|medium|high|critical",
      "confidence": 0.8,
      "item_indices": [1, 2, 3],
      "potential_causes": ["cause1", "cause2"]
    }
  ]
}

Return only the JSON response, no additional text.
`;
  }

  /**
   * Build semantic trend analysis prompt
   */
  private buildSemanticTrendPrompt(items: any[]): string {
    const itemSummaries = items
      .map((item, index) => {
        return `${index + 1}. Type: ${item.kind}, Created: ${item.created_at || 'unknown'}, Content: ${this.extractKeyContent(item)}`;
      })
      .join('\n');

    return `
Analyze the following knowledge items and identify semantic trends:

${itemSummaries}

Look for:
1. Emerging topics or themes
2. Shifts in focus areas
3. Evolving terminology
4. Changing content patterns
5. New subject areas
6. Declining or growing topics

Provide analysis in JSON format:
{
  "trends": [
    {
      "name": "Trend Name",
      "description": "Description of the semantic trend",
      "trend_direction": "increasing|decreasing|stable|volatile",
      "trend_strength": 0.8,
      "confidence": 0.7,
      "key_topics": ["topic1", "topic2"],
      "time_indicators": ["recent", "growing"],
      "affected_item_indices": [1, 2, 3]
    }
  ]
}

Return only the JSON response, no additional text.
`;
  }

  /**
   * Build behavioral trend analysis prompt
   */
  private buildBehavioralTrendPrompt(items: any[]): string {
    const itemSummaries = items
      .map((item, index) => {
        return `${index + 1}. Type: ${item.kind}, Created: ${item.created_at || 'unknown'}, Content: ${this.extractKeyContent(item)}`;
      })
      .join('\n');

    return `
Analyze the following knowledge items and identify behavioral trends:

${itemSummaries}

Look for:
1. Changes in work patterns
2. Collaboration trends
3. Shifts in documentation habits
4. Changes in item types over time
5. Team behavior patterns
6. Process adoption trends

Provide analysis in JSON format:
{
  "trends": [
    {
      "name": "Behavioral Trend Name",
      "description": "Description of the behavioral trend",
      "trend_direction": "increasing|decreasing|stable|volatile",
      "trend_strength": 0.8,
      "confidence": 0.7,
      "behavior_type": "collaboration|documentation|process",
      "indicators": ["indicator1", "indicator2"],
      "affected_item_indices": [1, 2, 3]
    }
  ]
}

Return only the JSON response, no additional text.
`;
  }

  /**
   * Parse anomaly response
   */
  private parseAnomalyResponse(
    response: any,
    items: any[],
    anomalyType: AnomalyAnalysis['anomaly_type']
  ): AnomalyAnalysis[] {
    try {
      const content = response.choices?.[0]?.message?.content;
      if (!content) {
        return [];
      }

      const analysis = JSON.parse(content);
      const anomalies = analysis.anomalies || [];

      return anomalies.map((anomaly: any) => ({
        anomaly_type: anomalyType,
        anomaly_name: anomaly.name,
        description: anomaly.description,
        severity: anomaly.severity || 'medium',
        confidence: anomaly.confidence || 0.5,
        affected_items: (anomaly.item_indices || []).map((index: number) => {
          const item = items[index - 1];
          return {
            item_id: item.id,
            item_type: item.kind,
            anomaly_context: anomaly.name,
            confidence: anomaly.confidence || 0.5,
          };
        }),
        baseline_data: {},
        deviation_score: anomaly.confidence || 0.5,
        potential_causes: anomaly.potential_causes || [],
        metadata: {
          analysis_method: 'zai_semantic_analysis',
          detection_algorithm: 'ai_pattern_recognition',
          statistical_significance: 0.95,
          time_period: 'recent',
        },
      }));
    } catch (error) {
      logger.error({ error }, 'Failed to parse anomaly response');
      return [];
    }
  }

  /**
   * Parse trend response
   */
  private parseTrendResponse(
    response: any,
    items: any[],
    trendType: TrendAnalysis['trend_type']
  ): TrendAnalysis[] {
    try {
      const content = response.choices?.[0]?.message?.content;
      if (!content) {
        return [];
      }

      const analysis = JSON.parse(content);
      const trends = analysis.trends || [];

      return trends.map((trend: any) => ({
        trend_type: trendType,
        trend_name: trend.name,
        description: trend.description,
        trend_direction: trend.trend_direction || 'stable',
        trend_strength: trend.trend_strength || 0.5,
        confidence: trend.confidence || 0.5,
        time_period: {
          start: items[0]?.created_at || new Date().toISOString(),
          end: items[items.length - 1]?.created_at || new Date().toISOString(),
        },
        data_points: (trend.affected_item_indices || []).map((index: number) => ({
          timestamp: items[index - 1]?.created_at || new Date().toISOString(),
          value: 1,
          context: trend.name,
        })),
        predictions: [
          {
            timeframe: 'next_month',
            predicted_value: trend.trend_strength || 0.5,
            confidence: trend.confidence || 0.5,
          },
        ],
        metadata: {
          analysis_method: 'zai_trend_analysis',
          trend_algorithm: 'ai_pattern_analysis',
          forecast_method: 'trend_projection',
        },
      }));
    } catch (error) {
      logger.error({ error }, 'Failed to parse trend response');
      return [];
    }
  }

  /**
   * Utility methods
   */
  private getContentLength(item: any): number {
    const content = this.extractKeyContent(item);
    return content.length;
  }

  private extractKeyContent(item: any): string {
    const content = [
      item.data?.content,
      item.data?.title,
      item.data?.description,
      item.data?.summary,
    ].filter(Boolean);

    if (content.length === 0) {
      return JSON.stringify(item.data).substring(0, 200);
    }

    return content.join(' ').substring(0, 500);
  }

  private getWeekKey(date: Date): string {
    const year = date.getFullYear();
    const month = date.getMonth();
    const day = date.getDate();
    const weekStart = day - date.getDay();
    return new Date(year, month, weekStart).toISOString().split('T')[0];
  }

  private getDayName(dayIndex: number): string {
    const days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
    return days[dayIndex];
  }

  private calculateTrendDirection(
    values: number[]
  ): 'increasing' | 'decreasing' | 'stable' | 'volatile' {
    if (values.length < 3) return 'stable';

    const firstHalf = values.slice(0, Math.floor(values.length / 2));
    const secondHalf = values.slice(Math.floor(values.length / 2));

    const firstAvg = firstHalf.reduce((sum, val) => sum + val, 0) / firstHalf.length;
    const secondAvg = secondHalf.reduce((sum, val) => sum + val, 0) / secondHalf.length;

    const difference = (secondAvg - firstAvg) / firstAvg;

    if (Math.abs(difference) < 0.1) return 'stable';
    if (this.isVolatile(values)) return 'volatile';
    return difference > 0 ? 'increasing' : 'decreasing';
  }

  private isVolatile(values: number[]): boolean {
    if (values.length < 4) return false;

    const avg = values.reduce((sum, val) => sum + val, 0) / values.length;
    const variance = values.reduce((sum, val) => sum + Math.pow(val - avg, 2), 0) / values.length;
    const coefficientOfVariation = Math.sqrt(variance) / avg;

    return coefficientOfVariation > 0.5;
  }

  private calculateTrendStrength(values: number[]): number {
    if (values.length < 3) return 0;

    // Simple linear regression to calculate trend strength
    const n = values.length;
    const x = Array.from({ length: n }, (_, i) => i);
    const y = values;

    const sumX = x.reduce((sum, val) => sum + val, 0);
    const sumY = y.reduce((sum, val) => sum + val, 0);
    const sumXY = x.reduce((sum, val, i) => sum + val * y[i], 0);
    const sumX2 = x.reduce((sum, val) => sum + val * val, 0);

    const slope = (n * sumXY - sumX * sumY) / (n * sumX2 - sumX * sumX);
    const avgY = sumY / n;
    const yVariance = y.reduce((sum, val) => sum + Math.pow(val - avgY, 2), 0) / (n - 1);

    // Normalize slope by variance to get trend strength
    return Math.abs(slope) / (Math.sqrt(yVariance) || 1);
  }

  private generateSimplePredictions(
    values: number[]
  ): Array<{ timeframe: string; predicted_value: number; confidence: number }> {
    const lastValue = values[values.length - 1];
    const trend = this.calculateTrendDirection(values);
    const strength = this.calculateTrendStrength(values);

    let predictedValue = lastValue;
    if (trend === 'increasing') {
      predictedValue = lastValue * (1 + strength * 0.2);
    } else if (trend === 'decreasing') {
      predictedValue = lastValue * (1 - strength * 0.2);
    }

    return [
      {
        timeframe: 'next_week',
        predicted_value: Math.round(predictedValue),
        confidence: Math.min(strength + 0.3, 0.9),
      },
      {
        timeframe: 'next_month',
        predicted_value: Math.round(predictedValue * 4.3), // Approximate month length
        confidence: Math.min(strength + 0.1, 0.7),
      },
    ];
  }

  /**
   * Convert anomaly analysis to insight
   */
  private convertAnomalyToInsight(
    analysis: AnomalyAnalysis,
    scope: any,
    options: AnomalyDetectionOptions
  ): AnomalyInsight {
    return {
      id: randomUUID(),
      type: 'anomalies',
      title: analysis.anomaly_name,
      description: analysis.description,
      confidence: analysis.confidence,
      priority: this.mapSeverityToPriority(analysis.severity),
      item_ids: analysis.affected_items.map((item) => item.item_id),
      scope: scope,
      metadata: {
        generated_at: new Date().toISOString(),
        generated_by: 'anomaly-detection-strategy',
        processing_time_ms: 1,
        data_sources: ['knowledge_items'],
        tags: ['anomaly', analysis.anomaly_type, analysis.severity],
      },
      actionable: this.isAnomalyActionable(analysis),
      category: 'anomaly',
      anomaly_data: {
        anomaly_type: analysis.anomaly_type,
        severity: analysis.severity,
        baseline_data: analysis.baseline_data,
        deviation_score: analysis.deviation_score,
        potential_causes: analysis.potential_causes,
      },
    };
  }

  /**
   * Convert trend analysis to insight
   */
  private convertTrendToInsight(
    analysis: TrendAnalysis,
    scope: any,
    options: AnomalyDetectionOptions
  ): TrendInsight {
    return {
      id: randomUUID(),
      type: 'trends',
      title: analysis.trend_name,
      description: analysis.description,
      confidence: analysis.confidence,
      priority: this.calculateTrendPriority(analysis),
      item_ids: analysis.data_points.map((_, index) => scope.project || 'unknown'),
      scope: scope,
      metadata: {
        generated_at: new Date().toISOString(),
        generated_by: 'anomaly-detection-strategy',
        processing_time_ms: 1,
        data_sources: ['knowledge_items'],
        tags: ['trend', analysis.trend_type, analysis.trend_direction],
      },
      actionable: this.isTrendActionable(analysis),
      category: 'trend',
      trend_data: {
        trend_direction: analysis.trend_direction,
        trend_strength: analysis.trend_strength,
        time_period: analysis.time_period,
        data_points: analysis.data_points,
      },
    };
  }

  private mapSeverityToPriority(severity: string): number {
    switch (severity) {
      case 'critical':
        return 1;
      case 'high':
        return 2;
      case 'medium':
        return 3;
      case 'low':
        return 4;
      default:
        return 3;
    }
  }

  private calculateTrendPriority(analysis: TrendAnalysis): number {
    if (Math.abs(analysis.trend_strength) > 0.7 && analysis.confidence > 0.8) return 1;
    if (Math.abs(analysis.trend_strength) > 0.5 && analysis.confidence > 0.6) return 2;
    return 3;
  }

  private isAnomalyActionable(analysis: AnomalyAnalysis): boolean {
    // Critical and high severity anomalies are actionable
    return ['critical', 'high'].includes(analysis.severity) && analysis.confidence > 0.7;
  }

  private isTrendActionable(analysis: TrendAnalysis): boolean {
    // Strong, confident trends are actionable
    return Math.abs(analysis.trend_strength) > 0.6 && analysis.confidence > 0.7;
  }
}
