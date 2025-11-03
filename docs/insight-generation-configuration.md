# Insight Generation Configuration

This document provides comprehensive configuration examples and usage guidelines for the Insight Generation system in Cortex Memory MCP.

## Overview

The Insight Generation system analyzes stored knowledge items to generate actionable insights, patterns, connections, recommendations, anomaly detection, and trend analysis. It's designed to be lightweight, configurable, and production-safe with environment-based controls.

## Environment Configuration

### Basic Environment Variables

```bash
# Enable/disable insight generation
INSIGHT_GENERATION_ENABLED=false                    # Default: false (production-safe)
INSIGHT_GENERATION_ENV_ENABLED=false               # Default: false (environment-specific)

# Generation settings
INSIGHT_GENERATION_MAX_INSIGHTS_PER_ITEM=3         # Default: 3
INSIGHT_GENERATION_MAX_INSIGHTS_PER_BATCH=10       # Default: 10
INSIGHT_GENERATION_CONFIDENCE_THRESHOLD=0.6        # Default: 0.6
INSIGHT_GENERATION_PROCESSING_TIMEOUT=5000         # Default: 5000ms

# Performance settings
INSIGHT_GENERATION_PERFORMANCE_THRESHOLD=5         # Default: 5% max impact
INSIGHT_GENERATION_CACHE_TTL=3600                  # Default: 3600 seconds

# Insight type controls
INSIGHT_GENERATION_PATTERNS_ENABLED=true           # Default: true
INSIGHT_GENERATION_CONNECTIONS_ENABLED=true       # Default: true
INSIGHT_GENERATION_RECOMMENDATIONS_ENABLED=true   # Default: true
INSIGHT_GENERATION_ANOMALIES_ENABLED=false        # Default: false (noise prevention)
INSIGHT_GENERATION_TRENDS_ENABLED=false           # Default: false (requires historical data)
```

## Development Environment Example

```bash
# .env.development
NODE_ENV=development
INSIGHT_GENERATION_ENABLED=true
INSIGHT_GENERATION_ENV_ENABLED=true
INSIGHT_GENERATION_PATTERNS_ENABLED=true
INSIGHT_GENERATION_CONNECTIONS_ENABLED=true
INSIGHT_GENERATION_RECOMMENDATIONS_ENABLED=true
INSIGHT_GENERATION_ANOMALIES_ENABLED=true
INSIGHT_GENERATION_TRENDS_ENABLED=true
INSIGHT_GENERATION_CONFIDENCE_THRESHOLD=0.5
INSIGHT_GENERATION_MAX_INSIGHTS_PER_BATCH=20
```

## Production Environment Example

```bash
# .env.production
NODE_ENV=production
INSIGHT_GENERATION_ENABLED=false                  # Disabled by default for safety
INSIGHT_GENERATION_ENV_ENABLED=false              # Explicitly disabled
INSIGHT_GENERATION_PATTERNS_ENABLED=false         # All types disabled
INSIGHT_GENERATION_CONNECTIONS_ENABLED=false
INSIGHT_GENERATION_RECOMMENDATIONS_ENABLED=false
INSIGHT_GENERATION_ANOMALIES_ENABLED=false
INSIGHT_GENERATION_TRENDS_ENABLED=false
```

## Staging Environment Example

```bash
# .env.staging
NODE_ENV=production
INSIGHT_GENERATION_ENABLED=false                  # Keep disabled by default
INSIGHT_GENERATION_ENV_ENABLED=true               # Enable environment control
INSIGHT_GENERATION_PATTERNS_ENABLED=true          # Enable selective types
INSIGHT_GENERATION_CONNECTIONS_ENABLED=true
INSIGHT_GENERATION_RECOMMENDATIONS_ENABLED=true
INSIGHT_GENERATION_ANOMALIES_ENABLED=false        # Keep noise generators disabled
INSIGHT_GENERATION_TRENDS_ENABLED=false
INSIGHT_GENERATION_CONFIDENCE_THRESHOLD=0.8       # Higher threshold for production
INSIGHT_GENERATION_PERFORMANCE_THRESHOLD=2         # Lower performance impact
```

## Runtime Configuration

The Insight Generation service can also be configured at runtime using the configuration system:

```typescript
import { insightGenerationService } from './services/insights/insight-generation-service.js';

// Update configuration at runtime
insightGenerationService.updateConfig({
  max_insights_per_item: 5,
  max_insights_per_batch: 15,
  min_confidence_threshold: 0.7,
  insight_types: {
    patterns: {
      ...insightGenerationService.getConfig().insight_types.patterns,
      enabled: true,
      confidence_threshold: 0.8,
    },
  },
});
```

## Usage Examples

### Basic Memory Store with Insights

```typescript
import { memoryStore } from './services/memory-store.js';

// Store items with insights enabled
const response = await memoryStore(items, { insight: true });

// Check insight results
if (response.meta.insights) {
  console.log(`Generated ${response.meta.insights.total_insights} insights`);
  console.log(`Average confidence: ${response.meta.insights.average_confidence}`);
  console.log(`Processing time: ${response.meta.insights.processing_time_ms}ms`);
  console.log(`Performance impact: ${response.meta.insights.performance_impact}%`);
}
```

### Selective Insight Type Generation

```typescript
// Generate only specific insight types
const insightResponse = await insightGenerationService.generateInsights({
  items: storedItems,
  options: {
    enabled: true,
    insight_types: ['patterns', 'connections'], // Only these types
    max_insights_per_item: 2,
    confidence_threshold: 0.7,
    include_metadata: true,
  },
  scope: { project: 'my-project' },
});
```

### High-Confidence Insights Only

```typescript
const highConfidenceResponse = await memoryStore(items, {
  insight: true,
  // Custom options can be added here for future extensions
});
```

## Performance Metrics

The system tracks comprehensive performance metrics:

```typescript
const metrics = insightGenerationService.getMetrics();

console.log('Insight Generation Metrics:');
console.log(`Total insights generated: ${metrics.total_insights_generated}`);
console.log(`Generation success rate: ${metrics.generation_success_rate * 100}%`);
console.log(`Average processing time: ${metrics.processing_time_avg}ms`);
console.log(`Average performance impact: ${metrics.performance_impact_avg}%`);
console.log(`Cache hit rate: ${metrics.cache_hit_rate * 100}%`);
console.log(`Error rate: ${metrics.error_rate * 100}%`);
```

## Insight Types Configuration

### Pattern Recognition
- **Purpose**: Identify recurring patterns and keywords
- **Default Confidence**: 0.7
- **Typical Use Cases**:
  - Finding frequently mentioned topics
  - Identifying recurring themes
  - Detecting keyword patterns

```typescript
// Example pattern insight
{
  "type": "patterns",
  "title": "Recurring Pattern: \"authentication\"",
  "description": "The term \"authentication\" appears frequently across stored items",
  "confidence": 0.85,
  "category": "pattern",
  "pattern_data": {
    "pattern_type": "keyword_frequency",
    "frequency": 8,
    "strength": 0.73
  }
}
```

### Connection Analysis
- **Purpose**: Find relationships between items
- **Default Confidence**: 0.6
- **Typical Use Cases**:
  - Project scope connections
  - Kind-based relationships
  - Shared context detection

```typescript
// Example connection insight
{
  "type": "connections",
  "title": "Project Connection: auth-service",
  "description": "Multiple items are related to project \"auth-service\"",
  "confidence": 0.92,
  "category": "connection",
  "connection_data": {
    "connection_type": "project_scope",
    "relationship_strength": 0.92,
    "source_items": ["item-1", "item-2"],
    "target_items": ["item-3", "item-4"]
  }
}
```

### Action Recommendations
- **Purpose**: Suggest actionable steps
- **Default Confidence**: 0.8 (higher threshold)
- **Typical Use Cases**:
  - Issue resolution recommendations
  - Task management suggestions
  - Decision documentation needs

```typescript
// Example recommendation insight
{
  "type": "recommendations",
  "title": "Address Multiple Issues",
  "description": "Multiple issues detected - prioritize resolution",
  "confidence": 0.88,
  "category": "recommendation",
  "actionable": true,
  "recommendation_data": {
    "action_type": "resolve_issues",
    "priority": "high",
    "effort_estimate": "medium",
    "impact_assessment": "high",
    "success_probability": 0.85
  }
}
```

### Anomaly Detection
- **Purpose**: Detect unusual patterns
- **Default Confidence**: 0.9 (highest threshold)
- **Default State**: Disabled (noise prevention)
- **Typical Use Cases**:
  - Distribution anomalies
  - Unusual concentration patterns
  - Outlier detection

```typescript
// Example anomaly insight
{
  "type": "anomalies",
  "title": "Unusual Pattern: issue Items",
  "description": "Higher than expected concentration of \"issue\" items detected",
  "confidence": 0.94,
  "category": "anomaly",
  "anomaly_data": {
    "anomaly_type": "distribution_skew",
    "severity": "high",
    "deviation_score": 3.2,
    "potential_causes": ["Focused work", "Data collection bias"]
  }
}
```

### Trend Analysis
- **Purpose**: Identify temporal trends
- **Default Confidence**: 0.7
- **Default State**: Disabled (requires historical data)
- **Typical Use Cases**:
  - Knowledge accumulation trends
  - Activity patterns over time
  - Topic evolution analysis

```typescript
// Example trend insight
{
  "type": "trends",
  "title": "Knowledge Accumulation Trend",
  "description": "Continuous knowledge accumulation detected",
  "confidence": 0.78,
  "category": "trend",
  "trend_data": {
    "trend_direction": "increasing",
    "trend_strength": 0.75,
    "time_period": {
      "start": "2025-01-01T00:00:00Z",
      "end": "2025-01-08T00:00:00Z"
    }
  }
}
```

## Best Practices

### Production Deployment
1. **Start Disabled**: Always begin with `INSIGHT_GENERATION_ENABLED=false`
2. **Enable Gradually**: Enable one insight type at a time
3. **Monitor Performance**: Watch performance impact metrics closely
4. **High Confidence**: Use higher confidence thresholds in production
5. **Set Limits**: Configure appropriate batch and per-item limits

### Performance Optimization
1. **Enable Caching**: Keep `INSIGHT_GENERATION_CACHE_TTL` at reasonable values
2. **Filter Early**: Use appropriate confidence thresholds
3. **Batch Processing**: Process items in optimal batch sizes
4. **Monitor Impact**: Keep performance impact under configured thresholds

### Development and Testing
1. **Enable All Types**: Use development environment to test all insight types
2. **Lower Thresholds**: Use lower confidence thresholds for testing
3. **Increase Limits**: Use higher batch limits for comprehensive testing
4. **Monitor Logs**: Enable debug logging for detailed insight generation analysis

## Troubleshooting

### Common Issues

**No Insights Generated**
- Check if insight generation is enabled
- Verify confidence thresholds aren't too high
- Ensure sufficient data for analysis
- Check if specific insight types are enabled

**High Performance Impact**
- Reduce `INSIGHT_GENERATION_MAX_INSIGHTS_PER_BATCH`
- Increase `INSIGHT_GENERATION_CONFIDENCE_THRESHOLD`
- Disable noisy insight types (anomalies, trends)
- Reduce processing timeout

**Insight Quality Issues**
- Adjust confidence thresholds per insight type
- Enable/disable specific insight types based on use case
- Review insight filtering and prioritization settings
- Check data quality and content structure

### Monitoring and Debugging

```typescript
// Enable debug logging for insight generation
process.env.LOG_LEVEL = 'debug';

// Monitor insight service metrics
const metrics = insightGenerationService.getMetrics();
if (metrics.error_rate > 0.1) {
  console.warn('High error rate in insight generation');
}

// Reset metrics if needed
insightGenerationService.resetMetrics();
```

## Integration Examples

### API Endpoint Integration

```typescript
app.post('/memory/store', async (req, res) => {
  const { items, insights = false } = req.body;

  try {
    const response = await memoryStore(items, { insight: insights });

    res.json({
      success: true,
      stored: response.summary.stored,
      insights: response.meta.insights,
      processing_time: response.observability.execution_time_ms,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
```

### Background Job Integration

```typescript
// Generate insights for existing stored items
async function generateInsightsForExistingItems() {
  const existingItems = await getStoredItems({ limit: 100 });

  const insightResponse = await insightGenerationService.generateInsights({
    items: existingItems,
    options: {
      enabled: true,
      insight_types: ['patterns', 'connections'],
      max_insights_per_item: 2,
      confidence_threshold: 0.7,
    },
    scope: { project: 'background-analysis' },
  });

  // Store insights or process as needed
  console.log(`Generated ${insightResponse.metadata.total_insights} insights`);
}
```

This configuration guide provides comprehensive examples and best practices for implementing and managing the Insight Generation system in various environments and use cases.