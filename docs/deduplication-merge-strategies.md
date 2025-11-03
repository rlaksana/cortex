# Enhanced Deduplication and Merge Strategies

## Overview

The Cortex Memory MCP server features advanced configurable deduplication with 5 distinct merge strategies, enabling intelligent duplicate detection and content merging based on configurable similarity thresholds, time windows, and scope rules.

## Configuration Options

### Core Deduplication Settings

- **Similarity Threshold** (0.5-1.0): Controls how strict duplicate detection is
  - `0.95`: Very strict (only near-identical content)
  - `0.85`: Standard balanced approach
  - `0.70`: More lenient (catches more potential duplicates)
  - `0.50`: Very lenient (may have false positives)

- **Time Window** (1-365 days): Temporal scope for duplicate consideration
  - Limits deduplication to items within specified time range
  - Prevents very old content from being considered duplicates
  - Useful for time-sensitive knowledge domains

- **Scope Filtering**: Controls cross-scope deduplication behavior
  - **Same Scope Only**: Only dedupe within same project/org/branch
  - **Cross-Scope**: Allow deduplication across different scopes
  - **Scope Priority**: Weight org > project > branch matching

## Merge Strategies

### 1. Skip Strategy

**Behavior**: Completely skip duplicate items without any modification.

**Use Case**: When you want to preserve existing knowledge exactly as-is.

**Configuration**:
```json
{
  "merge_strategy": "skip",
  "similarity_threshold": 0.85
}
```

**Results**:
- Items above threshold are skipped
- Existing content remains unchanged
- Audit log records skip action with similarity score

**Example Response**:
```json
{
  "action": "skipped",
  "similarity_score": 0.92,
  "reason": "Duplicate skipped due to merge strategy: skip",
  "existing_id": "existing-item-id"
}
```

### 2. Prefer Existing Strategy

**Behavior**: Always keep the existing item, regardless of new content.

**Use Case**: When historical records should take precedence over new information.

**Configuration**:
```json
{
  "merge_strategy": "prefer_existing",
  "similarity_threshold": 0.80
}
```

**Results**:
- Existing items are always preserved
- New items are discarded when duplicates are found
- Useful for maintaining data integrity

### 3. Prefer Newer Strategy

**Behavior**: Replace existing items with newer versions based on timestamps.

**Use Case**: When recent information should override historical data.

**Configuration**:
```json
{
  "merge_strategy": "prefer_newer",
  "similarity_threshold": 0.85,
  "time_window_days": 30
}
```

**Logic**:
1. Compare `created_at` and `updated_at` timestamps
2. If newer item is within time window, replace existing
3. Otherwise, keep existing item

**Results**:
- "updated" action when newer item replaces existing
- "skipped" action when existing item is newer

### 4. Combine Strategy

**Behavior**: Intelligently merge fields from both items.

**Use Case**: When you want to combine knowledge from multiple sources.

**Configuration**:
```json
{
  "merge_strategy": "combine",
  "similarity_threshold": 0.75
}
```

**Merge Logic**:
- **Content Fields**: Prefer longer, more complete content
- **Metadata**: Merge metadata fields with newer values taking precedence
- **Arrays**: Combine unique elements
- **Object Fields**: Deep merge with conflict resolution

**Merge Details**:
```json
{
  "strategy": "combine",
  "fields_merged": ["content", "tags", "metadata"],
  "conflicts_resolved": ["description"],
  "new_fields_added": ["additional_info"],
  "merge_duration": 45
}
```

### 5. Intelligent Strategy (Default)

**Behavior**: Multi-factor analysis to determine optimal merge approach.

**Use Case**: When you want sophisticated decision-making for each duplicate.

**Configuration**:
```json
{
  "merge_strategy": "intelligent",
  "similarity_threshold": 0.85,
  "enable_semantic_analysis": true,
  "prioritize_same_scope": true
}
```

**Decision Factors**:

#### Time Analysis (40% weight)
- **Newer content**: Prefer if recently updated and within time window
- **Freshness bonus**: Items updated in last 24 hours get preference
- **Historical preservation**: Very old items may be preserved for reference

#### Scope Analysis (30% weight)
- **Same scope preference**: Items in same project/org get preference
- **Scope match score**: Higher score increases merge preference
- **Cross-scope handling**: Different scopes may be kept separate

#### Content Quality (20% weight)
- **Completeness**: Longer, more detailed content preferred
- **Structure**: Well-structured content with proper formatting
- **Richness**: Items with more metadata and tags preferred

#### Content Similarity (10% weight)
- **High similarity (≥95%)**: May prefer newer version
- **Medium similarity (85-95%)**: Usually combine content
- **Low similarity (<85%)**: Store as separate items

**Intelligent Merge Outcomes**:

1. **Exact Match + Newer**: Replace with newer version
2. **High Similarity + Better Content**: Intelligent field combination
3. **Medium Similarity + Same Scope**: Combine with scope preference
4. **Low Similarity**: Store as separate items

## Configuration Examples

### Strict Deduplication
```json
{
  "dedupe_global_config": {
    "enabled": true,
    "similarity_threshold": 0.95,
    "merge_strategy": "skip",
    "audit_logging": true
  }
}
```

### Aggressive Merging
```json
{
  "dedupe_global_config": {
    "enabled": true,
    "similarity_threshold": 0.70,
    "merge_strategy": "combine",
    "audit_logging": true
  }
}
```

### Time-Sensitive Processing
```json
{
  "dedupe_global_config": {
    "enabled": true,
    "similarity_threshold": 0.85,
    "merge_strategy": "prefer_newer",
    "audit_logging": true
  },
  "items": [
    {
      "kind": "decision",
      "content": "Architecture decision",
      "dedupe_config": {
        "time_window_days": 7,
        "cross_scope_dedupe": false,
        "scope_only": true
      }
    }
  ]
}
```

### Intelligent Cross-Project Deduplication
```json
{
  "dedupe_global_config": {
    "enabled": true,
    "similarity_threshold": 0.85,
    "merge_strategy": "intelligent",
    "audit_logging": true
  },
  "items": [
    {
      "kind": "entity",
      "content": "User service component",
      "dedupe_config": {
        "cross_scope_dedupe": true,
        "scope_only": false,
        "time_window_days": 30
      }
    }
  ]
}
```

## Audit Logging

All deduplication decisions are logged with comprehensive details:

### Audit Entry Structure
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "item_id": "item-123",
  "action": "merged",
  "similarity_score": 0.92,
  "strategy": "intelligent",
  "match_type": "content",
  "scope": {
    "project": "my-project",
    "org": "my-org"
  },
  "existing_id": "existing-456",
  "reason": "Intelligently merged based on content, time, and scope analysis",
  "merge_details": {
    "strategy": "intelligent",
    "fields_merged": ["content", "metadata"],
    "conflicts_resolved": ["description"],
    "merge_duration": 67
  },
  "config_snapshot": {
    "similarity_threshold": 0.85,
    "merge_strategy": "intelligent"
  }
}
```

### Performance Metrics
```json
{
  "totalProcessed": 100,
  "duplicatesFound": 25,
  "mergesPerformed": 15,
  "avgProcessingTime": 45,
  "avgSimilarityScore": 0.87
}
```

## Best Practices

### 1. Choose Appropriate Similarity Threshold
- **0.90-0.95**: For technical documentation, code, specifications
- **0.80-0.90**: For business documents, decisions, requirements
- **0.70-0.80**: For general knowledge, notes, observations

### 2. Configure Time Windows Appropriately
- **1-7 days**: For fast-changing domains (news, incidents)
- **30 days**: Standard for most business knowledge
- **90+ days**: For stable reference material

### 3. Use Scope Filtering Effectively
- Enable cross-scope deduplication for shared organizational knowledge
- Use scope-only filtering for project-specific information
- Consider org-level vs project-level separation needs

### 4. Monitor and Tune
- Review audit logs regularly
- Adjust thresholds based on false positive/negative rates
- Monitor performance metrics for optimization opportunities

### 5. Test Different Strategies
- Start with "intelligent" strategy for balanced approach
- Use "skip" for data integrity requirements
- Use "combine" for knowledge aggregation scenarios
- Use "prefer_newer" for rapidly evolving information

## Troubleshooting

### High False Positive Rate
- Increase similarity threshold
- Enable scope-only filtering
- Reduce time window

### High False Negative Rate
- Decrease similarity threshold
- Enable cross-scope deduplication
- Increase time window
- Enable semantic analysis

### Performance Issues
- Reduce `maxItemsToCheck` setting
- Enable batch processing
- Consider disabling audit logging for high-volume scenarios

### Unexpected Merge Behavior
- Review audit logs for decision rationale
- Check configuration priority (global vs per-item)
- Verify timestamp accuracy in source data
- Consider scope match scores affecting decisions

## Migration from Basic Deduplication

The enhanced system is backward compatible with existing basic deduplication:

1. **Existing Configurations**: Continue to work with default intelligent strategy
2. **Gradual Migration**: Start with basic configurations, then add advanced options
3. **A/B Testing**: Compare new strategies with existing behavior
4. **Rollback**: Can disable enhanced features if needed

## Future Enhancements

Planned improvements to the deduplication system:

1. **Machine Learning**: ML-based similarity scoring
2. **Custom Similarity Functions**: Domain-specific similarity algorithms
3. **Graph-based Deduplication**: Relationship-aware duplicate detection
4. **Real-time Deduplication**: Streaming duplicate detection
5. **Multi-language Support**: Cross-language content deduplication