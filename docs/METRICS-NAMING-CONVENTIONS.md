# Cortex Memory MCP - Metrics Naming Conventions

**Version:** v2.0.0
**Last Updated:** 2025-11-03

---

## 📊 **Overview**

This document defines the standardized naming conventions and categorization for all metrics collected by the Cortex Memory MCP system. Consistent naming ensures clarity, maintainability, and effective monitoring across all components.

---

## 🎯 **Naming Convention Standards**

### **Format Pattern**

```
{category}.{subcategory}.{metric_name}.{unit}
```

### **Naming Rules**

- **Lowercase**: All metric names must be lowercase
- **Underscore Separators**: Use underscores between words
- **Hierarchical Structure**: Category → Subcategory → Specific metric
- **Unit Suffix**: Always include units when applicable
- **Descriptive Names**: Clear, self-explanatory metric names
- **Consistent Verbs**: Use consistent action verbs (rate, count, duration, size)

---

## 📈 **Metric Categories**

### **1. Performance Metrics (`perf`)**

#### **Response Time Metrics**

```
perf.store.duration_ms          # Average store operation duration
perf.find.duration_ms           # Average find operation duration
perf.validation.duration_ms     # Average validation duration
perf.chunking.duration_ms       # Average chunking duration
perf.cleanup.duration_ms        # Average cleanup operation duration
perf.total.duration_ms          # Total operation duration
```

#### **Throughput Metrics**

```
perf.operations.rate_per_sec    # Operations per second
perf.store.rate_per_sec         # Store operations per second
perf.find.rate_per_sec          # Find operations per second
perf.cleanup.rate_per_sec       # Cleanup operations per second
```

### **2. Database Metrics (`db`)**

#### **Operation Metrics**

```
db.items.total_count            # Total items in database
db.items.by_type.{type}_count   # Items by knowledge type
db.items.expired_count          # Expired items count
db.items.active_count           # Active items count
db.collections.total_count      # Total collections
db.collections.size_bytes       # Collection size in bytes
```

#### **Connection Metrics**

```
db.connections.active_count     # Active database connections
db.connections.pool_size        # Connection pool size
db.connections.max_reached      # Maximum connections reached
db.connections.errors_count     # Connection errors count
```

### **3. Deduplication Metrics (`dedupe`)**

#### **Detection Metrics**

```
dedupe.items.processed_count    # Items processed for deduplication
dedupe.duplicates_detected_count # Duplicates detected
dedupe.similarity.avg_score     # Average similarity score
dedupe.similarity.min_score     # Minimum similarity score
dedupe.similarity.max_score     # Maximum similarity score
```

#### **Merge Operation Metrics**

```
dedupe.merge.total_count        # Total merge operations
dedupe.merge.skip_count         # Items skipped (merge strategy)
dedupe.merge.combine_count      # Items combined
dedupe.merge.intelligent_count  # Intelligent merges
dedupe.merge.conflicts_count    # Merge conflicts resolved
```

### **4. Validation Metrics (`validation`)**

#### **Item Validation**

```
validation.items.processed_count      # Items validated
validation.items.failed_count         # Validation failures
validation.items.business_blocks_count # Business rule blocks
validation.fail_rate_percent          # Validation failure rate
```

#### **Schema Validation**

```
validation.schema.pass_count          # Schema validation passes
validation.schema.fail_count          # Schema validation failures
validation.schema.errors_by_type      # Errors by validation type
```

### **5. Chunking Metrics (`chunking`)**

#### **Processing Metrics**

```
chunking.items.processed_count        # Items chunked
chunking.chunks.generated_count       # Chunks generated
chunking.avg_chunks_per_item          # Average chunks per item
chunking.avg_chunk_size_chars         # Average chunk size (characters)
chunking.success_rate_percent         # Chunking success rate
```

#### **Semantic Analysis**

```
chunking.semantic.boundaries_count   # Semantic boundaries found
chunking.semantic.analysis_count      # Semantic analysis operations
chunking.semantic.accuracy_percent    # Semantic analysis accuracy
```

### **6. Cleanup Metrics (`cleanup`)**

#### **Operation Metrics**

```
cleanup.operations.run_count          # Cleanup operations run
cleanup.items.deleted_count           # Items deleted
cleanup.items.dryrun_count           # Items identified in dry-run
cleanup.duration_ms                  # Cleanup operation duration
cleanup.success_rate_percent         # Cleanup success rate
```

#### **Safety Metrics**

```
cleanup.backup.operations_count       # Backup operations
cleanup.backup.size_bytes             # Backup size
cleanup.confirmations.required_count  # Confirmations required
cleanup.confirmations.completed_count # Confirmations completed
```

### **7. System Metrics (`system`)**

#### **Resource Metrics**

```
system.memory.rss_bytes              # Resident set size
system.memory.heap_used_bytes        # Heap memory used
system.memory.heap_total_bytes       # Total heap memory
system.cpu.utilization_percent        # CPU utilization
system.uptime.seconds                # System uptime
```

#### **Process Metrics**

```
system.process.pid                    # Process ID
system.process.threads_count         # Thread count
system.process.file_descriptors_count # Open file descriptors
system.process.errors_count           # Process errors
```

### **8. Rate Limiting Metrics (`ratelimit`)**

#### **Request Metrics**

```
ratelimit.requests.total_count       # Total requests
ratelimit.requests.blocked_count     # Blocked requests
ratelimit.requests.allowed_count     # Allowed requests
ratelimit.block_rate_percent         # Block rate percentage
```

#### **Policy Metrics**

```
ratelimit.policies.active_count      # Active rate limit policies
ratelimit.actors.active_count        # Active actors
ratelimit.windows.active_count       # Active time windows
```

### **9. Error Metrics (`errors`)**

#### **General Error Metrics**

```
errors.total_count                    # Total errors
errors.by_type.{error_type}_count     # Errors by type
errors.by_tool.{tool_name}_count      # Errors by tool
errors.recovery_attempts_count        # Error recovery attempts
errors.recovery_success_rate_percent  # Recovery success rate
```

#### **Circuit Breaker Metrics**

```
errors.circuit_breaker.trips_count   # Circuit breaker trips
errors.circuit_breaker.recovery_time_ms # Circuit breaker recovery time
errors.circuit_breaker.state          # Circuit breaker state (0=closed,1=open,2=half-open)
```

### **10. Business Metrics (`business`)**

#### **Knowledge Type Distribution**

```
business.knowledge_types.{type}_count # Knowledge items by type
business.scopes.active_count          # Active scopes
business.scopes.project_count         # Project scopes
business.scopes.branch_count          # Branch scopes
business.scopes.org_count             # Organization scopes
```

#### **Content Metrics**

```
business.content.avg_size_chars       # Average content size
business.content.total_size_chars     # Total content size
business.content.truncated_count      # Truncated items
business.content.expansion_count      # Content expansions
```

---

## 🏷️ **Tag Standards**

### **Standard Tags**

- **`operation_type`**: `store`, `find`, `cleanup`, `validate`
- **`knowledge_type`**: `entity`, `relation`, `observation`, etc.
- **`scope`**: Project, branch, organization context
- **`strategy`**: Operation strategy used
- **`status`**: `success`, `failure`, `partial`
- **`error_type`**: Type of error if applicable
- **`tool_name`**: MCP tool name
- **`actor_id`**: Unique actor identifier

### **Tag Formatting**

- **Lowercase**: All tags must be lowercase
- **Underscore Separators**: Use underscores for multi-word tags
- **Consistent Values**: Use consistent value formats across tags

---

## 📊 **Metric Types**

### **Counter Metrics**

- **Purpose**: Counting events or occurrences
- **Suffix**: `_count`
- **Examples**: `requests.total_count`, `errors.total_count`

### **Gauge Metrics**

- **Purpose**: Current values that can increase or decrease
- **Suffix**: `_value`, `_bytes`, `_percent`
- **Examples**: `system.memory.heap_used_bytes`, `system.cpu.utilization_percent`

### **Histogram Metrics**

- **Purpose**: Distribution of values (durations, sizes)
- **Suffix**: `_duration_ms`, `_size_bytes`
- **Examples**: `perf.store.duration_ms`, `db.collections.size_bytes`

### **Rate Metrics**

- **Purpose**: Rate of occurrences over time
- **Suffix**: `_rate_per_sec`, `_percent`
- **Examples**: `perf.operations.rate_per_sec`, `validation.fail_rate_percent`

---

## 🔧 **Implementation Guidelines**

### **Code Integration**

```typescript
// Example metric naming in code
this.metrics.record('perf.store.duration_ms', duration, {
  operation_type: 'store',
  knowledge_type: item.kind,
  status: 'success',
});

this.metrics.increment('db.items.total_count', 1, {
  knowledge_type: item.kind,
  scope: item.scope?.project || 'global',
});
```

### **Monitoring Integration**

```yaml
# Prometheus example
- name: cortex_perf_store_duration_ms
  type: histogram
  help: Average store operation duration in milliseconds

- name: cortex_dedupe_merge_total_count
  type: counter
  help: Total number of merge operations
```

### **Dashboard Organization**

- **Performance Dashboard**: `perf.*` metrics
- **Database Dashboard**: `db.*` metrics
- **Business Dashboard**: `business.*` metrics
- **System Dashboard**: `system.*`, `errors.*` metrics
- **Operations Dashboard**: `cleanup.*`, `ratelimit.*` metrics

---

## 📋 **Quality Standards**

### **Metric Review Checklist**

- [ ] Name follows naming convention pattern
- [ ] Unit suffix is appropriate and consistent
- [ ] Description is clear and meaningful
- [ ] Tags are relevant and standardized
- [ ] Metric type is appropriate for data
- [ ] Dashboard placement is logical
- [ ] Alert thresholds are reasonable
- [ ] Historical data retention is defined

### **New Metric Process**

1. **Review Naming Convention**: Ensure compliance with standards
2. **Check for Duplicates**: Verify similar metrics don't exist
3. **Define Purpose**: Clear documentation of metric purpose
4. **Implement with Tags**: Include relevant standard tags
5. **Dashboard Integration**: Add to appropriate dashboard
6. **Alert Configuration**: Set up appropriate alerts
7. **Documentation Update**: Update this document

---

## 🚀 **Best Practices**

### **Do's**

- ✅ Use descriptive, self-explanatory names
- ✅ Include units in metric names
- ✅ Apply consistent tagging across similar metrics
- ✅ Group related metrics in dashboards
- ✅ Document complex metrics clearly
- ✅ Review metric usage regularly

### **Don'ts**

- ❌ Use abbreviations or unclear acronyms
- ❌ Mix naming conventions
- ❌ Create duplicate or overlapping metrics
- ❌ Use inconsistent tag values
- ❌ Ignore metric cardinality limits
- ❌ Forget to document new metrics

---

## 📞 **Support & Maintenance**

### **Metric Ownership**

- **Performance Metrics**: Performance engineering team
- **Database Metrics**: Database administration team
- **Business Metrics**: Product and analytics team
- **System Metrics**: DevOps and infrastructure team

### **Review Schedule**

- **Weekly**: New metric reviews and compliance checks
- **Monthly**: Dashboard optimization and alert tuning
- **Quarterly**: Metric strategy and naming convention reviews
- **Annually**: Complete metrics taxonomy review

---

**Document Owner**: Cortex Development Team
**Review Date**: 2025-11-03
**Next Review**: 2025-12-03

_For questions or suggestions about metrics naming conventions, please contact the Cortex development team or create an issue in the project repository._
