# Flow Lengkap Proses Store - Cortex Memory MCP Server

## Overview

Proses `store` dalam Cortex Memory MCP Server adalah alur komprehensif untuk menyimpan knowledge items ke dalam database vektor Qdrant dengan berbagai validasi, deduplikasi, dan pengolahan lanjutan.

## 1. Entry Point: MCP Tool Call

### 1.1. Client Request

```typescript
memory_store({
  items: [
    {
      kind: "entity",  // atau 15 jenis lainnya
      content: "Content yang akan disimpan",
      scope?: {
        org?: "organization-name",
        project?: "project-name",
        branch?: "branch-name"
      },
      metadata?: { ... }
    }
  ]
})
```

### 1.2. MCP Server Handler (`handleMemoryStore`)

**Location:** `src/index.ts:881-1042`

```typescript
async function handleMemoryStore(args: { items: any[] }) {
  const startTime = Date.now();
  const batchId = `batch_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

  // 1. Validasi dasar input
  if (!args.items || !Array.isArray(args.items)) {
    throw new Error('items must be an array');
  }

  // 2. Log operasi start dengan audit service
  await auditService.logOperation('memory_store_start', {
    resource: 'knowledge_items',
    scope: { batchId },
    metadata: {
      item_count: args.items.length,
      item_types: args.items.map((item) => item?.kind).filter(Boolean),
      source: 'mcp_tool',
    },
  });
}
```

## 2. Input Validation Layer

### 2.1. MCP Format Validation (`validateMcpInputFormat`)

**Location:** `src/utils/mcp-transform.ts`

```typescript
// Step 1: Validate MCP input format
const mcpValidation = validateMcpInputFormat(args.items);
if (!mcpValidation.valid) {
  await auditService.logOperation('memory_store_validation_failed', {
    resource: 'knowledge_items',
    scope: { batchId },
    success: false,
    severity: 'warn',
    metadata: {
      validation_errors: mcpValidation.errors,
      item_count: args.items.length,
    },
  });
  throw new Error(`Invalid MCP input format: ${mcpValidation.errors.join(', ')}`);
}
```

### 2.2. Validasi yang Dilakukan:

- ✅ `kind` harus salah satu dari 16 jenis yang didukung
- ✅ `content` harus string dan tidak kosong
- ✅ `scope` validasi (org, project, branch format)
- ✅ `metadata` validasi struktur
- ✅ Field wajib sesuai jenis knowledge item

## 3. Input Transformation Layer

### 3.1. MCP to Internal Format (`transformMcpInputToKnowledgeItems`)

**Location:** `src/utils/mcp-transform.ts`

```typescript
// Step 2: Transform MCP input to internal format
const transformedItems = transformMcpInputToKnowledgeItems(args.items);
```

### 3.2. Transformasi yang Dilakukan:

- 🔄 Konversi field names ke internal format
- 🔄 Normalisasi scope defaults
- 🔄 Metadata enrichment
- 🔄 ID generation untuk items tanpa ID
- 🔄 Timestamp assignment (created_at, updated_at)

## 4. Memory Store Orchestrator

### 4.1. Orchestrator Entry Point (`memoryStoreOrchestrator.storeItems`)

**Location:** `src/services/orchestrators/memory-store-orchestrator-qdrant.ts:112-280`

```typescript
async storeItems(items: unknown[]): Promise<MemoryStoreResponse> {
  const startTime = Date.now();
  const stored: StoreResult[] = [];
  const errors: StoreError[] = [];
  const duplicateResults: (DuplicateDetectionResult | null)[] = [];

  // Initialize database if needed
  await this.ensureDatabaseInitialized();

  // Reset duplicate detection stats
  this.duplicateDetectionStats = {
    contentHashMatches: 0,
    semanticSimilarityMatches: 0,
    totalChecks: 0,
  };
}
```

## 5. Comprehensive Validation Layer

### 5.1. Service Layer Validation (`validationService.validateStoreInput`)

**Location:** `src/services/validation/validation-service.ts`

```typescript
// Step 1: Validate input
const validation = await validationService.validateStoreInput(items);
if (!validation.valid) {
  return this.createErrorResponse(validation.errors);
}
```

### 5.2. Validasi yang Dilakukan:

- 🔍 **Business Rules Validation**:
  - ADR Immutability Check untuk jenis `decision`
  - Spec Write Lock Check untuk jenis `ddl`
  - Required Field Validation per jenis
- 🔍 **Content Validation**:
  - Maximum content length check
  - Content format validation
  - Character encoding validation
- 🔍 **Scope Validation**:
  - Organization existence check
  - Project permission check
  - Branch validation

## 6. Chunking Layer (Phase 6 Enhancement)

### 6.1. Intelligent Chunking (`chunkingService.processItemsForStorage`)

**Location:** `src/services/chunking/chunking-service.ts`

```typescript
// Step 2: Apply chunking to all items (replaces 8k truncation)
const chunkedItems = this.chunkingService.processItemsForStorage(validItems);
logger.info(
  {
    original_count: validItems.length,
    chunked_count: chunkedItems.length,
    expansion_ratio: chunkedItems.length / validItems.length,
  },
  'Applied chunking to replace truncation'
);
```

### 6.2. Chunking Process:

- 📄 **Content Analysis**:
  - Identify logical break points
  - Semantic boundary detection
  - Preserve context relationships
- 📄 **Chunk Creation**:
  - Default chunk size: 1000 characters
  - Overlap: 200 characters
  - Metadata inheritance from parent
  - Scope inheritance
- 📄 **Quality Assurance**:
  - Minimum chunk size validation
  - Content integrity checks
  - Semantic coherence validation

### 6.3. Implementation Status:

- ✅ **Basic Chunking**: Content size-based chunking implemented
- ⚠️ **Semantic Chunking**: Basic length-based, not truly semantic yet
- ❌ **Parent/Child Relationships**: Child chunks track parent but no reassembly in find
- ❌ **Context Reassembly**: Find pipeline doesn't stitch chunks back together
- 📋 **Action Needed**: Implement semantic boundary detection and chunk reassembly

## 7. Per-Item Processing Loop

### 7.1. Individual Item Processing

```typescript
// Step 3: Process each chunked item
for (let index = 0; index < chunkedItems.length; index++) {
  const item = chunkedItems[index];

  try {
    // Run duplicate detection
    const duplicateResult = await this.detectDuplicates(item);
    duplicateResults.push(duplicateResult);

    // Process item
    const result = await this.processItem(item, index, duplicateResult);
    stored.push(result);

    // Log successful operation
    await auditService.logStoreOperation(
      result.status === 'deleted' ? 'delete' : result.status === 'updated' ? 'update' : 'create',
      item.kind,
      result.id,
      item.scope,
      undefined,
      true
    );
  } catch (error) {
    // Error handling
  }
}
```

## 8. Duplicate Detection Layer

### 8.1. Comprehensive Duplicate Detection (`detectDuplicates`)

**Location:** `src/services/orchestrators/memory-store-orchestrator-qdrant.ts`

```typescript
async detectDuplicates(item: KnowledgeItem): Promise<DuplicateDetectionResult> {
  this.duplicateDetectionStats.totalChecks++;

  // Step 1: Content Hash Check
  const contentHash = this.generateContentHash(item);
  const existingByHash = await this.findByContentHash(contentHash, item.scope);

  if (existingByHash) {
    this.duplicateDetectionStats.contentHashMatches++;
    return {
      isDuplicate: true,
      similarityScore: 1.0,
      existingItem: existingByHash,
      duplicateType: 'content_hash',
      reason: `Duplicate content detected (hash: ${contentHash.substring(0, 8)}...)`
    };
  }

  // Step 2: Semantic Similarity Check
  const similarItems = await this.findBySemanticSimilarity(item, 0.85);

  if (similarItems.length > 0) {
    this.duplicateDetectionStats.semanticSimilarityMatches++;
    const mostSimilar = similarItems[0];
    return {
      isDuplicate: true,
      similarityScore: mostSimilar.similarity_score,
      existingItem: mostSimilar,
      duplicateType: 'semantic_similarity',
      reason: `Semantic similarity ${(mostSimilar.similarity_score * 100).toFixed(1)}% exceeds threshold 85.0%`
    };
  }

  return {
    isDuplicate: false,
    duplicateType: 'none',
    reason: 'No duplicate found'
  };
}
```

### 8.2. Duplicate Detection Methods:

#### Content Hash Detection:

1. **Hash Generation**: SHA-256 hash dari content + metadata
2. **Database Query**: Cari existing item dengan hash sama
3. **Scope Matching**: Filter berdasarkan scope yang sama
4. **Result**: Exact match detection

#### Semantic Similarity Detection:

1. **Embedding Generation**: Convert content ke vector embedding
2. **Vector Search**: Cari similar items dalam Qdrant
3. **Threshold Check**: Compare dengan threshold 85%
4. **Best Match**: Pilih item dengan similarity tertinggi

### 8.3. Implementation Status:

- ✅ **Content Hash Detection**: Fully implemented with explicit reasons
- ✅ **Semantic Similarity Detection**: Implemented with 85% threshold
- ✅ **Explicit Reasons**: DuplicateDetectionResult includes reason field
- ⚠️ **Dedupe Rules**: Same kind + same scope detection, but time-based rules not documented
- ❌ **Rule Documentation**: 7-day rule and scope rules not clearly defined
- 📋 **Action Needed**: Document actual dedupe rules and add time-based logic

## 9. Item Processing Layer

### 9.1. Individual Item Processing (`processItem`)

```typescript
async processItem(
  item: KnowledgeItem,
  index: number,
  duplicateResult: DuplicateDetectionResult
): Promise<StoreResult> {

  // Handle duplicates
  if (duplicateResult.isDuplicate) {
    return {
      id: duplicateResult.existingItem!.id,
      status: 'skipped_dedupe',
      kind: item.kind,
      created_at: duplicateResult.existingItem!.created_at,
      reason: duplicateResult.reason
    };
  }

  // Process new item
  const storeResult = await this.database.store(item);

  return {
    id: storeResult.id,
    status: 'stored',
    kind: item.kind,
    created_at: new Date().toISOString()
  };
}
```

## 10. Database Storage Layer

### 10.1. Qdrant Vector Storage

**Location:** `src/db/qdrant-client.ts`

```typescript
async store(item: KnowledgeItem): Promise<StoreResult> {
  // Generate embedding
  const embedding = await this.generateEmbedding(item.content);

  // Create point for Qdrant
  const point = {
    id: item.id,
    vector: embedding,
    payload: {
      content: item.content,
      metadata: item.metadata,
      kind: item.kind,
      scope: item.scope,
      created_at: item.created_at,
      content_hash: this.generateContentHash(item),
      ttl_epoch: this.calculateTTLEpoch(item.kind, item.created_at)
    }
  };

  // Store in Qdrant
  await this.qdrantClient.upsert(this.collectionName, {
    points: [point]
  });

  return {
    id: item.id,
    status: 'stored',
    kind: item.kind,
    created_at: item.created_at
  };
}
```

### 10.2. Storage Process:

1. **Embedding Generation**: Convert content ke vector using OpenAI embeddings
2. **Point Creation**: Prepare Qdrant point dengan payload lengkap
3. **TTL Calculation**: Hitung expiry time berdasarkan jenis item
4. **Database Operation**: Upsert ke Qdrant collection
5. **Index Update**: Automatic vector indexing oleh Qdrant

## 11. TTL & Expiry Management

### 11.1. TTL Policy Application

**Location:** `src/utils/tl-utils.ts`

```typescript
const TTL_DURATIONS = {
  short: 30 * 24 * 60 * 60 * 1000, // 30 days
  default: 90 * 24 * 60 * 60 * 1000, // 90 days
  long: 365 * 24 * 60 * 60 * 1000, // 365 days
  permanent: Infinity, // No expiration
};

function getDefaultTTLPolicy(kind: string): TTLPolicy {
  switch (kind) {
    case 'pr_context':
      return 'short'; // 30 days
    case 'entity':
    case 'relation':
    case 'observation':
    case 'decision':
    case 'section':
      return 'long'; // 365 days
    default:
      return 'default'; // 90 days
  }
}
```

### 11.2. TTL Application Rules:

- 🕐 **Short TTL** (30 days): pr_context
- 🕐 **Default TTL** (90 days): Most items (todo, issue, change, etc.)
- 🕐 **Long TTL** (365 days): entity, relation, observation, decision, section
- 🕐 **Permanent TTL** (∞): No items currently permanent

### 11.3. Implementation Status:

- ✅ **TTL Calculation**: Policy-based TTL calculation implemented
- ✅ **Expiry Worker**: Scheduled cleanup worker implemented
- ⚠️ **Qdrant TTL Integration**: TTL calculated but not persisted to Qdrant payload
- ❌ **Automatic Expiry**: Worker exists but expiry_at not stored in Qdrant
- 📋 **Action Needed**: Wire TTL calculation to Qdrant payload and enable worker

## 12. Response Generation

### 12.1. Response Format Creation

```typescript
// Create enhanced response format
const itemResults: ItemResult[] = stored.map((result, index) => {
  const duplicateResult = duplicateResults[index];

  let status: 'stored' | 'skipped_dedupe' | 'business_rule_blocked' | 'validation_error';
  let reason: string | undefined;
  let existingId: string | undefined;

  if (result.status === 'skipped_dedupe' && duplicateResult) {
    status = 'skipped_dedupe';
    reason = duplicateResult.reason;
    existingId = duplicateResult.existingItem?.id;
  } else {
    status = 'stored';
  }

  const itemResult: ItemResult = {
    input_index: index,
    status,
    kind: result.kind,
    id: result.id,
    created_at: result.created_at,
  };

  // Only add optional properties if they have values
  if (reason !== undefined) itemResult.reason = reason;
  if (existingId !== undefined) itemResult.existing_id = existingId;

  return itemResult;
});
```

### 12.2. Summary Calculation

```typescript
const summary: BatchSummary = {
  stored: storedCount,
  skipped_dedupe: skippedDedupeCount,
  business_rule_blocked: 0,
  validation_error: errors.length,
  total: itemResults.length + errors.length,
};
```

## 13. Autonomous Context Generation

### 13.1. Context Generation (`generateAutonomousContext`)

```typescript
async generateAutonomousContext(stored: StoreResult[], errors: StoreError[]): Promise<AutonomousContext> {
  return {
    operations_summary: {
      total_items: stored.length + errors.length,
      successful_stores: stored.filter(s => s.status === 'stored').length,
      duplicates_skipped: stored.filter(s => s.status === 'skipped_dedupe').length,
      validation_errors: errors.length,
      business_rule_blocks: errors.filter(e => e.error_code === 'business_rule_blocked').length
    },
    duplicate_detection_stats: this.duplicateDetectionStats,
    knowledge_graph_changes: this.analyzeGraphChanges(stored),
    performance_metrics: {
      total_duration: Date.now() - startTime,
      average_item_duration: (Date.now() - startTime) / (stored.length + errors.length),
      chunking_efficiency: this.calculateChunkingEfficiency()
    }
  };
}
```

## 14. Audit & Telemetry Layer

### 14.1. Comprehensive Audit Logging

```typescript
// Log batch operation
await auditService.logBatchOperation(
  'store',
  chunkedItems.length,
  stored.length,
  errors.length,
  undefined,
  undefined,
  Date.now() - startTime
);
```

### 14.2. System Metrics Update

```typescript
// Update system metrics
const { systemMetricsService } = await import('./services/metrics/system-metrics.js');
systemMetricsService.updateMetrics({
  operation: 'store',
  data: {
    success,
    kind: transformedItems[0]?.kind || 'unknown',
    item_count: args.items.length,
  },
  duration_ms: duration,
});
```

## 15. Final Response

### 15.1. MCP Response Format

```typescript
return {
  content: [
    {
      type: 'text',
      text: JSON.stringify(
        {
          success,
          stored: response.stored.length,
          stored_items: response.stored,
          errors: response.errors,
          summary: response.summary,
          autonomous_context: response.autonomous_context,
          total: args.items.length,
          audit_metadata: {
            batch_id: batchId,
            duration_ms: duration,
            audit_logged: true,
          },
        },
        null,
        2
      ),
    },
  ],
};
```

## 16. Error Handling

### 16.1. Error Categories

1. **Validation Errors**: Input format atau business rule violations
2. **Processing Errors**: Database connection, embedding generation
3. **System Errors: Memory**, network, atau resource exhaustion

### 16.2. Error Response Format

```typescript
{
  success: false,
  stored: 0,
  stored_items: [],
  errors: [{
    index: 0,
    error_code: 'VALIDATION_ERROR',
    message: 'Invalid item kind: unsupported_type',
    details: { field: 'kind', value: 'unsupported_type' }
  }],
  summary: {
    stored: 0,
    skipped_dedupe: 0,
    business_rule_blocked: 0,
    validation_error: 1,
    total: 1
  },
  autonomous_context: { ... },
  total: 1,
  audit_metadata: { ... }
}
```

## Flow Summary

### Complete Flow Steps:

1. ✅ **MCP Tool Call** → Client memanggil `memory_store`
2. ✅ **Basic Validation** → Format array checking
3. ✅ **Audit Log Start** → Log operasi dimulai
4. ✅ **MCP Format Validation** → Validasi format MCP input
5. ✅ **Input Transformation** → Konversi ke internal format
6. ✅ **Service Layer Validation** → Business rules & content validation
7. ✅ **Chunking Application** → Intelligent content chunking
8. ✅ **Duplicate Detection** → Content hash + semantic similarity
9. ✅ **Individual Item Processing** → Proses per-item loop
10. ✅ **Database Storage** → Qdrant vector storage dengan TTL
11. ✅ **Response Generation** → Format response MCP
12. ✅ **Autonomous Context** → Generate context & insights
13. ✅ **Audit & Telemetry** → Log operasi & update metrics
14. ✅ **Final Response** → Kembalikan response ke client

### Key Features:

- 🔍 **Comprehensive Validation**: Multi-layer validation dengan business rules
- 🧠 **Intelligent Chunking**: Replace 8k truncation dengan semantic chunking
- 🔄 **Advanced Deduplication**: Content hash + semantic similarity detection
- ⏰ **TTL Management**: Otomatis expiry berdasarkan jenis item
- 📊 **Rich Analytics**: Detailed metrics & autonomous context
- 🛡️ **Error Resilience**: Comprehensive error handling & recovery
- 📝 **Complete Audit**: Full operation tracking & logging

## Known Gaps & Implementation Status (2025-10-31)

### ⚠️ Partially Implemented Features:

1. **Semantic Chunking**: Currently length-based, not truly semantic
2. **Chunk Reassembly**: Find pipeline doesn't stitch chunks back together
3. **TTL Integration**: Calculated but not persisted to Qdrant
4. **Dedupe Rules**: Time-based rules not clearly documented

### ❌ Missing Features:

1. **Parent/Child Graph Navigation**: No chunk relationship navigation
2. **TTL Automatic Purging**: Worker exists but expiry data not stored
3. **MCP Schema Enforcement**: Basic validation but not strict schema

### 📋 Action Items:

- Implement semantic boundary detection for chunking
- Add chunk reassembly in find pipeline
- Wire TTL calculation to Qdrant payload
- Document and implement time-based dedupe rules
- Add comprehensive MCP input validation
- Create integration tests for all features

### 🎯 Production Readiness:

- **Core Functionality**: ✅ Working (store/find items)
- **Advanced Features**: ⚠️ Partial (chunking, TTL, dedupe)
- **Enterprise Features**: ❌ Missing (strict validation, comprehensive testing)
- **Documentation**: ✅ Complete with status tracking
