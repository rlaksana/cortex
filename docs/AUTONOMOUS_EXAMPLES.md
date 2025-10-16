# Autonomous Collaboration Examples

Complete examples showing how Claude Code autonomously manages memory without user prompts.

## Example 1: User Shares New Information

**User**: "We're using PostgreSQL 18 for the database"

**Claude Code Autonomous Flow**:

```typescript
// Step 1: Search existing memory
const existing = await memory.find({
  query: "PostgreSQL database",
  scope: {project: "my-app", branch: "main"}
});

// Step 2: Check if anything found
if (existing.hits.length === 0) {
  // No existing info, create new
  const result = await memory.store({
    items: [{
      kind: "section",
      scope: {project: "my-app", branch: "main"},
      data: {
        title: "Database Technology",
        body_md: "Using PostgreSQL 18 for persistence"
      }
    }]
  });

  // Step 3: Inform user using autonomous context
  console.log(result.autonomous_context.user_message_suggestion);
  // Output: "✓ Saved section: 18a539bc..."
}
```

**Result**: User sees clean confirmation, no questions asked.

---

## Example 2: User Corrects Information

**User**: "Actually, we're using PostgreSQL 18, not 17"

**Claude Code Autonomous Flow**:

```typescript
// Step 1: Detect correction intent (keywords: "actually", "not")
const isCorrection = true;

// Step 2: Search for old information
const oldInfo = await memory.find({
  query: "PostgreSQL version",
  scope: {project: "my-app"}
});

// Step 3: Found old version (PostgreSQL 17)
if (oldInfo.hits.length > 0) {
  // Autonomous decision: DELETE old + CREATE new

  // Delete old
  await memory.store({
    items: [{
      operation: "delete",
      kind: "section",
      id: oldInfo.hits[0].id
    }]
  });

  // Create new
  const newResult = await memory.store({
    items: [{
      kind: "section",
      scope: {project: "my-app"},
      data: {
        title: "Database Technology",
        body_md: "Using PostgreSQL 18 for persistence"
      }
    }]
  });

  // Step 4: Inform user
  console.log("✓ Corrected database version (17 → 18)");
}
```

**Result**: User's correction applied automatically, seamless experience.

---

## Example 3: Duplicate Detection

**User**: Shares same information twice (accidentally)

**Claude Code Autonomous Flow**:

```typescript
// First time: User shares "OAuth 2.0 setup guide"
const first = await memory.store({
  items: [{
    kind: "section",
    scope: {project: "my-app"},
    data: {title: "Auth Setup", body_md: "OAuth 2.0 configuration..."}
  }]
});

console.log(first.autonomous_context.user_message_suggestion);
// "✓ Saved section"

// Second time: User accidentally repeats same info
const second = await memory.store({
  items: [{
    kind: "section",
    scope: {project: "my-app"},
    data: {title: "Auth Setup", body_md: "OAuth 2.0 configuration..."}
  }]
});

// Autonomous handling: Auto-dedupe via content hash
expect(second.stored[0].status).toBe('skipped_dedupe');
expect(second.autonomous_context.action_performed).toBe('skipped');
expect(second.autonomous_context.duplicates_found).toBeGreaterThan(0);

console.log(second.autonomous_context.user_message_suggestion);
// "⊘ Already in memory, skipped"
```

**Result**: No duplicate created, user informed, no questions.

---

## Example 4: Low Confidence Search with Autonomous Retry

**User**: "Find auth docs" (vague query)

**Claude Code Autonomous Flow**:

```typescript
// Step 1: Initial search
let result = await memory.find({
  query: "auth docs",
  mode: "auto"
});

// Step 2: Check confidence
if (result.autonomous_metadata.confidence === 'low') {
  // Autonomous decision: Retry with better keywords
  result = await memory.find({
    query: "authentication documentation",
    mode: "deep"  // Use fuzzy matching
  });
}

// Step 3: Use results
if (result.hits.length > 0) {
  console.log(result.autonomous_metadata.user_message_suggestion);
  // "Found 3 results"

  // Present top results to user
  result.hits.forEach(h => console.log(`- ${h.title}`));
} else {
  console.log("No authentication documentation found");
}
```

**Result**: Claude autonomously retries with better strategy, user gets best results.

---

## Example 5: Auto-Purge (Transparent)

**Scenario**: Database grows over time, old data accumulates

**Autonomous Cleanup**:

```typescript
// Every memory.store or memory.find call checks purge thresholds
await memory.store({...});  // Increments operation counter

// When threshold exceeded (24h OR 1000 ops):
// 1. Auto-purge runs in background (async, non-blocking)
// 2. Deletes: closed todos (>90d), merged PRs (>30d), etc.
// 3. Updates _purge_metadata table
// 4. User sees NOTHING (seamless)

// Check purge status (admin only):
const meta = await client.query('SELECT * FROM _purge_metadata');
console.log(meta.rows[0].deleted_counts);
// {"todo": 45, "pr_context": 12, "issue": 8}
```

**Result**: Database stays clean automatically, zero manual intervention.

---

## Configuration Examples

### Disable Auto-Purge (Development)

```bash
# .env
PURGE_ENABLED=false
```

### Aggressive Purge (High Activity)

```bash
# .env
PURGE_TIME_THRESHOLD_HOURS=12       # Every 12 hours
PURGE_OPERATION_THRESHOLD=500       # After 500 operations
TODO_TTL_DAYS=30                    # Delete todos after 30 days
```

### Conservative Purge (Archival)

```bash
# .env
PURGE_TIME_THRESHOLD_HOURS=168      # Weekly (7 days)
PURGE_OPERATION_THRESHOLD=5000      # After 5000 operations
TODO_TTL_DAYS=365                   # Keep todos for 1 year
```

---

## Decision Matrix Reference

For Claude Code/AI agents implementing autonomous logic:

| User Intent | Keywords Detected | Autonomous Action |
|-------------|-------------------|-------------------|
| Share new info | Normal statement | Search → if none found → CREATE |
| Correct info | "actually", "correction", "wrong", "not X but Y" | Search → DELETE old + CREATE new |
| Explicit delete | "delete", "remove", "forget" | Search → DELETE |
| Duplicate | (auto-detected via hash) | SKIP with status: "skipped_dedupe" |
| High similarity | (>0.8 match on title/content) | Recommend UPDATE existing |
| Low confidence search | (avg_score < 0.4) | Auto-retry with broader keywords or mode="deep" |

**Key Principle**: Claude decides, user sees clean results. No "which option?" prompts!
