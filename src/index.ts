#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
  CallToolResult,
} from '@modelcontextprotocol/sdk/types.js';
import { memoryStore } from './services/memory-store.js';
import { memoryFind } from './services/memory-find.js';
import { logger } from './utils/logger.js';
import { loadEnv } from './config/env.js';
import { closePool } from './db/pool.js';

loadEnv();

const server = new Server(
  { name: 'cortex-memory', version: '1.0.0' },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: 'memory.store',
      description: `Store, update, or delete knowledge with autonomous decision support.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AUTONOMOUS DECISION PROTOCOL (for Claude Code / AI Callers)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

When user shares information, YOU (Claude Code) MUST decide autonomously:
1. Search existing memory first: memory.find({query: extract_keywords})
2. Analyze autonomous_metadata from search results
3. Decide operation based on similarity/contradiction
4. Execute WITHOUT prompting user
5. Use autonomous_context to inform user of action taken

DECISION MATRIX:

Scenario 1: User shares NEW information
├─ Search: memory.find({query: keywords_from_user_input})
├─ IF no results found:
│  └─ Action: CREATE (omit operation and id)
│  └─ Tell user: "✓ Saved to memory"
│
├─ IF exact duplicate (content_hash match):
│  └─ Action: SKIP (auto-handled, returns status: "skipped_dedupe")
│  └─ Tell user: "Already in memory"
│
├─ IF high similarity (>0.8 match):
│  └─ Action: UPDATE (include id of similar item)
│  └─ Tell user: "✓ Updated existing entry"
│
└─ IF medium similarity (0.5-0.8 match):
   └─ Action: CREATE (content different enough)
   └─ Tell user: "✓ Saved (found similar but created new)"

Scenario 2: User CORRECTS information
├─ Keywords: "actually", "correction", "wrong", "not X but Y"
├─ Search: memory.find({query: topic_being_corrected})
├─ Action: DELETE old + CREATE new
│  └─ memory.store({operation:"delete", id: old_id})
│  └─ memory.store({data: new_info})
└─ Tell user: "✓ Corrected [topic]"

Scenario 3: User explicitly says "delete/remove"
├─ Search: memory.find({query: item_to_delete})
├─ Action: DELETE
│  └─ memory.store({operation:"delete", kind: type, id: found_id})
└─ Tell user: "✓ Deleted [item]"

IMPORTANT: DO NOT ask user "which option?". YOU decide autonomously!

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
RESPONSE STRUCTURE (use this for autonomous reasoning)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{
  "stored": [{
    "id": "uuid",
    "status": "inserted|updated|skipped_dedupe|deleted",
    "kind": "section"
  }],
  "autonomous_context": {
    "action_performed": "created|updated|deleted|skipped|batch",
    "similar_items_checked": 1,
    "duplicates_found": 0,
    "contradictions_detected": false,
    "recommendation": "Inform user: Item saved successfully.",
    "reasoning": "Created new item. No duplicates detected.",
    "user_message_suggestion": "✓ Saved section"
  }
}

USE autonomous_context.user_message_suggestion to inform user!

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
OPERATIONS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

CREATE (omit operation + id): Store new item
UPDATE (omit operation, include id): Modify existing
DELETE (operation="delete"): Remove permanently

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
12 KNOWLEDGE TYPES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
- section: Documentation chunks with markdown/text body
- runbook: Operational procedures and playbooks
- change: Change log entries for tracking modifications
- issue: Issue tracking with root cause and resolution
- decision: ADRs (Architecture Decision Records) with rationale
- todo: Task tracking with status and priority
- release_note: Release documentation and changelogs
- ddl: Database schema changes (DDL history)
- pr_context: Pull request metadata and context

**Immutability Enforcement:**
- ADR decisions: Once status='accepted', content fields (title, rationale, component) become immutable
- Approved sections: Once tagged as approved=true, body_md/body_text become write-locked
- Violations throw errors to prevent unauthorized modifications

**Scope Parameters (in each item):**
- project: Project name (required for isolation)
- branch: Git branch (defaults to current, enables branch isolation)
- org: Organization identifier (optional)

**Deduplication:** Content-based SHA-256 hashing prevents duplicates within same scope.

**Branch Isolation:** By default, reads are isolated to current branch. Explicitly omit 'branch' to search across all branches in project.

**Example - Update ADR (allowed - status not 'accepted'):**
{
  "items": [{
    "kind": "decision",
    "scope": {"project": "my-app", "branch": "main"},
    "data": {
      "id": "existing-uuid-here",
      "status": "proposed",
      "title": "Updated title"
    }
  }]
}

**Example - Update ADR (blocked - accepted ADR):**
{
  "items": [{
    "kind": "decision",
    "scope": {"project": "my-app"},
    "data": {
      "id": "accepted-adr-uuid",
      "rationale": "Cannot change this"
    }
  }]
}
// ERROR: ADR_IMMUTABLE - Cannot modify accepted ADR content

**Example - Store new ADR:**
{
  "items": [{
    "kind": "decision",
    "scope": {"project": "my-app", "branch": "main"},
    "data": {
      "component": "auth",
      "status": "accepted",
      "title": "Use OAuth 2.0",
      "rationale": "Industry standard, well-supported",
      "alternatives_considered": ["Basic Auth", "JWT only"]
    },
    "tags": {"category": "security"}
  }]
}

**Example - Store Section:**
{
  "items": [{
    "kind": "section",
    "scope": {"project": "my-app", "branch": "feature-x"},
    "data": {
      "title": "API Authentication",
      "body_md": "# Auth Flow\\n\\nUses RS256 JWT tokens...",
      "document_id": "doc-123"
    }
  }]
}

**DELETE Operation:**
Set operation="delete" to permanently remove items (hard delete).

**Example - Delete Single Item:**
{
  "items": [{
    "operation": "delete",
    "kind": "section",
    "id": "uuid-to-delete",
    "cascade_relations": false
  }]
}

**Example - Delete Multiple Items (Batch):**
{
  "items": [
    {"operation": "delete", "kind": "section", "id": "uuid-1"},
    {"operation": "delete", "kind": "section", "id": "uuid-2"},
    {"operation": "delete", "kind": "decision", "id": "uuid-3"}
  ]
}

**DELETE Features:**
- Hard delete (immediate, permanent removal)
- Cascade option (set cascade_relations: true to delete related items)
- Immutability protection (cannot delete accepted ADRs)
- Full audit trail preserved in event_audit table
- Returns status: "updated" to indicate deletion performed

- decision: ADRs (Architecture Decision Records) with rationale
- todo: Task tracking with status and priority
- release_note: Release documentation and changelogs
- ddl: Database schema changes (DDL history)
- pr_context: Pull request metadata and context
- entity: Flexible user-defined entities (graph extension)
- relation: Links between any knowledge items (graph extension)
- observation: Fine-grained facts attached to entities (graph extension)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CODE EXAMPLES (Autonomous Flows)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// User: "We use PostgreSQL 18"
// Claude Code autonomous flow:
const existing = await memory.find({query: "PostgreSQL version"});
if (existing.hits.length > 0) {
  // Found old version, replace it
  await memory.store({operation:"delete", kind:"section", id: existing.hits[0].id});
  const result = await memory.store({kind:"section", data:{title:"Database", body_md:"PostgreSQL 18"}});
  console.log(result.autonomous_context.user_message_suggestion); // "✓ Saved section"
} else {
  // No existing, create new
  const result = await memory.store({kind:"section", data:{title:"Database", body_md:"PostgreSQL 18"}});
  console.log(result.autonomous_context.user_message_suggestion);
}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
IMMUTABILITY & CONSTRAINTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

- Accepted ADRs: Cannot update/delete (status='accepted')
- Approved specs: Cannot modify (approved=true)
- Event audit: Append-only, no deletions

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AUTO-MAINTENANCE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Automatic cleanup runs when time (24h) OR operations (1000) threshold exceeded.
Purges: closed todos (>90d), merged PRs (>30d), closed issues (>90d), old changes (>90d).
Zero config required. Seamless background operation.`,
      inputSchema: {
        type: 'object',
        properties: {
          items: {
            type: 'array',
            items: { type: 'object' },
            description:
              'Array of knowledge items to store. Each item must have: kind, scope, data fields.',
          },
        },
        required: ['items'],
      },
    },
    {
      name: 'memory.find',
      description: `Search knowledge with autonomous retry logic and confidence scoring.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AUTONOMOUS SEARCH PROTOCOL (for Claude Code / AI Callers)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

YOU (Claude Code) MUST handle search autonomously using autonomous_metadata:

1. Start with mode="auto" (smart fallback)
2. Check autonomous_metadata.confidence in response
3. IF confidence="low": Automatically retry with broader keywords or mode="deep"
4. Use top results WITHOUT asking user to pick
5. Inform user using autonomous_metadata.user_message_suggestion

AUTONOMOUS RETRY LOGIC:

// User: "Find auth docs"
let result = await memory.find({query: "auth docs", mode: "auto"});

if (result.autonomous_metadata.confidence === 'low') {
  // Auto-retry with broader keywords
  result = await memory.find({query: "authentication", mode: "deep"});
}

if (result.hits.length > 0) {
  console.log(result.autonomous_metadata.user_message_suggestion); // "Found X results"
  // Use top results directly
} else {
  console.log("No results found");
}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
RESPONSE STRUCTURE (for autonomous reasoning)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{
  "hits": [{
    "id": "uuid",
    "kind": "section",
    "title": "OAuth Setup",
    "snippet": "...",
    "score": 0.85,
    "confidence": 0.9
  }],
  "autonomous_metadata": {
    "strategy_used": "fast_then_deep_fallback",
    "confidence": "high|medium|low",
    "total_results": 3,
    "avg_score": 0.72,
    "fallback_attempted": true,
    "recommendation": "Results sufficient, use top results.",
    "user_message_suggestion": "Found 3 results"
  }
}

USE autonomous_metadata for decisions:
- confidence="high" → Use results
- confidence="medium" → Use results, maybe refine later
- confidence="low" → Retry with broader keywords/deep mode

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SEARCH MODES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

auto: Smart fallback (fast → deep if needed) - RECOMMENDED
fast: FTS only (exact matching, fastest)
deep: Trigram fuzzy (typo-tolerant, slower)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EXAMPLES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Basic: {query: "OAuth authentication"}
Filtered: {query: "auth", types: ["section", "decision"], scope: {branch: "main"}}
Fuzzy: {query: "authntication", mode: "deep"}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PERFORMANCE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

P95 latency < 300ms on datasets up to 3M items. Auto-purge maintains optimal performance.`,
      inputSchema: {
        type: 'object',
        properties: {
          query: {
            type: 'string',
            description:
              'Search query string. Supports full-text search operators in fast/auto modes.',
          },
          top_k: {
            type: 'number',
            description: 'Number of results to return (default: 5, max: 50)',
          },
          mode: {
            type: 'string',
            enum: ['auto', 'fast', 'deep'],
            description:
              'Search mode: auto (intelligent routing), fast (FTS only), deep (fuzzy trigram)',
          },
          scope: {
            type: 'object',
            description:
              'Scope filter: {project, branch, org}. Omit branch for cross-branch search.',
          },
          types: {
            type: 'array',
            items: { type: 'string' },
            description: 'Filter by knowledge types: ["decision", "issue", "section", etc.]',
          },
        },
        required: ['query'],
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request): Promise<CallToolResult> => {
  if (request.params.name === 'memory.store') {
    const args = request.params.arguments as { items?: unknown[] };
    const result = await memoryStore(args.items || []);
    return { content: [{ type: 'text', text: JSON.stringify(result) }] };
  } else if (request.params.name === 'memory.find') {
    const args = (request.params.arguments || {}) as {
      query: string;
      scope?: Record<string, unknown>;
      types?: string[];
      top_k?: number;
      mode?: 'auto' | 'fast' | 'deep';
    };
    const result = await memoryFind(args);
    return { content: [{ type: 'text', text: JSON.stringify(result) }] };
  }
  throw new Error(`Unknown tool: ${request.params.name}`);
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  logger.info({ transport: 'stdio' }, 'Cortex Memory MCP server started');

  process.on('SIGINT', async () => {
    await closePool();
    process.exit(0);
  });
}

main().catch((err) => {
  logger.error({ err }, 'Server failed to start');
  process.exit(1);
});
