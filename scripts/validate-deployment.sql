-- Post-Deployment Validation Script for Cortex Memory MCP
-- Tests database functionality, triggers, and data integrity

\echo '=== CORTEX MEMORY MCP - POST-DEPLOYMENT VALIDATION ==='
\echo ''

-- Test 1: Insert sample section (test deduplication)
\echo 'Test 1: Insert sample section with deduplication...'
INSERT INTO section (heading, body_jsonb, content_hash, tags)
VALUES (
  'Test Section - Getting Started',
  '{"text": "This is a test documentation section for Cortex Memory MCP deployment validation."}',
  encode(digest('test-section-validation', 'sha256'), 'hex'),
  '{"branch": "main", "project": "cortex-memory", "type": "docs"}'
)
ON CONFLICT (content_hash) DO NOTHING
RETURNING id, heading, created_at;

\echo ''

-- Test 2: Verify FTS index works
\echo 'Test 2: Verify Full-Text Search...'
SELECT
  id,
  heading,
  ts_rank(ts, to_tsquery('english', 'test & documentation')) AS rank
FROM section
WHERE ts @@ to_tsquery('english', 'test & documentation')
ORDER BY rank DESC
LIMIT 5;

\echo ''

-- Test 3: Check audit trail
\echo 'Test 3: Verify audit logging...'
SELECT
  entity_type,
  operation,
  created_at,
  change_summary::jsonb->>'heading' AS heading_changed
FROM event_audit
WHERE entity_type = 'section'
ORDER BY created_at DESC
LIMIT 5;

\echo ''

-- Test 4: Insert ADR and test immutability
\echo 'Test 4: Test ADR immutability governance...'
INSERT INTO adr_decision (component, status, title, rationale, tags)
VALUES (
  'cortex-mcp',
  'proposed',
  'Test ADR - Use PostgreSQL 18+',
  'PostgreSQL 18+ provides required JSON and FTS features',
  '{"branch": "main"}'
)
RETURNING id, component, status, title;

\echo ''

-- Test 5: Database statistics
\echo 'Test 5: Database statistics...'
SELECT
  schemaname,
  tablename,
  pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size,
  n_tup_ins AS inserts,
  n_tup_upd AS updates,
  n_tup_del AS deletes
FROM pg_stat_user_tables
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;

\echo ''

-- Test 6: Index usage
\echo 'Test 6: Index usage statistics...'
SELECT
  schemaname,
  tablename,
  indexname,
  idx_scan AS scans,
  idx_tup_read AS tuples_read,
  idx_tup_fetch AS tuples_fetched
FROM pg_stat_user_indexes
WHERE schemaname = 'public'
ORDER BY idx_scan DESC
LIMIT 10;

\echo ''

-- Test 7: Verify constraints
\echo 'Test 7: Verify CHECK constraints...'
SELECT
  conname AS constraint_name,
  conrelid::regclass AS table_name,
  pg_get_constraintdef(oid) AS definition
FROM pg_constraint
WHERE contype = 'c' AND connamespace = 'public'::regnamespace
ORDER BY conrelid::regclass::text;

\echo ''

-- Test 8: Connection pool health
\echo 'Test 8: Active connections...'
SELECT
  state,
  COUNT(*) AS count,
  MAX(now() - state_change) AS max_duration
FROM pg_stat_activity
WHERE datname = 'cortex_prod'
GROUP BY state;

\echo ''
\echo '=== VALIDATION COMPLETE ==='
\echo ''
\echo 'Summary:'
SELECT
  (SELECT COUNT(*) FROM section) AS total_sections,
  (SELECT COUNT(*) FROM event_audit) AS total_audit_events,
  (SELECT COUNT(*) FROM adr_decision) AS total_adrs,
  (SELECT COUNT(*) FROM pg_stat_user_tables WHERE schemaname = 'public') AS total_tables,
  (SELECT COUNT(*) FROM pg_indexes WHERE schemaname = 'public') AS total_indexes;
