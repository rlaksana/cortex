-- Test data insertion for validation

\echo 'Inserting test section...'
INSERT INTO section (heading, body_jsonb, content_hash, tags)
VALUES (
  'Cortex Memory MCP - Quick Start Guide',
  '{"text": "Welcome to Cortex Memory MCP! This is your central knowledge repository for storing documentation, ADRs, runbooks, and more."}',
  encode(digest('quickstart-guide-v1', 'sha256'), 'hex'),
  '{"branch": "main", "project": "cortex-memory", "type": "docs", "priority": "high"}'::jsonb
);

\echo 'Test FTS search for "knowledge repository"...'
SELECT
  id,
  heading,
  ts_rank(ts, to_tsquery('english', 'knowledge & repository')) AS rank
FROM section
WHERE ts @@ to_tsquery('english', 'knowledge & repository')
ORDER BY rank DESC;

\echo ''
\echo 'Verify audit trail...'
SELECT
  entity_type,
  entity_id,
  operation,
  created_at
FROM event_audit
WHERE entity_type = 'section'
ORDER BY created_at DESC
LIMIT 3;

\echo ''
\echo 'Current section count:'
SELECT COUNT(*) AS total_sections FROM section;
