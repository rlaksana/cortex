-- T014: Index creation migration
-- GIN indexes for FTS, JSONB tags, and performance optimization

-- FTS index on section (primary search target)
CREATE INDEX section_fts_idx ON section USING gin(ts);

-- JSONB tag indexes for scope filtering
CREATE INDEX section_tags_gin ON section USING gin(tags);
CREATE INDEX section_body_gin ON section USING gin(body_jsonb jsonb_path_ops);
CREATE INDEX runbook_tags_gin ON runbook USING gin(tags);
CREATE INDEX change_log_tags_gin ON change_log USING gin(tags);
CREATE INDEX issue_log_tags_gin ON issue_log USING gin(tags);
CREATE INDEX adr_decision_tags_gin ON adr_decision USING gin(tags);
CREATE INDEX todo_log_tags_gin ON todo_log USING gin(tags);

-- Composite index for issue deduplication
CREATE INDEX issue_log_tracker_external ON issue_log(tracker, external_id);

-- Audit trail indexes for efficient queries
CREATE INDEX event_audit_entity_idx ON event_audit(entity_type, entity_id);
CREATE INDEX event_audit_created_at_idx ON event_audit(created_at DESC);

-- Performance: Index on content_hash for deduplication
CREATE INDEX section_content_hash_idx ON section(content_hash);
CREATE INDEX change_log_content_hash_idx ON change_log(content_hash);
