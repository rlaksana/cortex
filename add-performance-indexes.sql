-- Add Performance Indexes
-- Priority 4: MEDIUM - Important for scalability

-- Execute these SQL statements after standardizing timestamps

-- CONTENT HASH DEDUPLICATION INDEXES
-- ==================================

-- Section table - Content hash uniqueness with scope isolation
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_section_content_hash_scope
ON section (content_hash, project, COALESCE(branch, 'main'))
WHERE content_hash IS NOT NULL AND deleted_at IS NULL;

-- ADR Decision table - Content hash uniqueness with scope isolation
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_adr_decision_content_hash_scope
ON adr_decision (content_hash, project, COALESCE(branch, 'main'))
WHERE content_hash IS NOT NULL;

-- Issue Log table - Content hash uniqueness with scope isolation
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_issue_log_content_hash_scope
ON issue_log (content_hash, project, COALESCE(branch, 'main'))
WHERE content_hash IS NOT NULL;

-- Todo Log table - Content hash uniqueness with scope isolation
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_todo_log_content_hash_scope
ON todo_log (content_hash, project, COALESCE(branch, 'main'))
WHERE content_hash IS NOT NULL;

-- PERFORMANCE SORTING INDEXES
-- ============================

-- Section table - Updated at descending sort
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_section_updated_at_desc
ON section (updated_at DESC, created_at ASC)
WHERE deleted_at IS NULL;

-- ADR Decision table - Updated at descending sort
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_adr_decision_updated_at_desc
ON adr_decision (updated_at DESC, created_at ASC);

-- Issue Log table - Updated at descending sort
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_issue_log_updated_at_desc
ON issue_log (updated_at DESC, created_at ASC);

-- Todo Log table - Updated at descending sort
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_todo_log_updated_at_desc
ON todo_log (updated_at DESC, created_at ASC);

-- BRANCH ISOLATION INDEXES
-- ========================

-- Section table - Branch isolation for queries
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_section_branch_isolation
ON section (project, COALESCE(branch, 'main'), updated_at DESC)
WHERE deleted_at IS NULL;

-- ADR Decision table - Branch isolation for queries
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_adr_decision_branch_isolation
ON adr_decision (project, COALESCE(branch, 'main'), updated_at DESC);

-- Issue Log table - Branch isolation for queries
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_issue_log_branch_isolation
ON issue_log (project, COALESCE(branch, 'main'), updated_at DESC);

-- Todo Log table - Branch isolation for queries
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_todo_log_branch_isolation
ON todo_log (project, COALESCE(branch, 'main'), updated_at DESC);

-- ACTIVE RECORD INDEXES
-- =====================

-- Section table - Active records only
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_section_active
ON section (project, COALESCE(branch, 'main'), updated_at DESC)
WHERE deleted_at IS NULL;

-- Todo Log table - Active todos with status
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_todo_active
ON todo_log (project, COALESCE(branch, 'main'), status, updated_at DESC)
WHERE deleted_at IS NULL;

-- Issue Log table - Active issues with status and severity
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_issue_active
ON issue_log (project, COALESCE(branch, 'main'), status, severity, updated_at DESC);

-- FULL-TEXT SEARCH INDEXES
-- ========================

-- Section table - Full-text search on title and content
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_section_fts
ON section USING gin(to_tsvector('english', title || ' ' || COALESCE(content, '')))
WHERE deleted_at IS NULL;

-- ADR Decision table - Full-text search on title and rationale
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_adr_decision_fts
ON adr_decision USING gin(to_tsvector('english', title || ' ' || rationale || ' ' || COALESCE(array_to_string(alternativesConsidered, ' '), '')));

-- Issue Log table - Full-text search on title and description
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_issue_log_fts
ON issue_log USING gin(to_tsvector('english', title || ' ' || COALESCE(description, '')));

-- Todo Log table - Full-text search on title and description
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_todo_log_fts
ON todo_log USING gin(to_tsvector('english', title || ' ' || COALESCE(description, '')));

-- KNOWLEDGE ENTITY INDEXES
-- ========================

-- Entity table - Type and name search
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_entity_type_name
ON entity (type, name) WHERE deleted_at IS NULL;

-- Entity table - Project scope
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_entity_project_scope
ON entity (project, COALESCE(branch, 'main'), type) WHERE deleted_at IS NULL;

-- Knowledge Entity table - Entity type and name
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_knowledge_entity_type_name
ON knowledge_entity (entity_type, name) WHERE deleted_at IS NULL;

-- Knowledge Observation table - Entity lookup
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_knowledge_observation_entity
ON knowledge_observation (entity_type, entity_id, created_at DESC) WHERE deleted_at IS NULL;

-- Knowledge Relation table - Relation lookup
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_knowledge_relation_lookup
ON knowledge_relation (from_entity_type, from_entity_id, relation_type) WHERE deleted_at IS NULL;

-- SESSION-LOGS INDEXES
-- ====================

-- Entity table - UUID primary key (already exists, ensure it's indexed)
-- Note: Primary key automatically creates index, this is just documentation

-- Relation table - Source and target entity lookup
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_relation_source_lookup
ON relation (source_entity_id, relation_type) WHERE deleted_at IS NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_relation_target_lookup
ON relation (target_entity_id, relation_type) WHERE deleted_at IS NULL;

-- Observation table - Entity and confidence lookup
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_observation_entity_confidence
ON observation (entity_id, confidence DESC, observed_at DESC) WHERE deleted_at IS NULL;

-- Incident table - Severity and timeline lookup
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_incident_severity_timeline
ON incident (severity, detected_at DESC) WHERE deleted_at IS NULL;

-- Risk table - Probability and score lookup
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_risk_probability_score
ON risk (impact_probability DESC, risk_score DESC NULLS LAST) WHERE deleted_at IS NULL;

-- Release table - Version and deployment lookup
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_release_deployment
ON release (deployment_date DESC, status) WHERE deleted_at IS NULL;

-- Assumption table - Validation status lookup
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_assumption_validation_status
ON assumption (validation_status, created_at DESC) WHERE deleted_at IS NULL;

-- AUDIT AND LOG INDEXES
-- =====================

-- Event Audit table - Table and operation lookup
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_event_audit_table_operation
ON event_audit (table_name, operation, created_at DESC);

-- Event Audit table - Record lookup
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_event_audit_record
ON event_audit (record_id, table_name, created_at DESC);

-- DDL History table - Migration lookup
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_ddl_history_migration
ON ddl_history (migration_id, applied_at DESC);

-- CHANGE LOG INDEXES
-- ==================

-- Change Log table - Change type and subject lookup
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_change_log_type_subject
ON change_log (change_type, subject_ref, created_at DESC);

-- Change Log table - Author and timeline lookup
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_change_log_author_timeline
ON change_log (author, created_at DESC);

-- PR CONTEXT INDEXES
-- ==================

-- PR Context table - Status and author lookup
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_pr_context_status_author
ON pr_context (status, author, created_at DESC);

-- PR Context table - Number lookup
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_pr_context_number
ON pr_context (pr_number);

-- COMPOUND INDEXES FOR COMMON QUERIES
-- ====================================

-- Todo items by project and status
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_todo_project_status_priority
ON todo_log (project, COALESCE(branch, 'main'), status, priority, created_at DESC)
WHERE deleted_at IS NULL;

-- Issues by project and severity
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_issue_project_severity_status
ON issue_log (project, COALESCE(branch, 'main'), severity, status, created_at DESC);

-- Knowledge entities by type and project
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_knowledge_entity_project_type
ON knowledge_entity (entity_type, name, project) WHERE deleted_at IS NULL;

-- Purge metadata for cleanup operations
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_purge_metadata_enabled_last
ON purge_metadata (enabled, last_purge_at DESC);

RAISE NOTICE '✅ Performance indexes creation complete';

-- INDEX MAINTENANCE QUERIES
-- =========================

-- Query to check index usage statistics (run after some usage):
/*
SELECT
    schemaname,
    tablename,
    indexname,
    idx_scan,
    idx_tup_read,
    idx_tup_fetch
FROM pg_stat_user_indexes
WHERE schemaname = 'public'
ORDER BY idx_scan DESC;
*/

-- Query to check index sizes:
/*
SELECT
    schemaname,
    tablename,
    indexname,
    pg_size_pretty(pg_relation_size(indexname::regclass)) AS index_size
FROM pg_indexes
JOIN pg_stat_user_indexes USING (schemaname, tablename, indexname)
WHERE schemaname = 'public'
ORDER BY pg_relation_size(indexname::regclass) DESC;
*/

-- Query to identify unused indexes (for cleanup):
/*
SELECT
    schemaname,
    tablename,
    indexname,
    idx_scan,
    pg_size_pretty(pg_relation_size(indexname::regclass)) AS index_size
FROM pg_stat_user_indexes
WHERE schemaname = 'public'
    AND idx_scan = 0
    AND indexname NOT LIKE '%_pkey'
ORDER BY pg_relation_size(indexname::regclass) DESC;
*/

RAISE NOTICE '✅ Performance indexing setup complete with maintenance queries';