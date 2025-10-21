-- Create Database Triggers
-- Priority 5: LOW - Database automation for consistency

-- Execute these SQL statements after adding performance indexes

-- UPDATE TIMESTAMP TRIGGER FUNCTION
-- =================================

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    NEW.updated_by = COALESCE(NEW.updated_by, 'system');
    RETURN NEW;
END;
$$ language 'plpgsql';

-- CONTENT HASH GENERATION FUNCTION
-- ================================

CREATE OR REPLACE FUNCTION generate_content_hash()
RETURNS TRIGGER AS $$
BEGIN
    -- Generate content hash based on table-specific data
    IF TG_TABLE_NAME = 'section' THEN
        NEW.content_hash = encode(sha256(NEW.title::bytea || COALESCE(NEW.content, '')::bytea), 'hex');
    ELSIF TG_TABLE_NAME = 'adr_decision' THEN
        NEW.content_hash = encode(sha256(NEW.title::bytea || NEW.rationale::bytea || COALESCE(array_to_string(NEW.alternativesConsidered, ','), '')::bytea), 'hex');
    ELSIF TG_TABLE_NAME = 'issue_log' THEN
        NEW.content_hash = encode(sha256(NEW.title::bytea || COALESCE(NEW.description, '')::bytea), 'hex');
    ELSIF TG_TABLE_NAME = 'todo_log' THEN
        NEW.content_hash = encode(sha256(NEW.title::bytea || COALESCE(NEW.description, '')::bytea), 'hex');
    ELSIF TG_TABLE_NAME = 'runbook' THEN
        NEW.content_hash = encode(sha256(NEW.title::bytea || COALESCE(NEW.description, '')::bytea || COALESCE(NEW.steps::text, '')::bytea), 'hex');
    ELSIF TG_TABLE_NAME = 'change_log' THEN
        NEW.content_hash = encode(sha256(NEW.change_type::bytea || NEW.subject_ref::bytea || NEW.summary::bytea), 'hex');
    ELSIF TG_TABLE_NAME = 'release_note' THEN
        NEW.content_hash = encode(sha256(NEW.version::bytea || NEW.summary::bytea), 'hex');
    ELSIF TG_TABLE_NAME = 'assumption' THEN
        NEW.content_hash = encode(sha256(NEW.title::bytea || NEW.description::bytea || COALESCE(NEW.validation_status, '')::bytea), 'hex');
    ELSIF TG_TABLE_NAME = 'entity' THEN
        NEW.content_hash = encode(sha256(NEW.name::bytea || NEW.type::bytea || COALESCE(NEW.description, '')::bytea), 'hex');
    ELSIF TG_TABLE_NAME = 'incident' THEN
        NEW.content_hash = encode(sha256(NEW.title::bytea || NEW.severity::bytea || NEW.impact::bytea), 'hex');
    ELSIF TG_TABLE_NAME = 'release' THEN
        NEW.content_hash = encode(sha256(NEW.version::bytea || NEW.scope::bytea || COALESCE(NEW.status, '')::bytea), 'hex');
    ELSIF TG_TABLE_NAME = 'risk' THEN
        NEW.content_hash = encode(sha256(NEW.title::bytea || NEW.description::bytea || NEW.impact_severity::bytea), 'hex');
    END IF;

    RETURN NEW;
END;
$$ language 'plpgsql';

-- DEFAULT VALUES FUNCTION
-- =======================

CREATE OR REPLACE FUNCTION set_default_values()
RETURNS TRIGGER AS $$
BEGIN
    -- Set default server-managed values
    NEW.created_by = COALESCE(NEW.created_by, 'system');
    NEW.updated_by = COALESCE(NEW.updated_by, 'system');

    -- Set default project/branch/org if not provided
    IF TG_TABLE_NAME IN ('entity', 'relation', 'observation', 'incident', 'release', 'risk', 'assumption', 'ddl_log') THEN
        NEW.project = COALESCE(NEW.project, 'cortex-local');
        NEW.branch = COALESCE(NEW.branch, 'main');
        NEW.org = COALESCE(NEW.org, 'default');
    END IF;

    -- Set default tags and metadata
    NEW.tags = COALESCE(NEW.tags, '{}'::jsonb);
    NEW.metadata = COALESCE(NEW.metadata, '{}'::jsonb);

    RETURN NEW;
END;
$$ language 'plpgsql';

-- APPLY TRIGGERS TO LEGACY TABLES
-- ================================

-- Section table triggers
DROP TRIGGER IF EXISTS update_section_updated_at ON section;
DROP TRIGGER IF EXISTS generate_section_content_hash ON section;
DROP TRIGGER IF EXISTS set_section_defaults ON section;

CREATE TRIGGER update_section_updated_at
BEFORE UPDATE ON section
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER generate_section_content_hash
BEFORE INSERT OR UPDATE ON section
FOR EACH ROW EXECUTE FUNCTION generate_content_hash();

CREATE TRIGGER set_section_defaults
BEFORE INSERT ON section
FOR EACH ROW EXECUTE FUNCTION set_default_values();

-- ADR Decision table triggers
DROP TRIGGER IF EXISTS update_adr_decision_updated_at ON adr_decision;
DROP TRIGGER IF EXISTS generate_adr_decision_content_hash ON adr_decision;
DROP TRIGGER IF EXISTS set_adr_decision_defaults ON adr_decision;

CREATE TRIGGER update_adr_decision_updated_at
BEFORE UPDATE ON adr_decision
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER generate_adr_decision_content_hash
BEFORE INSERT OR UPDATE ON adr_decision
FOR EACH ROW EXECUTE FUNCTION generate_content_hash();

CREATE TRIGGER set_adr_decision_defaults
BEFORE INSERT ON adr_decision
FOR EACH ROW EXECUTE FUNCTION set_default_values();

-- Issue Log table triggers
DROP TRIGGER IF EXISTS update_issue_log_updated_at ON issue_log;
DROP TRIGGER IF EXISTS generate_issue_log_content_hash ON issue_log;
DROP TRIGGER IF EXISTS set_issue_log_defaults ON issue_log;

CREATE TRIGGER update_issue_log_updated_at
BEFORE UPDATE ON issue_log
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER generate_issue_log_content_hash
BEFORE INSERT OR UPDATE ON issue_log
FOR EACH ROW EXECUTE FUNCTION generate_content_hash();

CREATE TRIGGER set_issue_log_defaults
BEFORE INSERT ON issue_log
FOR EACH ROW EXECUTE FUNCTION set_default_values();

-- Todo Log table triggers
DROP TRIGGER IF EXISTS update_todo_log_updated_at ON todo_log;
DROP TRIGGER IF EXISTS generate_todo_log_content_hash ON todo_log;
DROP TRIGGER IF EXISTS set_todo_log_defaults ON todo_log;

CREATE TRIGGER update_todo_log_updated_at
BEFORE UPDATE ON todo_log
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER generate_todo_log_content_hash
BEFORE INSERT OR UPDATE ON todo_log
FOR EACH ROW EXECUTE FUNCTION generate_content_hash();

CREATE TRIGGER set_todo_log_defaults
BEFORE INSERT ON todo_log
FOR EACH ROW EXECUTE FUNCTION set_default_values();

-- Runbook table triggers
DROP TRIGGER IF EXISTS update_runbook_updated_at ON runbook;
DROP TRIGGER IF EXISTS generate_runbook_content_hash ON runbook;
DROP TRIGGER IF EXISTS set_runbook_defaults ON runbook;

CREATE TRIGGER update_runbook_updated_at
BEFORE UPDATE ON runbook
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER generate_runbook_content_hash
BEFORE INSERT OR UPDATE ON runbook
FOR EACH ROW EXECUTE FUNCTION generate_content_hash();

CREATE TRIGGER set_runbook_defaults
BEFORE INSERT ON runbook
FOR EACH ROW EXECUTE FUNCTION set_default_values();

-- APPLY TRIGGERS TO SESSION-LOGS TABLES
-- =====================================

-- Entity table triggers
DROP TRIGGER IF EXISTS update_entity_updated_at ON entity;
DROP TRIGGER IF EXISTS generate_entity_content_hash ON entity;
DROP TRIGGER IF EXISTS set_entity_defaults ON entity;

CREATE TRIGGER update_entity_updated_at
BEFORE UPDATE ON entity
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER generate_entity_content_hash
BEFORE INSERT OR UPDATE ON entity
FOR EACH ROW EXECUTE FUNCTION generate_content_hash();

CREATE TRIGGER set_entity_defaults
BEFORE INSERT ON entity
FOR EACH ROW EXECUTE FUNCTION set_default_values();

-- Relation table triggers
DROP TRIGGER IF EXISTS update_relation_updated_at ON relation;
DROP TRIGGER IF EXISTS set_relation_defaults ON relation;

CREATE TRIGGER update_relation_updated_at
BEFORE UPDATE ON relation
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER set_relation_defaults
BEFORE INSERT ON relation
FOR EACH ROW EXECUTE FUNCTION set_default_values();

-- Observation table triggers
DROP TRIGGER IF EXISTS update_observation_updated_at ON observation;
DROP TRIGGER IF EXISTS set_observation_defaults ON observation;

CREATE TRIGGER update_observation_updated_at
BEFORE UPDATE ON observation
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER set_observation_defaults
BEFORE INSERT ON observation
FOR EACH ROW EXECUTE FUNCTION set_default_values();

-- Incident table triggers
DROP TRIGGER IF EXISTS update_incident_updated_at ON incident;
DROP TRIGGER IF EXISTS generate_incident_content_hash ON incident;
DROP TRIGGER IF EXISTS set_incident_defaults ON incident;

CREATE TRIGGER update_incident_updated_at
BEFORE UPDATE ON incident
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER generate_incident_content_hash
BEFORE INSERT OR UPDATE ON incident
FOR EACH ROW EXECUTE FUNCTION generate_content_hash();

CREATE TRIGGER set_incident_defaults
BEFORE INSERT ON incident
FOR EACH ROW EXECUTE FUNCTION set_default_values();

-- Release table triggers
DROP TRIGGER IF EXISTS update_release_updated_at ON release;
DROP TRIGGER IF EXISTS generate_release_content_hash ON release;
DROP TRIGGER IF EXISTS set_release_defaults ON release;

CREATE TRIGGER update_release_updated_at
BEFORE UPDATE ON release
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER generate_release_content_hash
BEFORE INSERT OR UPDATE ON release
FOR EACH ROW EXECUTE FUNCTION generate_content_hash();

CREATE TRIGGER set_release_defaults
BEFORE INSERT ON release
FOR EACH ROW EXECUTE FUNCTION set_default_values();

-- Risk table triggers
DROP TRIGGER IF EXISTS update_risk_updated_at ON risk;
DROP TRIGGER IF EXISTS generate_risk_content_hash ON risk;
DROP TRIGGER IF EXISTS set_risk_defaults ON risk;

CREATE TRIGGER update_risk_updated_at
BEFORE UPDATE ON risk
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER generate_risk_content_hash
BEFORE INSERT OR UPDATE ON risk
FOR EACH ROW EXECUTE FUNCTION generate_content_hash();

CREATE TRIGGER set_risk_defaults
BEFORE INSERT ON risk
FOR EACH ROW EXECUTE FUNCTION set_default_values();

-- Assumption table triggers
DROP TRIGGER IF EXISTS update_assumption_updated_at ON assumption;
DROP TRIGGER IF EXISTS generate_assumption_content_hash ON assumption;
DROP TRIGGER IF EXISTS set_assumption_defaults ON assumption;

CREATE TRIGGER update_assumption_updated_at
BEFORE UPDATE ON assumption
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER generate_assumption_content_hash
BEFORE INSERT OR UPDATE ON assumption
FOR EACH ROW EXECUTE FUNCTION generate_content_hash();

CREATE TRIGGER set_assumption_defaults
BEFORE INSERT ON assumption
FOR EACH ROW EXECUTE FUNCTION set_default_values();

-- DDL Log table triggers
DROP TRIGGER IF EXISTS update_ddl_log_updated_at ON ddl_log;
DROP TRIGGER IF EXISTS set_ddl_log_defaults ON ddl_log;

CREATE TRIGGER update_ddl_log_updated_at
BEFORE UPDATE ON ddl_log
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER set_ddl_log_defaults
BEFORE INSERT ON ddl_log
FOR EACH ROW EXECUTE FUNCTION set_default_values();

-- AUDIT TRIGGER FUNCTION
-- =====================

CREATE OR REPLACE FUNCTION audit_trigger_function()
RETURNS TRIGGER AS $$
BEGIN
    -- Only audit specific tables to avoid noise
    IF TG_TABLE_NAME IN ('section', 'adr_decision', 'issue_log', 'todo_log', 'entity', 'relation', 'observation', 'incident', 'release', 'risk', 'assumption') THEN
        INSERT INTO event_audit (
            event_type,
            table_name,
            record_id,
            operation,
            old_data,
            new_data,
            changed_by,
            created_at
        ) VALUES (
            TG_OP,
            TG_TABLE_NAME,
            COALESCE(NEW.id, OLD.id)::text,
            TG_OP,
            CASE WHEN TG_OP = 'DELETE' THEN row_to_json(OLD) ELSE NULL END,
            CASE WHEN TG_OP IN ('INSERT', 'UPDATE') THEN row_to_json(NEW) ELSE NULL END,
            COALESCE(NEW.updated_by, OLD.updated_by, 'system'),
            NOW()
        );
    END IF;

    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

-- Apply audit triggers to key tables
DO $$
DECLARE
    table_name TEXT;
    audit_tables TEXT[] := ARRAY['section', 'adr_decision', 'issue_log', 'todo_log', 'entity', 'relation', 'observation', 'incident', 'release', 'risk', 'assumption'];
BEGIN
    FOREACH table_name IN ARRAY audit_tables
    LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS audit_%I ON %I', table_name, table_name);
        EXECUTE format('CREATE TRIGGER audit_%I
                        AFTER INSERT OR UPDATE OR DELETE ON %I
                        FOR EACH ROW EXECUTE FUNCTION audit_trigger_function()',
                        table_name, table_name);
    END LOOP;
END $$;

-- TRIGGER VERIFICATION QUERIES
-- ============================

-- Query to check all triggers on a specific table:
/*
SELECT
    trigger_name,
    event_manipulation,
    event_object_table,
    action_timing,
    action_condition,
    action_statement
FROM information_schema.triggers
WHERE trigger_schema = 'public'
    AND event_object_table = 'section'
ORDER BY trigger_name;
*/

-- Query to check all triggers in the database:
/*
SELECT
    event_object_table,
    trigger_name,
    event_manipulation,
    action_timing
FROM information_schema.triggers
WHERE trigger_schema = 'public'
ORDER BY event_object_table, trigger_name;
*/

-- Test trigger functionality:
/*
-- Test content hash generation
BEGIN;
INSERT INTO section (title, content) VALUES ('Test Title', 'Test Content');
SELECT title, content_hash FROM section WHERE title = 'Test Title';
ROLLBACK;

-- Test updated_at trigger
BEGIN;
INSERT INTO section (title, content) VALUES ('Test Title', 'Test Content') RETURNING updated_at;
-- Wait a second, then update
UPDATE section SET title = 'Updated Title' WHERE title = 'Test Title' RETURNING updated_at;
ROLLBACK;
*/

RAISE NOTICE '✅ Database triggers setup complete';
RAISE NOTICE '✅ Automatic timestamp management enabled';
RAISE NOTICE '✅ Content hash generation enabled';
RAISE NOTICE '✅ Default value population enabled';
RAISE NOTICE '✅ Audit logging enabled for key tables';