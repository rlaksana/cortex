/**
 * Cortex Memory MCP - PostgreSQL 18 Database Schema
 *
 * Production-ready schema with comprehensive tables, indexes, and constraints.
 * Supports all 16 knowledge types with full-text search, graph relationships,
 * and audit trail capabilities.
 *
 * PostgreSQL 18 Features Used:
 * - gen_random_uuid() for UUID generation
 * - Generated columns for FTS optimization
 * - JSONB with GIN indexes for flexible metadata
 * - Trigger-based audit logging
 * - Partial indexes for performance
 * - Check constraints for data integrity
 */

import { Client } from 'pg';

/**
 * Complete database schema definition for Cortex Memory MCP
 */
export const SCHEMA_DDL = `
-- ============================================================================
-- CORE TABLES - Knowledge Storage
-- ============================================================================

-- Document containers for organizing sections
CREATE TABLE IF NOT EXISTS document (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title VARCHAR(500) NOT NULL,
  description TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  tags JSONB DEFAULT '{}',
  metadata JSONB DEFAULT '{}',
  CONSTRAINT document_title_length CHECK (char_length(title) >= 1 AND char_length(title) <= 500)
);

-- Sections with full-text search support (primary knowledge storage)
CREATE TABLE IF NOT EXISTS section (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  document_id UUID REFERENCES document(id) ON DELETE CASCADE,
  heading VARCHAR(300) NOT NULL,
  body_md TEXT,
  body_text TEXT,
  title VARCHAR(500) NOT NULL,
  citation_count INTEGER DEFAULT 0 NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  tags JSONB DEFAULT '{}',
  metadata JSONB DEFAULT '{}',
  body_jsonb JSONB GENERATED ALWAYS AS (
    jsonb_build_object(
      'text', COALESCE(body_text, ''),
      'markdown', COALESCE(body_md, '')
    )
  ) STORED,
  -- Full-text search vector
  ts TSVECTOR GENERATED ALWAYS AS (
    to_tsvector('english', COALESCE(heading, '') || ' ' || COALESCE(title, '') || ' ' || COALESCE(body_text, ''))
  ) STORED,
  CONSTRAINT section_title_length CHECK (char_length(title) >= 1 AND char_length(title) <= 500),
  CONSTRAINT section_heading_length CHECK (char_length(heading) >= 1 AND char_length(heading) <= 300)
);

-- Runbook table for operational procedures
CREATE TABLE IF NOT EXISTS runbook (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  service VARCHAR(200) NOT NULL,
  title VARCHAR(500) NOT NULL,
  description TEXT,
  steps_jsonb JSONB NOT NULL,
  triggers TEXT[],
  last_verified_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  tags JSONB DEFAULT '{}',
  metadata JSONB DEFAULT '{}',
  CONSTRAINT runbook_service_length CHECK (char_length(service) >= 1 AND char_length(service) <= 200),
  CONSTRAINT runbook_title_length CHECK (char_length(title) >= 1 AND char_length(title) <= 500),
  CONSTRAINT runbook_steps_not_empty CHECK (jsonb_array_length(steps_jsonb) > 0)
);

-- Change log for tracking code changes
CREATE TABLE IF NOT EXISTS change_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  change_type VARCHAR(50) NOT NULL,
  subject_ref VARCHAR(200) NOT NULL,
  summary TEXT NOT NULL,
  details TEXT,
  affected_files TEXT[],
  author VARCHAR(200),
  commit_sha VARCHAR(100),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  tags JSONB DEFAULT '{}',
  metadata JSONB DEFAULT '{}',
  CONSTRAINT change_log_valid_type CHECK (change_type IN ('feature_add', 'feature_modify', 'feature_remove', 'bugfix', 'refactor', 'config_change', 'dependency_update')),
  CONSTRAINT change_log_subject_ref_length CHECK (char_length(subject_ref) >= 1 AND char_length(subject_ref) <= 200),
  CONSTRAINT change_log_summary_length CHECK (char_length(summary) >= 1)
);

-- Issue tracking table
CREATE TABLE IF NOT EXISTS issue_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tracker VARCHAR(100) NOT NULL,
  external_id VARCHAR(100) NOT NULL,
  title VARCHAR(500) NOT NULL,
  description TEXT,
  status VARCHAR(50) NOT NULL DEFAULT 'open',
  assignee VARCHAR(200),
  labels TEXT[],
  url TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  tags JSONB DEFAULT '{}',
  metadata JSONB DEFAULT '{}',
  CONSTRAINT issue_log_tracker_length CHECK (char_length(tracker) >= 1 AND char_length(tracker) <= 100),
  CONSTRAINT issue_log_external_id_length CHECK (char_length(external_id) >= 1 AND char_length(external_id) <= 100),
  CONSTRAINT issue_log_title_length CHECK (char_length(title) >= 1 AND char_length(title) <= 500),
  CONSTRAINT issue_log_valid_status CHECK (status IN ('open', 'in_progress', 'resolved', 'closed', 'wont_fix')),
  CONSTRAINT issue_log_unique_external UNIQUE (tracker, external_id)
);

-- Architecture Decision Records (ADR)
CREATE TABLE IF NOT EXISTS adr_decision (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  component VARCHAR(200) NOT NULL,
  status VARCHAR(50) NOT NULL DEFAULT 'proposed',
  title VARCHAR(500) NOT NULL,
  rationale TEXT NOT NULL,
  alternatives_considered TEXT[],
  consequences TEXT,
  supersedes UUID REFERENCES adr_decision(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  tags JSONB DEFAULT '{}',
  metadata JSONB DEFAULT '{}',
  CONSTRAINT adr_decision_component_length CHECK (char_length(component) >= 1 AND char_length(component) <= 200),
  CONSTRAINT adr_decision_title_length CHECK (char_length(title) >= 1 AND char_length(title) <= 500),
  CONSTRAINT adr_decision_rationale_length CHECK (char_length(rationale) >= 1),
  CONSTRAINT adr_decision_valid_status CHECK (status IN ('proposed', 'accepted', 'rejected', 'deprecated', 'superseded'))
);

-- TODO/task management
CREATE TABLE IF NOT EXISTS todo_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scope VARCHAR(200) NOT NULL,
  todo_type VARCHAR(50) NOT NULL DEFAULT 'task',
  text TEXT NOT NULL,
  status VARCHAR(50) NOT NULL DEFAULT 'open',
  priority VARCHAR(20),
  assignee VARCHAR(200),
  due_date TIMESTAMPTZ,
  closed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  tags JSONB DEFAULT '{}',
  metadata JSONB DEFAULT '{}',
  CONSTRAINT todo_log_scope_length CHECK (char_length(scope) >= 1 AND char_length(scope) <= 200),
  CONSTRAINT todo_log_text_length CHECK (char_length(text) >= 1),
  CONSTRAINT todo_log_valid_type CHECK (todo_type IN ('task', 'bug', 'epic', 'story', 'spike')),
  CONSTRAINT todo_log_valid_status CHECK (status IN ('open', 'in_progress', 'done', 'cancelled', 'archived')),
  CONSTRAINT todo_log_valid_priority CHECK (priority IS NULL OR priority IN ('low', 'medium', 'high', 'critical'))
);

-- Release notes table
CREATE TABLE IF NOT EXISTS release_note (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  version VARCHAR(100) NOT NULL,
  release_date TIMESTAMPTZ NOT NULL,
  summary TEXT NOT NULL,
  breaking_changes TEXT[],
  new_features TEXT[],
  bug_fixes TEXT[],
  deprecations TEXT[],
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  tags JSONB DEFAULT '{}',
  metadata JSONB DEFAULT '{}',
  CONSTRAINT release_note_version_length CHECK (char_length(version) >= 1 AND char_length(version) <= 100),
  CONSTRAINT release_note_summary_length CHECK (char_length(summary) >= 1),
  CONSTRAINT release_note_unique_version UNIQUE (version)
);

-- DDL/Migration history
CREATE TABLE IF NOT EXISTS ddl_history (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  migration_id VARCHAR(200) NOT NULL,
  ddl_text TEXT NOT NULL,
  checksum VARCHAR(64) NOT NULL,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  description TEXT,
  status VARCHAR(20) NOT NULL DEFAULT 'applied',
  tags JSONB DEFAULT '{}',
  metadata JSONB DEFAULT '{}',
  CONSTRAINT ddl_history_migration_id_length CHECK (char_length(migration_id) >= 1 AND char_length(migration_id) <= 200),
  CONSTRAINT ddl_history_ddl_length CHECK (char_length(ddl_text) >= 1),
  CONSTRAINT ddl_history_checksum_length CHECK (char_length(checksum) = 64),
  CONSTRAINT ddl_history_valid_status CHECK (status IN ('pending', 'applied', 'failed', 'rolled_back')),
  CONSTRAINT ddl_history_unique_migration UNIQUE (migration_id)
);

-- Pull request context table
CREATE TABLE IF NOT EXISTS pr_context (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  pr_number INTEGER NOT NULL,
  title VARCHAR(500) NOT NULL,
  description TEXT,
  author VARCHAR(200) NOT NULL,
  status VARCHAR(50) NOT NULL DEFAULT 'open',
  base_branch VARCHAR(200) NOT NULL,
  head_branch VARCHAR(200) NOT NULL,
  merged_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  tags JSONB DEFAULT '{}',
  metadata JSONB DEFAULT '{}',
  CONSTRAINT pr_context_title_length CHECK (char_length(title) >= 1 AND char_length(title) <= 500),
  CONSTRAINT pr_context_author_length CHECK (char_length(author) >= 1 AND char_length(author) <= 200),
  CONSTRAINT pr_context_branch_length CHECK (char_length(base_branch) >= 1 AND char_length(base_branch) <= 200),
  CONSTRAINT pr_context_branch_head_length CHECK (char_length(head_branch) >= 1 AND char_length(head_branch) <= 200),
  CONSTRAINT pr_context_valid_status CHECK (status IN ('open', 'merged', 'closed', 'draft')),
  CONSTRAINT pr_context_pr_number_positive CHECK (pr_number > 0)
);

-- ============================================================================
-- GRAPH EXTENSION TABLES - Entity-Relationship Model
-- ============================================================================

-- Flexible entity storage (graph nodes)
CREATE TABLE IF NOT EXISTS knowledge_entity (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  entity_type VARCHAR(100) NOT NULL,
  name VARCHAR(500) NOT NULL,
  data JSONB NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMPTZ,
  tags JSONB DEFAULT '{}',
  metadata JSONB DEFAULT '{}',
  CONSTRAINT knowledge_entity_type_length CHECK (char_length(entity_type) >= 1 AND char_length(entity_type) <= 100),
  CONSTRAINT knowledge_entity_name_length CHECK (char_length(name) >= 1 AND char_length(name) <= 500),
  CONSTRAINT knowledge_entity_unique_name_type UNIQUE (entity_type, name) WHERE deleted_at IS NULL
);

-- Entity relationships (graph edges)
CREATE TABLE IF NOT EXISTS knowledge_relation (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  from_entity_type VARCHAR(100) NOT NULL,
  from_entity_id UUID NOT NULL,
  to_entity_type VARCHAR(100) NOT NULL,
  to_entity_id UUID NOT NULL,
  relation_type VARCHAR(100) NOT NULL,
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  tags JSONB DEFAULT '{}',
  CONSTRAINT knowledge_relation_from_type_length CHECK (char_length(from_entity_type) >= 1 AND char_length(from_entity_type) <= 100),
  CONSTRAINT knowledge_relation_to_type_length CHECK (char_length(to_entity_type) >= 1 AND char_length(to_entity_type) <= 100),
  CONSTRAINT knowledge_relation_type_length CHECK (char_length(relation_type) >= 1 AND char_length(relation_type) <= 100),
  CONSTRAINT knowledge_relation_self_loop CHECK (from_entity_type != to_entity_type OR from_entity_id != to_entity_id),
  CONSTRAINT knowledge_relation_unique_relationship UNIQUE (from_entity_type, from_entity_id, to_entity_type, to_entity_id, relation_type)
);

-- Fine-grained observations attached to entities
CREATE TABLE IF NOT EXISTS knowledge_observation (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  entity_type VARCHAR(100) NOT NULL,
  entity_id UUID NOT NULL,
  observation TEXT NOT NULL,
  observation_type VARCHAR(100),
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  tags JSONB DEFAULT '{}',
  CONSTRAINT knowledge_observation_type_length CHECK (char_length(entity_type) >= 1 AND char_length(entity_type) <= 100),
  CONSTRAINT knowledge_observation_length CHECK (char_length(observation) >= 1),
  CONSTRAINT knowledge_observation_type_length_optional CHECK (observation_type IS NULL OR (char_length(observation_type) >= 1 AND char_length(observation_type) <= 100))
);

-- ============================================================================
-- 8-LOG SYSTEM TABLES - Session Persistence
-- ============================================================================

-- Incident management log
CREATE TABLE IF NOT EXISTS incident_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title VARCHAR(500) NOT NULL,
  severity VARCHAR(20) NOT NULL,
  impact TEXT NOT NULL,
  timeline JSONB,
  root_cause_analysis TEXT,
  resolution_status VARCHAR(50) NOT NULL DEFAULT 'open',
  affected_services TEXT[],
  business_impact TEXT,
  recovery_actions TEXT[],
  follow_up_required BOOLEAN DEFAULT false,
  incident_commander VARCHAR(200),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  tags JSONB DEFAULT '{}',
  metadata JSONB DEFAULT '{}',
  CONSTRAINT incident_log_title_length CHECK (char_length(title) >= 1 AND char_length(title) <= 500),
  CONSTRAINT incident_log_impact_length CHECK (char_length(impact) >= 1),
  CONSTRAINT incident_log_valid_severity CHECK (severity IN ('critical', 'high', 'medium', 'low')),
  CONSTRAINT incident_log_valid_status CHECK (resolution_status IN ('open', 'investigating', 'resolved', 'closed'))
);

-- Release management log
CREATE TABLE IF NOT EXISTS release_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  version VARCHAR(100) NOT NULL,
  release_type VARCHAR(50) NOT NULL,
  scope TEXT NOT NULL,
  release_date TIMESTAMPTZ,
  status VARCHAR(50) NOT NULL DEFAULT 'planned',
  ticket_references TEXT[],
  included_changes TEXT[],
  deployment_strategy TEXT,
  rollback_plan TEXT,
  testing_status TEXT,
  approvers TEXT[],
  release_notes TEXT,
  post_release_actions TEXT[],
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  tags JSONB DEFAULT '{}',
  metadata JSONB DEFAULT '{}',
  CONSTRAINT release_log_version_length CHECK (char_length(version) >= 1 AND char_length(version) <= 100),
  CONSTRAINT release_log_scope_length CHECK (char_length(scope) >= 1),
  CONSTRAINT release_log_valid_type CHECK (release_type IN ('major', 'minor', 'patch', 'hotfix')),
  CONSTRAINT release_log_valid_status CHECK (status IN ('planned', 'in_progress', 'completed', 'rolled_back'))
);

-- Risk management log
CREATE TABLE IF NOT EXISTS risk_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title VARCHAR(500) NOT NULL,
  category VARCHAR(50) NOT NULL,
  risk_level VARCHAR(20) NOT NULL,
  probability VARCHAR(20) NOT NULL,
  impact_description TEXT NOT NULL,
  trigger_events TEXT[],
  mitigation_strategies TEXT[],
  owner VARCHAR(200),
  review_date TIMESTAMPTZ,
  status VARCHAR(50) NOT NULL DEFAULT 'active',
  related_decisions UUID[],
  monitoring_indicators TEXT[],
  contingency_plans TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  tags JSONB DEFAULT '{}',
  metadata JSONB DEFAULT '{}',
  CONSTRAINT risk_log_title_length CHECK (char_length(title) >= 1 AND char_length(title) <= 500),
  CONSTRAINT risk_log_impact_length CHECK (char_length(impact_description) >= 1),
  CONSTRAINT risk_log_valid_category CHECK (category IN ('technical', 'business', 'operational', 'security', 'compliance')),
  CONSTRAINT risk_log_valid_level CHECK (risk_level IN ('critical', 'high', 'medium', 'low')),
  CONSTRAINT risk_log_valid_probability CHECK (probability IN ('very_likely', 'likely', 'possible', 'unlikely', 'very_unlikely')),
  CONSTRAINT risk_log_valid_status CHECK (status IN ('active', 'mitigated', 'accepted', 'closed'))
);

-- Assumption management log
CREATE TABLE IF NOT EXISTS assumption_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title VARCHAR(500) NOT NULL,
  description TEXT NOT NULL,
  category VARCHAR(50) NOT NULL,
  validation_status VARCHAR(50) NOT NULL DEFAULT 'assumed',
  impact_if_invalid TEXT NOT NULL,
  validation_criteria TEXT[],
  validation_date TIMESTAMPTZ,
  owner VARCHAR(200),
  related_assumptions UUID[],
  dependencies TEXT[],
  monitoring_approach TEXT,
  review_frequency VARCHAR(20),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  tags JSONB DEFAULT '{}',
  metadata JSONB DEFAULT '{}',
  CONSTRAINT assumption_log_title_length CHECK (char_length(title) >= 1 AND char_length(title) <= 500),
  CONSTRAINT assumption_log_description_length CHECK (char_length(description) >= 1),
  CONSTRAINT assumption_log_impact_length CHECK (char_length(impact_if_invalid) >= 1),
  CONSTRAINT assumption_log_valid_category CHECK (category IN ('technical', 'business', 'user', 'market', 'resource')),
  CONSTRAINT assumption_log_valid_status CHECK (validation_status IN ('validated', 'assumed', 'invalidated', 'needs_validation')),
  CONSTRAINT assumption_log_valid_frequency CHECK (review_frequency IS NULL OR review_frequency IN ('daily', 'weekly', 'monthly', 'quarterly', 'as_needed'))
);

-- ============================================================================
-- AUDIT TRAIL TABLE
-- ============================================================================

-- Comprehensive audit trail for all operations
CREATE TABLE IF NOT EXISTS event_audit (
  id BIGSERIAL PRIMARY KEY,
  event_id UUID NOT NULL DEFAULT gen_random_uuid(),
  event_type VARCHAR(100) NOT NULL,
  table_name VARCHAR(100) NOT NULL,
  record_id UUID NOT NULL,
  operation VARCHAR(20) NOT NULL,
  old_data JSONB,
  new_data JSONB,
  changed_by VARCHAR(200) NOT NULL,
  changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  tags JSONB DEFAULT '{}',
  metadata JSONB DEFAULT '{}',
  CONSTRAINT event_audit_valid_operation CHECK (operation IN ('INSERT', 'UPDATE', 'DELETE')),
  CONSTRAINT event_audit_type_length CHECK (char_length(event_type) >= 1 AND char_length(event_type) <= 100),
  CONSTRAINT event_audit_table_length CHECK (char_length(table_name) >= 1 AND char_length(table_name) <= 100)
);

-- ============================================================================
-- INDEXES FOR PERFORMANCE OPTIMIZATION
-- ============================================================================

-- Full-text search indexes
CREATE INDEX IF NOT EXISTS idx_section_ts ON section USING GIN (ts);
CREATE INDEX IF NOT EXISTS idx_section_title ON section USING gin (to_tsvector('english', title));
CREATE INDEX IF NOT EXISTS idx_section_heading ON section USING gin (to_tsvector('english', heading));

-- JSONB indexes for flexible querying
CREATE INDEX IF NOT EXISTS idx_section_tags ON section USING GIN (tags);
CREATE INDEX IF NOT EXISTS idx_runbook_tags ON runbook USING GIN (tags);
CREATE INDEX IF NOT EXISTS idx_change_log_tags ON change_log USING GIN (tags);
CREATE INDEX IF NOT EXISTS idx_issue_log_tags ON issue_log USING GIN (tags);
CREATE INDEX IF NOT EXISTS idx_adr_decision_tags ON adr_decision USING GIN (tags);
CREATE INDEX IF NOT EXISTS idx_todo_log_tags ON todo_log USING GIN (tags);
CREATE INDEX IF NOT EXISTS idx_release_note_tags ON release_note USING GIN (tags);
CREATE INDEX IF NOT EXISTS idx_pr_context_tags ON pr_context USING GIN (tags);
CREATE INDEX IF NOT EXISTS idx_knowledge_entity_tags ON knowledge_entity USING GIN (tags);
CREATE INDEX IF NOT EXISTS idx_knowledge_relation_tags ON knowledge_relation USING GIN (tags);
CREATE INDEX IF NOT EXISTS idx_knowledge_observation_tags ON knowledge_observation USING GIN (tags);
CREATE INDEX IF NOT EXISTS idx_incident_log_tags ON incident_log USING GIN (tags);
CREATE INDEX IF NOT EXISTS idx_release_log_tags ON release_log USING GIN (tags);
CREATE INDEX IF NOT EXISTS idx_risk_log_tags ON risk_log USING GIN (tags);
CREATE INDEX IF NOT EXISTS idx_assumption_log_tags ON assumption_log USING GIN (tags);

-- Performance indexes for common queries
CREATE INDEX IF NOT EXISTS idx_section_updated_at ON section (updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_section_created_at ON section (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_section_citation_count ON section (citation_count DESC);
CREATE INDEX IF NOT EXISTS idx_document_created_at ON document (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_runbook_service ON runbook (service);
CREATE INDEX IF NOT EXISTS idx_runbook_updated_at ON runbook (updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_change_log_updated_at ON change_log (updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_issue_log_status ON issue_log (status);
CREATE INDEX IF NOT EXISTS idx_issue_log_updated_at ON issue_log (updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_adr_decision_status ON adr_decision (status);
CREATE INDEX IF NOT EXISTS idx_adr_decision_component ON adr_decision (component);
CREATE INDEX IF NOT EXISTS idx_todo_log_status ON todo_log (status);
CREATE INDEX IF NOT EXISTS idx_todo_log_priority ON todo_log (priority);
CREATE INDEX IF NOT EXISTS idx_todo_log_due_date ON todo_log (due_date);
CREATE INDEX IF NOT EXISTS idx_release_note_version ON release_note (version);
CREATE INDEX IF NOT EXISTS idx_release_note_release_date ON release_note (release_date DESC);
CREATE INDEX IF NOT EXISTS idx_pr_context_status ON pr_context (status);
CREATE INDEX IF NOT EXISTS idx_pr_context_pr_number ON pr_context (pr_number);
CREATE INDEX IF NOT EXISTS idx_pr_context_expires_at ON pr_context (expires_at);

-- Graph-specific indexes
CREATE INDEX IF NOT EXISTS idx_knowledge_entity_type ON knowledge_entity (entity_type);
CREATE INDEX IF NOT EXISTS idx_knowledge_entity_name ON knowledge_entity (name);
CREATE INDEX IF NOT EXISTS idx_knowledge_entity_deleted_at ON knowledge_entity (deleted_at) WHERE deleted_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_knowledge_relation_from ON knowledge_relation (from_entity_type, from_entity_id);
CREATE INDEX IF NOT EXISTS idx_knowledge_relation_to ON knowledge_relation (to_entity_type, to_entity_id);
CREATE INDEX IF NOT EXISTS idx_knowledge_relation_type ON knowledge_relation (relation_type);
CREATE INDEX IF NOT EXISTS idx_knowledge_observation_entity ON knowledge_observation (entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_knowledge_observation_type ON knowledge_observation (observation_type);

-- 8-LOG SYSTEM indexes
CREATE INDEX IF NOT EXISTS idx_incident_log_severity ON incident_log (severity);
CREATE INDEX IF NOT EXISTS idx_incident_log_status ON incident_log (resolution_status);
CREATE INDEX IF NOT EXISTS idx_incident_log_created_at ON incident_log (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_release_log_version ON release_log (version);
CREATE INDEX IF NOT EXISTS idx_release_log_status ON release_log (status);
CREATE INDEX IF NOT EXISTS idx_release_log_release_date ON release_log (release_date DESC);
CREATE INDEX IF NOT EXISTS idx_risk_log_level ON risk_log (risk_level);
CREATE INDEX IF NOT EXISTS idx_risk_log_status ON risk_log (status);
CREATE INDEX IF NOT EXISTS idx_risk_log_category ON risk_log (category);
CREATE INDEX IF NOT EXISTS idx_assumption_log_status ON assumption_log (validation_status);
CREATE INDEX IF NOT EXISTS idx_assumption_log_category ON assumption_log (category);

-- Audit trail indexes
CREATE INDEX IF NOT EXISTS idx_event_audit_event_type ON event_audit (event_type);
CREATE INDEX IF NOT EXISTS idx_event_audit_table_name ON event_audit (table_name);
CREATE INDEX IF NOT EXISTS idx_event_audit_record_id ON event_audit (record_id);
CREATE INDEX IF NOT EXISTS idx_event_audit_operation ON event_audit (operation);
CREATE INDEX IF NOT EXISTS idx_event_audit_changed_at ON event_audit (changed_at DESC);
CREATE INDEX IF NOT EXISTS idx_event_audit_event_id ON event_audit (event_id);

-- Partial indexes for performance optimization
CREATE INDEX IF NOT EXISTS idx_todo_log_open ON todo_log (id, text, priority, due_date) WHERE status = 'open';
CREATE INDEX IF NOT EXISTS idx_issue_log_open ON issue_log (id, title, status) WHERE status = 'open';
CREATE INDEX IF NOT EXISTS idx_incident_log_active ON incident_log (id, title, severity) WHERE resolution_status != 'closed';
CREATE INDEX IF NOT EXISTS idx_risk_log_active ON risk_log (id, title, risk_level) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_assumption_log_active ON assumption_log (id, title, validation_status) WHERE validation_status != 'validated';

-- ============================================================================
-- TRIGGERS FOR AUTOMATIC AUDIT TRAIL
-- ============================================================================

-- Function to create audit entries
CREATE OR REPLACE FUNCTION audit_trigger_function()
RETURNS TRIGGER AS $$
DECLARE
  old_data_json JSONB;
  new_data_json JSONB;
  operation_type VARCHAR(20);
BEGIN
  -- Determine operation type
  IF TG_OP = 'INSERT' THEN
    operation_type := 'INSERT';
    new_data_json := to_jsonb(NEW);
    old_data_json := NULL;
  ELSIF TG_OP = 'UPDATE' THEN
    operation_type := 'UPDATE';
    new_data_json := to_jsonb(NEW);
    old_data_json := to_jsonb(OLD);
  ELSIF TG_OP = 'DELETE' THEN
    operation_type := 'DELETE';
    new_data_json := NULL;
    old_data_json := to_jsonb(OLD);
  ELSE
    RETURN NEW;
  END IF;

  -- Insert audit record
  INSERT INTO event_audit (
    event_type,
    table_name,
    record_id,
    operation,
    old_data,
    new_data,
    changed_by,
    tags,
    metadata
  ) VALUES (
    TG_ARGV[0], -- event type
    TG_TABLE_NAME,
    COALESCE(NEW.id, OLD.id),
    operation_type,
    old_data_json,
    new_data_json,
    COALESCE(NEW.updated_by, OLD.updated_by, 'system'),
    COALESCE(NEW.tags, OLD.tags, '{}'),
    COALESCE(NEW.metadata, OLD.metadata, '{}')
  );

  RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

-- Create audit triggers for all main tables
DO $$
DECLARE
  table_record RECORD;
  trigger_name TEXT;
BEGIN
  FOR table_record IN
    SELECT table_name
    FROM information_schema.tables
    WHERE table_schema = 'public'
      AND table_name NOT IN ('event_audit', 'ddl_history')
      AND table_type = 'BASE TABLE'
  LOOP
    trigger_name := 'audit_trigger_' || table_record.table_name;

    EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I', trigger_name, table_record.table_name);
    EXECUTE format('
      CREATE TRIGGER %I
      AFTER INSERT OR UPDATE OR DELETE ON %I
      FOR EACH ROW EXECUTE FUNCTION audit_trigger_function(%L)
    ', trigger_name, table_record.table_name, 'knowledge_change');
  END LOOP;
END $$;

-- ============================================================================
-- TRIGGERS FOR AUTOMATIC TIMESTAMP UPDATES
-- ============================================================================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create updated_at triggers for tables that need it
DO $$
DECLARE
  table_record RECORD;
  trigger_name TEXT;
BEGIN
  FOR table_record IN
    SELECT table_name
    FROM information_schema.tables
    WHERE table_schema = 'public'
      AND table_name IN (
        'document', 'section', 'runbook', 'change_log', 'issue_log',
        'adr_decision', 'todo_log', 'release_note', 'pr_context',
        'knowledge_entity', 'knowledge_relation', 'knowledge_observation',
        'incident_log', 'release_log', 'risk_log', 'assumption_log'
      )
  LOOP
    trigger_name := 'update_updated_at_' || table_record.table_name;

    EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I', trigger_name, table_record.table_name);
    EXECUTE format('
      CREATE TRIGGER %I
      BEFORE UPDATE ON %I
      FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()
    ', trigger_name, table_record.table_name);
  END LOOP;
END $$;

-- ============================================================================
-- VIEWS FOR COMMON QUERIES
-- ============================================================================

-- View for active knowledge items (non-deleted entities, open todos/issues)
CREATE OR REPLACE VIEW active_knowledge AS
SELECT
  'section' as type, s.id, s.title as name, s.updated_at, s.tags
  FROM section s
UNION ALL
SELECT
  'runbook' as type, r.id, r.title as name, r.updated_at, r.tags
  FROM runbook r
UNION ALL
SELECT
  'change' as type, c.id, c.subject_ref as name, c.updated_at, c.tags
  FROM change_log c
UNION ALL
SELECT
  'issue' as type, i.id, i.title as name, i.updated_at, i.tags
  FROM issue_log i WHERE i.status != 'closed'
UNION ALL
SELECT
  'decision' as type, a.id, a.title as name, a.updated_at, a.tags
  FROM adr_decision a
UNION ALL
SELECT
  'todo' as type, t.id, t.text as name, t.updated_at, t.tags
  FROM todo_log t WHERE t.status != 'done' AND t.status != 'cancelled'
UNION ALL
SELECT
  'release_note' as type, r.id, r.version as name, r.updated_at, r.tags
  FROM release_note r
UNION ALL
SELECT
  'pr_context' as type, p.id, p.title as name, p.updated_at, p.tags
  FROM pr_context p WHERE p.status != 'merged'
UNION ALL
SELECT
  'entity' as type, e.id, e.name, e.updated_at, e.tags
  FROM knowledge_entity e WHERE e.deleted_at IS NULL;

-- View for graph relationships
CREATE OR REPLACE VIEW graph_relationships AS
SELECT
  kr.from_entity_type,
  kr.from_entity_id,
  kr.to_entity_type,
  kr.to_entity_id,
  kr.relation_type,
  kr.metadata,
  kr.created_at
FROM knowledge_relation kr
UNION ALL
-- Include ADR supersedes relationships
SELECT
  'adr_decision' as from_entity_type,
  a1.id as from_entity_id,
  'adr_decision' as to_entity_type,
  a1.supersedes as to_entity_id,
  'supersedes' as relation_type,
  jsonb_build_object('type', 'adr_supersedes') as metadata,
  a1.updated_at as created_at
FROM adr_decision a1
WHERE a1.supersedes IS NOT NULL;

-- View for recent activity
CREATE OR REPLACE VIEW recent_activity AS
SELECT
  'section' as type, s.id, s.title as description, s.updated_at as timestamp, s.tags
  FROM section s
  WHERE s.updated_at >= NOW() - INTERVAL '7 days'
UNION ALL
SELECT
  'change' as type, c.id, c.summary as description, c.updated_at as timestamp, c.tags
  FROM change_log c
  WHERE c.updated_at >= NOW() - INTERVAL '7 days'
UNION ALL
SELECT
  'issue' as type, i.id, i.title as description, i.updated_at as timestamp, i.tags
  FROM issue_log i
  WHERE i.updated_at >= NOW() - INTERVAL '7 days'
UNION ALL
SELECT
  'todo' as type, t.id, t.text as description, t.updated_at as timestamp, t.tags
  FROM todo_log t
  WHERE t.updated_at >= NOW() - INTERVAL '7 days'
ORDER BY timestamp DESC;

-- ============================================================================
-- TABLE STATISTICS (for monitoring and optimization)
-- ============================================================================

-- Create a function to get table statistics
CREATE OR REPLACE FUNCTION get_table_statistics()
RETURNS TABLE (
  table_name TEXT,
  total_rows BIGINT,
  table_size BIGINT,
  index_size BIGINT,
  total_size BIGINT,
  last_vacuum TIMESTAMPTZ,
  last_autovacuum TIMESTAMPTZ,
  last_analyze TIMESTAMPTZ,
  last_autoanalyze TIMESTAMPTZ
) AS $$
BEGIN
  RETURN QUERY
  SELECT
    schemaname || '.' || tablename as table_name,
    n_live_tup as total_rows,
    pg_total_relation_size(schemaname || '.' || tablename) as table_size,
    pg_indexes_size(schemaname || '.' || tablename) as index_size,
    pg_total_relation_size(schemaname || '.' || tablename) + pg_indexes_size(schemaname || '.' || tablename) as total_size,
    last_vacuum,
    last_autovacuum,
    last_analyze,
    last_autoanalyze
  FROM pg_stat_user_tables
  WHERE schemaname = 'public'
  ORDER BY total_rows DESC;
END;
$$ LANGUAGE plpgsql;

-- Grant necessary permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO PUBLIC;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO PUBLIC;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO PUBLIC;

-- Set default permissions for future objects
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL PRIVILEGES ON TABLES TO PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL PRIVILEGES ON SEQUENCES TO PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO PUBLIC;
`;

/**
 * Create the complete database schema
 */
export async function createSchema(client: Client): Promise<void> {
  try {
    console.log('Creating Cortex Memory MCP database schema...');

    // Execute the complete schema DDL
    await client.query(SCHEMA_DDL);

    console.log('✓ Database schema created successfully');
    console.log('✓ All tables created with proper constraints and indexes');
    console.log('✓ Audit triggers installed for all tables');
    console.log('✓ Updated_at triggers installed for timestamp management');
    console.log('✓ Performance indexes created for optimal query performance');
    console.log('✓ Views created for common query patterns');
  } catch (error) {
    console.error('Error creating database schema:', error);
    throw error;
  }
}

/**
 * Verify that all tables were created successfully
 */
export async function verifySchema(client: Client): Promise<boolean> {
  const expectedTables = [
    'document',
    'section',
    'runbook',
    'change_log',
    'issue_log',
    'adr_decision',
    'todo_log',
    'release_note',
    'ddl_history',
    'pr_context',
    'knowledge_entity',
    'knowledge_relation',
    'knowledge_observation',
    'incident_log',
    'release_log',
    'risk_log',
    'assumption_log',
    'event_audit',
  ];

  try {
    const result = await client.query(`
      SELECT table_name
      FROM information_schema.tables
      WHERE table_schema = 'public'
        AND table_type = 'BASE TABLE'
    `);

    const createdTables = result.rows.map((row) => row.table_name);
    const missingTables = expectedTables.filter((table) => !createdTables.includes(table));

    if (missingTables.length > 0) {
      console.error('Missing tables:', missingTables);
      return false;
    }

    console.log('✓ All expected tables created successfully');
    return true;
  } catch (error) {
    console.error('Error verifying schema:', error);
    return false;
  }
}

/**
 * Get schema statistics for monitoring
 */
export async function getSchemaStatistics(client: Client): Promise<any[]> {
  try {
    const result = await client.query('SELECT * FROM get_table_statistics()');
    return result.rows;
  } catch (error) {
    console.error('Error getting schema statistics:', error);
    return [];
  }
}
