-- T013: Initial schema migration
-- Creates all 11 tables with PostgreSQL 18+ features

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- 1. document table
CREATE TABLE document (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  type TEXT NOT NULL CHECK (type IN ('spec', 'doc', 'guide', 'other')),
  title TEXT NOT NULL,
  tags JSONB NOT NULL DEFAULT '{}'::jsonb,
  approved_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 2. section table with generated FTS column
CREATE TABLE section (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  document_id UUID REFERENCES document(id) ON DELETE CASCADE,
  heading TEXT,
  body_jsonb JSONB NOT NULL,
  body_text TEXT GENERATED ALWAYS AS (body_jsonb->>'text') STORED,
  content_hash TEXT NOT NULL,
  tags JSONB NOT NULL DEFAULT '{}'::jsonb,
  citation_count BIGINT DEFAULT 0,
  last_verified_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  ts TSVECTOR GENERATED ALWAYS AS (
    setweight(to_tsvector('english', COALESCE(heading, '')), 'A') ||
    setweight(to_tsvector('english', COALESCE(body_jsonb->>'text', '')), 'B')
  ) STORED
);

-- 3-11. Remaining tables (compact definitions)
CREATE TABLE runbook (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  service TEXT NOT NULL,
  steps_jsonb JSONB NOT NULL,
  last_verified_at TIMESTAMPTZ,
  owner TEXT,
  tags JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE pr_context (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  pr_number BIGINT NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  author TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('open', 'merged', 'closed', 'draft')),
  base_branch TEXT NOT NULL,
  head_branch TEXT NOT NULL,
  merged_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ,
  tags JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE ddl_history (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  migration_id TEXT NOT NULL UNIQUE,
  ddl_text TEXT NOT NULL,
  checksum TEXT NOT NULL,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  description TEXT
);

CREATE TABLE release_note (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  version TEXT NOT NULL,
  release_date TIMESTAMPTZ NOT NULL,
  summary TEXT NOT NULL,
  breaking_changes JSONB,
  new_features JSONB,
  bug_fixes JSONB,
  deprecations JSONB,
  tags JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE change_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  change_type TEXT NOT NULL CHECK (change_type IN ('feature_add', 'feature_modify', 'feature_remove', 'bugfix', 'refactor', 'config_change', 'dependency_update')),
  subject_ref TEXT NOT NULL,
  summary TEXT NOT NULL,
  details TEXT,
  content_hash TEXT NOT NULL,
  affected_files JSONB,
  author TEXT,
  commit_sha TEXT,
  tags JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE issue_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tracker TEXT NOT NULL,
  external_id TEXT NOT NULL,
  title TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('open', 'in_progress', 'resolved', 'closed', 'wont_fix')),
  description TEXT,
  assignee TEXT,
  labels JSONB,
  url TEXT,
  tags JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE adr_decision (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  component TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('proposed', 'accepted', 'rejected', 'deprecated', 'superseded')),
  title TEXT NOT NULL,
  rationale TEXT NOT NULL,
  alternatives_considered JSONB,
  consequences TEXT,
  supersedes UUID,
  tags JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE todo_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scope TEXT NOT NULL,
  todo_type TEXT NOT NULL CHECK (todo_type IN ('task', 'bug', 'epic', 'story', 'spike')),
  text TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('open', 'in_progress', 'done', 'cancelled', 'archived')),
  priority TEXT CHECK (priority IN ('low', 'medium', 'high', 'critical')),
  assignee TEXT,
  due_date TIMESTAMPTZ,
  closed_at TIMESTAMPTZ,
  tags JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE event_audit (
  id BIGSERIAL PRIMARY KEY,
  entity_type TEXT NOT NULL,
  entity_id UUID NOT NULL,
  operation TEXT NOT NULL CHECK (operation IN ('INSERT', 'UPDATE', 'DELETE')),
  actor TEXT,
  change_summary JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
