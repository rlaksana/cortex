-- Migration 004: Add Graph Schema Extension
-- Created: 2025-10-13
-- Purpose: Add knowledge graph capabilities (knowledge_entity, knowledge_relation, knowledge_observation)
-- Risk: LOW (additive changes, no breaking modifications)

-- ============================================================================
-- 1. Create knowledge_entity table (Flexible entity storage)
-- ============================================================================

CREATE TABLE knowledge_entity (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  entity_type TEXT NOT NULL,
  name TEXT NOT NULL,
  data JSONB NOT NULL,
  tags JSONB NOT NULL DEFAULT '{}'::jsonb,
  content_hash TEXT NOT NULL,
  deleted_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX knowledge_entity_name_idx ON knowledge_entity(name);
CREATE INDEX knowledge_entity_type_idx ON knowledge_entity(entity_type);
CREATE INDEX knowledge_entity_tags_gin ON knowledge_entity USING gin(tags);
CREATE INDEX knowledge_entity_data_gin ON knowledge_entity USING gin(data);
CREATE INDEX knowledge_entity_content_hash_idx ON knowledge_entity(content_hash);
CREATE INDEX knowledge_entity_deleted_at_idx ON knowledge_entity(deleted_at);
CREATE UNIQUE INDEX knowledge_entity_unique_active ON knowledge_entity(entity_type, name) WHERE deleted_at IS NULL;

COMMENT ON TABLE knowledge_entity IS 'Flexible entity storage for user-defined types (10th knowledge type)';
COMMENT ON COLUMN knowledge_entity.entity_type IS 'User-defined entity type (e.g., user, organization, goal, preference)';
COMMENT ON COLUMN knowledge_entity.name IS 'Unique identifier within entity_type';
COMMENT ON COLUMN knowledge_entity.data IS 'Flexible JSONB schema - no validation constraints';
COMMENT ON COLUMN knowledge_entity.content_hash IS 'SHA-256(entity_type + name + data) for deduplication';
COMMENT ON COLUMN knowledge_entity.deleted_at IS 'Soft delete timestamp (NULL = active)';

-- ============================================================================
-- 2. Create knowledge_relation table (Entity relationships)
-- ============================================================================

CREATE TABLE knowledge_relation (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  from_entity_type TEXT NOT NULL,
  from_entity_id UUID NOT NULL,
  to_entity_type TEXT NOT NULL,
  to_entity_id UUID NOT NULL,
  relation_type TEXT NOT NULL,
  metadata JSONB,
  tags JSONB NOT NULL DEFAULT '{}'::jsonb,
  deleted_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX knowledge_relation_from_idx ON knowledge_relation(from_entity_type, from_entity_id);
CREATE INDEX knowledge_relation_to_idx ON knowledge_relation(to_entity_type, to_entity_id);
CREATE INDEX knowledge_relation_type_idx ON knowledge_relation(relation_type);
CREATE INDEX knowledge_relation_tags_gin ON knowledge_relation USING gin(tags);
CREATE INDEX knowledge_relation_metadata_gin ON knowledge_relation USING gin(metadata);
CREATE INDEX knowledge_relation_deleted_at_idx ON knowledge_relation(deleted_at);
CREATE UNIQUE INDEX knowledge_relation_unique_active ON knowledge_relation(
  from_entity_type, from_entity_id, to_entity_type, to_entity_id, relation_type
) WHERE deleted_at IS NULL;

COMMENT ON TABLE knowledge_relation IS 'Directed relationships between any knowledge items (polymorphic)';
COMMENT ON COLUMN knowledge_relation.from_entity_type IS 'Source entity type (section, decision, entity, etc.)';
COMMENT ON COLUMN knowledge_relation.from_entity_id IS 'Source entity UUID';
COMMENT ON COLUMN knowledge_relation.to_entity_type IS 'Target entity type';
COMMENT ON COLUMN knowledge_relation.to_entity_id IS 'Target entity UUID';
COMMENT ON COLUMN knowledge_relation.relation_type IS 'Relation type (resolves, supersedes, references, implements, etc.)';
COMMENT ON COLUMN knowledge_relation.metadata IS 'Optional JSONB for relation attributes (weight, confidence, timestamps)';
COMMENT ON COLUMN knowledge_relation.deleted_at IS 'Soft delete timestamp (NULL = active)';

-- ============================================================================
-- 3. Create knowledge_observation table (Fine-grained facts)
-- ============================================================================

CREATE TABLE knowledge_observation (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  entity_type TEXT NOT NULL,
  entity_id UUID NOT NULL,
  observation TEXT NOT NULL,
  observation_type TEXT,
  metadata JSONB,
  deleted_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX knowledge_observation_entity_idx ON knowledge_observation(entity_type, entity_id);
CREATE INDEX knowledge_observation_type_idx ON knowledge_observation(observation_type);
CREATE INDEX knowledge_observation_metadata_gin ON knowledge_observation USING gin(metadata);
CREATE INDEX knowledge_observation_created_at_idx ON knowledge_observation(created_at);
CREATE INDEX knowledge_observation_deleted_at_idx ON knowledge_observation(deleted_at);
CREATE INDEX knowledge_observation_fts_idx ON knowledge_observation USING gin(to_tsvector('english', observation));

COMMENT ON TABLE knowledge_observation IS 'Fine-grained timestamped facts attached to any entity';
COMMENT ON COLUMN knowledge_observation.entity_type IS 'Entity type (section, decision, entity, etc.)';
COMMENT ON COLUMN knowledge_observation.entity_id IS 'Entity UUID';
COMMENT ON COLUMN knowledge_observation.observation IS 'Key:value format or free text (e.g., "status: completed")';
COMMENT ON COLUMN knowledge_observation.observation_type IS 'Optional categorization (status, progress, note, metric)';
COMMENT ON COLUMN knowledge_observation.deleted_at IS 'Soft delete timestamp (NULL = active)';

-- ============================================================================
-- 4. Add triggers for updated_at timestamps
-- ============================================================================

-- Reuse existing touch_updated_at() function if it exists, otherwise create it
CREATE OR REPLACE FUNCTION touch_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER knowledge_entity_touch_updated_at
  BEFORE UPDATE ON knowledge_entity
  FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

CREATE TRIGGER knowledge_relation_touch_updated_at
  BEFORE UPDATE ON knowledge_relation
  FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

-- ============================================================================
-- 5. Add audit triggers (extend event_audit to cover new tables)
-- ============================================================================

-- Reuse existing audit_mutation() function if it exists, otherwise create it
CREATE OR REPLACE FUNCTION audit_mutation()
RETURNS TRIGGER AS $$
BEGIN
  IF (TG_OP = 'DELETE') THEN
    INSERT INTO event_audit (entity_type, entity_id, operation, change_summary)
    VALUES (TG_TABLE_NAME, OLD.id, 'DELETE', row_to_json(OLD)::jsonb);
    RETURN OLD;
  ELSIF (TG_OP = 'UPDATE') THEN
    INSERT INTO event_audit (entity_type, entity_id, operation, change_summary)
    VALUES (TG_TABLE_NAME, NEW.id, 'UPDATE', jsonb_build_object('old', row_to_json(OLD)::jsonb, 'new', row_to_json(NEW)::jsonb));
    RETURN NEW;
  ELSIF (TG_OP = 'INSERT') THEN
    INSERT INTO event_audit (entity_type, entity_id, operation, change_summary)
    VALUES (TG_TABLE_NAME, NEW.id, 'INSERT', row_to_json(NEW)::jsonb);
    RETURN NEW;
  END IF;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER knowledge_entity_audit AFTER INSERT OR UPDATE OR DELETE ON knowledge_entity
  FOR EACH ROW EXECUTE FUNCTION audit_mutation();

CREATE TRIGGER knowledge_relation_audit AFTER INSERT OR UPDATE OR DELETE ON knowledge_relation
  FOR EACH ROW EXECUTE FUNCTION audit_mutation();

CREATE TRIGGER knowledge_observation_audit AFTER INSERT OR UPDATE OR DELETE ON knowledge_observation
  FOR EACH ROW EXECUTE FUNCTION audit_mutation();

-- ============================================================================
-- 6. Validation & Verification
-- ============================================================================

-- Verify tables created
DO $$
BEGIN
  ASSERT (SELECT COUNT(*) FROM information_schema.tables WHERE table_name IN ('knowledge_entity', 'knowledge_relation', 'knowledge_observation')) = 3,
    'ERROR: Not all graph tables were created';

  RAISE NOTICE 'Graph schema migration completed successfully';
  RAISE NOTICE '  - knowledge_entity: % indexes', (SELECT COUNT(*) FROM pg_indexes WHERE tablename = 'knowledge_entity');
  RAISE NOTICE '  - knowledge_relation: % indexes', (SELECT COUNT(*) FROM pg_indexes WHERE tablename = 'knowledge_relation');
  RAISE NOTICE '  - knowledge_observation: % indexes', (SELECT COUNT(*) FROM pg_indexes WHERE tablename = 'knowledge_observation');
END $$;
