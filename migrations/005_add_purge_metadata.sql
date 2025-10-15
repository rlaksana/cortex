-- Migration 005: Add Auto-Purge Metadata
-- Created: 2025-10-14
-- Purpose: Enable threshold-based automatic cleanup of old data
-- Risk: LOW (additive only, no breaking changes)

-- ============================================================================
-- 1. Create _purge_metadata table (singleton pattern)
-- ============================================================================

CREATE TABLE _purge_metadata (
  id INTEGER PRIMARY KEY DEFAULT 1,
  last_purge_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  operations_since_purge INTEGER NOT NULL DEFAULT 0,
  time_threshold_hours INTEGER NOT NULL DEFAULT 24,
  operation_threshold INTEGER NOT NULL DEFAULT 1000,
  deleted_counts JSONB DEFAULT '{}'::jsonb,
  last_duration_ms INTEGER,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  -- Ensure only one row exists
  CONSTRAINT singleton_check CHECK (id = 1)
);

-- Initialize with default configuration
INSERT INTO _purge_metadata (id) VALUES (1);

-- Indexes for performance
CREATE INDEX _purge_metadata_last_purge_idx ON _purge_metadata(last_purge_at);
CREATE INDEX _purge_metadata_operations_idx ON _purge_metadata(operations_since_purge);

-- Comments for documentation
COMMENT ON TABLE _purge_metadata IS 'Singleton table tracking auto-purge status and configuration';
COMMENT ON COLUMN _purge_metadata.last_purge_at IS 'Timestamp of last successful purge execution';
COMMENT ON COLUMN _purge_metadata.operations_since_purge IS 'Counter incremented on each memory.store/find call';
COMMENT ON COLUMN _purge_metadata.time_threshold_hours IS 'Hours elapsed before triggering purge (default: 24)';
COMMENT ON COLUMN _purge_metadata.operation_threshold IS 'Operations count before triggering purge (default: 1000)';
COMMENT ON COLUMN _purge_metadata.deleted_counts IS 'JSONB object tracking items deleted per type in last purge';
COMMENT ON COLUMN _purge_metadata.last_duration_ms IS 'Duration of last purge execution in milliseconds';
COMMENT ON COLUMN _purge_metadata.enabled IS 'Global enable/disable flag for auto-purge';

-- ============================================================================
-- 2. Add updated_at trigger
-- ============================================================================

CREATE TRIGGER _purge_metadata_touch_updated_at
  BEFORE UPDATE ON _purge_metadata
  FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

-- ============================================================================
-- 3. Validation & Verification
-- ============================================================================

DO $$
BEGIN
  ASSERT (SELECT COUNT(*) FROM _purge_metadata) = 1,
    'ERROR: _purge_metadata should have exactly 1 row';

  ASSERT (SELECT enabled FROM _purge_metadata WHERE id = 1) = TRUE,
    'ERROR: Auto-purge should be enabled by default';

  RAISE NOTICE 'Purge metadata migration completed successfully';
  RAISE NOTICE '  - Configuration: %h hours OR % operations',
    (SELECT time_threshold_hours FROM _purge_metadata WHERE id = 1),
    (SELECT operation_threshold FROM _purge_metadata WHERE id = 1);
END $$;
