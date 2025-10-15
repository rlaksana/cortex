-- Initialize PostgreSQL extensions for Cortex Memory MCP
-- Executed automatically by PostgreSQL on first container startup

\c cortex_prod;

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- Verify installations
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_extension WHERE extname = 'pgcrypto'
  ) THEN
    RAISE EXCEPTION 'pgcrypto extension failed to install';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm'
  ) THEN
    RAISE EXCEPTION 'pg_trgm extension failed to install';
  END IF;

  RAISE NOTICE 'Extensions installed successfully: pgcrypto, pg_trgm';
END $$;
