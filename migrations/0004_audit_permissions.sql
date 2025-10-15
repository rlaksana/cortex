-- Migration 0004: Audit Append-Only Enforcement
-- Purpose: Enforce audit log immutability at database permission level
-- Principle: Audit integrity requires immutable event history
-- Constitutional Alignment: IV. Immutability & Governance

-- Create dedicated application role if not exists (PostgreSQL 18 syntax)
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'cortex_app_role') THEN
    CREATE ROLE cortex_app_role;
  END IF;
END
$$;

-- Revoke destructive operations on audit log
-- event_audit must be append-only for audit integrity
REVOKE UPDATE, DELETE ON event_audit FROM cortex_app_role;
REVOKE UPDATE, DELETE ON event_audit FROM PUBLIC;

-- Grant only INSERT and SELECT permissions
-- Application can write new audit entries and read historical entries
-- but cannot modify or delete existing entries
GRANT INSERT, SELECT ON event_audit TO cortex_app_role;

-- Ensure sequence permissions for auto-increment columns
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO cortex_app_role;

-- Add comment documenting the security policy
COMMENT ON TABLE event_audit IS 'Append-only audit log. UPDATE and DELETE operations prohibited to preserve audit trail integrity. Mutations tracked via INSERT operations only.';

-- Optional: Create view for read-only audit queries
CREATE OR REPLACE VIEW v_audit_log AS
SELECT
  id,
  entity_type,
  entity_id,
  operation,
  actor,
  change_summary,
  created_at
FROM event_audit
ORDER BY created_at DESC;

COMMENT ON VIEW v_audit_log IS 'Read-only view of audit log for safe querying without modification risk';

-- Grant SELECT on view to application role
GRANT SELECT ON v_audit_log TO cortex_app_role;
