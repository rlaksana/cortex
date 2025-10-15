-- T015: Trigger creation migration
-- Auto-updated_at, audit logging, immutability enforcement

-- Function: auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION trigger_set_timestamp()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Function: audit logging
CREATE OR REPLACE FUNCTION trigger_audit_log()
RETURNS TRIGGER AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    INSERT INTO event_audit (entity_type, entity_id, operation, change_summary)
    VALUES (TG_TABLE_NAME, OLD.id, 'DELETE', to_jsonb(OLD));
    RETURN OLD;
  ELSIF TG_OP = 'INSERT' THEN
    INSERT INTO event_audit (entity_type, entity_id, operation, change_summary)
    VALUES (TG_TABLE_NAME, NEW.id, 'INSERT', to_jsonb(NEW));
    RETURN NEW;
  ELSE
    INSERT INTO event_audit (entity_type, entity_id, operation, change_summary)
    VALUES (TG_TABLE_NAME, NEW.id, 'UPDATE', jsonb_build_object('old', to_jsonb(OLD), 'new', to_jsonb(NEW)));
    RETURN NEW;
  END IF;
END;
$$ LANGUAGE plpgsql;

-- Function: ADR immutability (status='accepted' blocks content changes)
CREATE OR REPLACE FUNCTION trigger_adr_immutable()
RETURNS TRIGGER AS $$
BEGIN
  IF OLD.status = 'accepted' AND (
    NEW.title != OLD.title OR
    NEW.rationale != OLD.rationale OR
    NEW.component != OLD.component OR
    NEW.alternatives_considered IS DISTINCT FROM OLD.alternatives_considered OR
    NEW.consequences IS DISTINCT FROM OLD.consequences
  ) THEN
    RAISE EXCEPTION 'Cannot modify content of accepted ADR (id: %)', OLD.id;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Function: Approved document write-lock
CREATE OR REPLACE FUNCTION trigger_doc_approved_lock()
RETURNS TRIGGER AS $$
BEGIN
  IF OLD.approved_at IS NOT NULL AND NEW.title != OLD.title THEN
    RAISE EXCEPTION 'Cannot modify title of approved document (id: %)', OLD.id;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply triggers to all tables
CREATE TRIGGER t_document_touch BEFORE UPDATE ON document
  FOR EACH ROW EXECUTE FUNCTION trigger_set_timestamp();
CREATE TRIGGER t_section_touch BEFORE UPDATE ON section
  FOR EACH ROW EXECUTE FUNCTION trigger_set_timestamp();
CREATE TRIGGER t_runbook_touch BEFORE UPDATE ON runbook
  FOR EACH ROW EXECUTE FUNCTION trigger_set_timestamp();
CREATE TRIGGER t_change_touch BEFORE UPDATE ON change_log
  FOR EACH ROW EXECUTE FUNCTION trigger_set_timestamp();
CREATE TRIGGER t_issue_touch BEFORE UPDATE ON issue_log
  FOR EACH ROW EXECUTE FUNCTION trigger_set_timestamp();
CREATE TRIGGER t_adr_touch BEFORE UPDATE ON adr_decision
  FOR EACH ROW EXECUTE FUNCTION trigger_set_timestamp();
CREATE TRIGGER t_todo_touch BEFORE UPDATE ON todo_log
  FOR EACH ROW EXECUTE FUNCTION trigger_set_timestamp();
CREATE TRIGGER t_pr_touch BEFORE UPDATE ON pr_context
  FOR EACH ROW EXECUTE FUNCTION trigger_set_timestamp();

-- Audit triggers (all mutations)
CREATE TRIGGER t_audit_document AFTER INSERT OR UPDATE OR DELETE ON document
  FOR EACH ROW EXECUTE FUNCTION trigger_audit_log();
CREATE TRIGGER t_audit_section AFTER INSERT OR UPDATE OR DELETE ON section
  FOR EACH ROW EXECUTE FUNCTION trigger_audit_log();
CREATE TRIGGER t_audit_runbook AFTER INSERT OR UPDATE OR DELETE ON runbook
  FOR EACH ROW EXECUTE FUNCTION trigger_audit_log();
CREATE TRIGGER t_audit_change AFTER INSERT OR UPDATE OR DELETE ON change_log
  FOR EACH ROW EXECUTE FUNCTION trigger_audit_log();
CREATE TRIGGER t_audit_issue AFTER INSERT OR UPDATE OR DELETE ON issue_log
  FOR EACH ROW EXECUTE FUNCTION trigger_audit_log();
CREATE TRIGGER t_audit_adr AFTER INSERT OR UPDATE OR DELETE ON adr_decision
  FOR EACH ROW EXECUTE FUNCTION trigger_audit_log();
CREATE TRIGGER t_audit_todo AFTER INSERT OR UPDATE OR DELETE ON todo_log
  FOR EACH ROW EXECUTE FUNCTION trigger_audit_log();

-- Immutability triggers
CREATE TRIGGER t_adr_immutable BEFORE UPDATE ON adr_decision
  FOR EACH ROW EXECUTE FUNCTION trigger_adr_immutable();
CREATE TRIGGER t_doc_approved_lock BEFORE UPDATE ON document
  FOR EACH ROW EXECUTE FUNCTION trigger_doc_approved_lock();

-- Audit table is append-only (enforce at trigger level)
CREATE OR REPLACE FUNCTION trigger_audit_readonly()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'event_audit table is append-only (no updates or deletes allowed)';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER t_audit_readonly BEFORE UPDATE OR DELETE ON event_audit
  FOR EACH ROW EXECUTE FUNCTION trigger_audit_readonly();
