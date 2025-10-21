-- AlterTable
ALTER TABLE "AssumptionLog" ADD COLUMN     "monitoring_approach" TEXT,
ADD COLUMN     "owner" VARCHAR(200),
ADD COLUMN     "related_assumptions" JSONB DEFAULT '[]',
ADD COLUMN     "review_frequency" VARCHAR(50),
ADD COLUMN     "validation_criteria" JSONB DEFAULT '[]',
ADD COLUMN     "validation_date" TEXT;

-- AlterTable
ALTER TABLE "IncidentLog" ADD COLUMN     "affected_services" JSONB DEFAULT '[]',
ADD COLUMN     "business_impact" TEXT,
ADD COLUMN     "follow_up_required" BOOLEAN DEFAULT false,
ADD COLUMN     "incident_commander" VARCHAR(200),
ADD COLUMN     "recovery_actions" JSONB DEFAULT '[]';

-- AlterTable
ALTER TABLE "IssueLog" ADD COLUMN     "assignee" VARCHAR(200),
ADD COLUMN     "external_id" VARCHAR(100),
ADD COLUMN     "labels" JSONB DEFAULT '[]',
ADD COLUMN     "severity" VARCHAR(50),
ADD COLUMN     "tracker" VARCHAR(100),
ADD COLUMN     "url" TEXT;

-- AlterTable
ALTER TABLE "KnowledgeObservation" ADD COLUMN     "observation_type" VARCHAR(100);

-- AlterTable
ALTER TABLE "ReleaseLog" ADD COLUMN     "approvers" JSONB DEFAULT '[]',
ADD COLUMN     "deployment_strategy" TEXT,
ADD COLUMN     "included_changes" JSONB DEFAULT '[]',
ADD COLUMN     "post_release_actions" JSONB DEFAULT '[]',
ADD COLUMN     "release_notes" TEXT,
ADD COLUMN     "testing_status" TEXT,
ADD COLUMN     "ticket_references" JSONB DEFAULT '[]';

-- AlterTable
ALTER TABLE "RiskLog" ADD COLUMN     "contingency_plans" TEXT,
ADD COLUMN     "monitoring_indicators" JSONB DEFAULT '[]',
ADD COLUMN     "owner" VARCHAR(200),
ADD COLUMN     "review_date" TEXT,
ADD COLUMN     "trigger_events" JSONB DEFAULT '[]',
ALTER COLUMN "probability" DROP DEFAULT,
ALTER COLUMN "probability" SET DATA TYPE VARCHAR(20);

-- AlterTable
ALTER TABLE "Runbook" ADD COLUMN     "last_verified_at" TIMESTAMP(3),
ADD COLUMN     "service" VARCHAR(200),
ADD COLUMN     "triggers" JSONB DEFAULT '[]';

-- AlterTable
ALTER TABLE "Section" ADD COLUMN     "body_md" TEXT,
ADD COLUMN     "body_text" TEXT,
ADD COLUMN     "citation_count" INTEGER DEFAULT 0,
ADD COLUMN     "document_id" VARCHAR(200),
ADD COLUMN     "heading" VARCHAR(500);

-- AlterTable
ALTER TABLE "TodoLog" ADD COLUMN     "assignee" VARCHAR(200),
ADD COLUMN     "text" TEXT,
ADD COLUMN     "todo_type" VARCHAR(50);

-- CreateIndex
CREATE INDEX "idx_IncidentLog_severity_status" ON "IncidentLog"("severity", "resolution_status");

-- CreateIndex
CREATE INDEX "idx_IssueLog_tracker_external" ON "IssueLog"("tracker", "external_id");

-- CreateIndex
CREATE INDEX "idx_KnowledgeEntity_type_name" ON "KnowledgeEntity"("entity_type", "name");

-- CreateIndex
CREATE INDEX "idx_KnowledgeObservation_entity" ON "KnowledgeObservation"("entity_type", "entity_id");

-- CreateIndex
CREATE INDEX "idx_KnowledgeObservation_type" ON "KnowledgeObservation"("observation_type");

-- CreateIndex
CREATE INDEX "idx_ReleaseLog_version_status" ON "ReleaseLog"("version", "status");

-- CreateIndex
CREATE INDEX "idx_Runbook_service" ON "Runbook"("service");

-- CreateIndex
CREATE INDEX "idx_Section_document_id" ON "Section"("document_id");

-- CreateIndex
CREATE INDEX "idx_TodoLog_type_status" ON "TodoLog"("todo_type", "status");

-- CreateIndex
CREATE INDEX "idx_TodoLog_assignee" ON "TodoLog"("assignee");
