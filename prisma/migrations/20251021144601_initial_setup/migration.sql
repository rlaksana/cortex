-- CreateTable
CREATE TABLE "Section" (
    "id" TEXT NOT NULL,
    "title" VARCHAR(500) NOT NULL,
    "content" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,
    "tags" JSONB NOT NULL DEFAULT '{}',
    "metadata" JSONB NOT NULL DEFAULT '{}',
    "created_by" VARCHAR(200) DEFAULT 'system',
    "updated_by" VARCHAR(200) DEFAULT 'system',
    "request_id" VARCHAR(100),
    "content_hash" VARCHAR(128),

    CONSTRAINT "Section_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AdrDecision" (
    "id" TEXT NOT NULL,
    "component" VARCHAR(200) NOT NULL,
    "status" VARCHAR(50) NOT NULL,
    "title" VARCHAR(500) NOT NULL,
    "rationale" TEXT NOT NULL,
    "alternativesConsidered" TEXT[],
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,
    "tags" JSONB NOT NULL DEFAULT '{}',
    "metadata" JSONB NOT NULL DEFAULT '{}',
    "created_by" VARCHAR(200) DEFAULT 'system',
    "updated_by" VARCHAR(200) DEFAULT 'system',
    "request_id" VARCHAR(100),
    "content_hash" VARCHAR(128),
    "accepted_at" TIMESTAMPTZ(6),
    "accepted_by" VARCHAR(200),

    CONSTRAINT "AdrDecision_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "IssueLog" (
    "id" TEXT NOT NULL,
    "title" VARCHAR(500) NOT NULL,
    "description" TEXT,
    "status" VARCHAR(50) NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,
    "tags" JSONB NOT NULL DEFAULT '{}',
    "metadata" JSONB NOT NULL DEFAULT '{}',
    "created_by" VARCHAR(200) DEFAULT 'system',
    "updated_by" VARCHAR(200) DEFAULT 'system',
    "request_id" VARCHAR(100),
    "content_hash" VARCHAR(128),

    CONSTRAINT "IssueLog_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "TodoLog" (
    "id" TEXT NOT NULL,
    "title" VARCHAR(500) NOT NULL,
    "description" TEXT,
    "status" VARCHAR(50) NOT NULL,
    "priority" VARCHAR(50),
    "due_date" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,
    "tags" JSONB NOT NULL DEFAULT '{}',
    "metadata" JSONB NOT NULL DEFAULT '{}',
    "closed_at" TIMESTAMP(3),
    "created_by" VARCHAR(200) DEFAULT 'system',
    "updated_by" VARCHAR(200) DEFAULT 'system',
    "request_id" VARCHAR(100),
    "content_hash" VARCHAR(128),
    "completed_at" TIMESTAMPTZ(6),
    "completed_by" VARCHAR(200),

    CONSTRAINT "TodoLog_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Runbook" (
    "id" TEXT NOT NULL,
    "title" VARCHAR(500) NOT NULL,
    "description" TEXT,
    "steps" JSONB NOT NULL DEFAULT '[]',
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,
    "tags" JSONB NOT NULL DEFAULT '{}',
    "metadata" JSONB NOT NULL DEFAULT '{}',
    "created_by" VARCHAR(200) DEFAULT 'system',
    "updated_by" VARCHAR(200) DEFAULT 'system',
    "request_id" VARCHAR(100),
    "content_hash" VARCHAR(128),

    CONSTRAINT "Runbook_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ChangeLog" (
    "id" TEXT NOT NULL,
    "change_type" VARCHAR(100) NOT NULL,
    "subject_ref" VARCHAR(200) NOT NULL,
    "summary" TEXT NOT NULL,
    "author" VARCHAR(200) NOT NULL,
    "commit_sha" VARCHAR(100),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,
    "tags" JSONB NOT NULL DEFAULT '{}',
    "metadata" JSONB NOT NULL DEFAULT '{}',
    "created_by" VARCHAR(200) DEFAULT 'system',
    "updated_by" VARCHAR(200) DEFAULT 'system',
    "request_id" VARCHAR(100),
    "content_hash" VARCHAR(128),

    CONSTRAINT "ChangeLog_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ReleaseNote" (
    "id" TEXT NOT NULL,
    "version" VARCHAR(100) NOT NULL,
    "summary" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,
    "tags" JSONB NOT NULL DEFAULT '{}',
    "metadata" JSONB NOT NULL DEFAULT '{}',
    "created_by" VARCHAR(200) DEFAULT 'system',
    "updated_by" VARCHAR(200) DEFAULT 'system',
    "request_id" VARCHAR(100),
    "content_hash" VARCHAR(128),

    CONSTRAINT "ReleaseNote_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DdlHistory" (
    "id" TEXT NOT NULL,
    "migration_id" VARCHAR(200) NOT NULL,
    "ddl_text" TEXT NOT NULL,
    "checksum" VARCHAR(64) NOT NULL,
    "applied_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "description" TEXT,
    "status" VARCHAR(20) NOT NULL DEFAULT 'applied',
    "tags" JSONB NOT NULL DEFAULT '{}',
    "metadata" JSONB NOT NULL DEFAULT '{}',
    "created_by" VARCHAR(200) DEFAULT 'system',
    "updated_by" VARCHAR(200) DEFAULT 'system',
    "request_id" VARCHAR(100),
    "content_hash" VARCHAR(128),

    CONSTRAINT "DdlHistory_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PrContext" (
    "id" TEXT NOT NULL,
    "pr_number" INTEGER NOT NULL,
    "title" VARCHAR(500) NOT NULL,
    "description" TEXT,
    "author" VARCHAR(200) NOT NULL,
    "status" VARCHAR(50) NOT NULL DEFAULT 'open',
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,
    "tags" JSONB NOT NULL DEFAULT '{}',
    "metadata" JSONB NOT NULL DEFAULT '{}',
    "merged_at" TIMESTAMP(3),
    "created_by" VARCHAR(200) DEFAULT 'system',
    "updated_by" VARCHAR(200) DEFAULT 'system',
    "request_id" VARCHAR(100),
    "content_hash" VARCHAR(128),

    CONSTRAINT "PrContext_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "KnowledgeEntity" (
    "id" TEXT NOT NULL,
    "entity_type" VARCHAR(100) NOT NULL,
    "name" VARCHAR(500) NOT NULL,
    "data" JSONB NOT NULL DEFAULT '{}',
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,
    "tags" JSONB NOT NULL DEFAULT '{}',
    "metadata" JSONB NOT NULL DEFAULT '{}',
    "deleted_at" TIMESTAMP(3),
    "created_by" VARCHAR(200) DEFAULT 'system',
    "updated_by" VARCHAR(200) DEFAULT 'system',
    "request_id" VARCHAR(100),
    "content_hash" VARCHAR(128),

    CONSTRAINT "KnowledgeEntity_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "KnowledgeRelation" (
    "id" TEXT NOT NULL,
    "from_entity_type" VARCHAR(100) NOT NULL,
    "from_entity_id" TEXT NOT NULL,
    "to_entity_type" VARCHAR(100) NOT NULL,
    "to_entity_id" TEXT NOT NULL,
    "relation_type" VARCHAR(100) NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,
    "tags" JSONB NOT NULL DEFAULT '{}',
    "metadata" JSONB NOT NULL DEFAULT '{}',
    "deleted_at" TIMESTAMP(3),
    "created_by" VARCHAR(200) DEFAULT 'system',
    "updated_by" VARCHAR(200) DEFAULT 'system',
    "request_id" VARCHAR(100),
    "content_hash" VARCHAR(128),

    CONSTRAINT "KnowledgeRelation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "KnowledgeObservation" (
    "id" TEXT NOT NULL,
    "entity_type" VARCHAR(100) NOT NULL,
    "entity_id" TEXT NOT NULL,
    "observation" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,
    "tags" JSONB NOT NULL DEFAULT '{}',
    "metadata" JSONB NOT NULL DEFAULT '{}',
    "deleted_at" TIMESTAMP(3),
    "created_by" VARCHAR(200) DEFAULT 'system',
    "updated_by" VARCHAR(200) DEFAULT 'system',
    "request_id" VARCHAR(100),
    "content_hash" VARCHAR(128),

    CONSTRAINT "KnowledgeObservation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "IncidentLog" (
    "id" TEXT NOT NULL,
    "title" VARCHAR(500) NOT NULL,
    "severity" VARCHAR(20) NOT NULL,
    "impact" TEXT NOT NULL,
    "resolution_status" VARCHAR(50) NOT NULL DEFAULT 'open',
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,
    "tags" JSONB NOT NULL DEFAULT '{}',
    "metadata" JSONB NOT NULL DEFAULT '{}',
    "created_by" VARCHAR(200) DEFAULT 'system',
    "updated_by" VARCHAR(200) DEFAULT 'system',
    "request_id" VARCHAR(100),
    "content_hash" VARCHAR(128),
    "detected_at" TIMESTAMPTZ(6),
    "timeline" JSONB DEFAULT '[]',
    "root_cause_analysis" TEXT,
    "resolution" TEXT,

    CONSTRAINT "IncidentLog_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ReleaseLog" (
    "id" TEXT NOT NULL,
    "version" VARCHAR(100) NOT NULL,
    "release_type" VARCHAR(50) NOT NULL,
    "scope" TEXT NOT NULL,
    "status" VARCHAR(50) NOT NULL DEFAULT 'planned',
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,
    "tags" JSONB NOT NULL DEFAULT '{}',
    "metadata" JSONB NOT NULL DEFAULT '{}',
    "created_by" VARCHAR(200) DEFAULT 'system',
    "updated_by" VARCHAR(200) DEFAULT 'system',
    "request_id" VARCHAR(100),
    "content_hash" VARCHAR(128),
    "deployment_date" TIMESTAMPTZ(6),
    "rollback_plan" TEXT,

    CONSTRAINT "ReleaseLog_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RiskLog" (
    "id" TEXT NOT NULL,
    "title" VARCHAR(500) NOT NULL,
    "category" VARCHAR(50) NOT NULL,
    "risk_level" VARCHAR(20) NOT NULL,
    "impact_description" TEXT NOT NULL,
    "probability" DECIMAL(3,2) DEFAULT 0.5,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,
    "tags" JSONB NOT NULL DEFAULT '{}',
    "metadata" JSONB NOT NULL DEFAULT '{}',
    "status" VARCHAR(50) NOT NULL DEFAULT 'open',
    "created_by" VARCHAR(200) DEFAULT 'system',
    "updated_by" VARCHAR(200) DEFAULT 'system',
    "request_id" VARCHAR(100),
    "content_hash" VARCHAR(128),
    "mitigation_strategies" JSONB DEFAULT '[]',

    CONSTRAINT "RiskLog_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AssumptionLog" (
    "id" TEXT NOT NULL,
    "title" VARCHAR(500) NOT NULL,
    "description" TEXT NOT NULL,
    "category" VARCHAR(50) NOT NULL,
    "validation_status" VARCHAR(50) NOT NULL DEFAULT 'assumed',
    "impact_if_invalid" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,
    "tags" JSONB NOT NULL DEFAULT '{}',
    "metadata" JSONB NOT NULL DEFAULT '{}',
    "created_by" VARCHAR(200) DEFAULT 'system',
    "updated_by" VARCHAR(200) DEFAULT 'system',
    "request_id" VARCHAR(100),
    "content_hash" VARCHAR(128),
    "dependencies" JSONB DEFAULT '[]',

    CONSTRAINT "AssumptionLog_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PurgeMetadata" (
    "id" INTEGER NOT NULL DEFAULT 1,
    "last_purge_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "operations_since_purge" INTEGER NOT NULL DEFAULT 0,
    "time_threshold_hours" INTEGER NOT NULL DEFAULT 24,
    "operation_threshold" INTEGER NOT NULL DEFAULT 1000,
    "deleted_counts" JSONB NOT NULL DEFAULT '{}',
    "last_duration_ms" INTEGER,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "PurgeMetadata_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EventAudit" (
    "id" TEXT NOT NULL,
    "event_type" VARCHAR(100) NOT NULL,
    "table_name" VARCHAR(100) NOT NULL,
    "record_id" VARCHAR(500) NOT NULL,
    "operation" VARCHAR(10) NOT NULL,
    "old_data" JSONB,
    "new_data" JSONB,
    "changed_by" VARCHAR(200),
    "tags" JSONB NOT NULL DEFAULT '{}',
    "metadata" JSONB NOT NULL DEFAULT '{}',
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "EventAudit_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "idx_AdrDecision_updated_at_desc" ON "AdrDecision"("updated_at" DESC, "created_at");

-- CreateIndex
CREATE INDEX "idx_IssueLog_updated_at_desc" ON "IssueLog"("updated_at" DESC, "created_at");

-- CreateIndex
CREATE INDEX "idx_TodoLog_updated_at_desc" ON "TodoLog"("updated_at" DESC, "created_at");

-- CreateIndex
CREATE UNIQUE INDEX "PurgeMetadata_id_key" ON "PurgeMetadata"("id");
