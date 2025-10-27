{
  "title": "Knowledge Types Batch Test 2 - DDL, PR Context, Incident, Release, Risk, Assumption",
  "description": "Testing final 6 knowledge types with enterprise scenarios",
  "test_scenarios": [
    {
      "type": "ddl",
      "content": "Qdrant Collection Schema Definition - Created knowledge_items collection with 1536-dimensional vectors",
      "metadata": {
        "schema_type": "vector_collection",
        "vector_size": 1536,
        "distance_metric": "cosine",
        "collection_name": "knowledge_items",
        "migration_status": "completed"
      }
    },
    {
      "type": "pr_context",
      "content": "Pull Request #123 - Implement comprehensive MCP tool testing framework with maximum coverage",
      "metadata": {
        "pr_number": 123,
        "title": "Comprehensive MCP Testing Implementation",
        "author": "system_admin",
        "reviewers": ["tech_lead", "qa_engineer"],
        "files_changed": 12,
        "tests_added": 50,
        "approval_status": "pending"
      }
    },
    {
      "type": "incident",
      "content": "System Performance Incident - Temporary degradation in embedding generation due to OpenAI API rate limiting",
      "metadata": {
        "incident_id": "INC-2025-001",
        "severity": "medium",
        "start_time": "2025-10-25T10:00:00Z",
        "resolution_time": "2025-10-25T10:15:00Z",
        "root_cause": "OpenAI API rate limiting",
        "impact": "reduced response times",
        "resolution": "Implemented retry logic with exponential backoff"
      }
    },
    {
      "type": "release",
      "content": "Production Release v1.0.0 - Full deployment of Cortex Memory MCP system to production environment",
      "metadata": {
        "release_id": "REL-2025-001",
        "version": "1.0.0",
        "deployment_time": "2025-10-25T12:00:00Z",
        "deployment_status": "successful",
        "rollback_available": true,
        "production_ready": true
      }
    },
    {
      "type": "risk",
      "content": "OpenAI API Dependency Risk - System relies on external OpenAI service for embedding generation",
      "metadata": {
        "risk_id": "RISK-001",
        "probability": "low",
        "impact": "high",
        "risk_score": 6.0,
        "mitigation_strategies": [
          "Implement fallback embedding system",
          "Multiple API key rotation",
          "Service level monitoring"
        ],
        "owner": "system_architect"
      }
    },
    {
      "type": "assumption",
      "content": "User Training Assumption - Users are familiar with MCP protocol and Claude Code integration",
      "metadata": {
        "assumption_id": "ASSUMP-001",
        "description": "Users understand how to configure and use MCP servers",
        "validation_method": "user_feedback_surveys",
        "validation_status": "pending",
        "impact_if_invalid": "increased_support_tickets",
        "mitigation_plan": "create comprehensive documentation and tutorials"
      }
    }
  ]
}