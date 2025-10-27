{
  "title": "Knowledge Types Batch Test 1 - Change, Issue, Decision, Todo, Release Note",
  "description": "Testing 5 knowledge types with real-world scenarios",
  "test_scenarios": [
    {
      "type": "change",
      "content": "System Architecture Update - Migrated from PostgreSQL hybrid to pure Qdrant vector database for improved performance",
      "metadata": {
        "change_type": "architecture_migration",
        "impact": "high",
        "rollback_available": true,
        "testing_required": "regression_tests"
      }
    },
    {
      "type": "issue", 
      "content": "OpenAI API Key Persistence Issue - Keys were disappearing after system restarts due to missing environment variable configuration",
      "metadata": {
        "severity": "medium",
        "status": "resolved",
        "resolution": "Implemented dual storage in .env file and Windows environment variables",
        "affected_components": ["authentication", "embeddings"]
      }
    },
    {
      "type": "decision",
      "content": "Technology Stack Decision - Chose Qdrant v1.13.2 over PostgreSQL for vector operations due to superior semantic search performance",
      "metadata": {
        "decision_type": "technology_selection",
        "alternatives_considered": ["PostgreSQL with pgvector", "Elasticsearch", "Weaviate"],
        "rationale": "Native vector operations, superior performance, easier maintenance",
        "impact_assessment": "positive"
      }
    },
    {
      "type": "todo",
      "content": "Complete comprehensive MCP tool testing validation - Test all 16 knowledge types with complex scenarios and edge cases",
      "metadata": {
        "priority": "high",
        "status": "in_progress",
        "assignee": "system_admin",
        "due_date": "2025-10-25",
        "estimated_effort": "2-3 hours"
      }
    },
    {
      "type": "release_note",
      "content": "Cortex MCP v1.0.0 Release - Production-ready memory management system with comprehensive OpenAI integration",
      "metadata": {
        "version": "1.0.0",
        "release_date": "2025-10-25",
        "features": ["16 knowledge types", "semantic search", "OpenAI embeddings", "zero configuration"],
        "breaking_changes": "none",
        "upgrade_path": "seamless"
      }
    }
  ]
}