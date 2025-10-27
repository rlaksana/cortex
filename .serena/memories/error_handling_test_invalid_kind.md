{
  "title": "Error Handling Test - Invalid Knowledge Type",
  "description": "Testing system behavior with invalid knowledge type",
  "test_scenario": "Submit invalid knowledge type parameter",
  "test_data": {
    "content": "Test content with invalid kind",
    "kind": "invalid_knowledge_type"
  },
  "expected_result": "Should return clear error about valid knowledge types",
  "expected_error_message": "Invalid knowledge type",
  "valid_types_should_be_listed": ["entity", "relation", "observation", "section", "runbook", "change", "issue", "decision", "todo", "release_note", "ddl", "pr_context", "incident", "release", "risk", "assumption"]
}