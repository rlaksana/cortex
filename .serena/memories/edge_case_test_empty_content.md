{
  "title": "Edge Case Test - Empty Content Validation",
  "description": "Testing system behavior with empty content",
  "test_scenario": "Submit empty string content to memory_store",
  "expected_result": "Should return clear error message about required content",
  "test_data": {
    "content": "",
    "kind": "entity"
  },
  "expected_error": "Content is required"
}