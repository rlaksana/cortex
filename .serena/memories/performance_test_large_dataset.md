{
  "title": "Performance Test - Large Dataset Handling",
  "description": "Testing system performance with large knowledge base",
  "test_scenario": "Query performance with 1000+ stored knowledge items",
  "test_parameters": {
    "dataset_size": 1000,
    "query_complexity": ["simple_keyword", "complex_semantic", "cross_domain"],
    "result_limits": [10, 50, 100, 500],
    "search_patterns": ["random_access", "sequential_access", "burst_queries"]
  },
  "expected_performance_metrics": {
    "search_response_time": "<300ms for simple queries",
    "complex_query_time": "<1s for semantic searches",
    "memory_efficiency": "linear scaling",
    "index_performance": "sub-100ms lookups"
  },
  "scalability_indicators": [
    "Response time scaling with data size",
    "Memory usage patterns",
    "Query optimization effectiveness",
    "Index utilization efficiency"
  ]
}