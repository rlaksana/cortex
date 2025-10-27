{
  "title": "Performance Test - Concurrent Operations",
  "description": "Testing system performance under concurrent load",
  "test_scenario": "Simulate 20+ simultaneous memory operations",
  "test_parameters": {
    "concurrent_operations": 25,
    "operation_types": ["memory_store", "memory_find"],
    "data_variety": "all_16_knowledge_types",
    "test_duration": "60_seconds"
  },
  "expected_performance_metrics": {
    "response_time_p95": "<500ms",
    "success_rate": ">99%",
    "throughput": "1000+ operations/minute",
    "memory_usage": "stable",
    "error_rate": "<1%"
  },
  "monitoring_points": [
    "CPU usage during load",
    "Memory consumption patterns",
    "Database connection pooling",
    "OpenAI API rate limiting",
    "System resource utilization"
  ]
}