{
  "title": "Observation Test - System Performance Measurements",
  "description": "Testing observation storage with detailed metrics and measurements",
  "test_scenario": "Real-time system performance monitoring data",
  "test_data": {
    "content": "System Performance Observation: OpenAI embedding generation consistently achieving 800-950ms response time with 100% success rate",
    "kind": "observation"
  },
  "observation_metadata": {
    "measurement_type": "performance_metrics",
    "timestamp": "2025-10-25T12:32:00Z",
    "measurements": {
      "embedding_response_time": {
        "min": "800ms",
        "max": "950ms", 
        "avg": "875ms",
        "p95": "920ms"
      },
      "success_rate": "100%",
      "concurrent_operations": "20+",
      "memory_usage": "stable"
    },
    "environment": "production_ready"
  }
}