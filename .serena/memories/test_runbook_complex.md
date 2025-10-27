{
  "title": "Runbook Test - Complete System Recovery Procedures",
  "description": "Testing runbook storage with detailed recovery procedures",
  "test_scenario": "Comprehensive incident response and system recovery workflow",
  "test_data": {
    "content": "Cortex MCP System Recovery Runbook - Complete procedure for handling system failures and data recovery",
    "kind": "runbook"
  },
  "runbook_metadata": {
    "procedure_type": "disaster_recovery",
    "severity": "critical",
    "estimated_duration": "15-30 minutes",
    "prerequisites": [
      "Docker access",
      "Qdrant backup availability",
      "OpenAI API key validation"
    ],
    "steps": [
      "Verify Docker container status",
      "Check Qdrant database connectivity", 
      "Validate OpenAI API connectivity",
      "Restart MCP server if needed",
      "Run comprehensive validation tests"
    ],
    "rollback_procedures": "documented",
    "success_criteria": "All systems operational"
  }
}