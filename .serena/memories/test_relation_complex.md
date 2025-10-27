{
  "title": "Relation Test - System Dependency Mapping",
  "description": "Testing relation storage with complex dependency chains",
  "test_scenario": "Multi-level system dependencies with connection strength",
  "test_data": {
    "content": "System Dependency Chain: MCP Protocol → OpenAI API → Vector Embeddings → Qdrant Storage",
    "kind": "relation"
  },
  "relationship_metadata": {
    "from_component": "mcp_protocol",
    "to_component": "qdrant_storage",
    "relation_type": "data_flow_dependency",
    "strength": 0.95,
    "dependency_chain": ["openai_api", "vector_embeddings"],
    "criticality": "critical_path"
  }
}