#!/usr/bin/env python3

# Script to add observability metadata to memory-find-orchestrator-qdrant.ts

import re

def fix_file():
    file_path = r"D:\WORKSPACE\tools-node\mcp-cortex\src\services\orchestrators\memory-find-orchestrator-qdrant.ts"

    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Add import after the ResultGroupingService import
    content = re.sub(
        r"(import { ResultGroupingService } from '\.\./search/result-grouping-service\.js';)",
        r"\1\nimport { createFindObservability } from '../../utils/observability-helper.js';",
        content
    )

    # Add startTime tracking to findItemsLegacy method
    content = re.sub(
        r"(async findItemsLegacy\(query: SearchQuery\): Promise<MemoryFindResponse> \{)",
        r"\1\n    const startTime = Date.now();",
        content
    )

    # Add observability to return statement
    # Find the return statement and add observability after autonomous_context
    return_pattern = r'(\s+autonomous_context: \{[^}]+\}\,)\s*(\}\;)'
    observability_code = r'\1\n      observability: createFindObservability(\n        result.autonomous_metadata.strategy_used as any,\n        true, // vector_used - Qdrant always uses vectors\n        false, // degraded - assume not degraded unless error occurs\n        Date.now() - startTime,\n        Number(result.autonomous_metadata.confidence) || 0\n      ),\n\2'

    content = re.sub(return_pattern, observability_code, content, flags=re.DOTALL)

    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)

    print("Successfully added observability to memory-find-orchestrator-qdrant.ts")

if __name__ == "__main__":
    fix_file()