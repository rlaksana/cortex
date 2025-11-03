#!/usr/bin/env python3

# Script to add observability metadata to memory-store-orchestrator-qdrant.ts

import re

def fix_file():
    file_path = r"D:\WORKSPACE\tools-node\mcp-cortex\src\services\orchestrators\memory-store-orchestrator-qdrant.ts"

    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Add import after the last import
    content = re.sub(
        r"(import type \{.*?\} from '\.\./\.\./types/core-interfaces\.js';)",
        r"\1\nimport { createStoreObservability } from '../../utils/observability-helper.js';",
        content,
        flags=re.DOTALL
    )

    # Add startTime tracking to main store method
    content = re.sub(
        r"(async storeItems\(items: KnowledgeItem\[\], options: StoreOptions = \{\}\): Promise<MemoryStoreResponse> \{)",
        r"\1\n    const startTime = Date.now();",
        content
    )

    # Fix return statement 1 (around line 194 - rate limit error response)
    return_pattern_1 = r'(\s+return \{\s+items: \[\],\s+stored: \[\],\s+summary: \{[^}]+\}\,)\s*(\}\;)'
    observability_code_1 = r'\1\n      observability: createStoreObservability(\n        false, // vector_used - no vectors used in rate limit error\n        true, // degraded - rate limit is degraded state\n        Date.now() - startTime,\n        0\n      ),\n\2'

    content = re.sub(return_pattern_1, observability_code_1, content, flags=re.DOTALL)

    # Fix return statement 2 (around line 370 - normal success response)
    return_pattern_2 = r'(\s+return \{\s+// Enhanced response format\s+items: itemResults,\s+summary,.*?Legacy fields for backward compatibility.*?\}\,)\s*(\}\;)'
    observability_code_2 = r'\1\n      observability: createStoreObservability(\n        true, // vector_used - Qdrant uses vectors for embeddings\n        false, // degraded - successful operation\n        Date.now() - startTime,\n        0.8 // confidence score for successful storage\n      ),\n\2'

    content = re.sub(return_pattern_2, observability_code_2, content, flags=re.DOTALL)

    # Fix return statement 3 (around line 994 - error response)
    # Add startTime to createErrorResponse method
    content = re.sub(
        r"(private createErrorResponse\(errors: StoreError\[\]: MemoryStoreResponse\) \{)",
        r"\1\n    const startTime = Date.now();",
        content
    )

    error_pattern = r'(\s+return \{\s+// Enhanced response format\s+items: \[\],\s+summary: \{[^}]+\}\,.*?\}\,)\s*(\}\;)'
    observability_error = r'\1\n      observability: createStoreObservability(\n        false, // vector_used - no vectors used in error\n        true, // degraded - error is degraded state\n        Date.now() - startTime,\n        0\n      ),\n\2'

    # Apply the error pattern to the createErrorResponse method
    parts = content.split('private createErrorResponse')
    if len(parts) > 1:
        # Find the return statement in createErrorResponse
        error_method = 'private createErrorResponse' + parts[-1]
        error_method = re.sub(error_pattern, observability_error, error_method, flags=re.DOTALL)
        content = 'private createErrorResponse'.join(parts[:-1]) + error_method

    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)

    print("Successfully added observability to memory-store-orchestrator-qdrant.ts")

if __name__ == "__main__":
    fix_file()