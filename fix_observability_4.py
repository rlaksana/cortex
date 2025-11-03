#!/usr/bin/env python3

# Script to add observability metadata to memory-store-orchestrator.ts

import re

def fix_file():
    file_path = r"D:\WORKSPACE\tools-node\mcp-cortex\src\services\orchestrators\memory-store-orchestrator.ts"

    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Add import after the last import
    content = re.sub(
        r"(// P6-T6\.1: Import expiry utilities\nimport \{ calculateItemExpiry \} from '\.\./\.\./utils/expiry-utils\.js';)",
        r"\1\nimport { createStoreObservability } from '../../utils/observability-helper.js';",
        content
    )

    # Add startTime tracking to main store method
    content = re.sub(
        r"(async storeItems\(items: KnowledgeItem\[\], options: StoreOptions = \{\}\): Promise<MemoryStoreResponse> \{)",
        r"\1\n    const startTime = Date.now();",
        content
    )

    # Fix return statement 1 (around line 264 - normal success response)
    return_pattern_1 = r'(\s+return \{\s+items: itemResults,\s+summary,\s+stored,\s+errors,\s+autonomous_context: autonomousContext,\s+\}\;)'
    observability_code_1 = r'\1\n      observability: createStoreObservability(\n        true, // vector_used - embeddings used for semantic search\n        false, // degraded - successful operation\n        Date.now() - startTime,\n        0.8 // confidence score for successful storage\n      ),\n    };'

    content = re.sub(return_pattern_1, observability_code_1, content, flags=re.DOTALL)

    # Fix return statement 2 (around line 675 - error response)
    # Add startTime to the method containing the second return statement
    # Find the method that contains the second return statement and add startTime
    content = re.sub(
        r"(private createValidationErrorResponse\([^}]+)return \{",
        r"\1const startTime = Date.now();\n\n    return {",
        content,
        flags=re.DOTALL
    )

    return_pattern_2 = r'(\s+return \{\s+items: itemResults,\s+summary,\s+stored: \[\],\s+errors,\s+autonomous_context: \{[^}]+\}\,\s+\}\;)'
    observability_code_2 = r'\1\n      observability: createStoreObservability(\n        false, // vector_used - no vectors used in validation error\n        true, // degraded - validation error is degraded state\n        Date.now() - startTime,\n        0\n      ),\n    };'

    content = re.sub(return_pattern_2, observability_code_2, content, flags=re.DOTALL)

    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)

    print("Successfully added observability to memory-store-orchestrator.ts")

if __name__ == "__main__":
    fix_file()