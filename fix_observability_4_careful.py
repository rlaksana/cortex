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

    # Add startTime tracking to main store method (find the method signature)
    content = re.sub(
        r"(async storeItems\(items: KnowledgeItem\[\], options: StoreOptions = \{\}\): Promise<MemoryStoreResponse> \{[\s\S]*?logger\.info\([\s\S]*?'P5-T5\.3: Starting batch storage')",
        r"\1\n    const startTime = Date.now();",
        content
    )

    # Fix return statement 1 (around line 264 - normal success response)
    # This is the main success return in storeItems method
    content = re.sub(
        r"(return \{\s+items: itemResults,\s+summary,\s+stored,\s+errors,\s+autonomous_context: autonomousContext,\s+\};)",
        r"return {\n        items: itemResults,\n        summary,\n        stored,\n        errors,\n        autonomous_context: autonomousContext,\n        observability: createStoreObservability(\n          true, // vector_used - embeddings used for semantic search\n          false, // degraded - successful operation\n          Date.now() - startTime,\n          0.8 // confidence score for successful storage\n        ),\n      };",
        content,
        flags=re.DOTALL
    )

    # Add startTime to createErrorResponse method
    content = re.sub(
        r"(private createErrorResponse\(errors: StoreError\[\]: MemoryStoreResponse\) \{)",
        r"\1\n    const startTime = Date.now();",
        content
    )

    # Fix return statement 2 (in createErrorResponse method around line 675)
    # Find the createErrorResponse method and fix its return statement
    content = re.sub(
        r"(private createErrorResponse\(errors: StoreError\[\]: MemoryStoreResponse\) \{[\s\S]*?)return \{\s+items: itemResults,\s+summary,\s+stored: \[\],\s+errors,\s+autonomous_context: \{[^}]+\},\s+\};",
        r"\1return {\n      items: itemResults,\n      summary,\n      stored: [],\n      errors,\n      autonomous_context: {\n        action_performed: 'skipped',\n        similar_items_checked: 0,\n        duplicates_found: 0,\n        contradictions_detected: false,\n        recommendation: 'Fix validation errors before retrying',\n        reasoning: 'Request failed validation',\n        user_message_suggestion: '❌ Request validation failed',\n      },\n      observability: createStoreObservability(\n        false, // vector_used - no vectors used in error\n        true, // degraded - error is degraded state\n        Date.now() - startTime,\n        0\n      ),\n    };",
        content,
        flags=re.DOTALL
    )

    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)

    print("Successfully added observability to memory-store-orchestrator.ts")

if __name__ == "__main__":
    fix_file()