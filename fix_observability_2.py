#!/usr/bin/env python3

# Script to add observability metadata to memory-find-orchestrator.ts

import re

def fix_file():
    file_path = r"D:\WORKSPACE\tools-node\mcp-cortex\src\services\orchestrators\memory-find-orchestrator.ts"

    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Add import after the last import
    content = re.sub(
        r"(import type \{ AuthContext \} from '\.\./\.\./types/auth-types\.js';)",
        r"\1\nimport { createFindObservability } from '../../utils/observability-helper.js';",
        content
    )

    # Find and fix return statement around line 376 (rate limit error response)
    # This one needs startTime tracking added to the function
    content = re.sub(
        r"(async findItems\([^}]+)return \{",
        r"\1const startTime = Date.now();\n\n    return {",
        content,
        flags=re.DOTALL
    )

    # Fix return statement 1 (rate limit response)
    return_pattern_1 = r'(\s+return \{\s+results: \[\],\s+total_count: 0,\s+items: \[\],\s+autonomous_context: \{[^}]+\}\,)\s*(\}\;)'
    observability_code_1 = r'\1\n      observability: createFindObservability(\n        "fallback",\n        false, // vector_used - no vectors used in rate limit error\n        true, // degraded - rate limit is degraded state\n        Date.now() - startTime,\n        0\n      ),\n\2'

    content = re.sub(return_pattern_1, observability_code_1, content, flags=re.DOTALL)

    # Fix return statement 2 (around line 1024 - normal success response)
    return_pattern_2 = r'(\s+return \{\s+results,\s+items: results,\s+total_count: searchResult\.totalCount,\s+autonomous_context: \{[^}]+\}\,)\s*(\}\;)'
    observability_code_2 = r'\1\n      observability: createFindObservability(\n        searchResult.strategy.primary.name as any,\n        true, // vector_used - Qdrant uses vectors\n        searchResult.fallbackUsed,\n        Date.now() - startTime,\n        results.reduce((sum: number, r: any) => sum + r.confidence_score, 0) / results.length\n      ),\n\2'

    content = re.sub(return_pattern_2, observability_code_2, content, flags=re.DOTALL)

    # Fix return statement 3 (around line 1085 - validation error)
    # Add startTime to createValidationErrorResponse method
    content = re.sub(
        r"(private createValidationErrorResponse\(errors: string\[\]: MemoryFindResponse\) \{)",
        r"\1\n    const startTime = Date.now();",
        content
    )

    validation_pattern = r'(\s+return \{\s+results: \[\],\s+items: \[\],\s+total_count: 0,\s+autonomous_context: \{[^}]+\}\,)\s*(\}\;)'
    observability_validation = r'\1\n      observability: createFindObservability(\n        "error",\n        false, // vector_used - no vectors used in validation error\n        true, // degraded - validation error is degraded state\n        Date.now() - startTime,\n        0\n      ),\n\2'

    content = re.sub(validation_pattern, observability_validation, content, flags=re.DOTALL)

    # Fix return statement 4 (around line 1102 - error response)
    # Add startTime to createErrorResponse method
    content = re.sub(
        r"(private createErrorResponse\(_error: any\): MemoryFindResponse\) \{)",
        r"\1\n    const startTime = Date.now();",
        content
    )

    error_pattern = r'(\s+return \{\s+results: \[\],\s+items: \[\],\s+total_count: 0,\s+autonomous_context: \{[^}]+\}\,)\s*(\}\;)'
    observability_error = r'\1\n      observability: createFindObservability(\n        "error",\n        false, // vector_used - no vectors used in error\n        true, // degraded - error is degraded state\n        Date.now() - startTime,\n        0\n      ),\n\2'

    # Apply the error pattern to the last occurrence (createErrorResponse)
    parts = content.split('private createErrorResponse')
    if len(parts) > 1:
        # Find the return statement in createErrorResponse
        error_method = 'private createErrorResponse' + parts[-1]
        error_method = re.sub(error_pattern, observability_error, error_method, flags=re.DOTALL)
        content = 'private createErrorResponse'.join(parts[:-1]) + error_method

    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)

    print("Successfully added observability to memory-find-orchestrator.ts")

if __name__ == "__main__":
    fix_file()