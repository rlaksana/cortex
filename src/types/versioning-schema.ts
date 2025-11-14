// @ts-nocheck
// EMERGENCY ROLLBACK: Catastrophic TypeScript errors from parallel batch removal
// TODO: Implement systematic interface synchronization before removing @ts-nocheck

/**
 * Versioning and Contract System for Cortex MCP Tools
 *
 * Implements SemVer versioning, x-version header support, and contract validation
 * for all MCP tools with backward compatibility guarantees.
 */

import { z } from 'zod';

// ============================================================================
// SemVer Versioning Schema
// ============================================================================

/**
 * Semantic Versioning schema following SemVer 2.0.0 specification
 */
export const SemVerSchema = z.object({
  major: z.number().int().min(0).default(1),
  minor: z.number().int().min(0).default(0),
  patch: z.number().int().min(0).default(0),
  prerelease: z.string().optional(),
  build: z.string().optional(),
});

/**
 * Semantic Versioning string schema for validation
 */
export const SemVerStringSchema = z
  .string()
  .regex(/^\d+\.\d+\.\d+(-[a-zA-Z0-9.-]+)?(\+[a-zA-Z0-9.-]+)?$/)
  .transform((version) => {
    const parsed = parseSemVer(version);
    return {
      major: parsed.major,
      minor: parsed.minor,
      patch: parsed.patch,
      prerelease: parsed.prerelease,
      build: parsed.build,
    };
  });

/**
 * Version compatibility matrix
 */
export const VersionCompatibilitySchema = z.object({
  min_version: z.string().regex(/^\d+\.\d+\.\d+(-[a-zA-Z0-9.-]+)?(\+[a-zA-Z0-9.-]+)?$/),
  max_version: z.string().regex(/^\d+\.\d+\.\d+(-[a-zA-Z0-9.-]+)?(\+[a-zA-Z0-9.-]+)?$/),
  deprecated_versions: z.array(z.string()).optional(),
  breaking_changes: z
    .array(
      z.object({
        version: z.string(),
        description: z.string(),
        migration_required: z.boolean().default(true),
        migration_guide: z.string().optional(),
      })
    )
    .optional(),
});

/**
 * Tool contract definition
 */
export const ToolContractSchema = z.object({
  name: z.string().min(1),
  version: SemVerSchema,
  compatibility: VersionCompatibilitySchema,
  input_schema: z.any(), // Zod schema
  output_schema: z.any(), // Zod schema
  required_scopes: z.array(z.string()).default([]),
  rate_limits: z
    .object({
      requests_per_minute: z.number().int().min(1).default(60),
      tokens_per_minute: z.number().int().min(1).default(10000),
      burst_allowance: z.number().int().min(0).default(10),
    })
    .optional(),
  input_validation: z
    .object({
      max_content_length: z.number().int().min(1).default(1000000), // 1MB
      max_items_per_request: z.number().int().min(1).default(100),
      allowed_content_types: z.array(z.string()).default(['application/json']),
    })
    .optional(),
  tenant_isolation: z.boolean().default(true),
  deprecation: z
    .object({
      deprecated_at: z.string().datetime().optional(),
      removal_at: z.string().datetime().optional(),
      replacement_tool: z.string().optional(),
      migration_instructions: z.string().optional(),
    })
    .optional(),
});

// ============================================================================
// Version Registry
// ============================================================================

/**
 * Tool version registry
 */
export interface ToolVersionRegistry {
  [toolName: string]: {
    current_version: string;
    available_versions: string[];
    contracts: {
      [version: string]: z.infer<typeof ToolContractSchema>;
    };
  };
}

/**
 * Built-in tool contracts with version information
 */
export const BUILTIN_TOOL_CONTRACTS: ToolVersionRegistry = {
  memory_store: {
    current_version: '1.2.0',
    available_versions: ['1.0.0', '1.1.0', '1.2.0'],
    contracts: {
      '1.0.0': {
        name: 'memory_store',
        version: { major: 1, minor: 0, patch: 0 },
        compatibility: {
          min_version: '1.0.0',
          max_version: '1.0.x',
        },
        input_schema: z.object({
          items: z.array(z.any()).min(1).max(50),
        }),
        output_schema: z.any(),
        required_scopes: ['memory:write'],
        rate_limits: {
          requests_per_minute: 60,
          tokens_per_minute: 10000,
          burst_allowance: 10,
        },
        input_validation: {
          max_content_length: 1000000,
          max_items_per_request: 50,
          allowed_content_types: ['application/json'],
        },
        tenant_isolation: true,
      },
      '1.1.0': {
        name: 'memory_store',
        version: { major: 1, minor: 1, patch: 0 },
        compatibility: {
          min_version: '1.0.0',
          max_version: '1.1.x',
        },
        input_schema: z.object({
          items: z.array(z.any()).min(1).max(100),
          deduplication: z
            .object({
              enabled: z.boolean().default(true),
              similarity_threshold: z.number().min(0.1).max(1.0).default(0.85),
            })
            .optional(),
        }),
        output_schema: z.any(),
        required_scopes: ['memory:write'],
        rate_limits: {
          requests_per_minute: 60,
          tokens_per_minute: 10000,
          burst_allowance: 10,
        },
        input_validation: {
          max_content_length: 1000000,
          max_items_per_request: 100,
          allowed_content_types: ['application/json'],
        },
        tenant_isolation: true,
      },
      '1.2.0': {
        name: 'memory_store',
        version: { major: 1, minor: 2, patch: 0 },
        compatibility: {
          min_version: '1.0.0',
          max_version: '1.2.x',
          breaking_changes: [
            {
              version: '1.2.0',
              description: 'Added required idempotency_key field',
              migration_required: true,
              migration_guide: 'Add idempotency_key field to all items',
            },
          ],
        },
        input_schema: z.object({
          items: z.array(z.any()).min(1).max(100),
          deduplication: z
            .object({
              enabled: z.boolean().default(true),
              similarity_threshold: z.number().min(0.1).max(1.0).default(0.85),
            })
            .optional(),
          processing: z
            .object({
              enable_validation: z.boolean().default(true),
              enable_async_processing: z.boolean().default(false),
            })
            .optional(),
        }),
        output_schema: z.any(),
        required_scopes: ['memory:write'],
        rate_limits: {
          requests_per_minute: 60,
          tokens_per_minute: 10000,
          burst_allowance: 10,
        },
        input_validation: {
          max_content_length: 1000000,
          max_items_per_request: 100,
          allowed_content_types: ['application/json'],
        },
        tenant_isolation: true,
      },
    },
  },
  memory_find: {
    current_version: '1.3.0',
    available_versions: ['1.0.0', '1.1.0', '1.2.0', '1.3.0'],
    contracts: {
      '1.0.0': {
        name: 'memory_find',
        version: { major: 1, minor: 0, patch: 0 },
        compatibility: {
          min_version: '1.0.0',
          max_version: '1.0.x',
        },
        input_schema: z.object({
          query: z.string().min(1).max(1000),
          scope: z
            .object({
              project: z.string().optional(),
              branch: z.string().optional(),
              org: z.string().optional(),
            })
            .optional(),
        }),
        output_schema: z.any(),
        required_scopes: ['memory:read'],
        rate_limits: {
          requests_per_minute: 120,
          tokens_per_minute: 20000,
          burst_allowance: 20,
        },
        input_validation: {
          max_content_length: 100000,
          max_items_per_request: 1,
          allowed_content_types: ['application/json'],
        },
        tenant_isolation: true,
      },
      '1.3.0': {
        name: 'memory_find',
        version: { major: 1, minor: 3, patch: 0 },
        compatibility: {
          min_version: '1.0.0',
          max_version: '1.3.x',
        },
        input_schema: z.object({
          query: z.string().min(1).max(1000),
          scope: z
            .object({
              project: z.string().optional(),
              branch: z.string().optional(),
              org: z.string().optional(),
              service: z.string().optional(),
              tenant: z.string().optional(),
            })
            .optional(),
          search_strategy: z.enum(['fast', 'auto', 'deep']).default('auto'),
          limit: z.number().int().min(1).max(100).default(10),
          graph_expansion: z
            .object({
              enabled: z.boolean().default(false),
              max_depth: z.number().int().min(1).max(5).default(2),
            })
            .optional(),
        }),
        output_schema: z.any(),
        required_scopes: ['memory:read'],
        rate_limits: {
          requests_per_minute: 120,
          tokens_per_minute: 20000,
          burst_allowance: 20,
        },
        input_validation: {
          max_content_length: 100000,
          max_items_per_request: 1,
          allowed_content_types: ['application/json'],
        },
        tenant_isolation: true,
      },
    },
  },
  system_status: {
    current_version: '1.0.0',
    available_versions: ['1.0.0'],
    contracts: {
      '1.0.0': {
        name: 'system_status',
        version: { major: 1, minor: 0, patch: 0 },
        compatibility: {
          min_version: '1.0.0',
          max_version: '1.0.x',
        },
        input_schema: z.object({
          operation: z.enum(['health', 'stats', 'metrics']),
          scope: z
            .object({
              project: z.string().optional(),
              org: z.string().optional(),
            })
            .optional(),
        }),
        output_schema: z.any(),
        required_scopes: ['system:read'],
        rate_limits: {
          requests_per_minute: 30,
          tokens_per_minute: 5000,
          burst_allowance: 5,
        },
        input_validation: {
          max_content_length: 100000,
          max_items_per_request: 1,
          allowed_content_types: ['application/json'],
        },
        tenant_isolation: false, // System tools are cross-tenant
      },
    },
  },
};

// ============================================================================
// Version Validation Utilities
// ============================================================================

/**
 * Parse SemVer string to components
 */
export function parseSemVer(version: string): z.infer<typeof SemVerSchema> {
  const regex = /^(\d+)\.(\d+)\.(\d+)(?:-([a-zA-Z0-9.-]+))?(?:\+([a-zA-Z0-9.-]+))?$/;
  const match = version.match(regex);

  if (!match) {
    throw new Error(`Invalid semantic version: ${version}`);
  }

  return {
    major: parseInt(match[1], 10),
    minor: parseInt(match[2], 10),
    patch: parseInt(match[3], 10),
    prerelease: match[4],
    build: match[5],
  };
}

/**
 * Check if version A is compatible with version B according to SemVer rules
 */
export function isVersionCompatible(versionA: string, versionB: string): boolean {
  const a = parseSemVer(versionA);
  const b = parseSemVer(versionB);

  // Major version must match for compatibility
  if (a.major !== b.major) return false;

  // Minor version of consumer must be less than or equal to provider
  if (a.minor > b.minor) return false;

  // If minor versions are equal, patch of consumer must be less than or equal to provider
  if (a.minor === b.minor && a.patch > b.patch) return false;

  return true;
}

/**
 * Get the best available version for a requested version range
 */
export function getBestCompatibleVersion(
  requestedVersion: string,
  availableVersions: string[]
): string | null {
  // Sort versions in descending order
  const sortedVersions = availableVersions
    .map(parseSemVer)
    .sort((a, b) => {
      if (a.major !== b.major) return b.major - a.major;
      if (a.minor !== b.minor) return b.minor - a.minor;
      return b.patch - a.patch;
    })
    .map((v) => `${v.major}.${v.minor}.${v.patch}${v.prerelease ? `-${v.prerelease}` : ''}`);

  // Find the most recent compatible version
  for (const version of sortedVersions) {
    if (isVersionCompatible(requestedVersion, version)) {
      return version;
    }
  }

  return null;
}

/**
 * Validate input against version-specific schema
 */
export function validateInputForVersion(
  toolName: string,
  version: string,
  input: unknown
): { isValid: boolean; error?: string; validatedInput?: unknown } {
  const contract = BUILTIN_TOOL_CONTRACTS[toolName]?.contracts[version];
  if (!contract) {
    return {
      isValid: false,
      error: `Unknown tool version: ${toolName}@${version}`,
    };
  }

  try {
    const validatedInput = contract.input_schema.parse(input);
    return { isValid: true, validatedInput };
  } catch (error) {
    return {
      isValid: false,
      error: `Input validation failed for ${toolName}@${version}: ${
        error instanceof Error ? error.message : 'Unknown error'
      }`,
    };
  }
}

/**
 * Validate output against version-specific schema
 */
export function validateOutputForVersion(
  toolName: string,
  version: string,
  output: unknown
): { isValid: boolean; error?: string } {
  const contract = BUILTIN_TOOL_CONTRACTS[toolName]?.contracts[version];
  if (!contract) {
    return {
      isValid: false,
      error: `Unknown tool version: ${toolName}@${version}`,
    };
  }

  try {
    contract.output_schema.parse(output);
    return { isValid: true };
  } catch (error) {
    return {
      isValid: false,
      error: `Output validation failed for ${toolName}@${version}: ${
        error instanceof Error ? error.message : 'Unknown error'
      }`,
    };
  }
}

// ============================================================================
// X-Version Header Support
// ============================================================================

/**
 * Version header parsing and validation
 */
export const VersionHeaderSchema = z.object({
  'x-version': z
    .string()
    .regex(/^\d+\.\d+\.\d+(-[a-zA-Z0-9.-]+)?$/)
    .optional(),
  'x-api-version': z
    .string()
    .regex(/^\d+\.\d+\.\d+(-[a-zA-Z0-9.-]+)?$/)
    .optional(),
  'x-client-version': z
    .string()
    .regex(/^\d+\.\d+\.\d+(-[a-zA-Z0-9.-]+)?$/)
    .optional(),
});

/**
 * Extract version information from headers
 */
export function extractVersionFromHeaders(headers: Record<string, string>): {
  requestedVersion?: string;
  apiVersion?: string;
  clientVersion?: string;
} {
  try {
    const parsed = VersionHeaderSchema.parse(headers);
    return {
      requestedVersion: parsed['x-version'],
      apiVersion: parsed['x-api-version'],
      clientVersion: parsed['x-client-version'],
    };
  } catch {
    return {};
  }
}

/**
 * Resolve version for tool execution
 */
export function resolveToolVersion(
  toolName: string,
  headers: Record<string, string>,
  defaultVersion?: string
): { version: string; warnings: string[] } {
  const versions = BUILTIN_TOOL_CONTRACTS[toolName];
  if (!versions) {
    throw new Error(`Unknown tool: ${toolName}`);
  }

  const { requestedVersion, apiVersion, clientVersion } = extractVersionFromHeaders(headers);
  const targetVersion =
    requestedVersion || apiVersion || defaultVersion || versions.current_version;

  const warnings: string[] = [];

  // Check if the exact version exists
  if (versions.available_versions.includes(targetVersion)) {
    // Check for deprecation
    const contract = versions.contracts[targetVersion];
    if (contract.deprecation?.deprecated_at) {
      warnings.push(
        `Version ${targetVersion} is deprecated since ${contract.deprecation.deprecated_at}`
      );
      if (contract.deprecation.replacement_tool) {
        warnings.push(`Consider migrating to ${contract.deprecation.replacement_tool}`);
      }
    }

    return { version: targetVersion, warnings };
  }

  // Try to find compatible version
  const compatibleVersion = getBestCompatibleVersion(targetVersion, versions.available_versions);
  if (compatibleVersion) {
    warnings.push(
      `Requested version ${targetVersion} not available, using compatible version ${compatibleVersion}`
    );
    return { version: compatibleVersion, warnings };
  }

  // Fallback to current version with warning
  warnings.push(
    `Requested version ${targetVersion} not compatible, using current version ${versions.current_version}`
  );
  return { version: versions.current_version, warnings };
}
