# MCP Server Consolidation Plan

## Current State Analysis

### Multiple Entry Points Identified
- `src/index.ts` - Main production entry point
- `src/index-simplified.ts` - Simplified MCP interface
- `src/index-working.ts` - Development/testing entry point
- `src/index-high-level-api.ts` - High-level API interface
- `src/silent-mcp-entry.ts` - Silent production entry

### Duplication Issues
1. **Multiple server implementations** - 4 different server entry points
2. **Tool registration duplication** - Same tools registered across multiple files
3. **Configuration scattered** - Config logic duplicated across entry points
4. **Service initialization inconsistency** - Different startup sequences

## Consolidation Strategy

### Phase 1: Entry Point Standardization

**Target Structure:**
```
src/
├── index.ts              # Main production entry (consolidated)
├── index.dev.ts          # Development entry point
├── index.test.ts         # Test entry point
├── server/
│   ├── mcp-server.ts     # Core MCP server logic
│   ├── tools/            # Tool implementations
│   ├── middleware/       # Server middleware
│   └── startup/          # Startup orchestration
```

**Consolidation Actions:**
1. **Merge core server logic** into `src/server/mcp-server.ts`
2. **Extract tool definitions** to `src/server/tools/`
3. **Standardize startup sequence** in `src/server/startup/`
4. **Create environment-specific entry points**

### Phase 2: Tool Consolidation

**Current Tool Distribution:**
- Memory Store (4 implementations)
- Memory Find (3 implementations)
- System Status (2 implementations)
- AI Status (2 implementations)

**Consolidation Plan:**
```typescript
// src/server/tools/index.ts
export * from './memory-store.tool';
export * from './memory-find.tool';
export * from './system-status.tool';
export * from './ai-status.tool';

// src/server/tools/tool-registry.ts
export class ToolRegistry {
  private tools = new Map<string, Tool>();

  register(tool: Tool) {
    this.tools.set(tool.name, tool);
  }

  get(name: string) {
    return this.tools.get(name);
  }

  getAll() {
    return Array.from(this.tools.values());
  }
}
```

### Phase 3: Configuration Consolidation

**Configuration Issues:**
- Production config scattered across multiple files
- Environment-specific configs not centralized
- Type safety inconsistencies

**Solution:**
```typescript
// src/config/server-config.ts
export interface ServerConfig {
  environment: 'development' | 'production' | 'test';
  database: DatabaseConfig;
  mcp: MCPConfig;
  logging: LoggingConfig;
}

export function createServerConfig(): ServerConfig {
  const env = process.env.NODE_ENV || 'development';

  switch (env) {
    case 'production':
      return createProductionConfig();
    case 'test':
      return createTestConfig();
    default:
      return createDevelopmentConfig();
  }
}
```

## Implementation Steps

### Step 1: Create Core Server Infrastructure
```bash
mkdir -p src/server/{tools,middleware,startup}
```

### Step 2: Extract Tool Implementations
- Move tool handlers to dedicated files
- Create consistent tool interface
- Implement tool registry

### Step 3: Standardize Entry Points
- Create 3 standardized entry points
- Remove duplicate implementations
- Update package.json scripts

### Step 4: Update Build System
- Update TypeScript paths
- Fix import resolution
- Update build scripts

## Benefits of Consolidation

1. **Reduced Bundle Size** - Eliminate duplicate code (~40% reduction expected)
2. **Simplified Maintenance** - Single source of truth for server logic
3. **Better Type Safety** - Centralized type definitions
4. **Easier Testing** - Clear separation of concerns
5. **Improved Performance** - Faster startup due to reduced initialization overhead

## Migration Timeline

- **Week 1**: Create server infrastructure and extract tools
- **Week 2**: Consolidate entry points and update configuration
- **Week 3**: Update build system and tests
- **Week 4**: Performance testing and optimization

## Risk Mitigation

1. **Feature Flags** - Enable gradual migration of tools
2. **Backward Compatibility** - Maintain old entry points during transition
3. **Comprehensive Testing** - Ensure all existing functionality works
4. **Performance Monitoring** - Track bundle size and startup times

## Success Metrics

- Bundle size reduction: 30-40%
- Startup time improvement: 20-30%
- Code duplication reduction: 80%
- Test coverage maintenance: ≥95%
- Zero breaking changes for existing API consumers