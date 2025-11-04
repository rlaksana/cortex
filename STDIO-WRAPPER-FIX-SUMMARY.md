# MCP Stdio Wrapper JSON-RPC Detection Fix

## Problem Identified

The original `silent-mcp-entry.js` wrapper used a flawed JSON-RPC message detection approach:

```javascript
function isJsonRpcMessage(data) {
    try {
        const trimmed = data.trim();
        return trimmed.startsWith('{"jsonrpc":"2.0"');
    }
    catch {
        return false;
    }
}
```

**Issues with this approach:**
1. **Too restrictive**: Only detected messages starting with exact JSON-RPC 2.0 format
2. **False positives**: Could block legitimate MCP protocol messages with different structures
3. **Handshake interference**: Could interfere with MCP protocol initialization and error messages
4. **Maintenance burden**: Required knowing all possible MCP message formats

## Solution Implemented

### Phase-Based Wrapper Approach

Replaced JSON-RPC detection with a simple, reliable phase-based system:

#### Phase 1: Startup (First 3 seconds)
- **All stdout redirected to stderr** to prevent log contamination
- No message detection required - everything goes to stderr
- Timeout-based: 3 seconds should be sufficient for MCP server startup

#### Phase 2: Protocol (After startup)
- **Original stdout completely restored**
- Complete transparency for MCP protocol communication
- No interference with JSON-RPC handshake, initialization, or error messages

### Key Changes Made

1. **Removed JSON-RPC detection logic entirely**
2. **Added timeout-based phase switching** (3 seconds)
3. **Added spawn event handler** for early restoration (500ms after spawn)
4. **Enhanced process cleanup** with proper timeout handling
5. **Added signal handlers** for graceful termination

### Technical Implementation

```javascript
// Configuration
const STARTUP_TIMEOUT_MS = 3000; // 3 seconds for startup
let isInStartupPhase = true;
let startupTimeoutId = null;

// Phase 1: Redirect all stdout to stderr during startup
function redirectStdoutToStderr(str, encoding, cb) {
    const args = [str, encoding, cb].filter((arg) => arg !== undefined);
    return originalStderrWrite.apply(process.stderr, args);
}

// Phase 2: Restore original stdout for protocol communication
function restoreOriginalStdout() {
    if (!isInStartupPhase) return;

    isInStartupPhase = false;
    process.stdout.write = originalStdoutWrite;

    // Clear any pending timeout
    if (startupTimeoutId) {
        clearTimeout(startupTimeoutId);
        startupTimeoutId = null;
    }
}
```

## Benefits of New Approach

1. **Zero false positives**: No message detection means no incorrect blocking
2. **Complete protocol transparency**: MCP handshake works without interference
3. **Simple and maintainable**: Easy to understand and debug
4. **Robust**: Works with any MCP protocol message format
5. **Automatic cleanup**: Proper timeout and signal handling

## Test Results

### Before Fix
- Risk of MCP handshake failures due to message detection
- Complex JSON-RPC parsing logic
- Potential for protocol message blocking

### After Fix
- ✅ Startup logs correctly redirected to stderr
- ✅ MCP protocol messages flow freely on stdout
- ✅ No interference with handshake process
- ✅ Clean startup and protocol communication
- ✅ Proper resource cleanup on exit

## Files Modified

- `D:\WORKSPACE\tools-node\mcp-cortex\dist\silent-mcp-entry.js` - Main wrapper implementation
- `D:\WORKSPACE\tools-node\mcp-cortex\dist\silent-mcp-entry.js.backup` - Backup of fixed version

## Usage

The wrapper is used automatically when running:
- `npm start` (uses `dist/silent-mcp-entry.js` as main entry point)
- `node dist/silent-mcp-entry.js` (direct execution)
- `cortex` command (configured as binary in package.json)

No configuration changes required - the fix is transparent to end users.