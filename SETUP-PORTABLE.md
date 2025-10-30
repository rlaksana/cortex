# Portable Setup - Cortex Memory MCP

## 🚀 Quick Setup (Clone & Run)

### **1. Clone Repository**
```bash
git clone <repository-url>
cd mcp-cortex
```

### **2. Install Dependencies**
```bash
npm install
```

### **3. Build Project**
```bash
npm run build
```

### **4. Setup Environment Variable**
```bash
# Windows (PowerShell)
$env:OPENAI_API_KEY = "your-openai-api-key"

# Windows (CMD)
set OPENAI_API_KEY=your-openai-api-key

# Linux/Mac
export OPENAI_API_KEY=your-openai-api-key
```

### **5. Start Qdrant**
```bash
docker run -p 6333:6333 -d --name cortex-qdrant qdrant/qdrant:latest
```

### **6. Add to Claude Code**
Copy `claude-code-config.json` to your Claude Code config location:

**Windows:** `%APPDATA%\Claude\claude_code_config.json`
**Mac:** `~/Library/Application Support/Claude/claude_code_config.json`
**Linux:** `~/.config/claude/claude_code_config.json`

Then merge with your existing config:
```json
{
  "mcpServers": {
    "cortex": {
      "command": "node",
      "args": ["./dist/index.js"],
      "env": {
        "OPENAI_API_KEY": "${OPENAI_API_KEY}"
      }
    },
    "...your other servers": {}
  }
}
```

### **7. Restart Claude Code**
Done! Cortex MCP will automatically connect.

## ✅ Why This Works Portably

### **Relative Paths**
- `"./dist/index.js"` works from any directory
- No absolute paths like `"D:\\WORKSPACE\\..."`

### **Environment Variables**
- `${OPENAI_API_KEY}` pulls from system environment
- Works across Windows, Mac, Linux

### **Standard MCP Pattern**
- Follows official MCP server configuration
- Same pattern as @modelcontextprotocol/server-github

## 🔧 Alternative Configurations

### **For Different Working Directories**
If you run Claude Desktop from a different directory, use:
```json
{
  "mcpServers": {
    "cortex": {
      "command": "node",
      "args": ["path/to/mcp-cortex/dist/index.js"],
      "cwd": "path/to/mcp-cortex",
      "env": {
        "OPENAI_API_KEY": "${OPENAI_API_KEY}"
      }
    }
  }
}
```

### **For Production**
```json
{
  "mcpServers": {
    "cortex": {
      "command": "node",
      "args": ["./dist/index.js"],
      "env": {
        "OPENAI_API_KEY": "${OPENAI_API_KEY}",
        "NODE_ENV": "production",
        "LOG_LEVEL": "warn"
      }
    }
  }
}
```

## 🧪 Verification

1. **Build Success:**
   ```bash
   npm run build && ls -la dist/index.js
   ```

2. **Manual Test:**
   ```bash
   node ./dist/index.js
   ```

3. **Qdrant Connection:**
   ```bash
   curl http://localhost:6333/health
   ```

## 🆚 Old vs New Approach

### **❌ Old (Not Portable)**
```json
{
  "args": ["D:\\WORKSPACE\\tools-node\\mcp-cortex\\dist\\index.js"]
}
```
- ❌ Hardcoded Windows path
- ❌ Only works on your machine
- ❌ Breaks when moved

### **✅ New (Portable)**
```json
{
  "args": ["./dist/index.js"]
}
```
- ✅ Relative path works anywhere
- ✅ Cross-platform compatible
- ✅ Clone and run directly

## 🎯 Best Practices

1. **Always use relative paths** for portable configurations
2. **Use environment variables** for sensitive data
3. **Follow official MCP patterns** for compatibility
4. **Test in different directories** to ensure portability

This setup follows the same pattern as official MCP servers like @modelcontextprotocol/server-github, ensuring maximum compatibility and portability.