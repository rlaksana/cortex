# Development Policy - Cortex Memory MCP Server

## 🚫 STRICT PROHIBITION: Multiple Index Files Only

### **RULE: Single Index Policy**
```
❌ FORBIDDEN: index-claude.ts, index-qdrant.ts, index-minimal.ts, index-full.ts
✅ ALLOWED: HANYA index.ts (tunggal)
```

### **Scope:**
- **HANYA** index files yang dilarang multiple
- **BOLEH** hardcoded paths untuk simplicity dan kemudahan penggunaan
- **BOLEH** absolute paths di configuration
- **NO complex environment variable setup**

### **Policy Enforcement**

#### **1. Index File Management**
- **ONLY ONE** index file diperbolehkan: `src/index.ts`
- **TIDAK BOLEH** membuat multiple index files untuk different purposes
- **TIDAK BOLEH** membuat variant seperti:
  - `index-claude.ts` ❌
  - `index-qdrant.ts` ❌
  - `index-minimal.ts` ❌
  - `index-full.ts` ❌
  - `index-*.ts` (apapun suffix) ❌

#### **2. Configuration Guidelines**
- **BOLEH** hardcoded absolute paths untuk simplicity:
  ```json
  // ✅ CORRECT: Simple dan langsung digunakan
  {"args": ["D:\\WORKSPACE\\tools-node\\mcp-cortex\\dist\\index.js"]}
  ```
- **BOLEH** hardcoded URLs yang standar:
  ```typescript
  // ✅ CORRECT: Default configuration
  const qdrantUrl = "http://localhost:6333";
  ```
- **HARUS** gunakan environment variables untuk API keys:
  ```typescript
  // ✅ REQUIRED: Security
  const apiKey = process.env.OPENAI_API_KEY;
  ```

#### **3. Build Configuration**
- **HANYA** `dist/index.js` sebagai output
- **TIDAK BOLEH** multiple build outputs
- **TIDAK BOLEH** hardcoded paths dalam build scripts
- Package.json HARUS mengarah ke single entry point

#### **4. Rationale**
- **Simplicity**: Satu index file, satu configuration, langsung jalan
- **Ease of Use**: Tidak perlu setup environment variables yang kompleks
- **Maintainability**: Single entry point lebih mudah di-maintain
- **Build Efficiency**: Single build target lebih cepat dan reliable
- **Practicality**: Hardcoded paths lebih simple untuk development
- **Security**: Hanya API keys yang perlu environment variables

## ✅ Recommended Portable Configuration

### **MCP Configuration (Portable & Simple)**
```json
{
  "mcpServers": {
    "cortex": {
      "command": "node",
      "args": ["./dist/index.js"],
      "env": {
        "OPENAI_API_KEY": "${OPENAI_API_KEY}"
      }
    }
  }
}
```

### **Why This Works:**
- ✅ **Portable**: Relative paths work across machines
- ✅ **Simple**: Only 1 environment variable needed
- ✅ **Standard**: Follows official MCP server pattern
- ✅ **Cross-platform**: Works on Windows, Mac, Linux

### **Environment Setup (Minimal)**
```bash
# Hanya satu yang diperlukan:
OPENAI_API_KEY=your-key-here

# Tidak perlu yang lain untuk basic usage
```

### **Optional Feature Flags (If Needed)**
```bash
# Opsional, tidak mandatory:
CORTEX_DEBUG_MODE=false
LOG_LEVEL=info
```

### **Keuntungan Approach Ini:**
- ✅ **Simple**: Copy-paste configuration langsung jalan
- ✅ **No Setup**: Tidak perlu environment variables yang kompleks
- ✅ **Direct**: Hardcoded paths yang jelas dan predictable
- ✅ **Secure**: Hanya API key yang perlu disetup
- ✅ **Works**: Langsung bisa digunakan tanpa konfigurasi rumit

## 🛡️ AI Assistant Guidelines

### **For Claude Code, Copilot, and other AI assistants:**

#### **When creating index files:**
1. **CHECK**: Apakah `src/index.ts` sudah ada?
2. **IF EXISTS**: Modify existing file, JANGAN buat baru
3. **IF NOT EXISTS**: HANYA buat `src/index.ts`
4. **NEVER**: Buat `index-[suffix].ts` untuk variant apapun

#### **When suggesting configurations:**
1. **USE**: `dist/index.js` sebagai MCP server path
2. **NEVER**: Refer ke `dist/index-claude.js` atau variant lain
3. **RECOMMEND**: Environment variables untuk different modes

#### **When building:**
1. **TARGET**: `src/index.ts` → `dist/index.js`
2. **NEVER**: Build multiple index variants
3. **ENSURE**: Single output file

## 🔍 Detection Rules

### **AI Assistant Checklist:**
```
□ Is src/index.ts already present?
  → YES: Modify existing file
  → NO: Create ONLY src/index.ts

□ Am I creating index-[suffix].ts?
  → YES: 🚫 STOP! Use index.ts instead
  → NO: ✅ Continue

□ Is configuration pointing to multiple index files?
  → YES: 🚫 STOP! Use dist/index.js only
  → NO: ✅ Continue
```

### **Code Review Checklist:**
```
□ Check for multiple index files in src/
□ Check package.json for multiple entry points
□ Verify MCP configuration uses single path
□ Ensure build scripts target single file
```

## ⚡ Implementation Examples

### ✅ **CORRECT: Single Index with Features**
```typescript
// src/index.ts - The ONLY index file
import { config } from 'dotenv';

// Feature flags
const ENABLE_ADVANCED_FEATURES = process.env.CORTEX_ADVANCED_FEATURES !== 'false';
const ENABLE_HEALTH_CHECKS = process.env.CORTEX_ENABLE_HEALTH_CHECKS !== 'false';

// Conditional feature loading
if (ENABLE_ADVANCED_FEATURES) {
  // Load all 4 tools: memory_store, memory_find, database_health, database_stats
} else {
  // Load minimal tools: memory_store, memory_find
}
```

### ❌ **FORBIDDEN: Multiple Index Files**
```typescript
// ❌ JANGAN BUAT INI!
// src/index-claude.ts - Minimal version
// src/index-qdrant.ts - Full version
// src/index-minimal.ts - Simple version
```

## 📋 Configuration Templates

### ✅ **Correct MCP Configuration**
```json
{
  "mcpServers": {
    "cortex": {
      "command": "node",
      "args": ["D:\\WORKSPACE\\tools-node\\mcp-cortex\\dist\\index.js"]
    }
  }
}
```

### ❌ **Forbidden Configuration**
```json
{
  "mcpServers": {
    "cortex-minimal": {
      "command": "node",
      "args": ["D:\\WORKSPACE\\tools-node\\mcp-cortex\\dist\\index-minimal.js"]
    },
    "cortex-full": {
      "command": "node",
      "args": ["D:\\WORKSPACE\\tools-node\\mcp-cortex\\dist\\index-full.js"]
    }
  }
}
```

## 🚨 Violation Consequences

### **Automatic Detection:**
- Build scripts akan gagal jika multiple index files detected
- CI/CD pipeline akan reject PR dengan multiple index files
- Linter rules akan flag multiple index file creation

### **Manual Review:**
- Code review MUST reject multiple index file creation
- Architectural review REQUIRED untuk exceptions
- Documentation update REQUIRED jika policy changes

## 🔄 Policy Evolution

### **Future Changes:**
Jika perlu mengubah policy ini:
1. Update file ini dengan alasan yang jelas
2. Update AI assistant guidelines
3. Update build scripts dan CI/CD rules
4. Communicate changes ke semua developers

### **Exception Process:**
Exception hanya diperbolehkan dengan:
1. Technical justification yang kuat
2. Architectural review approval
3. Updated documentation
4. Migration plan

---

**🎯 REMEMBER: Single Index = Simplicity, Clarity, Maintainability**

**File ini HARUS dibaca oleh AI assistant sebelum membuat index files!**