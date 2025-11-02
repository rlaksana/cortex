# 🚨 CRITICAL: OpenAI API Key Required

## ⚠️ MANDATORY REQUIREMENT

Cortex Memory MCP **tidak akan berjalan tanpa OpenAI API key yang valid**. Tidak ada fallback system.

## 🔧 Setup Instructions

### Step 1: Dapatkan OpenAI API Key

1. Login ke https://platform.openai.com
2. Buka API Keys section
3. Create new secret key
4. Copy key (format: `sk-proj-...`)

### Step 2: Set Environment Variable

**Windows (PowerShell):**

```powershell
$env:OPENAI_API_KEY="sk-proj-your-actual-key-here"
```

**Windows (CMD):**

```cmd
set OPENAI_API_KEY=sk-proj-your-actual-key-here
```

**Linux/Mac:**

```bash
export OPENAI_API_KEY=sk-proj-your-actual-key-here
```

### Step 3: Persistent Setup (Recommended)

**Buat file `.env` di project root:**

```
OPENAI_API_KEY=sk-proj-your-actual-key-here
```

## ⚡ Cara Kerja Sistem

### ✅ Dengan OpenAI API Key:

- **Embedding Quality**: State-of-the-art semantic understanding
- **Search Relevance**: High-precision vector similarity
- **Performance**: Optimal speed dan accuracy
- **Compatibility**: Full feature support
- **Reliability**: 100% operational guarantee

### ❌ Tanpa OpenAI API Key:

- **Server Startup**: System exits immediately dengan error message
- **No Fallback**: Tidak ada alternative embedding system
- **Zero Functionality**: Tidak ada memory operations yang bisa dijalankan

## 🔍 Error Messages

Jika Anda melihat error ini:

```
❌ CRITICAL: OPENAI_API_KEY environment variable is required
❌ Please set your OpenAI API key to use Cortex Memory MCP
❌ Example: export OPENAI_API_KEY=sk-your-key-here
```

**Solution**: Set environment variable atau buat file `.env`.

Jika Anda melihat error ini:

```
❌ CRITICAL: Invalid OpenAI API key format
❌ OpenAI API keys must start with "sk-"
```

**Solution**: Pastikan API key format benar (dimulai dengan `sk-`).

## 💡 Best Practices

1. **Security**: Jangan share API key Anda
2. **Billing**: Pastikan OpenAI account Anda memiliki quota cukup
3. **Persistence**: Gunakan `.env` file untuk permanent setup
4. **Validation**: API key akan divalidasi saat server startup
5. **Error Handling**: System memberikan specific error message untuk troubleshooting

## 🚀 Setelah Setup

Setelah OpenAI API key terkonfigurasi dengan benar:

1. Server akan startup tanpa error
2. Semua 16 knowledge types akan berfungsi 100%
3. Semantic search akan optimal
4. Memory operations akan reliable dan fast

## 📞 Support

Jika Anda mengalami masalah:

1. Verify API key format (`sk-proj-...`)
2. Check OpenAI account billing
3. Ensure internet connection
4. Contact OpenAI support jika API key tidak berfungsi

**Status**: 100% operational dengan OpenAI API key yang valid.
**No Compromise**: Tidak ada downgrade atau alternative system.
