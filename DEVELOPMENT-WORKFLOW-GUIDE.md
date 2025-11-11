# Development Workflow Guide for MCP-Cortex

## 🚀 Quick Start Development Commands

### Essential Commands (Sehari-hari)
```bash
# Development dengan hot reload
npm run dev:esm

# Build dan watch TypeScript
npm run build:watch

# Development panas (build + dev server)
npm run dev:hot

# Quick quality check
npm run quality:quick

# Auto-fix common issues
npm run precommit:fix
```

### Perintah Lengkap

#### **🔧 Build & Development**
```bash
npm run build              # Build production
npm run build:watch         # Build with watch mode
npm run build:esm           # Build ESM modules
npm run dev:esm             # Development dengan tsx watch
npm run dev:hot             # Kombinasi build + dev
npm run dev:clean            # Clean build + dev
npm run start                # Start production build
npm run start:silent          # Start MCP server
```

#### **📝 Code Quality & Formatting**
```bash
npm run lint                 # Lint semua file
npm run lint:fix              # Auto-fix linting issues
npm run lint:incremental      # Lint dengan cache (lebih cepat)
npm run lint:security         # Security-focused linting
npm run format:all           # Format semua file types
npm run format:check          # Cek formatting
npm run quality:quick        # Quick quality gate
npm run quality:full         # Comprehensive quality check
```

#### **🧪 Testing & Validation**
```bash
npm run type-check           # Type checking only
npm run type-check:index     # Type check entry point
npm run quality-check         # Pre-commit validation
npm run quality-gate          # Quality gate validation
npm run verify                # Verify readiness
```

#### **🛠️ TypeScript Error Fixing**
```bash
npm run ts-fix:all           # Fix semua TS errors
npm run ts-fix:hotspots       # Fix error hotspots
npm run ts-fix:imports        # Fix import issues
npm run ts-fix:interfaces     # Fix interface issues
npm run ts-fix:audit           # Audit TS fixes
```

## 📋 Development Best Practices

### **Workflow Harian**
1. **Start**: `npm run dev:hot` untuk development dengan hot reload
2. **Changes**: Edit code di `src/`
3. **Auto-format**: Editor akan auto-format dengan Prettier
4. **Quick check**: `npm run quality:quick` sebelum commit
5. **Fix issues**: `npm run precommit:fix` untuk auto-fix
6. **Commit**: Git commit (pre-commit hooks akan validate)

### **Pre-commit Quality Gates**
```bash
# Pre-commit hook otomatis menjalankan:
- Type checking (tsc --noEmit)
- Linting (ESLint)
- Security scanning
- Import fixing (auto)

# Manual quality check:
npm run prepush
```

### **IDE Configuration Setup**
- **VS Code**: Install ESLint dan Prettier extensions
- **Auto-save**: Enable untuk auto-format
- **Settings**: Gunakan workspace settings untuk consistency

## 🔧 Configuration Files

### **TypeScript Configurations**
- `tsconfig.base.json` - Base configuration (strict mode)
- `tsconfig.json` - Development configuration
- `tsconfig.ci.json` - CI/CD configuration
- `tsconfig.build.json` - Build configuration

### **ESLint Configurations**
- `eslint.config.cjs` - Main configuration (permissive)
- `eslint.security.config.cjs` - Security-focused rules
- `eslint.development.config.cjs` - Development-friendly rules

### **Prettier Configuration**
- `.prettierrc` - Production formatting
- `.prettierrc.development.json` - Development formatting

## 🎯 Development Levels

### **Level 1: Development**
```bash
npm run dev:hot          # Hot reload development
npm run quality:quick     # Quick validation
npm run precommit:fix     # Auto-fix common issues
```

### **Level 2: Quality Assurance**
```bash
npm run quality:full      # Comprehensive check
npm run lint:security     # Security validation
npm run type-check        # Type checking
```

### **Level 3: Production Ready**
```bash
npm run quality-gate:ci   # CI/CD quality gates
npm run verify             # Production readiness
npm run performance-gate  # Performance validation
```

## 📊 Performance Optimization

### **Memory Settings**
```bash
# Development (4GB heap)
NODE_OPTIONS="--max-old-space-size=4096 --expose-gc"

# Production (8GB heap)
NODE_OPTIONS="--max-old-space-size=8192 --max-heap-size=8192 --expose-gc"
```

### **Build Optimization**
- Use `--preserveWatchOutput` untuk maintain build output di watch mode
- Enable cache untuk ESLint dengan `--cache` flag
- Use incremental TypeScript compilation

## 🐛 Common Issues & Solutions

### **TypeScript Errors**
```bash
# Fix common TS errors:
npm run ts-fix:all
npm run ts-fix:imports
npm run ts-fix:interfaces
```

### **ESLint Conflicts**
```bash
# Use development config for permissive rules:
npx eslint src --config eslint.development.config.cjs

# Auto-fix with development rules:
npx eslint src --config eslint.development.config.cjs --fix
```

### **Import Issues**
```bash
# Fix import paths and aliases:
npm run ts-fix:imports:apply
```

## 🔍 Monitoring & Debugging

### **Build Performance**
```bash
# Monitor build times
npm run build --verbose

# Debug TypeScript compilation
npx tsc --listFiles --explainFiles
```

### **Linting Performance**
```bash
# Lint dengan cache untuk speed
npm run lint:incremental

# Debug linting rules
npm run lint --debug
```

## 🚀 Tips & Tricks

### **Productivity**
1. **Watch Mode**: Gunakan `--watch` untuk TypeScript dan ESLint
2. **Cache**: Enable ESLint cache dengan `--cache` flag
3. **Selective Linting**: Lint hanya changed files dengan `--cache-location`
4. **Auto-fix**: Gunakan `--fix` untuk auto-fix issues
5. **IDE Integration**: Gunakan ESLint dan Prettier extensions

### **Code Organization**
1. **Path Mapping**: Gunakan alias `@/*` untuk imports
2. **Type Organization**: Separate interface, types, dan implementation
3. **Module Boundaries**: Gunakan consistent module structure
4. **Error Handling**: Gunakan proper error boundaries dan try-catch

### **Testing Strategy**
1. **Type Coverage**: Rely on TypeScript untuk type safety
2. **Linting**: Use ESLint untuk code quality
3. **Validation**: Use custom scripts untuk business logic validation
4. **Performance**: Monitor build times dan optimize bottlenecks