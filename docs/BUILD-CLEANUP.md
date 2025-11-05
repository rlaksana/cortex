# Build Artifacts Cleanup

## Overview

The MCP-Cortex project includes an automated build artifacts cleanup system that ensures a clean development environment by removing temporary files, build outputs, and development artifacts. This helps prevent issues related to stale files and ensures consistent builds.

## Cleanup Script

### Location
`scripts/clean-build-artifacts.cjs`

### Purpose
- Remove build directories (dist/, build/, coverage/)
- Clean temporary files and logs
- Remove development artifacts and test results
- Ensure clean state for builds and installations

## Available Scripts

### Primary Cleanup Scripts
```bash
# Clean build artifacts only
npm run clean

# Alternative command for build artifacts
npm run clean:build

# Clean everything including node_modules
npm run clean:all
```

### Automated Cleanup
The cleanup script runs automatically during:
- `npm install` (via postinstall hook)
- Before builds (when called manually)
- CI/CD pipeline setup

## What Gets Cleaned

### Build Directories
- `dist/` - TypeScript compilation output
- `build/` - Alternative build output directory
- `dist-test/` - Test build outputs
- `temp-dist/` - Temporary build files
- `coverage/` - Test coverage reports
- `.nyc_output/` - NYC coverage tool output

### TypeScript Artifacts
- `*.tsbuildinfo` - TypeScript incremental build info files

### Backup and Temporary Files
- Files ending in `.backup`, `.old-detection`, `.bak`, `~`
- Temporary log files (`tmp_last_run.log`, `cortex-local.log`, etc.)

### Test and Development Artifacts
- `test-results/` - Test result files
- `tests/temp/` - Temporary test files
- `temp/`, `tmp/` - General temporary directories
- `debug/`, `dev/`, `development/` - Development directories

### Development Test Files
- `test-array-serialization*`
- `array-serialization-test*`
- `production-test*`
- `stress-test-suite*`
- `workflow-test-suite*`
- `comprehensive-memory-test*`
- `test-autonomous.cjs`

## Usage Examples

### Before Building
```bash
# Clean and build fresh
npm run clean
npm run build
```

### Troubleshooting Build Issues
```bash
# Complete clean and reinstall
npm run clean:all
pnpm install
npm run build
```

### CI/CD Integration
```bash
# Clean before running tests in CI
npm run clean && npm run test:ci
```

## Configuration

### Custom Cleanup Patterns
The cleanup script can be extended by modifying the `scripts/clean-build-artifacts.cjs` file to include additional patterns or directories.

### Dry Run Mode
```bash
# See what would be cleaned without removing files
node scripts/clean-build-artifacts.cjs --dry-run
```

## Benefits

1. **Clean Builds**: Ensures builds start from a clean state
2. **Disk Space**: Removes unnecessary files that consume disk space
3. **Consistency**: Prevents issues from stale build artifacts
4. **Development**: Provides clean slate for testing and debugging
5. **CI/CD**: Ensures consistent pipeline execution

## Troubleshooting

### Permission Issues
If you encounter permission errors on Unix-like systems:
```bash
chmod +x scripts/clean-build-artifacts.cjs
```

### Files Not Being Cleaned
- Check if files are in use by running processes
- Verify file permissions
- Ensure patterns match the file names

### Excessive Cleanup
If important files are being removed:
- Review the patterns in the cleanup script
- Add exceptions for files that should be preserved
- Use dry-run mode to preview what will be cleaned

## Integration with Development Workflow

### IDE Integration
Most IDEs can be configured to run cleanup before builds:
- **VS Code**: Add to tasks.json or pre-launch tasks
- **WebStorm**: Configure in File Watchers settings
- **Vim/Neovim**: Add to autocmd for build commands

### Git Hooks
The cleanup is integrated with npm lifecycle scripts:
- `postinstall` - Runs after dependency installation
- Can be extended with husky pre-commit hooks if needed

## Performance Considerations

- The cleanup script is optimized for speed
- Uses Node.js fs operations for efficient file removal
- Typically completes in under 1 second for most projects
- Minimal impact on development workflow

## Related Documentation

- [TOOLCHAIN.md](./TOOLCHAIN.md) - Toolchain configuration and setup
- [DEVELOPMENT-SETUP.md](./DEVELOPMENT-SETUP.md) - Development environment setup
- [CONTRIBUTING.md](./CONTRIBUTING.md) - Contribution guidelines

---

**Last Updated**: 2025-11-04
**Maintainer**: Cortex Development Team