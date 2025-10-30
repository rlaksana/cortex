# Documentation File Renaming Mapping

This document provides the complete mapping of current documentation file names to their new categorized names for better organization and identification.

## Current Documentation Files Analysis

**Total Files to Rename:** 38
**Target:** Make document categories immediately identifiable from filename alone

## Root Directory Files → New Names with Prefixes

### Setup Guides → SETUP-*
| Current File | New File | Category | Reason |
|--------------|----------|----------|--------|
| `CLONE-SETUP.md` | `SETUP-CLONE.md` | SETUP | Repository cloning and initial setup |
| `OPENAI-SETUP-GUIDE.md` | `SETUP-OPENAI.md` | SETUP | OpenAI API configuration |
| `ESM-CONFIGURATION.md` | `SETUP-ESM.md` | SETUP | ES modules configuration setup |
| `QUICK-START.md` | `SETUP-QUICK-START.md` | SETUP | Main quick start guide (most important) |
| `README-PORTABLE-SETUP.md` | `SETUP-PORTABLE.md` | SETUP | Portable environment setup |

### Analysis Reports → ANALYSIS-*
| Current File | New File | Category | Reason |
|--------------|----------|----------|--------|
| `CONFIGURATION_CONFLICT_ANALYSIS.md` | `ANALYSIS-CONFIG-CONFLICTS.md` | ANALYSIS | Configuration system conflicts analysis |
| `EDGE_CASE_ANALYSIS_REPORT.md` | `ANALYSIS-EDGE-CASES.md` | ANALYSIS | Edge case analysis and handling |
| `COMPREHENSIVE-TEST-VERIFICATION-REPORT.md` | `ANALYSIS-TEST-VERIFICATION.md` | ANALYSIS | Comprehensive test validation results |
| `CORTEX-MEMORY-9-LOG-TEST-REPORT.md` | `ANALYSIS-CORTEX-TESTS.md` | ANALYSIS | Cortex memory system test results |
| `LOGGING_SERVICE_TEST_SUMMARY.md` | `ANALYSIS-LOGGING-TESTS.md` | ANALYSIS | Logging service test results |
| `PHASE_3_CORE_INTERFACES_SUMMARY.md` | `ANALYSIS-CORE-INTERFACES.md` | ANALYSIS | Core interface design summary |

### Test Results → TEST-*
| Current File | New File | Category | Reason |
|--------------|----------|----------|--------|
| `EMFILE-TEST-RESULTS.md` | `TEST-EMFILE-RESULTS.md` | TEST | EMFILE prevention test results |
| `VERIFIED-TEST-COVERAGE-REPORT.md` | `TEST-COVERAGE-REPORT.md` | TEST | Verified test coverage metrics |

### Configuration → CONFIG-*
| Current File | New File | Category | Reason |
|--------------|----------|----------|--------|
| `SECURITY-CONFIGURATION-SUMMARY.md` | `CONFIG-SECURITY.md` | CONFIG | Security configuration analysis |
| `VITEST-ESMODULE-FIX.md` | `CONFIG-VITEST-ESM.md` | CONFIG | Vitest ES modules configuration |

### Development → DEV-*
| Current File | New File | Category | Reason |
|--------------|----------|----------|--------|
| `DEVELOPMENT-POLICY.md` | `DEV-POLICY.md` | DEV | Development guidelines and policies |

### Special Files → Keep as-is
| Current File | New File | Category | Reason |
|--------------|----------|----------|--------|
| `README.md` | `README.md` | SPECIAL | Main project index (standard name) |
| `.ai-assistant-guidelines.md` | `.ai-assistant-guidelines.md` | SPECIAL | AI assistant guidelines (hidden file) |

## docs/ Directory Files → New Names with Prefixes

### API Documentation → API-*
| Current File | New File | Category | Reason |
|--------------|----------|----------|--------|
| `docs/API.md` | `docs/API-REFERENCE.md` | API | Complete API reference documentation |

### Setup Guides → SETUP-*
| Current File | New File | Category | Reason |
|--------------|----------|----------|--------|
| `docs/DEVELOPER.md` | `docs/SETUP-DEVELOPER.md` | SETUP | Development setup and environment |
| `docs/CONFIGURATION.md` | `docs/SETUP-CONFIGURATION.md` | SETUP | General configuration guide |

### Troubleshooting → TROUBLESHOOT-*
| Current File | New File | Category | Reason |
|--------------|----------|----------|--------|
| `docs/EMFILE-TROUBLESHOOTING.md` | `docs/TROUBLESHOOT-EMFILE.md` | TROUBLESHOOT | EMFILE error troubleshooting |
| `docs/error-handling-guide.md` | `docs/TROUBLESHOOT-ERRORS.md` | TROUBLESHOOT | General error handling guide |

### Architecture → ARCH-*
| Current File | New File | Category | Reason |
|--------------|----------|----------|--------|
| `docs/ARCHITECTURE.md` | `docs/ARCH-SYSTEM.md` | ARCH | System architecture overview |
| `docs/DATABASE_REFACTORING.md` | `docs/ARCH-DATABASE.md` | ARCH | Database architecture and refactoring |

### Configuration → CONFIG-*
| Current File | New File | Category | Reason |
|--------------|----------|----------|--------|
| `docs/MONITORING-AND-SECURITY.md` | `docs/CONFIG-MONITORING.md` | CONFIG | Monitoring and security setup |
| `docs/DEPLOYMENT.md` | `docs/CONFIG-DEPLOYMENT.md` | CONFIG | Deployment configuration |

### Development → DEV-*
| Current File | New File | Category | Reason |
|--------------|----------|----------|--------|
| `docs/file-handle-manager-usage.md` | `docs/DEV-FILE-HANDLES.md` | DEV | File handle management development |
| `docs/phase-3-package-management-summary.md` | `docs/DEV-PACKAGE-MANAGEMENT.md` | DEV | Package management and dependencies |
| `docs/comprehensive-test-combinations-guide.md` | `docs/DEV-TEST-COMBINATIONS.md` | DEV | Test combination strategies |

## Special Directory Files

### Configuration Directory → CONFIG-*
| Current File | New File | Category | Reason |
|--------------|----------|----------|--------|
| `config/mcp-config-guide.md` | `config/CONFIG-MCP-SERVER.md` | CONFIG | MCP server configuration guide |

### Test Framework → TEST-*
| Current File | New File | Category | Reason |
|--------------|----------|----------|--------|
| `tests/framework/TESTING_GUIDELINES.md` | `tests/framework/TEST-GUIDELINES.md` | TEST | Testing framework guidelines |
| `tests/MOCK_PATTERNS.md` | `tests/TEST-MOCK-PATTERNS.md` | TEST | Mock patterns for testing |
| `tests/systematic/README-systematic-test-design.md` | `tests/systematic/TEST-SYSTEMATIC-DESIGN.md` | TEST | Systematic test design methodology |

### Scripts → SCRIPT-*
| Current File | New File | Category | Reason |
|--------------|----------|----------|--------|
| `scripts/README-EMFILE-Fixes.md` | `scripts/SCRIPT-EMFILE-FIXES.md` | SCRIPT | EMFILE prevention scripts documentation |

### Memory Files → MEMORY-* (Keep in .serena)
| Current File | New File | Category | Reason |
|--------------|----------|----------|--------|
| `.serena/memories/comprehensive-test-coverage-plan.md` | `.serena/memories/MEMORY-TEST-PLAN.md` | MEMORY | Test coverage strategy (memory) |
| `.serena/memories/final-test-coverage-analysis.md` | `.serena/memories/MEMORY-TEST-ANALYSIS.md` | MEMORY | Test coverage analysis (memory) |
| `.serena/memories/knowledge-services-analysis.md` | `.serena/memories/MEMORY-KNOWLEDGE-SERVICES.md` | MEMORY | Knowledge services analysis (memory) |

## Summary Statistics

| Category | Count | Files |
|----------|-------|-------|
| SETUP | 7 | Main setup and installation guides |
| ANALYSIS | 6 | Analysis reports and studies |
| TEST | 6 | Test results and testing guides |
| CONFIG | 5 | Configuration documentation |
| DEV | 5 | Development guides and policies |
| ARCH | 2 | Architecture documentation |
| TROUBLESHOOT | 2 | Troubleshooting guides |
| API | 1 | API reference |
| SCRIPT | 1 | Script documentation |
| MEMORY | 3 | Memory/knowledge files (Serena) |
| SPECIAL | 2 | README and hidden files |
| **TOTAL** | **40** | **All documentation files** |

## Benefits of This Organization

1. **Immediate Identification**: File purpose is clear from name alone
2. **Logical Grouping**: Related files are grouped by prefix
3. **Easy Navigation**: Files sort alphabetically by category
4. **Consistent Naming**: Standardized prefix convention
5. **Clear Separation**: Distinct categories for different user needs

## Next Steps

1. Execute git mv commands for each file rename
2. Update all internal references and links
3. Update README.md documentation index
4. Update any configuration or script references
5. Verify all links work correctly