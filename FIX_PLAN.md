# Type Check Fix Plan

## Step 1: Fix Interface Export Issues
**Files:** `src/types/contradiction-detector.interface.ts`, `src/services/ttl/ttl-safety-service.ts`
**Commands:**
- Export KnowledgeItem interface from contradiction-detector.interface.ts
- Fix import statements in services

## Step 2: Fix Response Meta Property Missing
**Files:** `src/db/adapters/qdrant-adapter.ts`, `src/db/database-factory.ts`, `src/services/core-memory-find.ts`
**Commands:**
- Add missing `meta` property to MemoryStoreResponse and MemoryFindResponse
- Ensure all response objects include required meta field

## Step 3: Fix Type Mismatch Issues
**Files:** Multiple files with string/enum mismatches
**Commands:**
- Fix config key mapping (high_load vs high)
- Fix enum type mismatches for priority/effort fields
- Fix ValidationError type issues

## Step 4: Fix Import/Export Issues
**Files:** `src/services/ttl/index.ts`, `src/services/truncation/truncation-service.ts`
**Commands:**
- Fix import type vs import value issues
- Fix missing exports and service imports

## Step 5: Fix Undefined Handling
**Files:** `src/utils/content-similarity-verifier.ts`, TTL services
**Commands:**
- Add null/undefined checks before accessing optional properties
- Fix optional parameter handling

## Minimal Patches:
1. Add exports for KnowledgeItem interface
2. Add meta fields to response objects
3. Fix enum type assignments
4. Fix import statements
5. Add null safety checks

**Estimated Time:** 30-45 minutes
**Priority:** Critical - Blocks all other gates