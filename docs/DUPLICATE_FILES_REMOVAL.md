# Duplicate Files Identified for Removal

## Summary

The following duplicate and orphaned files have been identified and can be safely removed to reduce code duplication and improve maintainability:

## 1. Trust Anchor Duplicate Directory

**Duplicate:** `/src/trust_anchor/trust-anchor/` (entire directory)
- **Files:**
  - `src/trust_anchor/trust-anchor/app/grpc_service.py`
  - `src/trust_anchor/trust-anchor/app/services/openxpki_service.py`
  - `src/trust_anchor/trust-anchor/app/services/__init__.py`
  - `src/trust_anchor/trust-anchor/ARCHITECTURE.md`
  - `src/trust_anchor/trust-anchor/Dockerfile`
  - `src/trust_anchor/trust-anchor/README.md`
  - `src/trust_anchor/trust-anchor/config/`
  - `src/trust_anchor/trust-anchor/src/`
  - `src/trust_anchor/trust-anchor/tests/`

**Active Version:** `/src/trust_anchor/app/` (current implementation)
**Reason:** The `trust-anchor/` subdirectory appears to be an orphaned duplicate with different implementations. No references found in active codebase.

## 2. Experimental Refactored Files

**Duplicate:** `src/services/mdoc_engine_refactored.py`
**Active Version:** `src/services/mdoc_engine.py`
**Reason:** Experimental refactoring not being used by active codebase. The original implementation is still being imported and used.

## 3. Previous Validation Scripts (Already Addressed)

**Note:** The duplicate validation logic in `scripts/validation/validate_implementation.py` has already been refactored into reusable utilities in `src/marty_common/validation/validators.py`.

## Removal Action Plan

1. **Remove trust-anchor duplicate directory:**
   ```bash
   rm -rf src/trust_anchor/trust-anchor/
   ```

2. **Remove experimental refactored file:**
   ```bash
   rm src/services/mdoc_engine_refactored.py
   ```

3. **Verify no broken references:**
   - Search for any imports or references to removed files
   - Update reports/analysis files if they reference removed paths

## Impact Assessment

- **Space Saved:** Approximately 15+ files removed
- **Maintenance Reduced:** Eliminates confusion between duplicate implementations
- **Code Clarity:** Clearer project structure with single source of truth for each component
- **Risk:** Low - duplicate directory not referenced in active codebase, experimental file not used

## Verification Steps

After removal:
1. Run full test suite to ensure no broken imports
2. Check build processes still work correctly
3. Verify services start up properly
4. Update any documentation that might reference removed files