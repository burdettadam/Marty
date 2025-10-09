"""
Example migration for MRZ validation module to use enhanced parser.

This file demonstrates how to migrate existing MRZ validation code to use
the enhanced hardened parser while maintaining backward compatibility.
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

import logging
from typing import Any, Dict, Optional

from src.marty_common.models.mrz_validation import MRZValidationResult

# Updated imports for enhanced features
from src.marty_common.utils.mrz_enhanced import MRZParser, validate_mrz

logger = logging.getLogger(__name__)


class EnhancedMRZValidator:
    """
    Enhanced MRZ validator demonstrating migration to hardened parser.

    This class shows how to upgrade from basic MRZ parsing to comprehensive
    validation with detailed error reporting and confidence scoring.
    """

    def __init__(self, use_hardened: bool = True, strict_mode: bool = False):
        """
        Initialize enhanced MRZ validator.

        Args:
            use_hardened: Whether to use hardened parser (recommended: True)
            strict_mode: Whether to enforce strict ICAO compliance
        """
        self.parser = MRZParser(use_hardened=use_hardened, strict_mode=strict_mode)
        self.use_hardened = use_hardened

    def validate_mrz_basic(self, mrz_data: str) -> dict[str, Any] | None:
        """
        Basic MRZ validation (legacy approach for comparison).

        Args:
            mrz_data: MRZ string to validate

        Returns:
            Parsed MRZ data dictionary or None if invalid
        """
        try:
            # Legacy approach - basic parsing with minimal error info
            parsed_data = self.parser.parse_mrz(mrz_data)
            return {
                "success": True,
                "data": parsed_data,
                "errors": [],
                "confidence": 1.0,  # Legacy assumes 100% confidence
            }
        except Exception as e:
            logger.error(f"MRZ validation failed: {e}")
            return None

    def validate_mrz_enhanced(self, mrz_data: str) -> dict[str, Any]:
        """
        Enhanced MRZ validation with comprehensive error reporting.

        Args:
            mrz_data: MRZ string to validate

        Returns:
            Detailed validation result with errors, warnings, and confidence
        """
        if not self.use_hardened:
            logger.warning("Enhanced validation requires hardened parser mode")
            return self.validate_mrz_basic(mrz_data) or {
                "success": False,
                "data": None,
                "errors": ["Basic parser failed"],
                "confidence": 0.0,
            }

        # Enhanced approach - comprehensive validation
        result = self.parser.parse_mrz_with_validation(mrz_data)

        # Convert to standard format
        validation_result = {
            "success": result.is_valid,
            "data": result.parsed_data if result.is_valid else None,
            "errors": [error.message for error in result.errors],
            "warnings": [warning.message for warning in result.warnings],
            "confidence": result.confidence,
            "document_type": result.document_type.value if result.document_type else None,
            "field_validations": result.field_validations,
        }

        # Log detailed information
        if result.is_valid:
            logger.info(f"MRZ validation successful (confidence: {result.confidence:.2f})")
            if result.warnings:
                logger.warning(f"MRZ validation warnings: {[w.message for w in result.warnings]}")
        else:
            logger.error(f"MRZ validation failed with {len(result.errors)} errors")
            for error in result.errors:
                logger.error(f"  [{error.code}] {error.message}")
                if error.suggestion:
                    logger.info(f"    Suggestion: {error.suggestion}")

        return validation_result

    def validate_document_mrz(
        self, mrz_data: str, expected_doc_type: str | None = None
    ) -> dict[str, Any]:
        """
        Validate MRZ with document type checking.

        Args:
            mrz_data: MRZ string to validate
            expected_doc_type: Expected document type (TD1, TD2, TD3)

        Returns:
            Validation result with document type verification
        """
        result = self.validate_mrz_enhanced(mrz_data)

        if result["success"] and expected_doc_type:
            inferred_type = result.get("document_type")
            if inferred_type and inferred_type != expected_doc_type:
                result["warnings"].append(
                    f"Document type mismatch: expected {expected_doc_type}, "
                    f"inferred {inferred_type}"
                )
                result["confidence"] *= 0.8  # Reduce confidence

        return result


def demonstrate_migration():
    """Demonstrate the migration from legacy to enhanced MRZ validation."""

    # Sample MRZ data for testing
    test_mrzs = [
        # Valid TD3 passport
        "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<\n"
        "L898902C36UTO7408122F1204159ZE184226B<<<<<10",
        # TD3 with potential OCR errors
        "P<UTOERIKSSON<<ANNA<MAR1A<<<<<<<<<<<<<<<<<<<\n"  # '1' instead of 'I'
        "L898902C36UTO7408122F1204159ZE184226B<<<<<10",
        # Invalid TD3 with checksum errors
        "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<\n"
        "L898902C36UTO7408122F1204159ZE184226B<<<<<99",  # Wrong final check digit
    ]

    print("MRZ Validation Migration Demonstration")
    print("=" * 50)

    # Initialize validators
    legacy_validator = EnhancedMRZValidator(use_hardened=False)
    enhanced_validator = EnhancedMRZValidator(use_hardened=True, strict_mode=False)
    strict_validator = EnhancedMRZValidator(use_hardened=True, strict_mode=True)

    for i, mrz in enumerate(test_mrzs, 1):
        print(f"\nTest MRZ #{i}:")
        print("-" * 15)

        # Legacy validation
        print("Legacy Validation:")
        legacy_result = legacy_validator.validate_mrz_basic(mrz)
        if legacy_result:
            print(f"  Success: {legacy_result['success']}")
            print(f"  Confidence: {legacy_result['confidence']}")
        else:
            print("  Failed with basic error handling")

        # Enhanced validation (lenient)
        print("\nEnhanced Validation (Lenient):")
        enhanced_result = enhanced_validator.validate_mrz_enhanced(mrz)
        print(f"  Success: {enhanced_result['success']}")
        print(f"  Confidence: {enhanced_result['confidence']:.2f}")
        print(f"  Document Type: {enhanced_result.get('document_type', 'Unknown')}")

        if enhanced_result["errors"]:
            print(f"  Errors: {enhanced_result['errors']}")
        if enhanced_result["warnings"]:
            print(f"  Warnings: {enhanced_result['warnings']}")

        # Enhanced validation (strict)
        print("\nEnhanced Validation (Strict):")
        strict_result = strict_validator.validate_mrz_enhanced(mrz)
        print(f"  Success: {strict_result['success']}")
        print(f"  Confidence: {strict_result['confidence']:.2f}")

        if strict_result["errors"]:
            print(f"  Errors: {strict_result['errors']}")

        print("\n" + "=" * 50)


if __name__ == "__main__":
    demonstrate_migration()
