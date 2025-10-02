#!/usr/bin/env python3
"""Debug fallback passport loading."""

from pathlib import Path

from tests.fixtures.data_loader import TestDataLoader

# Create a loader with nonexistent directory
print("Creating TestDataLoader with nonexistent directory...")
fallback_loader = TestDataLoader(Path("/nonexistent"))
fallback_loader.generated_data_root = Path("/nonexistent_generated")  # Force no generated data
fallback_loader.has_generated_data = False

print("Loading passport data...")
fallback_passport = fallback_loader.load_passport_data()

print("Keys in fallback passport:")
for key in sorted(fallback_passport.keys()):
    value = fallback_passport[key]
    if len(str(value)) < 50:
        print(f"  {key}: {value!r}")
    else:
        print(f"  {key}: {str(value)[:47]}...")

print(f"\npassport_number present: {'passport_number' in fallback_passport}")
print(f"_is_fallback present: {'_is_fallback' in fallback_passport}")

if "_is_fallback" in fallback_passport:
    print(f"_is_fallback value: {fallback_passport['_is_fallback']}")
else:
    print("_is_fallback key is missing!")
