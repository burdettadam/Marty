# Passport Data Generators

This directory contains generators for creating test passport data for the Marty project. These generators are designed to produce realistic passport data structures that comply with ICAO 9303 standards.

## Overview

The passport data generator creates:

- Valid MRZ (Machine Readable Zone) data
- Data Group 1 (DG1) containing personal information
- Data Group 2 (DG2) containing facial images
- Security Object (SOD) with digital signatures
- Complete passport structures for testing

## Licensing Note

**Important**: The code in this directory is inspired by the [pypassport](https://github.com/roeften/pypassport) project, which is licensed under LGPL-3.0. Our implementation has been completely rewritten to:

1. Ensure compatibility with our project's license
2. Remove any direct code copying from the pypassport project
3. Adapt the functionality to fit our specific testing needs

The current implementation references the pypassport project for validation purposes only. **These references will be removed** once our implementation has been fully validated to ensure there are no licensing conflicts.

## Usage

The passport generator can be used in tests as follows:

```python
from tests.generators.passport_generator import PassportGenerator

# Initialize the generator
generator = PassportGenerator(output_dir="/path/to/output")

# Generate a passport
passport = generator.generate_passport(
    issuing_country="USA",
    name="SMITH",
    surname="JOHN",
    nationality="USA",
    passport_num="123456789",
    birth_date="850531",
    expiry_date="250531",
    output_file="test_passport.json"
)
```

## Validation

The generators include test cases to validate their output. Run the tests with:

```
python -m tests.generators.test_passport_generator
```

## Implementation Plan

1. ✅ Initial implementation based on pypassport concepts
2. ✅ Test validation to ensure correctness
3. ⬜ Final review and removal of all pypassport references
4. ⬜ Confirmation of compliance with project licensing