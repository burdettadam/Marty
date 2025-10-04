# Trust Service Testing with Master Lists

This guide demonstrates how to generate master lists for testing the trust service without database insertion.

## Generating Master Lists for Testing

The `generate_synthetic_data.py` script now supports a `--master-list-only` mode that generates master lists specifically for trust service testing without inserting them into the database.

### Basic Usage

```bash
# Generate master lists for 10 countries
python3 scripts/generate_synthetic_data.py --master-list-only --countries 10

# Generate master lists for specific number of countries with custom output directory
python3 scripts/generate_synthetic_data.py --master-list-only --countries 5 --output-dir data/trust_test

# Use a specific seed for reproducible results
python3 scripts/generate_synthetic_data.py --master-list-only --countries 3 --seed 123
```

### Generated Files

When using `--master-list-only`, the script generates:

1. **`master_lists.json`** - Array of master lists with mock certificate references (JSON format)
2. **`master_list_<country>.ml`** - Individual master list files in binary `.ml` format
3. **`synthetic_test_data.json`** - Complete dataset structure for compatibility
4. **`data_summary.json`** - Summary statistics

### Master List Formats

The script generates master lists in two formats:

#### JSON Format (`master_lists.json`)
Human-readable JSON containing all master lists for easy inspection and debugging.

#### Binary ML Format (`master_list_<country>.ml`)
Binary files using a simplified ICAO-style format specifically for trust service testing. Each `.ml` file contains:

- Magic bytes: "ICAOML" (6 bytes)
- Version number (2 bytes)
- Country code (3 bytes)
- Sequence number (4 bytes)
- Issue and next update timestamps (16 bytes)
- Certificate count and certificate data
- Digital signature placeholder (32 bytes)

### Reading ML Files

Use the included reader tool to inspect `.ml` files:

```bash
python3 examples/read_ml_file.py data/trust_test/master_list_usa.ml
```

### JSON Structure

Each generated master list (in JSON format) contains:

```json
{
  "country": "USA",
  "sequenceNumber": 42,
  "version": "1.0.0",
  "issueDate": "2025-10-03T18:36:57.485698+00:00",
  "nextUpdate": "2025-11-03T18:36:57.485698+00:00",
  "certificates": [
    {
      "certificateId": "USA_CSCA_1",
      "thumbprint": "3bce999cd531b2c31131e1f1f796afb34ac3310d",
      "subject": "CN=USA CSCA 1, O=USA Government, C=USA",
      "validFrom": "2025-07-14T00:36:57.485281+00:00",
      "validTo": "2028-06-05T00:36:57.485281+00:00"
    }
  ],
  "signer": "USA CSCA",
  "signature": "base64-encoded-signature",
  "dataHash": "hex-encoded-hash",
  "metadata": {
    "generatedAt": "2025-10-03T18:36:57.485698+00:00",
    "certificateCount": 5,
    "testingOnly": true,
    "note": "Generated for trust service testing - no database insertion"
  }
}
```

### Key Features

- **No Database Insertion**: Master lists are generated but not inserted into the trust service database
- **Mock Certificates**: Each master list contains 3-8 mock certificate references
- **Testing Metadata**: Includes `testingOnly` flag and explanatory notes
- **Reproducible**: Use `--seed` parameter for consistent results
- **Validation**: Prevents accidental database insertion with mutual exclusivity checks

### Integration with Trust Service

To use these master lists for testing your trust service:

1. Generate the master lists using the script
2. Load the JSON files in your test suite
3. Use the master list data to test trust service validation logic
4. Verify that your service correctly processes master list structures

### Example Test Workflow

```bash
# Step 1: Generate test data
python3 scripts/generate_synthetic_data.py --master-list-only --countries 5 --output-dir test_data

# Step 2: Use in your tests
# Load test_data/master_lists.json in your test framework
# Test trust service validation against the master list data
```

This approach allows you to test your trust service with realistic master list data without affecting your database or requiring complex setup procedures.