# DRY Synthetic Data Generation for Marty

This document describes the consolidated, DRY (Don't Repeat Yourself) approach to synthetic data generation that replaces multiple scattered generator scripts with a single, comprehensive solution.

## Overview

The new synthetic data generator consolidates functionality from:
- `scripts/testing/generate_test_data.py` (basic passport/certificate data)
- `scripts/testing/generate_realistic_test_data.py` (realistic passport data using PassportGenerator)
- `src/trust_svc/dev_job.py` (trust service synthetic data with database integration)

## Key Features

### 🎯 Comprehensive Data Generation
- **Passport Documents**: ePassports with realistic MRZ, photos, and security features
- **Certificate Hierarchies**: CSCA and Document Signer certificates with proper chains
- **Trust Service Data**: Master lists with database integration
- **mDL/mDoc Credentials**: Mobile driver's licenses and documents
- **DTC Documents**: Digital travel credentials
- **Revocation Lists**: Certificate Revocation Lists (CRLs)
- **Test Scenarios**: Invalid data for negative testing

### 🔄 DRY Principles
- Single script replaces multiple generators
- Shared utility functions for common operations
- Consistent data structures across all types
- Centralized configuration and validation

### 💾 Database Integration
- Direct insertion into trust service database
- Support for master lists, trust anchors, DSC certificates, and CRLs
- Conflict resolution with ON CONFLICT clauses
- Async database operations

### 🧪 Integration Testing
- Built-in validation for generated data
- Consistency checks across data types
- Comprehensive test reports
- Integration with existing test frameworks

## Quick Start

### Basic Usage

```bash
# Generate standard test dataset
python scripts/generate_synthetic_data.py --output-dir data/synthetic

# Generate large dataset for performance testing
python scripts/generate_synthetic_data.py --passports 1000 --countries 50

# Generate minimal dataset for CI/CD
python scripts/generate_synthetic_data.py --passports 20 --countries 5
```

### Database Integration

```bash
# Generate and insert into trust service database
python scripts/generate_synthetic_data.py --database-insert

# Focus on trust service data only
python scripts/generate_synthetic_data.py --passports 0 --database-insert
```

### Integration Testing

```bash
# Run comprehensive validation tests
python scripts/test_synthetic_integration.py

# Demo all functionality
python scripts/demo_synthetic_data.py
```

## Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--output-dir` | Output directory for generated data | `./data/synthetic` |
| `--countries` | Number of countries to generate data for | 10 |
| `--passports` | Number of passport documents | 100 |
| `--mdl` | Number of mDL credentials | 50 |
| `--mdoc` | Number of mDoc credentials | 50 |
| `--dtc` | Number of DTC documents | 30 |
| `--database-insert` | Insert data into trust service database | False |
| `--seed` | Random seed for reproducible results | 42 |
| `--format` | Output format (json) | json |

## Architecture

### SyntheticDataGenerator Class

The main generator class provides:

```python
class SyntheticDataGenerator:
    def __init__(self, output_dir: Path, database_insert: bool = False)
    async def initialize(self) -> None
    async def close(self) -> None
    
    # Data generation methods
    def generate_passport_data(self, country: str = None, ...) -> dict[str, Any]
    def generate_csca_certificate(self, country: str) -> dict[str, Any]
    def generate_ds_certificate(self, country: str, csca_id: str) -> dict[str, Any]
    def generate_master_list(self, country: str, certificates: list[str]) -> dict[str, Any]
    def generate_crl(self, country: str, issuer_cert_id: str, revoked_certs: list[str]) -> dict[str, Any]
    
    # Comprehensive generation
    async def generate_all_data(self, countries: list[str] = None, ...) -> dict[str, Any]
    
    # Output methods
    async def save_data(self, data: dict[str, Any], format_type: str = "json") -> None
    async def insert_trust_service_data(self, data: dict[str, Any]) -> None
```

### Database Integration

Trust service database integration supports:

- **Master Lists**: Inserted into `trust_svc.master_lists` table
- **Trust Anchors**: CSCA certificates in `trust_svc.trust_anchors`
- **DSC Certificates**: Document signers in `trust_svc.dsc_certificates`
- **CRL Data**: Revocation lists in `trust_svc.crl_cache`

All insertions use `ON CONFLICT` clauses for safe updates.

### Data Structure

Generated data follows this structure:

```json
{
  "passports": [...],
  "certificates": {
    "csca": [...],
    "ds": [...],
    "crls": [...],
    "masterLists": [...]
  },
  "credentials": {
    "mdl": [...],
    "mdoc": [...],
    "dtc": [...]
  },
  "metadata": {
    "countries": [...],
    "generatedAt": "...",
    "generator": "Marty Synthetic Data Generator"
  }
}
```

## Validation and Testing

### SyntheticDataTester Class

The testing framework provides:

```python
class SyntheticDataTester:
    def validate_passport_data(self, passports: list[dict[str, Any]]) -> dict[str, Any]
    def validate_certificate_chain(self, csca_certs: list[dict[str, Any]], ds_certs: list[dict[str, Any]]) -> dict[str, Any]
    def validate_master_lists(self, master_lists: list[dict[str, Any]]) -> dict[str, Any]
    def test_data_consistency(self, data: dict[str, Any]) -> dict[str, Any]
    async def run_comprehensive_tests(self) -> None
    def generate_test_report(self) -> None
```

### Test Coverage

- **Structure Validation**: Required fields, data types
- **Content Validation**: Country codes, date ranges, relationships
- **Chain Validation**: Certificate issuer relationships
- **Consistency Checks**: Cross-data type consistency
- **Error Reporting**: Detailed validation results

## Migration from Old Scripts

### Replacing generate_test_data.py

Old:
```python
from scripts.testing.generate_test_data import generate_passports
passports = generate_passports(count=100)
```

New:
```python
from scripts.generate_synthetic_data import SyntheticDataGenerator
generator = SyntheticDataGenerator(Path("./data"))
await generator.initialize()
data = await generator.generate_all_data(passport_count=100)
```

### Replacing generate_realistic_test_data.py

Old:
```python
from scripts.testing.generate_realistic_test_data import generate_realistic_passports
passports = generate_realistic_passports(count=100, countries=["USA", "CAN"])
```

New:
```python
generator = SyntheticDataGenerator(Path("./data"))
await generator.initialize()
data = await generator.generate_all_data(
    countries=["USA", "CAN"],
    passport_count=100
)
```

### Replacing trust_svc/dev_job.py

Old:
```python
from src.trust_svc.dev_job import DevJobRunner
runner = DevJobRunner(config)
await runner.generate_synthetic_data()
```

New:
```python
generator = SyntheticDataGenerator(Path("./data"), database_insert=True)
await generator.initialize()
data = await generator.generate_all_data()
await generator.insert_trust_service_data(data)
```

## Benefits

### 🎯 DRY Compliance
- **Single Source of Truth**: One script for all synthetic data needs
- **Shared Logic**: Common utilities for data generation and validation
- **Consistent API**: Uniform interface across all data types
- **Reduced Maintenance**: Changes in one place affect all consumers

### 🚀 Enhanced Functionality
- **Comprehensive Coverage**: All document and credential types
- **Database Integration**: Direct trust service database insertion
- **Validation Framework**: Built-in data consistency checking
- **Test Integration**: Ready-to-use test scenarios

### 📈 Improved Developer Experience
- **Better Documentation**: Comprehensive CLI help and examples
- **Error Handling**: Detailed error reporting and validation
- **Extensibility**: Easy to add new data types and features
- **Performance**: Async operations for better scalability

### 🔧 Operations Benefits
- **Simplified Deployment**: Single script to maintain
- **Consistent Data**: Standardized synthetic data across environments
- **Debugging**: Better logging and error reporting
- **Monitoring**: Built-in validation and health checks

## Examples

### Generate Test Data for Development

```bash
# Small dataset for development
python scripts/generate_synthetic_data.py \
  --output-dir data/dev \
  --countries 3 \
  --passports 20 \
  --mdl 10 \
  --mdoc 10 \
  --dtc 5
```

### Generate Performance Test Data

```bash
# Large dataset for performance testing
python scripts/generate_synthetic_data.py \
  --output-dir data/perf \
  --countries 50 \
  --passports 10000 \
  --mdl 5000 \
  --mdoc 5000 \
  --dtc 1000
```

### Generate Trust Service Data

```bash
# Trust service focused data with database insertion
python scripts/generate_synthetic_data.py \
  --output-dir data/trust \
  --countries 20 \
  --passports 100 \
  --database-insert
```

### Run Validation Tests

```bash
# Generate data and run validation
python scripts/test_synthetic_integration.py
```

### Demo All Features

```bash
# Run comprehensive demo
python scripts/demo_synthetic_data.py
```

## Configuration

### Environment Variables

- `TRUST_SERVICE_DATABASE_URL`: Trust service database connection string
- `SYNTHETIC_DATA_SEED`: Default random seed for reproducible generation

### Dependencies

Required:
- Python 3.11+
- asyncio
- pathlib
- json

Optional (for trust service integration):
- sqlalchemy
- asyncpg
- src.trust_svc.config
- src.trust_svc.database

Optional (for enhanced passport generation):
- tests.generators.passport_generator

## Troubleshooting

### Trust Service Not Available
```
Trust service not available - database integration disabled
```
**Solution**: Ensure trust service dependencies are installed and configured.

### Database Connection Failed
```
Failed to initialize trust database: connection refused
```
**Solution**: Check database connection string and ensure trust service database is running.

### Import Errors
```
ModuleNotFoundError: No module named 'tests.generators.passport_generator'
```
**Solution**: Enhanced passport generation is optional. Basic generation will still work.

### Permission Errors
```
PermissionError: [Errno 13] Permission denied: 'data/synthetic'
```
**Solution**: Ensure write permissions to output directory or choose different location.

## Future Enhancements

- Support for additional document types (visa, permits)
- Enhanced biometric data generation (fingerprints, iris)
- Integration with external PKI systems
- Support for blockchain-based credentials
- Real-time data streaming capabilities
- Enhanced performance with parallel generation
- Support for custom validation rules
- Integration with CI/CD pipelines

---

This DRY approach significantly improves maintainability, reduces duplication, and provides a robust foundation for synthetic data generation across the Marty ecosystem.